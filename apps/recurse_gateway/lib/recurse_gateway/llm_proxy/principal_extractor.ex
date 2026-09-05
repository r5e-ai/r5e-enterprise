defmodule Recurse.Gateway.LlmProxy.PrincipalExtractor do
  @moduledoc """
  Extract audit-identity claims from the inbound `Authorization` header
  WITHOUT verifying the JWT signature.

  Spec source of truth:
    * `specs/009-llm-api-proxy/research.md` R-001 — Codex CLI auth flow.
      The bearer token Codex sends is minted by `auth.openai.com`. The
      upstream (`chatgpt.com`) is the verifier; we are the audit-only
      observer in the path.
    * `specs/009-llm-api-proxy/spec.md` FR-002 — OAuth flow preservation.
      We MUST NOT short-circuit or modify the bearer token — we just
      peek at its claims for audit-row identity (`principal_id`,
      `chatgpt_account_id`).
    * `specs/009-llm-api-proxy/research.md` R-014 — Eddy login flow that
      shows the JWT shape this module decodes.

  ## Why decode-without-verify is the right shape (Iron Law check)

  The `Recurse.Gateway.Identity.JwtValidator` module DOES full strict
  verification (allowed alg, kid resolution, signature, exp/nbf/iat,
  replay) and is correct for routes WHERE THE GATEWAY IS THE
  AUTHENTICATOR (Audit Plane, Browser, SIEM forwarder).

  The LLM proxy is NOT one of those routes. The upstream provider
  (`chatgpt.com`) authenticates the JWT. If we tried to verify it here:

    * We don't have the issuer's JWKS and would have to maintain a fan-
      out fetcher for every supported LLM provider's signing keys.
    * Verification failures would block legitimate Codex traffic
      whenever `auth.openai.com` rotates its keys before our cache
      refresh.
    * It's not our trust boundary — `chatgpt.com` re-validates anyway.

  So we decode the payload to read claims, and treat the payload as
  observed-not-trusted data. The audit row carries the `principal_id`
  the user CLAIMED they were; the upstream's accept-or-reject of the
  call is what makes that claim authoritative for the call. This is
  the same shape as a webserver's access-log: it logs the request's
  declared identity without re-running auth itself.

  ## Fail-OPEN posture

  The caller MUST treat any error return as "use the synthetic
  `:anonymous` principal and log a warning" — NOT as a request-block.
  Failing closed here would break Codex on every request that doesn't
  exactly fit our parsing assumptions, including legitimate non-
  Enterprise tokens. The audit gap (an `:anonymous` row) is observable
  and fixable; a 401 to Codex breaks the demo.

  ## Iron Law (`elixir:elixir-thinking`)

    1. Mutable state across calls? No — every call is a pure function.
    2. Concurrent execution? No — pure transform on the caller process.
    3. Fault isolation? No — failures return `{:error, _}`.

  All three NO → plain functions.

  ## Algorithmic notes

  We could call `JOSE.JWT.peek_payload/1`, but that returns a
  `%JOSE.JWT{}` record and pulls in the full JOSE record-conversion
  surface. For our use (return claims as a plain map) the manual
  decode is simpler and has identical behaviour: split on `.`,
  base64-url-decode the second segment, JSON-decode. JOSE itself does
  the same thing under the covers.
  """

  @typedoc """
  The shape returned on `{:ok, _}` from `extract_from_headers/1`.

    * `:principal_id` — the JWT `sub` claim. Used as the
      `LlmCallRecord.principal_id` audit row column + the
      `:llm_call_attested` predicate's subject `name`.
    * `:principal_kind` — `:obo_human | :service_account | :autonomous`.
      Classified from claims. `LlmCallRecord.principal_kind` is a
      closed enum string; `principal_kind_to_string/1` on the call site
      converts.
    * `:chatgpt_account_id` — the `chatgpt_account_id` claim (or
      `account_id` legacy alias) when present. Codex CLI sets this as
      a request header for ChatGPT-Enterprise tokens. Absent for
      non-Enterprise (Plus / Pro) tokens.
    * `:claims` — the entire decoded payload as a plain string-keyed
      map. The proxy doesn't use this directly today, but it's the
      raw claim set so future extensions (token_use, scope-based
      gate context) don't need to re-decode.
    * `:principal_source` — where the identity came from (spec 012 S4
      review): `:jwt` (peeked from the bearer's payload), or
      `:client_metadata` (Claude Code's `metadata.user_id`, a
      client-asserted value corroborated only by the upstream accepting
      the presented bearer). The proxy's synthetic fallback is
      `:anonymous`; `:mtls_svid` is reserved for a future SPIFFE path
      and is never produced today. Recorded on the predicate + receipt
      tags so a verifier can weigh the identity claim.
  """
  @type principal :: %{
          principal_id: String.t(),
          principal_kind: :obo_human | :service_account | :autonomous,
          chatgpt_account_id: String.t() | nil,
          claims: map(),
          principal_source: principal_source()
        }

  @typedoc "Provenance of a principal identity. See `t:principal/0`."
  @type principal_source :: :jwt | :client_metadata | :mtls_svid | :anonymous

  @principal_sources [:jwt, :client_metadata, :mtls_svid, :anonymous]

  # Claude Code's `account_uuid` is an RFC 4122 UUID (8-4-4-4-12 hex).
  # Enforcing the layout is what makes `claude-code:<uuid>` safe to
  # interpolate into a Cedar entity id: no quote, backslash, newline or
  # other control byte can survive it.
  # `\A`/`\z`, not `^`/`$`: `$` also matches before a trailing newline.
  @uuid_re ~r/\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z/

  require Logger

  @typedoc """
  Failure modes:
    * `:no_authorization` — header absent or non-Bearer scheme. The
      LLM proxy can be reached pre-auth in some test rigs; this is the
      "fall back to :anonymous" signal.
    * `:malformed_jwt` — token doesn't decode. Defensive — Codex's
      tokens are well-formed; this catches local corruption + paste
      errors.
    * `:missing_sub_claim` — payload decoded but no `sub`. Should not
      happen with real upstream tokens; the contract requires `sub`.
  """
  @type extract_error :: :no_authorization | :malformed_jwt | :missing_sub_claim

  @doc """
  Extract a principal record from inbound HTTP headers.

  Accepts headers as either a list-of-2-tuples (Plug.Conn shape) or a
  map. Header lookup is case-insensitive per RFC 7230.
  """
  @spec extract_from_headers([{String.t(), String.t()}] | map()) ::
          {:ok, principal()} | {:error, extract_error()}
  def extract_from_headers(headers) do
    with {:ok, jwt} <- find_bearer_token(headers),
         {:ok, claims} <- decode_payload(jwt),
         {:ok, sub} <- extract_sub(claims) do
      {:ok,
       %{
         principal_id: sub,
         principal_kind: classify_kind(claims),
         chatgpt_account_id: extract_chatgpt_account_id(claims),
         claims: claims,
         principal_source: :jwt
       }}
    end
  end

  @doc """
  Wire form of a `t:principal_source/0` for predicates + receipt tags
  (`"jwt" | "client_metadata" | "mtls_svid" | "anonymous"`). Unknown or
  missing values are reported as `"anonymous"`: an identity whose
  provenance the gateway cannot name must not be recorded as stronger
  than it is.
  """
  @spec principal_source_to_string(term()) :: String.t()
  def principal_source_to_string(source) when source in @principal_sources,
    do: Atom.to_string(source)

  def principal_source_to_string(source) when is_binary(source) do
    if source in Enum.map(@principal_sources, &Atom.to_string/1), do: source, else: "anonymous"
  end

  def principal_source_to_string(_), do: "anonymous"

  @doc """
  `true` when `account` has the RFC 4122 UUID layout Claude Code uses
  for `account_uuid`. The gate builds `User::"claude-code:<account>"`
  from it, so anything outside the hex-and-dash charset is refused
  here rather than escaped later.
  """
  @spec valid_account_uuid?(term()) :: boolean()
  def valid_account_uuid?(account) when is_binary(account), do: Regex.match?(@uuid_re, account)
  def valid_account_uuid?(_), do: false

  @doc """
  Extract a principal from the headers OR the decoded request body
  (spec 012 S4).

  The JWT path (`extract_from_headers/1`) is tried first and is
  unchanged for Codex. When the bearer is not a JWT — Claude Code sends
  an opaque OAuth token (`sk-ant-oat01-…`) or an API key — the body's
  `metadata.user_id` is consulted: Claude Code encodes
  `{"device_id","account_uuid","session_id"}` as a JSON string there,
  and the principal becomes `claude-code:<account_uuid>` (`:obo_human`;
  the login is a person's subscription) with those three values as the
  observed claims. Same trust posture as the JWT peek: the upstream
  authenticates the token; the account id is what the client claimed.

  The `account_uuid` must have the RFC 4122 UUID layout
  (`valid_account_uuid?/1`); the value is client-controlled and ends up
  inside a Cedar entity id, so anything else is logged at info and
  treated as an opaque bearer (the caller substitutes its `:anonymous`
  synthetic). The account is lower-cased so one login yields one
  principal id regardless of the client's hex case.

  Errors: the JWT errors as before when the bearer is JWT-shaped;
  `:opaque_bearer` when it is not and no usable metadata exists (the
  caller logs that at debug — it is the normal API-key case).
  """
  @spec extract_from_request([{String.t(), String.t()}] | map(), map() | nil) ::
          {:ok, principal()} | {:error, extract_error() | :opaque_bearer}
  def extract_from_request(headers, request_params) do
    case extract_from_headers(headers) do
      {:ok, principal} ->
        {:ok, principal}

      {:error, :malformed_jwt} = jwt_error ->
        case {jwt_shaped_bearer?(headers), from_claude_code_metadata(request_params)} do
          {_, {:ok, principal}} -> {:ok, principal}
          {true, :error} -> jwt_error
          {false, :error} -> {:error, :opaque_bearer}
        end

      {:error, _} = error ->
        error
    end
  end

  # Claude Code: `metadata.user_id` is a JSON-encoded string.
  defp from_claude_code_metadata(%{"metadata" => %{"user_id" => user_id}})
       when is_binary(user_id) and user_id != "" do
    with {:ok, %{"account_uuid" => account} = meta} <- Jason.decode(user_id),
         :ok <- check_account_uuid(account) do
      account = String.downcase(account)

      claims =
        meta
        |> Map.take(["account_uuid", "device_id", "session_id"])
        |> Map.put("account_uuid", account)
        |> Map.put("source", "claude_code_metadata")

      {:ok,
       %{
         principal_id: "claude-code:" <> account,
         principal_kind: :obo_human,
         chatgpt_account_id: nil,
         claims: claims,
         principal_source: :client_metadata
       }}
    else
      _ -> :error
    end
  end

  defp from_claude_code_metadata(_), do: :error

  defp check_account_uuid(account) do
    if valid_account_uuid?(account) do
      :ok
    else
      # Never echo the client-controlled value itself: log its shape only.
      Logger.info(fn ->
        "principal_extractor: metadata.user_id.account_uuid is not a UUID " <>
          "(#{describe_shape(account)}); treating the bearer as opaque"
      end)

      :error
    end
  end

  defp describe_shape(v) when is_binary(v), do: "binary of #{byte_size(v)} bytes"
  defp describe_shape(_), do: "non-binary"

  # Three dot-separated segments → the caller meant a JWT; report its
  # decode failure as before. Anything else is an opaque token.
  defp jwt_shaped_bearer?(headers) do
    case find_bearer_token(headers) do
      {:ok, token} -> length(String.split(token, ".")) == 3
      _ -> false
    end
  end

  # ---------------------------------------------------------------------------
  # Header extraction
  # ---------------------------------------------------------------------------

  defp find_bearer_token(headers) when is_list(headers) do
    headers
    |> Enum.find_value(fn {name, value} ->
      if String.downcase(name) == "authorization", do: value, else: nil
    end)
    |> parse_bearer_value()
  end

  defp find_bearer_token(headers) when is_map(headers) do
    headers
    |> Enum.find_value(fn {name, value} ->
      if String.downcase(to_string(name)) == "authorization", do: value, else: nil
    end)
    |> parse_bearer_value()
  end

  defp find_bearer_token(_), do: {:error, :no_authorization}

  defp parse_bearer_value(nil), do: {:error, :no_authorization}

  defp parse_bearer_value(value) when is_binary(value) do
    case String.split(value, " ", parts: 2) do
      [scheme, token] ->
        if String.downcase(scheme) == "bearer" and token != "" do
          {:ok, String.trim(token)}
        else
          {:error, :no_authorization}
        end

      _ ->
        {:error, :no_authorization}
    end
  end

  defp parse_bearer_value(_), do: {:error, :no_authorization}

  # ---------------------------------------------------------------------------
  # JWT decode (no signature verification)
  # ---------------------------------------------------------------------------

  defp decode_payload(jwt) when is_binary(jwt) do
    case String.split(jwt, ".") do
      [_header, payload, _signature] ->
        decode_segment(payload)

      _ ->
        {:error, :malformed_jwt}
    end
  end

  defp decode_segment(segment) do
    with {:ok, json_bytes} <- url_decode(segment),
         {:ok, claims} when is_map(claims) <- Jason.decode(json_bytes) do
      {:ok, claims}
    else
      _ -> {:error, :malformed_jwt}
    end
  end

  # JWT spec uses base64url WITHOUT padding (RFC 7519 §3 + RFC 7515 §3).
  # Erlang's `Base.url_decode64/2` requires the right padding flag; we
  # try un-padded first (the canonical path), then padded (some non-
  # conformant minters add `=`).
  defp url_decode(segment) do
    case Base.url_decode64(segment, padding: false) do
      {:ok, bytes} ->
        {:ok, bytes}

      :error ->
        case Base.url_decode64(segment, padding: true) do
          {:ok, bytes} -> {:ok, bytes}
          :error -> {:error, :malformed_jwt}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Claim extraction + classification
  # ---------------------------------------------------------------------------

  defp extract_sub(%{"sub" => sub}) when is_binary(sub) and sub != "" do
    {:ok, sub}
  end

  defp extract_sub(_), do: {:error, :missing_sub_claim}

  # Some tokens use `account_id` as a legacy alias for the same value.
  defp extract_chatgpt_account_id(%{"chatgpt_account_id" => v}) when is_binary(v) and v != "",
    do: v

  defp extract_chatgpt_account_id(%{"account_id" => v}) when is_binary(v) and v != "", do: v
  defp extract_chatgpt_account_id(_), do: nil

  # Classify the principal kind from claims:
  #
  #   * `token_use: "service"` (or some variants set `token_type`) →
  #     :service_account. This is what AWS Cognito + several enterprise
  #     IdPs emit for machine identities.
  #   * `token_use: "autonomous"` OR `sub` is a SPIFFE ID → :autonomous.
  #     SPIFFE IDs always start with `spiffe://`.
  #   * Default → :obo_human. ChatGPT-Enterprise SSO tokens fall here;
  #     they don't usually carry a `token_use` claim and `sub` is a
  #     human user ID.
  defp classify_kind(claims) do
    cond do
      Map.get(claims, "token_use") == "service" -> :service_account
      Map.get(claims, "token_type") == "service_account" -> :service_account
      Map.get(claims, "token_use") == "autonomous" -> :autonomous
      spiffe_sub?(claims) -> :autonomous
      true -> :obo_human
    end
  end

  defp spiffe_sub?(%{"sub" => sub}) when is_binary(sub) do
    String.starts_with?(sub, "spiffe://")
  end

  defp spiffe_sub?(_), do: false
end
