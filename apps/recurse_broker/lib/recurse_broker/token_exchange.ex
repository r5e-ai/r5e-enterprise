defmodule RecurseBroker.TokenExchange do
  @moduledoc """
  Plug handler for `POST /token/exchange` (F002 T088).

  Pure module-Plug (not `Plug.Router`) — `RecurseBroker.Endpoint`'s
  `post "/token/exchange"` route forwards the pre-parsed form body
  here. Implements RFC 8693 OAuth 2.0 Token Exchange per
  `contracts/recurse_broker_api.md`:

  ```
  customer-IdP id_token  --->  X-Observed-Identity JWT
  ```

  Flow (each step short-circuits on error with the RFC-shaped body):

    1. Validate request form per RFC 8693 §2.1.
    2. `OIDC.Validator.validate_id_token/2` verifies the
       `subject_token` signature + claims against the customer IdP's
       JWKS (JWKS fetched via `OIDC.DiscoveryCache`; infra errors
       distinguished from auth failures — discovery/JWKS fetch is
       `503 temporarily_unavailable` per the spec table).
    3. Derive `principal.kind`. F002 slice implements `obo_human`
       fully; `service_account` / `autonomous` are reserved for slice
       1b and surface as `401 invalid_subject_token` with
       `"kind indeterminate"`.
    4. `RoleMapper.resolve_role/2` resolves the Recurse role from the
       subject's `groups` claim; `{:error, :no_role_match_no_default}`
       → `403 unauthorized_client`.
    5. `JWT.Signer.mint/2` mints the ES256-signed
       `X-Observed-Identity` JWT using `KeyRing.current_key/0`.
    6. Respond 200 with the RFC 8693 JSON envelope
       `{access_token, issued_token_type, token_type, expires_in}`.

  ## Config / DI

  Opts (accepted by `init/1` and also auto-pulled from
  `Application.get_env(:recurse_broker, :...)` as a fallback) are
  merged at `call/2` time so updating application config via
  release-cookie reload doesn't require restarting the Endpoint:

    * `:expected_audience` — Gateway audience that `form.audience`
      MUST match, and which the minted JWT's `aud` claim is set to.
    * `:broker_issuer` — the broker's own public issuer URL
      (minted as `iss` in the output JWT).
    * `:role_mapping` — map from `RoleMapper.load_mapping_file/1`;
      Phase-1 reloaded operator-side via process restart (SIGHUP
      reload deferred — documented in
      `contracts/recurse_broker_api.md` "broker-role-mapping.yaml
      schema").
    * `:oidc_validator_opts` — forwarded to
      `OIDC.Validator.validate_id_token/2`. Minimally carries
      `:issuer` + `:audience` for the CUSTOMER IdP (not the
      Gateway audience — customer_idp_aud is whatever the customer's
      id_token `aud` claim is expected to equal; per-issuer).
    * `:validator` / `:signer` / `:role_mapper` — DI seams; default
      to `OIDC.Validator`, `JWT.Signer`, `RoleMapper`. Mox-friendly.

  ## F002 slice limits (documented for explicit hand-off to slice 1b)

    * `service_account` + `autonomous` principal kinds reject with
      `401 invalid_subject_token`, `"kind indeterminate"`. Slice 1b
      adds `azp` + configured "service" client-id lookup.
    * `aud`-based `obo_human` detection is simplified: any id_token
      with an `aud` claim is treated as `obo_human`. Full "interactive
      client-id matches" logic moves to slice 1b once the role-mapping
      YAML carries per-issuer `interactive_client_ids` lists.
    * `scope` field on the request is ignored (reserved for
      fine-grained role-within-role scoping post-F002).

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      ("POST /token/exchange", "Minted X-Observed-Identity JWT shape")
    * `specs/002-standalone-gateway-vertical-slice/research.md` D2
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T088
  """

  @behaviour Plug

  import Plug.Conn

  @grant_type_token_exchange "urn:ietf:params:oauth:grant-type:token-exchange"
  @subject_token_type_id_token "urn:ietf:params:oauth:token-type:id_token"
  @requested_token_type_jwt "urn:ietf:params:oauth:token-type:jwt"

  @default_ttl_seconds 900

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Plug.Conn{method: "POST"} = conn, opts) do
    resolved = resolve_opts(opts)

    with {:ok, form} <- extract_form(conn),
         :ok <- check_grant_type(form),
         :ok <- check_subject_token_type(form),
         :ok <- check_requested_token_type(form),
         {:ok, subject_token} <- require_subject_token(form),
         :ok <- check_audience(form, resolved.expected_audience),
         {:ok, claims} <- validate_subject_token(subject_token, resolved),
         {:ok, :obo_human} <- derive_kind(form, claims),
         {:ok, role} <- resolve_role(claims, resolved),
         {:ok, compact_jws} <- mint_access_token(claims, role, resolved) do
      respond_ok(conn, compact_jws, resolved.ttl_seconds)
    else
      {:error, http_error} -> respond_error(conn, http_error)
    end
  end

  def call(conn, _opts) do
    respond_error(conn, {405, "method_not_allowed", "POST required"})
  end

  # -- Opt resolution -------------------------------------------------------

  defp resolve_opts(opts) do
    validator = Keyword.get(opts, :validator, RecurseBroker.OIDC.Validator)
    signer = Keyword.get(opts, :signer, RecurseBroker.JWT.Signer)
    role_mapper = Keyword.get(opts, :role_mapper, RecurseBroker.RoleMapper)

    expected_audience =
      Keyword.get(opts, :expected_audience) ||
        Application.get_env(:recurse_broker, :expected_audience)

    broker_issuer =
      Keyword.get(opts, :broker_issuer) ||
        Application.get_env(:recurse_broker, :broker_issuer)

    role_mapping =
      Keyword.get(opts, :role_mapping) ||
        Application.get_env(:recurse_broker, :role_mapping)

    oidc_validator_opts =
      Keyword.get(opts, :oidc_validator_opts) ||
        Application.get_env(:recurse_broker, :oidc_validator_opts, [])

    ttl_seconds =
      Keyword.get(opts, :ttl_seconds) ||
        Application.get_env(:recurse_broker, :ttl_seconds, @default_ttl_seconds)

    %{
      validator: validator,
      signer: signer,
      role_mapper: role_mapper,
      expected_audience: expected_audience,
      broker_issuer: broker_issuer,
      role_mapping: role_mapping,
      oidc_validator_opts: oidc_validator_opts,
      ttl_seconds: ttl_seconds
    }
  end

  # -- Request validation ---------------------------------------------------

  defp extract_form(%Plug.Conn{body_params: %Plug.Conn.Unfetched{}}) do
    {:error, {400, "invalid_request", "missing form body"}}
  end

  defp extract_form(%Plug.Conn{body_params: params}) when is_map(params) do
    {:ok, params}
  end

  defp extract_form(_conn), do: {:error, {400, "invalid_request", "missing form body"}}

  defp check_grant_type(%{"grant_type" => @grant_type_token_exchange}), do: :ok

  defp check_grant_type(_form) do
    {:error,
     {400, "unsupported_grant_type",
      "only urn:ietf:params:oauth:grant-type:token-exchange supported"}}
  end

  defp check_subject_token_type(%{"subject_token_type" => @subject_token_type_id_token}), do: :ok

  defp check_subject_token_type(_form) do
    {:error, {400, "invalid_subject_token_type", "unknown subject_token_type"}}
  end

  defp check_requested_token_type(form) do
    case Map.get(form, "requested_token_type") do
      nil -> :ok
      @requested_token_type_jwt -> :ok
      _ -> {:error, {400, "invalid_request", "unsupported requested_token_type"}}
    end
  end

  defp require_subject_token(%{"subject_token" => token}) when is_binary(token) and token != "" do
    {:ok, token}
  end

  defp require_subject_token(_form) do
    {:error, {400, "invalid_request", "missing subject_token"}}
  end

  defp check_audience(%{"audience" => aud}, expected)
       when is_binary(expected) and aud == expected,
       do: :ok

  defp check_audience(_form, _expected) do
    {:error, {400, "invalid_request", "invalid audience"}}
  end

  # -- OIDC validation ------------------------------------------------------

  defp validate_subject_token(subject_token, %{
         validator: validator,
         oidc_validator_opts: validator_opts
       }) do
    case validator.validate_id_token(subject_token, validator_opts) do
      {:ok, claims} ->
        {:ok, claims}

      {:error, :jwks_fetch_failed} ->
        {:error, {503, "temporarily_unavailable", "customer IdP JWKS fetch failed"}}

      {:error, :oidc_discovery_failed} ->
        {:error, {503, "temporarily_unavailable", "customer IdP discovery failed"}}

      {:error, reason} ->
        {:error, {401, "invalid_subject_token", Atom.to_string(reason)}}
    end
  end

  # -- Principal kind -------------------------------------------------------

  # F002 slice-1: if the id_token carries an `aud` claim treat as obo_human.
  # Slice 1b will extend this to distinguish service_account (azp matches
  # configured "service" client id) + autonomous (operator-opted).
  defp derive_kind(%{"subject_token_type" => @subject_token_type_id_token}, claims) do
    case Map.get(claims, "aud") do
      nil ->
        {:error, {401, "invalid_subject_token", "kind indeterminate"}}

      _ ->
        {:ok, :obo_human}
    end
  end

  defp derive_kind(_form, _claims) do
    {:error, {401, "invalid_subject_token", "kind indeterminate"}}
  end

  # -- Role mapping ---------------------------------------------------------

  defp resolve_role(claims, %{role_mapper: role_mapper, role_mapping: role_mapping}) do
    case role_mapper.resolve_role(claims, role_mapping || %{}) do
      {:ok, role} ->
        {:ok, role}

      {:error, :no_role_match_no_default} ->
        {:error,
         {403, "unauthorized_client",
          "principal has no role mapping and no default_recurse_role configured"}}

      {:error, other} ->
        {:error, {500, "server_error", Atom.to_string(other)}}
    end
  end

  # -- JWT minting ----------------------------------------------------------

  defp mint_access_token(claims, role, resolved) do
    principal = build_principal(claims, role)

    signer_opts = [
      issuer: resolved.broker_issuer,
      audience: resolved.expected_audience,
      subject: Map.get(claims, "sub"),
      ttl_seconds: resolved.ttl_seconds,
      principal: principal
    ]

    case resolved.signer.mint(%{}, signer_opts) do
      {:ok, compact_jws} -> {:ok, compact_jws}
      {:error, _reason} -> {:error, {500, "server_error", "token mint failed"}}
    end
  end

  defp build_principal(claims, role) do
    %{
      "kind" => "obo_human",
      "issuer" => Map.get(claims, "iss"),
      "subject" => Map.get(claims, "sub"),
      "display_name" =>
        Map.get(claims, "name") ||
          Map.get(claims, "preferred_username") ||
          Map.get(claims, "sub"),
      "groups" => Map.get(claims, "groups") || [],
      "recurse_role" => role
    }
  end

  # -- Responses ------------------------------------------------------------

  defp respond_ok(conn, compact_jws, ttl_seconds) do
    body =
      Jason.encode!(%{
        "access_token" => compact_jws,
        "issued_token_type" => @requested_token_type_jwt,
        "token_type" => "Bearer",
        "expires_in" => ttl_seconds
      })

    conn
    |> put_resp_content_type("application/json", "utf-8")
    |> send_resp(200, body)
  end

  defp respond_error(conn, {status, code, description}) do
    body =
      Jason.encode!(%{
        "error" => code,
        "error_description" => description
      })

    conn
    |> put_resp_content_type("application/json", "utf-8")
    |> send_resp(status, body)
  end
end
