defmodule Recurse.Gateway.Identity.IdentityContextBuilder do
  @moduledoc """
  Construct an immutable `Recurse.Shared.IdentityContext.t()` from inbound
  HTTP headers at the Gateway's Data-Plane (and Audit-Plane) ingress.

  Pure module — NO state. Iron Law check (elixir-thinking):

    1. Mutable state persisting across calls? No — every call is a pure
       function of `(conn_headers, deployment_tenant_id, opts)`.
    2. Concurrent execution? No — runs on the request process.
    3. Fault isolation? No — errors are `{:error, _}`, not crashes.

  All three NO → plain functions.

  ## Flow (FR-009 + FR-026)

    1. Extract `Authorization: Bearer <jwt>` (case-insensitive header
       name per RFC 9110). Missing or malformed → `:missing_authorization`.
    2. Delegate to `Recurse.Gateway.Identity.JwtValidator.validate/2` —
       propagate any validator error atom unchanged.
    3. Materialize `%Recurse.Shared.Principal{}` from the JWT's `principal`
       custom claim per F002 FR-009 + `contracts/recurse_broker_api.md`.
    4. Compose machine identity as `{:observed_jwt_subject, %{subject,
       issuer}}` — the F001 `IdentityContext.machine_identity` field
       accepts this observed-identity shape.
    5. Extract `X-Correlation-ID` header; validate via F001's
       `Recurse.Shared.CorrelationId.validate/1`. On absent / invalid,
       mint a fresh ULID via `Recurse.Shared.CorrelationId.generate/0`.
    6. Construct the immutable `%Recurse.Shared.IdentityContext{}` struct
       (tenant_id = deployment-level config).

  The produced struct is treated read-only everywhere downstream per
  F001 FR-026 / SC-016 / `Recurse.Shared.IdentityContext` moduledoc.

  ## `opts` forwarding

  `opts` passes through to `JwtValidator.validate/2`, minus the
  Builder-internal keys. Callers typically pass:

      Recurse.Gateway.Identity.IdentityContextBuilder.build(
        conn.req_headers,
        Application.fetch_env!(:recurse_gateway, :tenant_id),
        audience: "recurse-gateway-prod",
        issuer: "https://recurse-broker.corp.example",
        known_kids: {:cache, Recurse.Gateway.Identity.JwksCache}
      )

  ## Return shape

    * `{:ok, %Recurse.Shared.IdentityContext{}}`
    * `{:error, :missing_authorization}` — no Authorization header /
      non-Bearer scheme / empty token.
    * `{:error, jwt_validator_reason}` — any atom the JwtValidator
      emits (`:token_expired`, `:invalid_audience`, `:unknown_kid`,
      etc.) is propagated verbatim.
    * `{:error, :malformed_principal}` — JWT validates but its
      `principal` claim doesn't match the FR-009 shape. Defense-in-depth
      against a mis-configured broker.

  ## Cross-references

    * `Recurse.Shared.IdentityContext` — the target struct
    * `Recurse.Shared.Principal` — the nested principal struct
    * `Recurse.Shared.CorrelationId` — header validator + ULID mint
    * `contracts/recurse_broker_api.md` — `principal` claim shape
    * F001 FR-026 (immutability), F002 FR-009 (principal shape)
  """

  alias Recurse.Gateway.Identity.JwtValidator
  alias Recurse.Shared.CorrelationId
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @builder_only_opts [
    :audience,
    :issuer,
    :known_kids,
    :seen_jtis,
    :jti_check,
    :clock_skew_seconds
  ]

  @type reason ::
          :missing_authorization
          | :malformed_principal
          | JwtValidator.reason()

  @doc """
  Build an `IdentityContext` from inbound headers.

  See moduledoc for semantics. `conn_headers` is the `Plug.Conn.req_headers`
  list shape (`[{String.t(), String.t()}]`); header names are normalized
  to lower-case per Plug convention, but we normalize defensively anyway.
  """
  @spec build([{String.t(), String.t()}], String.t(), keyword()) ::
          {:ok, IdentityContext.t()} | {:error, reason()}
  def build(conn_headers, deployment_tenant_id, opts \\ [])
      when is_list(conn_headers) and is_binary(deployment_tenant_id) do
    with {:ok, jwt} <- extract_bearer_token(conn_headers),
         validator_opts = build_validator_opts(opts),
         {:ok, claims} <- JwtValidator.validate(jwt, validator_opts),
         {:ok, principal} <- build_principal(claims),
         machine_identity <- build_machine_identity(claims),
         correlation_id <- resolve_correlation_id(conn_headers) do
      context =
        IdentityContext.new(%{
          machine_identity: machine_identity,
          principal: principal,
          tenant_id: deployment_tenant_id,
          correlation_id: correlation_id
        })

      {:ok, context}
    end
  end

  # ---------------------------------------------------------------------------
  # Authorization: Bearer extraction.
  #
  # Plug lower-cases header names but we normalize explicitly because tests
  # sometimes construct raw header lists.
  # ---------------------------------------------------------------------------

  defp extract_bearer_token(headers) do
    case find_header(headers, "authorization") do
      nil ->
        {:error, :missing_authorization}

      raw ->
        parse_bearer(String.trim(raw))
    end
  end

  defp parse_bearer("Bearer " <> token), do: non_empty_token(token)
  defp parse_bearer("bearer " <> token), do: non_empty_token(token)
  defp parse_bearer(_), do: {:error, :missing_authorization}

  defp non_empty_token(token) do
    trimmed = String.trim(token)

    if trimmed == "" do
      {:error, :missing_authorization}
    else
      {:ok, trimmed}
    end
  end

  defp find_header(headers, name) do
    needle = String.downcase(name)

    Enum.find_value(headers, fn {k, v} ->
      if String.downcase(k) == needle, do: v, else: nil
    end)
  end

  # ---------------------------------------------------------------------------
  # Validator opts conversion. The validator expects a map; we extract the
  # Builder-whitelisted keys from the keyword list callers pass.
  # ---------------------------------------------------------------------------

  defp build_validator_opts(opts) do
    opts
    |> Keyword.take(@builder_only_opts)
    |> Map.new()
  end

  # ---------------------------------------------------------------------------
  # Principal materialization from the `principal` custom claim.
  #
  # Per F002 FR-009 the broker mints `{kind, issuer, subject, display_name?,
  # groups?, recurse_role}` for obo_human. We dispatch on `kind`, falling
  # through to `:malformed_principal` if the shape is wrong — defense against
  # a mis-configured broker.
  # ---------------------------------------------------------------------------

  defp build_principal(%{"principal" => %{"kind" => "obo_human"} = claim}) do
    with {:ok, issuer} <- fetch_binary(claim, "issuer"),
         {:ok, subject} <- fetch_binary(claim, "subject") do
      principal =
        Principal.obo_human(%{
          issuer: issuer,
          subject: subject,
          display_name: Map.get(claim, "display_name"),
          groups: Map.get(claim, "groups"),
          recurse_role: Map.get(claim, "recurse_role")
        })

      {:ok, principal}
    else
      _ -> {:error, :malformed_principal}
    end
  end

  defp build_principal(%{"principal" => %{"kind" => "service_account"} = claim}) do
    with {:ok, issuer} <- fetch_binary(claim, "issuer"),
         {:ok, account_id} <- fetch_binary(claim, "account_id") do
      principal =
        Principal.service_account(%{
          issuer: issuer,
          account_id: account_id,
          scope: Map.get(claim, "scope"),
          recurse_role: Map.get(claim, "recurse_role")
        })

      {:ok, principal}
    else
      _ -> {:error, :malformed_principal}
    end
  end

  defp build_principal(%{"principal" => %{"kind" => "autonomous"} = claim}) do
    case fetch_binary(claim, "spiffe_id") do
      {:ok, spiffe_id} ->
        {:ok,
         Principal.autonomous(%{
           spiffe_id: spiffe_id,
           recurse_role: Map.get(claim, "recurse_role")
         })}

      _ ->
        {:error, :malformed_principal}
    end
  end

  defp build_principal(_claims), do: {:error, :malformed_principal}

  defp fetch_binary(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} when is_binary(value) and value != "" -> {:ok, value}
      _ -> :error
    end
  end

  # ---------------------------------------------------------------------------
  # Machine identity — per task spec, from JWT claims (observed-identity
  # mode). F001 `IdentityContext.machine_identity` accepts a map here via the
  # `{:observed_identity, map}` shape or a SPIFFE-ID string; we use the tuple
  # form so Cedar / attestation code can match on `{:observed_jwt_subject, _}`.
  # ---------------------------------------------------------------------------

  defp build_machine_identity(claims) do
    {:observed_jwt_subject,
     %{
       observed_jwt_subject: Map.get(claims, "sub"),
       issuer: Map.get(claims, "iss")
     }}
  end

  # ---------------------------------------------------------------------------
  # Correlation ID resolution.
  #
  # Accepts ULID (canonical form) or "foreign" shapes (W3C traceparent,
  # Jaeger hex, etc.) per `CorrelationId.validate/1`. Missing / malformed
  # → mint a fresh ULID. NEVER reject for invalid correlation_id — per
  # the F001 CorrelationId moduledoc, this would break cross-system
  # tracing.
  # ---------------------------------------------------------------------------

  defp resolve_correlation_id(headers) do
    case CorrelationId.validate(find_header(headers, CorrelationId.header_name())) do
      {:ok, :ulid, canonical} -> canonical
      {:ok, :foreign, original} -> original
      :error -> CorrelationId.generate()
    end
  end
end
