defmodule Recurse.Gateway.AuditPlane.Authz do
  @moduledoc """
  Shared JWT + Cedar authorization pipeline for Audit Plane handlers
  (F002 T059 / T061 / T062, FR-023).

  Pure module. Given a `Plug.Conn`, the Cedar action name, a Cedar resource
  spec, and optional extra context, this module:

    1. Extracts + validates the `Authorization: Bearer <JWT>` via the
       same `IdentityContextBuilder` the Data Plane uses (FR-007).
    2. Captures a per-request Cedar bundle snapshot via
       `Recurse.Gateway.Policy.Active.current/0` (FR-010).
    3. Evaluates Cedar with the caller-supplied `(action, resource, context)`.
    4. Returns either `{:ok, conn_with_ctx, identity_ctx, bundle_ref}` or
       one of the error variants the caller converts into an HTTP
       response via the `send_*` helpers below.

  All responses use the canonical Audit-Plane error envelope
  (`Recurse.Gateway.AuditPlane.ErrorEnvelope` — flat shape:
  `error`, `error_description`, `correlation_id`, `attested_run_id`)
  — NOT the OpenAI Data-Plane shape.

  ## Per-cause error codes (MR !31 audit-pass)

  Both `send_auth_failure/2` and `send_forbidden/2` discriminate on
  the gate-error reason atom and emit a per-cause code:

    * `send_auth_failure/2` → `ERR_UNAUTHORIZED_*` (mapped via
      `Recurse.Gateway.Identity.AuthFailureReason.audit_plane_code_for/1`).
    * `send_forbidden/2` → `ERR_FORBIDDEN_TENANT` for tenant-scope
      denials (`:tenant_mismatch`, `:cross_tenant`); `ERR_FORBIDDEN`
      for generic Cedar denies.

  Per-cause codes preserve the semantic discrimination the F001-nested
  `details.auth_reason` field used to provide pre-MR-31. SIEM
  forwarders that consumed `auth_reason` migrate to grep on `error`
  (the code) instead. Cleaner: structured codes don't require
  regex-on-prose.

  ## Iron Law check (`elixir:otp-thinking`)

  No process. Every call is a pure function of its inputs. Runs on the
  Bandit-spawned request process.
  """

  alias Recurse.Gateway.AuditPlane.ErrorEnvelope
  alias Recurse.Gateway.Identity.AuthFailureReason
  alias Recurse.Gateway.Identity.IdentityContextBuilder
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.Policy.Evaluator
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Shared.IdentityContext

  @recurse_correlation_header "x-recurse-correlation-id"

  @type action :: String.t()
  @type reason :: atom() | term()

  @type resource_spec :: %{
          required(:type) => String.t(),
          required(:id) => String.t(),
          optional(:attrs) => map()
        }

  @type authz_ok :: {:ok, Plug.Conn.t(), IdentityContext.t(), PolicyBundleRef.t()}
  @type gate_error ::
          {:error, :auth_failed, reason()}
          | {:error, :forbidden, reason()}
          | {:error, :bundle_not_loaded, reason()}
          | {:error, :rate_limited, Plug.Conn.t()}
  @type authz_err :: gate_error()

  @doc """
  Gate a request against the Audit Plane's authn + authz pipeline.

  On success, the returned `conn` has the correlation ID stamped on the
  response headers (so even a later handler failure still carries
  observability) and `:identity_ctx` in `conn.assigns`.
  """
  @spec gate(Plug.Conn.t(), action(), resource_spec(), map()) ::
          authz_ok() | authz_err()
  def gate(conn, action, resource, extra_context \\ %{})
      when is_binary(action) and is_map(resource) and is_map(extra_context) do
    with {:ok, conn_with_ctx, ctx} <- authenticate(conn),
         {:ok, conn_after_ratelimit} <- rate_limit(conn_with_ctx),
         {:ok, bundle_ref} <- fetch_bundle(),
         :allowed <- evaluate_cedar(bundle_ref, ctx, action, resource, extra_context) do
      {:ok, conn_after_ratelimit, ctx, bundle_ref}
    end
  end

  # F002 T092 / FR-030 — per-tenant rate limit for the Audit Plane. The
  # plug halts the conn + sends a 429 with the F001 error envelope on
  # breach; we detect that via `conn.halted == true` and short-circuit
  # the `with` chain into `{:error, :rate_limited, conn}` so callers
  # return the halted conn as-is (do NOT re-send). Disabled (pass-through)
  # when `:rate_limit_enabled?` is false (the common test-suite posture).
  defp rate_limit(conn) do
    if Application.get_env(:recurse_gateway, :rate_limit_enabled?, false) do
      opts =
        Application.get_env(:recurse_gateway, :audit_rate_limit, [])
        |> Keyword.put_new(:plane, :audit)
        |> Keyword.put_new(:limit, 120)

      plug_opts = Recurse.Gateway.Plug.RateLimiter.init(opts)
      limited_conn = Recurse.Gateway.Plug.RateLimiter.call(conn, plug_opts)

      if limited_conn.halted do
        {:error, :rate_limited, limited_conn}
      else
        {:ok, limited_conn}
      end
    else
      {:ok, conn}
    end
  end

  # ---------------------------------------------------------------------------
  # JWT extraction + validation — mirrors Router.authenticate/1 exactly.
  # ---------------------------------------------------------------------------

  defp authenticate(conn) do
    tenant_id = ProviderRegistry.tenant_id()
    opts = Application.get_env(:recurse_gateway, :jwt_validator_opts, [])

    case IdentityContextBuilder.build(conn.req_headers, tenant_id, opts) do
      {:ok, ctx} ->
        conn_with_ctx =
          conn
          |> Plug.Conn.put_resp_header(@recurse_correlation_header, ctx.correlation_id)
          |> Plug.Conn.assign(:identity_ctx, ctx)

        {:ok, conn_with_ctx, ctx}

      {:error, reason} ->
        {:error, :auth_failed, reason}
    end
  end

  defp fetch_bundle do
    case Active.current() do
      {:ok, %Active{bundle: ref}} -> {:ok, ref}
      {:error, reason} -> {:error, :bundle_not_loaded, reason}
    end
  end

  defp evaluate_cedar(bundle_ref, ctx, action, resource, extra_context) do
    request = %{
      action: action,
      resource: resource,
      context: extra_context
    }

    case Evaluator.evaluate(bundle_ref, ctx, request) do
      {:allow, _matched} -> :allowed
      {:deny, matched} -> {:error, :forbidden, matched}
    end
  end

  # ---------------------------------------------------------------------------
  # Gate-error dispatch — fan gate/4's error ADT into the matching HTTP
  # response exactly once. Adding a new gate-error arm means updating
  # exactly one call site (this function).
  # ---------------------------------------------------------------------------

  @doc """
  Dispatch a gate error into the matching HTTP response.

  Accepts the original `conn` plus the gate-error tuple returned by
  `gate/4`. For `{:error, :rate_limited, halted_conn}`, the halted
  conn is returned unchanged — the RateLimiter plug already sent the
  429 with the F001 envelope + `Retry-After` header; re-sending would
  raise `Plug.Conn.AlreadySentError`. All other arms route through
  the corresponding `send_*` helpers.

  This is the only place the gate-error ADT is pattern-matched; the
  four audit-plane handlers all collapse to a single `with … else`
  arm that calls this.
  """
  @spec dispatch_gate_error(Plug.Conn.t(), gate_error()) :: Plug.Conn.t()
  def dispatch_gate_error(_conn, {:error, :rate_limited, halted_conn}) do
    # RateLimiter.call already sent 429 + body + Retry-After; do NOT re-send.
    halted_conn
  end

  def dispatch_gate_error(conn, {:error, :auth_failed, reason}) do
    send_auth_failure(conn, reason)
  end

  def dispatch_gate_error(conn, {:error, :forbidden, matched}) do
    send_forbidden(conn, matched)
  end

  def dispatch_gate_error(conn, {:error, :bundle_not_loaded, _reason}) do
    send_service_unavailable(conn, "policy bundle not loaded")
  end

  # ---------------------------------------------------------------------------
  # Error response helpers — F001 error envelope shape.
  # ---------------------------------------------------------------------------

  @doc """
  Send an auth-failure 401 in the canonical Audit Plane error envelope
  with a per-cause code (delegates to `ErrorEnvelope.send_unauthorized/4`).

  The `code` is sourced from
  `AuthFailureReason.audit_plane_code_for/1` so SIEM forwarders can
  triage on the structured code (e.g.,
  `ERR_UNAUTHORIZED_TOKEN_EXPIRED`) without regex-on-prose against the
  description.
  """
  @spec send_auth_failure(Plug.Conn.t(), reason()) :: Plug.Conn.t()
  def send_auth_failure(conn, reason) do
    ErrorEnvelope.send_unauthorized(
      conn,
      AuthFailureReason.audit_plane_code_for(reason),
      AuthFailureReason.message_for(reason),
      []
    )
  end

  @doc """
  Send a 403 Forbidden in the canonical Audit Plane error envelope.

  Discriminates on the deny reason:

    * `:tenant_mismatch` / `:cross_tenant` — caller's tenant did not
      match the resource's tenant. Emits `ERR_FORBIDDEN_TENANT` with
      the tenant-scope description, matching the contract that
      `TenantGuard` documents in its moduledoc.
    * Anything else — generic Cedar deny. Emits `ERR_FORBIDDEN` with
      the audit-action description.
  """
  @spec send_forbidden(Plug.Conn.t(), reason()) :: Plug.Conn.t()
  def send_forbidden(conn, reason) do
    {code, description} = forbidden_code_and_message(reason)
    ErrorEnvelope.send_forbidden(conn, code, description, [])
  end

  @doc """
  Send a 503 Service Unavailable in the canonical Audit Plane error envelope
  (bundle-not-loaded).
  """
  @spec send_service_unavailable(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def send_service_unavailable(conn, reason) do
    ErrorEnvelope.send_service_unavailable(
      conn,
      "ERR_SERVICE_UNAVAILABLE",
      "Gateway unavailable: " <> reason,
      []
    )
  end

  @doc """
  Send a generic 400 Bad Request in the canonical Audit Plane error envelope.
  """
  @spec send_bad_request(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def send_bad_request(conn, message) do
    ErrorEnvelope.send_bad_request(conn, "ERR_BAD_REQUEST", message, [])
  end

  @doc """
  Send a 404 Not Found in the canonical Audit Plane error envelope.
  """
  @spec send_not_found(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def send_not_found(conn, message) do
    ErrorEnvelope.send_not_found(conn, "ERR_NOT_FOUND", message, [])
  end

  @doc """
  Send a 500 Internal Server Error in the canonical Audit Plane error envelope.

  The reason is logged via `Logger.error` at the call site (see
  `dispatch_gate_error/2`); it is NOT folded into the response
  description because operator-facing toast text on the SPA renders
  `error_description` directly to end users. `inspect(reason)` on an
  exception or struct can include error message text containing
  customer data, internal hostnames, or internal IDs. GAN review fix
  on !31 (claude_cli MEDIUM finding) — the prior implementation
  exposed this in the visible toast string; ops debugging continues
  via Logger.
  """
  @spec send_internal_error(Plug.Conn.t(), term()) :: Plug.Conn.t()
  def send_internal_error(conn, _reason) do
    ErrorEnvelope.send_internal_error(
      conn,
      "ERR_INTERNAL",
      "Internal error processing Audit Plane request",
      []
    )
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  # Tenant-scope denies (`:tenant_mismatch` from PayloadBroker /
  # ReceiptsHandler / LocalVerifyHandler / EvidenceZipBuilder, and
  # `:cross_tenant` from SessionTimelineHandler) are the same domain
  # concept — caller's tenant doesn't match the resource's tenant.
  # Both map to `ERR_FORBIDDEN_TENANT` so SIEM forwarders see one
  # stable code regardless of which handler surfaced the breach.
  defp forbidden_code_and_message(:tenant_mismatch) do
    {"ERR_FORBIDDEN_TENANT", "Caller's tenant does not match resource tenant"}
  end

  defp forbidden_code_and_message(:cross_tenant) do
    {"ERR_FORBIDDEN_TENANT", "Caller's tenant does not match resource tenant"}
  end

  defp forbidden_code_and_message(_other) do
    {"ERR_FORBIDDEN", "Caller is not authorized for this Audit Plane action"}
  end
end
