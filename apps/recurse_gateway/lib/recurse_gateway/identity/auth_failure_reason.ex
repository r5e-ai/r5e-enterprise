defmodule Recurse.Gateway.Identity.AuthFailureReason do
  @moduledoc """
  Single source of truth for the human-readable description AND the
  machine-readable code that map from a JWT-validation failure reason
  (an atom returned by `IdentityContextBuilder.build/3` /
  `JwtValidator.validate/3`) to the values shipped on the wire.

  ## Why this module exists (Constitution Principle VII)

  Before this module landed, `auth_failure_message/1` was duplicated
  verbatim across two emit sites:

    * `Recurse.Gateway.Router.send_auth_failure/2` (Data Plane —
      OpenAI-shaped 401 with `code: Atom.to_string(reason)` and the
      message rendered into the OpenAI envelope).
    * `Recurse.Gateway.AuditPlane.Authz.send_auth_failure/2` (Audit
      Plane — F001 envelope with `error: "ERR_UNAUTHORIZED"` and the
      message rendered into the canonical SPA envelope).

  Adding a new validation reason (a new atom from
  `IdentityContextBuilder`) required editing both modules in lockstep.
  This module is the second-consumer extraction.

  In addition, MR !31 of the audit-pass-resolver-consolidation branch
  collapsed the F001-nested `details.auth_reason` field that
  Audit-Plane SIEM forwarders had been able to grep. To preserve the
  semantic discrimination that field used to provide, the Audit Plane
  now emits a per-cause error code (`ERR_UNAUTHORIZED_TOKEN_EXPIRED`
  vs `ERR_UNAUTHORIZED_INVALID_SIGNATURE` etc.) instead of a single
  generic `ERR_UNAUTHORIZED`. The mapping lives here.

  ## Canonical reasons

  The atoms below are what `IdentityContextBuilder.build/3` returns
  on `{:error, reason}`. New atoms get added here first; both Audit-
  Plane and Data-Plane emit sites pick up the new mapping for free.

    * `:missing_authorization` — no Bearer header, or malformed.
    * `:token_expired`         — `exp` claim is in the past.
    * `:invalid_signature`     — JWT signature does not verify.
    * `:invalid_audience`      — `aud` does not match the gateway's
      configured audience.
    * `:invalid_issuer`        — `iss` does not match the configured
      issuer.
    * `:unknown_kid`           — `kid` is not present in the gateway's
      JWKS cache.
    * `:malformed_principal`   — the JWT validates but the principal
      claims (sub, recurse_role, …) cannot be projected to an
      `IdentityContext`.

  Any other atom (or term) is treated as a generic auth failure.

  ## Iron Law

  Pure module. No process. Pattern-match dispatch on the atom; both
  functions are tail-callable and inline-friendly.
  """

  @typedoc """
  The atoms `IdentityContextBuilder.build/3` returns on
  `{:error, reason}`. We accept any term here so the helpers also
  handle the catch-all "unknown reason" case (defensive against
  surprise atoms from upstream changes).
  """
  @type reason :: atom() | term()

  @doc """
  Map a validation reason to the human-readable description rendered
  into the response body (Audit Plane: `error_description`; Data
  Plane: `error.message`).
  """
  @spec message_for(reason()) :: String.t()
  def message_for(:missing_authorization),
    do: "Missing or malformed Authorization header"

  def message_for(:token_expired), do: "JWT has expired"
  def message_for(:invalid_signature), do: "JWT signature is invalid"
  def message_for(:invalid_audience), do: "JWT audience is not accepted"
  def message_for(:invalid_issuer), do: "JWT issuer is not accepted"
  def message_for(:unknown_kid), do: "JWT signing key is not recognized"
  def message_for(:malformed_principal), do: "JWT principal claim is malformed"
  def message_for(_), do: "Authentication failed"

  @doc """
  Map a validation reason to the canonical Audit-Plane error code.

  Per-cause codes preserve the semantic discrimination the F001-nested
  `details.auth_reason` field used to provide pre-MR-31. SIEM
  forwarders that consumed `auth_reason` migrate to grep on `error`
  (the code) instead — cleaner contract since structured codes don't
  require regex-on-prose.

  Data-Plane emit sites (`Router.send_auth_failure/2`) use the OpenAI
  `error.code` shape with `Atom.to_string(reason)` instead — the same
  semantic discrimination via a different field, because the OpenAI
  protocol is non-negotiable on the Data Plane.
  """
  @spec audit_plane_code_for(reason()) :: String.t()
  def audit_plane_code_for(:missing_authorization), do: "ERR_UNAUTHORIZED_MISSING"
  def audit_plane_code_for(:token_expired), do: "ERR_UNAUTHORIZED_TOKEN_EXPIRED"
  def audit_plane_code_for(:invalid_signature), do: "ERR_UNAUTHORIZED_INVALID_SIGNATURE"
  def audit_plane_code_for(:invalid_audience), do: "ERR_UNAUTHORIZED_INVALID_AUDIENCE"
  def audit_plane_code_for(:invalid_issuer), do: "ERR_UNAUTHORIZED_INVALID_ISSUER"
  def audit_plane_code_for(:unknown_kid), do: "ERR_UNAUTHORIZED_UNKNOWN_KID"
  def audit_plane_code_for(:malformed_principal), do: "ERR_UNAUTHORIZED_MALFORMED_PRINCIPAL"
  def audit_plane_code_for(_), do: "ERR_UNAUTHORIZED"
end
