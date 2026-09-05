defmodule Recurse.Gateway.Admin.BrowserAuth.Schemas.OidcLoginNonce do
  @moduledoc """
  Ecto schema for the `oidc_login_nonces` table — short-lived OIDC PKCE state
  for the browser sign-in flow.

  Cross-references:
    * `specs/004-audit-console/data-model.md` §1.6 (column rationale, indices,
      lifecycle, PII handling).
    * Migration — `apps/recurse_providers/priv/repo/migrations/20260424_f004_oidc_login_nonces.exs`
      (Wave 1A, sibling task).
    * `specs/004-audit-console/contracts/browser_oidc_flow.md` Step 2 + Step 4
      — primary consumer.
    * Glossary cluster — **Audit Console / Browser Auth**.

  This entity lives in the Gateway Admin auth namespace (NOT the admin-state
  contexts above) because it is a **transient broker-side artifact** — not
  durable UI state. Lifetime: 10-minute TTL, single-use, purged eagerly.

  **Single-use lifecycle**: enforced at consume time via
  `SELECT ... FOR UPDATE WHERE state = ? AND used_at IS NULL AND expires_at >
  now()`; the consumer (auth callback handler) flips `used_at` inside the
  transaction. This schema only cast/validates the row shape; the
  consume-time race-free guard lives in the parent context module.

  This table does NOT have a `deleted_at` column — rows are hard-deleted at
  TTL purge by the `Recurse.Gateway.Admin.BrowserAuth.NoncePurger` Oban.Cron
  job. Operational scratch, not auditable state.

  **Federation note**: post-GAN review (claude #3, codex implied, gemini #4)
  the OIDC PKCE state was migrated from in-memory ETS to Postgres so a
  `/login/start` on node A and `/login/callback` on node B don't lose the
  nonce. This makes Constitution Principle I (federation-ready) genuinely
  satisfied for the browser auth path.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :id,
             :state,
             :return_to,
             :tenant_id,
             :created_at,
             :used_at,
             :expires_at,
             :inserted_at,
             :updated_at
           ]}

  schema "oidc_login_nonces" do
    field(:state, :string)
    # `code_verifier` is sensitive (PKCE secret, 10-min TTL); deliberately NOT
    # in the @derive Jason.Encoder allowlist above so it never accidentally
    # serializes into a log line or response body.
    field(:code_verifier, :string)
    field(:return_to, :string)
    field(:tenant_id, :string)
    field(:created_at, :utc_datetime_usec)
    field(:used_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required_fields [:state, :code_verifier, :return_to, :tenant_id, :created_at, :expires_at]
  @optional_fields [:used_at]

  @doc """
  Cast + validate an OidcLoginNonce row per data-model §1.6.

  Validations:
    * `state` ∈ 32..128 chars (CSRF token; UNIQUE-constrained at DB layer).
    * `code_verifier` ∈ 43..128 chars (PKCE RFC 7636 length envelope).
    * `return_to` ≤ 2048 chars and starts with `http(s)://` (sanitized
      server-side at create time against `gateway.admin.allowed_login_redirect_origins`;
      this changeset only enforces the format guard).
    * `unique_constraint(:state)` — replay protection.

  No FK constraints — `tenant_id` is a free string here (nonce creation
  predates principal authentication).
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(nonce, attrs) do
    nonce
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:state, min: 32, max: 128)
    |> validate_length(:code_verifier, min: 43, max: 128)
    |> validate_length(:return_to, max: 2048)
    |> validate_format(:return_to, ~r{^https?://})
    |> unique_constraint(:state)
  end
end
