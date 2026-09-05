defmodule Recurse.Providers.Repo.Migrations.F004OidcLoginNonces do
  @moduledoc """
  F004 Audit Console — `oidc_login_nonces` table (browser OIDC PKCE state).

  Postgres-backed CSRF state + PKCE code_verifier for the browser OIDC login
  flow (`/login/start` → IdP → `/login/callback`). See
  specs/004-audit-console/data-model.md §1.6 and
  specs/004-audit-console/contracts/browser_oidc_flow.md Step 2 for usage.

  Added 2026-04-24 post-GAN review (claude #3, gemini #4) to replace the
  originally-specified ETS-backed in-memory state, which broke federated
  multi-node deployments (a `/login/start` on node A + `/login/callback` on
  node B = lost state = unrecoverable failed sign-in).

  This table INTENTIONALLY OMITS `deleted_at` per task T019 — operational
  scratch with hard-delete TTL (rows are eagerly purged 1 hour past
  `expires_at` by `Recurse.Gateway.Admin.BrowserAuth.NoncePurger`). Soft-delete
  semantics add no value here.

  No FK to `tenants` — nonce creation predates principal authentication; we
  don't yet know if the tenant_id presented is one we recognize.

  Indices:
    - UNIQUE (state) → primary lookup at callback (replay protection)
    - (expires_at) → drives the TTL purge sweep

  Single-use enforced via `SELECT ... FOR UPDATE WHERE state = ? AND used_at
  IS NULL AND expires_at > now()` followed by a `used_at = now()` flip.

  Sensitive columns:
    - `code_verifier` — PKCE secret; never log
    - `state` — CSRF token; not strictly PII but keep off operator logs
    - `return_to` — must match a server-side allowlist (open-redirect guard)
  """
  use Ecto.Migration

  def change do
    create table(:oidc_login_nonces, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :state, :string, null: false, size: 128
      add :code_verifier, :string, null: false, size: 128
      add :return_to, :string, null: false, size: 2048
      add :tenant_id, :string, null: false
      add :created_at, :utc_datetime_usec, null: false
      add :used_at, :utc_datetime_usec
      add :expires_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec)
    end

    # UNIQUE on `state` — primary callback lookup; replay protection.
    create unique_index(:oidc_login_nonces, [:state],
             name: :oidc_login_nonces_state_unique_index
           )

    # TTL purge sweep — `DELETE FROM ... WHERE expires_at < now() - INTERVAL '1 hour'`.
    create index(:oidc_login_nonces, [:expires_at],
             name: :oidc_login_nonces_expires_at_index
           )
  end
end
