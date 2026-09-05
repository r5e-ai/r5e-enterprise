defmodule Recurse.Providers.Repo do
  @moduledoc """
  Ecto Repo for the Postgres-Merkle LedgerProvider reference impl.

  Scope: owns the relational state that concretizes F001's conceptual
  persistent entities (Tenant, Session, SessionEpoch, Attestation,
  PolicyBundle, SigningKey, AuditExport) plus the F002-new tables
  (merkle_nodes, global_ledger_entries, payload_outbox, jwt_jti_cache).

  This Repo is distinct from any Repo the `:recurse_runtime` app
  may own for its own session-chain CAS. Provider-Interface Neutrality
  (Constitution Principle V) means vendor-specific persistence lives
  inside the `impls/` tree; this Repo is that boundary for the Postgres
  backend.
  """
  use Ecto.Repo,
    otp_app: :recurse_providers,
    adapter: Ecto.Adapters.Postgres
end
