defmodule Recurse.Providers.Repo.Migrations.F002InitialSchemas do
  @moduledoc """
  F002 initial relational schemas — the seven F001-conceptual entities landing
  as concrete Postgres tables under the Postgres-Merkle LedgerProvider
  reference impl.

  Source of truth: specs/002-standalone-gateway-vertical-slice/data-model.md,
  section "F001-conceptual schemas, now concrete under PostgresMerkleLedger".

  Scope:
    - tenants
    - sessions
    - session_epochs
    - attestations
    - policy_bundles
    - signing_keys
    - audit_exports

  Out of scope (landed in sibling migrations):
    - merkle_nodes / global_ledger_entries / payload_outbox / jwt_jti_cache
      → 20260423100001_f002_merkle_ledger_tables.exs
    - signing_keys append-only triggers → 20260423100002_f002_signing_keys_append_only.exs
  """
  use Ecto.Migration

  def change do
    # --------------------------------------------------------------------- tenants
    # ULID string PK — matches Tier Configuration `tenant_id` (FR-031).
    # Single-tenant marker per FR-019; one row per deployment.
    create table(:tenants, primary_key: false) do
      add :tenant_id, :string, primary_key: true, null: false
      add :display_name, :string, null: false
      add :tier, :string, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    # Enum check for tier — standalone_gateway only in F002;
    # managed_saas / vpc_runner / appliance reserved.
    create constraint(
             :tenants,
             :tenants_tier_check,
             check:
               "tier IN ('standalone_gateway', 'managed_saas', 'vpc_runner', 'appliance')"
           )

    # --------------------------------------------------------------------- sessions
    # Bounded unit per F001 FR-036 / F002 FR-016. Under "1 run = 1 session"
    # heuristic, one row per Gateway-traversing call.
    create table(:sessions, primary_key: false) do
      add :session_id, :binary_id, primary_key: true, null: false

      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :session_scope, :string, null: false
      add :state, :string, null: false
      add :session_start, :utc_datetime_usec, null: false
      add :session_end, :utc_datetime_usec
      add :agent_spiffe_id, :string
      add :principal_kind, :string, null: false
      add :principal_canonical, :binary, null: false

      add :interim_commit_event_count, :integer, null: false, default: 10_000
      add :interim_commit_threshold_minutes, :integer, null: false, default: 60

      timestamps(type: :utc_datetime_usec)
    end

    create index(:sessions, [:tenant_id, :state])

    create constraint(
             :sessions,
             :sessions_session_scope_check,
             check: "session_scope IN ('discovery_session')"
           )

    create constraint(
             :sessions,
             :sessions_state_check,
             check:
               "state IN ('active', 'interim_committed', 'commit_retry', " <>
                 "'commit_retry_exhausted', 'aborted', 'cancelled', 'committed')"
           )

    create constraint(
             :sessions,
             :sessions_principal_kind_check,
             check: "principal_kind IN ('obo_human', 'service_account', 'autonomous')"
           )

    # --------------------------------------------------------------------- session_epochs
    # One row per session epoch. Under 1-run-1-session, every row has
    # epoch_index = 0 and event_count = 1.
    create table(:session_epochs, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false

      add :session_id,
          references(:sessions, column: :session_id, type: :binary_id, on_delete: :restrict),
          null: false

      add :epoch_index, :integer, null: false
      add :epoch_root, :binary, null: false
      add :epoch_start_at, :utc_datetime_usec, null: false
      add :epoch_end_at, :utc_datetime_usec
      add :committed_at, :utc_datetime_usec
      # global_ledger_sequence FK wired in the next migration (global_ledger_entries
      # does not exist yet at this point).
      add :global_ledger_sequence, :bigint
      add :event_count, :integer, null: false, default: 0

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:session_epochs, [:session_id, :epoch_index])

    # epoch_root is SHA-256 → 32 bytes.
    create constraint(
             :session_epochs,
             :session_epochs_epoch_root_len,
             check: "octet_length(epoch_root) = 32"
           )

    # --------------------------------------------------------------------- attestations
    # One row per emitted Attestation Envelope per F001 FR-021 + F002 FR-014.
    create table(:attestations, primary_key: false) do
      # Signed-predicate columns (immutable once written).
      add :run_id, :binary_id, primary_key: true, null: false

      add :session_id,
          references(:sessions, column: :session_id, type: :binary_id, on_delete: :restrict),
          null: false

      add :turn_id, :binary_id, null: false
      add :event_kind, :string, null: false
      add :machine_identity, :map, null: false
      add :principal, :map, null: false

      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :policy_canonical_hash, :binary, null: false
      add :payload_hash, :binary, null: false
      add :payload_uri, :string, null: false
      add :correlation_id, :string, null: false
      add :signer_kms_key_id, :string, null: false
      add :signer_key_version, :string, null: false
      add :timestamp, :utc_datetime_usec, null: false
      add :signed_predicate_bytes, :binary, null: false
      add :dsse_signature, :binary, null: false

      # Outer-container columns (mutable as verification_level advances).
      add :verification_level, :string, null: false
      add :tier_completeness_advisory, :string, null: false
      add :session_chain_root, :binary
      add :session_chain_epoch, :integer, null: false, default: 0
      add :local_inclusion_proof, :binary
      add :global_inclusion_proof, :binary
      add :commit_retry_exhausted, :boolean, null: false, default: false
      add :policy_decision, :string, null: false
      add :outcome, :string, null: false
      add :upstream_status_code, :integer

      timestamps(type: :utc_datetime_usec)
    end

    create index(:attestations, [:tenant_id, :inserted_at],
             name: :attestations_tenant_inserted_at_desc_index
           )

    create index(:attestations, [:session_id])
    create index(:attestations, [:verification_level])
    create index(:attestations, [:policy_canonical_hash])

    # Partial index for ops dashboards per data-model.md.
    create index(:attestations, [:inserted_at],
             name: :attestations_upstream_error_index,
             where: "outcome = 'upstream_error'"
           )

    create constraint(
             :attestations,
             :attestations_event_kind_check,
             check: "event_kind IN ('llm_call')"
           )

    create constraint(
             :attestations,
             :attestations_verification_level_check,
             check:
               "verification_level IN ('signed', 'local_inclusion_verified', 'global_inclusion_verified')"
           )

    create constraint(
             :attestations,
             :attestations_tier_completeness_advisory_check,
             check: "tier_completeness_advisory IN ('partial', 'full')"
           )

    create constraint(
             :attestations,
             :attestations_policy_decision_check,
             check: "policy_decision IN ('allow', 'deny')"
           )

    create constraint(
             :attestations,
             :attestations_outcome_check,
             check: "outcome IN ('success', 'upstream_error', 'cancelled')"
           )

    create constraint(
             :attestations,
             :attestations_policy_canonical_hash_len,
             check: "octet_length(policy_canonical_hash) = 32"
           )

    create constraint(
             :attestations,
             :attestations_payload_hash_len,
             check: "octet_length(payload_hash) = 32"
           )

    create constraint(
             :attestations,
             :attestations_session_chain_root_len,
             check: "session_chain_root IS NULL OR octet_length(session_chain_root) = 32"
           )

    # --------------------------------------------------------------------- policy_bundles
    # One row per Cedar policy bundle version loaded by the Gateway.
    create table(:policy_bundles, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false

      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :policy_canonical_hash, :binary, null: false
      add :bundle_bytes, :binary, null: false
      add :cedar_version, :string, null: false
      add :loaded_at, :utc_datetime_usec, null: false
      add :source, :string, null: false
    end

    create index(:policy_bundles, [:policy_canonical_hash])

    create constraint(
             :policy_bundles,
             :policy_bundles_source_check,
             check: "source IN ('filesystem')"
           )

    create constraint(
             :policy_bundles,
             :policy_bundles_policy_canonical_hash_len,
             check: "octet_length(policy_canonical_hash) = 32"
           )

    # --------------------------------------------------------------------- signing_keys
    # Append-only archive of every KMS signing-key version used per F001 FR-046
    # + F002 FR-015. The append-only trigger is installed in the next migration.
    create table(:signing_keys, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false

      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :kms_key_id, :string, null: false
      add :key_version, :string, null: false
      add :public_key_pem, :binary, null: false
      add :algorithm, :string, null: false
      add :first_seen_at, :utc_datetime_usec, null: false
      add :last_seen_at, :utc_datetime_usec, null: false
      add :chain_hash, :binary, null: false
      add :inserted_at, :utc_datetime_usec, null: false
    end

    create unique_index(:signing_keys, [:kms_key_id, :key_version])

    create constraint(
             :signing_keys,
             :signing_keys_chain_hash_len,
             check: "octet_length(chain_hash) = 32"
           )

    # --------------------------------------------------------------------- audit_exports
    # One row per Export Evidence zip produced (audit trail of exports).
    create table(:audit_exports, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false

      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :exporter_principal_subject, :string, null: false
      add :exporter_principal_role, :string, null: false
      add :run_ids, {:array, :string}, null: false
      add :zip_sha256, :binary, null: false
      add :exported_at, :utc_datetime_usec, null: false
    end

    create index(:audit_exports, [:tenant_id, :exported_at])

    create constraint(
             :audit_exports,
             :audit_exports_zip_sha256_len,
             check: "octet_length(zip_sha256) = 32"
           )
  end
end
