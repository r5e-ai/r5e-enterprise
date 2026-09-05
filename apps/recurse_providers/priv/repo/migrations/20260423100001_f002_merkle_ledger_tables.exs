defmodule Recurse.Providers.Repo.Migrations.F002MerkleLedgerTables do
  @moduledoc """
  F002-new tables for the Postgres-Merkle LedgerProvider reference impl.

  Source of truth: specs/002-standalone-gateway-vertical-slice/data-model.md,
  section "F002-new schemas".

  Tables:
    - merkle_nodes (append-only, enforced by trigger)
    - global_ledger_entries (BIGSERIAL PK; RFC 9162 sequence)
    - payload_outbox (FR-032 durable retry queue for S3 PUT reconciliation)
    - jwt_jti_cache (FR-007 bounded JWT replay cache)

  The append-only invariant on merkle_nodes is enforced by raw-SQL triggers
  (`enforce_append_only_merkle_nodes`) that RAISE EXCEPTION on any UPDATE or
  DELETE — Ecto migrations reach the Postgres layer via `execute/1`.
  """
  use Ecto.Migration

  def up do
    # --------------------------------------------------------------------- merkle_nodes
    # Append-only binary Merkle-tree node storage. Stores nodes for both
    # per-session epoch trees AND the global ledger tree under different
    # `tree_id` namespaces.
    create table(:merkle_nodes, primary_key: false) do
      add :tree_id, :string, null: false
      add :level, :smallint, null: false
      add :position, :bigint, null: false
      add :hash, :binary, null: false
      add :inserted_at, :utc_datetime_usec, null: false
    end

    # Composite PK (tree_id, level, position). Ecto doesn't express composite
    # PKs directly in `create table`, so we add it via raw SQL.
    execute "ALTER TABLE merkle_nodes ADD PRIMARY KEY (tree_id, level, position);"

    create constraint(
             :merkle_nodes,
             :merkle_nodes_hash_len,
             check: "octet_length(hash) = 32"
           )

    # Append-only invariant: no UPDATE, no DELETE. Only INSERT permitted.
    execute """
    CREATE OR REPLACE FUNCTION enforce_append_only_merkle_nodes()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      RAISE EXCEPTION 'merkle_nodes is append-only';
    END;
    $$;
    """

    execute """
    CREATE TRIGGER enforce_append_only_merkle_nodes_update
      BEFORE UPDATE ON merkle_nodes
      FOR EACH ROW
      EXECUTE FUNCTION enforce_append_only_merkle_nodes();
    """

    execute """
    CREATE TRIGGER enforce_append_only_merkle_nodes_delete
      BEFORE DELETE ON merkle_nodes
      FOR EACH ROW
      EXECUTE FUNCTION enforce_append_only_merkle_nodes();
    """

    # --------------------------------------------------------------------- global_ledger_entries
    # One row per globally-committed session epoch root. Monotonic `sequence`
    # matches RFC 9162 tree index.
    create table(:global_ledger_entries, primary_key: false) do
      add :sequence, :bigserial, primary_key: true, null: false

      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :session_id,
          references(:sessions, column: :session_id, type: :binary_id, on_delete: :restrict),
          null: false

      add :session_epoch_id,
          references(:session_epochs, column: :id, type: :binary_id, on_delete: :restrict),
          null: false

      add :session_epoch_root, :binary, null: false
      add :committed_at, :utc_datetime_usec, null: false
    end

    create index(:global_ledger_entries, [:tenant_id, :committed_at],
             name: :global_ledger_entries_tenant_committed_at_desc_index
           )

    create constraint(
             :global_ledger_entries,
             :global_ledger_entries_session_epoch_root_len,
             check: "octet_length(session_epoch_root) = 32"
           )

    # Now that global_ledger_entries exists, wire the session_epochs FK on
    # global_ledger_sequence back-reference.
    alter table(:session_epochs) do
      modify :global_ledger_sequence,
             references(:global_ledger_entries,
               column: :sequence,
               type: :bigint,
               on_delete: :restrict
             )
    end

    # --------------------------------------------------------------------- payload_outbox
    # Durable retry queue for S3 payload PUT reconciliation (FR-032).
    create table(:payload_outbox, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :run_id, :binary_id, null: false
      add :attestation_bytes, :binary, null: false
      add :payload_bytes, :binary, null: false
      add :target_uri, :string, null: false
      add :attempts, :integer, null: false, default: 0
      add :last_attempt_at, :utc_datetime_usec
      add :next_attempt_at, :utc_datetime_usec, null: false
      add :status, :string, null: false
      add :last_error, :string

      timestamps(type: :utc_datetime_usec)
    end

    create index(:payload_outbox, [:status, :next_attempt_at])

    create constraint(
             :payload_outbox,
             :payload_outbox_status_check,
             check: "status IN ('pending', 'committed', 'dead_letter')"
           )

    # --------------------------------------------------------------------- jwt_jti_cache
    # Bounded replay cache for X-Observed-Identity JWT `jti` values (FR-007).
    # Nightly cron purges rows where `exp < now() - interval '1 hour'`.
    create table(:jwt_jti_cache, primary_key: false) do
      add :jti, :string, primary_key: true, null: false
      add :iss, :string, null: false
      add :exp, :utc_datetime_usec, null: false
    end

    create index(:jwt_jti_cache, [:exp])
  end

  def down do
    # Unwire FK added in up/0 before dropping global_ledger_entries.
    drop(
      constraint(
        :session_epochs,
        "session_epochs_global_ledger_sequence_fkey"
      )
    )

    drop table(:jwt_jti_cache)
    drop table(:payload_outbox)
    drop table(:global_ledger_entries)

    execute "DROP TRIGGER IF EXISTS enforce_append_only_merkle_nodes_delete ON merkle_nodes;"
    execute "DROP TRIGGER IF EXISTS enforce_append_only_merkle_nodes_update ON merkle_nodes;"
    execute "DROP FUNCTION IF EXISTS enforce_append_only_merkle_nodes();"

    drop table(:merkle_nodes)
  end
end
