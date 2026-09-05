defmodule Recurse.Providers.Repo.Migrations.F002SigningKeysAppendOnly do
  @moduledoc """
  Append-only enforcement for `signing_keys` per data-model.md §SigningKey:

    > Postgres trigger enforces `NO DELETE` + `UPDATE` restricted to
    > `last_seen_at` column only.

  Two triggers are installed:
    1. `enforce_signing_keys_no_delete` — rejects all DELETE.
    2. `enforce_signing_keys_update_last_seen_only` — rejects any UPDATE that
       mutates a column other than `last_seen_at`.

  Rationale: `last_seen_at` is the only sanctioned mutation (touched each
  time the Gateway observes a signing-key version being used). All other
  columns — kms_key_id, key_version, public_key_pem, algorithm, first_seen_at,
  chain_hash, inserted_at — are immutable once the row is written. The
  `chain_hash` invariant (SHA-256(prev_chain_hash || row_bytes)) is what
  gives the archive its append-only integrity guarantee at boot per the
  KMS rotation watcher (F001 FR-046 / F002 T075).
  """
  use Ecto.Migration

  def up do
    execute """
    CREATE OR REPLACE FUNCTION enforce_signing_keys_no_delete()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      RAISE EXCEPTION 'signing_keys is append-only: DELETE not permitted';
    END;
    $$;
    """

    execute """
    CREATE TRIGGER enforce_signing_keys_no_delete
      BEFORE DELETE ON signing_keys
      FOR EACH ROW
      EXECUTE FUNCTION enforce_signing_keys_no_delete();
    """

    execute """
    CREATE OR REPLACE FUNCTION enforce_signing_keys_update_last_seen_only()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      IF (NEW.id IS DISTINCT FROM OLD.id OR
          NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
          NEW.kms_key_id IS DISTINCT FROM OLD.kms_key_id OR
          NEW.key_version IS DISTINCT FROM OLD.key_version OR
          NEW.public_key_pem IS DISTINCT FROM OLD.public_key_pem OR
          NEW.algorithm IS DISTINCT FROM OLD.algorithm OR
          NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at OR
          NEW.chain_hash IS DISTINCT FROM OLD.chain_hash OR
          NEW.inserted_at IS DISTINCT FROM OLD.inserted_at) THEN
        RAISE EXCEPTION 'signing_keys is append-only except for last_seen_at';
      END IF;
      RETURN NEW;
    END;
    $$;
    """

    execute """
    CREATE TRIGGER enforce_signing_keys_update_last_seen_only
      BEFORE UPDATE ON signing_keys
      FOR EACH ROW
      EXECUTE FUNCTION enforce_signing_keys_update_last_seen_only();
    """
  end

  def down do
    execute "DROP TRIGGER IF EXISTS enforce_signing_keys_update_last_seen_only ON signing_keys;"
    execute "DROP FUNCTION IF EXISTS enforce_signing_keys_update_last_seen_only();"
    execute "DROP TRIGGER IF EXISTS enforce_signing_keys_no_delete ON signing_keys;"
    execute "DROP FUNCTION IF EXISTS enforce_signing_keys_no_delete();"
  end
end
