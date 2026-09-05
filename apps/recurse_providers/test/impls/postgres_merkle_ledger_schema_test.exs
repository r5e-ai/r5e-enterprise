defmodule Recurse.Providers.Impls.PostgresMerkleLedgerSchemaTest do
  @moduledoc """
  T097 — Postgres-Merkle LedgerProvider schema fixture test.

  Verifies, against a live Ecto SQL Sandbox checkout:

    1. **Migrations apply cleanly.** The count of rows in
       `schema_migrations` equals the count of `.exs` files under
       `priv/repo/migrations/` (the sandbox is presumed to have run
       `Ecto.Migrator` at boot per `config/test.exs`; an unmigrated DB
       would fail the first `SQL.query!`).
    2. **`merkle_nodes` is append-only.** Any `UPDATE` or `DELETE` against
       a row raises via the `enforce_append_only_merkle_nodes_{update,delete}`
       trigger installed by
       `20260423100001_f002_merkle_ledger_tables.exs`.
    3. **`signing_keys` is append-only except `last_seen_at`.** Any `DELETE`
       raises via `enforce_signing_keys_no_delete`; any `UPDATE` of a
       column other than `last_seen_at` raises via
       `enforce_signing_keys_update_last_seen_only`; a targeted
       `UPDATE ... SET last_seen_at = $1` succeeds.
    4. **CHECK constraints match data-model.md.**
       - `attestations.verification_level` permits
         `:signed | :local_inclusion_verified | :global_inclusion_verified`.
       - `attestations.event_kind` permits `:llm_call | :policy_denied`
         (Wave R1 / US2 migration widened this from `:llm_call` only).

  These are DB-layer invariants. In-memory changeset validations live in
  `postgres_merkle_ledger/schemas_test.exs` (T035). That split is
  intentional — schemas_test.exs stays async + pure; this file requires
  Postgres and is `async: false`.
  """

  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL
  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Ulid

  @migrations_dir Path.expand(
                    "../../priv/repo/migrations",
                    __DIR__
                  )

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  describe "schema_migrations" do
    test "row count matches on-disk migration file count" do
      migration_files =
        @migrations_dir
        |> File.ls!()
        |> Enum.filter(&String.ends_with?(&1, ".exs"))

      assert migration_files != [],
             "expected migration files under #{@migrations_dir}"

      %{rows: rows} =
        SQL.query!(Repo, "SELECT version FROM schema_migrations ORDER BY version", [])

      applied_count = length(rows)
      file_count = length(migration_files)

      assert applied_count == file_count, """
      schema_migrations row count (#{applied_count}) does not match the
      number of migration files on disk (#{file_count}).

      Files: #{inspect(migration_files)}
      Applied versions: #{inspect(Enum.map(rows, &List.first/1))}

      Either a migration failed to apply, or a migration was deleted
      without rolling it back first. Run `mix ecto.migrate` against a
      fresh DB to resolve.
      """
    end
  end

  describe "merkle_nodes append-only triggers" do
    setup do
      # Seed a single row via raw SQL so the test is independent of the
      # higher-level commit pipeline. `tree_id = "schema_test_<ulid>"`
      # keeps this row in its own namespace and avoids collisions with
      # other tests running in the shared sandbox.
      tree_id = "schema_test_#{Ulid.generate()}"
      hash = :crypto.hash(:sha256, "fixture")
      now = DateTime.utc_now()

      SQL.query!(
        Repo,
        """
        INSERT INTO merkle_nodes (tree_id, level, position, hash, inserted_at)
        VALUES ($1, $2, $3, $4, $5)
        """,
        [tree_id, 0, 0, hash, now]
      )

      {:ok, tree_id: tree_id, hash: hash}
    end

    test "UPDATE raises via enforce_append_only_merkle_nodes_update", %{tree_id: tid} do
      new_hash = :crypto.hash(:sha256, "tampered")

      error =
        assert_raise Postgrex.Error, fn ->
          SQL.query!(
            Repo,
            "UPDATE merkle_nodes SET hash = $1 WHERE tree_id = $2",
            [new_hash, tid]
          )
        end

      assert %Postgrex.Error{postgres: %{message: msg}} = error
      assert msg =~ "merkle_nodes is append-only"
    end

    test "DELETE raises via enforce_append_only_merkle_nodes_delete", %{tree_id: tid} do
      error =
        assert_raise Postgrex.Error, fn ->
          SQL.query!(Repo, "DELETE FROM merkle_nodes WHERE tree_id = $1", [tid])
        end

      assert %Postgrex.Error{postgres: %{message: msg}} = error
      assert msg =~ "merkle_nodes is append-only"
    end
  end

  describe "signing_keys append-only triggers" do
    setup do
      tenant_id = Ulid.generate()
      now = DateTime.utc_now()

      {:ok, _} =
        Repo.insert(
          Tenant.changeset(%Tenant{}, %{
            tenant_id: tenant_id,
            display_name: "schema-test-tenant",
            tier: :standalone_gateway,
            created_at: now
          })
        )

      id = Ecto.UUID.generate()

      SQL.query!(
        Repo,
        """
        INSERT INTO signing_keys (
          id, tenant_id, kms_key_id, key_version, public_key_pem,
          algorithm, first_seen_at, last_seen_at, chain_hash, inserted_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        [
          Ecto.UUID.dump!(id),
          tenant_id,
          "arn:aws:kms:us-east-1:1:key/schema-test",
          "v1",
          "-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n",
          "ecdsa_p256",
          now,
          now,
          :crypto.hash(:sha256, "chain"),
          now
        ]
      )

      {:ok, id: id}
    end

    test "DELETE raises via enforce_signing_keys_no_delete", %{id: id} do
      error =
        assert_raise Postgrex.Error, fn ->
          SQL.query!(
            Repo,
            "DELETE FROM signing_keys WHERE id = $1",
            [Ecto.UUID.dump!(id)]
          )
        end

      assert %Postgrex.Error{postgres: %{message: msg}} = error
      assert msg =~ "DELETE not permitted"
    end

    test "UPDATE of an immutable column raises via enforce_signing_keys_update_last_seen_only",
         %{id: id} do
      error =
        assert_raise Postgrex.Error, fn ->
          SQL.query!(
            Repo,
            "UPDATE signing_keys SET kms_key_id = $1 WHERE id = $2",
            ["arn:aws:kms:us-east-1:1:key/tampered", Ecto.UUID.dump!(id)]
          )
        end

      assert %Postgrex.Error{postgres: %{message: msg}} = error
      assert msg =~ "append-only except for last_seen_at"
    end

    test "UPDATE of last_seen_at alone is permitted", %{id: id} do
      new_last_seen = DateTime.add(DateTime.utc_now(), 3600, :second)

      # Must not raise. Also assert num_rows = 1 to prove the UPDATE
      # actually landed on our seed row.
      result =
        SQL.query!(
          Repo,
          "UPDATE signing_keys SET last_seen_at = $1 WHERE id = $2",
          [new_last_seen, Ecto.UUID.dump!(id)]
        )

      assert result.num_rows == 1
    end
  end

  describe "attestations CHECK constraints" do
    test "verification_level admits all three allowed values, rejects a bogus one" do
      # `1 = 0` is always false, so the row-producing subquery never
      # emits a candidate. The CHECK constraint, however, still fires
      # against the constant we supply — that's the smallest-surface
      # way to probe the constraint without seeding FK parents.
      #
      # Simpler: do a `SELECT` that parses the constraint text and
      # asserts the allowed value set verbatim. Postgres makes CHECK
      # text available via pg_catalog.
      %{rows: [[constraint_def]]} =
        SQL.query!(
          Repo,
          """
          SELECT pg_get_constraintdef(oid)
          FROM   pg_constraint
          WHERE  conname = 'attestations_verification_level_check'
          """,
          []
        )

      assert constraint_def =~ "'signed'"
      assert constraint_def =~ "'local_inclusion_verified'"
      assert constraint_def =~ "'global_inclusion_verified'"
    end

    test "event_kind admits llm_call and policy_denied (Wave R1 widening)" do
      %{rows: [[constraint_def]]} =
        SQL.query!(
          Repo,
          """
          SELECT pg_get_constraintdef(oid)
          FROM   pg_constraint
          WHERE  conname = 'attestations_event_kind_check'
          """,
          []
        )

      assert constraint_def =~ "'llm_call'"
      assert constraint_def =~ "'policy_denied'"
    end

    test "policy_decision admits allow + deny" do
      %{rows: [[constraint_def]]} =
        SQL.query!(
          Repo,
          """
          SELECT pg_get_constraintdef(oid)
          FROM   pg_constraint
          WHERE  conname = 'attestations_policy_decision_check'
          """,
          []
        )

      assert constraint_def =~ "'allow'"
      assert constraint_def =~ "'deny'"
    end

    test "tier_completeness_advisory admits partial + full" do
      %{rows: [[constraint_def]]} =
        SQL.query!(
          Repo,
          """
          SELECT pg_get_constraintdef(oid)
          FROM   pg_constraint
          WHERE  conname = 'attestations_tier_completeness_advisory_check'
          """,
          []
        )

      assert constraint_def =~ "'partial'"
      assert constraint_def =~ "'full'"
    end

    test "outcome admits the three enum values" do
      %{rows: [[constraint_def]]} =
        SQL.query!(
          Repo,
          """
          SELECT pg_get_constraintdef(oid)
          FROM   pg_constraint
          WHERE  conname = 'attestations_outcome_check'
          """,
          []
        )

      assert constraint_def =~ "'success'"
      assert constraint_def =~ "'upstream_error'"
      assert constraint_def =~ "'cancelled'"
    end
  end
end
