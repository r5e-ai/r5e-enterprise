defmodule Recurse.Providers.Impls.PostgresMerkleLedgerTest do
  @moduledoc """
  T033 real-DB contract tests for
  `Recurse.Providers.Impls.PostgresMerkleLedger`.

  Runs against the Ecto SQL Sandbox (configured in `config/test.exs`) — each
  test checks out a fresh connection so DB state is isolated per-test. Tests
  that rely on Phoenix.PubSub broadcasts use `async: false` so subscriber
  registrations across tests don't cross-talk; the Repo sandbox is still
  per-test.
  """

  use ExUnit.Case, async: false

  import Ecto.Query, only: [from: 2]

  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.MerkleTree

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.{
    Attestation,
    GlobalLedgerEntry,
    MerkleNode,
    Session,
    SessionEpoch,
    Tenant
  }

  alias Recurse.Providers.Repo
  alias Recurse.Shared.Attestation.{Envelope, OuterContainer, SignedPredicate}
  alias Recurse.Shared.Ulid

  @topic "recurse:attestation_first_committed"

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    {:ok, state} = PostgresMerkleLedger.init(%{})
    %{state: state}
  end

  describe "init/1" do
    test "returns {:ok, state} with repo + pubsub names", %{state: state} do
      assert %{repo: Recurse.Providers.Repo, pubsub: Recurse.PubSub} = state
    end
  end

  describe "capabilities/1" do
    test "advertises commit_epoch + rfc9162_native", %{state: state} do
      caps = PostgresMerkleLedger.capabilities(state)
      assert :commit_epoch in caps
      assert :rfc9162_native in caps
    end
  end

  describe "healthcheck/1" do
    test "returns :ok when Repo is reachable", %{state: state} do
      assert :ok = PostgresMerkleLedger.healthcheck(state)
    end
  end

  describe "commit_attestation/2" do
    test "writes attestation + merkle leaves + advances to :global_inclusion_verified" do
      envelope = build_envelope()
      sp = envelope.signed_predicate

      assert {:ok, result} = PostgresMerkleLedger.commit_attestation(envelope)
      assert result.run_id == sp.run_id
      assert result.verification_level == :global_inclusion_verified
      assert byte_size(result.session_chain_root) == 32
      assert is_binary(result.global_inclusion_proof)

      # Attestation row persisted with final verification_level.
      assert %Attestation{
               verification_level: :global_inclusion_verified,
               session_chain_root: root,
               global_inclusion_proof: proof
             } = Repo.get(Attestation, sp.run_id)

      assert byte_size(root) == 32
      assert is_binary(proof)

      # Session + epoch rows materialized.
      assert %Session{tenant_id: tid} = Repo.get(Session, sp.session_id)
      assert tid == sp.tenant_id

      assert %SessionEpoch{epoch_root: ^root, epoch_end_at: %DateTime{}} =
               Repo.one!(from(se in SessionEpoch, where: se.session_id == ^sp.session_id))

      # Session-tree leaf present.
      tree_id = "session_#{sp.session_id}_epoch_0"

      assert %MerkleNode{hash: ^root} =
               Repo.get_by(MerkleNode, tree_id: tree_id, level: 0, position: 0)

      # Global ledger advanced exactly once in this transaction's scope.
      # Note: BIGSERIAL `sequence` advances non-transactionally (prior
      # sandbox-rolled-back tests may have incremented it), so assert on
      # row-count + the session_epoch_root linkage rather than `sequence`.
      assert [%GlobalLedgerEntry{session_epoch_root: ^root}] =
               Repo.all(from(g in GlobalLedgerEntry, order_by: g.sequence))

      # Global leaf matches hash_leaf(epoch_root) at position 0 (first
      # visible leaf in this transaction).
      expected_global_leaf = MerkleTree.hash_leaf(root)

      assert %MerkleNode{hash: ^expected_global_leaf} =
               Repo.get_by(MerkleNode, tree_id: "global", level: 0, position: 0)
    end

    test "fires a single :first_committed PubSub broadcast on success" do
      :ok = Phoenix.PubSub.subscribe(Recurse.PubSub, @topic)
      envelope = build_envelope()
      run_id = envelope.signed_predicate.run_id

      assert {:ok, %{run_id: ^run_id}} = PostgresMerkleLedger.commit_attestation(envelope)

      assert_receive {:first_committed, ^run_id, payload}, 1_000
      assert payload.verification_level == :global_inclusion_verified
      refute_receive {:first_committed, ^run_id, _}, 50
    end

    test "does NOT broadcast when the transaction rolls back" do
      :ok = Phoenix.PubSub.subscribe(Recurse.PubSub, @topic)
      envelope = build_envelope()
      run_id = envelope.signed_predicate.run_id

      assert {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

      # Drain the success broadcast so it doesn't confuse the refute_receive.
      assert_receive {:first_committed, ^run_id, _}, 1_000

      # Second attempt re-uses the same run_id → PK conflict on `attestations`.
      assert {:error, {:attestation, _reason}} =
               PostgresMerkleLedger.commit_attestation(envelope)

      refute_receive {:first_committed, ^run_id, _}, 100
    end
  end

  describe "commit_epoch/4 (behaviour callback)" do
    test "appends a pre-computed root + advances global tree size", %{state: state} do
      # Seed a session + epoch directly (narrow callback doesn't own that setup).
      tenant_id = seed_tenant()
      session_id = seed_session(tenant_id)
      epoch_root = :crypto.hash(:sha256, "synthetic-epoch-#{Ulid.generate()}")
      %SessionEpoch{id: _} = seed_session_epoch(session_id, epoch_root)

      assert {:ok, %{index: 1, tree_size: 1, root: root}} =
               PostgresMerkleLedger.commit_epoch(state, session_id, 0, epoch_root)

      assert Repo.aggregate(GlobalLedgerEntry, :count, :sequence) == 1
      # Single-leaf tree: root == hash_leaf(epoch_root).
      assert root == MerkleTree.hash_leaf(epoch_root)
    end
  end

  describe "inclusion_proof/3" do
    test "round-trips through MerkleTree.verify_inclusion_proof", %{state: state} do
      envelope = build_envelope()
      assert {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

      # Reload session_epoch_root from DB so we verify the on-disk leaf.
      # Use current_root/1 for the tree_size — it counts visible rows
      # (BIGSERIAL `sequence` can have gaps from prior sandboxed-rollbacks).
      [%GlobalLedgerEntry{session_epoch_root: stored_root}] =
        Repo.all(from(g in GlobalLedgerEntry, order_by: g.sequence))

      {:ok, %{tree_size: tree_size, root: expected_root}} =
        PostgresMerkleLedger.current_root(state)

      # Single visible leaf → position 0, tree_size 1.
      assert tree_size == 1

      assert {:ok, proof_bytes} = PostgresMerkleLedger.inclusion_proof(state, 0, tree_size)

      {:ok, %{inclusion_path: path, tree_size: ^tree_size, leaf_index: 0}} =
        Recurse.Shared.Attestation.Rfc9162.decode(proof_bytes)

      assert MerkleTree.verify_inclusion_proof(
               stored_root,
               0,
               tree_size,
               path,
               expected_root
             )
    end
  end

  describe "query_paginated/1 (T059 / FR-021)" do
    test "returns an empty page when no attestations exist" do
      assert {:ok, %{rows: [], next_cursor: nil}} = PostgresMerkleLedger.query_paginated(%{})
    end

    test "returns committed attestations + filters by run_id" do
      envelope_1 = build_envelope()
      envelope_2 = build_envelope()
      run_id_1 = envelope_1.signed_predicate.run_id
      run_id_2 = envelope_2.signed_predicate.run_id

      assert {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope_1)
      assert {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope_2)

      # Unfiltered: both rows visible.
      assert {:ok, %{rows: rows, next_cursor: nil}} = PostgresMerkleLedger.query_paginated(%{})
      assert length(rows) == 2
      assert Enum.any?(rows, &(&1.run_id == run_id_1))
      assert Enum.any?(rows, &(&1.run_id == run_id_2))

      # Filter by run_id.
      assert {:ok, %{rows: [row]}} = PostgresMerkleLedger.query_paginated(%{run_id: run_id_1})
      assert row.run_id == run_id_1
    end

    test "returns a cursor when more than `limit` rows exist; second page excludes prior" do
      # Commit three attestations, ask for pages of 2.
      envelopes = for _ <- 1..3, do: build_envelope()
      for e <- envelopes, do: assert({:ok, _} = PostgresMerkleLedger.commit_attestation(e))

      assert {:ok, %{rows: rows_page_1, next_cursor: cursor}} =
               PostgresMerkleLedger.query_paginated(%{limit: 2})

      assert length(rows_page_1) == 2
      assert is_binary(cursor)

      assert {:ok, %{rows: rows_page_2, next_cursor: nil}} =
               PostgresMerkleLedger.query_paginated(%{limit: 2, cursor: cursor})

      assert length(rows_page_2) == 1

      # No overlap between pages.
      ids_1 = MapSet.new(rows_page_1, & &1.run_id)
      ids_2 = MapSet.new(rows_page_2, & &1.run_id)
      assert MapSet.intersection(ids_1, ids_2) |> MapSet.size() == 0
    end

    test "rejects a malformed cursor" do
      assert {:error, :invalid_cursor} =
               PostgresMerkleLedger.query_paginated(%{cursor: "not-base64-encoded-json"})
    end
  end

  describe "force_commit_for_run_ids/2 (T060 / FR-017)" do
    test "short-circuits for a receipt already at :global_inclusion_verified", %{state: state} do
      envelope = build_envelope()
      run_id = envelope.signed_predicate.run_id

      assert {:ok, %{verification_level: :global_inclusion_verified, session_chain_root: root}} =
               PostgresMerkleLedger.commit_attestation(envelope)

      assert {:ok, outcomes} = PostgresMerkleLedger.force_commit_for_run_ids(state, [run_id])
      assert %{^run_id => {:already_global_inclusion_verified, ^root}} = outcomes
    end

    test "advances a :signed attestation to :global_inclusion_verified", %{state: state} do
      envelope = build_envelope()
      run_id = envelope.signed_predicate.run_id

      # Commit attestation, then force it BACK to :signed to simulate a receipt
      # that stalled before reaching the global level.
      assert {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

      {:ok, _} =
        Attestation
        |> Repo.get!(run_id)
        |> Attestation.changeset(%{verification_level: :signed, global_inclusion_proof: nil})
        |> Repo.update()

      assert {:ok, %{^run_id => :committed}} =
               PostgresMerkleLedger.force_commit_for_run_ids(state, [run_id])

      assert %Attestation{verification_level: :global_inclusion_verified} =
               Repo.get(Attestation, run_id)
    end

    test "returns {:error, {run_id, :not_found}} when a run_id is unknown", %{state: state} do
      unknown = Ecto.UUID.generate()

      assert {:error, {^unknown, :not_found}} =
               PostgresMerkleLedger.force_commit_for_run_ids(state, [unknown])
    end
  end

  describe "generate_inclusion_proof/1 (T064 / FR-022)" do
    test "returns TransItem bytes that round-trip through the Rfc9162 decoder" do
      envelope = build_envelope()
      run_id = envelope.signed_predicate.run_id

      assert {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

      assert {:ok, %{session_chain: sc, global: g}} =
               PostgresMerkleLedger.generate_inclusion_proof(run_id)

      assert is_binary(sc) and byte_size(sc) > 0
      assert is_binary(g) and byte_size(g) > 0

      assert {:ok, %{type: :inclusion_v1, tree_size: 1, leaf_index: 0, inclusion_path: []}} =
               Recurse.Shared.Attestation.Rfc9162.decode(sc)

      assert {:ok, %{type: :inclusion_v1, tree_size: ts, leaf_index: idx}} =
               Recurse.Shared.Attestation.Rfc9162.decode(g)

      assert ts >= 1
      assert idx >= 0 and idx < ts
    end

    test "returns {:error, :not_found} for an unknown run_id" do
      assert {:error, :not_found} =
               PostgresMerkleLedger.generate_inclusion_proof(Ecto.UUID.generate())
    end
  end

  # -- Fixtures --------------------------------------------------------------

  defp build_envelope do
    tenant_id = Ulid.generate()
    session_id = Ecto.UUID.generate()
    run_id = Ecto.UUID.generate()

    # Ensure the tenant exists so the session FK resolves.
    {:ok, _} =
      Repo.insert(
        Tenant.changeset(%Tenant{}, %{
          tenant_id: tenant_id,
          display_name: "test",
          tier: :standalone_gateway,
          created_at: DateTime.utc_now()
        })
      )

    sp = %SignedPredicate{
      envelope_version: "1.0",
      run_id: run_id,
      step_id: run_id,
      turn_id: run_id,
      session_id: session_id,
      session_chain_position: 0,
      event_kind: :llm_call,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      tenant_id: tenant_id,
      machine_identity: %{
        observed_jwt_subject: "alice@example.com",
        observed_jwt_issuer: "https://issuer.example.com"
      },
      principal: %{"kind" => "obo_human", "subject" => "alice@example.com"},
      policy_canonical_hash: :crypto.hash(:sha256, "policy-" <> run_id),
      payload_hash: :crypto.hash(:sha256, "payload-" <> run_id),
      payload_uri: "s3://bucket/tenants/#{tenant_id}/runs/#{run_id}.json",
      correlation_id: Ulid.generate(),
      signer: "arn:aws:kms:us-east-1:123:key/test"
    }

    oc = %OuterContainer{
      verification_level: :signed,
      tier_completeness_advisory: :partial,
      session_chain_epoch: 0,
      session_state: :active
    }

    Envelope.new(sp, oc, %{"signatures" => [%{"sig" => Base.encode64(<<0::size(8 * 72)>>)}]})
  end

  defp seed_tenant do
    tid = Ulid.generate()

    {:ok, _} =
      Repo.insert(
        Tenant.changeset(%Tenant{}, %{
          tenant_id: tid,
          display_name: "test",
          tier: :standalone_gateway,
          created_at: DateTime.utc_now()
        })
      )

    tid
  end

  defp seed_session(tenant_id) do
    sid = Ecto.UUID.generate()

    {:ok, _} =
      Repo.insert(
        Session.changeset(%Session{session_id: sid}, %{
          tenant_id: tenant_id,
          session_scope: :discovery_session,
          state: :active,
          session_start: DateTime.utc_now(),
          principal_kind: :service_account,
          principal_canonical: "principal-canon"
        })
      )

    sid
  end

  defp seed_session_epoch(session_id, epoch_root) do
    {:ok, ep} =
      Repo.insert(
        SessionEpoch.changeset(%SessionEpoch{}, %{
          session_id: session_id,
          epoch_index: 0,
          epoch_root: epoch_root,
          epoch_start_at: DateTime.utc_now(),
          event_count: 1
        })
      )

    ep
  end
end
