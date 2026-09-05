defmodule Recurse.Providers.Impls.PostgresMerkleLedger.SchemasTest do
  @moduledoc """
  T035 — schema-layer unit tests for the six Postgres-Merkle LedgerProvider
  schemas. Exercises `changeset/2` for each schema: success path, missing
  required fields, Ecto.Enum rejection, and JSONB acceptance on Attestation.

  These tests do NOT hit Postgres — they exercise the in-memory changeset
  surface only. DB-level invariants (check constraints, triggers) are
  covered by `postgres_merkle_ledger_schema_test.exs` (T097).
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.{
    Attestation,
    GlobalLedgerEntry,
    MerkleNode,
    Session,
    SessionEpoch,
    Tenant
  }

  @tenant_id "01ARZ3NDEKTSV4RRFFQ69G5FAV"
  @session_id "11111111-1111-1111-1111-111111111111"
  @epoch_id "22222222-2222-2222-2222-222222222222"
  @run_id "33333333-3333-3333-3333-333333333333"
  @turn_id @run_id
  @now ~U[2026-04-23 12:00:00.000000Z]
  @hash32 <<0::256>>
  @sig <<1::8*72>>

  describe "Tenant.changeset/2" do
    test "valid attrs → changeset.valid?" do
      cs =
        Tenant.changeset(%Tenant{}, %{
          tenant_id: @tenant_id,
          display_name: "Acme",
          tier: :standalone_gateway,
          created_at: @now
        })

      assert cs.valid?
    end

    test "missing required → errors" do
      cs = Tenant.changeset(%Tenant{}, %{})
      refute cs.valid?
      assert %{tenant_id: _, display_name: _, tier: _, created_at: _} = errors_map(cs)
    end

    test "Ecto.Enum rejects unknown tier atom" do
      cs =
        Tenant.changeset(%Tenant{}, %{
          tenant_id: @tenant_id,
          display_name: "Acme",
          tier: :bogus_tier,
          created_at: @now
        })

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :tier)
    end
  end

  describe "Session.changeset/2" do
    test "valid attrs → changeset.valid?" do
      cs =
        Session.changeset(%Session{}, %{
          tenant_id: @tenant_id,
          session_scope: :discovery_session,
          state: :active,
          session_start: @now,
          principal_kind: :obo_human,
          principal_canonical: "{}"
        })

      assert cs.valid?
    end

    test "missing required → errors" do
      cs = Session.changeset(%Session{}, %{})
      refute cs.valid?
    end

    test "Ecto.Enum rejects unknown state atom" do
      cs =
        Session.changeset(%Session{}, %{
          tenant_id: @tenant_id,
          session_scope: :discovery_session,
          state: :never_heard_of_it,
          session_start: @now,
          principal_kind: :obo_human,
          principal_canonical: "{}"
        })

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :state)
    end
  end

  describe "SessionEpoch.changeset/2" do
    test "valid attrs → changeset.valid?" do
      cs =
        SessionEpoch.changeset(%SessionEpoch{}, %{
          session_id: @session_id,
          epoch_index: 0,
          epoch_root: @hash32,
          epoch_start_at: @now
        })

      assert cs.valid?
    end

    test "missing required → errors" do
      cs = SessionEpoch.changeset(%SessionEpoch{}, %{})
      refute cs.valid?
    end
  end

  describe "Attestation.changeset/2" do
    test "valid attrs (JSONB principal + machine_identity) → changeset.valid?" do
      machine_identity = %{
        "kind" => "observed_jwt_subject",
        "observed_jwt_subject" => "user@acme.example",
        "issuer" => "https://idp.acme.example"
      }

      principal = %{
        "subject" => "user@acme.example",
        "recurse_role" => "caller",
        "kind" => "obo_human"
      }

      cs =
        Attestation.changeset(%Attestation{}, %{
          session_id: @session_id,
          turn_id: @turn_id,
          event_kind: :llm_call,
          machine_identity: machine_identity,
          principal: principal,
          tenant_id: @tenant_id,
          policy_canonical_hash: @hash32,
          payload_hash: @hash32,
          payload_uri: "s3://bucket/tenants/#{@tenant_id}/runs/20260423/#{@run_id}.json",
          correlation_id: "corr-1",
          signer_kms_key_id: "arn:aws:kms:us-east-1:1:key/abc",
          signer_key_version: "v1",
          timestamp: @now,
          signed_predicate_bytes: "pae-bytes",
          dsse_signature: @sig,
          verification_level: :signed,
          tier_completeness_advisory: :partial,
          policy_decision: :allow,
          outcome: :success
        })

      assert cs.valid?
      # JSONB map survives unchanged through cast.
      assert Ecto.Changeset.get_field(cs, :machine_identity) == machine_identity
      assert Ecto.Changeset.get_field(cs, :principal) == principal
    end

    test "missing required → errors" do
      cs = Attestation.changeset(%Attestation{}, %{})
      refute cs.valid?
    end

    test "Ecto.Enum rejects unknown policy_decision atom" do
      cs =
        Attestation.changeset(%Attestation{}, %{
          policy_decision: :maybe,
          outcome: :success,
          verification_level: :signed,
          tier_completeness_advisory: :partial,
          event_kind: :llm_call
        })

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :policy_decision)
    end
  end

  describe "MerkleNode.changeset/2" do
    test "valid attrs (composite PK fields) → changeset.valid?" do
      cs =
        MerkleNode.changeset(%MerkleNode{}, %{
          tree_id: "session_#{@session_id}_epoch_0",
          level: 0,
          position: 0,
          hash: @hash32,
          inserted_at: @now
        })

      assert cs.valid?
    end

    test "missing required → errors" do
      cs = MerkleNode.changeset(%MerkleNode{}, %{})
      refute cs.valid?
    end
  end

  describe "GlobalLedgerEntry.changeset/2" do
    test "valid attrs → changeset.valid?" do
      cs =
        GlobalLedgerEntry.changeset(%GlobalLedgerEntry{}, %{
          tenant_id: @tenant_id,
          session_id: @session_id,
          session_epoch_id: @epoch_id,
          session_epoch_root: @hash32,
          committed_at: @now
        })

      assert cs.valid?
    end

    test "missing required → errors" do
      cs = GlobalLedgerEntry.changeset(%GlobalLedgerEntry{}, %{})
      refute cs.valid?
    end
  end

  defp errors_map(changeset) do
    Enum.reduce(changeset.errors, %{}, fn {k, v}, acc -> Map.put(acc, k, v) end)
  end
end
