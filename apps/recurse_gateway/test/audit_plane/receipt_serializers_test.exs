defmodule Recurse.Gateway.AuditPlane.ReceiptSerializersTest do
  @moduledoc """
  Issue #29 / B10. Pure unit tests; no DB.

  Pins the de-facto canonical receipt JSON shape so the SPA's detail tab
  (lightweight) and the export-zip's `signed_predicate.json` /
  `outer_container.json` (heavy with bytes) agree on field names while
  differing only in inclusion via the per-call options.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.AuditPlane.ReceiptSerializers

  defp sample_attestation do
    %{
      run_id: "run_01HZQ",
      session_id: "sess_01HZQ",
      turn_id: "turn_01",
      event_kind: :llm_call,
      machine_identity: %{spiffe_id: "spiffe://example.org/gateway"},
      principal: %{kind: :service_account, subject: "svc-abc"},
      tenant_id: "org_01HZQ3R5E0",
      policy_canonical_hash: <<1, 2, 3>>,
      payload_hash: <<4, 5, 6>>,
      payload_uri: "s3://recurse/run_01HZQ.json",
      correlation_id: "corr-1",
      signer_kms_key_id: "arn:aws:kms:us-east-1:000000000000:key/k1",
      signer_key_version: "v1",
      timestamp: ~U[2026-04-29 00:00:00.000000Z],
      verification_level: :standalone_v1,
      tier_completeness_advisory: :complete,
      session_chain_epoch: 0,
      session_chain_root: <<7, 8, 9>>,
      policy_decision: :allow,
      outcome: :success,
      upstream_status_code: 200,
      commit_retry_exhausted: false,
      signed_predicate_bytes: <<10, 11, 12>>,
      dsse_signature: <<13, 14, 15>>,
      global_inclusion_proof: <<16>>,
      local_inclusion_proof: <<17>>
    }
  end

  describe "signed_predicate/2 — default (lightweight, SPA detail-tab shape)" do
    test "renders all baseline fields" do
      out = ReceiptSerializers.signed_predicate(sample_attestation())

      assert out["run_id"] == "run_01HZQ"
      assert out["event_kind"] == "llm_call"
      assert out["policy_canonical_hash"] == "010203"
      assert out["timestamp"] == "2026-04-29T00:00:00.000000Z"
      assert out["machine_identity"] == %{spiffe_id: "spiffe://example.org/gateway"}
      assert out["principal"] == %{kind: :service_account, subject: "svc-abc"}
    end

    test "EXCLUDES signature bytes by default" do
      out = ReceiptSerializers.signed_predicate(sample_attestation())

      refute Map.has_key?(out, "signed_predicate_bytes_b64")
      refute Map.has_key?(out, "dsse_signature_b64")
    end
  end

  describe "signed_predicate/2 — include_signature_bytes: true (export-zip shape)" do
    test "INCLUDES signature bytes Base64-encoded" do
      out =
        ReceiptSerializers.signed_predicate(sample_attestation(),
          include_signature_bytes: true
        )

      assert out["signed_predicate_bytes_b64"] == Base.encode64(<<10, 11, 12>>)
      assert out["dsse_signature_b64"] == Base.encode64(<<13, 14, 15>>)
    end

    test "absent bytes default to empty Base64" do
      att = Map.merge(sample_attestation(), %{signed_predicate_bytes: nil, dsse_signature: nil})

      out = ReceiptSerializers.signed_predicate(att, include_signature_bytes: true)

      assert out["signed_predicate_bytes_b64"] == Base.encode64(<<>>)
      assert out["dsse_signature_b64"] == Base.encode64(<<>>)
    end
  end

  describe "outer_container/2 — default vs include_proof_bytes: true" do
    test "default excludes proof bytes" do
      out = ReceiptSerializers.outer_container(sample_attestation())

      refute Map.has_key?(out, "global_inclusion_proof_b64")
      refute Map.has_key?(out, "local_inclusion_proof_b64")
      assert out["session_chain_root"] == "070809"
    end

    test "include_proof_bytes: true adds the Base64-encoded proofs" do
      out =
        ReceiptSerializers.outer_container(sample_attestation(),
          include_proof_bytes: true
        )

      assert out["global_inclusion_proof_b64"] == Base.encode64(<<16>>)
      assert out["local_inclusion_proof_b64"] == Base.encode64(<<17>>)
    end
  end

  describe "receipt/2 — full receipt assembly" do
    test "hoists run_id and embeds signed_predicate + outer_container" do
      out = ReceiptSerializers.receipt(sample_attestation())

      assert %{
               "run_id" => "run_01HZQ",
               "signed_predicate" => sp,
               "outer_container" => oc
             } = out

      assert is_map(sp)
      assert is_map(oc)
      assert sp["run_id"] == "run_01HZQ"
      assert oc["verification_level"] == "standalone_v1"
    end

    test "passes opts through to both blocks" do
      out =
        ReceiptSerializers.receipt(sample_attestation(),
          include_signature_bytes: true,
          include_proof_bytes: true
        )

      assert out["signed_predicate"]["dsse_signature_b64"] == Base.encode64(<<13, 14, 15>>)
      assert out["outer_container"]["global_inclusion_proof_b64"] == Base.encode64(<<16>>)
    end
  end

  describe "nil handling" do
    test "nil enum/atom values render as nil" do
      att = %{
        run_id: nil,
        session_id: nil,
        turn_id: nil,
        event_kind: nil,
        machine_identity: nil,
        principal: nil,
        tenant_id: nil,
        policy_canonical_hash: nil,
        payload_hash: nil,
        payload_uri: nil,
        correlation_id: nil,
        signer_kms_key_id: nil,
        signer_key_version: nil,
        timestamp: nil
      }

      out = ReceiptSerializers.signed_predicate(att)

      assert out["event_kind"] == nil
      assert out["policy_canonical_hash"] == nil
      assert out["timestamp"] == nil
    end
  end

  describe "B7 tool_name + tool_summary surfacing" do
    test "renders tool_name + tool_summary when present on the row" do
      att =
        sample_attestation()
        |> Map.put(:event_kind, :tool_call)
        |> Map.put(:tool_name, "Bash")
        |> Map.put(:tool_summary, "Bash: ls /etc")

      out = ReceiptSerializers.signed_predicate(att)

      assert out["tool_name"] == "Bash"
      assert out["tool_summary"] == "Bash: ls /etc"
    end

    test "renders nil for both when absent (non-tool_call rows)" do
      att = sample_attestation()

      out = ReceiptSerializers.signed_predicate(att)

      assert out["tool_name"] == nil
      assert out["tool_summary"] == nil
    end

    test "absent keys (Map.get fallback) render as nil — backward compat with raw maps" do
      att =
        sample_attestation()
        |> Map.delete(:tool_name)
        |> Map.delete(:tool_summary)

      out = ReceiptSerializers.signed_predicate(att)

      assert out["tool_name"] == nil
      assert out["tool_summary"] == nil
    end
  end

  describe "tool-call extractor — outer_container.tags" do
    test "renders tags map verbatim when present (tool_call row)" do
      tags = %{
        "category" => "subprocess_exec",
        "display_summary" => "Bash: git status",
        "scope_kind" => "git_readonly",
        "scope_value" => "git status",
        "target_resources" => [],
        "semantic_args" => %{"verb" => "git", "subverb" => "status", "writes" => false}
      }

      att =
        sample_attestation()
        |> Map.put(:event_kind, :tool_call)
        |> Map.put(:tags, tags)

      out = ReceiptSerializers.outer_container(att)

      assert out["tags"] == tags
    end

    test "renders nil for tags when absent (non-tool_call row)" do
      att = sample_attestation()
      out = ReceiptSerializers.outer_container(att)
      assert out["tags"] == nil
    end

    test "absent :tags key (Map.get fallback) renders as nil — backward compat" do
      att = sample_attestation() |> Map.delete(:tags)
      out = ReceiptSerializers.outer_container(att)
      assert out["tags"] == nil
    end

    test "tags survives include_proof_bytes: true (no opt-driven divergence)" do
      tags = %{"category" => "file_read", "display_summary" => "Read: lib/x.ex"}
      att = sample_attestation() |> Map.put(:tags, tags)
      out = ReceiptSerializers.outer_container(att, include_proof_bytes: true)
      assert out["tags"] == tags
      assert out["global_inclusion_proof_b64"] == Base.encode64(<<16>>)
    end
  end
end
