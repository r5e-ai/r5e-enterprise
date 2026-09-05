defmodule Recurse.Gateway.AuditPlane.EvidenceZipBuilderRetentionTest do
  @moduledoc """
  Spec 012 S6b — the export packs what the signature commits to:

    * `predicate/<run_id>.json` — the retained JCS predicate body, whose
      SHA-256 is the receipt's `payload_hash`;
    * `payloads/<sha256>` — the retained request / response bytes, for
      the parent `:llm_call_attested` AND for a `:tool_use_denied` child
      (resolved through the parent's LlmCallRecord via `turn_id`);
    * `manifest.json` names them and states the retention status.

  A receipt without retained artifacts still exports; the manifest says
  `predicate_body: null` / `payload_retention: "not_retained"`.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  import Ecto.Query, only: [from: 2]

  alias Recurse.Gateway.AuditPlane.EvidenceZipBuilder
  alias Recurse.Gateway.LlmProxy.AttestationEmitter
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.StubStorageProvider
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.{Attestation, SigningKey, Tenant}
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.LlmProxy.ToolUseIntent
  alias Recurse.Shared.Principal

  @tenant_id "01TEN_S6B_ZIP_RETENTION"
  @bundle "permit(principal, action, resource);\n"
  @prompt ~s|{"model":"claude","messages":[{"role":"user","content":"rm it"}]}|
  @response ~s|event: message_start\ndata: {"type":"message_start"}\n\n|
  @archive_chain_anchor <<0::size(256)>>

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok = StubStorageProvider.reset()

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "S6b zip retention tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    {:ok, storage_state} = StubStorageProvider.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {StubStorageProvider, storage_state},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/s6b-zip-test"
    })

    # Live bundle whose hash the receipts carry (loader_match path; the
    # archive path is covered by BundleArchiveTest).
    bundle_hash = :crypto.hash(:sha256, @bundle)
    previous_active = Active.current()

    Active.update(%Active{
      source: :filesystem,
      source_ref: "s6b-zip-test",
      loaded_at: DateTime.utc_now(),
      bundle: %PolicyBundleRef{
        bundle_id: Base.encode16(bundle_hash, case: :lower),
        canonical_hash: bundle_hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: @bundle,
        bundle_bytes: @bundle
      }
    })

    on_exit(fn ->
      ProviderRegistry.uninstall()

      case previous_active do
        {:ok, active} -> Active.update(active)
        _ -> Active.erase()
      end
    end)

    {:ok, bundle_hash: bundle_hash}
  end

  test "parent and denial exports carry the predicate body and both payloads", %{
    bundle_hash: bundle_hash
  } do
    intents = [
      {intent("toolu_1", "Bash", %{"command" => "rm -rf /"}),
       {:deny, %{rule_id: "no_rm", reason: "blocked"}}}
    ]

    {:ok, parent_run_id} =
      AttestationEmitter.emit_call_attestation(
        call_state(intents, bundle_hash,
          request_payload: {:ok, @prompt},
          response_payload: {:ok, @response}
        )
      )

    [child] = Repo.all(from(a in Attestation, where: a.event_kind == :tool_use_denied))
    seed_signing_key(parent_run_id)
    seed_signing_key(child.run_id)

    prompt_hex = Base.encode16(:crypto.hash(:sha256, @prompt), case: :lower)
    response_hex = Base.encode16(:crypto.hash(:sha256, @response), case: :lower)

    for run_id <- [parent_run_id, child.run_id] do
      att = Repo.get!(Attestation, run_id)
      assert {:ok, zip_bytes} = EvidenceZipBuilder.build(run_id, identity_ctx())
      files = unzip(zip_bytes)

      body = Map.fetch!(files, "predicate/#{run_id}.json")
      assert :crypto.hash(:sha256, body) == att.payload_hash

      assert Map.fetch!(files, "payloads/#{prompt_hex}") == @prompt
      assert Map.fetch!(files, "payloads/#{response_hex}") == @response

      manifest = JSON.decode!(Map.fetch!(files, "manifest.json"))
      assert manifest["predicate_body"] == "predicate/#{run_id}.json"
      assert manifest["payload_retention"] == "retained"
      assert manifest["format_version"] == "1.1"

      assert Enum.sort(manifest["payloads"]) ==
               Enum.sort([
                 %{
                   "role" => "request",
                   "file" => "payloads/#{prompt_hex}",
                   "sha256" => prompt_hex
                 },
                 %{
                   "role" => "response",
                   "file" => "payloads/#{response_hex}",
                   "sha256" => response_hex
                 }
               ])

      assert "predicate/#{run_id}.json" in manifest["files"]
      assert "payloads/#{prompt_hex}" in manifest["files"]
      assert manifest["policy_bundle_source"] == "loader_match"

      # The predicate body in the child export carries the hashes step 7
      # checks the payloads against.
      decoded = JSON.decode!(body)
      assert decoded["predicate"]["prompt_hash"] == "sha256:" <> prompt_hex
      assert decoded["predicate"]["response_hash"] == "sha256:" <> response_hex
    end
  end

  test "a receipt with nothing retained still exports and the manifest says so", %{
    bundle_hash: bundle_hash
  } do
    {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state([], bundle_hash))

    # Simulate a pre-S6b row / failed put: clear the retained reference.
    Repo.update_all(from(a in Attestation, where: a.run_id == ^run_id),
      set: [predicate_body_uri: nil]
    )

    seed_signing_key(run_id)
    assert {:ok, zip_bytes} = EvidenceZipBuilder.build(run_id, identity_ctx())
    files = unzip(zip_bytes)

    refute Map.has_key?(files, "predicate/#{run_id}.json")
    refute Enum.any?(Map.keys(files), &String.starts_with?(&1, "payloads/"))

    manifest = JSON.decode!(Map.fetch!(files, "manifest.json"))
    assert manifest["predicate_body"] == nil
    assert manifest["payloads"] == []
    assert manifest["payload_retention"] == "not_retained"
  end

  test "a truncated capture is reported as such", %{bundle_hash: bundle_hash} do
    {:ok, run_id} =
      AttestationEmitter.emit_call_attestation(
        call_state([], bundle_hash, request_payload: {:ok, @prompt}, response_payload: :truncated)
      )

    seed_signing_key(run_id)
    assert {:ok, zip_bytes} = EvidenceZipBuilder.build(run_id, identity_ctx())
    files = unzip(zip_bytes)
    manifest = JSON.decode!(Map.fetch!(files, "manifest.json"))
    assert manifest["payload_retention"] == "truncated"
    assert [%{"role" => "request"}] = manifest["payloads"]
  end

  defp unzip(zip_bytes) do
    {:ok, entries} = :zip.unzip(zip_bytes, [:memory])
    Map.new(entries, fn {name, bytes} -> {to_string(name), bytes} end)
  end

  defp identity_ctx do
    IdentityContext.new(%{
      tenant_id: @tenant_id,
      machine_identity: "observed://gateway/s6b-zip-test",
      principal: Principal.service_account(%{issuer: "observed://gateway", account_id: "s6b"}),
      correlation_id: Recurse.Shared.Ulid.generate()
    })
  end

  defp intent(call_id, tool_name, args) do
    {:ok, intent} =
      ToolUseIntent.new(%{
        call_id: call_id,
        tool_name: tool_name,
        tool_args: args,
        provider_event_span: %{start_byte_offset: 0, end_byte_offset: 10, event_indices: [0]}
      })

    intent
  end

  defp call_state(intents, bundle_hash, extra \\ []) do
    Map.merge(
      %{
        tenant_id: @tenant_id,
        principal_id: "claude-code:s6b",
        principal_kind: "obo_human",
        session_id: "session-s6b-zip",
        started_at: DateTime.utc_now(),
        completed_at: DateTime.utc_now() |> DateTime.add(100, :millisecond),
        model: "claude-haiku-4-5",
        provider: "anthropic",
        upstream_host: "api.anthropic.com",
        transport: :https_sse,
        api_format: :anthropic_messages,
        request_path: "/v1/messages",
        prompt_hash: :crypto.hash(:sha256, @prompt),
        response_hash: :crypto.hash(:sha256, @response),
        prompt_token_count: 10,
        completion_token_count: 20,
        cedar_bundle_hash: bundle_hash,
        upstream_status_code: 200,
        intents: intents,
        latency_ms: 100,
        added_latency_ms: 0
      },
      Map.new(extra)
    )
  end

  defp seed_signing_key(run_id) do
    att = Repo.get!(Attestation, run_id)
    now = DateTime.utc_now()

    identity = %{
      tenant_id: @tenant_id,
      kms_key_id: att.signer_kms_key_id,
      key_version: att.signer_key_version,
      public_key_pem: "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n",
      algorithm: :ecdsa_p256,
      first_seen_at: now
    }

    chain_hash =
      :crypto.hash(:sha256, @archive_chain_anchor <> SigningKey.canonical_row_bytes(identity))

    attrs =
      identity
      |> Map.put(:last_seen_at, now)
      |> Map.put(:chain_hash, chain_hash)
      |> Map.put(:inserted_at, now)

    %SigningKey{}
    |> SigningKey.insert_changeset(attrs)
    |> Repo.insert(on_conflict: :nothing, conflict_target: [:kms_key_id, :key_version])
  end
end
