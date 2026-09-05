defmodule RecurseGateway.Integration.US3ExportVerifyTest do
  @moduledoc """
  US3 — end-to-end Export Evidence zip → `docs/auditor/recurse-verify`
  shell-out verification (F002 T067).

  Builds a real DSSE-signed attestation using a freshly-minted ES256
  keypair, commits it through `PostgresMerkleLedger.commit_attestation/2`,
  seeds the `signing_keys` + `policy_bundles` archive rows the builder
  needs, exports a zip via `EvidenceZipBuilder.build/3`, then runs the
  vendored bash wrapper via `System.cmd/3` and asserts the strict exit
  code + trace output for six distinct verification scenarios.

  Covers the F002 GAN round-1-pinned exit-code taxonomy (contract:
  `specs/002-standalone-gateway-vertical-slice/contracts/recurse_verify_spec.md`):

    * `0` — strict cryptographic pass (`--trust-anchor` supplied and
      matched, all 7 steps passed).
    * `1` — verification failure (tampered payload, tampered signature,
      wrong trust anchor).
    * `2` — unanchored pass (no `--trust-anchor`, 6 steps passed).
    * `3` — bad input (malformed zip missing required member).

  ## `async: false`

    * `Ecto.SQL.Sandbox` (PostgresMerkleLedger.commit_attestation's
      Ecto.Multi binds a single checked-out connection).
    * `ProviderRegistry.install_raw!` / `uninstall/0` (persistent_term).
    * `System.cmd/3` to `docs/auditor/recurse-verify` (binds tmpdir
      filesystem paths + shells out).

  ## No Elixir skill invocation

    * Per the memory rule, this is a bash + vendored-binary + e2e test.
      The Elixir glue is minimal harness code; no new modules written.
      (The `US3MockSecretsProvider` below is pure test glue that signs
      with a real `JOSE.JWK` — it produces valid ES256 signatures
      `recurse-verify` can verify via `openssl dgst`.)
  """

  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Attestation.EnvelopeBuilder
  alias Recurse.Gateway.AuditPlane.EvidenceZipBuilder
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Attestation.SignedPredicate
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  import Ecto.Query, only: [from: 2]

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @archive_chain_anchor <<0::size(256)>>

  # Absolute path to the bash wrapper. `System.cmd/3` resolves relative paths
  # against the test process's cwd (which varies between `mix test` and `cd
  # apps/recurse_gateway && mix test`), so pin it off :recurse_gateway's app_dir.
  defp recurse_verify_path do
    # Walk up from `apps/recurse_gateway/_build/.../priv` to repo root.
    # Cheaper: compute from the :recurse_gateway mix project's :app_dir.
    # For robustness we probe both the source-tree path (mix test from repo
    # root) AND the build-tree path (unlikely but cheap to try).
    candidates = [
      Path.expand("../../docs/auditor/recurse-verify", __DIR__),
      Path.expand("../../../docs/auditor/recurse-verify", __DIR__),
      Path.expand("../../../../docs/auditor/recurse-verify", __DIR__)
    ]

    Enum.find(candidates, &File.exists?/1) ||
      flunk(
        "recurse-verify script not found; searched:\n  " <>
          Enum.join(candidates, "\n  ")
      )
  end

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    # Seed tenant row (signing_keys FK target).
    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "US3 Test Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    # Mint a fresh ES256 keypair (EC P-256). JOSE handles signing; PEM goes
    # into the signing_keys archive + the trust-anchor file side-by-side.
    {pub_raw, priv_raw} = :crypto.generate_key(:ecdh, :secp256r1)

    jwk =
      JOSE.JWK.from_key(
        {:ECPrivateKey, 1, priv_raw, {:namedCurve, :secp256r1}, pub_raw, :asn1_NOVALUE}
      )

    pub_jwk = JOSE.JWK.to_public(jwk)
    {_mod, pub_pem} = JOSE.JWK.to_pem(pub_jwk)

    # A separate "unrelated" pubkey for the wrong-anchor scenario.
    {pub_raw2, priv_raw2} = :crypto.generate_key(:ecdh, :secp256r1)

    other_jwk =
      JOSE.JWK.from_key(
        {:ECPrivateKey, 1, priv_raw2, {:namedCurve, :secp256r1}, pub_raw2, :asn1_NOVALUE}
      )

    {_mod, other_pem} = JOSE.JWK.to_pem(JOSE.JWK.to_public(other_jwk))

    tmp_dir = Path.join(System.tmp_dir!(), "us3_verify_#{System.unique_integer()}")
    File.mkdir_p!(tmp_dir)

    anchor_pem_path = Path.join(tmp_dir, "anchor.pem")
    File.write!(anchor_pem_path, pub_pem)

    wrong_anchor_pem_path = Path.join(tmp_dir, "wrong-anchor.pem")
    File.write!(wrong_anchor_pem_path, other_pem)

    on_exit(fn ->
      File.rm_rf!(tmp_dir)
      ProviderRegistry.uninstall()
    end)

    # ProviderRegistry install — EvidenceZipBuilder.build/3 reads the
    # StorageProvider from here to fetch payload bytes.
    {:ok, ledger_state} = PostgresMerkleLedger.init(%{})
    {:ok, storage_state} = Recurse.Gateway.Test.InlineStubStorage.init(%{})
    {:ok, secrets_state} = Recurse.Gateway.Test.US3MockSecretsProvider.init(%{jwk: jwk})

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, ledger_state},
      storage: {Recurse.Gateway.Test.InlineStubStorage, storage_state},
      secrets: {Recurse.Gateway.Test.US3MockSecretsProvider, secrets_state},
      tenant_id: @tenant_id,
      signer: "observed://gateway/us3-test"
    })

    %{
      jwk: jwk,
      pub_pem: pub_pem,
      anchor_pem_path: anchor_pem_path,
      wrong_anchor_pem_path: wrong_anchor_pem_path,
      tmp_dir: tmp_dir,
      recurse_verify: recurse_verify_path()
    }
  end

  describe "happy paths" do
    test "anchored happy path: exit 0 + 'PASS (strict, anchored)' + all 7 steps pass", ctx do
      {run_id, zip_path, _policy_hash} = build_and_export_attestation(ctx)

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, [
          "--zip",
          zip_path,
          "--trust-anchor",
          ctx.anchor_pem_path
        ])

      assert exit_code == 0, "expected strict anchored pass, got:\n#{stdout}"
      assert stdout =~ "VERIFY: PASS (strict, anchored)"
      # Step 0 must have run AND matched.
      assert stdout =~ "[0] Trust anchor match"
      assert stdout =~ ~r/MATCH \(sha256: [0-9a-f]+\.\.\.\)/
      assert stdout =~ "[1] DSSE signature"
      assert stdout =~ "VALID (ES256)"
      assert stdout =~ "[2] RFC 9162 local inclusion"
      assert stdout =~ "[3] RFC 9162 global inclusion"
      assert stdout =~ "[4] policy_canonical_hash"
      assert stdout =~ "[5] payload_hash"
      assert stdout =~ "[6] verification_level"

      # Sanity: the run_id we committed is the one whose zip we verified.
      assert is_binary(run_id)
    end

    test "unanchored happy path: exit 2 + WARNING + Step 0 SKIPPED + Steps 1-6 PASS", ctx do
      {_run_id, zip_path, _policy_hash} = build_and_export_attestation(ctx)

      {stdout, exit_code} = System.cmd(ctx.recurse_verify, ["--zip", zip_path])

      assert exit_code == 2, "expected unanchored pass (2), got:\n#{stdout}"
      assert stdout =~ "WARNING: no --trust-anchor supplied"
      assert stdout =~ "NOT evidentiary-grade"
      assert stdout =~ "[0] Trust anchor match"
      assert stdout =~ "SKIPPED (no anchor supplied)"
      assert stdout =~ "VALID (ES256)"
      assert stdout =~ "VERIFY: UNANCHORED PASS (exit 2 — NOT evidentiary-grade)"
    end

    test "anchored --json mode: exit 0 + top-level exit_code:0 + all step entries PASS", ctx do
      {_run_id, zip_path, _policy_hash} = build_and_export_attestation(ctx)

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, [
          "--zip",
          zip_path,
          "--trust-anchor",
          ctx.anchor_pem_path,
          "--json"
        ])

      assert exit_code == 0, "expected strict JSON-mode pass, got:\n#{stdout}"
      decoded = JSON.decode!(stdout)
      assert decoded["exit_code"] == 0
      assert decoded["zip"] == zip_path
      assert decoded["trust_anchor"] == ctx.anchor_pem_path

      steps_by_num = Map.new(decoded["steps"], fn step -> {step["step"], step["status"]} end)

      for n <- 0..6 do
        assert Map.get(steps_by_num, n) == "pass",
               "expected step #{n} to PASS in JSON output, got #{inspect(steps_by_num)}"
      end
    end
  end

  describe "failure paths (exit 1)" do
    test "tampered payload: exit 1 + 'payload_hash mismatch at Step 5'", ctx do
      {_run_id, zip_path, _policy_hash} = build_and_export_attestation(ctx)
      tampered_path = rezip_with_mutation(zip_path, "payload.json", &(&1 <> "TAMPER"))

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, [
          "--zip",
          tampered_path,
          "--trust-anchor",
          ctx.anchor_pem_path
        ])

      assert exit_code == 1
      assert stdout =~ "payload_hash mismatch at Step 5"
      assert stdout =~ "VERIFY: FAIL"
    end

    test "tampered DSSE signature: exit 1 + 'DSSE signature invalid at Step 1'", ctx do
      {_run_id, zip_path, _policy_hash} = build_and_export_attestation(ctx)

      tampered_path =
        rezip_with_mutation(zip_path, "signed_predicate.json", fn bytes ->
          decoded = JSON.decode!(bytes)
          sig_b64 = Map.fetch!(decoded, "dsse_signature_b64")
          sig = Base.decode64!(sig_b64)
          # Flip the first byte of the raw signature.
          <<first, rest::binary>> = sig
          tampered_sig = <<Bitwise.bxor(first, 0x01)>> <> rest
          updated = Map.put(decoded, "dsse_signature_b64", Base.encode64(tampered_sig))
          JSON.encode!(updated)
        end)

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, [
          "--zip",
          tampered_path,
          "--trust-anchor",
          ctx.anchor_pem_path
        ])

      assert exit_code == 1
      assert stdout =~ "DSSE signature invalid at Step 1"
      assert stdout =~ "VERIFY: FAIL"
    end

    test "wrong trust anchor: exit 1 + 'trust anchor does not match' at Step 0", ctx do
      {_run_id, zip_path, _policy_hash} = build_and_export_attestation(ctx)

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, [
          "--zip",
          zip_path,
          "--trust-anchor",
          ctx.wrong_anchor_pem_path
        ])

      assert exit_code == 1
      assert stdout =~ "trust anchor does not match zip signing-key archive entry"
      assert stdout =~ "VERIFY: FAIL"
      # The failure happens at Step 0; later steps should not have run.
      refute stdout =~ "[1] DSSE signature"
    end
  end

  describe "bad input (exit 3)" do
    test "malformed zip missing signed_predicate.json: exit 3 + 'bad input'", ctx do
      {_run_id, zip_path, _policy_hash} = build_and_export_attestation(ctx)
      broken_path = rezip_removing(zip_path, "signed_predicate.json")

      {output, exit_code} =
        System.cmd(
          ctx.recurse_verify,
          ["--zip", broken_path, "--trust-anchor", ctx.anchor_pem_path],
          stderr_to_stdout: true
        )

      assert exit_code == 3
      assert output =~ "bad input"
      assert output =~ "signed_predicate.json"
    end
  end

  # ---------------------------------------------------------------------------
  # Spec 012 S6b — predicate body + detached payloads through the emitter
  # ---------------------------------------------------------------------------

  describe "spec 012 S6b: predicate-only receipts verify against retained bytes" do
    test "llm_call_attested: Step 5 MATCH on the predicate body, Step 7 MATCH on both payloads, exit 0",
         ctx do
      %{parent_run_id: run_id} = emit_proxy_call(ctx)
      zip_path = export_zip(ctx, run_id)

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, ["--zip", zip_path, "--trust-anchor", ctx.anchor_pem_path])

      assert exit_code == 0, "expected strict anchored pass, got:\n#{stdout}"
      assert stdout =~ "[4] policy_canonical_hash"
      assert stdout =~ "MATCH (rule 2: SHA-256 of raw bundle bytes"
      assert stdout =~ "[5] payload_hash"
      assert stdout =~ "MATCH (predicate body predicate/#{run_id}.json"
      refute stdout =~ "SKIPPED (N/A"
      assert stdout =~ "[7] detached payloads"

      assert stdout =~
               ~r/prompt: MATCH \(payloads\/[0-9a-f]{16}\.\.\., \d+ bytes hash to prompt_hash\)/

      assert stdout =~
               ~r/response: MATCH \(payloads\/[0-9a-f]{16}\.\.\., \d+ bytes hash to response_hash\)/

      assert stdout =~ "VERIFY: PASS (strict, anchored)"
    end

    test "tool_use_denied child: payloads bind through the hashes the denial carries", ctx do
      %{child_run_id: child_run_id} = emit_proxy_call(ctx)
      zip_path = export_zip(ctx, child_run_id)

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, ["--zip", zip_path, "--trust-anchor", ctx.anchor_pem_path])

      assert exit_code == 0, "expected strict anchored pass, got:\n#{stdout}"
      assert stdout =~ "MATCH (predicate body predicate/#{child_run_id}.json"
      assert stdout =~ "prompt: MATCH"
      assert stdout =~ "response: MATCH"
    end

    test "--json: steps 0-7 all pass", ctx do
      %{parent_run_id: run_id} = emit_proxy_call(ctx)
      zip_path = export_zip(ctx, run_id)

      {stdout, 0} =
        System.cmd(ctx.recurse_verify, [
          "--zip",
          zip_path,
          "--trust-anchor",
          ctx.anchor_pem_path,
          "--json"
        ])

      steps = Map.new(JSON.decode!(stdout)["steps"], &{&1["step"], &1["status"]})
      for n <- 0..7, do: assert(steps[n] == "pass", "step #{n}: #{inspect(steps)}")
    end

    test "tampered predicate body: exit 1 + 'predicate body hash mismatch at Step 5'; Step 7 not checked",
         ctx do
      %{parent_run_id: run_id} = emit_proxy_call(ctx)
      zip_path = export_zip(ctx, run_id)

      tampered =
        rezip_with_mutation(zip_path, "predicate/#{run_id}.json", fn bytes ->
          String.replace(bytes, "\"model\":\"claude", "\"model\":\"other")
        end)

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, ["--zip", tampered, "--trust-anchor", ctx.anchor_pem_path])

      assert exit_code == 1
      assert stdout =~ "predicate body hash mismatch at Step 5"
      assert stdout =~ "NOT CHECKED"
      assert stdout =~ "VERIFY: FAIL"
    end

    test "tampered payload: exit 1 + 'payload hash mismatch at Step 7'", ctx do
      %{parent_run_id: run_id, response_hex: response_hex} = emit_proxy_call(ctx)
      zip_path = export_zip(ctx, run_id)
      tampered = rezip_with_mutation(zip_path, "payloads/#{response_hex}", &(&1 <> "TAMPER"))

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, ["--zip", tampered, "--trust-anchor", ctx.anchor_pem_path])

      assert exit_code == 1
      assert stdout =~ "prompt: MATCH"
      assert stdout =~ "response payload hash mismatch at Step 7"
      assert stdout =~ "VERIFY: FAIL"
    end

    test "payload not exported: NOT INCLUDED is not a failure", ctx do
      %{parent_run_id: run_id, prompt_hex: prompt_hex} = emit_proxy_call(ctx)
      zip_path = export_zip(ctx, run_id)
      stripped = rezip_removing(zip_path, "payloads/#{prompt_hex}")

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, ["--zip", stripped, "--trust-anchor", ctx.anchor_pem_path])

      assert exit_code == 0
      assert stdout =~ "prompt: NOT INCLUDED"
      assert stdout =~ "response: MATCH"
    end

    test "no predicate body in the export: Step 5 SKIPPED with the retention explanation", ctx do
      %{parent_run_id: run_id} = emit_proxy_call(ctx)
      zip_path = export_zip(ctx, run_id)
      stripped = rezip_removing(zip_path, "predicate/#{run_id}.json")

      {stdout, exit_code} =
        System.cmd(ctx.recurse_verify, ["--zip", stripped, "--trust-anchor", ctx.anchor_pem_path])

      assert exit_code == 0

      assert stdout =~
               "SKIPPED (N/A — predicate-only receipt and the export carries no predicate/<run_id>.json"

      assert stdout =~ "[7] detached payloads"
      assert stdout =~ "no predicate body in the export"
    end
  end

  @s6b_prompt ~s|{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"delete it"}]}|
  @s6b_response ~s|event: message_start\ndata: {"type":"message_start"}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n|
  @s6b_bundle "permit(principal, action, resource); // s6b\n"

  # Emit one proxied call with a denied intent through the real emitter
  # (real ES256 signatures via US3MockSecretsProvider; InlineStubStorage
  # content-addresses the puts) and seed what the export needs.
  defp emit_proxy_call(ctx) do
    bundle_hash = :crypto.hash(:sha256, @s6b_bundle)
    seed_policy_bundle(bundle_hash, @s6b_bundle)

    {:ok, intent} =
      Recurse.Shared.LlmProxy.ToolUseIntent.new(%{
        call_id: "toolu_s6b",
        tool_name: "Bash",
        tool_args: %{"command" => "rm -rf /"},
        provider_event_span: %{start_byte_offset: 0, end_byte_offset: 10, event_indices: [0]}
      })

    call_state = %{
      tenant_id: @tenant_id,
      principal_id: "claude-code:s6b",
      principal_kind: "obo_human",
      session_id: "session-s6b-verify",
      started_at: DateTime.utc_now(),
      completed_at: DateTime.utc_now() |> DateTime.add(50, :millisecond),
      model: "claude-haiku-4-5",
      provider: "anthropic",
      upstream_host: "api.anthropic.com",
      transport: :https_sse,
      api_format: :anthropic_messages,
      request_path: "/v1/messages",
      prompt_hash: :crypto.hash(:sha256, @s6b_prompt),
      response_hash: :crypto.hash(:sha256, @s6b_response),
      request_payload: {:ok, @s6b_prompt},
      response_payload: {:ok, @s6b_response},
      prompt_token_count: 10,
      completion_token_count: 5,
      cedar_bundle_hash: bundle_hash,
      upstream_status_code: 200,
      intents: [{intent, {:deny, %{rule_id: "no_rm", reason: "blocked rm -rf"}}}],
      latency_ms: 50,
      added_latency_ms: 0
    }

    {:ok, parent_run_id} =
      Recurse.Gateway.LlmProxy.AttestationEmitter.emit_call_attestation(call_state)

    parent =
      Repo.get!(Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation, parent_run_id)

    assert is_binary(parent.predicate_body_uri)

    %{run_id: child_run_id} =
      Repo.one!(
        from(a in Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation,
          where: a.event_kind == :tool_use_denied and a.turn_id == ^parent_run_id
        )
      )

    for run_id <- [parent_run_id, child_run_id],
        do: seed_signing_key_archive(ctx.pub_pem, %{run_id: run_id})

    %{
      parent_run_id: parent_run_id,
      child_run_id: child_run_id,
      prompt_hex: Base.encode16(:crypto.hash(:sha256, @s6b_prompt), case: :lower),
      response_hex: Base.encode16(:crypto.hash(:sha256, @s6b_response), case: :lower)
    }
  end

  defp export_zip(ctx, run_id) do
    identity_ctx = %IdentityContext{
      tenant_id: @tenant_id,
      machine_identity: "observed://gateway/us3-test",
      principal: Principal.service_account(%{issuer: "observed://gateway", account_id: "s6b"}),
      correlation_id: Recurse.Shared.Ulid.generate(),
      resolved_at_usec: System.os_time(:microsecond)
    }

    {:ok, zip_bytes} = EvidenceZipBuilder.build(run_id, identity_ctx)
    zip_path = Path.join(ctx.tmp_dir, "evidence-#{run_id}.zip")
    File.write!(zip_path, zip_bytes)
    zip_path
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Build a real ES256-signed envelope, commit via PostgresMerkleLedger, seed
  # signing_keys + policy_bundles, and export the zip.
  defp build_and_export_attestation(ctx) do
    identity_ctx = %IdentityContext{
      tenant_id: @tenant_id,
      machine_identity:
        {:observed_jwt_subject,
         %{observed_jwt_subject: "alice@corp", issuer: "https://test-broker.example.invalid"}},
      principal:
        Principal.obo_human(%{
          issuer: "https://test-broker.example.invalid",
          subject: "alice@corp",
          recurse_role: "caller"
        }),
      correlation_id: Recurse.Shared.Ulid.generate(),
      resolved_at_usec: System.os_time(:microsecond)
    }

    # Payload bytes — EnvelopeBuilder JCS-encodes these, then hashes.
    request_bytes = ~s|{"model":"gpt-4o-mini","messages":[]}|
    response_bytes = ~s|{"object":"chat.completion"}|

    # Cedar policy bundle: the file IS a .cedar source.
    policy_bundle_bytes = "permit(principal, action, resource);"
    policy_canonical_hash = :crypto.hash(:sha256, policy_bundle_bytes)

    # run_id + session_id columns are :binary_id — use UUIDs (the attestation
    # schema stores them as :binary_id strings even though production uses
    # ULIDs; see Attestation schema in PostgresMerkleLedger.Schemas).
    run_id = Ecto.UUID.generate()

    # Put payload to stub storage first so EnvelopeBuilder's `payload_uri`
    # can be filled accurately — but EnvelopeBuilder takes it as an opt,
    # we pass a known URI and the InlineStubStorage echoes it.
    payload_uri = "s3://test-bucket/us3/#{run_id}.json"

    :ok =
      Recurse.Gateway.Test.InlineStubStorage.preload(
        payload_uri,
        canonicalize_pair(request_bytes, response_bytes)
      )

    {:ok, envelope} =
      EnvelopeBuilder.build(
        identity_ctx,
        request_bytes,
        response_bytes,
        :allow,
        policy_canonical_hash,
        :success,
        run_id: run_id,
        session_id: run_id,
        turn_id: run_id,
        signer: "observed://gateway/us3-test",
        payload_uri: payload_uri,
        secrets_provider: ProviderRegistry.secrets_provider()
      )

    # `commit_attestation` writes the attestation + session + epoch + global
    # ledger leaf. Returns the committed run_id.
    {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

    # Seed signing_keys archive — EvidenceZipBuilder looks this up by
    # (kms_key_id, key_version) to stamp the PEM into `signing_key.pem`.
    seed_signing_key_archive(ctx.pub_pem, envelope.signed_predicate)

    # Seed policy_bundles so the zip embeds the bundle bytes whose SHA-256
    # matches the locked policy_canonical_hash.
    seed_policy_bundle(policy_canonical_hash, policy_bundle_bytes)

    # Build the zip.
    {:ok, zip_bytes} = EvidenceZipBuilder.build(run_id, identity_ctx)

    zip_path = Path.join(ctx.tmp_dir, "evidence-#{run_id}.zip")
    File.write!(zip_path, zip_bytes)

    {run_id, zip_path, policy_canonical_hash}
  end

  defp canonicalize_pair(request_bytes, response_bytes) do
    req_term = Jason.decode!(request_bytes)
    resp_term = Jason.decode!(response_bytes)

    Recurse.Shared.Jcs.encode(%{"request" => req_term, "response" => resp_term})
  end

  defp seed_signing_key_archive(pub_pem, %{run_id: _} = sp) do
    now = DateTime.utc_now()

    # EnvelopeBuilder's DSSE keyid is `"<sp.signer>:v1"`. But the
    # attestation table column `signer_kms_key_id` is filled from the
    # signed_predicate's `signer` field (observed://gateway/us3-test) —
    # that is NOT the KMS key ARN. However, the EvidenceZipBuilder reads
    # `signing_keys` by (signer_kms_key_id, signer_key_version), so the
    # attestation row's values are what the zip seeds with. Check what
    # the ledger wrote:
    att =
      Repo.get!(
        Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation,
        sp.run_id
      )

    identity = %{
      tenant_id: @tenant_id,
      kms_key_id: att.signer_kms_key_id,
      key_version: att.signer_key_version,
      public_key_pem: pub_pem,
      algorithm: :ecdsa_p256,
      first_seen_at: now
    }

    chain_hash =
      :crypto.hash(
        :sha256,
        @archive_chain_anchor <> SigningKey.canonical_row_bytes(identity)
      )

    attrs =
      identity
      |> Map.put(:last_seen_at, now)
      |> Map.put(:chain_hash, chain_hash)
      |> Map.put(:inserted_at, now)

    %SigningKey{}
    |> SigningKey.insert_changeset(attrs)
    |> Repo.insert!(
      on_conflict: :nothing,
      conflict_target: [:kms_key_id, :key_version]
    )
  end

  defp seed_policy_bundle(canonical_hash, bundle_bytes) do
    # Schema per apps/recurse_providers/priv/repo/migrations/20260423100000_f002_initial_schemas.exs:
    # policy_bundles(id binary_id, tenant_id, policy_canonical_hash bytea, bundle_bytes bytea,
    #                cedar_version, loaded_at, source CHECK IN ('filesystem'))
    now = DateTime.utc_now()

    sql = """
    INSERT INTO policy_bundles (id, tenant_id, policy_canonical_hash, bundle_bytes, cedar_version, loaded_at, source)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT DO NOTHING
    """

    {:ok, _} =
      Ecto.Adapters.SQL.query(Repo, sql, [
        Ecto.UUID.bingenerate(),
        @tenant_id,
        canonical_hash,
        bundle_bytes,
        "4.9.1",
        now,
        "filesystem"
      ])
  end

  # Re-zip a zip, applying `mutator` to the bytes of `member_name`.
  # `:zip.unzip/2` with a binary path reinterprets the arg as raw zip bytes; use charlist
  # OR feed already-read bytes. We use the bytes form for clarity.
  defp rezip_with_mutation(zip_path, member_name, mutator)
       when is_function(mutator, 1) do
    {:ok, entries} = :zip.unzip(File.read!(zip_path), [:memory])

    mutated_entries =
      Enum.map(entries, fn {name, bytes} ->
        if IO.iodata_to_binary(name) == member_name do
          {name, mutator.(bytes)}
        else
          {name, bytes}
        end
      end)

    out_path = String.replace_suffix(zip_path, ".zip", ".tampered.zip")
    {:ok, {_, out_bytes}} = :zip.create(~c"evidence.zip", mutated_entries, [:memory])
    File.write!(out_path, out_bytes)
    out_path
  end

  defp rezip_removing(zip_path, member_name) do
    {:ok, entries} = :zip.unzip(File.read!(zip_path), [:memory])

    filtered = Enum.reject(entries, fn {n, _} -> IO.iodata_to_binary(n) == member_name end)

    out_path = String.replace_suffix(zip_path, ".zip", ".missing.zip")
    {:ok, {_, out_bytes}} = :zip.create(~c"evidence.zip", filtered, [:memory])
    File.write!(out_path, out_bytes)
    out_path
  end
end

defmodule Recurse.Gateway.Test.US3MockSecretsProvider do
  @moduledoc """
  Test-only `SecretsProvider` that signs DSSE PAE bytes with a real
  `JOSE.JWK`-wrapped EC P-256 key.

  Kept inline at the bottom of the integration test file: it's tightly
  coupled to the key lifecycle established in the test's `setup` block,
  and a generic helper would invite re-use that doesn't match other
  tests (`StubSecretsProvider` returns a SHA-512 fake; `US5MockSecretsProvider`
  drives rotation without real signing). T067 is the only suite that
  needs real ES256 signatures.

  The returned `keyid` + `key_id` match the EnvelopeBuilder wire contract:
  `"<key_id>:v<key_version>"`.
  """
  @behaviour Recurse.Providers.SecretsProvider

  @key_id "arn:aws:kms:us-east-1:111122223333:key/us3-test-key"

  @impl true
  def init(config) when is_map(config), do: {:ok, config}

  @impl true
  def active_signing_key(_state) do
    {:ok, %{key_id: @key_id, key_version: "v1", algorithm: :ecdsa_p256}}
  end

  @impl true
  def sign(%{jwk: jwk}, _handle, pae_bytes) when is_binary(pae_bytes) do
    # Duplicate EnvelopeBuilder's ES256 raw-r||s signing path. We go
    # directly through :public_key rather than JOSE.JWS.sign because DSSE
    # signs the raw PAE bytes (not the JWS signing input). Matches
    # Recurse.Shared.Attestation.Dsse.sign_raw/3 for "ES256".
    {_, otp_priv_key} = JOSE.JWK.to_key(jwk)
    der = :public_key.sign(pae_bytes, :sha256, otp_priv_key)
    {:ok, ecdsa_der_to_raw(der, 32)}
  end

  @impl true
  def public_key(%{jwk: jwk}, _handle) do
    pub_jwk = JOSE.JWK.to_public(jwk)
    {_mod, pem} = JOSE.JWK.to_pem(pub_jwk)
    {:ok, pem}
  end

  @impl true
  def store_user_token(_state, _ctx, _tok, _ttl), do: :ok

  @impl true
  def exchange_for_downstream_token(_s, _c, _id, _scope),
    do: {:error, :not_implemented_in_test}

  @impl true
  def capabilities(_state), do: [:sign, :public_key_export]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok

  # Mirror of Recurse.Shared.Attestation.Dsse.ecdsa_der_to_raw/2 (private
  # there; we copy rather than expose the internal).
  defp ecdsa_der_to_raw(<<0x30, _len, 0x02, r_len, rest::binary>>, size) do
    <<r::binary-size(r_len), 0x02, s_len, s_rest::binary>> = rest
    <<s::binary-size(s_len), _::binary>> = s_rest
    pad(strip_leading_zero(r), size) <> pad(strip_leading_zero(s), size)
  end

  defp strip_leading_zero(<<0x00, rest::binary>>) when byte_size(rest) > 0, do: rest
  defp strip_leading_zero(other), do: other

  defp pad(bin, size) when byte_size(bin) == size, do: bin

  defp pad(bin, size) when byte_size(bin) < size do
    :binary.copy(<<0>>, size - byte_size(bin)) <> bin
  end
end

defmodule Recurse.Gateway.Test.InlineStubStorage do
  @moduledoc """
  Stub `StorageProvider` for T067 only. Accepts a preloaded (uri → bytes)
  mapping via `preload/2` so `EvidenceZipBuilder.build/3` can fetch
  exactly the canonicalized payload EnvelopeBuilder hashed. A plain ETS
  table is simpler than StubStorageProvider's bag-per-tenant shape and
  avoids double-recording on `put_payload`.
  """
  @behaviour Recurse.Providers.StorageProvider

  @table :us3_verify_stub_storage

  @impl true
  def init(_config) do
    ensure_table!()
    {:ok, %{}}
  end

  def preload(uri, bytes) when is_binary(uri) and is_binary(bytes) do
    ensure_table!()
    :ets.insert(@table, {uri, bytes})
    :ok
  end

  @impl true
  def put_payload(_state, bytes, _ctx) when is_binary(bytes) do
    ensure_table!()
    uri = "s3://us3-stub/" <> (:crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower))
    :ets.insert(@table, {uri, bytes})
    {:ok, %{uri: uri, hash: :crypto.hash(:sha256, bytes)}}
  end

  @impl true
  def get_payload(_state, uri, _ctx) do
    ensure_table!()

    case :ets.lookup(@table, uri) do
      [{^uri, bytes}] -> {:ok, bytes}
      [] -> {:error, :not_found}
    end
  end

  @impl true
  def delete_payload(_state, uri, _ctx) do
    ensure_table!()
    :ets.delete(@table, uri)
    :ok
  end

  @impl true
  def capabilities(_state), do: [:put, :get, :delete]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok

  defp ensure_table! do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
        :ok

      _ ->
        :ok
    end
  end
end
