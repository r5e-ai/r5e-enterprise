defmodule Recurse.Gateway.Attestation.EnvelopeBuilderTest do
  @moduledoc """
  Tests for `Recurse.Gateway.Attestation.EnvelopeBuilder` (F002 T048).

  ## Coverage

    * Happy path — build/7 produces an `%Envelope{}` with every signed
      predicate field populated per FR-014 + `contracts/attestation.schema.json`.
    * `payload_hash` matches SHA-256 of the JCS-encoded
      `{"request": <canon-req>, "response": <canon-resp>}` pair per
      `contracts/payload_canonicalization.md` — the most load-bearing
      hash in the system.
    * DSSE envelope is well-formed ITE-5 shape; `Dsse.verify/2`
      returns `{:unverified, payload}` (Phase-1 structural shell).
    * Outer container at emission is `:signed` + `:partial` +
      `:active` per FR-038.
    * Denial path (`policy_decision: :deny`) routes to
      `event_kind: :policy_denied`.
    * SecretsProvider error propagation — `active_signing_key` failure
      and `sign` failure each surface with their step tag.

  ## Async

  `async: true` — pure module under test; per-test mock secrets-provider
  state; no shared global state.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.Attestation.EnvelopeBuilder
  alias Recurse.Gateway.AuditPlane.PredicateOnlyUri
  alias Recurse.Gateway.Test.ActiveSigningKeyFailureProvider
  alias Recurse.Gateway.Test.SignFailureProvider
  alias Recurse.Gateway.Test.StubSecretsProvider
  alias Recurse.Shared.Attestation.{Dsse, Envelope, OuterContainer, SignedPredicate}
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Jcs
  alias Recurse.Shared.Principal
  alias Recurse.Shared.Ulid

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @issuer "https://test-broker.example.invalid"

  # -------------------------------------------------------------------------
  # Test fixtures
  # -------------------------------------------------------------------------

  defp identity_context do
    IdentityContext.new(%{
      machine_identity:
        {:observed_jwt_subject, %{observed_jwt_subject: "alice", issuer: @issuer}},
      principal:
        Principal.obo_human(%{
          issuer: @issuer,
          subject: "alice",
          display_name: "Alice Appleby"
        }),
      tenant_id: @tenant_id,
      correlation_id: Ulid.generate()
    })
  end

  defp sample_request do
    ~s({"model":"gpt-4o","messages":[{"role":"user","content":"hello"}],"max_tokens":32})
  end

  defp sample_response do
    ~s({"id":"cc-001","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"total_tokens":12}})
  end

  defp policy_hash, do: :crypto.hash(:sha256, "cedar-bundle-v1")

  defp build_opts do
    {:ok, state} = StubSecretsProvider.init(%{})
    run_id = Ulid.generate()

    [
      run_id: run_id,
      session_id: run_id,
      turn_id: run_id,
      signer: "observed://gateway/test-deployment",
      payload_uri: "",
      secrets_provider: {StubSecretsProvider, state},
      timestamp: ~U[2026-04-23 10:00:00.000000Z]
    ]
  end

  # -------------------------------------------------------------------------
  # Happy path
  # -------------------------------------------------------------------------

  describe "build/7 — happy path" do
    test "produces a fully-populated Envelope for policy_decision: :allow" do
      ctx = identity_context()
      opts = build_opts()

      assert {:ok, %Envelope{} = envelope} =
               EnvelopeBuilder.build(
                 ctx,
                 sample_request(),
                 sample_response(),
                 :allow,
                 policy_hash(),
                 :success,
                 opts
               )

      # Signed predicate shape + identity fields.
      assert %SignedPredicate{
               envelope_version: "1.0",
               event_kind: :llm_call,
               tenant_id: @tenant_id,
               correlation_id: correlation_id,
               principal: %{"kind" => "obo_human", "subject" => "alice"},
               machine_identity: %{
                 observed_jwt_subject: "alice",
                 observed_jwt_issuer: @issuer
               },
               signer: "observed://gateway/test-deployment"
             } = envelope.signed_predicate

      assert correlation_id == ctx.correlation_id

      # Run/session/turn identity — 1-run-1-session heuristic.
      assert envelope.signed_predicate.run_id == opts[:run_id]
      assert envelope.signed_predicate.session_id == opts[:run_id]
      assert envelope.signed_predicate.turn_id == opts[:run_id]
      assert envelope.signed_predicate.step_id == opts[:run_id]
      assert envelope.signed_predicate.session_chain_position == 0
    end

    test "payload_hash matches SHA-256 of JCS(request+response pair)" do
      ctx = identity_context()
      req = sample_request()
      resp = sample_response()

      {:ok, envelope} =
        EnvelopeBuilder.build(
          ctx,
          req,
          resp,
          :allow,
          policy_hash(),
          :success,
          build_opts()
        )

      expected_hash = expected_payload_hash(req, resp)
      assert envelope.signed_predicate.payload_hash == expected_hash
      assert byte_size(envelope.signed_predicate.payload_hash) == 32
    end

    test "payload_hash is stable across key-order permutations of request JSON" do
      ctx = identity_context()

      # Same JSON, different key order — JCS must canonicalize to the
      # same bytes → same hash. This is the FR-018 invariant.
      req1 =
        ~s({"model":"gpt-4o","messages":[{"role":"user","content":"x"}],"max_tokens":8})

      req2 =
        ~s({"max_tokens":8,"messages":[{"content":"x","role":"user"}],"model":"gpt-4o"})

      resp = sample_response()

      {:ok, e1} =
        EnvelopeBuilder.build(ctx, req1, resp, :allow, policy_hash(), :success, build_opts())

      {:ok, e2} =
        EnvelopeBuilder.build(ctx, req2, resp, :allow, policy_hash(), :success, build_opts())

      assert e1.signed_predicate.payload_hash == e2.signed_predicate.payload_hash
    end

    test "carries policy_canonical_hash and payload_hash as raw 32-byte binaries" do
      ctx = identity_context()
      hash = policy_hash()

      {:ok, envelope} =
        EnvelopeBuilder.build(
          ctx,
          sample_request(),
          sample_response(),
          :allow,
          hash,
          :success,
          build_opts()
        )

      assert envelope.signed_predicate.policy_canonical_hash == hash
      assert byte_size(envelope.signed_predicate.policy_canonical_hash) == 32
      assert byte_size(envelope.signed_predicate.payload_hash) == 32
    end

    test "DSSE envelope is ITE-5 shaped and decodable via Dsse.verify/2" do
      ctx = identity_context()

      {:ok, envelope} =
        EnvelopeBuilder.build(
          ctx,
          sample_request(),
          sample_response(),
          :allow,
          policy_hash(),
          :success,
          build_opts()
        )

      dsse = envelope.dsse_envelope
      assert is_map(dsse)
      assert dsse["payloadType"] == "application/vnd.in-toto+json"
      assert is_binary(dsse["payload"])
      assert [%{"keyid" => keyid, "sig" => sig}] = dsse["signatures"]
      assert is_binary(keyid)
      # StubSecretsProvider returns :ed25519 with key_version 1.
      assert keyid == "stub-signing-key-001:v1"
      assert is_binary(sig)

      # Phase-1 Dsse.verify/2 returns {:unverified, payload} for a
      # structurally valid envelope (signature is not actually checked).
      assert {:unverified, predicate_bytes} = Dsse.verify(dsse, %{})

      # The payload bytes round-trip to the signed predicate map.
      assert {:ok, predicate_map} = Jason.decode(predicate_bytes)

      assert predicate_map["envelope_version"] == "1.0"
      assert predicate_map["event_kind"] == "llm_call"
      assert predicate_map["tenant_id"] == @tenant_id
    end

    test "outer container at emission is :signed + :partial + :active" do
      ctx = identity_context()

      {:ok, envelope} =
        EnvelopeBuilder.build(
          ctx,
          sample_request(),
          sample_response(),
          :allow,
          policy_hash(),
          :success,
          build_opts()
        )

      assert %OuterContainer{
               verification_level: :signed,
               tier_completeness_advisory: :partial,
               session_chain_epoch: 0,
               session_chain_root: nil,
               inclusion_proof_local: nil,
               inclusion_proof_global: nil,
               commit_retry_exhausted: false,
               session_state: :active
             } = envelope.outer_container
    end

    test "signed_predicate_bytes round-trip: JCS(to_map(sp)) = Base64-decoded payload" do
      ctx = identity_context()

      {:ok, envelope} =
        EnvelopeBuilder.build(
          ctx,
          sample_request(),
          sample_response(),
          :allow,
          policy_hash(),
          :success,
          build_opts()
        )

      predicate_map = SignedPredicate.to_map(envelope.signed_predicate)
      expected_bytes = Jcs.encode(predicate_map)

      {:ok, actual_bytes} = Base.decode64(envelope.dsse_envelope["payload"])
      assert expected_bytes == actual_bytes
    end
  end

  # -------------------------------------------------------------------------
  # Denial path
  # -------------------------------------------------------------------------

  describe "build/7 — deny path" do
    test "policy_decision: :deny routes to event_kind :policy_denied" do
      ctx = identity_context()

      {:ok, envelope} =
        EnvelopeBuilder.build(
          ctx,
          sample_request(),
          # On deny the Gateway injects its own refusal-shaped response;
          # the canonicalization rule applies regardless of who produced
          # the bytes.
          ~s({"refusal":"policy_denied"}),
          :deny,
          policy_hash(),
          :success,
          build_opts()
        )

      assert envelope.signed_predicate.event_kind == :policy_denied
    end
  end

  describe "predicate-only variants" do
    test "build_system/4 always uses the system predicate-only payload URI" do
      ctx = identity_context()
      opts = Keyword.put(build_opts(), :payload_uri, "recurse://import/source/session/run")

      assert {:ok, envelope} =
               EnvelopeBuilder.build_system(:ui_query, ctx, %{"query_kind" => "verify"}, opts)

      assert envelope.signed_predicate.payload_uri ==
               PredicateOnlyUri.uri_scheme_prefix() <> opts[:run_id]
    end

    test "build_imported/4 requires an imported payload URI and preserves source position" do
      ctx = identity_context()

      opts =
        build_opts()
        |> Keyword.put(
          :payload_uri,
          PredicateOnlyUri.imported_uri_scheme_prefix() <> "codex/s/r"
        )
        |> Keyword.put(:session_chain_position, 7)

      assert {:ok, envelope} =
               EnvelopeBuilder.build_imported(
                 :tool_call,
                 ctx,
                 %{"source" => "codex", "content" => %{"redaction_status" => "redacted"}},
                 opts
               )

      assert envelope.signed_predicate.event_kind == :tool_call
      assert envelope.signed_predicate.payload_uri == opts[:payload_uri]
      assert envelope.signed_predicate.session_chain_position == 7
    end

    test "build_imported/4 rejects system payload URI sentinels" do
      ctx = identity_context()

      opts =
        build_opts()
        |> Keyword.put(:payload_uri, PredicateOnlyUri.uri_scheme_prefix() <> "run")

      assert {:error, {:invalid_import_payload_uri, _}} =
               EnvelopeBuilder.build_imported(:tool_call, ctx, %{"source" => "codex"}, opts)
    end
  end

  # -------------------------------------------------------------------------
  # Error propagation
  # -------------------------------------------------------------------------

  describe "build/7 — failure paths" do
    test "invalid request JSON surfaces :canonicalize_request" do
      ctx = identity_context()

      assert {:error, {:canonicalize_request, {:invalid_json, _}}} =
               EnvelopeBuilder.build(
                 ctx,
                 "not json",
                 sample_response(),
                 :allow,
                 policy_hash(),
                 :success,
                 build_opts()
               )
    end

    test "invalid response JSON surfaces :canonicalize_response" do
      ctx = identity_context()

      assert {:error, {:canonicalize_response, {:invalid_json, _}}} =
               EnvelopeBuilder.build(
                 ctx,
                 sample_request(),
                 "}{also not json",
                 :allow,
                 policy_hash(),
                 :success,
                 build_opts()
               )
    end

    test ":active_signing_key failure surfaces with its step tag" do
      ctx = identity_context()

      failing = failing_secrets_provider(:active_signing_key, :boom)

      opts =
        build_opts()
        |> Keyword.put(:secrets_provider, failing)

      assert {:error, {:active_signing_key, :boom}} =
               EnvelopeBuilder.build(
                 ctx,
                 sample_request(),
                 sample_response(),
                 :allow,
                 policy_hash(),
                 :success,
                 opts
               )
    end

    test ":sign failure surfaces with its step tag" do
      ctx = identity_context()

      failing = failing_secrets_provider(:sign, :kms_throttled)

      opts =
        build_opts()
        |> Keyword.put(:secrets_provider, failing)

      assert {:error, {:sign, :kms_throttled}} =
               EnvelopeBuilder.build(
                 ctx,
                 sample_request(),
                 sample_response(),
                 :allow,
                 policy_hash(),
                 :success,
                 opts
               )
    end
  end

  # -------------------------------------------------------------------------
  # Private — payload_hash reference implementation (rebuilds the spec's rule
  # independently so the test catches any drift in EnvelopeBuilder).
  # -------------------------------------------------------------------------

  defp expected_payload_hash(request_bytes, response_bytes) do
    {:ok, req_term} = Jason.decode(request_bytes)
    {:ok, resp_term} = Jason.decode(response_bytes)
    canon_req_bytes = Jcs.encode(req_term)
    canon_resp_bytes = Jcs.encode(resp_term)
    {:ok, canon_req_term} = Jason.decode(canon_req_bytes)
    {:ok, canon_resp_term} = Jason.decode(canon_resp_bytes)
    combined = Jcs.encode(%{"request" => canon_req_term, "response" => canon_resp_term})
    :crypto.hash(:sha256, combined)
  end

  # Build a `{module, state}` tuple that fails at the named step. The
  # helper modules live in `test/support/` so the gateway app's test
  # elixirc path compiles them before any test runs. `state` slot
  # carries the failure reason — the test-double reads it on the
  # failing callback.
  defp failing_secrets_provider(:active_signing_key, reason) do
    {ActiveSigningKeyFailureProvider, reason}
  end

  defp failing_secrets_provider(:sign, reason) do
    {SignFailureProvider, reason}
  end
end
