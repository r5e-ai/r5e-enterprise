defmodule Recurse.Gateway.Attestation.EnvelopeBuilder do
  @moduledoc """
  Compose + DSSE-sign a Recurse-native attestation envelope for a single
  LLM call per F001 FR-021 + F002 FR-014 / FR-015 / FR-018.

  Pure module. Iron Law check (`elixir:elixir-thinking`):

    1. Mutable state persisting across calls? No — every `build/7` call is
       a pure function of its arguments plus a single side-effecting KMS
       `sign/3` (routed through a passed-in state), with no BEAM-local
       memory kept between calls.
    2. Concurrent execution? No — runs on the caller Plug process. Multiple
       requests get called-through in parallel naturally.
    3. Fault isolation? No — errors are `{:error, {step, reason}}`, not
       crashes.

  All three NO → plain functions.

  ## Responsibilities

    1. Canonicalize the `(request, response)` pair per `contracts/
       payload_canonicalization.md`:

          canon_req  = JCS(parsed_request_json)
          canon_resp = JCS(parsed_response_json)       # reassembled for SSE
          combined   = JCS(%{"request" => canon_req,
                             "response" => canon_resp})
          payload_hash = SHA-256(combined)             # 32 raw bytes

       The `response_bytes` argument is ALREADY the reassembled final
       `chat.completion` JSON for SSE — the caller (SseProxy in T052)
       reassembles chunks; this module just JCS-encodes the result.

    2. Build the immutable `SignedPredicate` struct per F001 FR-021
       (event_kind, identity, hashes, timestamp, run/session/turn ids).

    3. DSSE-sign the canonicalized predicate bytes via
       `SecretsProvider.sign/3` with the configured KMS key (algorithm
       `ECDSA_SHA_256` per research D4). The raw signature is placed in
       an ITE-5-shaped DSSE envelope map with `keyid = "<kms_key_id>:v<ver>"`
       per F001 FR-046.

    4. Build the `OuterContainer` at its emission-time state
       (`:signed` + `:partial` under Standalone per FR-038).

    5. Compose into an `%Envelope{}` and return.

  ## Load-bearing contracts

    * `contracts/payload_canonicalization.md` — the most load-bearing hash
      rule in the system; this module is its implementation.
    * `contracts/attestation.schema.json` (F001) — `SignedPredicate.to_map/1`
      matches the schema field-for-field.
    * F001 `Recurse.Shared.Attestation.Dsse` — PAE assembly + envelope shape.

  ## Policy-decision / outcome routing

  `policy_decision` selects `event_kind` in the signed predicate:

    * `:allow` → `:llm_call`
    * `:deny`  → `:policy_denied`

  `outcome` (`:success | :upstream_error | :cancelled`) and
  `upstream_status_code` are NOT carried in the envelope itself — they
  are outer-container mutable state persisted alongside the envelope at
  commit time (see `Recurse.Providers.Impls.PostgresMerkleLedger.
  commit_attestation/2` and `data-model.md` attestations columns). The
  caller retains these values and passes them to the ledger at commit
  time.

  ## What this module does NOT own

    * `payload_uri` filling from the S3 put result — T051 wires that in
      after `StorageProvider.put/3` returns.
    * SIEM forwarding — T053 (`Recurse.Gateway.Siem.Forwarder`) owns it.
    * Ledger commit — T033 (`PostgresMerkleLedger.commit_attestation/2`).

  ## API shape

  Errors come back as `{:error, {step_atom, reason}}` where `step_atom`
  is one of `:canonicalize_request`, `:canonicalize_response`,
  `:canonicalize_combined`, `:active_signing_key`, `:sign`. The tag is
  useful for telemetry + test assertions.
  """

  alias Recurse.Shared.Attestation.{Dsse, Envelope, OuterContainer, SignedPredicate}
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Jcs

  @dsse_payload_type "application/vnd.in-toto+json"
  @envelope_version "1.0"
  @tier_completeness_advisory :partial

  @type policy_decision :: :allow | :deny
  @type outcome :: :success | :upstream_error | :cancelled

  @type build_error ::
          {:error,
           {:canonicalize_request
            | :canonicalize_response
            | :canonicalize_combined
            | :active_signing_key
            | :sign
            | :invalid_event_kind
            | :invalid_session_chain_position
            | :invalid_import_payload_uri, term()}}

  @typedoc """
  Builder options.

    * `:run_id` (required) — ULID string produced by the caller (T051 mints it).
    * `:session_id` (required) — ULID string; equal to `run_id` under the
      Standalone "1-run-1-session" heuristic.
    * `:turn_id` (optional) — ULID string; equal to `run_id` in the
      LLM-only slice. Defaults to `run_id`.
    * `:signer` (optional) — Gateway emitter identity string per F001
      `SignedPredicate.signer` (SPIFFE-ID-shaped in Governance shapes;
      under Standalone there is no SPIFFE, so the caller passes a
      deployment-configured pseudo-SPIFFE string, e.g.
      `"observed://gateway/<deployment_id>"`). Defaults to `"observed://gateway"`.
    * `:payload_uri` (optional) — `payload_uri` to stamp into the signed
      predicate. T051 does NOT pass this at build-time; it is filled
      after `StorageProvider.put/3`. If absent the predicate is built
      with `""` and the caller MUST NOT persist the envelope until it
      has replaced `payload_uri` with the real S3 URI. Defaults to `""`.
    * `:secrets_provider` (required) — `{module, state}` tuple. The
      builder calls `module.active_signing_key(state)` to fetch the KMS
      handle and `module.sign(state, handle, pae_bytes)` to sign.
    * `:timestamp` (optional) — `DateTime.t()`; defaults to
      `DateTime.utc_now/0`. Passed in for tests / deterministic replays.
  """
  @type opts :: [
          run_id: String.t(),
          session_id: String.t(),
          turn_id: String.t() | nil,
          signer: String.t(),
          payload_uri: String.t(),
          secrets_provider: {module(), term()},
          timestamp: DateTime.t()
        ]

  @doc """
  Build a signed attestation envelope.

  See module-doc for the full flow + option reference. Returns
  `{:ok, %Envelope{}}` on success; any step failure short-circuits to
  `{:error, {step_name, reason}}`.
  """
  @spec build(
          IdentityContext.t(),
          request_bytes :: binary(),
          response_bytes :: binary(),
          policy_decision(),
          policy_canonical_hash :: <<_::256>>,
          outcome(),
          opts()
        ) :: {:ok, Envelope.t()} | build_error()
  def build(
        %IdentityContext{} = identity_ctx,
        request_bytes,
        response_bytes,
        policy_decision,
        <<policy_canonical_hash::binary-size(32)>>,
        outcome,
        opts
      )
      when is_binary(request_bytes) and is_binary(response_bytes) and
             policy_decision in [:allow, :deny] and
             outcome in [:success, :upstream_error, :cancelled] and
             is_list(opts) do
    run_id = Keyword.fetch!(opts, :run_id)
    session_id = Keyword.fetch!(opts, :session_id)
    turn_id = Keyword.get(opts, :turn_id, run_id)
    signer = Keyword.get(opts, :signer, "observed://gateway")
    payload_uri = Keyword.get(opts, :payload_uri, "")
    {secrets_mod, secrets_state} = Keyword.fetch!(opts, :secrets_provider)
    timestamp = Keyword.get(opts, :timestamp, DateTime.utc_now())

    predicate_inputs = %{
      identity_ctx: identity_ctx,
      policy_decision: policy_decision,
      policy_canonical_hash: policy_canonical_hash,
      payload_uri: payload_uri,
      signer: signer,
      run_id: run_id,
      session_id: session_id,
      turn_id: turn_id,
      timestamp: timestamp
    }

    with {:ok, payload_hash} <- canonicalize_pair(request_bytes, response_bytes),
         {:ok, signing_key_handle} <- active_signing_key(secrets_mod, secrets_state),
         predicate = build_signed_predicate(predicate_inputs, payload_hash),
         predicate_bytes = Jcs.encode(SignedPredicate.to_map(predicate)),
         pae_bytes = Dsse.pae(@dsse_payload_type, predicate_bytes),
         {:ok, signature} <- sign(secrets_mod, secrets_state, signing_key_handle, pae_bytes) do
      dsse_envelope = build_dsse_envelope(predicate_bytes, signature, signing_key_handle)
      outer = build_outer_container()
      {:ok, Envelope.new(predicate, outer, dsse_envelope)}
    end
  end

  # ---------------------------------------------------------------------------
  # Canonicalization — the load-bearing hash rule.
  #
  # Both request and response bytes arrive as raw JSON. We decode each with
  # Jason, then JCS-encode for byte-stability, then nest them under
  # `{"request", "response"}`, JCS-encode the outer object, and SHA-256 the
  # result. Each step returns `{:error, {step, reason}}` on parse failure
  # so the caller can distinguish malformed-request from malformed-response.
  # ---------------------------------------------------------------------------

  defp canonicalize_pair(request_bytes, response_bytes) do
    with {:ok, canon_req_bytes} <- canonicalize_json(request_bytes, :canonicalize_request),
         {:ok, canon_resp_bytes} <- canonicalize_json(response_bytes, :canonicalize_response),
         {:ok, canon_req_term} <- decode_json(canon_req_bytes, :canonicalize_combined),
         {:ok, canon_resp_term} <- decode_json(canon_resp_bytes, :canonicalize_combined) do
      combined_bytes =
        Jcs.encode(%{"request" => canon_req_term, "response" => canon_resp_term})

      {:ok, :crypto.hash(:sha256, combined_bytes)}
    end
  end

  defp canonicalize_json(bytes, step) do
    with {:ok, term} <- decode_json(bytes, step) do
      {:ok, Jcs.encode(term)}
    end
  end

  defp decode_json(bytes, step) do
    case Jason.decode(bytes) do
      {:ok, term} -> {:ok, term}
      {:error, reason} -> {:error, {step, {:invalid_json, reason}}}
    end
  end

  # ---------------------------------------------------------------------------
  # Signed predicate assembly.
  # ---------------------------------------------------------------------------

  # Accepts `inputs` (the bundled non-hash fields) + `payload_hash`
  # (arity 2 keeps each argument semantically distinct: identity/config
  # vs the hash output of the canonicalization pipeline).
  defp build_signed_predicate(inputs, payload_hash) do
    %{
      identity_ctx: identity_ctx,
      policy_decision: policy_decision,
      policy_canonical_hash: policy_canonical_hash,
      payload_uri: payload_uri,
      signer: signer,
      run_id: run_id,
      session_id: session_id,
      turn_id: turn_id,
      timestamp: timestamp
    } = inputs

    %SignedPredicate{
      envelope_version: @envelope_version,
      run_id: run_id,
      step_id: run_id,
      turn_id: turn_id,
      session_id: session_id,
      session_chain_position: 0,
      event_kind: event_kind_for(policy_decision),
      timestamp: DateTime.to_iso8601(timestamp),
      tenant_id: identity_ctx.tenant_id,
      machine_identity: normalize_machine_identity(identity_ctx.machine_identity),
      principal: principal_to_map(identity_ctx.principal),
      policy_canonical_hash: policy_canonical_hash,
      payload_hash: payload_hash,
      payload_uri: payload_uri,
      correlation_id: identity_ctx.correlation_id,
      signer: signer
    }
  end

  defp event_kind_for(:allow), do: :llm_call
  defp event_kind_for(:deny), do: :policy_denied

  # IdentityContext carries `{:observed_jwt_subject, %{observed_jwt_subject,
  # issuer}}` or a SPIFFE string. SignedPredicate.to_map/1 expects one of:
  #   %{spiffe_id: String.t()}
  #   %{observed_jwt_subject: String.t(), observed_jwt_issuer: String.t()}
  # so we convert the tuple + rename `issuer` → `observed_jwt_issuer`.
  defp normalize_machine_identity({:observed_jwt_subject, %{} = m}) do
    %{
      observed_jwt_subject: Map.fetch!(m, :observed_jwt_subject),
      observed_jwt_issuer: Map.fetch!(m, :issuer)
    }
  end

  defp normalize_machine_identity(spiffe_id) when is_binary(spiffe_id) do
    %{spiffe_id: spiffe_id}
  end

  defp principal_to_map(%Recurse.Shared.Principal{} = principal) do
    Recurse.Shared.Principal.to_map(principal)
  end

  # ---------------------------------------------------------------------------
  # KMS signing. Failures are tagged with their phase so T051 / tests can
  # disambiguate `active_signing_key` (cache miss / handle lookup) from
  # `sign` (the network call to KMS).
  # ---------------------------------------------------------------------------

  defp active_signing_key(mod, state) do
    case mod.active_signing_key(state) do
      {:ok, handle} -> {:ok, handle}
      {:error, reason} -> {:error, {:active_signing_key, reason}}
    end
  end

  defp sign(mod, state, handle, pae_bytes) do
    case mod.sign(state, handle, pae_bytes) do
      {:ok, sig} -> {:ok, sig}
      {:error, reason} -> {:error, {:sign, reason}}
    end
  end

  # ---------------------------------------------------------------------------
  # DSSE envelope shape (ITE-5).
  #
  # `keyid` encodes the KMS reference per F001 FR-046 + signing_key_archive
  # contract: `"<key_id>:v<key_version>"`. This is distinct from
  # `SignedPredicate.signer` (Gateway emitter identity); the split is by
  # design — rotating a signing key does NOT change the Gateway's emitter
  # identity, only the `keyid` in subsequent DSSE envelopes.
  # ---------------------------------------------------------------------------

  defp build_dsse_envelope(predicate_bytes, signature, %{key_id: key_id, key_version: kver}) do
    %{
      "payloadType" => @dsse_payload_type,
      "payload" => Base.encode64(predicate_bytes),
      "signatures" => [
        %{
          "keyid" => "#{key_id}:v#{kver}",
          "sig" => Base.encode64(signature)
        }
      ]
    }
  end

  # ---------------------------------------------------------------------------
  # Outer container at emission time.
  #
  # FR-038: `:signed` at emission; T033's commit pipeline advances to
  # `:local_inclusion_verified` then `:global_inclusion_verified`.
  # Standalone is a Discovery-tier deployment → `:partial` on every
  # receipt per spec.md FR-001 + Constitution Principle III.
  # ---------------------------------------------------------------------------

  defp build_outer_container do
    %OuterContainer{
      verification_level: :signed,
      tier_completeness_advisory: @tier_completeness_advisory,
      session_chain_epoch: 0,
      session_chain_root: nil,
      inclusion_proof_local: nil,
      inclusion_proof_global: nil,
      commit_retry_exhausted: false,
      session_state: :active
    }
  end

  @doc """
  Expose the DSSE payload-type constant so T051 + tests don't duplicate
  the string.
  """
  @spec dsse_payload_type() :: String.t()
  def dsse_payload_type, do: @dsse_payload_type

  # ---------------------------------------------------------------------------
  # System-event variant (F004 T055a) — predicate-only, no LLM payload.
  #
  # F002's `build/7` canonicalizes a `(request_bytes, response_bytes)` LLM pair
  # into a 32-byte `payload_hash` and persists the canonical bytes via
  # `StorageProvider.put/3`. F004 introduces 24 new `:ui_*` event_kinds that
  # have no such payload — login flows, retention purges, browser sessions,
  # etc. emit metadata-only attestations.
  #
  # `build_system/4` mirrors `build/7`'s flow but:
  #   * Accepts an arbitrary `predicate_map` (the F004 contract surface for
  #     the predicate-only event payload — keyword-equivalent to a Cedar
  #     decision context).
  #   * Computes `payload_hash` as SHA-256 of the JCS-encoded predicate_map.
  #     This is NOT a load-bearing canonicalization (no off-platform verifier
  #     consumes it the way DSSE consumers consume the LLM payload bytes); it
  #     is a deterministic stand-in that makes the receipt round-trippable
  #     without changing the F002 `attestations.payload_hash NOT NULL`
  #     invariant.
  #   * Stamps the caller-supplied `event_kind` directly (no policy_decision
  #     mapping — system events are not Cedar-gated allow/deny pairs).
  #   * Sets `payload_uri` to a URI-form sentinel that documents the absence:
  #     `"recurse://system/predicate-only/<jti>"` — auditors querying the
  #     PayloadBroker for this URI get a documented 404 rather than a confusing
  #     dead S3 link.
  #
  # JTI assignment: `run_id` (the per-receipt UUID) IS the JTI in F002's
  # model — both the DSSE envelope and the `attestations.run_id` PK key off
  # it. No separate JTI generation needed; callers mint a UUID and pass it in.
  #
  # Signing key: same `SecretsProvider` handle that LLM-call attestations use
  # (via `ProviderRegistry.secrets_provider/0`). The KMS key signs system
  # events under the same identity envelope as user events — the distinction
  # lives in the `principal.kind = :service_account` discriminator, not in
  # a separate signer.
  # ---------------------------------------------------------------------------

  @typedoc """
  Builder options for `build_system/4` — same surface as `build/7` opts for
  predicate-only system events. System events always use the URI built by
  `Recurse.Gateway.AuditPlane.PredicateOnlyUri.build/1`; callers that need
  to preserve an imported payload reference use `build_imported/4`.
  """
  @type system_opts :: [
          run_id: String.t(),
          session_id: String.t(),
          turn_id: String.t() | nil,
          signer: String.t(),
          secrets_provider: {module(), term()},
          timestamp: DateTime.t(),
          policy_canonical_hash: <<_::256>>
        ]

  @typedoc """
  Builder options for `build_imported/4`.

  Imported receipts are predicate-only in this process, but they are not
  system events. They carry a caller-supplied `payload_uri` under
  `Recurse.Gateway.AuditPlane.PredicateOnlyUri.imported_uri_scheme_prefix/0`
  and a caller-supplied `session_chain_position` derived from the source
  session stream.
  """
  @type imported_opts :: [
          run_id: String.t(),
          session_id: String.t(),
          turn_id: String.t() | nil,
          signer: String.t(),
          payload_uri: String.t(),
          session_chain_position: non_neg_integer(),
          secrets_provider: {module(), term()},
          timestamp: DateTime.t(),
          policy_canonical_hash: <<_::256>>
        ]

  @typedoc """
  Caller-supplied predicate metadata for a system event. Encoded via JCS;
  the resulting bytes feed `payload_hash`. Keys are stringified at JCS time
  per RFC 8785 ordering rules. Atom keys are normalized to strings before
  encoding so callers can use the more idiomatic `%{event: "logout"}` shape
  without worrying about JCS encoder atom-handling semantics.
  """
  @type system_predicate :: map()

  # The predicate-only URI schemes (system + imported) and the synthetic
  # no-policy hash live in `Recurse.Gateway.AuditPlane.PredicateOnlyUri` —
  # that module is the single source of truth for both sign-side (this
  # builder) and verify-side (PayloadBroker, EvidenceZipBuilder,
  # LocalVerifyHandler). See issue #29 / AD-1 Option A — flips the
  # previously-asymmetric coupling where verify-side reached across to
  # import these constants from the sign-side module. Constitution
  # Principle VII: when the importer (!7) added the second predicate-only
  # scheme, recognition + accessors were extended in PredicateOnlyUri
  # rather than reintroducing a sibling constant here.
  alias Recurse.Gateway.AuditPlane.PredicateOnlyUri

  @doc """
  The exact bytes `build_system/4` / `build_imported/4` hash into
  `payload_hash`: the predicate map with its top-level keys stringified,
  JCS-encoded (RFC 8785). Spec 012 S6b: the emitter retains these bytes
  in the StorageProvider so a verifier can recompute the hash; keeping
  the encoding in ONE function is what makes "bytes put == bytes hashed"
  a property of the code rather than a convention.
  """
  @spec system_predicate_bytes(system_predicate()) :: binary()
  def system_predicate_bytes(predicate_map) when is_map(predicate_map),
    do: predicate_map |> stringify_top_level_keys() |> Jcs.encode()

  @doc """
  Build a signed attestation envelope for a system event with no
  request/response payload (F004 T055a).

  See "System-event variant" comment block above for the full design rationale.
  Returns `{:ok, %Envelope{}}` on success; any step failure short-circuits to
  `{:error, {step_name, reason}}` with the same error tag scheme as `build/7`.

  The `predicate_map` argument is the F004 caller-controlled metadata that
  describes the system action (e.g., `%{outcome: "rejected_no_role"}` for a
  login rejection, or `%{data_class: "chat_history", soft_deleted_count: 12}`
  for a retention cycle). It is canonicalized via JCS and SHA-256-hashed for
  `payload_hash` so the receipt round-trips deterministically.
  """
  @spec build_system(
          event_kind :: SignedPredicate.event_kind(),
          IdentityContext.t(),
          system_predicate(),
          system_opts()
        ) :: {:ok, Envelope.t()} | build_error()
  def build_system(event_kind, %IdentityContext{} = identity_ctx, predicate_map, opts)
      when is_atom(event_kind) and is_map(predicate_map) and is_list(opts) do
    if event_kind in SignedPredicate.event_kinds() do
      do_build_system(event_kind, identity_ctx, predicate_map, opts)
    else
      {:error, {:invalid_event_kind, event_kind}}
    end
  end

  defp do_build_system(event_kind, identity_ctx, predicate_map, opts) do
    run_id = Keyword.fetch!(opts, :run_id)
    session_id = Keyword.get(opts, :session_id, run_id)
    turn_id = Keyword.get(opts, :turn_id, run_id)
    signer = Keyword.get(opts, :signer, "observed://gateway")

    {secrets_mod, secrets_state} = Keyword.fetch!(opts, :secrets_provider)
    timestamp = Keyword.get(opts, :timestamp, DateTime.utc_now())

    policy_canonical_hash =
      Keyword.get(opts, :policy_canonical_hash, PredicateOnlyUri.system_event_no_policy_hash())

    payload_bytes = system_predicate_bytes(predicate_map)
    payload_hash = :crypto.hash(:sha256, payload_bytes)
    payload_uri = PredicateOnlyUri.build(run_id)

    with {:ok, signing_key_handle} <- active_signing_key(secrets_mod, secrets_state),
         predicate =
           build_system_predicate(%{
             event_kind: event_kind,
             identity_ctx: identity_ctx,
             policy_canonical_hash: policy_canonical_hash,
             payload_hash: payload_hash,
             payload_uri: payload_uri,
             signer: signer,
             run_id: run_id,
             session_id: session_id,
             session_chain_position: 0,
             turn_id: turn_id,
             timestamp: timestamp
           }),
         predicate_bytes = Jcs.encode(SignedPredicate.to_map(predicate)),
         pae_bytes = Dsse.pae(@dsse_payload_type, predicate_bytes),
         {:ok, signature} <- sign(secrets_mod, secrets_state, signing_key_handle, pae_bytes) do
      dsse_envelope = build_dsse_envelope(predicate_bytes, signature, signing_key_handle)
      outer = build_outer_container()
      {:ok, Envelope.new(predicate, outer, dsse_envelope)}
    end
  end

  @doc """
  Build a signed attestation envelope for an imported source event.

  Imported source-session receipts are predicate-only inside the Gateway
  import path, but unlike system events they represent external source
  artifacts. Their `payload_uri` must use `recurse://import/...` so verifiers
  can distinguish "source artifact imported, not CAS-stashed here" from
  "system event with no payload".
  """
  @spec build_imported(
          event_kind :: SignedPredicate.event_kind(),
          IdentityContext.t(),
          system_predicate(),
          imported_opts()
        ) :: {:ok, Envelope.t()} | build_error()
  def build_imported(event_kind, %IdentityContext{} = identity_ctx, predicate_map, opts)
      when is_atom(event_kind) and is_map(predicate_map) and is_list(opts) do
    if event_kind in SignedPredicate.event_kinds() do
      do_build_imported(event_kind, identity_ctx, predicate_map, opts)
    else
      {:error, {:invalid_event_kind, event_kind}}
    end
  end

  defp do_build_imported(event_kind, identity_ctx, predicate_map, opts) do
    run_id = Keyword.fetch!(opts, :run_id)
    session_id = Keyword.get(opts, :session_id, run_id)
    turn_id = Keyword.get(opts, :turn_id, run_id)
    signer = Keyword.get(opts, :signer, "observed://gateway")

    {secrets_mod, secrets_state} = Keyword.fetch!(opts, :secrets_provider)
    timestamp = Keyword.get(opts, :timestamp, DateTime.utc_now())

    policy_canonical_hash =
      Keyword.get(opts, :policy_canonical_hash, PredicateOnlyUri.system_event_no_policy_hash())

    payload_bytes = system_predicate_bytes(predicate_map)
    payload_hash = :crypto.hash(:sha256, payload_bytes)

    with {:ok, session_chain_position} <- imported_session_chain_position(opts),
         {:ok, payload_uri} <- imported_payload_uri(opts),
         {:ok, signing_key_handle} <- active_signing_key(secrets_mod, secrets_state),
         predicate =
           build_system_predicate(%{
             event_kind: event_kind,
             identity_ctx: identity_ctx,
             policy_canonical_hash: policy_canonical_hash,
             payload_hash: payload_hash,
             payload_uri: payload_uri,
             signer: signer,
             run_id: run_id,
             session_id: session_id,
             session_chain_position: session_chain_position,
             turn_id: turn_id,
             timestamp: timestamp
           }),
         predicate_bytes = Jcs.encode(SignedPredicate.to_map(predicate)),
         pae_bytes = Dsse.pae(@dsse_payload_type, predicate_bytes),
         {:ok, signature} <- sign(secrets_mod, secrets_state, signing_key_handle, pae_bytes) do
      dsse_envelope = build_dsse_envelope(predicate_bytes, signature, signing_key_handle)
      outer = build_outer_container()
      {:ok, Envelope.new(predicate, outer, dsse_envelope)}
    end
  end

  defp imported_payload_uri(opts) do
    payload_uri = Keyword.get(opts, :payload_uri)

    if PredicateOnlyUri.match_imported?(payload_uri) do
      {:ok, payload_uri}
    else
      {:error, {:invalid_import_payload_uri, payload_uri}}
    end
  end

  defp imported_session_chain_position(opts) do
    position = Keyword.get(opts, :session_chain_position, 0)

    if is_integer(position) and position >= 0 do
      {:ok, position}
    else
      {:error, {:invalid_session_chain_position, position}}
    end
  end

  defp build_system_predicate(inputs) do
    %{
      event_kind: event_kind,
      identity_ctx: identity_ctx,
      policy_canonical_hash: policy_canonical_hash,
      payload_hash: payload_hash,
      payload_uri: payload_uri,
      signer: signer,
      run_id: run_id,
      session_id: session_id,
      session_chain_position: session_chain_position,
      turn_id: turn_id,
      timestamp: timestamp
    } = inputs

    %SignedPredicate{
      envelope_version: @envelope_version,
      run_id: run_id,
      step_id: run_id,
      turn_id: turn_id,
      session_id: session_id,
      session_chain_position: session_chain_position,
      event_kind: event_kind,
      timestamp: DateTime.to_iso8601(timestamp),
      tenant_id: identity_ctx.tenant_id,
      machine_identity: normalize_machine_identity(identity_ctx.machine_identity),
      principal: principal_to_map(identity_ctx.principal),
      policy_canonical_hash: policy_canonical_hash,
      payload_hash: payload_hash,
      payload_uri: payload_uri,
      correlation_id: identity_ctx.correlation_id,
      signer: signer
    }
  end

  # JCS encodes maps with string keys lexicographically. Atom-keyed maps come
  # out the same way per Jcs.encode/1's promotion rule, but normalizing here
  # makes the payload-hash invariant explicit at the boundary: the bytes
  # hashed are the bytes a verifier reproduces.
  defp stringify_top_level_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} when is_binary(k) -> {k, v}
    end)
  end

  # Public accessors `system_event_no_policy_hash/0`,
  # `system_event_payload_uri_scheme/0`, and
  # `imported_event_payload_uri_scheme/0` were removed in issue #29 /
  # AD-1 Option A and !7's importer landing. Callers should use
  # `Recurse.Gateway.AuditPlane.PredicateOnlyUri` directly:
  #
  #   * PredicateOnlyUri.system_event_no_policy_hash/0
  #   * PredicateOnlyUri.uri_scheme_prefix/0
  #   * PredicateOnlyUri.imported_uri_scheme_prefix/0
  #   * PredicateOnlyUri.match?/1, match_imported?/1, kind/1 (recognition)
  #   * PredicateOnlyUri.build/1, build_imported/2 (construction)
end
