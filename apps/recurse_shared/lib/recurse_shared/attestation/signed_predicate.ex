defmodule Recurse.Shared.Attestation.SignedPredicate do
  @moduledoc """
  Signed-immutable in-toto v1.0 predicate payload per FR-021.

  The DSSE envelope wraps a serialization of this struct. Every field
  listed here is part of the cryptographically signed payload — once
  emitted, these fields NEVER mutate. Outer-container state
  (`verification_level`, inclusion proofs, etc.) lives separately in
  `Recurse.Shared.Attestation.OuterContainer`.

  ## Source-of-truth alignment

  The field set here MUST match `specs/001-api-jido-foundations/contracts/
  attestation.schema.json` — the auditor's JSON Schema validates receipts
  against that document, so any drift between this struct and the schema
  produces envelopes that fail off-platform verification. Caught by
  speckit-pr-review iteration-2 F002 on PR #1.

  ## Fields (FR-021 signed core)

    * `envelope_version` — semver starting at `"1.0"`
    * `run_id` — ULID; groups multiple `step_id`s in one logical agent run
    * `step_id` — ULID; unique within `run_id`
    * `turn_id` — ULID, optional — parent for parallel tool calls per FR-041
    * `session_id` — ULID; enclosing agent session per FR-036
    * `session_chain_position` — monotonic non-negative integer; immutable
      index within the session
    * `event_kind` — one of the 31 enumerated atoms (5 F002 +
      24 F004 + 2 MCP) returned by `event_kinds/0`. Typed in-memory; serialized as
      the corresponding string. F002 atoms cover LLM/tool/policy/session
      events; F004 atoms cover Audit Console UI surfaces (every `:ui_*`
      action emitted by browser sessions, login flows, retention purgers,
      etc., per `specs/004-audit-console/data-model.md` §0). The
      `:mcp_tool_call` atom (added in the MCP/SBOM/Trusted-Registry
      vertical slice) covers every hosted-MCP tool dispatch — agents
      calling `POST /v1/mcp/<server>/tools/<tool>` produce a receipt
      identifying which MCP server + tool + agent identity executed.
    * `timestamp` — RFC 3339 UTC string (trust anchor per FR-031)
    * `tenant_id` — ULID
    * `machine_identity` — either `%{spiffe_id: String.t()}` (Governance
      shapes) or `%{observed_jwt_subject: String.t(), observed_jwt_issuer:
      String.t()}` (Standalone Gateway shape per FR-017). Discriminated at
      serialization time by which keys are present.
    * `principal` — canonical principal claim per FR-026
      (`%{kind, schema_version, ...}`)
    * `policy_canonical_hash` — 32 raw bytes; serialized as `"sha256:<hex>"`
      per schema
    * `tool_sbom_ref` — optional string
    * `payload_hash` — 32 raw bytes; serialized as `"sha256:<hex>"` per schema
    * `payload_uri` — customer-storage location
    * `correlation_id` — ULID per FR-018
    * `signer` — SPIFFE ID of the Gateway instance (per-FR-021 "emitter"
      identity, distinct from the KMS-backed signing key referenced via the
      DSSE signature `keyid` per FR-046)
  """

  @type machine_identity ::
          %{required(:spiffe_id) => String.t()}
          | %{
              required(:observed_jwt_subject) => String.t(),
              required(:observed_jwt_issuer) => String.t()
            }

  @type event_kind ::
          :llm_call
          | :tool_call
          | :egress_denied
          | :policy_denied
          | :session_abort
          | :ui_login
          | :ui_session
          | :ui_query
          | :ui_policy_simulate
          | :ui_policy_replay
          | :ui_policy_draft_created
          | :ui_policy_draft_edited
          | :ui_policy_draft_archived
          | :ui_policy_draft_dry_run
          | :ui_policy_suggestion_generated
          | :ui_policy_suggestion_viewed
          | :ui_policy_suggestion_adopted
          | :ui_policy_suggestion_dismissed
          | :ui_policy_suggestion_refresh_requested
          | :ui_chat
          | :ui_chat_skill_invoked_query_receipts
          | :ui_chat_skill_invoked_fetch_receipt_detail
          | :ui_chat_skill_invoked_explain_denial
          | :ui_chat_skill_invoked_find_similar_receipts
          | :ui_chat_skill_invoked_simulate_policy_dryrun
          | :ui_chat_skill_invoked_suggest_policy_pattern
          | :ui_payload_access
          | :ui_evidence_export
          | :ui_retention_purge
          | :ui_mcp_quarantine
          | :mcp_tool_call
          | :policy_bundle_activated
          | :llm_call_attested
          | :tool_use_denied

  @type t :: %__MODULE__{
          envelope_version: String.t(),
          run_id: String.t(),
          step_id: String.t(),
          turn_id: String.t() | nil,
          session_id: String.t(),
          session_chain_position: non_neg_integer(),
          event_kind: event_kind(),
          timestamp: String.t(),
          tenant_id: String.t(),
          machine_identity: machine_identity(),
          principal: map(),
          policy_canonical_hash: binary(),
          tool_sbom_ref: String.t() | nil,
          payload_hash: binary(),
          payload_uri: String.t(),
          correlation_id: String.t(),
          signer: String.t()
        }

  @enforce_keys [
    :envelope_version,
    :run_id,
    :step_id,
    :session_id,
    :session_chain_position,
    :event_kind,
    :timestamp,
    :tenant_id,
    :machine_identity,
    :principal,
    :policy_canonical_hash,
    :payload_hash,
    :payload_uri,
    :correlation_id,
    :signer
  ]
  defstruct envelope_version: "1.0",
            run_id: nil,
            step_id: nil,
            turn_id: nil,
            session_id: nil,
            session_chain_position: nil,
            event_kind: nil,
            timestamp: nil,
            tenant_id: nil,
            machine_identity: nil,
            principal: nil,
            policy_canonical_hash: nil,
            tool_sbom_ref: nil,
            payload_hash: nil,
            payload_uri: nil,
            correlation_id: nil,
            signer: nil

  # 34 atoms total: 5 F002 (LLM/tool/policy/session lifecycle) + 24 F004
  # (Audit Console UI surfaces, per specs/004-audit-console/data-model.md §0)
  # + 2 MCP (`:mcp_tool_call` from the hosted MCP server vertical slice
  # plus `:ui_mcp_quarantine` from the registry operator-mutation surface)
  # + 1 OCI (`:policy_bundle_activated`)
  # + 2 Spec 009 (`:llm_call_attested`, `:tool_use_denied` — Phase 3
  # Sub-3.7 attestation emitter).
  # MUST stay in lockstep with:
  #   * `Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation.@event_kind_values`
  #   * Migration `priv/repo/migrations/20260424900000_f004_widen_event_kind_check.exs`
  #     (the DB CHECK constraint).
  # AD-001 c' note: `apps/recurse_shared/` is NOT pinned by
  # `scripts/verify-ad001-behaviour-surfaces.sh`; the guard only covers
  # behaviour files under `apps/recurse_providers/lib/recurse_providers/*_provider.ex`.
  # Widening this list is a routine union-extension, not a constitutional event.
  @event_kinds [
    # F002 base (5 atoms)
    :llm_call,
    :tool_call,
    :egress_denied,
    :policy_denied,
    :session_abort,
    # F004 UI session lifecycle (3 atoms)
    :ui_login,
    :ui_session,
    :ui_query,
    # F004 Policy Simulator (2 atoms)
    :ui_policy_simulate,
    :ui_policy_replay,
    # F004 Policy Draft lifecycle (4 atoms; :adopted deferred F005+)
    :ui_policy_draft_created,
    :ui_policy_draft_edited,
    :ui_policy_draft_archived,
    :ui_policy_draft_dry_run,
    # F004 Policy Suggestion lifecycle (5 atoms)
    :ui_policy_suggestion_generated,
    :ui_policy_suggestion_viewed,
    :ui_policy_suggestion_adopted,
    :ui_policy_suggestion_dismissed,
    :ui_policy_suggestion_refresh_requested,
    # F004 Chat drawer (1 atom)
    :ui_chat,
    # F004 Audit-agent six-tool vocabulary (6 atoms)
    :ui_chat_skill_invoked_query_receipts,
    :ui_chat_skill_invoked_fetch_receipt_detail,
    :ui_chat_skill_invoked_explain_denial,
    :ui_chat_skill_invoked_find_similar_receipts,
    :ui_chat_skill_invoked_simulate_policy_dryrun,
    :ui_chat_skill_invoked_suggest_policy_pattern,
    # F004 reused-action UI surfaces (2 atoms)
    :ui_payload_access,
    :ui_evidence_export,
    # F004 retention purge (1 atom; system principal — every data-plane
    # mutation is attestable per Principle III, even automated maintenance)
    :ui_retention_purge,
    # MCP Trusted Registry operator-mutation (1 atom)
    # Emitted by `Recurse.Gateway.Admin.McpRegistryHandler.update/1` when an
    # operator quarantines or restores an MCP server entry via
    # `PATCH /v1/mcp/registry/:id`. Receipts include the entry id, prior +
    # new trust_tier, the operator's principal_subject, and (when
    # quarantining) the auditor-supplied reason — closes the F7 quarantine
    # workflow loop with the same Principle III provenance the runtime
    # `:mcp_tool_call` denials carry.
    :ui_mcp_quarantine,
    # MCP/Trusted-Registry vertical slice (1 atom)
    # Emitted by `Recurse.Gateway.DataPlane.McpServerHandler` for every
    # hosted-MCP tool dispatch. Receipts include which MCP server + tool +
    # agent identity executed, plus the trust_tier of the registry entry
    # at call time (so quarantined-server denials are also attested).
    :mcp_tool_call,
    # OCI Cedar bundle activation (1 atom)
    # Emitted by `Recurse.Gateway.Admin.CedarBundleActivateHandler`
    # after a successful `OciBundleManager.activate/2`. Receipts
    # carry old_digest → new_digest + source_ref + operator
    # principal_subject so policy-state replay can reconstruct which
    # bundle was active at any past evaluation.
    :policy_bundle_activated,
    # Spec 009 LLM API Proxy — Phase 3 Sub-3.7 (2 atoms).
    # `:llm_call_attested` — exactly one per LLM call (request → final
    # response chunk). Emitted by
    # `Recurse.Gateway.LlmProxy.AttestationEmitter.emit_call_attestation/1`
    # at connection close (Invariant I-004). Carries full call metadata +
    # the per-tool-intent decisions array (tool_use_intents).
    # `:tool_use_denied` — exactly one per `decision == :deny` intent;
    # references the parent `:llm_call_attested` via
    # `parent_llm_call_run_id`.
    # Lockstep follow-ups required in same MR:
    #   * `UiReceipts.@allowed_event_kinds` + `ui_event_kind` typespec
    #   * `Attestation.@event_kind_values` (Ecto.Enum cast)
    #   * Migration `20260507000004_event_kinds_llm_call_attested_and_tool_use_denied.exs`
    :llm_call_attested,
    :tool_use_denied
  ]

  @doc "Valid event_kind atom values per attestation.schema.json."
  @spec event_kinds() :: [event_kind()]
  def event_kinds, do: @event_kinds

  @doc """
  Convert the struct to a JSON-compatible map suitable for JCS encoding.

  Field names match `attestation.schema.json#/$defs/RecursePredicate`:
  flat `machine_identity` + `principal` (not nested under `identities`),
  `sha256:<hex>` prefixed hashes, `event_kind` required. Absent optional
  fields are omitted (not emitted as `null`).
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = sp) do
    %{
      "envelope_version" => sp.envelope_version,
      "run_id" => sp.run_id,
      "step_id" => sp.step_id,
      "session_id" => sp.session_id,
      "session_chain_position" => sp.session_chain_position,
      "event_kind" => Atom.to_string(sp.event_kind),
      "timestamp" => sp.timestamp,
      "tenant_id" => sp.tenant_id,
      "machine_identity" => normalize_machine_identity(sp.machine_identity),
      "principal" => sp.principal,
      "policy_canonical_hash" => prefix_sha256(sp.policy_canonical_hash),
      "payload_hash" => prefix_sha256(sp.payload_hash),
      "payload_uri" => sp.payload_uri,
      "correlation_id" => sp.correlation_id,
      "signer" => sp.signer
    }
    |> maybe_put("turn_id", sp.turn_id)
    |> maybe_put("tool_sbom_ref", sp.tool_sbom_ref)
  end

  defp normalize_machine_identity(%{spiffe_id: sid}), do: %{"spiffe_id" => sid}

  defp normalize_machine_identity(%{
         observed_jwt_subject: sub,
         observed_jwt_issuer: iss
       }) do
    %{"observed_jwt_subject" => sub, "observed_jwt_issuer" => iss}
  end

  defp prefix_sha256(<<bytes::binary-size(32)>>),
    do: "sha256:" <> Base.encode16(bytes, case: :lower)

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
