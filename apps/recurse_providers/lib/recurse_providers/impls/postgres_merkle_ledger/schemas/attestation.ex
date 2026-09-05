defmodule Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation do
  @moduledoc """
  Ecto schema for the `attestations` table — one row per emitted Attestation
  Envelope per F001 FR-021 + F002 FR-014.

  Cross-references:
    * `specs/002-standalone-gateway-vertical-slice/data-model.md` §Attestation.
    * Migration — `priv/repo/migrations/20260423100000_f002_initial_schemas.exs`.

  Fields split into two bands per the contract:
    * **Signed-predicate columns** (immutable once written): `run_id`,
      `session_id`, `turn_id`, `event_kind`, `machine_identity`, `principal`,
      `tenant_id`, `policy_canonical_hash`, `payload_hash`, `payload_uri`,
      `correlation_id`, `signer_kms_key_id`, `signer_key_version`,
      `timestamp`, `signed_predicate_bytes`, `dsse_signature`.
    * **Outer-container columns** (mutable as `verification_level` advances):
      `verification_level`, `tier_completeness_advisory`, `session_chain_root`,
      `session_chain_epoch`, `local_inclusion_proof`, `global_inclusion_proof`,
      `commit_retry_exhausted`, `policy_decision`, `outcome`,
      `upstream_status_code`.

  `machine_identity` and `principal` ship as JSONB (Ecto `:map`) — the full
  F001 FR-026 principal shape (including `recurse_role`) stores as-is.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.{Session, Tenant}

  # `:llm_call` — successful or upstream-errored allow path (F001 FR-021).
  # `:tool_call` — imported agent session tool-call receipts. Other F002
  # predicate atoms are still contract-level vocabulary, but are not persisted
  # until a production emitter exists.
  # `:policy_denied` — Cedar-deny path (F002 FR-005 / FR-016a / US2). The
  # `EnvelopeBuilder` stamps this `event_kind` for denials so the signed
  # predicate distinguishes denied traversals from permitted ones at the
  # receipt-schema level (auditors can filter on `event_kind` directly
  # without parsing `policy_decision`).
  #
  # F004 (Audit Console) widens this union with 24 `:ui_*` atoms — every
  # UI-emitted action becomes attestable per Principle III. The full list
  # MUST stay in lockstep with the canonical matrix at
  # `specs/004-audit-console/data-model.md` §0 and the DB CHECK widening
  # migration `20260424_f004_widen_event_kind_check.exs` (§2.1). If §0
  # changes, this list AND the migration both change.
  @event_kind_values [
    # F002 persisted base (3 atoms)
    :llm_call,
    :tool_call,
    :policy_denied,
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
    # F004 retention purge (1 atom; not Cedar-gated, but every data-plane
    # mutation is attestable per Principle III)
    :ui_retention_purge,
    # MCP Trusted Registry operator-mutation (1 atom — F7 quarantine workflow)
    :ui_mcp_quarantine,
    # MCP/Trusted-Registry vertical slice (1 atom)
    :mcp_tool_call,
    # Spec A — OCI policy provider hot-reload (MR !119). Emitted by
    # `Recurse.Gateway.Admin.CedarBundleActivateHandler.handle/1` on every
    # successful `POST /v1/admin/cedar-bundle/activate`. Receipts include
    # the operator's principal_subject, the new ref, and old/new digest
    # — Constitution Principle III: every privileged state-changing
    # operation is attestable. Lockstep follow-ups required in same MR:
    # `SignedPredicate.@event_kinds`, `UiReceipts.@allowed_event_kinds`,
    # and a DB CHECK widening migration sibling to
    # `20260501000000_mcp_add_ui_mcp_quarantine_event_kind.exs`.
    :policy_bundle_activated,
    # Spec 009 LLM API Proxy — Phase 3 Sub-3.7 (2 atoms). Emitted by
    # `Recurse.Gateway.LlmProxy.AttestationEmitter.emit_call_attestation/1`
    # at LLM-call connection close. `:llm_call_attested` is the parent
    # per-call predicate carrying the full call metadata + tool_use_intents
    # decisions array; `:tool_use_denied` is the per-deny child predicate
    # referencing the parent via `parent_llm_call_run_id`. Lockstep:
    # `SignedPredicate.@event_kinds`, `UiReceipts.@allowed_event_kinds`,
    # and DB CHECK migration `20260507000004_event_kinds_llm_call_attested
    # _and_tool_use_denied.exs`.
    :llm_call_attested,
    :tool_use_denied
  ]
  @verification_level_values [:signed, :local_inclusion_verified, :global_inclusion_verified]
  @tier_completeness_values [:partial, :full]
  @policy_decision_values [:allow, :deny]
  @outcome_values [:success, :upstream_error, :cancelled]

  @primary_key {:run_id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :run_id,
             :session_id,
             :turn_id,
             :event_kind,
             :machine_identity,
             :principal,
             :tenant_id,
             :correlation_id,
             :signer_kms_key_id,
             :signer_key_version,
             :timestamp,
             :verification_level,
             :tier_completeness_advisory,
             :session_chain_epoch,
             :commit_retry_exhausted,
             :policy_decision,
             :outcome,
             :upstream_status_code,
             :inserted_at,
             :updated_at
           ]}

  schema "attestations" do
    belongs_to(:session, Session,
      foreign_key: :session_id,
      references: :session_id,
      type: :binary_id
    )

    belongs_to(:tenant, Tenant,
      foreign_key: :tenant_id,
      references: :tenant_id,
      type: :string
    )

    # Signed-predicate (immutable once written) -----------------------------
    field(:turn_id, :binary_id)
    field(:event_kind, Ecto.Enum, values: @event_kind_values)
    field(:machine_identity, :map)
    field(:principal, :map)
    field(:policy_canonical_hash, :binary)
    field(:payload_hash, :binary)
    field(:payload_uri, :string)
    field(:correlation_id, :string)
    field(:signer_kms_key_id, :string)
    field(:signer_key_version, :string)
    field(:timestamp, :utc_datetime_usec)
    field(:signed_predicate_bytes, :binary)
    field(:dsse_signature, :binary)

    # Outer-container (mutable as verification_level advances) --------------
    field(:verification_level, Ecto.Enum, values: @verification_level_values)
    field(:tier_completeness_advisory, Ecto.Enum, values: @tier_completeness_values)
    field(:session_chain_root, :binary)
    field(:session_chain_epoch, :integer, default: 0)
    field(:local_inclusion_proof, :binary)
    field(:global_inclusion_proof, :binary)
    field(:commit_retry_exhausted, :boolean, default: false)
    field(:policy_decision, Ecto.Enum, values: @policy_decision_values)
    field(:outcome, Ecto.Enum, values: @outcome_values)
    field(:upstream_status_code, :integer)

    # Demo punch-list B7 — non-signed UI metadata. NOT part of the signed
    # predicate, NOT hashed, NOT verified by DSSE. These light up an
    # already-present forward stub (see `live_tail_socket.ex` `pass_tool_name?/2`
    # and `receipts_handler.ex` `matches_tool_name?/2`) by giving them a
    # column to read. Populated by the importer at commit time; null for
    # event_kinds that don't represent a tool invocation.
    field(:tool_name, :string)
    field(:tool_summary, :string)

    # Tool-call extractor pipeline (2026-04-30) — schema-on-read enriched tags
    # produced by `Recurse.Gateway.Extractors.ClaudeCodeJsonl.extract/1`. NOT
    # part of the signed predicate, NOT hashed, NOT verified by DSSE — same
    # band as `tool_name` / `tool_summary`. The shape is `%{"category" => ...,
    # "display_summary" => ..., "scope_kind" => ..., "scope_value" => ...,
    # "target_resources" => [...], "semantic_args" => %{...}}`. See the
    # extractor module's @moduledoc for per-category semantic_args fields.
    # NULL for non-tool_call rows AND for tool_call rows imported before the
    # extractor existed.
    field(:tags, :map)

    # Spec 012 S6b — where the JCS-encoded predicate body (the bytes
    # `payload_hash` is the SHA-256 of) was retained in the StorageProvider.
    # NOT part of the signed predicate, NOT hashed; NULL when not retained
    # (pre-S6b rows, CAS put failure). See migration
    # `20260902000003_attestations_predicate_body_uri.exs`.
    field(:predicate_body_uri, :string)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @cast_fields [
    :session_id,
    :turn_id,
    :event_kind,
    :machine_identity,
    :principal,
    :tenant_id,
    :policy_canonical_hash,
    :payload_hash,
    :payload_uri,
    :correlation_id,
    :signer_kms_key_id,
    :signer_key_version,
    :timestamp,
    :signed_predicate_bytes,
    :dsse_signature,
    :verification_level,
    :tier_completeness_advisory,
    :session_chain_root,
    :session_chain_epoch,
    :local_inclusion_proof,
    :global_inclusion_proof,
    :commit_retry_exhausted,
    :policy_decision,
    :outcome,
    :upstream_status_code,
    # B7 — non-signed UI metadata; never required.
    :tool_name,
    :tool_summary,
    # Tool-call extractor pipeline — schema-on-read enriched tags; never required.
    :tags,
    # Spec 012 S6b — retained predicate body reference; never required.
    :predicate_body_uri
  ]

  @required_fields [
    :session_id,
    :turn_id,
    :event_kind,
    :machine_identity,
    :principal,
    :tenant_id,
    :policy_canonical_hash,
    :payload_hash,
    :payload_uri,
    :correlation_id,
    :signer_kms_key_id,
    :signer_key_version,
    :timestamp,
    :signed_predicate_bytes,
    :dsse_signature,
    :verification_level,
    :tier_completeness_advisory,
    :policy_decision,
    :outcome
  ]

  @doc """
  Cast + validate an Attestation row. Hash-length invariants
  (`policy_canonical_hash`, `payload_hash`, `session_chain_root` all 32 bytes)
  are enforced at the DB layer via check constraints; this changeset does
  not duplicate them to avoid drift. Business rules such as "set
  `global_inclusion_proof` iff `verification_level = :global_inclusion_verified`"
  live in the commit-pipeline (T033), not here.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(attestation, attrs) do
    attestation
    |> cast(attrs, @cast_fields)
    |> validate_required(@required_fields)
  end
end
