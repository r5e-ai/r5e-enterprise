defmodule Recurse.Gateway.Admin.BrowserAuth.UiReceipts do
  @moduledoc """
  UI receipt emission seam for the F004 browser-auth handlers
  (LoginHandler, LogoutHandler, BrowserSessionPlug).

  Per `contracts/browser_oidc_flow.md` Steps 4 + 6 + §"Sign-out", every
  successful or failed login / session / logout event MUST be attestable
  per Constitution Principle III ("everything attestable").

  ## Wave 3A wiring (T055a, F004)

  This module now performs a real DSSE-signed ledger commit for every
  emitted event:

    1. Build a system-event envelope via
       `Recurse.Gateway.Attestation.EnvelopeBuilder.build_system/4`.
    2. Persist the envelope through the configured `LedgerProvider`'s
       rich `commit_attestation/2` surface (F002 AD-001 c').
    3. Emit a `[:recurse, :ui_receipt, :emitted]` telemetry event +
       `Logger.info` line so existing test fixtures and SIEM tails
       continue to observe the same out-of-band shape.

  Emission failures are isolated — a ledger-commit error logs at
  `:error` and emits the telemetry-only fallback so the request path
  NEVER fails because of an audit gap. This keeps user-facing flows
  resilient against transient signing-service or DB outages while
  surfacing the gap loudly in Vector / SIEM (FR-031: "a missing
  receipt is an audit gap, not a user-facing failure").

  ## Iron Law check (`elixir:elixir-thinking`)

    1. Mutable state? No — every call assembles its own envelope from
       arguments + provider-registry lookups; no per-call BEAM state.
    2. Concurrent execution? No — runs synchronously on the caller
       process (the Plug handler). Multiple requests run in parallel
       naturally; the ledger commit's SERIALIZABLE transaction is what
       serializes Postgres writes.
    3. Fault isolation? No — failures rescue + log, do not raise.

  All three NO → plain functions.

  ## Why a `:service_account` system principal

  System events lack an OBO-human principal. Per F001 `Principal.kind`
  vocabulary the `:service_account` shape is the closest fit — it
  carries an `account_id` (we use `"recurse-gateway-system"` so
  auditors recognize the receipt as system-emitted, not OBO-on-behalf-
  of) and an `issuer` (the Gateway's emitter identity). The
  `recurse_role` slot stays nil — system events are not Cedar-gated
  through the role allowlist; they are an internal data-plane mutation
  attestable per Principle III.

  The login-success path is a special case: the principal IS known
  (the `:principal_subject` claim from the IdP), so we materialize an
  `:obo_human` principal. The `meta[:principal_subject]` discriminator
  is the seam for that bifurcation.

  ## Receipt shape

  The receipt's signed predicate carries:

    * `event_kind` — one of `:ui_login | :ui_session`
    * `principal` — `:obo_human` (login success) or `:service_account`
      (everything else; the operator-side principal isn't yet known
      until a session is established)
    * `payload_hash` — SHA-256 of the JCS-encoded `meta` map (the
      `outcome`/`event` discriminator + IDs are inside the payload
      bytes, byte-stable + auditor-reproducible)
    * `payload_uri` — `recurse://system/predicate-only/<run_id>`
      (sentinel — there is no S3 payload to fetch)

  Telemetry metadata mirrors the predicate's discriminator fields so
  test fixtures and dashboards built against the W2-A telemetry surface
  continue to fire identically.

  ## Cross-references

    * `specs/004-audit-console/contracts/browser_oidc_flow.md` Step 4 / 6 / Sign-out
    * `specs/004-audit-console/data-model.md` §0 (canonical event_kind matrix)
    * `apps/recurse_gateway/lib/recurse_gateway/attestation/envelope_builder.ex`
      `build_system/4` (the predicate-only envelope variant)
  """

  require Logger

  alias Recurse.Gateway.Attestation.EnvelopeBuilder
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @telemetry_event [:recurse, :ui_receipt, :emitted]
  @system_account_id "recurse-gateway-system"

  @typedoc """
  F004 `event_kind` atoms emitted by browser-auth + console handlers.

  Originally scoped to the BrowserAuth surface (login/session lifecycle);
  widened in F004 Phase 3 (T060/T061/T063) to cover `:ui_query` from the
  Audit Log and Session Timeline handlers, since the same receipt seam
  is the right place to materialize ALL `:ui_*` attestations through.
  Future F004 phases (Policy Simulator, Audit Agent) extend this list
  as they land — see `data-model.md` §0 for the canonical matrix.
  """
  @type ui_event_kind ::
          :ui_login
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

  # Allowlist — drives the emit/2 guard. Any new atom here MUST also
  # appear in `Recurse.Shared.Attestation.SignedPredicate.@event_kinds`
  # AND the DB CHECK enum (F004 widening migration). The lockstep is
  # documented at the SignedPredicate module-attribute comment.
  @allowed_event_kinds [
    :ui_login,
    :ui_session,
    :ui_query,
    :ui_policy_simulate,
    :ui_policy_replay,
    :ui_policy_draft_created,
    :ui_policy_draft_edited,
    :ui_policy_draft_archived,
    :ui_policy_draft_dry_run,
    :ui_policy_suggestion_generated,
    :ui_policy_suggestion_viewed,
    :ui_policy_suggestion_adopted,
    :ui_policy_suggestion_dismissed,
    :ui_policy_suggestion_refresh_requested,
    :ui_chat,
    :ui_chat_skill_invoked_query_receipts,
    :ui_chat_skill_invoked_fetch_receipt_detail,
    :ui_chat_skill_invoked_explain_denial,
    :ui_chat_skill_invoked_find_similar_receipts,
    :ui_chat_skill_invoked_simulate_policy_dryrun,
    :ui_chat_skill_invoked_suggest_policy_pattern,
    :ui_payload_access,
    :ui_evidence_export,
    :ui_retention_purge,
    # MCP Trusted Registry operator-mutation. `:ui_mcp_quarantine` is the
    # F7 operator-action atom emitted by `McpRegistryHandler.update/1` when
    # an operator quarantines or restores an entry. The principal IS known
    # (the operator's IdentityContext) but we emit through the same
    # `service_account` system-event path as the other write surfaces — the
    # auditor-meaningful `principal_subject` is in the payload metadata.
    :ui_mcp_quarantine,
    # MCP/Trusted-Registry vertical slice — `:mcp_tool_call` is NOT a
    # `:ui_*` UI surface; it is an agent-emitted hosted-MCP tool dispatch
    # receipt. The seam (predicate-only system event via
    # EnvelopeBuilder.build_system/4) is the right shape for it though,
    # so we widen the allowlist rather than re-implementing the seam.
    # A follow-up MR should rename this module to `SystemReceipts` and
    # split the type alias into `:ui_event_kind | :mcp_event_kind` —
    # tracked in this MR's reflect.
    :mcp_tool_call,
    # OCI Cedar bundle activation — emitted by
    # `CedarBundleActivateHandler` after a successful
    # `OciBundleManager.activate/2`. Records the old → new bundle
    # digest pair so receipt audits can replay the policy state at
    # any point in time. Lockstep: SignedPredicate.@event_kinds + DB
    # CHECK migration `2026...policy_bundle_activated_event_kind`.
    :policy_bundle_activated,
    # Spec 009 LLM API Proxy — Phase 3 Sub-3.7. NOT a `:ui_*` UI surface;
    # these are agent-emitted LLM-call attestations (`:llm_call_attested`)
    # and per-deny tool-intent attestations (`:tool_use_denied`). The
    # canonical emission path is
    # `Recurse.Gateway.LlmProxy.AttestationEmitter.emit_call_attestation/1`,
    # which uses `EnvelopeBuilder.build_system/4` directly rather than
    # going through this module's `emit_strict/2` allowlist guard. They
    # are still listed here so any future call site that DOES route via
    # `emit_strict/2` (e.g., synthetic test fixtures, debugging surfaces)
    # is permitted by the same guard. Lockstep:
    # SignedPredicate.@event_kinds + Attestation.@event_kind_values +
    # migration 20260507000004.
    :llm_call_attested,
    :tool_use_denied
  ]

  @typedoc """
  Metadata accepted by `emit/2`. `outcome` is mandatory for `:ui_login`,
  `event` for `:ui_session`. Additional keys flow through unchanged.
  """
  @type meta :: %{
          optional(:outcome) => String.t(),
          optional(:event) => String.t(),
          optional(:principal_subject) => String.t() | nil,
          optional(:browser_session_id) => String.t() | nil,
          optional(:tenant_id) => String.t() | nil,
          optional(:correlation_id) => String.t() | nil,
          optional(any()) => any()
        }

  @doc """
  Emit a UI receipt for the given `event_kind`. Returns `:ok` always —
  never raises (per fault-isolation rule).

  Mints a fresh `run_id` (UUID) so callers don't have to thread one
  through. The receipt is committed to the ledger via the configured
  `LedgerProvider`'s `commit_attestation/2` rich surface; on failure
  the telemetry-only emission still fires so the gap is observable.

  Example:

      UiReceipts.emit(:ui_login, %{outcome: "success",
                                   principal_subject: "alice@corp",
                                   browser_session_id: bsid,
                                   tenant_id: "t-1"})

      UiReceipts.emit(:ui_session, %{event: "absolute_timeout",
                                     browser_session_id: bsid,
                                     tenant_id: "t-1"})
  """
  @spec emit(ui_event_kind(), meta()) :: :ok
  def emit(event_kind, meta \\ %{})
      when event_kind in @allowed_event_kinds and is_map(meta) do
    run_id = Ecto.UUID.generate()
    enriched = meta |> Map.put(:event_kind, event_kind) |> Map.put(:run_id, run_id)

    _ = safe_commit(event_kind, enriched, meta)
    safe_dispatch_telemetry(enriched)
    :ok
  end

  @doc """
  Strict variant of `emit/2`: returns `{:ok, run_id} | {:error, reason}`
  instead of swallowing ledger-commit failures.

  Use this for handlers where Constitution Principle III requires the
  receipt to be ledger-committed BEFORE the HTTP response goes out (i.e.
  every write that mutates persistent state). The caller is responsible
  for translating an `{:error, _}` return into a 5xx response AND
  rolling back any state the request had already mutated, so the audit
  log invariant — every committed receipt corresponds to a real
  state change — is preserved.

  Telemetry still fires on both branches so SIEM tails see the same
  out-of-band signal regardless of ledger outcome.

  Compare to `emit/2`, which logs commit failures and returns `:ok` to
  keep request paths resilient against transient signing/DB outages —
  appropriate for read-only or session-lifecycle events where the gap
  is acceptable, but NOT for state-changing endpoints.
  """
  @spec emit_strict(ui_event_kind(), meta()) ::
          {:ok, String.t()} | {:error, term()}
  def emit_strict(event_kind, meta \\ %{})
      when event_kind in @allowed_event_kinds and is_map(meta) do
    run_id = Ecto.UUID.generate()
    enriched = meta |> Map.put(:event_kind, event_kind) |> Map.put(:run_id, run_id)

    case safe_commit(event_kind, enriched, meta) do
      :ok ->
        safe_dispatch_telemetry(enriched)
        {:ok, run_id}

      :error ->
        # Telemetry-only fallback so the gap is visible in SIEM even
        # though the strict caller will return 5xx + roll back state.
        safe_dispatch_telemetry(Map.put(enriched, :ledger_commit, :failed))
        {:error, :ledger_commit_failed}
    end
  end

  # Build + commit the system-event envelope via the configured
  # LedgerProvider. Never raises; on any error logs a single line and
  # returns `:error` so the caller falls through to telemetry-only mode.
  defp safe_commit(event_kind, enriched, original_meta) do
    case ProviderRegistry.fetch() do
      {:ok, _registry} ->
        do_commit(event_kind, enriched, original_meta)

      {:error, :not_installed} ->
        # No provider registry installed (mostly a unit-test scenario where
        # the fixture only attaches telemetry). This is not an audit gap —
        # the handler under test is not the integration system.
        :ok
    end
  rescue
    error ->
      Logger.error(fn ->
        "ui_receipt commit raised: #{inspect(error)} event_kind=#{inspect(event_kind)}"
      end)

      :error
  end

  defp do_commit(event_kind, enriched, _original_meta) do
    {secrets_mod, secrets_state} = ProviderRegistry.secrets_provider()
    {ledger_mod, _ledger_state} = ProviderRegistry.ledger_provider()
    tenant_id = Map.get(enriched, :tenant_id) || ProviderRegistry.tenant_id()
    signer = ProviderRegistry.signer()

    identity_ctx =
      IdentityContext.new(%{
        machine_identity: signer,
        principal: principal_for(event_kind, enriched, signer),
        tenant_id: tenant_id,
        correlation_id: Map.get(enriched, :correlation_id) || enriched.run_id
      })

    predicate_map = system_predicate_map(enriched)

    with {:ok, envelope} <-
           EnvelopeBuilder.build_system(
             event_kind,
             identity_ctx,
             predicate_map,
             run_id: enriched.run_id,
             secrets_provider: {secrets_mod, secrets_state},
             signer: signer
           ),
         {:ok, _result} <- commit_envelope(ledger_mod, envelope) do
      :ok
    else
      {:error, reason} ->
        Logger.error(fn ->
          "ui_receipt ledger commit failed: #{inspect(reason)} " <>
            "event_kind=#{inspect(event_kind)} run_id=#{enriched.run_id}"
        end)

        :error
    end
  end

  # Two paths matching the F002 ChatCompletionsHandler convention: the
  # Postgres impl gets called directly; alternative ledgers fall back to
  # `function_exported?/3` so the surface stays forward-compatible without
  # special-casing tests.
  defp commit_envelope(Recurse.Providers.Impls.PostgresMerkleLedger = mod, envelope) do
    mod.commit_attestation(envelope, [])
  end

  defp commit_envelope(mod, envelope) do
    if function_exported?(mod, :commit_attestation, 2) do
      mod.commit_attestation(envelope, [])
    else
      {:error, {:ledger_provider_missing_commit_attestation, mod}}
    end
  end

  # Login-success ⇒ obo_human (the IdP's principal_subject IS known and
  # is the auditor-meaningful identity). All other paths ⇒ service_account
  # (system principal — the UI flow is acting on behalf of the platform,
  # not a specific user; the cookie-tampered / state-invalid / etc. paths
  # by definition cannot resolve a user identity).
  defp principal_for(:ui_login, %{outcome: "success", principal_subject: subject}, signer)
       when is_binary(subject) do
    Principal.obo_human(%{
      issuer: signer,
      subject: subject
    })
  end

  defp principal_for(_event_kind, _meta, signer) do
    Principal.service_account(%{
      issuer: signer,
      account_id: @system_account_id
    })
  end

  # Strip non-payload meta keys (event_kind + run_id are predicate fields
  # already; correlation_id is on the IdentityContext). Everything else
  # flows through to the JCS-encoded payload-hash input.
  defp system_predicate_map(enriched) do
    enriched
    |> Map.drop([:event_kind, :run_id, :correlation_id])
    |> Map.new(fn {k, v} -> {k, normalize_predicate_value(v)} end)
  end

  # Convert atom values to strings so JCS treats them as JSON strings (the
  # encoder expects scalars or maps/lists of scalars). Unknown shapes pass
  # through unchanged.
  defp normalize_predicate_value(v) when is_atom(v) and not is_boolean(v) and not is_nil(v),
    do: Atom.to_string(v)

  defp normalize_predicate_value(v), do: v

  defp safe_dispatch_telemetry(meta) do
    :telemetry.execute(@telemetry_event, %{count: 1}, meta)

    Logger.info(fn ->
      meta
      |> Map.take([
        :event_kind,
        :outcome,
        :event,
        :principal_subject,
        :browser_session_id,
        :tenant_id,
        :correlation_id,
        :run_id
      ])
      |> inspect()
      |> then(&("ui_receipt " <> &1))
    end)
  rescue
    error ->
      Logger.error(fn ->
        "ui_receipt telemetry emission failed: #{inspect(error)} meta=#{inspect(meta)}"
      end)
  end

  @doc """
  Telemetry event name. Useful for `:telemetry.attach/4` test fixtures:

      :telemetry.attach(handler_id, UiReceipts.telemetry_event(),
                        &capture/4, %{pid: self()})
  """
  @spec telemetry_event() :: [atom()]
  def telemetry_event, do: @telemetry_event
end
