defmodule Recurse.Gateway.LlmProxy.AttestationEmitter do
  @moduledoc """
  Phase 3 Sub-3.7 — single-MR attestation emitter for LLM-call traversals.

  Spec source of truth:
    * `specs/009-llm-api-proxy/contracts/llm_call_attestation.md` — predicate
      shapes (LlmCallAttestation, ToolUseDeniedAttestation), invariants
      I-001..I-004, CT-001..CT-005, PT-001..PT-002.
    * `specs/009-llm-api-proxy/data-model.md` §LlmCallAttestation +
      §ToolUseDeniedAttestation + §LlmCallRecord + §ToolUseIntentRecord.

  ## What this module owns (Constitution Principle III + IV)

  Per Constitution Principle III ("Cryptographic Provenance"), every
  Gateway-traversing LLM call MUST produce exactly one attestation
  (`:llm_call_attested`). Per Constitution Principle IV ("Detached
  Payloads"), the predicate body carries SHA-256 hashes ONLY
  (`prompt_hash`, `response_hash`, `tool_args_hash` — already 32-byte
  bytes computed upstream by the parser / proxy).

  Two predicate shapes are emitted per call:

    1. One `:llm_call_attested` predicate carrying the full call
       metadata + a `tool_use_intents` array (one entry per intent the
       parser extracted).
    2. Zero or more `:tool_use_denied` predicates — one per intent
       whose Cedar decision was `:deny`. Each carries
       `parent_llm_call_run_id` (the parent's `run_id`) so blast-radius
       queries can pivot deny → call.

  In addition to the DSSE-signed predicates the emitter persists the
  queryable mirror rows (`LlmCallRecord` + N `ToolUseIntentRecord`)
  atomically via `Recurse.Providers.LlmCalls.write_call_with_intents/2`.
  The mirror rows are denormalized projections of the signed predicate
  optimized for `GET /v1/audit/llm-calls` (Sub-4.1) — the signed
  predicate is the source of truth, the rows are an index.

  ## Iron Law check (`elixir:elixir-thinking`)

    1. Mutable state across calls? No — every `emit_call_attestation/1`
       call is a pure function of its argument plus provider-registry
       lookups for the ledger / secrets handle.
    2. Concurrent execution? No — runs synchronously on the caller
       (proxy receive loop / WebSock callback). Multiple calls run in
       parallel naturally.
    3. Fault isolation? No — failures return `{:error, reason}` per
       Invariant I-004; the caller (proxy close hook) propagates the
       failure to the client (HTTP 500 / WS close 1011) rather than
       cleanly closing.

  All three NO → plain functions.

  ## Iron Law check (`elixir:ecto-thinking`)

  Two transactions, sequenced:

    1. Sign + commit the parent `:llm_call_attested` envelope via
       `LedgerProvider.commit_attestation/2`. This returns the attestation
       row (with the canonical `run_id` UUID).
    2. For each deny intent: sign + commit a `:tool_use_denied` child
       envelope. The parent `run_id` is captured in the child's predicate
       body (`parent_llm_call_run_id`).
    3. Write the mirror rows: one `LlmCallRecord` (FK
       `signed_predicate_run_id` = parent run_id) + N `ToolUseIntentRecord`s
       in a single `Ecto.Multi` via `LlmCalls.write_call_with_intents/2`.

  Cross-context FK by ID, not association — `signed_predicate_run_id`
  is plain `Ecto.UUID`. We do NOT model an Ecto association across the
  `recurse_providers` ↔ `recurse_gateway` boundary.

  ## Invariant I-004 — emit is the LAST step before connection close

  The proxy close hook calls this function as the final action before
  closing the client connection. On `{:ok, run_id}` the connection
  closes cleanly. On `{:error, _}` the caller propagates the failure to
  the client (HTTP 500 / WS close 1011 with error context) without
  performing a clean close — the agent loop sees the failure and surfaces
  it to the operator.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/attestation/envelope_builder.ex`
      `build_system/4` — DSSE-signing path used here.
    * `apps/recurse_providers/lib/recurse_providers/llm_calls.ex`
      `write_call_with_intents/2` — Sub-3.6 writer this module composes.
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/ui_receipts.ex`
      `do_commit/3` — the closest precedent for the "build_system + commit"
      seam; this module mirrors its commit_envelope/2 helper.
  """

  alias Recurse.Gateway.Attestation.EnvelopeBuilder
  alias Recurse.Gateway.AuditPlane.Resolvers.Payload, as: PayloadStore
  alias Recurse.Gateway.LlmProxy.PayloadCapture
  alias Recurse.Gateway.LlmProxy.PrincipalExtractor
  alias Recurse.Gateway.LlmProxy.RequestKind
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.LlmCalls
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.LlmProxy.ToolUseIntent
  alias Recurse.Shared.Principal

  require Logger

  @predicate_type_call "https://recurse.r5e.io/llm-call/v1"
  @predicate_type_denied "https://recurse.r5e.io/tool-use-denied/v1"
  @in_toto_statement_type "https://in-toto.io/Statement/v1"

  @typedoc """
  Per-intent tuple shape used by the emitter. The first element is the
  canonical `ToolUseIntent` struct produced by the per-provider parser
  (`Recurse.Shared.LlmProxy.ToolUseIntent`); the second is the gate
  decision tuple emitted by `Recurse.Gateway.LlmProxy.CedarToolUseGate`.

  Mirrors the `intents_seen` accumulator on `StreamingProxy` /
  `WebSocketBridge` state.
  """
  @type intent_decision :: {ToolUseIntent.t(), gate_decision()}

  @typedoc """
  Cedar gate decisions per `Recurse.Gateway.LlmProxy.CedarToolUseGate`.

  `{:error, _}` (spec 012 S4 review): the proxy suppresses the intent
  exactly as a deny, so the emitter records it as its own decision
  string `"error"` on the signed predicate, emits a `:tool_use_denied`
  child with `deny_reason: "policy_evaluation_error"`, and counts it in
  `tool_use_denied_count`. The mirror `ToolUseIntentRecord.decision` is
  a closed `allow | deny` enum (DB CHECK), so the row carries `"deny"`
  with the same `deny_reason`; the predicate is the source of truth for
  the distinction. Before this an error stringified as `"deny"` but was
  not counted, the row write failed on
  `:tool_use_denied_count_mismatch`, and the receipt was never written
  after the predicate had been committed.
  """
  @type gate_decision ::
          {:allow}
          | {:deny, %{rule_id: String.t(), reason: String.t()}}
          | {:error, term()}

  @typedoc """
  Per-call emitter input. Field documentation:

    * `:tenant_id` — tenant ULID; ends up on the LlmCallRecord row.
    * `:principal_id` — operator-meaningful identity string (the in-toto
      Statement subject `name`).
    * `:principal_kind` — `"obo_human" | "service_account" | "autonomous"`.
    * `:session_id` — agent session id (mirror of `gate_context_base.session_id`).
    * `:started_at` / `:completed_at` — RFC 3339 / `DateTime.t()`.
    * `:model` / `:provider` / `:upstream_host` / `:transport` /
      `:api_format` / `:request_path` — provider metadata captured at
      proxy open.
    * `:prompt_hash` / `:response_hash` — 32 raw bytes (SHA-256 over
      the exact captured request/response bytes, without canonicalization).
      Interrupted transport may yield only a captured response prefix.
    * `:prompt_token_count` / `:completion_token_count` /
      `:reasoning_token_count` — non-negative integers.
    * `:cedar_bundle_hash` — 32 raw bytes (the opening model admission's
      policy canonical hash; per-tool receipts carry their own policy bindings).
    * `:upstream_status_code` — provider response code (200 success;
      4xx/5xx maps via `:error_kind`).
    * `:error_kind` — nullable closed enum string per
      `LlmCallRecord.@error_kind_values`.
    * `:intents` — list of `intent_decision()` tuples (NOT a list of
      `ToolUseIntent.t()` — Sub-3.4 made this carry the gate decision
      per element).
    * `:latency_ms` / `:added_latency_ms` — non-negative integers.
    * `:correlation_id` — optional ULID; defaults to a freshly minted
      one.
    * `:chatgpt_account_id` — optional; preserved into LlmCallRecord row.
    * `:kind` — optional `RequestKind.kind()` (spec 012 plan §9 D2):
      `:agent_turn | :session_title | :side_query`. Recorded on the
      predicate (`predicate.kind`) and on the receipt's unsigned `tags`
      so the dashboard can filter by it. nil when the transport does not
      classify (WS bridge).
    * `:client_session_id` — optional; the client's own session id
      (`X-Claude-Code-Session-Id` / `metadata.user_id.session_id`).
      Recorded on the predicate (`predicate.client_session_id`) and the
      receipt `tags`; the wrap the dashboard groups leaves by.
    * `:parser` — spec 012 S4 (plan §11): `%{module, version, format}` —
      the recognizer that read the response bytes (`version` is the
      SHA-256 prefix of its source, `format` the wire format + version
      it is exhaustive for). Build it with `parser_identity/3`.
    * `:parse` — `%{events_total, events_unhandled, unhandled_types,
      status}` — recognition completeness. With `events_unhandled == 0`
      an empty `tool_use_intents` claims the response carried no tool
      call in the format's encoding; with `> 0` the listed types are the
      events the parser could not classify. `status` is `"ok"` or
      `"failed"` (the proxy stopped calling the parser after it raised;
      the rest of the stream was forwarded unread). Build it with
      `parse_completeness/2`. Both default (`parser_identity(nil, …)`,
      `{0, 0, [], "ok"}`) so a call that never produced bytes still
      carries them.
    * `:parser_failed?` — optional boolean (the proxy's call-state flag);
      when the `:parse` map carries no `status` this decides it.
    * `:principal_source` — optional `"jwt" | "client_metadata" |
      "mtls_svid" | "anonymous"` (or the atom); how the principal id was
      obtained. When absent it is derived from the id (`"anonymous"`,
      `claude-code:` → `"client_metadata"`, else `"jwt"`).
    * `:upstream_org_id` — optional; the upstream's
      `anthropic-organization-id` response header, the one identity
      signal the upstream itself attests. Also derived from
      `:upstream_response_headers` (a `[{name, value}]` list) when given.
    * `:request_payload` / `:response_payload` — optional
      `PayloadCapture.result()` (spec 012 S6b): the bytes `prompt_hash` /
      `response_hash` cover, `:truncated` when the capture exceeded
      `R5E_RETAIN_PAYLOADS_MAX_BYTES`, `:disabled` / absent when
      `R5E_RETAIN_PAYLOADS` is off. `{:ok, bytes}` is put in the
      StorageProvider and the URI recorded on the LlmCallRecord
      (`prompt_payload_uri` / `response_payload_uri`); a failed put
      never fails the receipt.

  ## Retention (spec 012 S6b, plan §16)

  `payload_hash` on every predicate-only receipt is the SHA-256 of the
  JCS-encoded predicate map. This emitter puts those exact bytes
  (`EnvelopeBuilder.system_predicate_bytes/1`, the same function the
  builder hashes) into the StorageProvider via `Resolvers.Payload.store/2`
  and records the URI in `attestations.predicate_body_uri` for the parent
  and every `:tool_use_denied` child. A put failure is logged at warning
  and the receipt commits with a NULL URI — the retention is what makes
  the hash checkable, never a precondition for the receipt.
  """
  @type call_state :: %{
          required(:tenant_id) => String.t(),
          required(:principal_id) => String.t(),
          required(:principal_kind) => String.t(),
          required(:session_id) => String.t(),
          required(:started_at) => DateTime.t(),
          required(:completed_at) => DateTime.t(),
          required(:model) => String.t(),
          required(:provider) => String.t(),
          required(:upstream_host) => String.t(),
          required(:transport) => :wss | :https_sse,
          required(:api_format) => atom() | String.t(),
          required(:request_path) => String.t(),
          required(:prompt_hash) => binary(),
          required(:response_hash) => binary(),
          required(:prompt_token_count) => non_neg_integer(),
          required(:completion_token_count) => non_neg_integer(),
          optional(:reasoning_token_count) => non_neg_integer() | nil,
          required(:cedar_bundle_hash) => binary(),
          required(:upstream_status_code) => integer(),
          optional(:error_kind) => String.t() | nil,
          required(:intents) => [intent_decision()],
          required(:latency_ms) => non_neg_integer(),
          required(:added_latency_ms) => non_neg_integer(),
          optional(:correlation_id) => String.t() | nil,
          optional(:chatgpt_account_id) => String.t() | nil,
          optional(:kind) => RequestKind.kind() | nil,
          optional(:client_session_id) => String.t() | nil,
          optional(:parser) => parser_identity() | nil,
          optional(:parse) => parse_completeness() | nil,
          optional(:parser_failed?) => boolean(),
          optional(:principal_source) => String.t() | atom() | nil,
          optional(:upstream_org_id) => String.t() | nil,
          optional(:upstream_response_headers) => [{String.t(), String.t()}] | nil,
          optional(:request_payload) => PayloadCapture.result() | nil,
          optional(:response_payload) => PayloadCapture.result() | nil
        }

  @typedoc "Recognizer identity recorded on every predicate (spec 012 S4)."
  @type parser_identity :: %{
          module: String.t(),
          version: String.t(),
          format: String.t()
        }

  @typedoc "Recognition completeness recorded on every predicate (spec 012 S4)."
  @type parse_completeness :: %{
          required(:events_total) => non_neg_integer(),
          required(:events_unhandled) => non_neg_integer(),
          required(:unhandled_types) => [String.t()],
          optional(:status) => String.t(),
          optional(:betas_requested) => [String.t()]
        }

  @policy_evaluation_error "policy_evaluation_error"
  @client_metadata_note "client-asserted (metadata.user_id); corroborated only by the upstream accepting the presented bearer"

  @typedoc """
  Failure modes:
    * `{:error, {:invariant, atom()}}` — pre-flight invariant rejected
      (e.g. malformed call_state).
    * `{:error, {:envelope_build, term()}}` — `EnvelopeBuilder.build_system/4`
      failed (KMS, JCS, etc).
    * `{:error, {:ledger_commit, term()}}` — ledger commit failed.
    * `{:error, {:write_audit_rows, term()}}` — `LlmCalls.write_call_with_intents/2`
      failed (typically count mismatch or invalid changeset).
  """
  @type emit_error ::
          {:error, {:invariant, atom()}}
          | {:error, {:envelope_build, term()}}
          | {:error, {:ledger_commit, term()}}
          | {:error, {:write_audit_rows, term()}}

  @doc """
  Re-derive the parent `:llm_call_attested` in-toto Statement predicate
  body (as a map) from the call_state. The body is JCS-encoded +
  SHA-256-hashed by `EnvelopeBuilder.build_system/4` to produce the
  attestation row's `payload_hash`. Verifiers re-derive the body from
  the call_state to confirm the hash. Test seam used by CT-003 / CT-004
  / CT-005 + the eventual recurse-verify CLI extension; not part of the
  caller-facing API.
  """
  @doc since: "0.0.0"
  @spec call_predicate_map(call_state()) :: map()
  def call_predicate_map(call_state), do: build_call_predicate_map(call_state)

  @doc """
  Re-derive the per-deny `:tool_use_denied` in-toto Statement predicate
  body for an intent. Same role as `call_predicate_map/1`; test +
  verifier seam.
  """
  @doc since: "0.0.0"
  @spec denied_predicate_map(
          call_state(),
          parent_run_id :: String.t(),
          ToolUseIntent.t(),
          deny_payload :: map()
        ) :: map()
  def denied_predicate_map(call_state, parent_run_id, %ToolUseIntent{} = intent, deny_payload),
    do: build_denied_predicate_map(call_state, parent_run_id, intent, deny_payload)

  @doc """
  Build the `:parser` field for a call state: the parser module's name,
  its compile-time source hash (`version/0`, `"unknown"` when the module
  does not export one) and the wire format it is exhaustive for (the
  parser summary's `:format`, else the config's `api_format`).
  """
  @spec parser_identity(module() | nil, map(), atom() | String.t()) :: parser_identity()
  def parser_identity(module, summary, api_format) do
    version =
      if is_atom(module) and module != nil and Code.ensure_loaded?(module) and
           function_exported?(module, :version, 0),
         do: module.version(),
         else: "unknown"

    %{
      module: if(is_atom(module) and module != nil, do: inspect(module), else: "unknown"),
      version: version,
      format:
        nonempty_string(Map.get(summary || %{}, :format)) || api_format_to_string(api_format)
    }
  end

  @doc """
  Build the `:parse` field from a parser summary (`events_total`,
  `events_unhandled`, `unhandled_types`, `betas_requested`); `{0, 0, []}`
  when the parser produced no summary (no response bytes). `opts` may
  carry `parser_failed?: true` (the proxy's call-state flag) which sets
  `status: "failed"`; the default is `"ok"`.
  """
  @spec parse_completeness(map() | nil, keyword()) :: parse_completeness()
  def parse_completeness(summary, opts \\ []) do
    summary = summary || %{}

    base = %{
      events_total: non_neg(Map.get(summary, :events_total) || Map.get(summary, :event_count)),
      events_unhandled: non_neg(Map.get(summary, :events_unhandled)),
      unhandled_types:
        string_list(Map.get(summary, :unhandled_types)) |> Enum.uniq() |> Enum.sort(),
      status: if(Keyword.get(opts, :parser_failed?, false) == true, do: "failed", else: "ok")
    }

    case string_list(Map.get(summary, :betas_requested)) do
      [] -> base
      betas -> Map.put(base, :betas_requested, betas)
    end
  end

  defp string_list(v), do: v |> List.wrap() |> Enum.filter(&is_binary/1)

  @doc """
  Wire form of the principal's provenance for a call state:
  `call_state.principal_source` when given, else derived from the
  principal id (see `t:call_state/0`).
  """
  @spec principal_source(map()) :: String.t()
  def principal_source(call_state) do
    case Map.get(call_state, :principal_source) do
      nil ->
        case Map.get(call_state, :principal_id) do
          "anonymous" -> "anonymous"
          "claude-code:" <> _ -> "client_metadata"
          id when is_binary(id) and id != "" -> "jwt"
          _ -> "anonymous"
        end

      source ->
        PrincipalExtractor.principal_source_to_string(source)
    end
  end

  @doc """
  The upstream's `anthropic-organization-id` response header, from
  `call_state.upstream_org_id` or `call_state.upstream_response_headers`;
  nil when the upstream sent none.
  """
  @spec upstream_org_id(map()) :: String.t() | nil
  def upstream_org_id(call_state) do
    nonempty_string(Map.get(call_state, :upstream_org_id)) ||
      header_value(Map.get(call_state, :upstream_response_headers), "anthropic-organization-id")
  end

  defp header_value(headers, name) when is_list(headers) do
    Enum.find_value(headers, fn
      {k, v} when is_binary(k) and is_binary(v) ->
        if String.downcase(k, :ascii) == name, do: nonempty_string(v), else: nil

      _ ->
        nil
    end)
  end

  defp header_value(_, _), do: nil

  @doc """
  Emit the per-LLM-call attestation suite + denormalized audit rows.

  Per the contract this returns `{:ok, run_id}` where `run_id` is the
  canonical UUID of the parent `:llm_call_attested` predicate row in
  the `attestations` table. The orchestrator (proxy close hook) uses
  this `run_id` to:

    1. Confirm the attestation persisted (and therefore close the
       connection cleanly per Invariant I-004).
    2. Round-trip into Sub-3.8's E2E smoke test for verification.

  On failure returns `{:error, reason}` per `t:emit_error/0` — the
  caller MUST propagate this to the client (HTTP 500 / WS close 1011)
  rather than performing a clean close.
  """
  @spec emit_call_attestation(call_state()) ::
          {:ok, run_id :: String.t()} | emit_error()
  def emit_call_attestation(call_state) when is_map(call_state) do
    with :ok <- validate_invariants(call_state),
         {:ok, parent_run_id} <- emit_parent(call_state),
         :ok <- emit_denials(call_state, parent_run_id),
         :ok <- write_audit_rows(call_state, parent_run_id) do
      # This legacy audit projection does not authorize or re-admit work.
      # The transport obtains kernel admission before releasing each act and
      # records completion against those references through Fold.Admission.
      {:ok, parent_run_id}
    end
  end

  # ---------------------------------------------------------------------------
  # Pre-flight invariants
  # ---------------------------------------------------------------------------

  defp validate_invariants(call_state) do
    cond do
      not present_string?(call_state[:tenant_id]) ->
        {:error, {:invariant, :tenant_id}}

      not present_string?(call_state[:principal_id]) ->
        {:error, {:invariant, :principal_id}}

      not present_string?(call_state[:session_id]) ->
        {:error, {:invariant, :session_id}}

      not match?(<<_::binary-size(32)>>, call_state[:prompt_hash]) ->
        {:error, {:invariant, :prompt_hash}}

      not match?(<<_::binary-size(32)>>, call_state[:response_hash]) ->
        {:error, {:invariant, :response_hash}}

      not match?(<<_::binary-size(32)>>, call_state[:cedar_bundle_hash]) ->
        {:error, {:invariant, :cedar_bundle_hash}}

      not is_list(call_state[:intents]) ->
        {:error, {:invariant, :intents}}

      true ->
        :ok
    end
  end

  defp present_string?(value), do: is_binary(value) and value != ""

  # ---------------------------------------------------------------------------
  # Parent :llm_call_attested predicate — sign + commit
  # ---------------------------------------------------------------------------

  defp emit_parent(call_state) do
    {secrets_mod, secrets_state} = ProviderRegistry.secrets_provider()
    {ledger_mod, _ledger_state} = ProviderRegistry.ledger_provider()
    signer = ProviderRegistry.signer()

    correlation_id = Map.get(call_state, :correlation_id) || Recurse.Shared.Ulid.generate()
    run_id = Ecto.UUID.generate()

    # The predicate's `session_id` field is a UUID FK to the `sessions`
    # table (`:binary_id` in `Recurse.Providers.Impls.PostgresMerkleLedger.
    # Schemas.Session`). The agent-meaningful free-form session string
    # the proxy carries on `gate_context_base.session_id` is preserved
    # in the LlmCallRecord row's `session_id` column (free-form
    # `:string`). They are distinct slots with distinct semantics. We
    # mint a fresh UUID per attestation so each :llm_call_attested row
    # has its own session aggregate (mirrors the UiReceipts pattern of
    # `session_id: run_id` for predicate-only system events).
    predicate_session_id = run_id

    identity_ctx = identity_context(call_state, signer, correlation_id)

    predicate_map = build_call_predicate_map(call_state)

    with {:ok, envelope} <-
           wrap_envelope_build_error(
             EnvelopeBuilder.build_system(
               :llm_call_attested,
               identity_ctx,
               predicate_map,
               run_id: run_id,
               session_id: predicate_session_id,
               turn_id: run_id,
               secrets_provider: {secrets_mod, secrets_state},
               signer: signer,
               timestamp: call_state.completed_at,
               policy_canonical_hash: policy_hash_for_receipt(call_state)
             )
           ),
         predicate_body_uri = retain_predicate_body(envelope, predicate_map, identity_ctx),
         {:ok, _result} <-
           commit_envelope(
             ledger_mod,
             envelope,
             [{:predicate_body_uri, predicate_body_uri} | parent_commit_opts(call_state)]
           ) do
      {:ok, run_id}
    end
  end

  defp identity_context(call_state, signer, correlation_id) do
    IdentityContext.new(%{
      machine_identity: signer,
      principal: principal_from_call_state(call_state, signer),
      tenant_id: call_state.tenant_id,
      correlation_id: correlation_id
    })
  end

  # ---------------------------------------------------------------------------
  # Spec 012 S6b — retain what the signature commits to
  # ---------------------------------------------------------------------------

  # Put the exact JCS bytes `payload_hash` was computed over into the
  # StorageProvider. The bytes are re-derived through the ONE function the
  # builder hashes with and checked against the envelope's own hash before
  # the put, so "bytes put == bytes hashed" holds by construction; any
  # failure returns nil and the receipt commits without a URI.
  defp retain_predicate_body(
         %{signed_predicate: %{payload_hash: expected, run_id: run_id}},
         predicate_map,
         identity_ctx
       ) do
    bytes = EnvelopeBuilder.system_predicate_bytes(predicate_map)

    if :crypto.hash(:sha256, bytes) == expected do
      case PayloadStore.store(bytes, identity_ctx) do
        {:ok, uri} ->
          uri

        {:error, reason} ->
          Logger.warning(
            "attestation_emitter: predicate body not retained for run_id=#{run_id} " <>
              "(receipt committed without predicate_body_uri): #{inspect(reason)}"
          )

          nil
      end
    else
      Logger.error(
        "attestation_emitter: predicate body bytes do not hash to the envelope payload_hash " <>
          "for run_id=#{run_id}; not retained"
      )

      nil
    end
  end

  defp retain_predicate_body(_envelope, _predicate_map, _identity_ctx), do: nil

  # Detached payloads (R5E_RETAIN_PAYLOADS): the captured request /
  # response bytes are put under the hash the predicate carries; the URIs
  # go on the LlmCallRecord. Bytes that do not hash to the predicate's
  # value are never stored (they would be evidence of nothing).
  defp retain_payloads(call_state, identity_ctx) do
    {prompt_uri, prompt_truncated?} =
      retain_payload(
        Map.get(call_state, :request_payload),
        call_state.prompt_hash,
        "request",
        identity_ctx
      )

    {response_uri, response_truncated?} =
      retain_payload(
        Map.get(call_state, :response_payload),
        call_state.response_hash,
        "response",
        identity_ctx
      )

    %{
      prompt_payload_uri: prompt_uri,
      response_payload_uri: response_uri,
      payload_truncated: prompt_truncated? or response_truncated?
    }
  end

  defp retain_payload({:ok, bytes}, expected_hash, label, identity_ctx) when is_binary(bytes) do
    if :crypto.hash(:sha256, bytes) == expected_hash do
      case PayloadStore.store(bytes, identity_ctx) do
        {:ok, uri} ->
          {uri, false}

        {:error, reason} ->
          Logger.warning("attestation_emitter: #{label} payload not retained: #{inspect(reason)}")

          {nil, false}
      end
    else
      Logger.warning(
        "attestation_emitter: captured #{label} bytes do not hash to #{label}_hash; not retained"
      )

      {nil, false}
    end
  end

  defp retain_payload(:truncated, _expected_hash, _label, _identity_ctx), do: {nil, true}

  defp retain_payload(_absent_or_disabled, _expected_hash, _label, _identity_ctx),
    do: {nil, false}

  # Unsigned, queryable receipt metadata (the `attestations.tags` JSONB +
  # `upstream_status_code` columns). The signed predicate body is the
  # source of truth; these are the index the receipts endpoint and the
  # dashboard filter on (spec 012 §10: group by session, default to
  # `agent_turn`). Same column the tool-call extractor pipeline uses for
  # imported sessions — schema-on-read, never required.
  defp parent_commit_opts(call_state) do
    parser = parser_field(call_state)
    parse = parse_field(call_state)

    tags =
      %{
        "kind" => RequestKind.to_string(Map.get(call_state, :kind)),
        "client_session_id" => Map.get(call_state, :client_session_id),
        "upstream_host" => call_state.upstream_host,
        "api_format" => api_format_to_string(call_state.api_format),
        "transport" => transport_to_string(call_state.transport),
        "model" => call_state.model,
        "tool_use_intent_count" => length(call_state.intents),
        "decision_summary" => format_decision_summary(call_state.intents),
        # Spec 012 S4 — recognizer identity + completeness, indexed so the
        # console can render "No tool calls" vs "N tool calls · …" and
        # the drift panel can join on the parser version.
        "parser_module" => parser.module,
        "parser_version" => parser.version,
        "parser_format" => parser.format,
        "parse_events_total" => parse.events_total,
        "parse_events_unhandled" => parse.events_unhandled,
        "parse_unhandled_types" => parse.unhandled_types,
        "parse_status" => parse_status(parse),
        "parse_betas_requested" => Map.get(parse, :betas_requested)
      }
      |> Map.merge(identity_tags(call_state))
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> Map.new()

    [
      tags: tags,
      upstream_status_code: call_state.upstream_status_code,
      # Spec 012 S6c handoff — the outer-container decision the Decision
      # facet counts. The parent is the traversal: `:deny` only when every
      # intent was suppressed (a mixed call is still an allowed traversal;
      # its denials are counted through the `:tool_use_denied` children).
      policy_decision: parent_policy_decision(call_state.intents)
    ]
  end

  defp parent_policy_decision([]), do: :allow

  defp parent_policy_decision(intents) do
    if Enum.all?(intents, &decision_is_deny?/1), do: :deny, else: :allow
  end

  # Identity provenance shared by the parent and every `:tool_use_denied`
  # child (spec 012 S4 review): how the principal id was obtained, the
  # one upstream-attested identity signal, and the client's session id.
  defp identity_tags(call_state) do
    source = principal_source(call_state)

    %{
      "principal_source" => source,
      "principal_source_note" => if(source == "client_metadata", do: @client_metadata_note),
      "upstream_org_id" => upstream_org_id(call_state),
      "client_session_id" => Map.get(call_state, :client_session_id)
    }
  end

  defp denied_commit_opts(call_state, intent, deny_payload) do
    tags =
      %{
        "kind" => RequestKind.to_string(Map.get(call_state, :kind)),
        "model" => call_state.model,
        "tool_name" => intent.tool_name,
        "call_id" => intent.call_id,
        "cedar_rule_id" => Map.get(deny_payload, :rule_id),
        "deny_reason" => Map.get(deny_payload, :reason),
        "parser_version" => parser_field(call_state).version
      }
      |> Map.merge(identity_tags(call_state))
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> Map.new()

    # Spec 012 S6c handoff — without this the ledger default `:allow`
    # landed in `outer_container.policy_decision` and the Decision facet
    # counted every denial as an allow.
    [tags: tags, policy_decision: :deny]
  end

  defp parse_status(parse), do: Map.get(parse, :status) || "ok"

  # This legacy aggregate has one policy slot: it names the opening model
  # admission's workload policy. Later tool admissions can use newer policy;
  # their event references and policy bindings are carried separately below.
  # Historical producers without an admission retain the legacy sentinel.
  defp policy_hash_for_receipt(call_state) do
    case Map.get(call_state, :cedar_bundle_hash) do
      <<_::binary-size(32)>> = hash when hash != <<0::256>> -> hash
      _ -> Recurse.Gateway.AuditPlane.PredicateOnlyUri.system_event_no_policy_hash()
    end
  end

  defp parser_field(call_state) do
    case Map.get(call_state, :parser) do
      %{module: _, version: _, format: _} = parser -> parser
      _ -> parser_identity(nil, %{}, call_state.api_format)
    end
  end

  # The proxy's `parser_failed?` call-state flag wins over whatever the
  # parse map says (the proxy builds the map from the parser summary,
  # which cannot know the proxy stopped calling it); otherwise the map's
  # own `status`, default "ok".
  defp parse_field(call_state) do
    failed? = Map.get(call_state, :parser_failed?) == true

    parse =
      case Map.get(call_state, :parse) do
        %{events_total: _, events_unhandled: _, unhandled_types: _} = parse -> parse
        _ -> parse_completeness(%{})
      end

    if failed?, do: Map.put(parse, :status, "failed"), else: Map.put_new(parse, :status, "ok")
  end

  defp parser_to_predicate(parser),
    do: %{"module" => parser.module, "version" => parser.version, "format" => parser.format}

  defp parse_to_predicate(parse) do
    base = %{
      "events_total" => parse.events_total,
      "events_unhandled" => parse.events_unhandled,
      "unhandled_types" => parse.unhandled_types,
      "status" => parse_status(parse)
    }

    case Map.get(parse, :betas_requested) do
      betas when is_list(betas) and betas != [] -> Map.put(base, "betas_requested", betas)
      _ -> base
    end
  end

  defp non_neg(n) when is_integer(n) and n >= 0, do: n
  defp non_neg(_), do: 0

  defp nonempty_string(s) when is_binary(s) and s != "", do: s
  defp nonempty_string(_), do: nil

  # ---------------------------------------------------------------------------
  # Per-deny :tool_use_denied predicates — sign + commit (one per deny)
  # ---------------------------------------------------------------------------

  defp emit_denials(call_state, parent_run_id) do
    {secrets_mod, secrets_state} = ProviderRegistry.secrets_provider()
    {ledger_mod, _ledger_state} = ProviderRegistry.ledger_provider()
    signer = ProviderRegistry.signer()

    deny_intents = denied_intents(call_state.intents)

    Enum.reduce_while(deny_intents, :ok, fn {intent, decision}, _acc ->
      deny_payload = deny_payload_for(decision)
      child_run_id = Ecto.UUID.generate()
      # Each child :tool_use_denied predicate gets its own session
      # aggregate (UUID-shaped). The auditor pivots from child →
      # parent via `parent_llm_call_run_id` in the predicate body, NOT
      # via session_id correlation.
      child_session_id = child_run_id

      identity_ctx =
        identity_context(call_state, signer, Map.get(call_state, :correlation_id) || child_run_id)

      predicate_map =
        build_denied_predicate_map(call_state, parent_run_id, intent, deny_payload)

      result =
        with {:ok, envelope} <-
               wrap_envelope_build_error(
                 EnvelopeBuilder.build_system(
                   :tool_use_denied,
                   identity_ctx,
                   predicate_map,
                   run_id: child_run_id,
                   session_id: child_session_id,
                   turn_id: parent_run_id,
                   secrets_provider: {secrets_mod, secrets_state},
                   signer: signer,
                   timestamp: intent.extracted_at,
                   policy_canonical_hash: policy_hash_for_receipt(call_state)
                 )
               ),
             predicate_body_uri = retain_predicate_body(envelope, predicate_map, identity_ctx),
             {:ok, _row} <-
               commit_envelope(
                 ledger_mod,
                 envelope,
                 [
                   {:predicate_body_uri, predicate_body_uri}
                   | denied_commit_opts(call_state, intent, deny_payload)
                 ]
               ) do
          :ok
        end

      case result do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # Audit rows — LlmCallRecord + N ToolUseIntentRecord (single Multi)
  # ---------------------------------------------------------------------------

  defp write_audit_rows(call_state, parent_run_id) do
    intents = call_state.intents
    deny_count = Enum.count(intents, &decision_is_deny?/1)
    intent_count = length(intents)

    signer = ProviderRegistry.signer()

    identity_ctx =
      identity_context(call_state, signer, Map.get(call_state, :correlation_id) || parent_run_id)

    call_attrs =
      call_state
      |> build_call_record_attrs(parent_run_id, intent_count, deny_count)
      |> Map.merge(retain_payloads(call_state, identity_ctx))

    intent_attrs_list =
      Enum.map(intents, fn intent_decision ->
        build_intent_record_attrs(intent_decision, call_state.tenant_id)
      end)

    case LlmCalls.write_call_with_intents(call_attrs, intent_attrs_list) do
      {:ok, _result} -> :ok
      {:error, _, _} = err -> {:error, {:write_audit_rows, err}}
      {:error, _} = err -> {:error, {:write_audit_rows, err}}
    end
  end

  # ---------------------------------------------------------------------------
  # Predicate body builders — the contract shapes
  # ---------------------------------------------------------------------------

  # The contract (`contracts/llm_call_attestation.md` §LlmCallAttestation)
  # defines the predicate as the in-toto Statement v1 envelope (`_type`,
  # `predicateType`, `subject`, `predicate`). `EnvelopeBuilder.build_system/4`
  # JCS-encodes this map and SHA-256-hashes the result for `payload_hash`,
  # then DSSE-wraps the SignedPredicate. The contract's "envelope" shape
  # is therefore the predicate body fed to `build_system/4`.
  defp build_call_predicate_map(call_state) do
    intents = call_state.intents
    decision_summary = format_decision_summary(intents)

    %{
      "_type" => @in_toto_statement_type,
      "predicateType" => @predicate_type_call,
      "subject" => [
        %{
          "name" => call_state.principal_id,
          "digest" => %{
            "sha256" => Base.encode16(principal_canonical_hash(call_state), case: :lower)
          }
        }
      ],
      "predicate" => %{
        "tenant_id" => call_state.tenant_id,
        "session_id" => call_state.session_id,
        "started_at" => DateTime.to_iso8601(call_state.started_at),
        "completed_at" => DateTime.to_iso8601(call_state.completed_at),
        "model" => call_state.model,
        "provider" => call_state.provider,
        "upstream_host" => call_state.upstream_host,
        "transport" => Atom.to_string(call_state.transport),
        "api_format" => api_format_to_string(call_state.api_format),
        "request_path" => call_state.request_path,
        # Spec 012 S2 (plan §9 D2 / §10) — receipt classification +
        # the client's own session id. Both nullable: the WS bridge
        # does not classify, and Codex carries no client session id
        # in the request body.
        "kind" => RequestKind.to_string(Map.get(call_state, :kind)),
        "client_session_id" => Map.get(call_state, :client_session_id),
        # Spec 012 S4 review — how the principal id was obtained and the
        # upstream's own organisation id (the only identity signal the
        # upstream attests). A `client_metadata` principal is what the
        # client said it was; the record says so in words.
        "principal_source" => principal_source(call_state),
        "principal_source_note" => principal_source_note(call_state),
        "upstream_org_id" => upstream_org_id(call_state),
        # Spec 012 S4 (plan §11) — which software interpreted the bytes
        # and how much of the stream it left unrecognised. With
        # `events_unhandled == 0` an empty `tool_use_intents` is the
        # claim that the response carried no tool call.
        "parser" => parser_to_predicate(parser_field(call_state)),
        "parse" => parse_to_predicate(parse_field(call_state)),
        "prompt_hash" => sha256_hex(call_state.prompt_hash),
        "response_hash" => sha256_hex(call_state.response_hash),
        "prompt_token_count" => call_state.prompt_token_count,
        "completion_token_count" => call_state.completion_token_count,
        "reasoning_token_count" => Map.get(call_state, :reasoning_token_count),
        "cedar_bundle_hash" => sha256_hex(call_state.cedar_bundle_hash),
        "cedar_bundle_hash_scope" => "opening_model_admission",
        "admission" => admission_evidence(call_state),
        "tool_use_intents" => Enum.map(intents, &intent_to_predicate_field/1),
        "decision_summary" => decision_summary,
        "upstream_status_code" => call_state.upstream_status_code,
        "error_kind" => Map.get(call_state, :error_kind),
        "latency_ms" => call_state.latency_ms,
        "added_latency_ms" => call_state.added_latency_ms
      }
    }
  end

  defp admission_evidence(%{admission: %{opening_receipt: opening}} = state) do
    %{
      "opening" => receipt_binding(opening),
      "tools" => Enum.map(Map.get(state, :tool_receipts, []), &receipt_binding/1),
      "note" =>
        "Projection of kernel receipts. Each event binds its own policy; the aggregate opening hash does not govern later tool decisions."
    }
  end

  defp admission_evidence(_), do: nil

  defp receipt_binding(receipt) do
    %{
      "eventRef" => receipt["eventRef"],
      "outcome" => receipt["outcome"],
      "policy" => receipt["policy"]
    }
  end

  defp build_denied_predicate_map(call_state, parent_run_id, intent, deny_payload) do
    %{
      "_type" => @in_toto_statement_type,
      "predicateType" => @predicate_type_denied,
      "subject" => [
        %{
          "name" => call_state.principal_id,
          "digest" => %{
            "sha256" => Base.encode16(principal_canonical_hash(call_state), case: :lower)
          }
        }
      ],
      "predicate" => %{
        "parent_llm_call_run_id" => parent_run_id,
        "tenant_id" => call_state.tenant_id,
        # Spec 012 S4 — the provider-issued call id (`toolu_…` for Claude
        # Code) so the denial joins the parent's intent + the client's
        # own transcript; and the parser that extracted it (plan §12).
        "call_id" => intent.call_id,
        "client_session_id" => Map.get(call_state, :client_session_id),
        "principal_source" => principal_source(call_state),
        "principal_source_note" => principal_source_note(call_state),
        "upstream_org_id" => upstream_org_id(call_state),
        "parser" => parser_to_predicate(parser_field(call_state)),
        "tool_name" => intent.tool_name,
        "tool_args_hash" => sha256_hex(intent.tool_args_hash),
        "tool_args_size_bytes" => intent.tool_args_size_bytes,
        # Spec 012 S6b — the bytes this denial was extracted from. Carried
        # on the child so a verifier can bind the retained request /
        # response payloads to THIS receipt's signature without trusting
        # the parent's body (which its own signature, not this one, covers).
        "prompt_hash" => sha256_hex(call_state.prompt_hash),
        "response_hash" => sha256_hex(call_state.response_hash),
        "cedar_rule_id" => Map.get(deny_payload, :rule_id),
        "deny_reason" => Map.get(deny_payload, :reason),
        "gate_error" => Map.get(deny_payload, :gate_error),
        "model" => call_state.model,
        "extracted_at" => DateTime.to_iso8601(intent.extracted_at)
      }
    }
  end

  defp intent_to_predicate_field({%ToolUseIntent{} = intent, decision}) do
    base = %{
      "call_id" => intent.call_id,
      "tool_name" => intent.tool_name,
      "tool_args_hash" => sha256_hex(intent.tool_args_hash),
      "decision" => decision_to_string(decision)
    }

    case decision do
      {:deny, %{rule_id: rule_id, reason: reason}} ->
        base
        |> Map.put("cedar_rule_id", rule_id)
        |> Map.put("deny_reason", reason)

      {:error, reason} ->
        base
        |> Map.put("cedar_rule_id", nil)
        |> Map.put("deny_reason", @policy_evaluation_error)
        |> Map.put("gate_error", inspect(reason))

      _ ->
        base
    end
  end

  # ---------------------------------------------------------------------------
  # Audit-row attribute builders
  # ---------------------------------------------------------------------------

  defp build_call_record_attrs(call_state, run_id, intent_count, deny_count) do
    %{
      tenant_id: call_state.tenant_id,
      signed_predicate_run_id: run_id,
      principal_id: call_state.principal_id,
      principal_kind: call_state.principal_kind,
      chatgpt_account_id: Map.get(call_state, :chatgpt_account_id),
      session_id: call_state.session_id,
      provider: call_state.provider,
      upstream_host: call_state.upstream_host,
      transport: transport_to_string(call_state.transport),
      model: call_state.model,
      api_format: api_format_to_string(call_state.api_format),
      request_path: call_state.request_path,
      prompt_hash: call_state.prompt_hash,
      response_hash: call_state.response_hash,
      prompt_token_count: call_state.prompt_token_count,
      completion_token_count: call_state.completion_token_count,
      reasoning_token_count: Map.get(call_state, :reasoning_token_count),
      tool_use_intent_count: intent_count,
      tool_use_denied_count: deny_count,
      decision_summary: format_decision_summary(call_state.intents),
      cedar_bundle_hash: call_state.cedar_bundle_hash,
      upstream_status_code: call_state.upstream_status_code,
      error_kind: Map.get(call_state, :error_kind),
      latency_ms: call_state.latency_ms,
      added_latency_ms: call_state.added_latency_ms,
      started_at: call_state.started_at,
      completed_at: call_state.completed_at
    }
  end

  defp build_intent_record_attrs({%ToolUseIntent{} = intent, decision}, tenant_id) do
    base = %{
      tenant_id: tenant_id,
      tool_name: intent.tool_name,
      tool_args_hash: intent.tool_args_hash,
      tool_args_inlined: maybe_inlined_args(intent),
      decision: row_decision_to_string(decision),
      tool_args_size_bytes: intent.tool_args_size_bytes,
      parallel_index: intent.parallel_index,
      call_id: intent.call_id,
      extracted_at: intent.extracted_at
    }

    case decision do
      {:deny, %{rule_id: rule_id, reason: reason}} ->
        base
        |> Map.put(:cedar_rule_id, rule_id)
        |> Map.put(:deny_reason, reason)

      {:error, _reason} ->
        Map.put(base, :deny_reason, @policy_evaluation_error)

      _ ->
        base
    end
  end

  # `tool_args_inlined` is JSONB and only set when the args fit the
  # inlining threshold (the parser sets `:tool_args = :too_large` when
  # they don't). For now we mirror the parser's `:too_large` sentinel
  # directly: inline when args is a map; nil otherwise. The size-threshold
  # gate is applied upstream by `CedarToolUseGate.gate_context_for_intent/2`.
  defp maybe_inlined_args(%ToolUseIntent{tool_args: args}) when is_map(args), do: args
  defp maybe_inlined_args(_), do: nil

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Signed predicate: three decision strings. Anything that is not an
  # explicit allow was suppressed on the wire, and the string says why.
  defp decision_to_string({:allow}), do: "allow"
  defp decision_to_string({:deny, _}), do: "deny"
  defp decision_to_string({:error, _}), do: "error"
  defp decision_to_string(_), do: "error"

  # Mirror row: `ToolUseIntentRecord.decision` is a closed `allow | deny`
  # enum (DB CHECK); an error is a deny there, with
  # `deny_reason = "policy_evaluation_error"`.
  defp row_decision_to_string({:allow}), do: "allow"
  defp row_decision_to_string(_), do: "deny"

  # Every suppressed intent (deny or error) counts as denied: this is the
  # count `LlmCalls.write_call_with_intents/2` checks against the rows.
  defp decision_is_deny?({_intent, {:allow}}), do: false
  defp decision_is_deny?({_intent, _}), do: true

  defp denied_intents(intents) do
    Enum.filter(intents, &decision_is_deny?/1)
  end

  defp deny_payload_for({:deny, payload}) when is_map(payload), do: payload

  defp deny_payload_for({:error, reason}),
    do: %{rule_id: nil, reason: @policy_evaluation_error, gate_error: inspect(reason)}

  defp deny_payload_for(_), do: %{rule_id: nil, reason: @policy_evaluation_error}

  defp principal_source_note(call_state) do
    if principal_source(call_state) == "client_metadata", do: @client_metadata_note
  end

  defp format_decision_summary(intents) do
    {allow, deny, error} =
      Enum.reduce(intents, {0, 0, 0}, fn
        {_intent, {:allow}}, {a, d, e} -> {a + 1, d, e}
        {_intent, {:deny, _}}, {a, d, e} -> {a, d + 1, e}
        {_intent, _}, {a, d, e} -> {a, d, e + 1}
        _, acc -> acc
      end)

    suppressed = deny + error

    summary =
      cond do
        allow == 0 and suppressed == 0 -> "no tools"
        suppressed == 0 -> "all allow"
        allow == 0 -> "all deny"
        true -> "#{allow} allow, #{suppressed} deny"
      end

    if error > 0, do: summary <> " (#{error} error)", else: summary
  end

  defp sha256_hex(<<bytes::binary-size(32)>>),
    do: "sha256:" <> Base.encode16(bytes, case: :lower)

  defp transport_to_string(:wss), do: "wss"
  defp transport_to_string(:https_sse), do: "https-sse"
  defp transport_to_string(other) when is_binary(other), do: other

  defp api_format_to_string(format) when is_atom(format), do: Atom.to_string(format)
  defp api_format_to_string(format) when is_binary(format), do: format

  defp principal_from_call_state(%{principal_kind: "obo_human", principal_id: subject}, signer) do
    Principal.obo_human(%{
      issuer: signer,
      subject: subject
    })
  end

  defp principal_from_call_state(%{principal_kind: "autonomous", principal_id: spiffe}, _signer) do
    Principal.autonomous(%{spiffe_id: spiffe})
  end

  defp principal_from_call_state(%{principal_id: principal_id}, signer) do
    # `:service_account` is the safe default for system-emitted attestations
    # where the principal lacks a strong OBO/autonomous identity (e.g. the
    # `anonymous` synthetic principal Sub-3.4 builds when no JWT is plumbed).
    Principal.service_account(%{
      issuer: signer,
      account_id: principal_id
    })
  end

  defp principal_canonical_hash(%{principal_id: principal_id}) do
    :crypto.hash(:sha256, principal_id)
  end

  defp wrap_envelope_build_error({:ok, _} = ok), do: ok
  defp wrap_envelope_build_error({:error, reason}), do: {:error, {:envelope_build, reason}}

  # Two paths matching the F002 ChatCompletionsHandler / UiReceipts.do_commit
  # convention: PostgresMerkleLedger gets called directly; alternative
  # ledgers fall back to `function_exported?/3` for forward-compat.
  defp commit_envelope(PostgresMerkleLedger = mod, envelope, opts) do
    case mod.commit_attestation(envelope, opts) do
      {:ok, _} = ok -> ok
      {:error, reason} -> {:error, {:ledger_commit, reason}}
    end
  end

  defp commit_envelope(mod, envelope, opts) do
    if function_exported?(mod, :commit_attestation, 2) do
      case mod.commit_attestation(envelope, opts) do
        {:ok, _} = ok -> ok
        {:error, reason} -> {:error, {:ledger_commit, reason}}
      end
    else
      {:error, {:ledger_commit, {:ledger_provider_missing_commit_attestation, mod}}}
    end
  end
end
