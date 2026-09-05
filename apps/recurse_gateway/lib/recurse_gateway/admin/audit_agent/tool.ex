defmodule Recurse.Gateway.Admin.AuditAgent.Tool do
  @moduledoc """
  Behaviour every Audit-Agent Day-1 tool MUST implement (F004 T106).

  The Audit Agent Day-1 vocabulary is a **closed set of six tools** per
  `specs/004-audit-console/contracts/audit_agent_tools.md`:

    1. `query_receipts`           — pure SQL faceted query
    2. `fetch_receipt_detail`     — wraps F002 receipt detail
    3. `explain_denial`           — LLM-calling, ≤2K in / ≤1K out
    4. `find_similar_receipts`    — pure SQL similarity
    5. `simulate_policy_dryrun`   — wraps `POST /v1/policy/simulate`
    6. `suggest_policy_pattern`   — operator-only; heuristic|llm sources

  Adding a seventh tool is a constitutional-amendment-class change: it
  requires (a) a new Cedar action, (b) a new `event_kind` sub-variant,
  (c) property-test surface coverage, (d) glossary entry. This discipline
  is what enforces "everything attestable" at the agent layer.

  ## Why a behaviour (and not, say, a protocol)?

  Six implementations, all swap-able by the runtime dispatcher. Pure
  module polymorphism — exactly the case the
  `elixir:elixir-antipatterns` skill catalog calls "behaviours = default
  for module polymorphism (very cheap at runtime)". Protocols would force
  us to invent a per-tool struct just to dispatch on type; the dispatch
  here is by tool name (a string from the LLM) so a behaviour-keyed
  module map (`%{"query_receipts" => Tools.QueryReceipts, ...}`) is the
  smallest mechanism that fits.

  ## AD-001 c' compliance

  This behaviour file lives at
  `apps/recurse_gateway/lib/recurse_gateway/admin/audit_agent/tool.ex`,
  NOT `apps/recurse_providers/lib/recurse_providers/*_provider.ex`.
  The AD-001 c' SHA guard pins ONLY the seven Provider Interface
  surfaces; new behaviours under the Gateway admin context add zero
  Provider surface area.

  ## Per-call lifecycle (in `runtime.ex`)

    1. Receive `(tool_name, input_json, conversation_ctx)` from the
       agent.
    2. Validate `input_json` against `c:input_schema/0` (Draft 2020-12).
       Invalid input fails synchronously with a structured error — NO
       Cedar call, NO receipt (input validation is a precondition, not
       an authorization decision).
    3. Cedar evaluation: `(principal, c:cedar_action/0,
       resource=AuditEndpoint, ctx)`. Deny → emit `:policy_denied` +
       return error.
    4. Invoke `c:call/2`.
    5. Emit `c:event_kind/0` receipt with the canonical signed-predicate
       fields (`tool_name`, `input_hash`, `output_hash`,
       `attested_run_ids`).
    6. Return `{output, attested_run_id}` to the agent runtime.

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_agent_tools.md` §"Common shape"
    * `specs/004-audit-console/data-model.md` §0 (canonical event_kind matrix)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/audit_agent/runtime.ex`
      (dispatcher + lifecycle)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/audit_agent/tool_call.ex`
      (per-call attestation emitter)
  """

  @typedoc """
  Per-call context the runtime passes into `c:call/2`. The `:identity_ctx`
  is the F001 IdentityContext resolved at Gateway ingress; `:tenant_id`
  is denormalized for ergonomics; `:conversation_id` lets tools that need
  to walk prior messages do so without re-resolving from headers.
  """
  @type call_ctx :: %{
          required(:identity_ctx) => Recurse.Shared.IdentityContext.t(),
          required(:tenant_id) => String.t(),
          required(:conversation_id) => String.t(),
          optional(:tokens_remaining_in_conversation) => non_neg_integer(),
          optional(any()) => any()
        }

  @typedoc """
  Output map returned by `c:call/2`. Always JSON-serializable; tools that
  reference receipts include `attested_run_ids` so the per-tool attestation
  can record cross-references at the signed-predicate layer.
  """
  @type output :: map()

  @typedoc """
  Per-call failure reasons surfaced to the runtime. Distinct from
  Cedar deny (handled by the runtime's pre-call gate) and input-schema
  validation (handled by the runtime's pre-call validator); these are
  tool-impl-internal failures.
  """
  @type call_error ::
          :upstream_unavailable
          | :agent_token_budget_exceeded
          | :runners_not_yet_implemented
          | {:internal, term()}
          | term()

  @doc """
  Stable string name. MUST match one of the six Day-1 Tool Vocabulary
  entries in `chat_messages.ex`'s `@tool_vocabulary`. Used as the
  dispatcher key and as `signed_predicate.tool_name` in the per-tool
  receipt.
  """
  @callback name() :: String.t()

  @doc """
  Cedar action UID, e.g. `~s|Recurse::Action::"AuditAgentToolQueryReceipts"|`.
  Used by the runtime's pre-call Cedar gate. MUST appear in the
  role-allowlist policy bundle (`platform_roles.cedar`) for at least one
  role; tools that are operator-only (e.g. `suggest_policy_pattern`)
  appear ONLY in the operator allowlist arm.
  """
  @callback cedar_action() :: String.t()

  @doc """
  Canonical `event_kind` atom emitted in the per-tool attestation. MUST
  match the canonical matrix at `data-model.md` §0:
  `:ui_chat_skill_invoked_<snake_case_name>`.
  """
  @callback event_kind() :: atom()

  @doc """
  JSON Schema (Draft 2020-12) for the `c:call/2` input map. Returned as
  a plain map so the runtime can pass it straight into a JSON Schema
  validator. The `additionalProperties: false` discipline is mandatory
  per the contract.
  """
  @callback input_schema() :: map()

  @doc """
  JSON Schema (Draft 2020-12) for the `c:call/2` output map. Used by
  contract tests to assert tool outputs validate against the schema; the
  runtime does NOT validate outputs at runtime (trust-the-implementation
  discipline; the property tests are the enforcement seam).
  """
  @callback output_schema() :: map()

  @doc """
  Run the tool. Receives the validated input map (already passed
  `c:input_schema/0`) and the per-call context; returns either a result
  map or a tagged error.

  Implementations MUST be pure functions of their inputs + Repo state;
  no per-tool process state. LLM-calling tools (Tools 3 + 6) reach the
  configured `LLMProvider` via `Recurse.Gateway.ProviderRegistry`
  synchronously on the caller process.
  """
  @callback call(input :: map(), ctx :: call_ctx()) ::
              {:ok, output()} | {:error, call_error()}
end
