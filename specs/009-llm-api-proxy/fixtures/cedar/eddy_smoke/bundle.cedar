// Spec 009 Phase 3 Sub-3.8 (T074) — Cedar fixture bundle for the
// Eddy + Codex CLI canonical user-journey smoke (US1).
//
// Three-rule bundle:
//   1. permit_all_else        — baseline permit so non-destructive tools
//                               reach :allow (Cedar's authorizer is
//                               "deny-by-default unless a permit applies
//                               AND no forbid applies"; without a baseline
//                               permit, a bare forbid alone denies
//                               everything because no permit ever fires).
//   2. rule_no_destructive    — forbid the legacy `shell` tool when the
//                               rendered command contains `rm -rf`.
//   3. rule_no_destructive_exec_command — same intent for codex 0.125+'s
//                               actual shape: tool `exec_command`, args
//                               field `cmd`.
//
// ## Why two forbid rules instead of one normalised rule?
//
// Codex CLI's tool naming is provider-internal and has shifted across
// versions. Pre-0.125 emitted `shell` with `command: "..."`; 0.125+
// emits `exec_command` with `cmd: "..."`. Cedar policies match on
// concrete resource + attribute names (no string-match across multiple
// schemas in a single rule), so the simplest bundle that's robust
// across both shapes is two parallel forbids. As we settle on a
// canonical-tool-name normalisation in CedarToolUseGate (R5E-NN
// follow-up — file when ready), this can collapse to one rule against
// the canonical shape.
//
// CedarToolUseGate exposes `tool_args` on the Cedar `context` (per
// build_cedar_context/2), inlined as a JSON map under the
// args-inline threshold (default 10KB).
//
// Cross-references:
//   * specs/009-llm-api-proxy/quickstart.md Flow 1 §"Trigger a deny"
//   * apps/recurse_gateway/lib/recurse_gateway/llm_proxy/cedar_tool_use_gate.ex
//     §"build_cedar_context/2" — `context.tool_args` shape
//   * apps/recurse_gateway/test/recurse_gateway/llm_proxy/cedar_tool_use_gate_test.exs
//     (existing forbid-shell rule patterns)

permit (
  principal,
  action,
  resource
);

// Legacy codex shape (`shell` tool, `command` field).
forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"shell"
) when {
  context has tool_args
  && context.tool_args has "command"
  && context.tool_args.command like "*rm -rf*"
};

// Codex 0.125+ shape (`exec_command` tool, `cmd` field). Confirmed
// empirically against audit-dev's tool_use_intent_records 2026-05-08:
// codex emits tool_name=exec_command with args={"cmd": "...", ...}.
forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"exec_command"
) when {
  context has tool_args
  && context.tool_args has "cmd"
  && context.tool_args.cmd like "*rm -rf*"
};
