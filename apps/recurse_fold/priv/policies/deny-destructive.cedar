// deny-destructive.cedar
//
// ATTRIBUTION: copied unchanged from the 2026-07-27 enterprise demo
// (`scripts/fable_demo/deny_destructive.cedar` in the r5e-enterprise
// fable-demo workspace), where it ran against the Recurse gateway's Cedar
// evaluator over a live codex session. Not one policy statement was edited
// for the fold. That is the whole point: the same policy text, the same
// Cedar 4.9.1 engine, now deciding inside the r5e kernel's admission gate,
// with its decisions landing on the kernel's chain.
//
// Deny-destructive Cedar bundle for the local demo (step d).
// Baseline permit + forbids for destructive tool invocations. Cedar is
// deny-by-default, so the bare permit is required for the allow path to
// fire at all; the forbids then override it for matching requests.
//
// Shapes covered (mirrors specs/009-llm-api-proxy/fixtures/cedar/eddy_smoke):
//   * legacy codex `shell` tool, `command` arg — rm -rf and DROP DATABASE
//   * codex 0.125+ `exec_command` tool, `cmd` arg — rm -rf and DROP DATABASE

permit (
  principal,
  action,
  resource
);

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"shell"
) when {
  context has tool_args
  && context.tool_args has "command"
  && (context.tool_args.command like "*rm -rf*"
      || context.tool_args.command like "*DROP DATABASE*")
};

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"exec_command"
) when {
  context has tool_args
  && context.tool_args has "cmd"
  && (context.tool_args.cmd like "*rm -rf*"
      || context.tool_args.cmd like "*DROP DATABASE*")
};
