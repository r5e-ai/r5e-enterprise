// r5e-enterprise default policy bundle (spec 012 D6).
//
// This file is mounted into the gateway at /policy/bundle.cedar and is the
// ONE bundle the gateway evaluates: every tool call the LLM proxy sees AND
// every audit-plane / console request (dashboard, receipts, export, policy
// drafts) — and, with R5E_FOLD_ENABLED=true, every act the fold records on
// its chain (section 4). Edit it and the gateway reloads it within 5 seconds
// (R5E_POLICY_BUNDLE_POLL_MS); a file that does not parse is rejected and
// the previous bundle stays active (see /readyz "policy"). To take the
// bundle from a git repository instead, start with the `git-policy`
// profile (docs/policy-from-git.md).
//
// Read this first
// ---------------
// The command patterns below are ILLUSTRATIVE. They are a starting point
// that shows the shape of a rule, not a security control:
//
//   * `like` is a glob (`*` matches any run of characters) and it is
//     case-sensitive. `*rm -rf*` does not match `rm -fr`, `rm -r -f`,
//     `RM -RF`, `sudo rm -rf` split across lines, or `find ... -delete`.
//   * A determined agent (or a prompt injection) can rephrase any command.
//     Pattern denials catch the obvious accident, not the adversary.
//   * Real containment is the deployment shape (non-root container, egress
//     only to the upstream) plus allow-lists of what the agent MAY run,
//     written by you for your repo. Add those below.
//
// Every decision, allow or deny, is recorded in a signed receipt with the
// SHA-256 of this bundle, so an auditor can prove which rules were in
// force when a call was made.
//
// How a tool call is presented to Cedar
// -------------------------------------
//   principal  User::"<who is running the agent>"
//   action     Action::"invoke_tool"
//   resource   ToolUse::"<tool name>"        e.g. ToolUse::"Bash"
//   context    { tool_args: { <the tool's input fields> },
//                tool_args_hash: "<sha256 hex>", tool_args_size_bytes: N, ... }
//
// Who `principal` is, and what it is not
// --------------------------------------
// For Claude Code the principal is User::"claude-code:<account_uuid>", taken
// from the request body's `metadata.user_id`. That value is CLIENT-ASSERTED:
// the gateway does not verify it, and the only corroboration is that the
// upstream accepted the bearer the client presented alongside it (the
// receipt's predicate body, `predicate/<run_id>.json` in an evidence
// export, records `principal_source: client_metadata` to say so). Do not
// write rules that grant anything on the strength of that principal alone
// (`permit (principal == User::"claude-code:…", …)` is a rule anyone can
// satisfy by editing a JSON field). Deny-shaped rules on it are fine. A
// principal peeked from a JWT (`principal_source: jwt`) is stronger but
// still unverified here; a future mTLS/SPIFFE path (`mtls_svid`) is the
// only source the gateway itself would attest. Real per-user authorization
// belongs where the credential is verified: the upstream, or an identity
// provider in front of this gateway.
//
// The size threshold and why every shell tool fails closed
// --------------------------------------------------------
// The gateway inlines `tool_args` into the context ONLY when the tool's
// input is at most 10 KB (`cedar_args_inline_threshold_bytes`, see
// CedarToolUseGate.build_cedar_context/2). Above that, `context` carries
// only `tool_args_hash` + `tool_args_size_bytes` and `context has tool_args`
// is false. A `forbid ... when { context has tool_args && ... }` clause
// can then never match, so without more the baseline permit would let an
// oversized `rm -rf` through. The `unless { context has tool_args }` clauses
// below close that gap: for every shell-shaped tool, no inspectable
// arguments means DENY. Pad a command past 10 KB and it is refused, not
// waved through. Non-shell tools (Read, Edit, Glob, ...) are still allowed
// without inlined args because there is no pattern to check on them.
//
// Note that Claude Code's `Write` tool carries the whole file in
// `tool_args.content`, which routinely exceeds the 10 KB threshold; a
// `file_path` rule on ToolUse::"Write" therefore cannot match today for any
// but small files (Edit, whose input is the patch, is the tool such rules
// do reach). Raise `cedar_args_inline_threshold_bytes` or fail Write closed
// with an `unless { context has tool_args }` clause if that matters to you.
//
// Cedar is deny-by-default: the `permit` is what lets ordinary work through;
// each `forbid` carves a denial out of it, and `forbid` always wins.

// ===========================================================================
// 1. Tool calls (LLM proxy)
// ===========================================================================

// Baseline: allow any tool call not forbidden below. Scoped to
// `invoke_tool` on purpose. This bundle also governs the audit plane
// (section 3), where an unscoped `permit (principal, action, resource)`
// would hand every role every console action, and the fold's recording
// acts (section 4), which have their own actions.
permit (
  principal,
  action == Action::"invoke_tool",
  resource
);

// ---------------------------------------------------------------------------
// Fail closed: a shell tool whose arguments were not inlined (over the size
// threshold, or the parser could not extract them) is denied outright.
// ---------------------------------------------------------------------------
forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"Bash"
) unless { context has tool_args };

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"shell"
) unless { context has tool_args };

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"exec_command"
) unless { context has tool_args };

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"local_shell"
) unless { context has tool_args };

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"unified_exec"
) unless { context has tool_args };

// ---------------------------------------------------------------------------
// Claude Code: the Bash tool's input is `{ "command": "..." }`.
// ---------------------------------------------------------------------------
forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"Bash"
) when {
  context has tool_args
  && context.tool_args has "command"
  && (context.tool_args.command like "*rm -rf*"
      || context.tool_args.command like "*DROP DATABASE*"
      || context.tool_args.command like "*git push --force*"
      || context.tool_args.command like "*> /dev/sd*")
};

// ---------------------------------------------------------------------------
// Codex (appendix path, last validated on Codex 0.149). Its shell tools
// have moved names + argument keys across releases; every shape the
// gateway's parser knows is listed so the same bundle serves both clients.
//   pre-0.125   `shell`         `command`
//   0.125+      `exec_command`  `cmd`
//   0.149       `local_shell`, `unified_exec`  (argument key not yet
//               confirmed on the wire; both `cmd` and `command` are checked)
// ---------------------------------------------------------------------------
forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"shell"
) when {
  context has tool_args
  && context.tool_args has "command"
  && (context.tool_args.command like "*rm -rf*"
      || context.tool_args.command like "*DROP DATABASE*"
      || context.tool_args.command like "*git push --force*"
      || context.tool_args.command like "*> /dev/sd*")
};

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"exec_command"
) when {
  context has tool_args
  && context.tool_args has "cmd"
  && (context.tool_args.cmd like "*rm -rf*"
      || context.tool_args.cmd like "*DROP DATABASE*"
      || context.tool_args.cmd like "*git push --force*"
      || context.tool_args.cmd like "*> /dev/sd*")
};

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"local_shell"
) when {
  context has tool_args
  && ((context.tool_args has "cmd"
       && (context.tool_args.cmd like "*rm -rf*"
           || context.tool_args.cmd like "*DROP DATABASE*"
           || context.tool_args.cmd like "*git push --force*"
           || context.tool_args.cmd like "*> /dev/sd*"))
      || (context.tool_args has "command"
          && (context.tool_args.command like "*rm -rf*"
              || context.tool_args.command like "*DROP DATABASE*"
              || context.tool_args.command like "*git push --force*"
              || context.tool_args.command like "*> /dev/sd*")))
};

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"unified_exec"
) when {
  context has tool_args
  && ((context.tool_args has "cmd"
       && (context.tool_args.cmd like "*rm -rf*"
           || context.tool_args.cmd like "*DROP DATABASE*"
           || context.tool_args.cmd like "*git push --force*"
           || context.tool_args.cmd like "*> /dev/sd*"))
      || (context.tool_args has "command"
          && (context.tool_args.command like "*rm -rf*"
              || context.tool_args.command like "*DROP DATABASE*"
              || context.tool_args.command like "*git push --force*"
              || context.tool_args.command like "*> /dev/sd*")))
};

// ===========================================================================
// 2. Your rules
// ===========================================================================
// Add your own rules here. Example: keep the agent out of secrets.
//
// forbid (
//   principal,
//   action == Action::"invoke_tool",
//   resource == ToolUse::"Read"
// ) when {
//   context has tool_args
//   && context.tool_args has "file_path"
//   && context.tool_args.file_path like "*/.env*"
// };
//
// Stronger than a deny list: allow only the tools you expect and deny the
// rest. Cedar is deny-by-default, so replacing the baseline permit above
// with `resource in [ToolUse::"Read", ToolUse::"Edit", ToolUse::"Bash"]`
// turns every other tool into a denial.

// ===========================================================================
// 3. Audit plane / console roles
// ===========================================================================
// Copied verbatim from
// apps/recurse_gateway/priv/reference_policies/platform_roles.cedar (the
// role model every audit-plane handler is written against). It lives in
// this file because RECURSE_POLICY_BUNDLE_PATH names exactly one file.
// Roles: `platform_operator` (what `bin/r5e login` mints), `tenant_auditor`
// (read-only), `caller` (data plane only). Anything not permitted here,
// e.g. Recurse::Action::"CedarBundleActivate" (OCI hot-reload, not wired
// in the compose stack), is denied for everyone.
//
// The `tenant_id` binding is a tautology in a single-tenant stack; it is
// kept so the same file works when a second tenant appears.

// platform_operator: F002 audit-plane actions.
permit(principal, action == Recurse::Action::"ReadReceipts", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
permit(principal, action == Recurse::Action::"ExportEvidence", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
permit(principal, action == Recurse::Action::"ReadPayload", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
// tenant_auditor: F002 audit-plane reads.
permit(principal, action == Recurse::Action::"ReadReceipts", resource) when { principal has recurse_role && principal.recurse_role == "tenant_auditor" };
permit(principal, action == Recurse::Action::"ExportEvidence", resource) when { principal has recurse_role && principal.recurse_role == "tenant_auditor" };
permit(principal, action == Recurse::Action::"ReadPayload", resource) when { principal has recurse_role && principal.recurse_role == "tenant_auditor" };
// caller: F002 data plane only.
permit(principal, action == Recurse::Action::"ChatCompletion", resource) when { principal has recurse_role && principal.recurse_role == "caller" };

// tenant_auditor: read-only audit + forensic console surface (F004).
permit (
  principal,
  action in [
    Recurse::Action::"LoginSession",
    Recurse::Action::"DashboardQuery",
    Recurse::Action::"PolicyReplay",
    Recurse::Action::"ChatDrawerQuery",
    Recurse::Action::"AuditAgentToolQueryReceipts",
    Recurse::Action::"AuditAgentToolFetchReceiptDetail",
    Recurse::Action::"AuditAgentToolExplainDenial",
    Recurse::Action::"AuditAgentToolFindSimilarReceipts",
    Recurse::Action::"AuditAgentToolSimulatePolicyDryrun"
  ],
  resource
)
when { principal.recurse_role == "tenant_auditor" && principal.tenant_id == context.tenant_id };

// platform_operator: superset of auditor + write-adjacent console actions
// (simulate, drafts, suggestions, MCP-registry quarantine).
permit (
  principal,
  action in [
    Recurse::Action::"LoginSession",
    Recurse::Action::"DashboardQuery",
    Recurse::Action::"PolicyReplay",
    Recurse::Action::"ChatDrawerQuery",
    Recurse::Action::"AuditAgentToolQueryReceipts",
    Recurse::Action::"AuditAgentToolFetchReceiptDetail",
    Recurse::Action::"AuditAgentToolExplainDenial",
    Recurse::Action::"AuditAgentToolFindSimilarReceipts",
    Recurse::Action::"AuditAgentToolSimulatePolicyDryrun",
    Recurse::Action::"PolicySimulate",
    Recurse::Action::"PolicyDraftCreate",
    Recurse::Action::"PolicyDraftEdit",
    Recurse::Action::"PolicyDraftArchive",
    Recurse::Action::"PolicyDraftDryRun",
    Recurse::Action::"PolicySuggestionView",
    Recurse::Action::"PolicySuggestionAdopt",
    Recurse::Action::"PolicySuggestionDismiss",
    Recurse::Action::"PolicySuggestionRefresh",
    Recurse::Action::"AuditAgentToolSuggestPolicyPattern",
    Recurse::Action::"McpRegistryQuarantine"
  ],
  resource
)
when { principal.recurse_role == "platform_operator" && principal.tenant_id == context.tenant_id };

// system principal: internally minted only (suggestion-engine worker).
// Not user-assignable; surface kept minimal on purpose.
permit (
  principal,
  action == Recurse::Action::"PolicySuggestionGenerate",
  resource
)
when { principal.recurse_role == "system" };

// ===========================================================================
// 4. The fold (only when R5E_FOLD_ENABLED=true)
// ===========================================================================
// The fold (spec 012 S9) writes a second, hash-chained record of every call
// beside the enterprise receipt, inside an r5e kernel embedded in the same
// release. Activating a bundle in the gateway ALSO activates it in the fold
// (`Fold.Submitter.submit_bundle/1` re-admits the fold's
// `PolicyBundle/active` citing these exact bytes), so from that point on
// THIS FILE is the policy the fold's admission gate reads — for every act
// it records, not only tool calls:
//
//   Action::"admit"       every recording act: the prompt and completion
//                         bytes (CasObject), the session (AgentSession),
//                         the Prompt/Completion/LlmResponse events, and
//                         the next bundle activation itself
//   Action::"call_model"  the LlmCall event, resource Model::"<model>"
//   Action::"invoke_tool" the ToolCall events — the SAME vocabulary
//                         section 1 uses, which is the point: one bundle,
//                         one decision, recorded on both records
//
// Cedar is deny-by-default, so WITHOUT the two permits below the fold
// records nothing but denials once this bundle is activated in it — and,
// because activating the next bundle is itself an `admit`, the fold's
// PolicyBundle/active can never be superseded again on that chain. Delete
// them only if you mean both of those things. They are inert for the
// gateway: it never asks Cedar about `admit` or `call_model`.
//
// Narrow them the way you would any other rule — e.g. forbid recording a
// model you do not allow — but keep the baseline permits, and keep
// `admit` on core.r5e.io/v1/CasObject in particular: it is what lets a
// later bundle reach the chain at all.

permit (
  principal,
  action == Action::"admit",
  resource
);

permit (
  principal,
  action == Action::"call_model",
  resource
);
