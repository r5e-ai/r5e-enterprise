# Contract: MCP Intercept (forward proxy)

**Module**: `Recurse.Gateway.Mcp.InterceptRouter` + `Recurse.Shared.Mcp.Envelope`
**Phase**: 3 (MCP intercept HTTP)

## Purpose

Customer agent's outbound MCP traffic to a non-Recurse-hosted MCP server flows THROUGH the gateway. Every JSON-RPC message is parsed, wrapped in an attested predicate, evaluated against Cedar policy, and (if allowed) forwarded to the upstream server. Responses come back through the same path with response-side attestation.

## Routing

```
[customer agent's MCP client]
       ↓  configured to point at:
       ↓  https://gateway.r5e.example/v1/mcp/intercept/<server_name>/<...path>
       ↓
[Bandit / Plug router]
       ↓
[InterceptRouter]
       ↓  parse JSON-RPC envelope
       ↓  resolve upstream URL from Hub registry (server_name → server URL)
       ↓  Cedar gate (principal × tool × args)
       ↓  emit `mcp_intercept_request` predicate
       ↓  forward via Req (HTTP) or Bandit upstream (SSE/Streamable)
       ↓  receive response
       ↓  emit `mcp_intercept_response` predicate
       ↓  return response to client
```

## Server name resolution

`server_name` is looked up in the Hub registry (`mcp_hub_entries`). If not in Hub OR not allowed by tenant trust dial, request is rejected with structured MCP error before any forwarding.

For Recurse-hosted MCP servers (Phase 4), the upstream URL is `http://localhost:<port>` for the supervised instance running on the BEAM.

For Hub-vouched-but-not-Recurse-hosted MCP servers (e.g., Linear's hosted `https://mcp.linear.app/sse`), the upstream URL is the published external endpoint.

## JSON-RPC envelope handling

```elixir
defmodule Recurse.Shared.Mcp.Envelope do
  @type t :: %__MODULE__{
          jsonrpc: String.t(),               # always "2.0"
          method: String.t() | nil,          # request method, nil for responses
          id: integer() | String.t() | nil,  # request/response correlation
          params: map() | nil,
          result: any() | nil,               # response only
          error: %{code: integer(), message: String.t()} | nil  # response only
        }

  @spec parse(binary()) :: {:ok, t()} | {:error, :invalid_json | :invalid_jsonrpc | :unsupported_version}
  @spec serialize(t()) :: binary()
  @spec is_request?(t()) :: boolean()
  @spec is_response?(t()) :: boolean()
  @spec is_notification?(t()) :: boolean()
end
```

## Per-message predicate emission

For each JSON-RPC request → response pair, TWO predicates are emitted:

1. `mcp_intercept_request` — fired BEFORE forwarding. Contains:
   - `mcp_method` (e.g., `"tools/call"`, `"resources/read"`)
   - `mcp_intercept_request_id` (correlation ID, derived from JSON-RPC `id`)
   - `tool_name` (extracted from `params.name` for `tools/call`)
   - `tool_args_digest` (SHA-256 of `params.arguments` — full payload in customer S3)
   - `cedar_decision`
   - `upstream_server_name`
   - `tenant_id`, `principal_id`, etc. from envelope

2. `mcp_intercept_response` — fired AFTER receiving upstream response. Contains:
   - `mcp_intercept_request_id` (matches the request)
   - `result_digest` (SHA-256 of upstream response, full body in customer S3)
   - `is_error` (true if upstream returned a JSON-RPC error)
   - `upstream_latency_ms`

For SSE / Streamable HTTP responses (multiple chunks per logical request), one `mcp_intercept_response` predicate per chunk; chunks share the same `mcp_intercept_request_id`.

## Cedar policy

Cedar resource path: `mcp_tool::<server_name>::<method_or_tool_name>`
Cedar action: `invoke`
Cedar principal: the authenticated Recurse Principal (developer or agent)

Example policy:
```cedar
permit(
  principal in Group::"engineering",
  action == Action::"invoke",
  resource is McpTool
) when {
  resource.server in ["github", "linear", "datadog"]
};

forbid(
  principal,
  action == Action::"invoke",
  resource is McpTool
) when {
  resource.tool_name == "delete_repo" || resource.tool_name == "delete_workspace"
};
```

## Upstream forwarding

- HTTP request/response: via `Req` (HTTP/1.1 + HTTP/2 negotiation)
- SSE: via Bandit upstream connection (long-lived; supports both connection directions)
- Streamable HTTP: via Bandit upstream with chunked transfer encoding

Connection pooling per (tenant_id, server_name) to avoid TLS handshake overhead. Pool size + timeout per-server-config.

## Error mapping

| Source of error | MCP wire response |
|-----------------|-------------------|
| Invalid JSON-RPC envelope | `{"error": {"code": -32700, "message": "Parse error"}}` |
| Unknown server_name | `{"error": {"code": -32601, "message": "Server not found in Hub"}}` |
| Cedar policy deny | `{"error": {"code": -32603, "message": "Policy denial: <policy clause>"}}` |
| Upstream timeout | `{"error": {"code": -32603, "message": "Upstream timeout"}}` |
| Upstream connection refused | `{"error": {"code": -32603, "message": "Upstream unreachable"}}` |
| Upstream returns JSON-RPC error | Forward verbatim |

All errors emit `mcp_intercept_response` predicate with `is_error: true`.

## Tests required

**Contract**:
- All four MCP transport patterns (HTTP request/response, SSE long-lived, Streamable HTTP) work end-to-end through the intercept
- Server name resolution honors trust dial: Recurse-vouched-only tenants reject non-Hub pulls
- Every JSON-RPC message produces exactly one request predicate + one response predicate (or N response predicates for streaming)

**Property tests**:
- JSON-RPC envelope fuzz: arbitrary JSON → parser correctly handles every input (no crashes; structured errors for malformed)
- Correlation ID round-trip: request `id` always matches response `id`; mismatched IDs result in error predicate
- Predicate count invariants: under any sequence of messages (req-only, req-response, notification-only, streaming), the count of emitted predicates is exactly the expected count

**Integration**:
- Set up a test upstream MCP server in a sidecar container; route an agent's traffic through intercept; verify (a) traffic flows correctly, (b) every message produces a receipt, (c) Cedar deny stops the request before forwarding

## Constitution alignment

- **Principle II** (Kernel-Level Enforcement, Governance tiers): the intercept IS the gateway path; this is where customer agent traffic must flow per existing netns jail. Compliance.
- **Principle III** (Cryptographic Provenance): per-message attestation is the design.
- **Principle IV** (Detached Payloads): full args/result bodies live in customer S3; predicates carry only digests.
- **Principle V**: no new vendor abstraction; HTTP forwarding is via existing `Req`/Bandit.
