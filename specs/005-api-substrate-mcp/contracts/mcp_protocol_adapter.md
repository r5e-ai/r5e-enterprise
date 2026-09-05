# Contract: MCP Protocol Adapter (Recurse-as-MCP-Server)

**Module**: `Recurse.Gateway.ApiSubstrate.McpAdapter`
**Phase**: 2 (MCP protocol adapter)

## Purpose

Translate MCP JSON-RPC method calls into substrate `ApiCapability.execute/2` calls. Translate `tools/list` into a substrate registry walk. Translate substrate responses back into MCP responses. The adapter is purely a protocol facade — zero business logic lives here.

## Surface

The adapter handles four MCP methods at v1:

| MCP Method | Substrate operation |
|------------|---------------------|
| `initialize` | Static handshake — no substrate call. Returns server info + protocol version. |
| `tools/list` | Walk capability registry; serialize each as MCP tool with parameter schema (request schema) + description. |
| `tools/call` | Look up capability by name; build `execution_context` from MCP request headers + auth; invoke `Capability.execute/2`; serialize response. |
| `notifications/cancelled` | Best-effort cancellation hook (substrate execute is not yet cancellable; v1 logs the cancellation request, no-op). |

## Tool naming

MCP tool name = substrate capability name (`name/0` callback). One-to-one.

For multi-version capabilities (same `name`, different `version`), the latest active version (highest semver, `is_active = true`) is the default tool. Specific versions addressable via tool name suffix: `query_receipts@1.0.0`, `query_receipts@2.0.0`.

## Tool parameter schema

The MCP tool's `inputSchema` is the capability's `request_schema()` — published with `predicateTypeDigest` reference for verifiable schema integrity. The `outputSchema` is the capability's `response_schema()`. MCP clients can use either for client-side validation.

## Authentication

- Bearer token in `Authorization: Bearer <token>` header → resolves to a Recurse Principal via existing F004 OIDC auth flow.
- Anonymous requests can call `initialize` and `tools/list` (catalog visible without auth, mirrors existing introspection norm) but every tool returned in `tools/list` is annotated `requires_auth: true`.
- `tools/call` without auth → MCP-shaped error: `{"code": -32603, "message": "Authentication required"}`.

## Per-tenant scoping

`execution_context.tenant_id` is derived from the authenticated Principal's tenant claim. Capabilities scope their queries by this field — the adapter never reaches into capability internals to enforce scoping; capabilities are responsible for honoring `context.tenant_id`.

## Transport

Bandit-native handlers for:
- HTTP request/response (`POST /v1/mcp/serve`)
- SSE long-lived connection (`GET /v1/mcp/serve` with `Accept: text/event-stream`)
- Streamable HTTP (`POST /v1/mcp/serve` with `Accept: application/json+streamable`) — the newer transport per the modern MCP spec

## Tests required

**Contract**:
- `tools/list` returns ALL active capabilities, with parameter + return schemas
- `tools/call` for a known capability invokes the underlying `Capability.execute/2`
- Auth-required tools refuse anonymous calls with structured MCP errors

**Property tests**:
- For every capability registered, `tools/list` exposes it and `tools/call` round-trips faithfully (request → execute → response → MCP wire format → matches expected shape)
- MCP error envelopes are well-formed (matching the JSON-RPC 2.0 + MCP error shape) for every error class

**Integration**:
- External MCP client (e.g., `npx @modelcontextprotocol/inspector`) connects, lists tools, invokes `query_receipts` against test data, gets a structured response, the predicate appears in the audit log

## Constitution alignment

- **Principle III**: every `tools/call` produces an `api_capability_invoke` predicate. NON-NEGOTIABLE.
- **Principle V**: MCP is one of many protocol adapters; the adapter is in `recurse_gateway`, not `recurse_providers` (it's not a vendor abstraction — Recurse always speaks MCP via this code).
- **Principle VII**: this adapter is the FIRST consumer of the substrate. The interface (substrate's `ApiCapability` behaviour) was defined upfront BECAUSE we know there will be more consumers (REST, GraphQL, gRPC).
