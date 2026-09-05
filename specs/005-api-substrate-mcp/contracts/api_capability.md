# Contract: ApiCapability behaviour

**Module**: `Recurse.Shared.ApiSubstrate.Capability`
**Phase**: 1 (substrate machinery)

## Purpose

Every operation Recurse exposes — to MCP, to future REST/GraphQL/gRPC adapters, to the audit-API consumers — is implemented as a module that adopts the `ApiCapability` behaviour. The behaviour is the single source of truth for: what an operation is named, what its request/response/error shapes are, what Cedar resource path governs it, whether it's a read or write, and how it actually executes.

The substrate machinery (registry, introspection, per-op predicate emission, Cedar gate) wraps every capability uniformly — capability code is pure-business-logic; substrate code is pure-cross-cutting-concerns. Capability authors do NOT touch attestation, signing, predicate envelopes, or Cedar evaluation — those happen automatically because they implement this behaviour.

## Behaviour callbacks

```elixir
defmodule Recurse.Shared.ApiSubstrate.Capability do
  @callback name() :: String.t()
  @callback version() :: String.t()
  @callback description() :: String.t()
  @callback read_or_write() :: :read | :write
  @callback policy_resource_path() :: String.t()
  @callback request_schema() :: map()              # JSON Schema (draft 2020-12)
  @callback response_schema() :: map()
  @callback error_schema() :: map()
  @callback execute(request :: map(), context :: execution_context()) ::
              {:ok, response :: map()} | {:error, error :: map()}

  @type execution_context :: %{
          principal: Recurse.Shared.Principal.t(),
          tenant_id: String.t(),
          parent_predicate_ref: String.t() | nil,
          cedar_decision: :allow | :deny,
          invocation_id: String.t()
        }
end
```

## Behaviour adoption pattern

Capability authors `use` the behaviour, which automatically:
1. Registers the module in the substrate's `:persistent_term`-backed capability registry at app boot
2. Compile-time-validates the JSON schemas (raises if invalid Schema)
3. Wires the per-op predicate emission + Cedar gate into the `execute/2` dispatch path

Author-facing surface is just the seven callbacks (`name`, `version`, `description`, `read_or_write`, `policy_resource_path`, `request_schema`, `response_schema`, `error_schema`) plus the `execute/2` implementation.

```elixir
defmodule Recurse.Gateway.Capabilities.QueryReceipts do
  use Recurse.Shared.ApiSubstrate.Capability,
    name: "query_receipts",
    version: "1.0.0",
    description: "Query the audit log of attested receipts within scope",
    read_or_write: :read,
    policy_resource_path: "capability::query_receipts"

  @impl true
  def request_schema, do: %{ ... }   # JSON Schema for filter args
  @impl true
  def response_schema, do: %{ ... }  # JSON Schema for receipt list shape
  @impl true
  def error_schema, do: %{ ... }     # JSON Schema for structured errors

  @impl true
  def execute(request, context) do
    # Pure business logic. Substrate wrapper has already:
    #   - Authenticated principal
    #   - Evaluated Cedar policy (this function only runs on :allow)
    #   - Allocated invocation_id
    # Substrate wrapper will, after this returns:
    #   - Emit api_capability_invoke predicate (success or error)
    #   - DSSE-sign + ledger-commit per existing F002 path
    #   - Return response to caller
    Recurse.Runtime.Receipts.query(request, scope: context.tenant_id)
  end
end
```

## Substrate wrapper responsibilities (NOT capability author's concern)

For each `execute/2` invocation, the substrate:

1. **Pre-flight Cedar gate**: evaluate `policy_resource_path()` against `context.principal` + `context.tenant_id` + `request`. If deny → return error without invoking `execute/2`; emit `api_capability_invoke` predicate with `outcome: denied`.
2. **Allocate invocation_id** (UUID v7) — used as the predicate's `run_id` field.
3. **Invoke `execute/2`** with the populated context.
4. **Emit predicate** with `event_kind: "api_capability_invoke"`, `api_capability_id`, `api_schema_publication_digest` (request schema's digest), `outcome: :success | :error`, plus the standard envelope fields.
5. **DSSE-sign + ledger-commit** the predicate via existing F002 path.
6. **Return** `{:ok, response}` or `{:error, error}` to the caller (one of the protocol adapters: MCP, REST, etc.)

## Tests required (per Constitution Principle VI)

**Contract tests**:
- A fake capability adopting the behaviour MUST round-trip through registry → introspection → execute → predicate emission.
- All seven callbacks return the expected shape.
- Schema validation fails compile-time for invalid JSON Schema.

**Property tests** (`StreamData`):
- Schema round-trip: arbitrary capability → schema published to CAS → fetch by digest → decode op → succeeds for valid requests, fails structurally for malformed.
- Predicate emission invariants: every `execute/2` call emits exactly one predicate (no leak, no duplicate); the predicate carries the correct `event_kind` + `api_capability_id`; the predicate's `outcome` matches the actual return value.
- Cedar gate invariants: deny short-circuits `execute/2` (capability code never runs).

## Constitution alignment

- **Principle III** (Cryptographic Provenance): every execute call emits a predicate. NON-NEGOTIABLE.
- **Principle V** (Provider-Interface Neutrality): capabilities are NOT vendor abstractions; they're Recurse-internal operations. The substrate IS the abstraction layer for protocol adapters (MCP, REST, etc.).
- **Principle VI** (Test-First): contract tests precede implementation; property tests cover the substrate invariants above.
- **Principle VII** (Interface-First on Second Consumer): the `ApiCapability` behaviour exists exactly because we know of 4+ consumers (MCP adapter, future REST/GraphQL/gRPC adapters, eventual audit-API consolidation). Defined upfront before the second consumer.
