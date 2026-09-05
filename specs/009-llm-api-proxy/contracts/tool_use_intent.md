# Contract: ToolUseIntent

**Module**: `Recurse.Shared.LlmProxy.ToolUseIntent`
**Owner phase**: Phase 1
**Consumed by**: Phase 2 (proxy passes to gate), Phase 3 (Cedar gate evaluates), Phase 4 (denial injector references), Phase 5 (attestation emitter records)

## Purpose

Canonical Elixir struct representing a single tool_use intent extracted from an LLM response. Provider-agnostic (parser converts provider-specific shape into this struct).

## Struct shape

```elixir
defmodule Recurse.Shared.LlmProxy.ToolUseIntent do
  @type t :: %__MODULE__{
          call_id: String.t(),                   # provider-issued correlation id (e.g., OpenAI "call_abc")
          tool_name: String.t(),                  # "shell", "edit", "web_fetch", etc.
          tool_args: map() | :too_large,          # JSON-decoded args object; or :too_large sentinel
          tool_args_hash: binary(),               # SHA-256 of canonical(tool_args)
          tool_args_size_bytes: pos_integer(),    # byte length of canonical-JSON tool_args
          parallel_index: non_neg_integer() | nil,  # index in parallel_tool_calls array; nil for non-parallel
          provider_event_span: provider_span(),   # which raw events constituted this intent (for injector to suppress)
          extracted_at: DateTime.t()
        }

  defstruct [:call_id, :tool_name, :tool_args, :tool_args_hash, :tool_args_size_bytes,
             :parallel_index, :provider_event_span, :extracted_at]

  @type provider_span :: %{
          start_byte_offset: non_neg_integer(),
          end_byte_offset: non_neg_integer(),
          event_indices: [non_neg_integer()]   # which event-numbers in the response stream constituted this intent
        }
end
```

## Invariants

- **I-001**: `tool_args_hash` = SHA-256 of `Jason.encode!(tool_args)` when `tool_args` is a map; SHA-256 of the original raw JSON when `:too_large`.
- **I-002**: `provider_event_span` accurately identifies the byte range / event indices that constitute this intent — used by the denial injector to know what to suppress.
- **I-003**: `call_id` is provider-issued (do NOT generate locally) — preserves correlation with provider's audit logs and the agent's `function_call_output` echo.
- **I-004**: `parallel_index` matches the provider's array position when parallel_tool_calls is in play; null otherwise.

## Construction

Constructed by per-provider parsers (Phase 1). The struct is immutable; passed by-reference through proxy stages.

## Dependencies

- `Jason` — for canonical JSON encoding
- `:crypto.hash(:sha256, _)` — for hash computation
