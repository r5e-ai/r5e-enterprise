# Contract: Cedar Tool-Use Gate

**Module**: `Recurse.Gateway.LlmProxy.CedarToolUseGate`
**Owner phase**: Phase 3
**Consumed by**: Phase 4 (denial injector takes the deny decision + reason)

## Purpose

Per-`ToolUseIntent` policy evaluation. Wraps the existing Cedar evaluator with the LLM-proxy-specific context shape (per R-004). Returns allow/deny with structured reason.

## API

```elixir
@spec evaluate(intent :: ToolUseIntent.t(), context :: gate_context()) ::
        {:allow}
      | {:deny, %{rule_id: String.t(), reason: String.t(), suggested_alternative: String.t() | nil}}
      | {:error, atom()}

@type gate_context :: %{
        principal: %{
          id: String.t(),
          kind: :obo_human | :service_account | :autonomous,
          chatgpt_account_id: String.t() | nil,
          claims: map()
        },
        model: String.t(),
        tenant: String.t(),
        session_id: String.t(),
        prompt_hash: binary(),
        response_so_far_hash: binary(),
        estimated_completion_tokens: integer(),
        parallel_tool_call_index: integer() | nil,
        cedar_bundle_hash: binary(),
        upstream_domain: String.t(),
        transport: :wss | :https_sse,
        started_at: DateTime.t()
      }
```

## Cedar context construction

The gate constructs a Cedar context like:

```
principal: User::"<id>"
action: Action::"invoke_tool"
resource: ToolUse::"<tool_name>"
context: {
  tool_args: <inlined-when-under-threshold>,
  tool_args_hash: "<hex>",
  model: "...",
  tenant: "...",
  session_id: "...",
  prompt_hash: "<hex>",
  response_so_far_hash: "<hex>",
  estimated_completion_tokens: 1234,
  parallel_tool_call_index: null,
  cedar_bundle_hash: "<hex>",
  upstream_domain: "chatgpt.com",
  transport: "wss",
  started_at: "...",
  principal_kind: "obo_human",
  chatgpt_account_id: "<uuid>",
  principal_groups: ["dev", "platform"]
}
```

Cedar policies can then key on any combination, e.g.:

```cedar
forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"shell"
) when {
  resource has tool_args && resource.tool_args has "command"
  && resource.tool_args.command.contains("rm -rf")
  && !principal in Group::"platform-operators"
};

permit (
  principal,
  action == Action::"invoke_tool",
  resource
) when {
  context.model == "gpt-5-codex" && context.transport == "wss"
};

forbid (
  principal,
  action == Action::"invoke_tool",
  resource
) when {
  context.estimated_completion_tokens > principal.token_budget_remaining
};
```

## Args inlining threshold

Default 10KB. Below threshold: `tool_args` inlined as JSON in Cedar context. Above threshold: only `tool_args_hash` available; Cedar can't pattern-match on content but can compare against allow-set hashes.

Per-tenant configurable via `LlmProviderConfig.metadata.cedar_args_inline_threshold_bytes`.

## Bundle snapshot semantic

The bundle active at call-start is captured (hash + content) and used for all intents in that call, even if a new bundle activates mid-stream. Documented as "policy snapshot at call start" in spec.md edge cases.

## Decision-cache (optional optimization)

Per `(principal_id, tool_name, tool_args_hash, cedar_bundle_hash)` decision cache (TTL 10s, size 1000). Sub-ms cache hits. Useful for parallel-tool-call cases where the same principal makes 3 similar calls in <1s.

## Test contracts

- **CT-001**: Known fixture intent + known Cedar policy → expected allow/deny decision with rule_id
- **CT-002**: Args-too-large → only hash provided; policy that depends on args content reaches allow-by-default (or hash-allowlist match)
- **CT-003**: Bundle activation during in-flight call uses start-of-call bundle (snapshot semantic)
- **CT-004**: Decision-cache hit returns same result as fresh eval

## Property tests

- **PT-001**: Cedar evaluation determinism (same context → same decision over 1000 runs)
- **PT-002**: Decision cache correctness (cache hit returns identical to cache miss)

## Performance

- **P-001**: Cedar eval p95 < 1ms (per !119's existing measurements)
- **P-002**: 5000 evals/sec single BEAM node throughput

## Dependencies

- Existing Cedar Rustler NIF (per !119)
- Existing `Recurse.Providers.PolicyProvider` for current bundle lookup
