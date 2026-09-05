# Eddy Smoke Cedar Fixture Bundle

Spec: `009-llm-api-proxy`, Phase 3 Sub-3.8, task T074.

## What this bundle does

Two-rule Cedar bundle exercised by the US1 E2E smoke test:

1. **permit_all_else** — baseline `permit (principal, action, resource);` so
   the bundle isn't deny-by-default and non-shell tool calls reach `:allow`.
2. **rule_no_destructive** — `forbid` the `shell` tool when the
   `command` argument in `context.tool_args` contains `rm -rf`.

## How it's loaded

The E2E test
(`apps/recurse_gateway/test/recurse_gateway/llm_proxy/integration/eddy_smoke_test.exs`)
loads the `bundle.cedar` source file directly into a
`%Recurse.Gateway.PolicyBundleRef{}` — same pattern as
`cedar_tool_use_gate_test.exs`. No `OciPolicyProvider` plumbing,
no `BundleLoader` dependency. The bundle reaches the proxy via the
`:bundle_loader_module` opt seam on `CedarToolUseGate.snapshot_bundle/1`.

## How operators load it

For the manual T076 pass against a local BEAM, copy `bundle.cedar`
to the Gateway's configured Cedar bundle path (or publish via the
admin Cedar-bundle-activate endpoint), then drive traffic through the
proxy. The seed script that used to do that is not in the public tree:
it seeded this operator's own environment.

## Verifying the bundle

The E2E test verifies behavior:
- `tool_args = %{"command" => "rm -rf /tmp/test"}` → `:deny`
  with `rule_id` matching the `rule_no_destructive` policy id.
- `tool_args = %{"command" => "ls -la"}` → `:allow`.

## Cross-references

- `specs/009-llm-api-proxy/quickstart.md` Flow 1 §"Trigger a deny"
- `apps/recurse_gateway/lib/recurse_gateway/llm_proxy/cedar_tool_use_gate.ex`
  §`build_cedar_context/2` (the `context.tool_args` shape)
- `apps/recurse_gateway/test/recurse_gateway/llm_proxy/cedar_tool_use_gate_test.exs`
  (precedent for inline-bundle-source tests)
