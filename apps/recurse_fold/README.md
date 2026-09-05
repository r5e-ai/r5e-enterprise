# recurse_fold

The fold defines the gateway API group and signs enterprise observations under
a node-issued endorsement. It is a required dependency of the gateway and
uses kernel admission for model requests, tool intents, evidence and policy
activation.

Kernel-owned policy governs maintenance and jurisdiction. Workload Cedar
governs LlmCall and ToolCall, conjunctively with the upstream decision. The
live proxy enforces that receipt; it does not repeat policy evaluation.

## Read the current boundary

- [Release contract](../../docs/release/oss-release-contract.md)
- [Execution surfaces and evidence limits](../../docs/release/execution-surfaces.md)
- [Export and independent verification](../../docs/fold-evidence.md)
- [Runtime environment](../../docs/reference/env.md)

## Implementation

| Concern | Source |
| --- | --- |
| Startup, signed seeds and preservation of active policy | `lib/recurse_fold/application.ex` |
| Signed admission and delegated authority | `lib/recurse_fold.ex` |
| Workload policy and admitted policy lookup | `lib/recurse_fold/policy/cedar.ex` |
| Measured deployed artifact descriptor | `lib/recurse_fold/policy/engine_build.ex` |
| Kind definitions and their scopes | `priv/kinds/` |
| Gateway request and tool boundary | `../recurse_gateway/lib/recurse_gateway/fold/admission.ex` |

The kernel data directory holds history, CAS and signing keys. The default
container uses `/data/kernel` on its own volume. Removing that volume removes
the deployment's history and identity. Disabling the fold refuses startup.

The fold suite includes fresh-kernel admission, policy jurisdiction,
replacement, restart, export and verifier regressions. Run it from the
enterprise root:

```sh
MIX_ENV=test mix test apps/recurse_fold/test
```

The frozen demo report is under `apps/recurse_fold/test/reports/fold-demo.txt`; its test invokes
the verifier on an export after restart. Read the complete report, including
its Kind scopes and not-checked block.
