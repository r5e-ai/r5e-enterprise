// TrustTierPill — single source of truth for the MCP-registry trust-tier
// chip. Maps `trust_tier` (verified | community | quarantined) to a
// `<Pill>` tone per R4 palette:
//
//   - verified    → success-green
//   - community   → muted-slate
//   - quarantined → warning-orange
//
// Danger-red is reserved for active-deny rows in the audit log; trust
// tiers do not use it.
//
// Constitution Principle VII: extracted on the second consumer
// (McpRegistry.tsx + McpRegistryDetail.tsx). Per the F001 finding on
// MR !88, the local copies were drift-prone (size differed, the
// detail page used `sm` while the list used `xs`); centralizing the
// switch eliminates that drift and gives a single place to register
// future tiers.
//
// Size pass-through: callers can still pick `xs` (list-row chips) or
// `sm` (header pill, Overview field) — the tone is the invariant, the
// size is per-consumer.
//
// Adding a new tier: extend the `McpRegistryEntry["trust_tier"]` enum
// in the JSON schema (regen types via `pnpm gen:types`) and add a case
// here. The TypeScript compiler will flag the missing case.

import { Pill, type PillSize } from "~/components/shared/Pill";
import type { McpRegistryEntry } from "~/lib/types";

interface Props {
  tier: McpRegistryEntry["trust_tier"];
  size?: PillSize;
  testId?: string;
}

export function TrustTierPill({
  tier,
  size = "xs",
  testId,
}: Props): JSX.Element {
  switch (tier) {
    case "verified":
      return (
        <Pill tone="success" size={size} testId={testId}>
          verified
        </Pill>
      );
    case "quarantined":
      return (
        <Pill tone="warning" size={size} testId={testId}>
          quarantined
        </Pill>
      );
    case "community":
    default:
      return (
        <Pill tone="muted" size={size} testId={testId}>
          community
        </Pill>
      );
  }
}
