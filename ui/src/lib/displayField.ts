// Generalized display helpers for receipt-shaped object fields.
//
// Many SPA surfaces receive backend objects whose schemas are loose
// (`Record<string, unknown>` until the T043 codegen lands) and whose shape
// varies by `kind`. Rendering the object directly crashes React with error
// #31 ("Objects are not valid as a React child"). The pattern is the same
// across `principal`, `machine_identity`, `principal_canonical`, etc.: pick
// a preferred key by precedence, fall back to `kind` or a truncated JSON
// dump.
//
// `displayObjectField` is the generic; `displayPrincipal`,
// `displayMachineIdentity`, and `displayPrincipalCanonical` are pre-configured
// helpers for the common receipt fields (per S-1 in the audit-pass resolver
// consolidation plan).
//
// Closes:
//   - LB-2 (machine_identity rendered with inline ternary at
//     ReceiptDetail.tsx:266-270)
//   - LB-3 (displayPrincipal's `agent_id` branch was dead code; the backend
//     emits `spiffe_id` for the autonomous principal)
//
// Defensive against:
//   - `null` / `undefined`           → returns `"—"`
//   - Already a string (passthrough) → returns the string
//   - Non-object scalar              → `String(value)`
//   - Object missing all preferred keys → falls back to `fallbackLabel` if
//     provided, else a truncated JSON dump (≤80 chars)

export interface DisplayFieldConfig {
  preferredKeys: string[];
  fallbackLabel?: string;
}

export function displayObjectField(
  value: unknown,
  config: DisplayFieldConfig,
): string {
  if (value == null) return "—";
  if (typeof value === "string") return value;
  if (typeof value !== "object") return String(value);
  const obj = value as Record<string, unknown>;
  for (const key of config.preferredKeys) {
    const v = obj[key];
    if (typeof v === "string" && v !== "") return v;
  }
  const json = JSON.stringify(obj);
  if (json.length > 80) return json.slice(0, 77) + "...";
  return config.fallbackLabel ?? json;
}

/**
 * Canonical per-kind identity keys that name the same domain concept across
 * the SPA. Order is the precedence used to render a principal as a string
 * via `displayPrincipal()`:
 *   - `obo_human`       → `subject`
 *   - `service_account` → `account_id`
 *   - `autonomous`      → `spiffe_id` (per identity_context_builder.ex:215)
 *   - any kind          → `kind` (kind-only fallback for `displayPrincipal`)
 *
 * Constitution Principle VII — owned in ONE place. Consumers that match
 * principals by identity (`matchesPrincipal` in `~/lib/timeline`, the
 * dev-mocks `/v1/audit/timeline` filter) compose this list rather than
 * re-listing the keys.
 *
 * Note: `PRINCIPAL_IDENTITY_KEYS` is the SUBSET used for matching
 * (excludes `kind`, which is a discriminator, not an identifier). The
 * full precedence list (`PRINCIPAL_DISPLAY_PREFERENCE`) is what
 * `displayPrincipal()` walks; matching omits `kind` because two distinct
 * autonomous principals share the same `kind` value.
 */
export const PRINCIPAL_IDENTITY_KEYS = [
  "subject",
  "account_id",
  "spiffe_id",
] as const;

export const PRINCIPAL_DISPLAY_PREFERENCE = [
  ...PRINCIPAL_IDENTITY_KEYS,
  "kind",
] as const;

/**
 * Receipt `signed_predicate.principal` — varies by `principal.kind`:
 *   - `obo_human`       → prefers `subject`
 *   - `service_account` → prefers `account_id`
 *   - `autonomous`      → prefers `spiffe_id` (NOT `agent_id` — LB-3 fix; the
 *                         backend autonomous principal at
 *                         identity_context_builder.ex:215 emits `spiffe_id`)
 *   - any kind          → falls back to `kind` or truncated JSON
 */
export const displayPrincipal = (v: unknown): string =>
  displayObjectField(v, {
    preferredKeys: [...PRINCIPAL_DISPLAY_PREFERENCE],
  });

/**
 * Receipt `signed_predicate.machine_identity` — typically a SPIFFE workload
 * identity. Replaces the inline ternary at ReceiptDetail.tsx:266-270 (LB-2).
 */
export const displayMachineIdentity = (v: unknown): string =>
  displayObjectField(v, {
    preferredKeys: ["spiffe_id", "kind"],
    fallbackLabel: "(unknown machine identity)",
  });

/**
 * Receipt `signed_predicate.principal_canonical` — the canonicalized
 * principal envelope used for policy matching. Reserved for future receipt
 * detail tabs.
 */
export const displayPrincipalCanonical = (v: unknown): string =>
  displayObjectField(v, {
    preferredKeys: ["canonical_form", "subject", "kind"],
  });

/**
 * Match a receipt's `signed_predicate.principal` blob against a target
 * identifier. Accepts the canonical display form OR any per-kind identity
 * key (`PRINCIPAL_IDENTITY_KEYS`).
 *
 * Lives in `displayField.ts` (no React deps) so the dev-mocks Vite plugin
 * — which runs in Node before the SPA bundle is built — can use the
 * SAME semantics as the SPA's `filterByScope` / `~/lib/timeline`. This
 * is Constitution Principle VII enforcement: a backend team consuming
 * the dev-mocks `/v1/audit/timeline` stub gets the same matching
 * behavior the SPA emits canonical SPIFFE-form deep links against.
 */
export function matchesPrincipal(raw: unknown, target: string): boolean {
  if (displayPrincipal(raw) === target) {
    return true;
  }
  if (raw && typeof raw === "object") {
    const o = raw as Record<string, unknown>;
    for (const key of PRINCIPAL_IDENTITY_KEYS) {
      const v = o[key];
      if (typeof v === "string" && v === target) return true;
    }
  }
  return false;
}
