// CategoryPill — colored pill showing a receipt's tag category (Wave C).
//
// Per the R1/R2 frames in `design/r5e-enterprise-audit-ui.pen`:
//   - Pill is `[CATEGORY-NAME]` in mono, uppercase tracking-wider, on a
//     low-saturation chart-color background, bordered with the same
//     chart color at full strength.
//   - Pill is the auditor's primary 1-glance hue — `policy_denied` is
//     red and SUPERSEDES the underlying tags.category (R4 Rule 01:
//     denials always read red).
//
// Class strings come from the shared `~/lib/chartTokens` resolver
// (extracted in MR !86 fix-pass-2 per Constitution Principle VII —
// CategoryPill, FilterFacet, and ToolCell were three inline copies of
// the same chart-token → Tailwind-class lookup; the third copy
// motivated the extraction). The token name comes from
// `~/lib/tags#categoryColorToken`.
//
// New chart-* tokens MUST be added to
// `ui/design-tokens.json` first and `pnpm gen:tailwind`
// re-run; the test at `ui/src/tests/unit/tailwindTokens.test.ts` enforces
// that every literal `r5e-*` class resolves to a real token.

import { chartTokenClasses } from "~/lib/chartTokens";
import { categoryColorToken } from "~/lib/tags";

interface Props {
  category: string | null | undefined;
  /** Render `policy_denied` regardless of the category prop. Used by the
   *  row to enforce R4 Rule 01 visually without re-deriving. */
  forceDenial?: boolean;
  /** Compact variant used in dense table rows. */
  size?: "sm" | "md";
}

export function CategoryPill({ category, forceDenial, size = "md" }: Props): JSX.Element {
  const effective = forceDenial ? "policy_denied" : (category ?? null);
  const label = effective ?? "unknown";
  const token = categoryColorToken(effective);
  const { text, bg, border } = chartTokenClasses(token, "pill");
  const padding = size === "sm" ? "px-1.5 py-px text-[9px]" : "px-2 py-0.5 text-[10px]";
  return (
    <span
      data-testid="category-pill"
      data-category={label}
      className={`inline-block rounded border font-mono uppercase tracking-wider ${padding} ${text} ${bg} ${border}`}
    >
      {label}
    </span>
  );
}
