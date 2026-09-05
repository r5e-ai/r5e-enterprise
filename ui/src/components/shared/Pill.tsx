// Pill — generic colored-pill primitive.
//
// CategoryPill (`~/components/audit/CategoryPill`) is the audit-log
// canonical category pill — that one MUST stay because it has its own
// strict R4 palette mapping. THIS Pill primitive is for everywhere
// else: blast radius `proven-safe` chips, MCP registry status pills,
// suggestion confidence chips, decision pills.
//
// Constitution Principle VII: extracted on the third inline copy after
// the Wave-D scan turned up 14+ inline pill class strings across the
// dashboard, drawer, suggestion cards, blast radius panel, and the MCP
// registry. Callers picked one of:
//   - "rounded border px-1.5 py-px text-[10px] uppercase tracking-wider"
//   - "rounded bg-r5e-border px-2 py-0.5 text-[10px] uppercase ..."
//   - mix of bg-/15 + border + text- in their own switch on a
//     decision/state/category enum.
//
// This primitive collapses those into a single shape with a `tone` enum
// driving the static Tailwind class strings (Tailwind 3 JIT requires
// statically-discoverable class names; dynamic interpolation breaks
// the purger). To add a new tone, register it here AND in the
// `TONE_CLASSES` table.

import type { ReactNode } from "react";

export type PillTone =
  | "neutral"
  | "accent"
  | "success"
  | "warning"
  | "danger"
  | "muted";

export type PillSize = "xs" | "sm" | "md";

interface Props {
  children: ReactNode;
  tone?: PillTone;
  size?: PillSize;
  /** When true, only the border is colored; bg stays transparent. Used
   *  by chips inside cards where a full bg would dominate. */
  outline?: boolean;
  /** When true, the label is rendered uppercase tracking-wider mono.
   *  Default true — matches CategoryPill / SuggestionCard convention. */
  uppercase?: boolean;
  testId?: string;
  className?: string;
}

const TONE_CLASSES: Record<PillTone, { fill: string; outline: string }> = {
  neutral: {
    fill: "border-r5e-border bg-r5e-border/40 text-r5e-text",
    outline: "border-r5e-border text-r5e-muted",
  },
  accent: {
    fill: "border-r5e-accent bg-r5e-accent/15 text-r5e-accent",
    outline: "border-r5e-accent text-r5e-accent",
  },
  success: {
    fill: "border-r5e-success bg-r5e-success/15 text-r5e-success",
    outline: "border-r5e-success text-r5e-success",
  },
  warning: {
    fill: "border-r5e-warning bg-r5e-warning/15 text-r5e-warning",
    outline: "border-r5e-warning text-r5e-warning",
  },
  danger: {
    fill: "border-r5e-danger bg-r5e-danger/15 text-r5e-danger",
    outline: "border-r5e-danger text-r5e-danger",
  },
  muted: {
    fill: "border-r5e-muted/40 bg-r5e-muted/15 text-r5e-muted",
    outline: "border-r5e-muted/60 text-r5e-muted",
  },
};

const SIZE_CLASSES: Record<PillSize, string> = {
  xs: "px-1 py-px text-[9px]",
  sm: "px-1.5 py-px text-[10px]",
  md: "px-2 py-0.5 text-[11px]",
};

export function Pill({
  children,
  tone = "neutral",
  size = "sm",
  outline = false,
  uppercase = true,
  testId = "pill",
  className = "",
}: Props): JSX.Element {
  const colors = outline ? TONE_CLASSES[tone].outline : TONE_CLASSES[tone].fill;
  const padding = SIZE_CLASSES[size];
  const typography = uppercase
    ? "font-mono uppercase tracking-wider"
    : "font-medium";
  return (
    <span
      data-testid={testId}
      data-tone={tone}
      className={`inline-block rounded border ${padding} ${typography} ${colors} ${className}`}
    >
      {children}
    </span>
  );
}
