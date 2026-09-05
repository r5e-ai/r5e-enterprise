// PulsingDots — three small dots with staggered pulse animation. The brief's
// streaming-state placeholder primitive, used both inside the chat
// ActivityStrip ("Agent is thinking…") AND inside an empty assistant
// MessageBubble while tokens haven't arrived yet.
//
// Constitution Principle VII (Interface-First on Second Consumer):
// previously inlined in both <ChatThread /> and <MessageBubble />, with
// near-identical markup differing only in the dot tone. Extracted on the
// second consumer per the constitutional rule the consolidation-check
// skill enforces.
//
// `tone` controls the dot color:
//   - "current" — `bg-current`, inheriting the parent's `text-*` color.
//     Used inside the ActivityStrip where the strip already sets a tone-
//     specific text color (accent / warning / danger) we want to follow.
//   - "muted"   — `bg-r5e-muted`, neutral grey. Used inside the empty
//     thinking-bubble where the parent surface has no tone color.

import type { JSX } from "react";

export type PulsingDotsTone = "current" | "muted";

export interface PulsingDotsProps {
  /** Color tone for the three dots. Defaults to `"current"`. */
  tone?: PulsingDotsTone;
  /** Test selector — caller controls so multiple instances stay distinct. */
  testId?: string;
}

export function PulsingDots({
  tone = "current",
  testId = "pulsing-dots",
}: PulsingDotsProps): JSX.Element {
  const dotColor = tone === "muted" ? "bg-r5e-muted" : "bg-current";
  const wrapperPadding = tone === "muted" ? "py-1" : "";
  const wrapperGap = tone === "muted" ? "gap-1" : "gap-0.5";
  return (
    <span
      aria-hidden="true"
      data-testid={testId}
      className={`inline-flex items-center ${wrapperGap} ${wrapperPadding}`.trim()}
    >
      <span
        className={`inline-block h-1.5 w-1.5 animate-pulse rounded-full ${dotColor} [animation-delay:0ms]`}
      />
      <span
        className={`inline-block h-1.5 w-1.5 animate-pulse rounded-full ${dotColor} [animation-delay:150ms]`}
      />
      <span
        className={`inline-block h-1.5 w-1.5 animate-pulse rounded-full ${dotColor} [animation-delay:300ms]`}
      />
    </span>
  );
}
