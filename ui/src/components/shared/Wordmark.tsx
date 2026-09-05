// Wordmark — reusable brand mark for the Audit Console.
//
// Per `design/briefs/08-login.md` (F8) the wordmark is a three-part inline
// horizontal mark — sparkle + "r5e" + "ENTERPRISE" eyebrow — used in two
// places:
//
//   1. Centered above the H1 on the unauthenticated `/admin/login` card.
//   2. The top-left chrome of the global `Sidebar` on every authenticated
//      route.
//
// Pulling it into a component keeps both surfaces typographically aligned
// and lets future surfaces (e.g. an Export-Evidence cover sheet, an OAuth
// consent screen) reference the same mark without redrawing it. Per
// Constitution Principle VII (Interface-First on Second Consumer), the
// second consumer (Sidebar) extracts the helper rather than re-inlining
// the markup.
//
// Visual spec from the brief (dark theme):
//   ✦  r5e  ENTERPRISE
//
//   - `✦` (Lucide `Sparkles`) in `text-r5e-accent`, slightly larger than
//     the body of the mark.
//   - `r5e` lowercase, `font-semibold`, `text-r5e-text` (white-ish).
//   - `ENTERPRISE` mono caps eyebrow, `text-r5e-muted`, smaller +
//     letter-spaced — the same caps-eyebrow treatment used elsewhere in
//     the console (per `01-shared-systems.md` typography).
//
// `size` lets callers choose between the larger Login presentation
// (`md`, default) and the more compact Sidebar header (`sm`).

import { Sparkles } from "lucide-react";

export interface WordmarkProps {
  /**
   * Visual size preset. `md` is the larger Login-card presentation;
   * `sm` is the compact Sidebar-header presentation.
   */
  size?: "sm" | "md";
  /**
   * Optional className override applied to the outer wrapper. Use sparingly
   * — alignment + spacing internal to the wordmark are owned by this
   * component.
   */
  className?: string;
}

const SIZE_CLASSES: Record<NonNullable<WordmarkProps["size"]>, {
  wrapper: string;
  sparkle: string;
  r5e: string;
  eyebrow: string;
}> = {
  sm: {
    wrapper: "gap-1.5",
    sparkle: "h-3.5 w-3.5",
    r5e: "text-[13px]",
    eyebrow: "text-[10px] tracking-[0.1em]",
  },
  md: {
    wrapper: "gap-2",
    sparkle: "h-5 w-5",
    r5e: "text-lg",
    eyebrow: "text-[11px] tracking-[0.1em]",
  },
};

export function Wordmark({
  size = "md",
  className,
}: WordmarkProps): JSX.Element {
  const cls = SIZE_CLASSES[size];
  const wrapperClasses = [
    "inline-flex items-center font-sans",
    cls.wrapper,
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <span
      data-testid="wordmark"
      data-wordmark-size={size}
      className={wrapperClasses}
      aria-label="r5e enterprise"
    >
      <Sparkles
        aria-hidden="true"
        className={`${cls.sparkle} shrink-0 text-r5e-accent`}
      />
      <span className={`font-semibold lowercase text-r5e-text ${cls.r5e}`}>
        r5e
      </span>
      <span
        className={`font-mono font-semibold uppercase text-r5e-muted ${cls.eyebrow}`}
      >
        Enterprise
      </span>
    </span>
  );
}

export default Wordmark;
