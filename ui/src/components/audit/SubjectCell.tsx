// SubjectCell — the SUBJECT column. Renders `tags.argument_body` as
// compact mono text with a hover/focus copy-to-clipboard affordance. Per
// Pencil's `comp/receipts-table-v2` design (.pen `kPFqb`) +
// `design/briefs/02-dashboard-table.md` SUBJECT column rules:
//
//   - Mono text (file paths, URLs, JSON, command flags) — read as a
//     sentence with the preceding [Tool][Command] cells.
//   - Truncate with ellipsis to fit the cell; tooltip shows the full
//     value (the parent applies `truncate` via its width-class).
//   - Denial rows render in `text-r5e-danger` (Rule 01 — deny trumps);
//     `chart-denied` is reserved for accent surfaces (pill bg/border).
//   - Empty when `argument_body` is null (some tools — TodoWrite, plain
//     LLM completion — have no meaningful subject string).
//   - Hover/focus reveals a click-to-copy icon button at the right of
//     the cell (brief: "the auditor's primary path to grab a file path /
//     URL / arg blob out of a row without opening the drawer"). Stops
//     propagation so the row's onOpen doesn't fire.
//
// ## CONSTITUTIONAL TODO — Principle IV / issue #66
//
// This cell renders `tags.argument_body` directly off the receipt row.
// `tags` is `outer_container.tags` and is part of the IMMUTABLE LEDGER
// record. The Constitution (.specify/memory/constitution.md, Principle
// IV — NON-NEGOTIABLE) says the ledger MUST NEVER store raw prompts,
// model responses, tool arguments, or PII — only their SHA-256 hashes.
// Rendering `argument_body` from the ledger normalizes a contract
// drift: command flags, file paths, URLs, and MCP JSON input arrive
// verbatim in the ledger.
//
// This was caught by GAN review of MR !86 (finding F002 — BLOCKER).
// The decision to defer is documented:
//
//   - **Demo (May 10 2026)**: ships !86 as-is. Mock data has no real
//     PII; the constitutional drift is contained.
//   - **Pre-production**: must convert this cell to a fetch-on-click
//     affordance per FR-019 (`:ui_payload_access` audit-eventing) — the
//     ledger stores `argument_body_sha256` only, the bytes live in the
//     detached payload broker, the operator's read is auditable.
//
// Tracked at https://gitlab.com/r5e-group/r5e-enterprise/-/work_items/66
// (full broker-residency vertical-slice spec; labeled `must-pre-production`).
// DO NOT change the rendering logic here without retiring issue #66's
// scope first — the demo path depends on this read shape.

import { Check, Copy } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type MouseEvent } from "react";

import type { ReceiptTags } from "~/lib/tags";

interface Props {
  tags: ReceiptTags | null;
  /** True iff `outer_container.policy_decision === "deny"`. */
  forceDenial?: boolean;
}

export function SubjectCell({ tags, forceDenial = false }: Props): JSX.Element {
  const subject = tags?.argument_body ?? null;
  const [copied, setCopied] = useState(false);
  const resetTimer = useRef<number | null>(null);

  // Clear the "copied" indicator 1.5s after the click. Cleaning up on
  // unmount prevents the setTimeout from firing into a stale component
  // (e.g. when the parent virtualized row scrolls out of view).
  useEffect(() => {
    return () => {
      if (resetTimer.current !== null) {
        window.clearTimeout(resetTimer.current);
      }
    };
  }, []);

  const onCopy = useCallback(
    async (event: MouseEvent<HTMLButtonElement>) => {
      event.stopPropagation(); // don't trigger row.onOpen
      event.preventDefault();
      if (!subject) return;
      try {
        await navigator.clipboard.writeText(subject);
        setCopied(true);
        if (resetTimer.current !== null) {
          window.clearTimeout(resetTimer.current);
        }
        resetTimer.current = window.setTimeout(() => setCopied(false), 1500);
      } catch {
        // navigator.clipboard.writeText can reject in jsdom or in non-
        // HTTPS test environments. Silently swallow — the affordance is
        // best-effort and the user still has the title-tooltip fallback.
      }
    },
    [subject],
  );

  if (!subject) {
    return <span aria-hidden="true">&nbsp;</span>;
  }

  const tone = forceDenial ? "text-r5e-danger" : "text-r5e-text";

  return (
    <span
      // `group/subject` lets the copy button reveal on group-hover without
      // colliding with parent group-named hover states elsewhere.
      className="group/subject relative flex items-center gap-1"
    >
      <span
        data-testid="subject-text"
        title={subject}
        className={`block truncate font-mono text-xs ${tone}`}
      >
        {subject}
      </span>
      <button
        type="button"
        aria-label={copied ? "Copied to clipboard" : `Copy subject: ${subject}`}
        data-testid="subject-copy"
        onClick={onCopy}
        onMouseDown={(e) => e.stopPropagation()}
        // Hidden by default; visible on group hover OR when the button
        // itself is focused (keyboard discoverability per the brief).
        className="shrink-0 rounded p-0.5 text-r5e-muted opacity-0 transition-opacity hover:bg-r5e-border/40 hover:text-r5e-text focus:opacity-100 focus:outline-none focus:ring-1 focus:ring-r5e-accent-glow group-hover/subject:opacity-100"
      >
        {copied ? (
          <Check size={12} aria-hidden="true" data-testid="subject-copy-success" />
        ) : (
          <Copy size={12} aria-hidden="true" />
        )}
      </button>
      {/* aria-live region announces copy success for SR users. */}
      <span aria-live="polite" className="sr-only">
        {copied ? "Copied to clipboard" : ""}
      </span>
    </span>
  );
}
