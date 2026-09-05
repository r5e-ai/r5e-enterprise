// CommandCell — the COMMAND column. Renders `tags.verb` as compact mono
// text. Per Pencil's `comp/receipts-table-v2` design (.pen `kPFqb`):
//
//   - Plain mono text (no pill chrome) so a row reads as a sentence:
//     `[Bash]  rm  -rf /tmp/build`.
//   - Destructive verbs (`rm`, `sudo`, `chmod`, `chown`, `kill`, `shutdown`)
//     render in `text-r5e-warning` to draw the eye.
//   - Denial rows render in `text-r5e-danger` (Rule 01 — deny trumps).
//   - Truncation handled by the parent cell's width class; tooltip shows
//     the full verb (rare to overflow, but defensive for unusual shapes).

import type { ReceiptTags } from "~/lib/tags";

const DESTRUCTIVE_VERBS: ReadonlySet<string> = new Set([
  "rm",
  "rmdir",
  "sudo",
  "chmod",
  "chown",
  "kill",
  "killall",
  "shutdown",
  "reboot",
  "dd",
  "mkfs",
  "fdisk",
]);

interface Props {
  tags: ReceiptTags | null;
  /** True iff `outer_container.policy_decision === "deny"`. */
  forceDenial?: boolean;
}

export function CommandCell({ tags, forceDenial = false }: Props): JSX.Element {
  const verb = tags?.verb ?? null;

  if (!verb) {
    return <span aria-hidden="true">&nbsp;</span>;
  }

  // Brief reserves chart-denied for accent surfaces (pill bg/border in
  // ToolCell). Inline text on denial rows uses the semantic `r5e-danger`
  // token. Same red palette today; semantically distinct.
  const tone = forceDenial
    ? "text-r5e-danger"
    : DESTRUCTIVE_VERBS.has(verb)
      ? "text-r5e-warning"
      : "text-r5e-text";

  return (
    <span
      data-testid="command-text"
      data-verb={verb}
      title={verb}
      className={`truncate font-mono text-xs ${tone}`}
    >
      {verb}
    </span>
  );
}
