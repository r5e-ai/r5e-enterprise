// Shared string helpers — extracted per Constitution Principle VII
// (Interface-First on Second Consumer).
//
// Both `slug()` and `truncate()` had grown private duplicates across the
// chat, sidebar, and audit surfaces. The MR !93 fix-pass-2 GAN review
// flagged them as canonical examples of the pattern Principle VII forbids:
// the second consumer should extract; later consumers re-use.
//
// Tests: `ui/src/tests/unit/strings.test.ts`.

/**
 * Slugify a label for use as a stable id / data-testid suffix.
 *
 * Behavior:
 *   - lowercase
 *   - replace any run of non-alphanumerics with a single `-`
 *   - strip leading and trailing `-`
 *   - optionally cap to `maxLength` characters (default: no cap)
 *
 * The pre-extraction Sidebar version was un-capped; the chat suggestion
 * card version was capped at 40 chars to keep selectors readable. Both
 * call sites now read the cap via the optional second argument. Passing
 * `undefined` reproduces the un-capped Sidebar behavior exactly.
 *
 * @example
 * slug("Show me all denials in the last hour.") // "show-me-all-denials-in-the-last-hour"
 * slug("Why was Alice's last bash_exec denied?", 40) // "why-was-alice-s-last-bash-exec-denied"
 */
export function slug(label: string, maxLength?: number): string {
  const base = label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
  if (typeof maxLength === "number" && maxLength > 0 && base.length > maxLength) {
    // Trim a trailing dash that may appear after slicing mid-run.
    return base.slice(0, maxLength).replace(/-$/, "");
  }
  return base;
}

/**
 * Truncate `text` to at most `maxChars` characters, appending an ellipsis
 * (`…`) when truncation occurs. Trailing whitespace before the ellipsis is
 * trimmed so we don't render `"foo …"`.
 *
 * Pre-extraction shapes:
 *   - TagsSection used `s.slice(0, max - 1) + "…"` (no trim).
 *   - ChatPage history-row dropdown used the same shape with a default of 60
 *     and an explicit `.trimEnd()` before the ellipsis.
 *
 * Both call sites are fine with always-trim (the TagsSection inputs are
 * tag values like `policy:bash-exec`, which don't have trailing whitespace,
 * so the trim is a no-op there). The trim is therefore unconditional.
 *
 * @example
 * truncate("hello world", 5)        // "hell…"
 * truncate("short", 10)              // "short"
 * truncate("Why was Alice's", 60)    // "Why was Alice's"
 */
export function truncate(text: string, maxChars = 60): string {
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars - 1).trimEnd()}…`;
}
