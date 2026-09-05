// Tailwind-token guardrail.
//
// Fails CI on any literal class string in `ui/src/**/*.{ts,tsx}` that
// references a token NOT present in the codegen'd `tailwind.config.ts`.
//
// ## Why this exists
//
// Tailwind 3 JIT only emits CSS for class strings it scans literally. If a
// component string-concatenates a non-existent token name (e.g.
// `text-r5e-chart-agent-dispatch` when only `text-r5e-chart-agent` exists),
// JIT silently drops it. The component renders unstyled — no compile error,
// no runtime error, no warning. The bug was caught by the GAN review of
// MR !86 (F001 BLOCKER): `ToolCell.tsx` invented 6 imaginary token names
// (`chart-agent-dispatch`, `chart-network-egress`, `chart-llm-call`,
// `chart-file-search`, `chart-todo-management`, `chart-ui-event`) — 6 of
// 11 tool_kind branches rendered with no color/bg/border. Visual
// verification only happened to exercise the 5 token names that DID
// resolve, masking the rest.
//
// ## What this test does
//
// 1. Reads `tailwind.config.ts` and extracts every color token name under
//    `theme.extend.colors`.
// 2. Globs `src/**/*.{ts,tsx}` and reads each file as text.
// 3. Greps for every class-string usage of `r5e-` tokens via the regex
//    `\b(text|bg|border|from|to|via|fill|stroke|ring|shadow|outline|caret|accent|decoration|placeholder|divide)-r5e-([a-z][a-z0-9-]*)` (the Tailwind utility prefixes
//    that ALL accept color tokens; expand this list if a new prefix is
//    introduced).
// 4. Asserts every referenced token is present in the config's color set.
//
// ## What this test does NOT catch
//
// - Tokens used via template interpolation (e.g. `text-r5e-${suffix}`) — JIT
//   wouldn't pick those up either, but our regex requires literal text after
//   the prefix, so we'll miss them in this test. Don't write those; this test
//   intentionally enforces "literal class strings only" by missing dynamic
//   ones.
// - Non-color utility classes (e.g. `rounded-r5e-md` for radii) — they use a
//   different token namespace which this test currently doesn't validate.
//   File a follow-up if a future bug class motivates extending coverage.
//
// ## When this test fails
//
// Either (a) the token is genuinely missing from
// `ui/design-tokens.json` — add it there and run
// `pnpm gen:tailwind`; or (b) the class string typo'd a real token name —
// fix the call site to match the canonical spelling. Don't suppress this
// test.

import { promises as fs } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(__dirname, "..", "..", "..");
const tailwindConfigPath = path.join(repoRoot, "tailwind.config.ts");
const srcDir = path.join(repoRoot, "src");

/**
 * Tailwind utility prefixes that consume a color token. New prefix? add
 * it here. Order doesn't matter; we use this in a regex alternation.
 */
const COLOR_UTILITY_PREFIXES = [
  "text",
  "bg",
  "border",
  "from",
  "to",
  "via",
  "fill",
  "stroke",
  "ring",
  "shadow",
  "outline",
  "caret",
  "accent",
  "decoration",
  "placeholder",
  "divide",
] as const;

// Token name must START with a letter and END with a letter or digit
// (intermediate hyphens allowed but never trailing). This prevents the
// regex from greedily capturing partial tokens from documentation strings
// like `text-r5e-chart-...` (where the trailing dot is a literary
// ellipsis, not a token suffix).
const TOKEN_RE = new RegExp(
  `\\b(?:${COLOR_UTILITY_PREFIXES.join("|")})-(r5e(?:-[a-z][a-z0-9]*)+)\\b`,
  "g",
);

/**
 * Walk `dir` recursively, returning absolute paths to every `.ts`/`.tsx`
 * file (excluding tests + vendor).
 */
async function walk(dir: string, out: string[] = []): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      // Skip our own tests dir + node_modules + dist
      if (
        entry.name === "tests" ||
        entry.name === "node_modules" ||
        entry.name === "dist" ||
        entry.name === ".vite"
      ) {
        continue;
      }
      await walk(full, out);
    } else if (entry.isFile() && /\.(ts|tsx)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Extract the canonical token name set from `tailwind.config.ts`. We
 * parse the file as text rather than importing it because the test runs
 * under jsdom and the config is a plain object literal — extracting the
 * `"r5e-..."` keys with a single regex is faster + more robust than
 * dynamic import shenanigans.
 */
async function readConfiguredTokens(): Promise<Set<string>> {
  const text = await fs.readFile(tailwindConfigPath, "utf8");
  const tokens = new Set<string>();
  // Match `"r5e-something": "#hex"` lines under the colors block. The
  // codegen indents with tabs/spaces; key always quoted; value always a
  // 6-digit hex (or 8 for alpha — both fine).
  const lineRe = /"(r5e-[a-z][a-z0-9-]*)"\s*:\s*"#[0-9a-fA-F]+"/g;
  let m: RegExpExecArray | null;
  while ((m = lineRe.exec(text)) !== null) {
    tokens.add(m[1]!);
  }
  return tokens;
}

describe("tailwind tokens — every literal r5e-* class must resolve to a real token", () => {
  it("every literal class string references a token defined in tailwind.config.ts", async () => {
    const configured = await readConfiguredTokens();
    expect(configured.size).toBeGreaterThan(0);

    const files = await walk(srcDir);
    expect(files.length).toBeGreaterThan(0);

    type Violation = {
      file: string;
      token: string;
      lineNumber: number;
      lineText: string;
    };
    const violations: Violation[] = [];

    for (const file of files) {
      const text = await fs.readFile(file, "utf8");
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        // Skip comment lines — JSDoc and inline comments often reference
        // illustrative class strings like `text-r5e-chart-...` with literary
        // ellipses, which the regex would otherwise interpret as malformed
        // tokens. This is a heuristic; it can miss tokens that legitimately
        // appear in comments AND violate the rule (vanishingly rare). The
        // tradeoff favors low-noise CI over completeness.
        const stripped = line.trim();
        if (
          stripped.startsWith("*") ||
          stripped.startsWith("//") ||
          stripped.startsWith("/*")
        ) {
          continue;
        }
        for (const match of line.matchAll(TOKEN_RE)) {
          const token = match[1]!;
          if (!configured.has(token)) {
            violations.push({
              file: path.relative(repoRoot, file),
              token,
              lineNumber: i + 1,
              lineText: stripped,
            });
          }
        }
      }
    }

    if (violations.length > 0) {
      const message = [
        `${violations.length} literal Tailwind class string(s) reference undefined token(s):`,
        "",
        ...violations.map(
          (v) =>
            `  ${v.file}:${v.lineNumber}  →  ${v.token}\n      ${v.lineText}`,
        ),
        "",
        "Each token must exist in ui/design-tokens.json.",
        "After editing tokens.json, run `pnpm gen:tailwind` to regenerate",
        "ui/tailwind.config.ts. Tailwind 3 JIT silently drops classes whose",
        "tokens it can't resolve, so the component renders unstyled in",
        "production with no compile-time or runtime error.",
      ].join("\n");
      throw new Error(message);
    }
  });

  it("config and token-source file are in sync (gen:tailwind hasn't drifted)", async () => {
    const configured = await readConfiguredTokens();
    const tokensJson = JSON.parse(
      await fs.readFile(
        path.join(repoRoot, "design-tokens.json"),
        "utf8",
      ),
    ) as { colors: Record<string, string> };

    const sourceTokens = new Set(Object.keys(tokensJson.colors));

    // Sets must match. If they don't, someone hand-edited tailwind.config.ts
    // (forbidden — file header says GENERATED) OR forgot to run gen:tailwind
    // after editing tokens.json.
    const missingFromConfig = [...sourceTokens].filter((t) => !configured.has(t));
    const extraInConfig = [...configured].filter((t) => !sourceTokens.has(t));

    expect(missingFromConfig, "tokens in tokens.json missing from tailwind.config.ts (run pnpm gen:tailwind)").toEqual([]);
    expect(extraInConfig, "tokens in tailwind.config.ts not in tokens.json (someone hand-edited the generated file)").toEqual([]);
  });
});
