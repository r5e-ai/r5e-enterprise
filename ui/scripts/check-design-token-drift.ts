import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../..");
const penPath = path.join(repoRoot, "design/r5e-enterprise-audit-ui.pen");
const tokensPath = path.join(repoRoot, "ui/design-tokens.json");

type PenVariable =
  | { type: "color"; value: string | Array<{ value: string }> }
  | { type: "number"; value: number }
  | { type: string; value: unknown };

type PenFile = {
  variables?: Record<string, PenVariable>;
};

type DesignTokens = {
  colors?: Record<string, string>;
  radii?: Record<string, string>;
};

type Violation = {
  key: string;
  expected: string;
  actual: string | null;
};

function normalizeHex(value: string): string {
  return value.trim().toUpperCase();
}

function firstColorValue(value: PenVariable["value"]): string | null {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value[0]?.value ?? null;
  return null;
}

function readJson<T>(file: string): T {
  return JSON.parse(readFileSync(file, "utf8")) as T;
}

function main(): void {
  if (!existsSync(penPath)) {
    // The .pen source is not part of the public tree; there
    // ui/design-tokens.json is the canonical token set and there is
    // nothing to drift from.
    console.log(
      `[check:tokens] no ${path.relative(repoRoot, penPath)} in this tree; ui/design-tokens.json is canonical here`,
    );
    return;
  }
  const pen = readJson<PenFile>(penPath);
  const tokens = readJson<DesignTokens>(tokensPath);
  const variables = pen.variables ?? {};
  const colors = tokens.colors ?? {};
  const radii = tokens.radii ?? {};
  const violations: Violation[] = [];

  for (const [name, variable] of Object.entries(variables)) {
    if (variable.type === "color") {
      const color = firstColorValue(variable.value);
      if (!color) continue;

      const tokenName = `r5e-${name}`;
      const actual = colors[tokenName] ?? null;
      const expected = normalizeHex(color);

      if (actual === null || normalizeHex(actual) !== expected) {
        violations.push({
          key: tokenName,
          expected,
          actual,
        });
      }
    }

    if (variable.type === "number" && name.startsWith("rounded-")) {
      const tokenName = `r5e-${name.replace(/^rounded-/, "")}`;
      const expected = `${variable.value}px`;
      const actual = radii[tokenName] ?? null;

      if (actual !== expected) {
        violations.push({
          key: `radii.${tokenName}`,
          expected,
          actual,
        });
      }
    }
  }

  if (violations.length === 0) {
    console.log("[check:tokens] tokens.json matches canonical .pen variables");
    return;
  }

  const message = [
    `${violations.length} design token(s) drifted from ${path.relative(repoRoot, penPath)}:`,
    "",
    ...violations.map(
      (v) => `  ${v.key}: expected ${v.expected}, got ${v.actual ?? "<missing>"}`,
    ),
    "",
    "Update ui/design-tokens.json from the canonical Pencil variables",
    "and run `pnpm gen:tailwind`.",
  ].join("\n");

  throw new Error(message);
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}
