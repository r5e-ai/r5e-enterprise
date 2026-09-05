import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const uiRoot = path.resolve(__dirname, "..");
const srcRoot = path.join(uiRoot, "src");
const componentsRoot = path.join(srcRoot, "components");

const SOURCE_EXT_RE = /\.(ts|tsx)$/;
const EXPORTED_COMPONENT_RE =
  /^\s*export\s+(?:function|const)\s+([A-Z][A-Za-z0-9_]*)\b/;
const LOCAL_FUNCTION_RE = /^\s*function\s+([A-Z][A-Za-z0-9_]*)\b/;
const LOCAL_CONST_RE =
  /^\s*const\s+([A-Z][A-Za-z0-9_]*)\s*=\s*(?:\([^)]*\)|[A-Za-z0-9_$]+)\s*=>/;

type Violation = {
  file: string;
  lineNumber: number;
  name: string;
  exportedFrom: string;
  lineText: string;
};

async function walk(dir: string, out: string[] = []): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (
        entry.name === "node_modules" ||
        entry.name === "dist" ||
        entry.name === ".vite" ||
        entry.name === "tests"
      ) {
        continue;
      }
      await walk(full, out);
    } else if (entry.isFile() && SOURCE_EXT_RE.test(entry.name)) {
      out.push(full);
    }
  }

  return out;
}

async function exportedComponentNames(): Promise<Map<string, string>> {
  const names = new Map<string, string>();

  for (const file of await walk(componentsRoot)) {
    const text = await fs.readFile(file, "utf8");
    for (const line of text.split(/\r?\n/)) {
      const match = EXPORTED_COMPONENT_RE.exec(line);
      if (match) {
        names.set(match[1]!, path.relative(uiRoot, file));
      }
    }
  }

  return names;
}

function localComponentName(line: string): string | null {
  return LOCAL_FUNCTION_RE.exec(line)?.[1] ?? LOCAL_CONST_RE.exec(line)?.[1] ?? null;
}

async function main(): Promise<void> {
  const exported = await exportedComponentNames();
  const violations: Violation[] = [];

  for (const file of await walk(srcRoot)) {
    const text = await fs.readFile(file, "utf8");
    const lines = text.split(/\r?\n/);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index]!;
      if (EXPORTED_COMPONENT_RE.test(line)) continue;

      const name = localComponentName(line);
      if (!name) continue;

      const exportedFrom = exported.get(name);
      if (!exportedFrom) continue;

      violations.push({
        file: path.relative(uiRoot, file),
        lineNumber: index + 1,
        name,
        exportedFrom,
        lineText: line.trim(),
      });
    }
  }

  if (violations.length === 0) {
    console.log("[check:component-shadows] no inline component shadows found");
    return;
  }

  const message = [
    `${violations.length} local component declaration(s) shadow exported components:`,
    "",
    ...violations.map(
      (v) =>
        `  ${v.file}:${v.lineNumber} ${v.name} shadows ${v.exportedFrom}\n      ${v.lineText}`,
    ),
    "",
    "Rename the local helper or use the exported component. Shadowed names have already caused",
    "receipt-drawer regressions where tests imported the shared component but production rendered",
    "a page-local duplicate.",
  ].join("\n");

  throw new Error(message);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
