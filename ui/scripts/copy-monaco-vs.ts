// copy-monaco-vs.ts — sync `node_modules/monaco-editor/min/vs/` into
// `ui/public/vs/` so Vite ships it as a same-origin static asset under
// `/admin/vs/*` (B6 fix: see lib/configureMonacoLoader.ts).
//
// Runs as `predev` and `prebuild` from package.json so dev + production
// builds always have the local Monaco bundle in place. Idempotent: if the
// destination already exists with the right monaco version we skip the
// copy (cheap re-run on every `pnpm dev` start).
//
// We deliberately copy ONLY `monaco-editor/min/vs/` — that's the runtime
// AMD bundle the loader needs at request time. The rest of monaco-editor
// (~500MB of language-server source, dev sources, monaco-editor-core,
// d.ts, etc.) is irrelevant at runtime; shipping it would bloat the
// `priv/static/admin/` directory inside the BEAM release artifact.
//
// `ui/public/vs/` is gitignored (regenerated artifact); the canonical
// source is `node_modules/monaco-editor`.

import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { cp } from "node:fs/promises";
import { join, resolve } from "node:path";

// Resolve from the ui/ project root, regardless of cwd.
const UI_ROOT = resolve(import.meta.dirname, "..");
const MONACO_PKG_JSON = join(
  UI_ROOT,
  "node_modules",
  "monaco-editor",
  "package.json",
);
const MONACO_VS_SRC = join(UI_ROOT, "node_modules", "monaco-editor", "min", "vs");
const PUBLIC_DIR = join(UI_ROOT, "public");
const PUBLIC_VS_DEST = join(PUBLIC_DIR, "vs");
const VERSION_STAMP = join(PUBLIC_VS_DEST, ".monaco-version");

interface MonacoPkgJson {
  version: string;
}

function readMonacoVersion(): string {
  if (!existsSync(MONACO_PKG_JSON)) {
    throw new Error(
      `monaco-editor not installed at ${MONACO_PKG_JSON}. Run 'pnpm install' first.`,
    );
  }
  const pkg = JSON.parse(readFileSync(MONACO_PKG_JSON, "utf8")) as MonacoPkgJson;
  if (!pkg.version) {
    throw new Error(
      `monaco-editor package.json at ${MONACO_PKG_JSON} has no 'version' field`,
    );
  }
  return pkg.version;
}

function readStampedVersion(): string | null {
  if (!existsSync(VERSION_STAMP)) return null;
  try {
    return readFileSync(VERSION_STAMP, "utf8").trim();
  } catch {
    return null;
  }
}

async function main(): Promise<void> {
  if (!existsSync(MONACO_VS_SRC) || !statSync(MONACO_VS_SRC).isDirectory()) {
    throw new Error(
      `monaco-editor min/vs not found at ${MONACO_VS_SRC}. ` +
        "Run 'pnpm install' to fetch it.",
    );
  }

  const installedVersion = readMonacoVersion();
  const stampedVersion = readStampedVersion();

  if (stampedVersion === installedVersion && existsSync(PUBLIC_VS_DEST)) {
    // Up-to-date — skip the copy.
    console.log(
      `[copy-monaco-vs] public/vs already at monaco-editor@${installedVersion}; skipping.`,
    );
    return;
  }

  // Wipe and recopy so we never accumulate stale files from a prior
  // monaco-editor version bump.
  if (existsSync(PUBLIC_VS_DEST)) {
    rmSync(PUBLIC_VS_DEST, { recursive: true, force: true });
  }
  mkdirSync(PUBLIC_DIR, { recursive: true });

  console.log(
    `[copy-monaco-vs] copying monaco-editor@${installedVersion} min/vs/ -> public/vs/`,
  );
  await cp(MONACO_VS_SRC, PUBLIC_VS_DEST, { recursive: true });

  // Stamp the version so the next run can short-circuit.
  await import("node:fs/promises").then((fs) =>
    fs.writeFile(VERSION_STAMP, installedVersion, "utf8"),
  );

  console.log(`[copy-monaco-vs] done.`);
}

main().catch((err) => {
  console.error("[copy-monaco-vs] FAILED:", err);
  process.exit(1);
});
