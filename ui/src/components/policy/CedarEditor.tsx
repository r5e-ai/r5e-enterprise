// CedarEditor — Monaco wrapper for Cedar policy authoring (T094 — Phase 5
// US3; T144 — Phase-9 polish: inline parse-error markers).
//
// Per `contracts/frontend_architecture.md` §"Folder layout" + research D1:
//   - Monaco is ~2MB gzipped; we keep it OUT of the main bundle by lazy-loading
//     the `@monaco-editor/react` package only when the PolicySimulator route
//     mounts. This component is the boundary: it imports Monaco statically,
//     and the parent (`PolicySimulator.tsx`) defers the dynamic import.
//   - Cedar grammar lives in `~/lib/cedar_monarch_grammar.ts`. We register it
//     once via the Monaco `beforeMount` hook so subsequent editor mounts
//     reuse the same language definition.
//   - The editor is controlled — the parent owns the source string. Save
//     wiring lives one level up (debounced PATCH from PolicySimulator).
//
// T144 (Phase-9 polish): when the user types, we debounce a `POST
// /v1/policy/simulate` validation request with the current source. If the
// server returns `cedar parse error: <message>`, we extract the line/col
// diagnostic from the error string and stamp a Monaco marker on the offending
// line so the user sees an inline red squiggle. The parse error does NOT
// block editing — the marker clears on the next successful validation.
//
// Validation is debounced 500ms after the last keystroke (Monaco emits one
// `onChange` per char). Inflight validation requests are cancelled via an
// `AbortController` when a newer request fires.
//
// This file IS in the lazy-loaded chunk (it imports `@monaco-editor/react`),
// so the page-level `React.lazy(() => import('./CedarEditorLazy'))` could pull
// it in directly. We expose a default export to keep the lazy import shape
// straightforward.

import MonacoEditor, { type Monaco } from "@monaco-editor/react";
import { useEffect, useRef } from "react";
import type { editor } from "monaco-editor";

import { apiPaths } from "~/lib/apiPaths";
import {
  CEDAR_LANGUAGE_ID,
  cedarLanguageConfiguration,
  cedarMonarchLanguage,
} from "~/lib/cedar_monarch_grammar";

interface Props {
  value: string;
  onChange: (next: string) => void;
  /** Read-only mode (used when previewing a deployed policy). */
  readOnly?: boolean;
  /** Optional fixed pixel height; defaults to a fluid 100% container fill. */
  height?: string | number;
  /**
   * Optional override for the Cedar parse-error validation endpoint. Defaults
   * to `/v1/policy/simulate`. Tests pass a stub URL.
   */
  validationEndpoint?: string;
  /** Optional debounce delay in ms; defaults to 500. */
  debounceMs?: number;
}

/**
 * Register Cedar with Monaco's language registry. Called once per Monaco
 * instance; subsequent mounts are no-ops because Monaco dedupes by language ID.
 */
function registerCedar(monaco: Monaco): void {
  const existing = monaco.languages
    .getLanguages()
    .find((l) => l.id === CEDAR_LANGUAGE_ID);
  if (existing) return;
  monaco.languages.register({ id: CEDAR_LANGUAGE_ID });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  monaco.languages.setMonarchTokensProvider(CEDAR_LANGUAGE_ID, cedarMonarchLanguage as any);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  monaco.languages.setLanguageConfiguration(CEDAR_LANGUAGE_ID, cedarLanguageConfiguration as any);
}

/**
 * Best-effort extraction of `(line, column)` from a Cedar parse-error string.
 * The Cedar NIF surfaces messages like
 *   "cedar parse error: parse error at line 3 column 12: unexpected token `a`"
 *
 * Falls back to `(1, 1)` if no match.
 */
function extractLineCol(message: string): { line: number; col: number } {
  const m = message.match(/line\s+(\d+)\s+column\s+(\d+)/i);
  if (m && m[1] !== undefined && m[2] !== undefined) {
    return { line: parseInt(m[1], 10), col: parseInt(m[2], 10) };
  }
  return { line: 1, col: 1 };
}

export default function CedarEditor({
  value,
  onChange,
  readOnly = false,
  height = "100%",
  validationEndpoint = apiPaths.policy.simulate,
  debounceMs = 500,
}: Props): JSX.Element {
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);
  const monacoRef = useRef<Monaco | null>(null);
  const debounceTimerRef = useRef<number | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Schedule a debounced validation request on every value change.
  // Cleanup the timer + abort the inflight request on unmount.
  useEffect(() => {
    if (readOnly) return;
    if (!editorRef.current || !monacoRef.current) return;
    if (!value) {
      clearMarkers();
      return;
    }

    if (debounceTimerRef.current !== null) {
      window.clearTimeout(debounceTimerRef.current);
    }

    debounceTimerRef.current = window.setTimeout(() => {
      void validateCedar(value);
    }, debounceMs);

    return () => {
      if (debounceTimerRef.current !== null) {
        window.clearTimeout(debounceTimerRef.current);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, readOnly, debounceMs]);

  useEffect(() => {
    return () => {
      // Final cleanup on unmount.
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      if (debounceTimerRef.current !== null) {
        window.clearTimeout(debounceTimerRef.current);
      }
    };
  }, []);

  function clearMarkers(): void {
    const monaco = monacoRef.current;
    const editor = editorRef.current;
    if (!monaco || !editor) return;
    const model = editor.getModel();
    if (!model) return;
    monaco.editor.setModelMarkers(model, "cedar-parse", []);
  }

  function setParseErrorMarker(message: string): void {
    const monaco = monacoRef.current;
    const editor = editorRef.current;
    if (!monaco || !editor) return;
    const model = editor.getModel();
    if (!model) return;

    const { line, col } = extractLineCol(message);
    const lineMaxCol = model.getLineMaxColumn(Math.min(line, model.getLineCount()));

    monaco.editor.setModelMarkers(model, "cedar-parse", [
      {
        severity: monaco.MarkerSeverity.Error,
        message,
        startLineNumber: line,
        startColumn: col,
        endLineNumber: line,
        endColumn: lineMaxCol,
      },
    ]);
  }

  async function validateCedar(source: string): Promise<void> {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const ctrl = new AbortController();
    abortControllerRef.current = ctrl;

    try {
      const resp = await fetch(validationEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          cedar_source: source,
          // Synthetic minimal request — we only care about the parse step.
          principal: { kind: "obo_human", id: "validation@local" },
          action: 'Recurse::Action::"DashboardQuery"',
          resource: { kind: "Recurse::Resource::ConsoleSurface", id: "validation" },
          context: {},
        }),
        signal: ctrl.signal,
      });

      if (resp.ok) {
        // 200 means parse OK (decision computed). Clear any prior markers.
        clearMarkers();
        return;
      }

      // 400 with body { error: { message: "cedar parse error: ..." } } per
      // the F001 envelope.
      const body = await resp.json().catch(() => null);
      const msg: string | undefined =
        body?.error?.message ?? body?.error_description ?? body?.message;

      if (typeof msg === "string" && msg.toLowerCase().includes("cedar parse error")) {
        setParseErrorMarker(msg);
      } else {
        // Non-parse errors (auth, rate-limit, etc.) — clear markers; the
        // parent surfaces those via the network-error path.
        clearMarkers();
      }
    } catch (err) {
      // Aborted (newer keystroke) or network — leave markers alone.
      if ((err as Error)?.name === "AbortError") return;
      // Otherwise silently swallow; the editor remains usable.
    }
  }

  return (
    <div
      data-testid="cedar-editor"
      className="h-full min-h-[280px] overflow-hidden rounded border border-r5e-border bg-r5e-bg"
    >
      <MonacoEditor
        value={value}
        onChange={(next) => onChange(next ?? "")}
        beforeMount={registerCedar}
        onMount={(editor, monaco) => {
          editorRef.current = editor;
          monacoRef.current = monaco;
          // Signal the surrounding `<CedarEditorBoundary>` that Monaco
          // initialized successfully. The boundary uses this to cancel
          // its loader-timeout and avoid surfacing the textarea
          // fallback. See `CedarEditorBoundary.tsx` for the rationale.
          if (typeof window !== "undefined" && typeof window.dispatchEvent === "function") {
            window.dispatchEvent(new Event("cedar-editor-mounted"));
          }
        }}
        language={CEDAR_LANGUAGE_ID}
        theme="vs-dark"
        height={height}
        options={{
          readOnly,
          minimap: { enabled: false },
          fontFamily: "'JetBrains Mono', ui-monospace, monospace",
          fontSize: 12,
          lineNumbers: "on",
          scrollBeyondLastLine: false,
          tabSize: 2,
          automaticLayout: true,
          renderLineHighlight: "gutter",
          wordWrap: "on",
          fixedOverflowWidgets: true,
        }}
      />
    </div>
  );
}
