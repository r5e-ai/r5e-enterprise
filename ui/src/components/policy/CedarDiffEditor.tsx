// CedarDiffEditor — Monaco DiffEditor wrapper for the Replay-mode "Compare
// with deployed" toggle (T141 — Phase 8 US6).
//
// Per research D1: Monaco DiffEditor adds a few hundred KB on top of the
// regular editor — we keep it in its OWN lazy chunk so the Simulate / Draft
// tabs don't pay for it until the operator actually flips the compare toggle
// in Replay mode.
//
// The original (left) side is read-only — that's the deployed bundle excerpt
// returned in the replay response. The modified (right) side is editable and
// the parent debounces its `onChange` to re-fire the replay with
// `override_cedar_source` per audit_api_extensions.md POST /v1/policy/replay.

import { DiffEditor, type Monaco } from "@monaco-editor/react";

import {
  CEDAR_LANGUAGE_ID,
  cedarLanguageConfiguration,
  cedarMonarchLanguage,
} from "~/lib/cedar_monarch_grammar";

interface Props {
  /** Deployed Cedar bundle excerpt (left side, read-only). */
  original: string;
  /** Editable override the operator types into (right side). */
  modified: string;
  onModifiedChange: (next: string) => void;
  height?: string | number;
}

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

export default function CedarDiffEditor({
  original,
  modified,
  onModifiedChange,
  height = "100%",
}: Props): JSX.Element {
  return (
    <div
      data-testid="cedar-diff-editor"
      className="h-full min-h-[280px] overflow-hidden rounded border border-r5e-border bg-r5e-bg"
    >
      <DiffEditor
        original={original}
        modified={modified}
        beforeMount={registerCedar}
        language={CEDAR_LANGUAGE_ID}
        theme="vs-dark"
        height={height}
        onMount={(editor) => {
          // Wire onChange off the modified-model so the parent can debounce
          // re-fire of the replay request.
          const modifiedEditor = editor.getModifiedEditor();
          modifiedEditor.onDidChangeModelContent(() => {
            onModifiedChange(modifiedEditor.getValue());
          });
        }}
        options={{
          readOnly: false,
          originalEditable: false,
          renderSideBySide: true,
          minimap: { enabled: false },
          fontFamily: "'JetBrains Mono', ui-monospace, monospace",
          fontSize: 12,
          lineNumbers: "on",
          scrollBeyondLastLine: false,
          automaticLayout: true,
          renderLineHighlight: "gutter",
          wordWrap: "on",
          fixedOverflowWidgets: true,
        }}
      />
    </div>
  );
}
