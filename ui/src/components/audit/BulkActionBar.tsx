// BulkActionBar — the toolbar that appears when ≥1 audit-log row is
// selected (T065 FR-015).
//
// Per spec.md "Out of Scope" addendum + tasks.md T065:
//   - Shows three real actions in F004:
//       (1) Open in detail (opens the first-selected row's drawer).
//       (2) Create policy rule from selection (routes to Policy Simulator
//           with `mode=draft-from-receipt&run_ids=...`).
//       (3) Export evidence for selection (POSTs the F002
//           `/v1/audit/export-evidence` endpoint with the run_id list).
//   - Visibility honors role: `tenant_auditor` sees Open + Export;
//     `platform_operator` sees all three real actions.
//   - The "Tag" affordance is rendered DISABLED with a Phase-2 tooltip
//     for visual parity with the pen-file design; clicking it is a no-op.
//   - Bar is sticky at the bottom of the viewport when visible (z-20).

import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { api, ApiError } from "~/lib/api";
import { routes, stripBasename } from "~/lib/routes";

interface Props {
  selectedRunIds: string[];
  role: "tenant_auditor" | "platform_operator";
  onClearSelection: () => void;
  onOpenDetail: (runId: string) => void;
}

type ExportStatus = "idle" | "in-flight" | "ok" | "error";

export function BulkActionBar({
  selectedRunIds,
  role,
  onClearSelection,
  onOpenDetail,
}: Props): JSX.Element | null {
  const navigate = useNavigate();
  const [exportStatus, setExportStatus] = useState<ExportStatus>("idle");
  const [exportError, setExportError] = useState<string | null>(null);

  if (selectedRunIds.length === 0) return null;

  const canDraft = role === "platform_operator";
  const firstRunId = selectedRunIds[0];

  function handleOpen(): void {
    if (firstRunId) onOpenDetail(firstRunId);
  }

  function handleDraft(): void {
    const params = new URLSearchParams();
    params.set("mode", "draft-from-receipt");
    params.set("run_ids", selectedRunIds.join(","));
    navigate(`${stripBasename(routes.policySimulator)}?${params.toString()}`);
  }

  async function handleExport(): Promise<void> {
    setExportStatus("in-flight");
    setExportError(null);
    try {
      // The F002 endpoint accepts a `run_ids` list and returns a signed
      // download URL or a streamed zip. The SPA receives the URL and
      // navigates to it (browser handles the download).
      const response = await api.post<{ download_url?: string }>(
        "/v1/audit/export-evidence",
        { run_ids: selectedRunIds },
      );
      if (response?.download_url) {
        window.location.assign(response.download_url);
      }
      setExportStatus("ok");
    } catch (err) {
      setExportStatus("error");
      if (err instanceof ApiError) setExportError(err.error_description);
      else if (err instanceof Error) setExportError(err.message);
    }
  }

  return (
    <div
      role="toolbar"
      aria-label="Bulk actions"
      className="sticky bottom-0 z-20 flex items-center gap-3 border-t border-r5e-border bg-r5e-surface/95 px-4 py-3 shadow-lg backdrop-blur"
    >
      <span className="text-xs text-r5e-muted">
        {selectedRunIds.length} selected
      </span>

      <button
        type="button"
        onClick={handleOpen}
        className="rounded border border-r5e-border bg-r5e-surface px-3 py-1.5 text-xs text-r5e-text hover:bg-r5e-surface/60"
      >
        Open in detail
      </button>

      {canDraft && (
        <button
          type="button"
          onClick={handleDraft}
          className="rounded border border-r5e-accent bg-r5e-accent/15 px-3 py-1.5 text-xs text-r5e-accent hover:bg-r5e-accent/25"
        >
          Create policy rule from selection
        </button>
      )}

      <button
        type="button"
        onClick={handleExport}
        disabled={exportStatus === "in-flight"}
        className="rounded border border-r5e-border bg-r5e-surface px-3 py-1.5 text-xs text-r5e-text hover:bg-r5e-surface/60 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {exportStatus === "in-flight" ? "Exporting…" : "Export evidence"}
      </button>

      {/* Tag — Phase 2 deferred per spec.md "Out of Scope" addendum.
          Rendered visually for parity with pen-file but disabled with a
          tooltip and a no-op click handler. */}
      <button
        type="button"
        disabled
        title="Tagging ships in Phase 2"
        aria-disabled="true"
        className="cursor-not-allowed rounded border border-dashed border-r5e-border bg-transparent px-3 py-1.5 text-xs text-r5e-muted opacity-60"
      >
        Tag
      </button>

      <div className="ml-auto flex items-center gap-3">
        {exportError && (
          <span className="text-[10px] text-r5e-danger">{exportError}</span>
        )}
        <button
          type="button"
          onClick={onClearSelection}
          className="text-[10px] uppercase tracking-wider text-r5e-muted hover:text-r5e-text"
        >
          Clear
        </button>
      </div>
    </div>
  );
}
