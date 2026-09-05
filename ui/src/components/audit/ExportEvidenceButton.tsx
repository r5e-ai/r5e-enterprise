// ExportEvidenceButton — issues an Export Evidence request for a single
// receipt and downloads the resulting zip (T079, US2).
//
// Wire shape mirrors `apps/recurse_gateway/lib/recurse_gateway/audit_plane/
// export_handler.ex`:
//   - `POST /v1/audit/export` body: `{"run_ids": [<run_id>, ...]}` (max 100).
//   - Response: `Content-Type: application/zip` with the zip bytes streamed
//     directly back. For N=1 the body is the inner zip; for N>1 it's a
//     zip-of-zips. There is NO async polling step (the previous SPA design
//     assumed `{export_id, status, download_path}` polling, but no such
//     endpoint exists in `router.ex`).
//   - On non-2xx the handler emits an F001 envelope; `apiFetch` throws an
//     `ApiError` for those.
//
// Browser download:
//   - We can't use `window.location.assign` because the endpoint is POST
//     (not GET) and the body must be a JSON envelope. We `fetch` directly,
//     receive the zip as a Blob, then trigger an anchor-element click on
//     an object URL so the browser owns the file-save dialog (with cookie
//     auth attached because `credentials: "include"`).
//   - `Content-Disposition: attachment; filename="evidence-<ts>.zip"` is the
//     server-issued filename; we re-derive a fallback timestamp client-side
//     in case the header is missing.

import { useMutation } from "@tanstack/react-query";

import { ApiError, useApiErrorHandler } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";

interface Props {
  runId: string;
}

const EXPORT_PATH = apiPaths.audit.export;

/**
 * Parse RFC 5987 / 6266 `filename="..."` from a Content-Disposition header.
 * Returns null on malformed/missing input — caller falls back to a synthetic
 * timestamped name.
 */
function parseFilename(header: string | null): string | null {
  if (!header) return null;
  const match = /filename="([^"]+)"/.exec(header);
  return match?.[1] ?? null;
}

function fallbackFilename(): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `evidence-${stamp}.zip`;
}

export async function downloadEvidence(runIds: string | string[]): Promise<void> {
  const ids = Array.isArray(runIds) ? runIds : [runIds];
  const response = await fetch(EXPORT_PATH, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/zip, application/json",
    },
    body: JSON.stringify({ run_ids: ids }),
  });

  if (!response.ok) {
    // Error path — backend responds with the F001 envelope as JSON.
    let envelope: Record<string, unknown> = {};
    try {
      envelope = (await response.json()) as Record<string, unknown>;
    } catch {
      // Non-JSON error body (e.g., 502 HTML) — synthesize.
    }
    throw new ApiError({
      error: typeof envelope.error === "string" ? envelope.error : "unknown_error",
      error_description:
        typeof envelope.error_description === "string"
          ? envelope.error_description
          : `HTTP ${response.status}`,
      correlation_id:
        typeof envelope.correlation_id === "string"
          ? envelope.correlation_id
          : "unknown",
      attested_run_id:
        typeof envelope.attested_run_id === "string"
          ? envelope.attested_run_id
          : null,
      status: response.status,
    });
  }

  const blob = await response.blob();
  const filename =
    parseFilename(response.headers.get("content-disposition")) ??
    fallbackFilename();

  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    // Anchor must be in the DOM in some browsers for the click to register.
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    // Defer revocation so the browser has time to start the download.
    setTimeout(() => URL.revokeObjectURL(url), 1_000);
  }
}

export function ExportEvidenceButton({ runId }: Props): JSX.Element {
  const handleApiError = useApiErrorHandler();

  const mutation = useMutation<void, Error, void>({
    mutationFn: () => downloadEvidence(runId),
    onError: handleApiError,
  });

  const errorMessage =
    mutation.isError && mutation.error instanceof ApiError
      ? mutation.error.error_description
      : null;

  return (
    <div className="flex flex-col gap-2" data-testid="export-evidence">
      <button
        type="button"
        onClick={() => mutation.mutate()}
        disabled={mutation.isPending}
        className="rounded border border-r5e-accent px-3 py-1.5 text-xs font-semibold uppercase tracking-wider text-r5e-accent hover:bg-r5e-accent/10 disabled:cursor-not-allowed disabled:opacity-50"
        data-testid="export-evidence-button"
      >
        {mutation.isPending ? "Building zip…" : "Export Evidence (.zip)"}
      </button>

      {errorMessage && (
        <div role="alert" className="text-[10px] text-r5e-danger">
          {errorMessage}
        </div>
      )}
    </div>
  );
}
