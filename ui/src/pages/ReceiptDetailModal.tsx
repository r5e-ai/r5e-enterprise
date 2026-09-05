// ReceiptDetailModal — self-contained 720px right-drawer wrapper around
// <ReceiptDetail />, used by the React-Router background-location modal
// pattern (see App.tsx).
//
// The brief's F5 chat surface contracts:
//   "click attested_run_id → opens that receipt's drawer over the chat"
//
// The Dashboard-nested ReceiptDetail route renders inside Dashboard's
// <aside> slot, which means it cannot layer over /admin/chat (a different
// route). This component re-uses the same <ReceiptDetail /> contents but
// gives it its own fixed-positioned drawer chrome + backdrop, so the chat
// (or any other authenticated surface) stays mounted underneath.
//
// Closing pops history (navigate(-1)) — the underlying location, captured
// in `location.state.backgroundLocation`, is restored automatically.

import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

import ReceiptDetail from "~/pages/ReceiptDetail";

export default function ReceiptDetailModal(): JSX.Element {
  const navigate = useNavigate();

  // Esc pops the modal. ReceiptDetail's own Esc handler also calls close
  // there — both are wired to navigate(-1), so the same behaviour holds
  // regardless of which closes first.
  useEffect(() => {
    function onKey(e: KeyboardEvent): void {
      if (e.key === "Escape") navigate(-1);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate]);

  return (
    <>
      {/* Backdrop — dimmed click-to-close layer above the underlying surface. */}
      <button
        type="button"
        aria-label="Close receipt"
        data-testid="receipt-modal-backdrop"
        onClick={() => navigate(-1)}
        className="fixed inset-0 z-40 cursor-default bg-black/40"
      />

      {/* Drawer aside — same 720px width as the Dashboard-nested variant. */}
      <aside
        role="dialog"
        aria-label="Receipt detail"
        data-testid="receipt-modal-drawer"
        className="fixed inset-y-0 right-0 z-50 w-[720px] border-l border-r5e-border bg-r5e-surface shadow-2xl"
      >
        <ReceiptDetail />
      </aside>
    </>
  );
}
