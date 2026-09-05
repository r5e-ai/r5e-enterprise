// ColumnPicker — dropdown menu that toggles audit-log columns on/off (#33).
//
// Per the brief:
//   - Default: all columns visible.
//   - Required columns (timestamp + summary) cannot be hidden — their
//     checkboxes are present but disabled.
//   - "X of Y columns" label on the trigger button.
//   - Persistence (localStorage write) is the parent's responsibility —
//     the picker is presentational + emits `onChange` with the next
//     visibility set.
//
// Hand-rolled dropdown (no third-party menu lib): brief warns about
// CDN-loaded UI libs blocking under CSP. The dropdown closes on:
//   - clicking the trigger again
//   - clicking outside
//   - pressing Escape
//
// Accessibility:
//   - Trigger has `aria-haspopup="menu"` + `aria-expanded`.
//   - Panel has `role="menu"`; items have `role="menuitemcheckbox"` with
//     `aria-checked`.

import { Check, ChevronDown, Columns3 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import {
  AUDIT_LOG_COLUMNS,
  columnCountLabel,
  toggleColumnVisibility,
  type AuditLogColumnId,
  type AuditLogColumnVisibility,
} from "~/lib/auditLogColumns";

interface Props {
  visibility: AuditLogColumnVisibility;
  onChange: (next: AuditLogColumnVisibility) => void;
}

export function ColumnPicker({ visibility, onChange }: Props): JSX.Element {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);

  // Click-outside + Escape close.
  useEffect(() => {
    if (!open) return;

    function handleDocClick(e: MouseEvent) {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }

    document.addEventListener("mousedown", handleDocClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleDocClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [open]);

  const label = useMemo(() => columnCountLabel(visibility), [visibility]);

  function toggle(id: AuditLogColumnId): void {
    onChange(toggleColumnVisibility(visibility, id));
  }

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        data-testid="column-picker-trigger"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded border border-r5e-border bg-r5e-surface px-3 py-1 text-xs text-r5e-text transition-colors hover:bg-r5e-surface/60 focus:outline-none focus:ring-2 focus:ring-r5e-accent-glow"
      >
        <Columns3 size={14} aria-hidden="true" />
        <span>{label}</span>
        <ChevronDown
          size={12}
          aria-hidden="true"
          className={`transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>

      {open && (
        <div
          role="menu"
          aria-label="Toggle columns"
          data-testid="column-picker-menu"
          className="absolute right-0 z-20 mt-1 w-56 rounded border border-r5e-border bg-r5e-surface py-1 text-xs shadow-lg"
        >
          {AUDIT_LOG_COLUMNS.map((c) => {
            const checked = visibility.has(c.id);
            const disabled = c.required;
            return (
              <button
                key={c.id}
                type="button"
                role="menuitemcheckbox"
                aria-checked={checked}
                aria-disabled={disabled}
                disabled={disabled}
                data-testid={`column-picker-item-${c.id}`}
                onClick={() => {
                  if (!disabled) toggle(c.id);
                }}
                className={`flex w-full items-center gap-2 px-3 py-1.5 text-left transition-colors ${
                  disabled
                    ? "cursor-not-allowed text-r5e-muted"
                    : "text-r5e-text hover:bg-r5e-surface/60"
                }`}
              >
                <span
                  className={`flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-sm border ${
                    checked
                      ? "border-r5e-accent bg-r5e-accent/20 text-r5e-accent"
                      : "border-r5e-border"
                  }`}
                >
                  {checked && <Check size={10} aria-hidden="true" />}
                </span>
                <span className="flex-1 truncate">{c.label}</span>
                {disabled && (
                  <span className="text-[10px] uppercase tracking-wider text-r5e-muted">
                    Required
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
