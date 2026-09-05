// ScopePicker — column 02 of the Policy Simulator's SCOPE & CONDITIONS,
// matching the canonical `MdEKl > drawer` Pencil frame's middle panel
// (`5oAdL` → `whoSection` + `whatSection`).
//
// Canonical structure:
//
//   WHO
//   ◉ Just this principal — User::"alice@corp"
//   ● All principals with role — [tenant_auditor ▾]
//   ◉ All principals in group
//   ◉ All principals in tenant
//
//   ────────────────────────────────────────────────
//   WHAT
//   ◉ This exact action & resource
//   ● This action, any resource of kind — Action::chat_completion, LLMEndpoint::*
//   ◉ This action, explicit resource set
//
// Pre-rewrite this was a 2x2 grid of segmented buttons. The buttons
// rendered the same scope-kind set but didn't match the canonical's
// vertical radio list with inline value displays, and had no WHAT
// section. The brief at design/briefs/04-policy-simulator.md described
// the segmented grid; the .pen showed the radio-list. Following the
// .pen wins.

import type * as React from "react";
import { type PolicyDraftScopeMetadata } from "~/hooks/usePolicyDrafts";

interface Props {
  value: PolicyDraftScopeMetadata | null;
  onChange: (next: PolicyDraftScopeMetadata) => void;
  /**
   * Action+resource scope (canonical's WHAT section). UI-only for now —
   * the draft envelope doesn't carry this yet; we surface the canonical
   * choice and let upstream wire it in once the backend extends the
   * draft schema. Defaults to "exact" (most restrictive, safest).
   */
  actionScope?: ActionScopeKind;
  onActionScopeChange?: (next: ActionScopeKind) => void;
}

export type ActionScopeKind = "exact" | "kind" | "explicit_set";

interface ScopeOption {
  kind: PolicyDraftScopeMetadata["scope_kind"];
  label: string;
  hint: string;
  placeholder: string;
}

const WHO_OPTIONS: readonly ScopeOption[] = [
  {
    kind: "principal",
    label: "Just this principal",
    hint: "Targets a single subject (e.g. alice@corp).",
    placeholder: "subject (e.g. auth0|alice@corp)",
  },
  {
    kind: "role",
    label: "All principals with role",
    hint: "Targets every principal carrying the named role.",
    placeholder: "role (e.g. tenant_auditor)",
  },
  {
    kind: "group",
    label: "All principals in group",
    hint: "Targets every principal in the IdP group.",
    placeholder: "group identifier (e.g. eng-platform)",
  },
  {
    kind: "tenant",
    label: "All principals in tenant",
    hint: "Targets every principal in the named tenant.",
    placeholder: "tenant_id (ULID)",
  },
] as const;

interface WhatOption {
  kind: ActionScopeKind;
  label: string;
  inlineValue?: string;
}

const WHAT_OPTIONS: readonly WhatOption[] = [
  { kind: "exact", label: "This exact action & resource" },
  {
    kind: "kind",
    label: "This action, any resource of kind",
    inlineValue: "Action::chat_completion, LLMEndpoint::*",
  },
  { kind: "explicit_set", label: "This action, explicit resource set" },
] as const;

export function ScopePicker({
  value,
  onChange,
  actionScope = "exact",
  onActionScopeChange,
}: Props): JSX.Element {
  const currentKind = value?.scope_kind ?? "principal";
  const currentValue = value?.scope_value ?? "";
  const selected =
    WHO_OPTIONS.find((o) => o.kind === currentKind) ?? WHO_OPTIONS[0]!;
  return (
    <div
      data-testid="scope-picker"
      className="flex flex-col gap-4 rounded-r5e-md border border-r5e-border-subtle bg-r5e-surface-card p-4"
    >
      {/* WHO */}
      <section className="flex flex-col gap-2">
        <SectionLabel>WHO</SectionLabel>
        <div role="radiogroup" aria-label="Principal scope">
          {WHO_OPTIONS.map((opt) => {
            const active = opt.kind === currentKind;
            return (
              <RadioRow
                key={opt.kind}
                active={active}
                onSelect={() =>
                  onChange({ scope_kind: opt.kind, scope_value: currentValue })
                }
                testId={`scope-kind-${opt.kind}`}
              >
                <span
                  className={
                    active
                      ? "text-r5e-foreground-primary"
                      : "text-r5e-foreground-secondary"
                  }
                >
                  {opt.label}
                </span>
                {active && currentValue && (
                  <span className="font-mono text-r5e-foreground-muted">
                    — {currentValue}
                  </span>
                )}
              </RadioRow>
            );
          })}
        </div>
        <input
          type="text"
          value={currentValue}
          onChange={(e) =>
            onChange({
              scope_kind: currentKind,
              scope_value: e.target.value,
            })
          }
          placeholder={selected.placeholder}
          className="rounded-r5e-sm border border-r5e-border-subtle bg-r5e-surface-base px-2 py-1 font-mono text-[11px] text-r5e-foreground-primary placeholder:text-r5e-foreground-muted focus:border-r5e-accent-purple focus:outline-none"
          data-testid="scope-value"
          aria-label={`Scope value for ${selected.label}`}
        />
        <p className="text-[10px] text-r5e-foreground-muted">{selected.hint}</p>
      </section>

      <hr className="border-r5e-border-subtle" />

      {/* WHAT */}
      <section className="flex flex-col gap-2">
        <SectionLabel>WHAT</SectionLabel>
        <div role="radiogroup" aria-label="Action and resource scope">
          {WHAT_OPTIONS.map((opt) => {
            const active = opt.kind === actionScope;
            return (
              <RadioRow
                key={opt.kind}
                active={active}
                onSelect={() => onActionScopeChange?.(opt.kind)}
                testId={`action-scope-${opt.kind}`}
              >
                <span
                  className={
                    active
                      ? "text-r5e-foreground-primary"
                      : "text-r5e-foreground-secondary"
                  }
                >
                  {opt.label}
                </span>
                {opt.inlineValue && (
                  <span className="font-mono text-r5e-foreground-muted">
                    — {opt.inlineValue}
                  </span>
                )}
              </RadioRow>
            );
          })}
        </div>
      </section>
    </div>
  );
}

function SectionLabel({
  children,
}: {
  children: React.ReactNode;
}): JSX.Element {
  return (
    <h4
      className="font-mono text-[11px] font-semibold uppercase text-r5e-foreground-secondary"
      style={{ letterSpacing: "0.08em" }}
    >
      {children}
    </h4>
  );
}

function RadioRow({
  active,
  onSelect,
  children,
  testId,
}: {
  active: boolean;
  onSelect: () => void;
  children: React.ReactNode;
  testId?: string;
}): JSX.Element {
  return (
    <label
      className="flex cursor-pointer items-center gap-2 py-1 text-[11px] hover:text-r5e-foreground-primary"
      data-testid={testId}
    >
      <input
        type="radio"
        checked={active}
        onChange={onSelect}
        className="sr-only"
      />
      <span
        aria-hidden="true"
        className={`relative inline-block h-3.5 w-3.5 shrink-0 rounded-full border-[1.5px] ${
          active
            ? "border-r5e-accent-purple bg-r5e-accent-purple"
            : "border-r5e-border-strong bg-transparent"
        }`}
      >
        {active && (
          <span className="absolute inset-1 rounded-full bg-r5e-surface-base" />
        )}
      </span>
      <span className="flex flex-1 items-center gap-1.5">{children}</span>
    </label>
  );
}
