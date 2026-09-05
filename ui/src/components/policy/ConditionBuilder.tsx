// ConditionBuilder — adds Cedar `when {…}` clauses (T094 — Phase 5 US3,
// FR-025; F4 redesign per `design/briefs/04-policy-simulator.md`).
//
// Per spec FR-025 + F4 brief: the operator can compose five condition kinds:
//   - ATTRIBUTE EQUALS         `<key> == <value>`   — eq
//   - ATTRIBUTE DIFFERS FROM   `<key> != <value>`   — neq
//   - ATTRIBUTE IN SET         `<key> in [a, b, …]` — in
//   - TIME WINDOW              `context.session_age < N` (or wall-clock range)
//   - GROUP MEMBERSHIP         `principal in Group::"<name>"`
//
// Per F4 brief, the attribute-key dropdown surfaces the canonical Cedar axes
// addressable in r5e (see `design/briefs/09-cedar-reference.md`):
//
//   principal.subject              principal.kind
//   principal.tenant_id            principal.role
//   resource.tags.tool_kind        resource.tags.verb
//   resource.tags.argument_body    resource.tags.scope_kind
//   resource.tags.target_resources resource.tags.category
//   resource.tags.semantic_args.*  context.time / context.session_age
//
// `semantic_args.*` keys are dynamic (different per tool_kind); we expose
// the canonical static set today and leave the dynamic suggestion seam for
// a future iteration where the gateway emits an axis-coverage report.
//
// State is fully controlled — the parent owns the array. Conditions are
// stored on the draft as `condition_metadata`; the parent regenerates the
// Cedar source skeleton from scope + conditions when in Draft-from-Receipt
// mode (we keep the Cedar-string generation in one place to avoid drift).
//
// Wire-shape note: each row emits `{kind, attr, value}` — `kind` is the
// backend-required discriminator (per `PolicyDraft.changeset/2`'s
// `validate_condition_metadata_shape/1`), not `op`. The five canonical
// kinds are `eq | neq | in | time_window | group_member`.

import { useState, type KeyboardEvent } from "react";

import { type PolicyDraftConditionKind, type PolicyDraftConditionMetadata } from "~/hooks/usePolicyDrafts";
import { coerceChipList, coerceRange } from "~/lib/conditionValues";

interface Props {
  value: PolicyDraftConditionMetadata[];
  onChange: (next: PolicyDraftConditionMetadata[]) => void;
}

type ConditionKind = PolicyDraftConditionKind;

// Canonical Cedar axes per `09-cedar-reference.md`. Ordered by likely
// frequency (tool_kind / verb top because they're the spine of every
// suggestion-engine template).
const CANONICAL_ATTRIBUTES: ReadonlyArray<{ key: string; hint: string }> = [
  { key: "resource.tags.tool_kind", hint: 'e.g. "bash" / "edit" / "mcp"' },
  { key: "resource.tags.verb", hint: 'e.g. "rm" / "Edit" / "query_metrics"' },
  { key: "resource.tags.argument_body", hint: "the action subject" },
  { key: "resource.tags.scope_kind", hint: 'e.g. "file_outside_workdir"' },
  { key: "resource.tags.category", hint: 'e.g. "subprocess_exec"' },
  { key: "resource.tags.target_resources", hint: "list of touched resources" },
  { key: "resource.tags.semantic_args.host", hint: "webfetch host" },
  { key: "resource.tags.semantic_args.scheme", hint: "http / https" },
  { key: "resource.tags.semantic_args.outside_workdir", hint: "true / false" },
  { key: "resource.tags.semantic_args.file_path", hint: "edit/read path" },
  { key: "resource.tags.semantic_args.server", hint: "mcp server" },
  { key: "resource.tags.semantic_args.tool", hint: "mcp tool" },
  { key: "resource.tags.semantic_args.subagent_type", hint: "agent dispatch" },
  { key: "principal.subject", hint: "for obo_human" },
  { key: "principal.kind", hint: "obo_human / service_account / autonomous" },
  { key: "principal.tenant_id", hint: "tenant identifier" },
  { key: "principal.role", hint: "platform_operator / …" },
  { key: "context.session_age_seconds", hint: "how long the session has been open" },
];

const CONDITION_TEMPLATES: ReadonlyArray<{
  kind: ConditionKind;
  label: string;
  /** Shape of the value input (chip-list for `in`, ISO range tuple for
   *  `time_window`, single text otherwise). */
  valueShape: "single" | "chips" | "range";
  defaultAttr: string;
  valuePlaceholder: string;
  hint: string;
}> = [
  {
    kind: "eq",
    label: "Attribute equals",
    valueShape: "single",
    defaultAttr: "resource.tags.tool_kind",
    valuePlaceholder: 'value (e.g. "bash")',
    hint: "<key> == <value>",
  },
  {
    kind: "neq",
    label: "Attribute differs from",
    valueShape: "single",
    defaultAttr: "resource.tags.tool_kind",
    valuePlaceholder: 'value (e.g. "bash")',
    hint: "<key> != <value>",
  },
  {
    kind: "in",
    label: "Attribute in set",
    valueShape: "chips",
    defaultAttr: "resource.tags.verb",
    valuePlaceholder: "value (press Enter or comma to add)",
    hint: "<key> in [a, b, …]",
  },
  {
    kind: "time_window",
    label: "Time window",
    valueShape: "range",
    // Per F009 — `defaultAttr` is `context.timestamp` (matches the ISO
    // range placeholder). The pre-fix default was
    // `context.session_age_seconds`, which is a numeric (seconds-since-
    // session-start) axis incompatible with an ISO range; now that the
    // splicer honors `attr` (F007), the operator MAY override this to
    // `context.session_age_seconds` if they're authoring numeric bounds
    // — but the default lines up with the placeholder shape.
    defaultAttr: "context.timestamp",
    valuePlaceholder: "ISO range (e.g. 2026-04-24T09:00Z..17:00Z)",
    hint: "<attr> >= ts1 && <attr> <= ts2",
  },
  {
    kind: "group_member",
    label: "Group membership",
    valueShape: "single",
    // `attr` carries the LHS of `<lhs> in Group::"<value>"`. Default is
    // `principal` per the Cedar EID convention; per F007 the operator
    // can override (e.g. `principal.parent`, `resource.owner`) and the
    // splicer respects it.
    defaultAttr: "principal",
    valuePlaceholder: 'group identifier (e.g. "eng-platform")',
    hint: '<attr> in Group::"<value>"',
  },
];

function templateFor(kind: ConditionKind): typeof CONDITION_TEMPLATES[number] {
  return CONDITION_TEMPLATES.find((t) => t.kind === kind) ?? CONDITION_TEMPLATES[0]!;
}

function valueAsString(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  return String(v);
}

// Per F004 — `valueAsChips` + `valueAsRange` were inline duplicates of the
// same coercion shape used by `cedarSourceSplice.ts`. Constitution
// Principle VII (Interface-First on Second Consumer) extracted the shared
// helpers into `~/lib/conditionValues`; both modules import from there.
const valueAsChips = coerceChipList;
const valueAsRange = coerceRange;

/** Default value for a freshly-added row, per condition kind. */
function defaultValueFor(kind: ConditionKind): unknown {
  if (kind === "in") return [];
  if (kind === "time_window") return ["", ""];
  return "";
}

export function ConditionBuilder({ value, onChange }: Props): JSX.Element {
  function addRow(kind: ConditionKind): void {
    const tpl = templateFor(kind);
    onChange([
      ...value,
      { kind, attr: tpl.defaultAttr, value: defaultValueFor(kind) },
    ]);
  }

  function updateRow(idx: number, patch: Partial<PolicyDraftConditionMetadata>): void {
    const next = value.slice();
    const current = next[idx];
    if (!current) return;
    // If `kind` is changing, also reset `value` to the new kind's default
    // so we never carry, say, a string into the chip-list slot.
    if (patch.kind && patch.kind !== current.kind) {
      next[idx] = { ...current, ...patch, value: defaultValueFor(patch.kind) };
    } else {
      next[idx] = { ...current, ...patch };
    }
    onChange(next);
  }

  function removeRow(idx: number): void {
    onChange(value.filter((_, i) => i !== idx));
  }

  return (
    <fieldset
      data-testid="condition-builder"
      className="flex flex-col gap-3 rounded border border-r5e-border bg-r5e-surface p-3"
    >
      <legend className="px-1 text-[10px] uppercase tracking-wider text-r5e-muted">
        Conditions ({value.length})
      </legend>

      {value.length === 0 && (
        <p className="text-[10px] text-r5e-muted">
          No conditions yet. Add one to narrow when this rule applies.
        </p>
      )}

      <ul className="flex flex-col gap-2">
        {value.map((row, idx) => {
          const tpl = templateFor(row.kind);
          const isAttributeKind = row.kind === "eq" || row.kind === "neq" || row.kind === "in";
          return (
            <li
              key={idx}
              data-testid={`condition-row-${idx}`}
              className="flex flex-col gap-1.5 rounded border border-r5e-border/60 bg-r5e-bg p-2"
            >
              <div className="flex items-center justify-between">
                <select
                  value={row.kind}
                  onChange={(e) =>
                    updateRow(idx, { kind: e.target.value as ConditionKind })
                  }
                  className="rounded border border-r5e-border bg-r5e-surface px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-r5e-text focus:border-r5e-accent focus:outline-none"
                  aria-label="Condition kind"
                >
                  {CONDITION_TEMPLATES.map((t) => (
                    <option key={t.kind} value={t.kind}>
                      {t.label}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={() => removeRow(idx)}
                  aria-label="Remove condition"
                  className="rounded border border-r5e-border px-2 py-0.5 text-[10px] uppercase tracking-wider text-r5e-muted hover:border-r5e-danger hover:text-r5e-danger"
                >
                  Remove
                </button>
              </div>

              {/* Attribute key — dropdown for attribute kinds, free text for
                  group_member (which addresses `principal` directly). */}
              {isAttributeKind ? (
                <input
                  type="text"
                  list={`condition-attrs-${idx}`}
                  value={row.attr}
                  onChange={(e) => updateRow(idx, { attr: e.target.value })}
                  placeholder="attribute key (e.g. resource.tags.tool_kind)"
                  className="rounded border border-r5e-border bg-r5e-surface px-2 py-1.5 font-mono text-xs text-r5e-text placeholder:text-r5e-muted/60 focus:border-r5e-accent focus:outline-none"
                  aria-label="Condition attribute"
                />
              ) : (
                <input
                  type="text"
                  value={row.attr}
                  onChange={(e) => updateRow(idx, { attr: e.target.value })}
                  placeholder={tpl.defaultAttr}
                  className="rounded border border-r5e-border bg-r5e-surface px-2 py-1.5 font-mono text-xs text-r5e-text placeholder:text-r5e-muted/60 focus:border-r5e-accent focus:outline-none"
                  aria-label="Condition attribute"
                />
              )}
              {isAttributeKind && (
                <datalist id={`condition-attrs-${idx}`}>
                  {CANONICAL_ATTRIBUTES.map((a) => (
                    <option key={a.key} value={a.key}>
                      {a.hint}
                    </option>
                  ))}
                </datalist>
              )}

              {/* Value editor — dispatched on `tpl.valueShape` per F4 brief.
                  Brief mandates a chip list for ATTRIBUTE IN SET and a
                  date-range pair for TIME WINDOW; everything else is the
                  single-string fallback. */}
              {tpl.valueShape === "chips" ? (
                <ChipsInput
                  rowIdx={idx}
                  value={valueAsChips(row.value)}
                  placeholder={tpl.valuePlaceholder}
                  onChange={(next) => updateRow(idx, { value: next })}
                />
              ) : tpl.valueShape === "range" ? (
                <RangeInput
                  rowIdx={idx}
                  value={valueAsRange(row.value)}
                  onChange={(next) => updateRow(idx, { value: next })}
                />
              ) : (
                <input
                  type="text"
                  value={valueAsString(row.value)}
                  onChange={(e) => updateRow(idx, { value: e.target.value })}
                  placeholder={tpl.valuePlaceholder}
                  className="rounded border border-r5e-border bg-r5e-surface px-2 py-1.5 font-mono text-xs text-r5e-text placeholder:text-r5e-muted/60 focus:border-r5e-accent focus:outline-none"
                  aria-label="Condition value"
                />
              )}

              <span className="font-mono text-[10px] text-r5e-muted">
                {tpl.hint}
              </span>
            </li>
          );
        })}
      </ul>

      {/* Per F4 brief mock — buttons grouped as:
            row 1: [+ ATTRIBUTE EQUALS]
            row 2: [+ ATTRIBUTE DIFFERS FROM]
            row 3: [+ ATTRIBUTE IN SET]   [+ TIME WINDOW]
            row 4: [+ GROUP MEMBERSHIP]
          A 2-column grid with the EQUALS / DIFFERS / GROUP buttons each
          spanning both columns gives the canonical layout regardless of
          column width. */}
      <div className="grid grid-cols-2 gap-2" data-testid="condition-add-buttons">
        <AddConditionButton kind="eq" label="Attribute equals" onAdd={addRow} className="col-span-2" />
        <AddConditionButton kind="neq" label="Attribute differs from" onAdd={addRow} className="col-span-2" />
        <AddConditionButton kind="in" label="Attribute in set" onAdd={addRow} />
        <AddConditionButton kind="time_window" label="Time window" onAdd={addRow} />
        <AddConditionButton kind="group_member" label="Group membership" onAdd={addRow} className="col-span-2" />
      </div>
    </fieldset>
  );
}

function AddConditionButton({
  kind,
  label,
  onAdd,
  className = "",
}: {
  kind: ConditionKind;
  label: string;
  onAdd: (kind: ConditionKind) => void;
  className?: string;
}): JSX.Element {
  return (
    <button
      type="button"
      onClick={() => onAdd(kind)}
      className={`rounded border border-dashed border-r5e-border bg-r5e-bg px-2 py-1 text-[10px] uppercase tracking-wider text-r5e-muted hover:border-r5e-accent hover:text-r5e-accent ${className}`}
      data-testid={`add-condition-${kind}`}
    >
      + {label}
    </button>
  );
}

// ---------------------------------------------------------------------------
// ChipsInput — small chip-list editor for ATTRIBUTE IN SET.
// ---------------------------------------------------------------------------
//
// Per F4 brief: "ATTRIBUTE IN SET — key + chip list". The user types into
// a free-text input; pressing Enter or "," commits the buffer to a chip;
// chips are removable with × or backspace-on-empty. The committed value is
// `string[]` on the wire, which both the backend (JSONB) and the
// suggestion-engine consume directly.
//
// We kept this inline instead of importing a 3rd-party tag-input lib —
// the brief calls for the simplest possible chip surface and a custom
// 60-line component is easier to evolve than a dependency.

function ChipsInput({
  rowIdx,
  value,
  placeholder,
  onChange,
}: {
  rowIdx: number;
  value: string[];
  placeholder: string;
  onChange: (next: string[]) => void;
}): JSX.Element {
  const [buffer, setBuffer] = useState("");

  function commit(): void {
    const trimmed = buffer.trim();
    if (trimmed.length === 0) return;
    if (value.includes(trimmed)) {
      setBuffer("");
      return;
    }
    onChange([...value, trimmed]);
    setBuffer("");
  }

  function removeChipAt(i: number): void {
    onChange(value.filter((_, idx) => idx !== i));
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>): void {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      commit();
    } else if (e.key === "Backspace" && buffer.length === 0 && value.length > 0) {
      // Pop the last chip on backspace-on-empty for keyboard ergonomics.
      e.preventDefault();
      onChange(value.slice(0, -1));
    }
  }

  return (
    <div
      data-testid={`condition-row-${rowIdx}-chips`}
      className="flex flex-wrap items-center gap-1 rounded border border-r5e-border bg-r5e-surface px-2 py-1.5"
    >
      {value.map((chip, i) => (
        <span
          key={`${chip}-${i}`}
          data-testid={`condition-row-${rowIdx}-chip-${i}`}
          className="inline-flex items-center gap-1 rounded border border-r5e-accent/40 bg-r5e-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-r5e-accent"
        >
          {chip}
          <button
            type="button"
            onClick={() => removeChipAt(i)}
            aria-label={`Remove ${chip}`}
            className="text-r5e-accent/70 hover:text-r5e-danger"
          >
            ×
          </button>
        </span>
      ))}
      <input
        type="text"
        value={buffer}
        onChange={(e) => setBuffer(e.target.value)}
        onKeyDown={handleKeyDown}
        onBlur={commit}
        placeholder={value.length === 0 ? placeholder : ""}
        className="min-w-[120px] flex-1 bg-transparent font-mono text-xs text-r5e-text placeholder:text-r5e-muted/60 focus:outline-none"
        aria-label="Condition value"
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// RangeInput — two ISO-timestamp inputs for TIME WINDOW.
// ---------------------------------------------------------------------------

function RangeInput({
  rowIdx,
  value,
  onChange,
}: {
  rowIdx: number;
  value: [string, string];
  onChange: (next: [string, string]) => void;
}): JSX.Element {
  const [start, end] = value;
  return (
    <div
      data-testid={`condition-row-${rowIdx}-range`}
      className="flex items-center gap-2"
    >
      <input
        type="text"
        value={start}
        onChange={(e) => onChange([e.target.value, end])}
        placeholder="2026-04-24T09:00Z"
        className="flex-1 rounded border border-r5e-border bg-r5e-surface px-2 py-1.5 font-mono text-xs text-r5e-text placeholder:text-r5e-muted/60 focus:border-r5e-accent focus:outline-none"
        aria-label="Range start"
      />
      <span className="text-[10px] text-r5e-muted">to</span>
      <input
        type="text"
        value={end}
        onChange={(e) => onChange([start, e.target.value])}
        placeholder="2026-04-24T17:00Z"
        className="flex-1 rounded border border-r5e-border bg-r5e-surface px-2 py-1.5 font-mono text-xs text-r5e-text placeholder:text-r5e-muted/60 focus:border-r5e-accent focus:outline-none"
        aria-label="Range end"
      />
    </div>
  );
}
