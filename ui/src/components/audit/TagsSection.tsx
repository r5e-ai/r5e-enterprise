// TagsSection — drawer's lead-with-action surface (R2 redesign).
//
// Per `design/briefs/03-receipt-drawer.md` (the R2 redesign's central move):
// the user clicks a row to ask "what was tried? what's the policy posture?
// could a policy block this?" — those answers are surfaced HERE, before the
// crypto-chain tabs.
//
// Structure (top to bottom):
//
//   EXTRACTED TAGS                              via extractor pipeline
//   > {display_summary}                          ← chevron-right prefix
//
//   TOOL_KIND       {tool_kind}                  ← 2-col key/value
//   VERB            {verb}                       ← 140px label width
//   ARGUMENT_BODY   {argument_body}              ← truncate ~100, expandable
//
//   [CATEGORY]  [SCOPE_KIND]  scope: {scope_value (truncated)}
//
//   TARGET RESOURCES                             ← only if non-empty
//     [host:gist.github.com]  [metric:cpu_load]
//
//   ▸ SEMANTIC_ARGS (N)                          ← collapsible disclosure
//      key1     value1
//      key2     value2
//
// The component degrades gracefully:
//   - tags === null → section returns null (drawer falls through to tabs)
//   - tags.display_summary is the only populated field → just the summary
//     row + category pill render

import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

import { CategoryPill } from "~/components/audit/CategoryPill";
import { Pill } from "~/components/shared/Pill";
import { llmCallParseFacts, tagsOf } from "~/lib/tags";
import { chipsForRow } from "~/lib/rowChips";
import { truncate } from "~/lib/strings";
import type { ReceiptDetail } from "~/hooks/useReceiptDetail";

interface Props {
  data: ReceiptDetail;
}

const ARGUMENT_BODY_TRUNCATE = 100;

export function TagsSection({ data }: Props): JSX.Element | null {
  const tags = tagsOf({
    outer_container: { tags: data.outer_container.tags ?? null },
  });
  // No tags → render nothing. Drawer falls through to tabs.
  if (!tags) return null;

  const displaySummary = (tags.display_summary ?? "").toString();
  const rowChips = chipsForRow(data);
  const category = rowChips.category;
  const hasExplicitCategory = typeof tags.category === "string" && tags.category.trim().length > 0;
  const decision = data.outer_container.policy_decision;
  const toolKind = (tags.tool_kind ?? null) as string | null;
  const verb = (tags.verb ?? null) as string | null;
  const argumentBody = (tags.argument_body ?? null) as string | null;
  const scopeKind = rowChips.scope_kind;
  const scopeValue = rowChips.scope_value;
  const targetResources = rowChips.target_resources.length > 0
    ? rowChips.target_resources
    : null;
  const semanticArgs =
    tags.semantic_args && typeof tags.semantic_args === "object"
      ? (tags.semantic_args as Record<string, unknown>)
      : null;
  // Spec 012 S4 (plan §13): recognition facts for LLM-proxy receipts live
  // here, in the detail view — plain lines, never a caveat on the row.
  const isLlmCall = data.signed_predicate.event_kind === "llm_call_attested";
  const parseFacts = isLlmCall ? llmCallParseFacts(tags) : [];

  // If literally no tag fields are populated, hide the section.
  const hasAnyContent =
    Boolean(displaySummary) ||
    hasExplicitCategory ||
    Boolean(toolKind) ||
    Boolean(verb) ||
    Boolean(argumentBody) ||
    Boolean(scopeKind) ||
    Boolean(scopeValue) ||
    (targetResources && targetResources.length > 0) ||
    (semanticArgs && Object.keys(semanticArgs).length > 0) ||
    parseFacts.length > 0;
  if (!hasAnyContent) return null;

  return (
    <section
      data-testid="tags-section"
      className="flex flex-col gap-3 border-b border-r5e-border bg-r5e-surface/60 px-4 py-3"
    >
      <header className="flex items-baseline justify-between">
        <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted">
          Extracted tags
        </span>
        <span className="font-mono text-[9px] text-r5e-muted">
          {isLlmCall ? "via LLM proxy parser" : "via extractor pipeline"}
        </span>
      </header>

      {parseFacts.length > 0 && (
        <ul className="flex flex-col gap-1" data-testid="tags-parse-facts">
          {parseFacts.map((fact) => (
            <li key={fact} className="font-mono text-[11px] text-r5e-text">
              {fact}
            </li>
          ))}
        </ul>
      )}

      {displaySummary && (
        <div
          className="flex items-start gap-2"
          data-testid="tags-summary"
        >
          <ChevronRight
            className="mt-0.5 h-3.5 w-3.5 shrink-0 text-r5e-muted"
            aria-hidden="true"
          />
          <span className="font-mono text-sm text-r5e-text">
            {displaySummary}
          </span>
        </div>
      )}

      {(toolKind || verb || argumentBody) && (
        <TypedPropertiesGrid
          toolKind={toolKind}
          verb={verb}
          argumentBody={argumentBody}
        />
      )}

      <div
        className="flex flex-wrap items-center gap-1.5"
        data-testid="tags-pills"
      >
        <CategoryPill category={category} forceDenial={decision === "deny"} size="sm" />
        {scopeKind && (
          <Pill
            tone="muted"
            outline
            size="xs"
            testId="tags-pill-scope-kind"
          >
            {scopeKind}
          </Pill>
        )}
        {scopeValue && (
          <Pill
            tone="muted"
            outline
            size="xs"
            uppercase={false}
            testId="tags-pill-scope-value"
            className="font-mono"
          >
            <span title={scopeValue}>scope: {truncate(scopeValue, 28)}</span>
          </Pill>
        )}
      </div>

      {targetResources && targetResources.length > 0 && (
        <TargetResourcesRow resources={targetResources} />
      )}

      {semanticArgs && Object.keys(semanticArgs).length > 0 && (
        <SemanticArgsTable args={semanticArgs} />
      )}
    </section>
  );
}

function TypedPropertiesGrid({
  toolKind,
  verb,
  argumentBody,
}: {
  toolKind: string | null;
  verb: string | null;
  argumentBody: string | null;
}): JSX.Element {
  return (
    <dl
      data-testid="tags-typed-properties"
      className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-1.5 rounded border border-r5e-border/60 bg-r5e-bg/40 px-3 py-2"
    >
      {toolKind && (
        <>
          <dt
            className="font-mono text-[10px] uppercase tracking-[0.1em] text-r5e-muted"
            data-testid="tags-typed-tool-kind-label"
          >
            tool_kind
          </dt>
          <dd
            className="font-mono text-[11px] text-r5e-text"
            data-testid="tags-typed-tool-kind"
          >
            {toolKind}
          </dd>
        </>
      )}
      {verb && (
        <>
          <dt
            className="font-mono text-[10px] uppercase tracking-[0.1em] text-r5e-muted"
            data-testid="tags-typed-verb-label"
          >
            verb
          </dt>
          <dd
            className="font-mono text-[11px] text-r5e-text"
            data-testid="tags-typed-verb"
          >
            {verb}
          </dd>
        </>
      )}
      {argumentBody && (
        <>
          <dt
            className="font-mono text-[10px] uppercase tracking-[0.1em] text-r5e-muted"
            data-testid="tags-typed-argument-body-label"
          >
            argument_body
          </dt>
          <dd
            className="font-mono text-[11px] text-r5e-text"
            data-testid="tags-typed-argument-body"
          >
            <ExpandableValue value={argumentBody} />
          </dd>
        </>
      )}
    </dl>
  );
}

function ExpandableValue({ value }: { value: string }): JSX.Element {
  const [expanded, setExpanded] = useState(false);
  if (value.length <= ARGUMENT_BODY_TRUNCATE) {
    return <span className="break-all">{value}</span>;
  }
  return (
    <button
      type="button"
      onClick={() => setExpanded((v) => !v)}
      className="text-left hover:text-r5e-accent"
      aria-expanded={expanded}
      title={expanded ? "Click to collapse" : "Click to expand"}
      data-testid="tags-typed-argument-body-toggle"
    >
      <span className={expanded ? "break-all" : "block truncate"}>
        {expanded ? value : truncate(value, ARGUMENT_BODY_TRUNCATE)}
      </span>
    </button>
  );
}

function TargetResourcesRow({ resources }: { resources: string[] }): JSX.Element {
  return (
    <div className="flex flex-col gap-1.5" data-testid="tags-target-resources">
      <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted">
        Target resources
      </span>
      <div className="flex flex-wrap items-center gap-1.5">
        {resources.map((resource, idx) => (
          <Pill
            key={`${idx}-${resource}`}
            tone="muted"
            outline
            size="xs"
            uppercase={false}
            testId="tags-pill-target"
            className="font-mono"
          >
            <span title={resource}>{truncate(resource, 32)}</span>
          </Pill>
        ))}
      </div>
    </div>
  );
}

function SemanticArgsTable({
  args,
}: {
  args: Record<string, unknown>;
}): JSX.Element {
  const [expanded, setExpanded] = useState(false);
  const keys = Object.keys(args).sort();
  return (
    <div
      data-testid="tags-semantic-args"
      className="overflow-hidden rounded border border-r5e-border"
    >
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-center justify-between border-b border-r5e-border bg-r5e-surface px-2.5 py-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted hover:text-r5e-text"
        aria-expanded={expanded}
        data-testid="tags-semantic-args-toggle"
      >
        <span>semantic_args ({keys.length})</span>
        {expanded ? (
          <ChevronDown className="h-3 w-3" aria-hidden="true" />
        ) : (
          <ChevronRight className="h-3 w-3" aria-hidden="true" />
        )}
      </button>
      {expanded && (
        <dl className="divide-y divide-r5e-border">
          {keys.map((k) => (
            <div
              key={k}
              className="grid grid-cols-[140px_1fr] gap-x-3 px-2.5 py-1.5"
            >
              <dt className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted">
                {k}
              </dt>
              <dd className="font-mono text-[11px] text-r5e-text">
                {renderValue(args[k])}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function renderValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}
