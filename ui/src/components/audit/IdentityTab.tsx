// IdentityTab — vertical scrolling stack matching the canonical
// `MdEKl > drawer > scrollContent` frame in design/r5e-enterprise-audit-ui.pen.
//
// Five stacked sections (top → bottom):
//   1. PRINCIPAL          (cyan accent header + bordered KV grid)
//   2. REQUEST SUMMARY    (purple accent header + surface-card narrative)
//   3. POLICY DECISION    (pink accent header + decision-tinted callout)
//   4. DRAFT POLICY CTA   (purple→pink gradient + pre-filled forbid block)
//   5. CRYPTOGRAPHIC PROOF (cyan accent header + compact 4-row status grid)
//
// Pre-rewrite this was a flat `<dl>` envelope-field dump (matched the
// brief at design/briefs/03-receipt-drawer.md, but the brief was a
// simplification of the canonical .pen frame). Live verification on
// audit-dev (May 2026) caught the divergence: the brief never matched
// the .pen, every implementation since followed the brief, and every
// GAN review compared against the brief — so the gap shipped four
// times in a row across F004's redesign waves.
//
// New rule: the .pen frame is the canonical for every visual surface.
// Briefs are derived implementation notes; if they diverge from the
// .pen, the .pen wins.

import { Check, ShieldAlert, Sparkles } from "lucide-react";
import type { ReactNode } from "react";
import { useNavigate } from "react-router-dom";

import type { ReceiptDetail as ReceiptDetailData } from "~/hooks/useReceiptDetail";
import { displayPrincipal } from "~/lib/displayField";
import { routes, stripBasename } from "~/lib/routes";

interface Props {
  data: ReceiptDetailData;
}

export function IdentityTab({ data }: Props): JSX.Element {
  const sp = data.signed_predicate;
  const oc = data.outer_container;
  const principalDetail = sp.principal_detail;
  return (
    <div
      data-testid="identity-tab"
      className="flex flex-col gap-5"
    >
      <PrincipalSection
        kind={principalDetail?.kind ?? readPrincipalKind(sp.principal)}
        accountId={principalDetail?.subject ?? displayPrincipal(sp.principal)}
        tenant={sp.tenant_id}
        sessionId={sp.session_id}
        verification={oc.verification_level}
      />
      <RequestSummarySection data={data} />
      <PolicyDecisionSection
        data={data}
      />
      <DraftPolicyCTA runId={sp.run_id ?? data.run_id} data={data} />
      <CryptographicProofSection data={data} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section 1 — PRINCIPAL
// ---------------------------------------------------------------------------

function PrincipalSection({
  kind,
  accountId,
  tenant,
  sessionId,
  verification,
}: {
  kind: string;
  accountId: string;
  tenant: string | null | undefined;
  sessionId: string | null | undefined;
  verification: string | null | undefined;
}): JSX.Element {
  return (
    <section
      data-testid="identity-principal-section"
      className="flex flex-col gap-2.5"
    >
      <SectionHeader label="PRINCIPAL" tone="cyan" />
      <div className="overflow-hidden rounded-r5e-md border border-r5e-border-subtle">
        <KvRow label="kind" value={kind} primary={false} />
        <KvRow label="account_id" value={accountId} primary />
        <KvRow label="tenant" value={tenant ?? "—"} primary={false} />
        <KvRow label="session_id" value={sessionId ?? "—"} primary={false} />
        <KvRow
          label="verification"
          value={
            <VerificationPill
              level={verification ?? "unknown"}
            />
          }
          primary={false}
          isLast
        />
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Section 2 — REQUEST SUMMARY
// ---------------------------------------------------------------------------

function RequestSummarySection({
  data,
}: {
  data: ReceiptDetailData;
}): JSX.Element {
  const summary = buildRequestSummary(data);
  return (
    <section
      data-testid="identity-request-section"
      className="flex flex-col gap-2.5"
    >
      <SectionHeader label="REQUEST SUMMARY" tone="purple" />
      <div className="rounded-r5e-md border border-r5e-border-subtle bg-r5e-surface-card px-4 py-3">
        <p className="text-[13px] font-medium text-r5e-foreground-primary">
          {summary.title}
        </p>
        {summary.subtitle && (
          <p className="mt-1.5 font-mono text-[11px] text-r5e-foreground-muted">
            {summary.subtitle}
          </p>
        )}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Section 3 — POLICY DECISION
// ---------------------------------------------------------------------------

function PolicyDecisionSection({
  data,
}: {
  data: ReceiptDetailData;
}): JSX.Element {
  const decision = data.outer_container.policy_decision;
  const ruleName = ruleNameFor(data);
  const cedarSource = data.matched_policy?.source_excerpt ?? null;
  const isDeny = decision === "deny";
  const isAllow = decision === "allow";
  const cardClass = isDeny
    ? "border-r5e-chart-denied bg-[#EF444410]"
    : isAllow
      ? "border-r5e-accent-green bg-[#28C84010]"
      : "border-r5e-border-subtle bg-r5e-surface-card";
  const verdictColor = isDeny
    ? "text-r5e-chart-denied"
    : isAllow
      ? "text-r5e-accent-green"
      : "text-r5e-foreground-muted";
  return (
    <section
      data-testid="identity-policy-section"
      className="flex flex-col gap-2.5"
    >
      <SectionHeader label="POLICY DECISION" tone="pink" />
      {isDeny ? (
        <DeniedPolicyCallout
          ruleName={ruleName}
          cedarSource={cedarSource}
          sourceLocation={policySourceLocation(data)}
        />
      ) : (
        <div className={`flex flex-col gap-2 rounded-r5e-md border px-4 py-3 ${cardClass}`}>
          <div className="flex items-center gap-2">
            <span
              data-testid="identity-policy-verdict"
              className={`font-mono text-[13px] font-bold ${verdictColor}`}
            >
              {isAllow ? "ALLOW" : "—"}
            </span>
            {ruleName && (
              <span className="font-mono text-[11px] text-r5e-foreground-muted">
                — {ruleName}
              </span>
            )}
          </div>
          {cedarSource ? (
            <pre
              data-testid="identity-policy-source"
              className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-[10px] text-r5e-foreground-secondary"
            >
              {cedarSource}
            </pre>
          ) : (
            <p className="font-mono text-[10px] italic text-r5e-foreground-muted">
              No matched-policy source on this receipt yet.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function DeniedPolicyCallout({
  ruleName,
  cedarSource,
  sourceLocation,
}: {
  ruleName: string | null;
  cedarSource: string | null;
  sourceLocation: string | null;
}): JSX.Element {
  return (
    <div
      data-testid="identity-deny-callout"
      className="flex flex-col gap-3 rounded-r5e-md border border-r5e-chart-denied/70 bg-r5e-chart-denied/10 px-4 py-3"
    >
      <div className="flex items-start gap-2">
        <ShieldAlert
          className="mt-0.5 h-4 w-4 shrink-0 text-r5e-chart-denied"
          aria-hidden="true"
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-r5e-chart-denied">
              Policy rule
            </span>
            <span
              data-testid="identity-policy-verdict"
              className="font-mono text-[13px] font-bold text-r5e-chart-denied"
            >
              DENY
            </span>
          </div>
          <p className="mt-1 font-mono text-[12px] text-r5e-foreground-primary">
            {ruleName ?? "matched_policy"} blocks this receipt.
          </p>
          {sourceLocation && (
            <p
              data-testid="identity-policy-source-location"
              className="mt-1 break-all font-mono text-[10px] text-r5e-foreground-muted"
            >
              {sourceLocation}
            </p>
          )}
        </div>
      </div>
      {cedarSource ? (
        <pre
          data-testid="identity-policy-source"
          className="max-h-40 overflow-auto rounded-r5e-sm border border-r5e-chart-denied/30 bg-r5e-bg/70 px-3 py-2 whitespace-pre-wrap break-words font-mono text-[10px] text-r5e-foreground-secondary"
        >
          {cedarSource}
        </pre>
      ) : (
        <p className="font-mono text-[10px] italic text-r5e-foreground-muted">
          No matched-policy source on this receipt yet.
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section 4 — DRAFT POLICY CTA
// ---------------------------------------------------------------------------

function DraftPolicyCTA({
  runId,
  data,
}: {
  runId: string;
  data: ReceiptDetailData;
}): JSX.Element {
  const navigate = useNavigate();
  const draftSkeleton = buildDraftSkeleton(data);
  const target = `${stripBasename(routes.policySimulator)}?mode=draft&run_id=${encodeURIComponent(runId)}`;
  return (
    <section
      data-testid="identity-draft-cta"
      className="rounded-r5e-lg border border-r5e-border-accent bg-gradient-to-b from-[#A855F714] to-[#EC489910] p-4"
    >
      <div className="flex items-center gap-2">
        <Sparkles className="h-4 w-4 text-r5e-accent-purple" aria-hidden="true" />
        <span className="text-[13px] font-semibold text-r5e-foreground-primary">
          Draft policy from this receipt
        </span>
      </div>
      <p className="mt-1.5 text-[11px] text-r5e-foreground-secondary">
        Pre-filled from extracted fields:
      </p>
      <pre
        data-testid="identity-draft-skeleton"
        className="mt-2.5 rounded-r5e-sm bg-r5e-surface-elevated px-2.5 py-2 font-mono text-[10px] leading-relaxed"
      >
        <span className="text-r5e-accent-purple">forbid(</span>
        {"\n"}
        <span className="text-r5e-accent-cyan">{`  category = ${draftSkeleton.category}`}</span>
        {draftSkeleton.condition && (
          <>
            {"\n"}
            <span className="text-r5e-accent-amber">{`  when ${draftSkeleton.condition}`}</span>
          </>
        )}
        {"\n"}
        <span className="text-r5e-accent-purple">{");"}</span>
      </pre>
      <div className="mt-3 flex justify-end gap-2">
        <button
          type="button"
          data-testid="identity-draft-customize"
          onClick={() => navigate(target)}
          className="rounded-r5e-md border border-r5e-border-strong px-3 py-1.5 font-mono text-[11px] text-r5e-foreground-secondary hover:border-r5e-accent-purple hover:text-r5e-foreground-primary"
        >
          Customize
        </button>
        <button
          type="button"
          data-testid="identity-draft-adopt"
          onClick={() => navigate(target)}
          className="rounded-r5e-md bg-gradient-to-b from-r5e-accent-purple to-r5e-accent-pink px-3 py-1.5 font-mono text-[11px] font-semibold text-white hover:opacity-90"
        >
          Adopt
        </button>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Section 5 — CRYPTOGRAPHIC PROOF
// ---------------------------------------------------------------------------

function CryptographicProofSection({
  data,
}: {
  data: ReceiptDetailData;
}): JSX.Element {
  const sp = data.signed_predicate;
  const oc = data.outer_container;
  const verification = oc.verification_level ?? "";
  const sigStatus =
    verification.includes("signed") || verification.includes("verified")
      ? "ok"
      : verification === ""
        ? "pending"
        : "ok";
  const localStatus = oc.session_chain_root ? "ok" : "pending";
  const globalStatus = verification === "global_inclusion_verified" ? "ok" : "pending";
  return (
    <section
      data-testid="identity-proof-section"
      className="flex flex-col gap-2.5"
    >
      <SectionHeader label="CRYPTOGRAPHIC PROOF" tone="cyan" />
      <div className="overflow-hidden rounded-r5e-md border border-r5e-border-subtle">
        <ProofRow label="signature" status={sigStatus} text="ES256 / KMS" />
        <ProofRow label="merkle_local" status={localStatus} text="session chain" />
        <ProofRow label="merkle_global" status={globalStatus} text="global ledger" />
        <ProofRow
          label="payload_hash"
          status="value"
          text={truncateHash(sp.payload_hash)}
          isLast
        />
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

function SectionHeader({
  label,
  tone,
}: {
  label: string;
  tone: "cyan" | "purple" | "pink";
}): JSX.Element {
  const color =
    tone === "cyan"
      ? "text-r5e-accent-cyan"
      : tone === "purple"
        ? "text-r5e-accent-purple"
        : "text-r5e-accent-pink";
  return (
    <h3
      className={`font-mono text-[10px] font-semibold uppercase ${color}`}
      style={{ letterSpacing: "0.16em" }}
    >
      {label}
    </h3>
  );
}

function KvRow({
  label,
  value,
  primary,
  isLast = false,
}: {
  label: string;
  value: ReactNode;
  primary: boolean;
  isLast?: boolean;
}): JSX.Element {
  const valueColor = primary
    ? "text-r5e-foreground-primary"
    : "text-r5e-foreground-secondary";
  return (
    <div
      className={`flex h-8 items-center px-3 ${
        isLast ? "" : "border-b border-r5e-border-subtle"
      }`}
    >
      <span className="w-40 shrink-0 font-mono text-[11px] font-semibold text-r5e-foreground-muted">
        {label}
      </span>
      <span className={`min-w-0 flex-1 truncate font-mono text-[11px] ${valueColor}`}>
        {value}
      </span>
    </div>
  );
}

function VerificationPill({ level }: { level: string }): JSX.Element {
  const verified = level === "global_inclusion_verified" || level.includes("verified");
  return (
    <span
      data-testid="identity-verification-pill"
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[10px] ${
        verified
          ? "bg-[#28C84015] text-r5e-accent-green"
          : "bg-r5e-surface-hover text-r5e-foreground-muted"
      }`}
    >
      {verified && <Check className="h-3 w-3" aria-hidden="true" />}
      {level}
    </span>
  );
}

function ProofRow({
  label,
  status,
  text,
  isLast = false,
}: {
  label: string;
  status: "ok" | "pending" | "value";
  text: string;
  isLast?: boolean;
}): JSX.Element {
  const statusBadge =
    status === "ok" ? (
      <span className="inline-flex items-center gap-1 text-r5e-accent-green">
        <Check className="h-3 w-3" aria-hidden="true" />
        <span className="font-mono text-[10px]">{text}</span>
      </span>
    ) : status === "pending" ? (
      <span className="font-mono text-[10px] italic text-r5e-foreground-muted">
        pending — {text}
      </span>
    ) : (
      <span className="font-mono text-[10px] text-r5e-foreground-secondary">
        {text}
      </span>
    );
  return (
    <div
      className={`flex h-7 items-center px-2.5 ${
        isLast ? "" : "border-b border-r5e-border-subtle"
      }`}
    >
      <span className="w-32 shrink-0 font-mono text-[10px] font-semibold text-r5e-foreground-muted">
        {label}
      </span>
      <span className="min-w-0 flex-1 truncate">{statusBadge}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Derivation helpers
// ---------------------------------------------------------------------------

function readPrincipalKind(
  principal: ReceiptDetailData["signed_predicate"]["principal"],
): string {
  if (principal && typeof principal === "object" && "kind" in principal) {
    return (principal as { kind?: string }).kind ?? "—";
  }
  return "—";
}

interface RequestSummary {
  title: string;
  subtitle: string | null;
}

/**
 * Derive a one-line "what was this request" sentence from the receipt's
 * extracted tags. The canonical example (deny case) is:
 *   title:    "curl subprocess — network egress to external API"
 *   subtitle: "Target: https://ext.api/exfil · Method: GET · Flags: -s (silent)"
 *
 * Live receipts vary widely; we fall back to `tool_summary` (when the
 * extractor gave us a one-liner) and then to a synthesized
 * "{verb} {tool_kind}" pattern.
 */
function buildRequestSummary(data: ReceiptDetailData): RequestSummary {
  const tags = (data.outer_container.tags ?? {}) as Record<string, unknown>;
  const toolKind = (tags.tool_kind as string | undefined) ?? null;
  const verb = (tags.verb as string | undefined) ?? null;
  const argument = (tags.argument_body as string | undefined) ?? null;
  const displaySummary = (tags.display_summary as string | undefined) ?? null;

  const title =
    displaySummary ??
    (verb && toolKind ? `${verb} ${toolKind}` : verb ?? toolKind ?? "Unattested action");

  const subtitleParts: string[] = [];
  const semantic = (tags.semantic_args as Record<string, unknown> | undefined) ?? null;
  if (semantic && typeof semantic === "object") {
    if (semantic.host) subtitleParts.push(`Host: ${String(semantic.host)}`);
    if (semantic.method) subtitleParts.push(`Method: ${String(semantic.method)}`);
    if (semantic.target_url) subtitleParts.push(`Target: ${String(semantic.target_url)}`);
    if (semantic.server) subtitleParts.push(`Server: ${String(semantic.server)}`);
    if (semantic.tool) subtitleParts.push(`Tool: ${String(semantic.tool)}`);
  }
  if (subtitleParts.length === 0 && argument) {
    subtitleParts.push(argument.length > 120 ? argument.slice(0, 117) + "…" : argument);
  }
  return {
    title,
    subtitle: subtitleParts.length > 0 ? subtitleParts.join(" · ") : null,
  };
}

interface DraftSkeleton {
  category: string;
  condition: string | null;
}

/**
 * Construct the pre-filled `forbid(...)` skeleton shown in the canonical
 * Draft Policy CTA. Real Cedar synthesis lives in the Simulator's
 * `useDraftFromReceipt` hook; this is a TEASER preview only — clicking
 * Customize/Adopt navigates to the simulator where the full draft is
 * generated.
 */
function buildDraftSkeleton(data: ReceiptDetailData): DraftSkeleton {
  const tags = (data.outer_container.tags ?? {}) as Record<string, unknown>;
  const category = (tags.category as string | undefined) ?? "tool_call";
  const semantic = (tags.semantic_args as Record<string, unknown> | undefined) ?? null;
  let condition: string | null = null;
  if (semantic && typeof semantic === "object") {
    if (semantic.host) condition = `url.host != "*.internal"`;
    else if (semantic.server) condition = `mcp_server == "${String(semantic.server)}"`;
    else if (semantic.outside_workdir === true)
      condition = `path outside workdir`;
  }
  if (!condition) {
    const verb = (tags.verb as string | undefined) ?? null;
    if (verb) condition = `verb == "${verb}"`;
  }
  return { category, condition };
}

function ruleNameFor(data: ReceiptDetailData): string | null {
  const file = data.matched_policy?.file ?? null;
  if (!file) return null;
  // Extract a friendly rule name from the file path:
  //   workspace/.r5e/policies/network-egress-policy.cedar → network_egress_policy
  const base = file.split("/").pop() ?? file;
  return base.replace(/\.(cedar|yaml|yml)$/, "").replace(/-/g, "_");
}

function policySourceLocation(data: ReceiptDetailData): string | null {
  const policy = data.matched_policy;
  if (!policy?.file) return null;
  if (policy.line_start !== null && policy.line_start !== undefined) {
    return `${policy.file}:${policy.line_start}`;
  }
  return policy.file;
}

function truncateHash(hash: string | null): string {
  if (!hash) return "—";
  if (hash.length <= 24) return hash;
  return `${hash.slice(0, 16)}…${hash.slice(-4)}`;
}
