// ProofTab — 2-column DSSE-signature + Merkle-inclusion summary for the
// Receipt Drawer's PROOF tab (R2 redesign).
//
// Per `design/briefs/03-receipt-drawer.md`:
//
//   Left — DSSE signature
//     ALGORITHM, SIGNER KMS KEY ARN, KEY VERSION, SIGNATURE (truncated),
//     PAYLOAD HASH (truncated, click to expand)
//
//   Right — Merkle inclusion
//     SESSION CHAIN EPOCH, SESSION CHAIN ROOT, LOCAL INCLUSION PROOF (N steps),
//     GLOBAL INCLUSION PROOF (present/absent), TIER COMPLETENESS
//
// Below: small visual of the inclusion proof path (hash steps as nodes).
//
// Pure presentational; takes the full ReceiptDetail so it can pull from
// signed_predicate (DSSE side) AND outer_container (epoch/tier) AND proof
// (Merkle path).

import { useState } from "react";

import type { ReceiptDetail as ReceiptDetailData } from "~/hooks/useReceiptDetail";

interface Props {
  data: ReceiptDetailData;
}

const VIEWBOX_WIDTH = 600;
const VIEWBOX_HEIGHT = 200;
const NODE_R = 7;

export function ProofTab({ data }: Props): JSX.Element {
  const sp = data.signed_predicate;
  const oc = data.outer_container;
  const proof = data.proof ?? null;

  return (
    <div className="flex flex-col gap-4" data-testid="proof-tab">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <DsseColumn
          algorithm="ES256"
          signerKmsKey={sp.signer_kms_key_id}
          keyVersion={sp.signer_key_version}
          payloadHash={sp.payload_hash}
        />
        <MerkleColumn
          epoch={oc.session_chain_epoch}
          sessionRoot={oc.session_chain_root}
          leafHash={proof?.leaf_hash ?? null}
          localPathLen={proof?.local_path?.length ?? 0}
          globalPresent={!!proof?.global_root}
          tierAdvisory={oc.tier_completeness_advisory}
        />
      </div>

      {proof && (
        <ProofPathVisual
          leafHash={proof.leaf_hash}
          epochRoot={proof.epoch_root ?? null}
          globalRoot={proof.global_root ?? null}
          localPath={proof.local_path ?? []}
          globalPath={proof.global_path ?? []}
        />
      )}

      {!proof && (
        <div className="flex h-32 items-center justify-center rounded border border-r5e-border bg-r5e-surface text-xs text-r5e-muted">
          No proof envelope available for this receipt.
        </div>
      )}

      {proof?.sth && (
        <div className="rounded border border-r5e-border bg-r5e-surface p-3">
          <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted">
            RFC 9162 STH (signed tree head)
          </div>
          <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px] text-r5e-text">
            {proof.sth}
          </pre>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// DSSE column (left)
// ---------------------------------------------------------------------------

function DsseColumn({
  algorithm,
  signerKmsKey,
  keyVersion,
  payloadHash,
}: {
  algorithm: string;
  signerKmsKey: string | null;
  keyVersion: string | null;
  payloadHash: string | null;
}): JSX.Element {
  // The DSSE signature bytes themselves (ES256 DER, ~71 bytes) aren't yet on
  // the wire — the receipt detail response carries the leaf hash and the
  // payload hash but not the raw signature. The signature row will land when
  // the detail-response schema sweep (#50) adds `dsse_signature_b64`. Until
  // then we surface the DSSE-side facts the wire DOES expose: algorithm,
  // signer KMS key + version, and the canonical payload hash that the
  // signature is computed over. Verify Locally is the auditor's
  // signature-validation surface today.
  return (
    <section
      className="flex flex-col gap-2 rounded border border-r5e-border bg-r5e-surface p-3"
      data-testid="proof-dsse-column"
    >
      <h3 className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted">
        DSSE signature
      </h3>
      <ProofRow label="Algorithm" value={algorithm} />
      <ProofRow label="Signer KMS key" value={signerKmsKey} breakAll />
      <ProofRow label="Key version" value={keyVersion} />
      <ExpandableHashRow label="Payload hash" value={payloadHash} />
    </section>
  );
}

// ---------------------------------------------------------------------------
// Merkle column (right)
// ---------------------------------------------------------------------------

function MerkleColumn({
  epoch,
  sessionRoot,
  leafHash,
  localPathLen,
  globalPresent,
  tierAdvisory,
}: {
  epoch: number | null;
  sessionRoot: string | null;
  leafHash: string | null;
  localPathLen: number;
  globalPresent: boolean;
  tierAdvisory: string | null;
}): JSX.Element {
  return (
    <section
      className="flex flex-col gap-2 rounded border border-r5e-border bg-r5e-surface p-3"
      data-testid="proof-merkle-column"
    >
      <h3 className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted">
        Merkle inclusion
      </h3>
      <ProofRow
        label="Session chain epoch"
        value={epoch != null ? String(epoch) : null}
      />
      <ExpandableHashRow label="Leaf hash" value={leafHash} />
      <ExpandableHashRow label="Session chain root" value={sessionRoot} />
      <ProofRow
        label="Local inclusion proof"
        value={`${localPathLen} step${localPathLen === 1 ? "" : "s"}`}
      />
      <ProofRow
        label="Global inclusion proof"
        value={globalPresent ? "present" : "pending"}
      />
      <ProofRow label="Tier completeness" value={tierAdvisory} />
    </section>
  );
}

function ProofRow({
  label,
  value,
  breakAll = false,
}: {
  label: string;
  value: string | null | undefined;
  breakAll?: boolean;
}): JSX.Element {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-x-3 text-[11px]">
      <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-r5e-muted">
        {label}
      </span>
      <span
        className={`font-mono text-r5e-text ${breakAll ? "break-all" : "truncate"}`}
        title={typeof value === "string" ? value : undefined}
      >
        {value ?? "—"}
      </span>
    </div>
  );
}

function ExpandableHashRow({
  label,
  value,
}: {
  label: string;
  value: string | null | undefined;
}): JSX.Element {
  const [expanded, setExpanded] = useState(false);
  if (value == null || value === "") {
    return <ProofRow label={label} value={null} />;
  }
  const truncated =
    value.length > 24 ? `${value.slice(0, 16)}…${value.slice(-6)}` : value;
  return (
    <div className="grid grid-cols-[140px_1fr] gap-x-3 text-[11px]">
      <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-r5e-muted">
        {label}
      </span>
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="text-left font-mono text-r5e-text hover:text-r5e-accent"
        aria-expanded={expanded}
        title={expanded ? "Click to collapse" : "Click to expand"}
      >
        <span className={expanded ? "break-all" : "truncate"}>
          {expanded ? value : truncated}
        </span>
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Inclusion proof visual (SVG path)
// ---------------------------------------------------------------------------

function ProofPathVisual({
  leafHash,
  epochRoot,
  globalRoot,
  localPath,
  globalPath,
}: {
  leafHash: string;
  epochRoot: string | null;
  globalRoot: string | null;
  localPath: Array<{ sibling: string; direction: "left" | "right" }>;
  globalPath: Array<{ sibling: string; direction: "left" | "right" }>;
}): JSX.Element {
  const leftX = 80;
  const siblingX = 240;
  const yLeaf = 24;
  const yEpoch = VIEWBOX_HEIGHT / 2;
  const yGlobal = VIEWBOX_HEIGHT - 24;

  return (
    <div className="rounded border border-r5e-border bg-r5e-surface p-3">
      <div className="mb-2 font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted">
        Inclusion path
      </div>
      <svg
        viewBox={`0 0 ${VIEWBOX_WIDTH} ${VIEWBOX_HEIGHT}`}
        role="img"
        aria-label="Merkle inclusion proof"
        className="h-[200px] w-full"
      >
        <line
          x1={leftX}
          y1={yLeaf}
          x2={leftX}
          y2={yEpoch}
          stroke="currentColor"
          className="text-r5e-accent"
          strokeWidth="1.5"
        />
        <line
          x1={leftX}
          y1={yEpoch}
          x2={leftX}
          y2={yGlobal}
          stroke="currentColor"
          className="text-r5e-accent"
          strokeWidth="1.5"
          strokeDasharray={globalRoot ? undefined : "4 4"}
        />
        <PathNode x={leftX} y={yLeaf} label="leaf" hash={leafHash} />
        <PathNode x={leftX} y={yEpoch} label="epoch root" hash={epochRoot} />
        <PathNode
          x={leftX}
          y={yGlobal}
          label={globalRoot ? "global root" : "global root (pending)"}
          hash={globalRoot}
        />
        {localPath.map((sib, idx) => {
          const y =
            yLeaf + ((yEpoch - yLeaf) * (idx + 1)) / (localPath.length + 1);
          return (
            <SiblingNode
              key={`local-${idx}`}
              x={siblingX}
              y={y}
              anchorX={leftX}
              hash={sib.sibling}
              direction={sib.direction}
            />
          );
        })}
        {globalPath.map((sib, idx) => {
          const y =
            yEpoch +
            ((yGlobal - yEpoch) * (idx + 1)) / (globalPath.length + 1);
          return (
            <SiblingNode
              key={`global-${idx}`}
              x={siblingX}
              y={y}
              anchorX={leftX}
              hash={sib.sibling}
              direction={sib.direction}
            />
          );
        })}
      </svg>
    </div>
  );
}

function PathNode({
  x,
  y,
  label,
  hash,
}: {
  x: number;
  y: number;
  label: string;
  hash: string | null;
}): JSX.Element {
  const truncated = hash ? `${hash.slice(0, 10)}…${hash.slice(-6)}` : "—";
  return (
    <g>
      <circle
        cx={x}
        cy={y}
        r={NODE_R}
        fill="currentColor"
        className="text-r5e-accent"
      >
        {hash && <title>{hash}</title>}
      </circle>
      <text
        x={x + NODE_R + 6}
        y={y + 4}
        className="fill-r5e-text font-mono text-[10px]"
      >
        {label}
      </text>
      <text
        x={x + NODE_R + 6}
        y={y + 16}
        className="fill-r5e-muted font-mono text-[9px]"
      >
        {truncated}
      </text>
    </g>
  );
}

function SiblingNode({
  x,
  y,
  anchorX,
  hash,
  direction,
}: {
  x: number;
  y: number;
  anchorX: number;
  hash: string;
  direction: "left" | "right";
}): JSX.Element {
  const truncated = `${hash.slice(0, 8)}…`;
  return (
    <g>
      <line
        x1={anchorX}
        y1={y}
        x2={x}
        y2={y}
        stroke="currentColor"
        className="text-r5e-border"
        strokeWidth="1"
      />
      <circle
        cx={x}
        cy={y}
        r={NODE_R - 2}
        fill="currentColor"
        className="text-r5e-muted"
      >
        <title>{`sibling (${direction}): ${hash}`}</title>
      </circle>
      <text
        x={x + NODE_R + 4}
        y={y + 4}
        className="fill-r5e-muted font-mono text-[9px]"
      >
        {truncated} · {direction}
      </text>
    </g>
  );
}
