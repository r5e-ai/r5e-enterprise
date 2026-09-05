# Contract: Audit Console SBOM Facet

**Modules**: `ui/src/components/audit/ReceiptDrawerSbomFacet.tsx`, `DependencyTreeView.tsx`, `BlastRadiusResultTable.tsx`, `ui/src/lib/sbomApi.ts`
**Owner phase**: Phase 6 (UI)
**Consumed by**: Audit-console operator workflow (no downstream module consumers — UI is a leaf)

## Purpose

Surface SBOM data in the existing F004 audit console:

1. **Receipt-drawer SBOM facet**: collapsible facet showing SBOM digest + top-level dep summary + drill-link
2. **Dependency tree view**: virtualized full-tree drill-down with search + expand/collapse + "show transitive only" filter
3. **Blast-radius result table**: paginated table of affected binaries from a CVE blast-radius query

## Component contracts

### ReceiptDrawerSbomFacet.tsx

**Props**:
```ts
interface ReceiptDrawerSbomFacetProps {
  sbomDigest: string;        // SHA-256 hex
  sbomSpecVersion: "1.4" | "1.5" | "1.6";
  arch: string;
  bindingPredicates: BindingPredicateSummary[]; 
  componentCount: number;
  edgeCount: number;
  maxDepth: number;
  hasCycles: boolean;
  topLevelComponents: { name: string; version: string; ecosystem: string }[];  // first ~10
  onDrillFullTree: () => void;
}

interface BindingPredicateSummary {
  attestedBy: "customer" | "recurse_managed" | "vendor";
  attestedBySubject: string;
  verifiedAt: string | null;
  verificationStatus: "verified" | "unverified" | "verification_failed";
}
```

**Visual contract**:

- Collapsed by default; renders header only (digest abbreviation + binding count + "Dep tree (N components, depth M)")
- Expanded: shows up to 10 top-level deps in a list with their ecosystem badges
- Each binding predicate displays: source icon (customer / Recurse / vendor) + verification status badge (✓ verified / ⚠ unverified / ✗ failed) + subject in monospace
- "Drill into full tree →" button at bottom; click triggers `onDrillFullTree`
- Cycle warning banner if `hasCycles: true`

**Performance contract**: First-paint of facet (closed state) <50ms; expanded state <150ms.

### DependencyTreeView.tsx

**Props**:
```ts
interface DependencyTreeViewProps {
  sbomPublicationId: number;
  sbomDigest: string;
  arch: string;
  onClose: () => void;
}
```

**Visual contract**:

- Modal overlay (full-screen on small viewports, large drawer on desktop)
- Top bar: search input + filter toggles ("Production only" / "Show transitive") + close button
- Body: virtualized tree rows (per `@tanstack/react-virtual`); only visible rows render
- Each row: indent per depth + component name + version + ecosystem badge + "Has CVE" indicator (if any open advisory matches)
- Expand-collapse per row (toggle children); root rows expanded by default
- Lazy-load: child trees fetched on first expand (initial load returns root + depth-1 only)

**Performance contract**:

- Initial render (root + depth-1 only) <300ms regardless of full SBOM size
- Expand-row latency <200ms (lazy-load children from `GET /v1/api/capabilities/query_sbom`)
- Search filter debounced 200ms; filter execution <100ms over 5000-component SBOM

### BlastRadiusResultTable.tsx

**Props**:
```ts
interface BlastRadiusResultTableProps {
  advisory: AdvisoryInput;
  result: BlastRadiusResult | null;  // null = loading
  onRefresh: () => void;
  onJumpToBinary: (sbomPublicationId: number) => void;
}

interface AdvisoryInput {
  cveId: string;
  componentName: string;
  ecosystem: string;
  affectedRange: string;
  patchedIn?: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
}

interface BlastRadiusResult {
  queryId: number;
  affected: AffectedBinary[];
  unaffectedCount: number;
  totalSbomsScanned: number;
  elapsedMs: number;
}

interface AffectedBinary {
  sbomPublicationId: number;
  binaryIdentity: string;
  arch: string;
  affectedComponents: { componentDigest: string; componentVersion: string; depthFromRoot: number }[];
  hasPatchedPath: boolean;
  lastActionAt: string | null;
  actionCount7d: number;
}
```

**Visual contract**:

- Table columns: severity badge, binary identity (truncated, monospace), arch, depth (sorted asc per defaul), action count (7d), patched path indicator, "Jump to binary" button
- Sort: by `(severity desc, action_count_7d desc, depth asc)` per default; user can click any column to re-sort
- Empty state: "No affected binaries found." with "Total SBOMs scanned: N" footer
- Loading state: skeleton rows; "Querying..." indicator
- Error state: structured error message + retry button

**Performance contract**: Table renders in <100ms after `result` prop populates; pagination at 50 rows per page.

## API client (sbomApi.ts)

```ts
export const sbomApi = {
  getPublication(digest: string, arch: string): Promise<SbomPublication>,
  
  getFullTree(publicationId: number, opts: { 
    maxDepth?: number; 
    includeDev?: boolean; 
    rootOnly?: boolean   // if true, only return depth-0 + 1
  }): Promise<{ nodes: ComponentNode[]; edges: EdgeRef[] }>,
  
  getComponentSubtree(publicationId: number, rootDigest: string, opts: {
    maxDepth?: number;
  }): Promise<{ nodes: ComponentNode[]; edges: EdgeRef[] }>,
  
  queryBlastRadius(advisory: AdvisoryInput): Promise<BlastRadiusResult>
};
```

The client wraps `GET /v1/api/capabilities/query_sbom` and `POST /v1/api/capabilities/blast_radius_query` (the API substrate exposes these as capabilities; consumed both via REST here AND via MCP from Spec A's Recurse-as-MCP-server adapter).

## Contract tests (Vitest)

- **CT-001**: `ReceiptDrawerSbomFacet` renders collapsed-state with correct header text given known props.
- **CT-002**: Expanding facet renders top-level deps; click on "Drill into full tree" calls `onDrillFullTree`.
- **CT-003**: `DependencyTreeView` renders root + depth-1 on first render; expanding a row triggers an additional API call for child subtree.
- **CT-004**: `BlastRadiusResultTable` sorts correctly per default order; user-click on a column header re-sorts.

## Integration tests (Playwright)

- **IT-001**: End-to-end — open audit console → navigate to a receipt with attested SBOM → SBOM facet renders → click drill → tree view opens → expand 3 levels → close → blast-radius UI → enter known CVE → table populates with affected binaries → click "Jump to binary" → navigates to binary's receipt list.

## Performance metrics

| Metric | Target | Measured how |
|--------|--------|--------------|
| Receipt drawer SBOM facet first-paint | <50ms | React Profiler in dev |
| Dep tree initial render (root + depth-1) | <300ms | React Profiler |
| Dep tree expand-row | <200ms | Manual timing in Playwright |
| Blast-radius table render after result loads | <100ms | React Profiler |

## Dependencies

- F004 component library (existing) — reuse drawer scaffolding, badge components, table primitives
- `@tanstack/react-virtual` — virtualization (lighter alternative to `react-window` / `react-virtualized`)
- Existing `useQuery` (TanStack Query) for API state management — consistent with rest of audit console

## Out of scope for V1

- License compliance dashboard (per research Q-B)
- VEX statement display (per research Q-C)
- Diff between two SBOM versions (potential V2 addition; not blocking)
- Per-component CVE history list (just the "has any open CVE" badge in V1)
