# Contract: Frontend Architecture (SPA)

**Feature**: F004 | **Spec**: FRs 008–046 (UI surfaces) | **Research**: D1, D8, D9, D10 | **Plan**: `ui/` tree

This contract defines the Single-Page Application architecture that lives at `ui/` (top-level repo dir), builds via Vite into `apps/recurse_gateway/priv/static/admin/`, and is served by the Gateway under `/admin/*`. The SPA is the human face of every F004 user story; this document establishes the structural conventions tests assume.

---

## Folder layout

```text
ui/
├── package.json                # Dependencies + scripts; pnpm workspace root
├── tsconfig.json               # Strict mode, ES2022 target, JSX react-jsx
├── vite.config.ts              # Dev server + proxy + production build config
├── tailwind.config.ts          # GENERATED from pen-file design tokens
├── playwright.config.ts        # E2E test config; runs against `mix run --no-halt`
├── postcss.config.cjs
├── eslint.config.js
├── .gitignore                  # node_modules, dist (src/lib/types.ts is committed, NOT ignored)
├── scripts/
│   ├── generate-tailwind-config.ts   # Reads design/r5e-enterprise-audit-ui.pen export → writes tailwind.config.ts
│   └── generate-types.ts             # Reads ../apps/recurse_gateway/priv/schemas/*.json from disk → writes src/lib/types.ts
├── public/
│   ├── favicon.ico
│   └── recurse-logo.svg
├── src/
│   ├── main.tsx                # SPA entrypoint; mounts <App /> into #root
│   ├── App.tsx                 # Router shell + auth gate; wraps QueryClientProvider
│   ├── pages/
│   │   ├── Login.tsx                   # /admin/login (no auth required; form is one button: "Sign in with SSO")
│   │   ├── Dashboard.tsx                # /admin/dashboard (audit log table + histogram + filter sidebar)
│   │   ├── ReceiptDetail.tsx            # Drawer overlay (rendered inside Dashboard for visual continuity)
│   │   ├── PolicySimulator.tsx          # /admin/policy-simulator (simulate / replay / draft modes)
│   │   ├── PolicySimulatorSuggestions.tsx # /admin/policy-simulator/suggestions
│   │   └── ChatDrawer.tsx               # Side-drawer mounted on every authenticated page
│   ├── components/
│   │   ├── audit/                       # ReceiptRow, FilterFacet, Histogram, LiveTailToggle
│   │   ├── policy/                      # CedarEditor, BlastRadiusPanel, ScopePicker, ConditionBuilder
│   │   ├── chat/                        # MessageBubble, ToolCallBlock, ReferencedDataFooter
│   │   ├── shared/                      # Layout, Sidebar, ErrorBoundary, Toast, AuthGate
│   │   └── ui/                          # Button, Card, Drawer, Input, Select (pen-file-derived)
│   ├── hooks/
│   │   ├── useReceipts.ts               # Paginated audit log; TanStack Query useInfiniteQuery
│   │   ├── useReceiptDetail.ts
│   │   ├── usePolicyDrafts.ts
│   │   ├── usePolicySuggestions.ts
│   │   ├── useChatConversation.ts
│   │   ├── useLiveTail.ts               # WebSocket → TanStack Query setQueryData bridge
│   │   ├── useBlastRadius.ts
│   │   └── useAuth.ts                   # Reads /v1/auth/me; handles login redirect
│   ├── lib/
│   │   ├── api.ts                       # fetch wrapper, schema validation, error normalization
│   │   ├── auth.ts                      # Cookie-aware redirect helpers
│   │   ├── live_tail.ts                 # WebSocket client class
│   │   ├── cedar_monarch_grammar.ts     # Monaco language definition for Cedar
│   │   ├── design_tokens.ts             # Generated from pen file; consumed by tailwind.config
│   │   ├── routes.ts                    # Single source-of-truth for route paths
│   │   └── types.ts                     # GENERATED from apps/recurse_gateway/priv/schemas/*.json (committed; CI staleness-checked)
│   └── tests/
│       ├── unit/                        # Vitest component tests
│       └── e2e/                         # Playwright tests (US1–US6 coverage)
└── README.md
```

The build output (`ui/dist/*`) is copied via `pnpm run sync-to-priv` into `apps/recurse_gateway/priv/static/admin/`, which `mix release` includes.

---

## Routing

Client-side via `react-router-dom@^7`:

```typescript
// src/lib/routes.ts (single source-of-truth)
export const routes = {
  login: "/admin/login",
  dashboard: "/admin/dashboard",
  receiptDetail: "/admin/dashboard/receipts/:run_id",
  policySimulator: "/admin/policy-simulator",
  policySimulatorSuggestions: "/admin/policy-simulator/suggestions",
  chat: "/admin/chat",
} as const;
```

Routes mirror the six UI screens from the pen mockup. `ReceiptDetail` is a sub-route of `Dashboard` (rendered as a drawer overlay) so URL deep-linking works (`/admin/dashboard/receipts/uuid` opens Dashboard with the drawer pre-opened).

`/admin/chat` is a route, but the ChatDrawer component also mounts as an always-available side panel on every authenticated page (per FR-036). The route exists for direct deep-link / page-refresh scenarios.

**Route guards**: a `<RequireAuth>` wrapper component runs `useAuth()` on every protected route; if `auth.status === "unauthenticated"`, it issues a full-page redirect to the same-origin `/admin/login/start?return_to=<current-path>`. The redirect is full-page (`window.location.assign`) rather than client-side router navigation because the login flow ends in a 302 from an external IdP and the SPA must be re-bootstrapped after the cookie is set. The Gateway hosts `/admin/login/start` and `/admin/login/callback` on the same origin as the SPA — see `browser_oidc_flow.md` for the full flow.

---

## State management

| Concern | Mechanism |
|---|---|
| Server state (audit log, drafts, suggestions, chat history) | **TanStack Query** with cache invalidation per mutation |
| Filter state on the audit log | URL query parameters (deep-linkable) — synced to component state via `useSearchParams` |
| Component-local UI ephemera (modal open/closed, tooltip hover, form draft state) | React `useState` / `useReducer` |
| Live-tail receipt prepending | `queryClient.setQueryData(['receipts', filterKey], (old) => [newReceipt, ...old.pages.flat()])` |
| Browser session presence | Implicit from cookie; SPA never reads JWT directly. `useAuth` polls `/v1/auth/me` to know the principal's identity. |
| Cedar editor source | Monaco editor's internal model; persisted to TanStack Query mutation on save |

**No Redux. No Zustand. No Recoil.** Per plan.md: "TanStack Query for server state; component-local React state for UI ephemera; no Redux/Zustand for F004." The justification is that F004's UI is not a complex client-side app — it's a thin client over a server-side audit log. Adding a client-state library would be premature.

---

## Auth state model

The SPA never reads, stores, or transmits the JWT directly. The authentication state is implicit from the Session Cookie (HttpOnly, JS-invisible).

```typescript
// src/hooks/useAuth.ts
export function useAuth() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['auth', 'me'],
    queryFn: () => api.get('/v1/auth/me'),
    staleTime: 60_000,        // refresh every minute
    retry: false,             // 401 → fail fast → redirect
  });

  if (isLoading) return { status: 'loading' };
  if (error) return { status: 'unauthenticated' };
  return {
    status: 'authenticated',
    principal: data.principal_subject,
    role: data.recurse_role,    // "tenant_auditor" | "platform_operator"
    tenantId: data.tenant_id,
  };
}
```

`/v1/auth/me` is a new lightweight endpoint that returns `{principal_subject, recurse_role, tenant_id, browser_session_id}` derived from the current authenticated request. It does NOT return the JWT or any cookie content.

Sign-out: `POST /admin/logout` (per `browser_oidc_flow.md`). The SPA receives 200 + `{redirect_to}`, navigates the browser to that URL, and TanStack Query's cache is fully invalidated.

---

## Design-token bridge

Tailwind CSS is configured from the pen file's design tokens — single source of truth. A build-time script reads pen-exported variables (the design tool produces a JSON export) and generates `tailwind.config.ts`:

```typescript
// ui/scripts/generate-tailwind-config.ts
import penExport from '../../design/r5e-enterprise-audit-ui.tokens.json';

const config = {
  theme: {
    extend: {
      colors: penExport.colors,        // {primary: '#...', danger: '#...', ...}
      spacing: penExport.spacing,      // {1: '4px', 2: '8px', ...}
      fontSize: penExport.typography.sizes,
      borderRadius: penExport.radii,
      // ...
    }
  }
};

writeFileSync('tailwind.config.ts', `export default ${JSON.stringify(config, null, 2)};`);
```

The JSON export from the pen tool lives at `design/r5e-enterprise-audit-ui.tokens.json` and is committed to git (it's a static export, not the `.pen` source itself which is encrypted). The `generate-tailwind-config.ts` script runs as part of `pnpm dev` and `pnpm build`. CI runs the script + `git diff --exit-code tailwind.config.ts` to catch drift between the pen file and the Tailwind config.

This means: design system updates flow `.pen` → export → `pnpm gen:tailwind` → committed config → SPA. No hand-editing of color hex codes scattered through component CSS.

---

## Error handling

API errors are normalized to the canonical flat error envelope shape (per `apps/recurse_gateway/priv/schemas/error_envelope.json`; F001-nested retired in MR !31 / issue #30 Task L):

```typescript
// src/lib/api.ts
async function apiFetch<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, { method, body: body ? JSON.stringify(body) : null, ... });
  if (!response.ok) {
    const errorEnvelope = await response.json();
    throw new ApiError({
      error: errorEnvelope.error,
      error_description: errorEnvelope.error_description,
      correlation_id: errorEnvelope.correlation_id,
      attested_run_id: errorEnvelope.attested_run_id ?? null,
      status: response.status,
    });
  }
  const json = await response.json();
  // Runtime schema validation via zod (per D10 generation):
  return validateAgainstSchema(path, json) as T;
}
```

The `ApiError` carries the `attested_run_id` from the flat error envelope so the SPA's error UX can link to the denial receipt for forbidden errors:

```typescript
function ErrorToast({ error }: { error: ApiError }) {
  return (
    <Toast variant="error">
      <p>{error.error_description}</p>
      {error.attested_run_id && (
        <Link to={routes.receiptDetail.replace(':run_id', error.attested_run_id)}>
          View attested receipt
        </Link>
      )}
    </Toast>
  );
}
```

For 5xx errors, the SPA shows a generic "Something went wrong; the system has logged this incident as receipt {correlation_id}" — the correlation_id is the auditor's path to forensics.

---

## Live-tail integration

```typescript
// src/hooks/useLiveTail.ts
const DEFAULT_MAX_ROWS = 5000; // Configurable via tier-config console.live_tail_max_rows

export function useLiveTail(filter: ReceiptFilter, enabled: boolean, maxRows = DEFAULT_MAX_ROWS) {
  const queryClient = useQueryClient();
  const pinned = usePinnedRows(); // selected for bulk action / favorited / in scroll viewport
  useEffect(() => {
    if (!enabled) return;
    const ws = new LiveTailClient('/admin/live-tail', filter);
    ws.on('attestation', (attestation) => {
      queryClient.setQueryData(['receipts', filter], (old) => {
        if (!old) return old;
        // Prepend new row, evict oldest non-pinned tail if cap exceeded.
        const allRows = [attestation, ...old.pages.flatMap(p => p.data)];
        const evicted = evictOldestNonPinned(allRows, maxRows, pinned);
        if (evicted.evictionCount > 0) {
          showToastOnce('live-tail-trimmed',
            `Live-tail trimmed ${evicted.evictionCount} older rows ` +
            `(showing latest ${maxRows}); use the time-range filter to view earlier receipts.`);
        }
        // Re-page evicted.kept into TanStack's page shape.
        return repaginateForInfiniteQuery(evicted.kept, old.pageParams);
      });
    });
    ws.on('backfill_summary', (s) => { if (s.truncated) showToast('Some receipts may be missing'); });
    return () => ws.close();
  }, [enabled, filter, maxRows]);
}
```

### SPA row cap and eviction (per `live_tail_transport.md` §"SPA row cap and eviction")

The TanStack Table state caps at **5,000 rows by default**, configurable per-tenant via tier-config `console.live_tail_max_rows`. Rationale: at 50 QPS Data Plane → 50 frames/sec into TanStack Table; 1-hour idle accumulates 180k rows without a cap → browser RAM blow-up + table-render lag.

**Eviction policy**:

- On overflow, drop oldest non-pinned rows from the TanStack cache (`old.pages.flatMap(p => p.data).slice(0, maxRows)` pattern, with pin-survival).
- **Pinned rows survive eviction**: rows currently selected for a bulk action; rows the user has explicitly favorited; rows within the current scroll viewport (TanStack Virtual's visible window).
- **User feedback**: a one-time toast "Live-tail trimmed older rows (showing latest 5,000); use the time-range filter to view earlier receipts." Subsequent evictions in the same session are silent.
- **Independence from backfill cap**: WebSocket backfill on reconnect is bounded at 1,000 receipts (per `live_tail_transport.md`); SPA row cap (5,000) is independent and bounds total table state regardless of backfill source.
- **Throughput-eviction composition**: at sustained 50 QPS the SPA evicts at ~50 rows/sec to maintain the cap. Eviction is O(1) at the tail end of the TanStack page list.

The hook prepends new attestations to the first page of the infinite-query cache, preserving pagination state for "load older."

---

## Schema validation (build + runtime)

Per D10:

- **Build-time**: `pnpm gen:types` reads JSON Schema files **directly from disk** at `../apps/recurse_gateway/priv/schemas/*.json` (relative path through the monorepo from `ui/`), runs `json-schema-to-typescript`, writes `src/lib/types.ts`. The SPA build does NOT need a running Gateway. The schema files in `priv/schemas/` are the source of truth, served at runtime via `/v1/schemas/{entity}.json` for clients that prefer to fetch them, but the SPA's own codegen reads them as ordinary files at build time.
- `src/lib/types.ts` IS committed to git (not gitignored). CI runs `pnpm gen:types && git diff --exit-code ui/src/lib/types.ts` — a developer who edited a schema without regenerating types fails CI with a clear error.
- **Runtime**: `zod@^3.23` schemas (also generated from JSON Schema via `json-schema-to-zod`, same file-based path) validate every API response shape. Mismatches log a warning + fall through to the response anyway (defensive — drift between SPA and API mid-deploy shouldn't break the UI; it should just be noisy).

---

## Tests

| Layer | Tool | Coverage |
|---|---|---|
| Component unit tests | Vitest + Testing Library | Each component in `components/` has at least one unit test |
| Hook tests | Vitest with `renderHook` | Each hook in `hooks/` has at least one test exercising its primary flow |
| API client tests | Vitest with `msw` (mocked endpoints) | Error envelope normalization, schema-validation behavior |
| E2E | Playwright | One test per user story (US1–US6) running against `mix run --no-halt` Gateway |

Playwright tests are wired through CI: `pnpm playwright install` + `mix run --no-halt &` + `pnpm test:e2e`. Tests assert receipts emitted by UI actions appear in the audit log within the SC-009 2-second budget.

---

## Out of scope

- Server-side rendering. SPA is fully client-rendered; the Gateway serves a static `index.html` shell.
- Internationalization. English-only in F004; i18n lib hooks reserved.
- Theming (light/dark). Single theme matching pen file. Future per-user-preference theming deferred.
- Mobile/tablet responsive layouts. Per spec Assumptions, mobile is out of scope.
- Offline mode. SPA assumes online connection; no service worker.
