defmodule Recurse.Gateway.Router do
  @moduledoc """
  Top-level Bandit-hosted HTTP router for the Gateway (F002 T050;
  expanded to F004 / Audit Console + MR !31 auth-pipeline consolidation).

  Release boundary: `Recurse.Gateway.ReleaseSurface` runs before dispatch
  and returns 503 for the legacy model-call, audit-agent chat, and MCP tool
  execution routes described below. Their handlers remain internal code;
  the governed execution surface is the separate LLM proxy listener.
  LLM suggestion generation is also unavailable; heuristic refresh remains.

  ## Route classes

  Routes split into four auth-surface classes; the per-class auth glue
  is centralized in `Recurse.Gateway.Auth.RouteMacros` (added in MR !31)
  so the route table reads as plain `cookie_only_get`, `dual_auth_post`,
  etc. without inline auth dispatch.

    1. **Public surface (no auth).** Liveness / readiness / Prometheus
       exposition (`/healthz`, `/readyz`, `/metrics`); the F004 Audit
       Console manifest + schema publication
       (`GET /.well-known/r5e-audit.json`, `GET /v1/schemas/index.json`,
       `GET /v1/schemas/:name.json`); the broker JWKS rebroadcast
       (`GET /v1/auth/jwks`); the OIDC PKCE entry points
       (`GET /admin/login/start`, `GET /admin/login/callback` —
       authentication itself, so by definition unauthenticated). Static
       SPA assets under `/admin/*` are served via `Plug.Static` ahead of
       the router.

    2. **Bearer-only data plane.** `POST /v1/chat/completions` —
       authenticated via `Authorization: Bearer <JWT>` only. Browser
       cookies are NOT accepted on this surface; the data plane is
       agent-to-agent traffic, not browser traffic. Dispatches to
       `Recurse.Gateway.DataPlane.ChatCompletionsHandler`.

    3. **Dual-auth audit plane (3 routes).** The legacy F002 Audit Plane
       endpoints — `GET /v1/audit/receipts`, `POST /v1/audit/export`,
       `GET /v1/audit/payload` — accept either `Authorization: Bearer
       <JWT>` (CLI / external SIEM forwarder) OR the `r5e_session` cookie
       (browser console). Auth dispatch is `RouteMacros.dual_auth_*` →
       `Recurse.Gateway.Auth.CookieOrBearerPlug`. Cedar-gated by
       `Recurse::Action::{ReadReceipts, ExportEvidence, ReadPayload}`.

    4. **Cookie-only F004 console surfaces (24 routes).** All other
       Audit Console endpoints — `/v1/auth/me`, the receipt detail +
       local verify routes, the live-tail WebSocket, logout, the policy
       drafts CRUD set, policy simulate / replay, the policy
       suggestions surface, the audit-agent chat surface, and the Oban
       job log dashboard. Auth dispatch is `RouteMacros.cookie_only_*` →
       `Recurse.Gateway.Admin.BrowserSessionPipe` (validates the
       encrypted `r5e_session` cookie, lifts the JWT into
       `Authorization: Bearer …`, builds the IdentityContext). Bearer
       tokens are rejected on this surface — these are SPA-only.

  Each non-public route ALSO carries a per-route Cedar gate keyed to its
  declared action; see `apps/recurse_gateway/priv/cedar/schema.cedarschema.json`
  for the canonical action vocabulary and `data-model.md` §0 for the
  UI-action × Cedar-action × `event_kind` matrix.

  Two final fall-through clauses:

    * `match <runtime-owned paths>` — any path tagged as Runtime-owned
      returns HTTP 501 `ERR_TIER_MISMATCH` per FR-024 / SC-009.
    * `match _` — unknown paths return a 404 JSON envelope.

  ## Iron Law check (`elixir:otp-thinking`)

  `Plug.Router` is pure function composition. No GenServer. The Bandit
  child under `RecurseGateway.Application` owns the acceptor pool; per-
  connection processes are Bandit's concern. Nothing in this module
  holds state across requests — every plug function is pure. The
  `RouteMacros` from MR !31 expand to the same per-route auth-dispatch
  function calls we used to write inline; they are a textual
  consolidation, not a state-holding seam.

  ## Auth flow (per-route via RouteMacros, not a shared plug pipeline)

  Auth gates remain per-route rather than in a global `plug` chain so
  public surfaces (health endpoints, manifest, schemas, the OIDC start
  routes themselves) don't get forced through JWT validation. The
  RouteMacros consolidation just moves the inline auth-dispatch
  boilerplate out of route bodies and behind macro names that name the
  auth class — `bearer_only_post`, `dual_auth_get`, `cookie_only_post`,
  etc. Public routes still use plain `Plug.Router` `get`/`post` macros
  with no auth dispatch.

  ## Correlation ID

  `IdentityContextBuilder.build/3` resolves `X-Correlation-ID` inbound
  and mints a fresh ULID if absent. The handler forwards the resolved
  ID back downstream as `x-recurse-correlation-id` per FR-006. The
  router does NOT touch the correlation ID itself — it passes the
  already-built `%IdentityContext{}` into the handler.

  ## Provider neutrality (Constitution Principle V)

  The Router does not reference any concrete provider impl module. All
  outbound I/O is reached via `Recurse.Gateway.ProviderRegistry` inside
  the handler; the Router's only dependency outside
  `:recurse_gateway` is `Recurse.Shared.IdentityContext`. Any future
  surface that adds a new transport / IdP / ledger backend lands behind
  the existing Provider Interfaces — the route table itself names
  handlers, never concrete providers.

  ## Runtime-only tier-mismatch enforcement (FR-024, SC-009)

  `@runtime_only_paths` hard-codes a list of paths that future Runtime
  or Governance-shape deployments will own. Under Standalone these MUST
  return 501 with the canonical `ERR_TIER_MISMATCH` body so clients
  learn the tier mismatch structurally — not by ambiguously routing to
  404. T102 iterates this list + asserts the 501 contract.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T050
    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-003,
      FR-005, FR-016a-f, FR-024, FR-028, SC-009
    * `specs/004-audit-console/contracts/browser_oidc_flow.md`
      (cookie-only console surface; BrowserSessionPipe contract)
    * `apps/recurse_gateway/lib/recurse_gateway/auth/route_macros.ex`
      (MR !31 — the four-class auth-dispatch macros)
    * `apps/recurse_gateway/lib/recurse_gateway/auth/cookie_or_bearer_plug.ex`
      (dual-auth dispatcher used by class 3)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_session_pipe.ex`
      (cookie-only dispatcher used by class 4)
    * `apps/recurse_gateway/lib/recurse_gateway/identity/identity_context_builder.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/data_plane/chat_completions_handler.ex`
  """

  use Plug.Router

  import Recurse.Gateway.Auth.RouteMacros

  alias Recurse.Gateway.Identity.AuthFailureReason
  alias Recurse.Gateway.Identity.IdentityContextBuilder

  # ---------------------------------------------------------------------------
  # Runtime-only endpoint paths.
  #
  # Every path below is owned by a Runtime or Governance-shape application
  # per the F001 openapi.yaml `owning_application` tag. Under Standalone
  # (`:recurse_runtime` disabled; `:recurse_governance` not yet an OTP app)
  # these paths MUST return 501 `ERR_TIER_MISMATCH` per FR-024.
  #
  # T102 (Wave 3F) iterates this list and asserts the contract.
  # ---------------------------------------------------------------------------

  @runtime_only_paths [
    {"/v1/control/runtime/spawn", "runtime_shape"},
    {"/v1/control/runtime/agents", "runtime_shape"},
    {"/v1/governance/policy/propose-from-event", "governance_shape"},
    {"/v1/governance/policy/blast-radius", "governance_shape"},
    {"/v1/governance/policy/simulate", "governance_shape"}
  ]

  @doc """
  Module attribute accessor — exposes `@runtime_only_paths` so T102
  can iterate the authoritative list without duplicating it.
  """
  @spec runtime_only_paths() :: [{String.t(), String.t()}]
  def runtime_only_paths, do: @runtime_only_paths

  # ---------------------------------------------------------------------------
  # Plug pipeline
  # ---------------------------------------------------------------------------

  plug(Plug.RequestId)
  plug(Recurse.Gateway.ReleaseSurface)

  # Parse JSON bodies up front so `POST /v1/chat/completions` sees
  # `conn.body_params`. `pass: ["*/*"]` lets the health / 501 routes skip
  # parsing unused content types. The Elixir 1.18+ built-in `JSON` module
  # has `decode!/1` and satisfies Plug.Parsers's json_decoder contract.
  plug(Plug.Parsers,
    parsers: [:json],
    pass: ["*/*"],
    json_decoder: JSON
  )

  plug(:match)
  plug(:dispatch)

  # ---------------------------------------------------------------------------
  # Runtime-only tier-mismatch matches — MUST come before the catch-all
  # match. Each path returns 501 with a canonical `ERR_TIER_MISMATCH` body
  # per FR-024 / SC-009.
  #
  # Plug.Router's `match` macro rejects dynamic path values (the macro's
  # arg must be a compile-time string), so these are enumerated by hand.
  # The authoritative list lives on `@runtime_only_paths` and is reflected
  # by `runtime_only_paths/0` so T102 iterates the single source.
  # ---------------------------------------------------------------------------

  match "/v1/control/runtime/spawn", via: [:get, :post, :put, :delete, :patch] do
    send_tier_mismatch(conn, "runtime_shape")
  end

  match "/v1/control/runtime/agents", via: [:get, :post, :put, :delete, :patch] do
    send_tier_mismatch(conn, "runtime_shape")
  end

  match "/v1/governance/policy/propose-from-event", via: [:get, :post, :put, :delete, :patch] do
    send_tier_mismatch(conn, "governance_shape")
  end

  match "/v1/governance/policy/blast-radius", via: [:get, :post, :put, :delete, :patch] do
    send_tier_mismatch(conn, "governance_shape")
  end

  match "/v1/governance/policy/simulate", via: [:get, :post, :put, :delete, :patch] do
    send_tier_mismatch(conn, "governance_shape")
  end

  # ---------------------------------------------------------------------------
  # Data Plane — /v1/chat/completions
  # ---------------------------------------------------------------------------

  post "/v1/chat/completions" do
    case authenticate(conn) do
      {:ok, conn_with_ctx} ->
        case apply_rate_limit(conn_with_ctx, :data) do
          %Plug.Conn{halted: true} = halted ->
            halted

          conn_with_ctx ->
            Recurse.Gateway.DataPlane.ChatCompletionsHandler.handle(conn_with_ctx)
        end

      {:error, reason} ->
        send_auth_failure(conn, reason)
    end
  end

  # ---------------------------------------------------------------------------
  # Audit Plane — /v1/audit/*
  #
  # Each handler embeds its own JWT + Cedar pipeline via
  # `Recurse.Gateway.AuditPlane.Authz.gate/4` (different Cedar action +
  # resource per endpoint). Router just dispatches — no shared auth hop
  # here on purpose: the Audit Plane uses the F001 error envelope while the
  # Data Plane uses the OpenAI shape (FR-016d vs FR-023) and those error
  # surfaces can't be unified at the Router layer.
  # ---------------------------------------------------------------------------

  # GET /v1/audit/receipts (list) — dual-auth.
  #
  # The F002-original Audit Plane uses Authorization: Bearer <jwt>
  # exclusively (SIEM forwarders, the `recurse-verify` OSS CLI, and
  # future RFC-8693 token-exchange agents / MCP servers). F004's SPA
  # uses cookie envelopes and never sends JWTs directly per its contract
  # (`ui/src/lib/api.ts`). Both modes converge on the same
  # `Authorization: Bearer <jwt>` shape downstream —
  # `Recurse.Gateway.Auth.CookieOrBearerPlug.dispatch/2` picks the right
  # path per request.
  #
  # The DETAIL/SESSION/VERIFY routes (lines 311+, 333+, 351+) were
  # cookie-wrapped during the F004 retrofit but the LIST route was
  # missed; this fix closes that gap without breaking F002 callers.
  dual_auth_get(
    "/v1/audit/receipts",
    &Recurse.Gateway.AuditPlane.ReceiptsHandler.handle/1
  )

  # POST /v1/audit/export + GET /v1/audit/payload — dual-auth.
  # Same shape as the receipts-list dual-auth above (line 200): the F004
  # SPA hits both via cookie envelope; F002 SIEM forwarders + the
  # `recurse-verify` OSS CLI hit them with `Authorization: Bearer <jwt>`.
  # `Recurse.Gateway.Auth.CookieOrBearerPlug.dispatch/2` picks the right
  # path per request. (Issue #25.)
  dual_auth_post(
    "/v1/audit/export",
    &Recurse.Gateway.AuditPlane.ExportHandler.handle/1
  )

  dual_auth_get(
    "/v1/audit/payload",
    &Recurse.Gateway.AuditPlane.PayloadBroker.handle/1
  )

  # ---------------------------------------------------------------------------
  # Observability — FR-028 (/healthz, /readyz, /metrics).
  #
  # Each endpoint is a thin dispatch to a dedicated module under
  # `Recurse.Gateway.Observability.*`. These routes deliberately bypass
  # the RateLimiter (when present) — Prometheus scrapes and LB probes
  # MUST NOT be subject to per-subject rate limits.
  # ---------------------------------------------------------------------------

  get "/healthz" do
    Recurse.Gateway.Observability.Healthz.call(conn, [])
  end

  get "/readyz" do
    Recurse.Gateway.Observability.Readyz.call(conn, [])
  end

  get "/metrics" do
    # Defer to the `Endpoint` module's safe-scrape wrapper: when the
    # `MetricsRegistry` hasn't been started (umbrella test env without
    # `:start_observability?`), the wrapper returns a stub body rather
    # than raising. Production + the prod-style tests boot the registry
    # so the real exposition is served.
    Recurse.Gateway.Observability.Endpoint.handle_metrics(conn)
  end

  # ---------------------------------------------------------------------------
  # F004 — Audit Console surface.
  #
  # Routes ordered most-specific-first to give Plug.Router's `match` macro
  # the right precedence. All admin/* and console-specific /v1/* surfaces
  # use the BrowserSessionPlug (cookie envelope) for auth, NOT the F002
  # IdentityContextBuilder (Authorization-header JWT). The two coexist:
  # F002 surfaces (`/v1/audit/*`, `/v1/chat/completions`) keep their
  # header-based auth; F004 surfaces (`/admin/*`, `/v1/auth/me`) lift
  # the cookie envelope into an `Authorization: Bearer <jwt>` header on
  # the way in via BrowserSessionPlug, then handlers see the same shape.
  #
  # Public-no-auth (CORS-allowed):
  #   GET /.well-known/r5e-audit.json
  #   GET /v1/schemas/index.json
  #   GET /v1/schemas/{name}.json
  # OIDC public (no cookie required by definition):
  #   GET /admin/login/start
  #   GET /admin/login/callback
  # Cookie-required:
  #   GET /v1/auth/me
  #   POST /admin/logout
  # Static SPA (cookie required for non-login paths):
  #   GET /admin/* — served from priv/static/admin/ via Plug.Static (T011)
  # ---------------------------------------------------------------------------

  # Public — Well-Known manifest + schema index + per-schema URIs.
  get "/.well-known/r5e-audit.json" do
    Recurse.Gateway.Admin.WellKnownManifest.call(conn, [])
  end

  get "/v1/schemas/index.json" do
    Recurse.Gateway.Admin.SchemaPublication.index(conn, [])
  end

  get "/v1/schemas/:name.json" do
    # The route captures `:name` as the BARE schema key (without the
    # `.json` suffix). Per contract `well_known_manifest.md`,
    # manifest URIs publish absolute paths ending in `.json`; the
    # suffix is part of the URL pattern but not the cache key inside
    # `SchemaPublication`. Keeping the suffix in the route shape
    # makes this contract explicit at the routing layer rather than
    # buried in handler-side string-stripping.
    #
    # Issue #30 Task H: previously this route was `/v1/schemas/:name`
    # which captured `:name` as e.g. `auth_me.json`, while
    # `SchemaPublication.serve_schema/2` looked up bare keys like
    # `auth_me`. Every documented schema URL in the manifest 404'd.
    Recurse.Gateway.Admin.SchemaPublication.serve_schema(conn, [])
  end

  # Public — RFC 7517 JWKS publication of the gateway's broker
  # signing key. Public-by-design (JWKS is published-key info). The
  # gateway's own JwksCache fetches this runtime-derived collapsed URL
  # on first cache miss to validate cookie-issued internal JWTs. In
  # split-broker production deploys, this endpoint is unused; the
  # JwksCache fetches from the broker container instead.
  get "/v1/auth/jwks" do
    Recurse.Gateway.Admin.BrokerJwksHandler.call(conn, [])
  end

  # OIDC PKCE — no cookie required (the START path mints state; the
  # CALLBACK path consumes state and SETS the cookie).
  #
  # The handler reads its IdP + broker wiring from
  # `Application.get_env(:recurse_gateway, :browser_idp, [])` (see
  # `LoginHandler.resolve_config/1`); we ALSO pass an explicit opts list
  # here that pins the production-default validator + token-exchange
  # callbacks. Without this, an empty opts list would still resolve via
  # app env, but threading the callbacks here makes the production wiring
  # call-site-visible to anyone reading the router (and lets future tests
  # override per-route by passing alternative `:id_token_validator` /
  # `:token_exchange` opts at this site).
  get "/admin/login/start" do
    Recurse.Gateway.Admin.BrowserAuth.LoginHandler.call(
      conn,
      Recurse.Gateway.Admin.BrowserAuth.LoginHandler.init(login_handler_opts())
    )
  end

  get "/admin/login/callback" do
    Recurse.Gateway.Admin.BrowserAuth.LoginHandler.call(
      conn,
      Recurse.Gateway.Admin.BrowserAuth.LoginHandler.init(login_handler_opts())
    )
  end

  # DEV/LOCAL ONLY — server-side cookie mint, no IdP round-trip. The
  # Playwright suite's `loginAs/2` helper has targeted this path since
  # F004 T005; it 404s unless `:dev_login_enabled?` is true (config/dev.exs,
  # or the `R5E_DEV_LOGIN_ENABLED` runtime env var — spec 012 quickstart).
  # Full gating rationale in the handler @moduledoc.
  post "/admin/test/login" do
    Recurse.Gateway.Admin.BrowserAuth.DevLoginHandler.handle(conn)
  end

  # Cookie-required F004 surfaces — apply BrowserSessionPlug per-route
  # so F002 surfaces are unaffected (the plug runs only on these matches).
  # The plug lifts the cookie envelope into Authorization: Bearer <jwt>
  # before the handler runs; on cookie-missing/expired/tampered, the plug
  # halts the conn with the appropriate :ui_session subtype receipt + 401.
  cookie_only_get(
    "/v1/auth/me",
    &Recurse.Gateway.Admin.AuthMeHandler.handle/1
  )

  # F004 T060 — session timeline (`GET /v1/audit/sessions/{session_id}`).
  # Cookie-required. Cedar action `DashboardQuery`; emits :ui_query with
  # `query_kind: "session_timeline"`.
  cookie_only_get(
    "/v1/audit/sessions/:session_id",
    &Recurse.Gateway.Admin.SessionTimelineHandler.handle/1
  )

  # Spec 012 S4 — parser drift (`GET /v1/audit/parser-drift`). Cookie-
  # required; Cedar action `DashboardQuery`; emits `:ui_query` with
  # `query_kind: "parser_drift"`. Lists the event/block/delta types the
  # LLM-proxy parsers could not classify (keys-only samples).
  cookie_only_get(
    "/v1/audit/parser-drift",
    &Recurse.Gateway.Admin.ParserDriftHandler.handle/1
  )

  # F004 T074 — singular receipt-detail (`GET /v1/audit/receipts/{run_id}`).
  # Cookie-required. Cedar action `ReadReceipts` (F002 reuse); emits
  # `:ui_query` with `query_kind: "audit_log"`. F002's `GET /v1/audit/receipts`
  # (list) stays untouched; this route is the F004-additive detail variant.
  # MUST appear AFTER the list route (`GET /v1/audit/receipts`) above so
  # `/v1/audit/receipts` (without a path segment) still dispatches to the
  # F002 list handler. Plug.Router compiles routes top-to-bottom; static
  # `/v1/audit/receipts` already matched at the F002 block earlier.
  cookie_only_get(
    "/v1/audit/receipts/:run_id",
    &Recurse.Gateway.AuditPlane.ReceiptsHandler.handle_detail/1
  )

  # F004 T075 — Verify Locally (`POST /v1/audit/receipts/{run_id}/verify`).
  # Cookie-required. Cedar action `ReadReceipts` (F002 reuse); emits
  # `:ui_query` with `query_kind: "verify_locally"`. Runs the 5-check
  # cryptographic pipeline server-side per FR-018; SC-002 budget ≤3s.
  cookie_only_post(
    "/v1/audit/receipts/:run_id/verify",
    &Recurse.Gateway.Admin.LocalVerifyHandler.handle/1
  )

  # F004 T063 — live-tail WebSocket upgrade. Cookie-required. Cedar action
  # `DashboardQuery`; emits `:ui_session` with `event: "live_tail_open"`
  # at upgrade and `"live_tail_close"` at disconnect. Browser-only — no
  # bearer-auth path per live_tail_transport.md §"Authentication".
  cookie_only_get(
    "/admin/live-tail",
    &Recurse.Gateway.Admin.LiveTailSocket.upgrade/1
  )

  cookie_only_post(
    "/admin/logout",
    &Recurse.Gateway.Admin.BrowserAuth.LogoutHandler.call(&1, [])
  )

  # ---------------------------------------------------------------------------
  # F004 Phase 5 (US3) — Policy authoring + Blast Radius surface.
  #
  # Eight routes wire the operator's "Create policy rule from this receipt"
  # workflow + Blast Radius dry-run + the Policy Simulator's synthetic
  # evaluator. All cookie-required (BrowserSessionPlug lifts cookie → JWT
  # before each handler runs); each handler embeds its own Cedar gate via
  # `AuditPlane.Authz.gate/4` against the per-route action enumerated in
  # `data-model.md` §0.
  #
  # Most-specific routes (`/from-receipt`, `/dry-run`) ordered BEFORE the
  # generic `/:id` matches so Plug.Router resolves them first.
  # ---------------------------------------------------------------------------

  # T146 — per-tenant rate-limit on policy simulate happens INSIDE
  # the handler (after Cedar gate has populated `:identity_ctx`).
  # The handler reads `:policy_simulate_rate_limit` config and
  # calls the F002 RateLimiter plug with the audit-plane key shape.
  cookie_only_post(
    "/v1/policy/simulate",
    &Recurse.Gateway.Admin.PolicySimulateHandler.handle/1
  )

  cookie_only_get(
    "/v1/policy/drafts",
    &Recurse.Gateway.Admin.PolicyDraftsHandler.list/1
  )

  cookie_only_post(
    "/v1/policy/drafts/from-receipt",
    &Recurse.Gateway.Admin.PolicyDraftsFromReceiptHandler.handle/1
  )

  cookie_only_post(
    "/v1/policy/drafts",
    &Recurse.Gateway.Admin.PolicyDraftsHandler.create/1
  )

  cookie_only_post(
    "/v1/policy/drafts/:id/dry-run",
    &Recurse.Gateway.Admin.PolicyDraftsDryRunHandler.handle/1
  )

  cookie_only_get(
    "/v1/policy/drafts/:id",
    &Recurse.Gateway.Admin.PolicyDraftsHandler.get/1
  )

  cookie_only_patch(
    "/v1/policy/drafts/:id",
    &Recurse.Gateway.Admin.PolicyDraftsHandler.update/1
  )

  cookie_only_delete(
    "/v1/policy/drafts/:id",
    &Recurse.Gateway.Admin.PolicyDraftsHandler.archive/1
  )

  # ---------------------------------------------------------------------------
  # F004 Phase 7 (US5) — Policy Suggestions surface.
  #
  # Five routes wire the Suggestions surface (Source Label-flagged
  # heuristic + LLM auto-generated suggestions) per
  # `audit_api_extensions.md` §"Policy suggestions".
  # All cookie-required (BrowserSessionPlug runs first); each handler
  # embeds its own Cedar gate via `AuditPlane.Authz.gate/4`. Manual
  # refresh is rate-limited per FR-030a (default 6/hour/tenant).
  #
  # Most-specific routes (`/refresh`, `/adopt`, `/dismiss`) ordered
  # BEFORE the generic `/:id` match so Plug.Router resolves them first.
  # ---------------------------------------------------------------------------

  cookie_only_post(
    "/v1/policy/suggestions/refresh",
    &Recurse.Gateway.Admin.PolicySuggestionsHandler.refresh/1
  )

  cookie_only_post(
    "/v1/policy/suggestions/:id/adopt",
    &Recurse.Gateway.Admin.PolicySuggestionsHandler.adopt/1
  )

  cookie_only_post(
    "/v1/policy/suggestions/:id/dismiss",
    &Recurse.Gateway.Admin.PolicySuggestionsHandler.dismiss/1
  )

  cookie_only_get(
    "/v1/policy/suggestions",
    &Recurse.Gateway.Admin.PolicySuggestionsHandler.list/1
  )

  cookie_only_get(
    "/v1/policy/suggestions/:id",
    &Recurse.Gateway.Admin.PolicySuggestionsHandler.get_one/1
  )

  # ---------------------------------------------------------------------------
  # F004 Phase 8 (US6) — Policy Replay surface.
  #
  # Single route. Cookie-required. Cedar action `PolicyReplay`; emits
  # `:ui_policy_replay` per `data-model.md` §0.
  # ---------------------------------------------------------------------------

  cookie_only_post(
    "/v1/policy/replay/:run_id",
    &Recurse.Gateway.Admin.PolicyReplayHandler.handle/1
  )

  # ---------------------------------------------------------------------------
  # F004 Phase 6 (US4) — Audit Agent chat surface.
  #
  # Three routes wire the chat drawer + audit-agent runtime + per-tool
  # attestations. All cookie-required (BrowserSessionPlug runs first); the
  # ChatHandler embeds its own Cedar gate (`ChatDrawerQuery`) and emits
  # `:ui_chat` for each message + one `:ui_chat_skill_invoked_<tool>` per
  # tool dispatched per `data-model.md` §0.
  #
  # `POST /v1/chat/messages` is SSE-streamed; the other two are plain JSON.
  # ---------------------------------------------------------------------------

  cookie_only_post(
    "/v1/chat/messages",
    &Recurse.Gateway.Admin.ChatHandler.handle/1
  )

  cookie_only_get(
    "/v1/chat/conversations",
    &Recurse.Gateway.Admin.ChatHandler.list_conversations/1
  )

  cookie_only_get(
    "/v1/chat/conversations/:id",
    &Recurse.Gateway.Admin.ChatHandler.get_conversation/1
  )

  # ---------------------------------------------------------------------------
  # MCP Trusted Registry vertical slice (Path B demo).
  #
  # Two read-only admin-console surfaces (cookie-only) for the static
  # registry catalog and one bearer-authenticated agent-facing endpoint
  # for hosted MCP tool dispatch. The DEMO endpoint accepts a synthetic
  # `Bearer demo-mcp-token-*` token in addition to the real RFC 8693
  # token-exchanged JWT path; full broker wire-up is a follow-up MR
  # (surfaced in this MR's reflect).
  #
  # Every tool dispatch — allow OR deny — emits an `:mcp_tool_call`
  # attestation. Quarantined registry entries are policy-denied at the
  # handler; the deny is still attested per Constitution Principle III.
  # ---------------------------------------------------------------------------

  cookie_only_get(
    "/v1/mcp/registry",
    &Recurse.Gateway.Admin.McpRegistryHandler.list/1
  )

  cookie_only_get(
    "/v1/mcp/registry/:id",
    &Recurse.Gateway.Admin.McpRegistryHandler.get_one/1
  )

  # F7 quarantine workflow — operator-only mutation that flips an entry's
  # `trust_tier` (and the documented Cedar policy clause). Cedar action
  # `McpRegistryQuarantine`, `platform_operator` only; emits
  # `:ui_mcp_quarantine` per Constitution Principle III. See
  # `apps/recurse_gateway/lib/recurse_gateway/admin/mcp_registry_handler.ex`
  # `update/1` for the handler.
  cookie_only_patch(
    "/v1/mcp/registry/:id",
    &Recurse.Gateway.Admin.McpRegistryHandler.update/1
  )

  # MCP tool dispatch — bearer-authenticated. Auth happens INSIDE the
  # handler (not via RouteMacros) because the demo accepts a synthetic
  # `demo-mcp-token-*` bearer alongside the production JWT path.
  post "/v1/mcp/:server/tools/:tool" do
    Recurse.Gateway.DataPlane.McpServerHandler.handle(conn)
  end

  # F004 T148 — Oban dashboard. Operator-only Cedar-gated; emits
  # `:ui_query` per the canonical matrix.
  cookie_only_get(
    "/admin/oban",
    fn conn_with_session ->
      conn_with_session
      |> apply_security_headers()
      |> Recurse.Gateway.Admin.ObanDashboardHandler.handle()
    end
  )

  # Spec A (MR !119) — OCI Cedar bundle hot-reload activation.
  # Cedar action `CedarBundleActivate` (gated to platform_operator via
  # the deployed bundle); emits `:policy_bundle_activated` on success.
  # Body: `{"ref": "0.2.0-abc1234", "digest": "sha256:..."}` (digest opt).
  # Returns 200 on success, 400 on validation, 502 on registry/cosign
  # failure. Implementation in
  # `apps/recurse_gateway/lib/recurse_gateway/admin/cedar_bundle_activate_handler.ex`.
  cookie_only_post(
    "/v1/admin/cedar-bundle/activate",
    fn conn_with_session ->
      conn_with_session
      |> apply_security_headers()
      |> Recurse.Gateway.Admin.CedarBundleActivateHandler.handle()
    end
  )

  # SPA static asset serving — `priv/static/admin/` populated by
  # `pnpm run sync-to-priv` (research D9). Mounted with `at: "/admin"`
  # and `from: {:recurse_gateway, "priv/static/admin"}`. The SPA is the
  # `RequireAuth`-gated entry point; deep links (`/admin/dashboard`,
  # `/admin/policy-simulator/...`) all serve `index.html` so the SPA
  # router can take over client-side. The SPA itself triggers the
  # OIDC redirect when `useAuth` returns unauthenticated (per Wave-1D
  # `RequireAuth` component).
  #
  # F004 T145 — security headers (CSP, frame-ancestors, X-Content-Type-Options,
  # Referrer-Policy) are applied via `Plug.Static`'s `:headers` callback by
  # forwarding through a tiny security-header wrapper plug FIRST.
  # NOTE: `at: "/"` is correct here, NOT `at: "/admin"`. Plug.Router's
  # `forward` strips the leading segment from `path_info` before invoking
  # the target plug, so by the time Plug.Static sees the conn the `/admin`
  # prefix is already gone. Setting `at: "/admin"` would match nothing
  # and the AdminStatic SPA-fallback would catch every request — including
  # asset requests, returning index.html instead of the JS/CSS/images.
  #
  # The `:only` allowlist enumerates top-level path segments under
  # `priv/static/admin/` that Plug.Static will serve. Anything not listed
  # falls through to `Plug.AdminStatic`'s SPA-fallback, which sends
  # `index.html` as `text/html` so client-side routing can take over for
  # deep links like `/admin/dashboard`. That fallback is correct for SPA
  # routes but WRONG for missing static assets — a request for
  # `/admin/<missing>/<file>.js` will receive HTML, the browser will fail
  # to parse it as JS, and the symptom surfaces as a silent loader hang
  # downstream.
  #
  # `vs` is the Monaco editor's AMD bundle (~2MB), copied from
  # `node_modules/monaco-editor/min/vs/` into `ui/public/vs/` at build
  # time by `pnpm copy:monaco` (see `ui/scripts/copy-monaco-vs.ts`). The
  # SPA's `~/lib/configureMonacoLoader.ts` points `@monaco-editor/loader`
  # at `/admin/vs/`, satisfying CSP `script-src 'self'`. Without `vs` on
  # the allowlist below, requests for `/admin/vs/loader.js` fall through
  # to the SPA fallback and Monaco's `loader.init()` hangs forever — the
  # exact bug fixed in MR !67 silently regressed (issue #61, 2026-04-30).
  # Spec 012 S6c — the SPA has no page at its root, so `/admin` and
  # `/admin/` (both arrive as `path_info == ["admin"]`) land on the
  # dashboard; `RequireAuth` there sends an unauthenticated browser on to
  # the login flow. Declared BEFORE the `forward` so the static fallback
  # never serves a routeless `index.html` for the bare prefix.
  get "/admin" do
    conn
    |> put_resp_header("location", "/admin/dashboard")
    |> send_resp(302, "")
  end

  forward("/admin",
    to: Recurse.Gateway.Plug.AdminStatic,
    init_opts: [
      static_opts: [
        at: "/",
        from: {:recurse_gateway, "priv/static/admin"},
        only: ~w(assets vs recurse-logo.svg favicon.ico vite.svg index.html),
        gzip: true
      ]
    ]
  )

  # ---------------------------------------------------------------------------
  # Root convenience — bare `/` redirects to the SPA login screen so a
  # browser hitting the dogfood domain without a path lands somewhere
  # useful instead of seeing the JSON 404 catch-all.
  # ---------------------------------------------------------------------------

  get "/" do
    conn
    |> put_resp_header("location", "/admin/login")
    |> send_resp(302, "")
  end

  # ---------------------------------------------------------------------------
  # Catch-all — JSON 404 (consistent shape with other routes).
  # ---------------------------------------------------------------------------

  match _ do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(404, ~s|{"error":"not_found"}|)
  end

  # ---------------------------------------------------------------------------
  # Private — auth
  # ---------------------------------------------------------------------------

  # FR-006 — responses carry `x-recurse-correlation-id` (distinct from the
  # inbound `x-correlation-id` header name that `CorrelationId` uses for
  # request parsing). Using the Recurse-prefixed form on responses makes
  # the value's provenance explicit to downstream observers.
  @recurse_correlation_header "x-recurse-correlation-id"

  defp authenticate(conn) do
    tenant_id = Recurse.Gateway.ProviderRegistry.tenant_id()
    opts = Application.get_env(:recurse_gateway, :jwt_validator_opts, [])

    case IdentityContextBuilder.build(conn.req_headers, tenant_id, opts) do
      {:ok, ctx} ->
        conn_with_correlation =
          conn
          |> Plug.Conn.put_resp_header(@recurse_correlation_header, ctx.correlation_id)
          |> Plug.Conn.assign(:identity_ctx, ctx)

        {:ok, conn_with_correlation}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # FR-016d — auth failures return OpenAI-shaped protocol-native 401s.
  # The `code` field carries the per-cause discrimination (atom string)
  # for Data-Plane consumers; the human-readable `message` is sourced
  # from the shared `AuthFailureReason` table so the Audit Plane and
  # the Data Plane can never drift on what an atom means.
  defp send_auth_failure(conn, reason) do
    error_body =
      JSON.encode!(%{
        "error" => %{
          "message" => AuthFailureReason.message_for(reason),
          "type" => "invalid_request_error",
          "code" => Atom.to_string(reason)
        }
      })

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, error_body)
  end

  # ---------------------------------------------------------------------------
  # Rate-limit dispatch (F002 T092 / FR-030).
  #
  # Invoked from the `POST /v1/chat/completions` route AFTER successful
  # authentication and BEFORE dispatching to the handler. Returns the
  # original conn on pass-through (rate-limiting disabled OR under limit),
  # or a halted conn with a 429 body already sent on breach.
  #
  # Configuration:
  #   * `:rate_limit_enabled?` — master on/off switch (default false for
  #     test ergonomics; `config/standalone_gateway.exs` flips it on).
  #   * `:data_rate_limit` — keyword-list forwarded to `RateLimiter.init/1`
  #     (merged with `plane: :data, limit: 60` defaults).
  # ---------------------------------------------------------------------------
  # Provider-aware LoginHandler opts selection. Reads
  # `:browser_oidc_idp.provider` (set by `config/runtime.exs` from the
  # `BROWSER_OIDC_PROVIDER` env var):
  #   * `"workos"` (dogfood default) → `Workos.default_*` callbacks;
  #     the WorkOS adapter handles code exchange + access_token
  #     verification + cookie-payload assembly without the broker.
  #   * any other value (`"oidc"`, `"okta"`, etc.) → broker-mediated
  #     defaults (the F002/F004 production wiring).
  defp login_handler_opts do
    idp_config = Application.get_env(:recurse_gateway, :browser_oidc_idp, [])
    provider = Keyword.get(idp_config, :provider, "workos")

    case provider do
      "workos" ->
        workos_config = Application.get_env(:recurse_gateway, :workos, [])

        [
          # WorkOS authorize URL is the WorkOS API base + path; the
          # `provider=authkit` + `organization_id` extras ride via
          # `:authorize_extra_params`.
          authorize_url:
            String.trim_trailing(
              Keyword.get(workos_config, :api_base, "https://api.workos.com"),
              "/"
            ) <>
              "/user_management/authorize",
          # WorkOS uses JSON, not form-encoded — handled inside the
          # adapter's `default_code_exchanger/3`. The LoginHandler still
          # reads `:idp_token_url` for the (unused) default path; we set
          # it for completeness so a misconfigured opt doesn't surprise.
          idp_token_url:
            String.trim_trailing(
              Keyword.get(workos_config, :api_base, "https://api.workos.com"),
              "/"
            ) <>
              "/user_management/authenticate",
          client_id: Keyword.get(workos_config, :client_id),
          redirect_uri: Keyword.get(workos_config, :redirect_uri),
          # `gateway_origin` controls where post-callback redirects land
          # (e.g., the `/admin/dashboard` URL the SPA bounces to after
          # cookie-set). Derive from the WorkOS `:redirect_uri`
          # (scheme + host), falling back to the runtime public hostname
          # for callers that provide WorkOS config directly in tests.
          gateway_origin: derive_gateway_origin(workos_config),
          # WorkOS AuthKit doesn't use an explicit `scope` query param.
          scope: "",
          authorize_extra_params: workos_authorize_extras(workos_config),
          # WorkOS-specific seam callbacks bypass the broker entirely.
          code_exchanger: &Recurse.Gateway.Admin.BrowserAuth.Workos.default_code_exchanger/3,
          id_token_validator: &Recurse.Gateway.Admin.BrowserAuth.Workos.default_validator/2,
          token_exchange: &Recurse.Gateway.Admin.BrowserAuth.Workos.default_exchange/3
        ]

      _other ->
        # Broker-mediated defaults — F002/F004 production wiring.
        [
          id_token_validator:
            &Recurse.Gateway.Admin.BrowserAuth.LoginHandler.default_id_token_validator/2,
          token_exchange: &Recurse.Gateway.Admin.BrowserAuth.LoginHandler.default_token_exchange/3
        ]
    end
  end

  defp workos_authorize_extras(workos_config) do
    base = %{"provider" => "authkit"}

    case Keyword.get(workos_config, :default_organization_id) do
      org_id when is_binary(org_id) and org_id != "" -> Map.put(base, "organization_id", org_id)
      _ -> base
    end
  end

  # Derive `gateway_origin` from `WORKOS_REDIRECT_URI`. The redirect URI
  # is `https://<host>/admin/login/callback`; the gateway_origin is just
  # `https://<host>`.
  defp derive_gateway_origin(workos_config) do
    workos_config
    |> Keyword.get(:redirect_uri)
    |> gateway_origin_from_redirect_uri()
  end

  defp gateway_origin_from_redirect_uri(uri) when is_binary(uri) and uri != "" do
    uri
    |> URI.parse()
    |> gateway_origin_from_uri()
  end

  defp gateway_origin_from_redirect_uri(_), do: configured_public_hostname()

  defp gateway_origin_from_uri(%URI{scheme: scheme, host: host, port: port})
       when is_binary(scheme) and is_binary(host) do
    if default_uri_port?(scheme, port) do
      "#{scheme}://#{host}"
    else
      "#{scheme}://#{host}:#{port}"
    end
  end

  defp gateway_origin_from_uri(_), do: configured_public_hostname()

  defp configured_public_hostname do
    Application.get_env(:recurse_gateway, :public_hostname, "http://127.0.0.1:4000")
  end

  defp default_uri_port?(_scheme, nil), do: true
  defp default_uri_port?("https", 443), do: true
  defp default_uri_port?("http", 80), do: true
  defp default_uri_port?(_scheme, _port), do: false

  # F004 T145 — apply security headers to F004 admin/JSON responses.
  defp apply_security_headers(conn) do
    Recurse.Gateway.Plug.SecurityHeaders.call(
      conn,
      Recurse.Gateway.Plug.SecurityHeaders.init([])
    )
  end

  @spec apply_rate_limit(Plug.Conn.t(), :data | :audit) :: Plug.Conn.t()
  defp apply_rate_limit(conn, :data) do
    if Application.get_env(:recurse_gateway, :rate_limit_enabled?, false) do
      opts =
        Application.get_env(:recurse_gateway, :data_rate_limit, [])
        |> Keyword.put_new(:plane, :data)
        |> Keyword.put_new(:limit, 60)

      plug_opts = Recurse.Gateway.Plug.RateLimiter.init(opts)
      Recurse.Gateway.Plug.RateLimiter.call(conn, plug_opts)
    else
      conn
    end
  end

  # FR-024 — canonical tier-mismatch body. Kept as a single function so
  # the emitted JSON shape is identical on every matched path.
  defp send_tier_mismatch(conn, required_tier) do
    body =
      JSON.encode!(%{
        "error" => %{
          "code" => "ERR_TIER_MISMATCH",
          "message" =>
            "Endpoint requires the #{required_tier}; this deployment is standalone_gateway.",
          "details" => %{
            "active_tier" => "standalone_gateway",
            "endpoint_requires_tier" => required_tier
          }
        }
      })

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(501, body)
  end
end
