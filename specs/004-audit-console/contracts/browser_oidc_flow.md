# Contract: Browser OIDC Flow + Session Cookie

**Feature**: F004 | **Spec**: FR-001 through FR-004 (Q1 clarification) | **Research**: D6 | **Glossary**: Browser Session, Session Cookie

This contract defines the browser-redirect OIDC flow that authenticates audit-console users and the **Session Cookie** mechanism that persists their authenticated state across page loads. The flow uses a **same-origin deployment topology**: the Gateway hosts the login surface (`GET /admin/login/start`, `GET /admin/login/callback`) and proxies token-exchange work into the F002 broker (`apps/recurse_broker/`) via in-VM call (or HTTP if the broker is split out). The Gateway also hosts a new plug (`BrowserSessionPlug`).

**Architectural note**: in F004 the broker no longer owns its own login surface. The Gateway owns the login surface; the broker is purely a token-exchange engine (RFC 8693). This is intentional — it gives us a single origin for the cookie, the SPA, and all `/v1/*` API calls, which avoids cross-domain cookie complexity, CORS, and host-only-cookie pitfalls.

---

## Identity-flow overview

The Gateway is the single browser-facing origin. All login traffic, the SPA, and all `/v1/*` API calls share `https://gateway.example.com`. The broker is reached only over a same-VM (or same-cluster) internal call.

```
┌────────┐                          ┌────────┐                      ┌────────┐                         ┌──────────┐
│Browser │                          │Gateway │                      │ Broker │                         │   IdP    │
└────┬───┘                          └────┬───┘                      └────┬───┘                         └────┬─────┘
     │  GET /admin/dashboard             │                                  │                                │
     │─────────────────────────────────▶│                                  │                                │
     │                                   │  no session cookie               │                                │
     │  302 to /admin/login/start       │                                  │                                │
     │◀─────────────────────────────────│                                  │                                │
     │  GET /admin/login/start          │                                  │                                │
     │─────────────────────────────────▶│  internal call:                 │                                │
     │                                   │  request login start             │                                │
     │                                   │─────────────────────────────────▶│                                │
     │                                   │                                  │  generate state+code_verifier  │
     │                                   │                                  │  INSERT oidc_login_nonces row  │
     │                                   │  IdP redirect URL + state        │                                │
     │                                   │◀─────────────────────────────────│                                │
     │  302 to IdP authorize            │                                  │                                │
     │◀─────────────────────────────────│                                  │                                │
     │  GET https://idp/authorize?...   │                                  │                                │
     │────────────────────────────────────────────────────────────────────────────────────────────────▶│
     │                                   │  user authenticates              │                                │
     │  302 to /admin/login/callback    │                                  │                                │
     │◀────────────────────────────────────────────────────────────────────────────────────────────────│
     │  GET /admin/login/callback?...   │                                  │                                │
     │─────────────────────────────────▶│  internal call:                 │                                │
     │                                   │  consume state + code            │                                │
     │                                   │─────────────────────────────────▶│                                │
     │                                   │                                  │  SELECT FOR UPDATE nonce row   │
     │                                   │                                  │  validate used_at IS NULL      │
     │                                   │                                  │  set used_at = now()           │
     │                                   │                                  │  POST IdP /token (PKCE)        │
     │                                   │                                  │───────────────────────────────▶│
     │                                   │                                  │  id_token                      │
     │                                   │                                  │◀───────────────────────────────│
     │                                   │                                  │  RFC 8693 token exchange       │
     │                                   │                                  │  → minted X-Observed-Identity  │
     │                                   │  minted JWT + return_to          │                                │
     │                                   │◀─────────────────────────────────│                                │
     │                                   │  Gateway sets Set-Cookie         │                                │
     │  302 to return_to                │  r5e_session=… ; Path=/          │                                │
     │◀─────────────────────────────────│                                  │                                │
     │  GET /admin/dashboard            │  (with cookie, same origin)      │                                │
     │─────────────────────────────────▶│                                  │                                │
     │                                   │  BrowserSessionPlug:             │                                │
     │                                   │   - decrypt cookie               │                                │
     │                                   │   - validate JWT exp claim       │                                │
     │                                   │   - lift JWT → Authorization    │                                │
     │                                   │   - JwtValidator runs            │                                │
     │                                   │   - rotate cookie (fresh        │                                │
     │                                   │     issued_at) on mutations     │                                │
     │  200 SPA bundle                  │                                  │                                │
     │◀─────────────────────────────────│                                  │                                │
```

---

## Step-by-step

### Step 1 — Initial visit (no cookie)

User lands at `https://gateway.example.com/admin/dashboard`. Gateway's `BrowserSessionPlug` runs first in the `/admin/*` pipeline.

`BrowserSessionPlug` checks for cookie `r5e_session` (cookie name configurable via tier-config; default `r5e_session`). Absent → 302 redirect to the same-origin login start endpoint:

```
HTTP/1.1 302 Found
Location: https://gateway.example.com/admin/login/start?return_to=%2Fadmin%2Fdashboard
```

Note `return_to` is URL-encoded and constrained to a path (no scheme/host) — the Gateway is the only origin that the Gateway will redirect to. The Gateway validates `return_to` is a path beginning with `/` and not `//` (which would otherwise let an attacker pass `//evil.example` and get a protocol-relative redirect).

### Step 2 — Gateway `/admin/login/start` (proxies to broker)

**HTTP**: `GET /admin/login/start?return_to=<path>`

The Gateway's handler is a thin shim that calls the broker's `BrokerLoginHandler.start_login/2` (in-VM; or HTTP `POST /internal/login/start` when the broker is split out). Broker logic:

1. Validate `return_to` is a Gateway-relative path (received from the Gateway after Gateway-side validation). Reject with `400 invalid_return_to` otherwise.
2. Generate `state` (32 random bytes, base64url) — CSRF token. **State is opaque to the browser**: it is sent to the IdP, which echoes it back; the browser cannot decrypt or derive the corresponding `code_verifier`. The `oidc_login_nonces` table is the only place `state` is correlated to `code_verifier` + `return_to`. An exfiltrated cookie therefore cannot be replayed via state-substitution alone.
3. Generate `code_verifier` (43–128 bytes, base64url) per RFC 7636 PKCE; compute `code_challenge = base64url(sha256(code_verifier))`.
4. **INSERT** a row into the Postgres-backed `oidc_login_nonces` table (schema below). The row is the durable, federation-safe record of the in-flight login.
5. Return the IdP redirect URL + `state` to the Gateway. The Gateway 302s the browser to the IdP:

```
HTTP/1.1 302 Found
Location: https://idp.example.com/authorize?
  response_type=code&
  client_id=<broker-client-id>&
  redirect_uri=https%3A%2F%2Fgateway.example.com%2Fadmin%2Flogin%2Fcallback&
  scope=openid%20profile%20email%20groups&
  state=<state>&
  code_challenge=<code_challenge>&
  code_challenge_method=S256
```

Note the `redirect_uri` is the Gateway, not the broker — the IdP will redirect the browser back to the Gateway origin (Step 4).

#### `oidc_login_nonces` table (new in F004)

```
oidc_login_nonces
  id              uuid primary key default gen_random_uuid()
  state           text not null            -- random CSRF token sent to IdP
  code_verifier   text not null            -- PKCE verifier
  return_to       text not null            -- Gateway-relative path
  tenant_id       text not null            -- which tenant's IdP / login surface
  created_at      timestamptz not null default now()
  used_at         timestamptz null         -- single-use; set when callback consumes the row
  expires_at      timestamptz not null     -- created_at + 10 minutes

  unique index (state)
  index (expires_at)                       -- TTL purge support
```

**Why Postgres, not ETS** (Constitution v1.3.0 Principle I — federated deployments): a user starting login on Gateway A and returning to Gateway B (round-robin load balancer, no sticky sessions) must succeed. Node-local ETS fails on round-robin; Postgres is shared state across all Gateway nodes pointed at the same database, so PKCE state survives the cross-node hop.

**Lookup contract**:
- `/admin/login/start`: INSERT a row, return `state` to the Gateway → embedded in the IdP redirect.
- `/admin/login/callback`: `SELECT … FOR UPDATE` by `state`, validate `used_at IS NULL` and `expires_at > now()`, set `used_at = now()`, COMMIT, then proceed to token exchange.
- **Single-use enforcement**: a replay attempt against a row with `used_at IS NOT NULL` returns `400 state_already_used` (audit-distinguishable from a never-issued state). `SELECT FOR UPDATE` serializes concurrent callback attempts on the same `state`.
- **TTL purge**: `DELETE FROM oidc_login_nonces WHERE expires_at < now() - INTERVAL '1 hour'` runs every 5 minutes. Implemented as an `Oban.Cron` job (`Recurse.Gateway.Admin.OidcNoncePurger`) — the F004 plan already pulls in `oban` for retention purging (D7), so reusing it here costs nothing and gives us telemetry + retry semantics for free. (We picked Oban.Cron over `:timer.send_interval` so a Gateway crash mid-purge doesn't drop scheduled work.)

### Step 3 — IdP authentication

The user authenticates at the IdP (out of scope; F004 doesn't constrain IdP UX). IdP redirects back to the Gateway origin (the `redirect_uri` registered with the IdP):

```
HTTP/1.1 302 Found
Location: https://gateway.example.com/admin/login/callback?state=<state>&code=<authorization_code>
```

### Step 4 — Gateway `/admin/login/callback` (proxies token exchange to broker)

**HTTP**: `GET /admin/login/callback?state=<state>&code=<code>`

The Gateway's handler calls into the broker (`BrokerLoginHandler.complete_login/3`) for steps 1–5; the Gateway itself owns step 6+ (cookie-setting and the final redirect, which must originate from the Gateway origin).

Broker logic (steps 1–5):
1. `SELECT … FOR UPDATE` from `oidc_login_nonces` by `state`. Not found → `400 invalid_state`. Found but `used_at IS NOT NULL` → `400 state_already_used`. Found but `expires_at <= now()` → `400 state_expired`. (All three emit attested `:ui_login` receipts with the corresponding `outcome` field.)
2. Set `used_at = now()` on the row, COMMIT. The `SELECT FOR UPDATE` ensures concurrent callback attempts on the same `state` race exactly once: the second loses with `state_already_used`.
3. Exchange `code` at the IdP token endpoint:
   ```
   POST https://idp.example.com/token
   grant_type=authorization_code
   code=<code>
   redirect_uri=https://gateway.example.com/admin/login/callback
   client_id=<broker-client-id>
   code_verifier=<code_verifier>
   ```
   Receive `id_token` + `access_token` from IdP.
4. Validate `id_token` (signature against IdP JWKS, `aud`, `iss`, `exp`, `nbf`).
5. Run the F002 RFC 8693 token-exchange path with `subject_token=id_token`, `subject_token_type=urn:ietf:params:oauth:token-type:id_token`, `audience=recurse-gateway-prod`. Mint the `X-Observed-Identity` JWT. Return `{minted_jwt, principal_subject, browser_session_id, tenant_id, return_to}` to the Gateway.

Gateway logic (steps 6–8):

6. Build the Session Cookie payload: `{jwt: <minted_jwt>, issued_at: <unix_ts>, last_activity_at: <unix_ts>, browser_session_id: <uuid_v4>}`. Sign + encrypt per D6 (`Plug.Crypto.MessageEncryptor` with `gateway.admin.session_secret_key_base`).
7. Emit attested `:ui_login` receipt with `outcome: "success"`, `principal_subject`, `browser_session_id`, `tenant_id`.
8. 302 redirect to `return_to` with `Set-Cookie` issued **at the Gateway origin** with `Path=/`:

```
HTTP/1.1 302 Found
Set-Cookie: r5e_session=<encrypted_payload>; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800
Location: /admin/dashboard
```

**Failure paths** (each emits an attested `:ui_login` receipt with the corresponding `outcome` field):

| Failure | HTTP | `outcome` |
|---|---|---|
| State not found in `oidc_login_nonces` | 400 | `state_invalid` |
| State found but `used_at IS NOT NULL` (replay attempt) | 400 | `state_already_used` |
| State found but `expires_at <= now()` (timed out) | 400 | `state_expired` |
| IdP code exchange fails | 502 | `idp_unreachable` or `idp_code_exchange_failed` |
| `id_token` signature invalid | 401 | `id_token_invalid` |
| Internal RFC 8693 token-exchange fails (e.g., role mapping returns no role + no default) | 403 | `jwt_mint_failed` |
| Catastrophic | 500 | `internal_error` |

On failure the Gateway renders an error page with a "Try sign-in again" link to `/admin/login/start`.

### Step 5 — Session Cookie attributes (per D6)

| Attribute | Value | Reason |
|---|---|---|
| `HttpOnly` | yes | Prevent JS-side reads (XSS defense). |
| `Secure` | yes (production); configurable in dev tier-config | Prevent transmission over plain HTTP. |
| `SameSite` | `Lax` | CSRF defense for cross-origin POST/PUT/DELETE while still permitting top-level GET navigations from the IdP redirect. `Strict` would block the cookie on the IdP→Gateway top-level GET callback, breaking the OAuth flow. Lax is the standard choice for OAuth-based session cookies. (Cross-origin `fetch()` from a malicious page still cannot send credentialed mutating requests, so the CSRF surface is limited to top-level GETs — which the SPA does not use for state-changing operations.) |
| `Path` | `/` | Cookie reaches BOTH `/admin/*` (the SPA shell) AND `/v1/*` (the SPA's authenticated API calls). Same-origin deployment makes this safe: there is no cross-application leakage because the Gateway is the sole origin. |
| `Max-Age` | `28800` (8 hours) | Absolute timeout per Q1. |
| `Domain` | (unset) | Cookie restricted to the Gateway's exact host (no subdomain leakage). |

**Why same-origin** (resolves the Path-mismatch hazard from earlier drafts):

- A previous design had the broker setting `Set-Cookie` while redirecting to the Gateway origin → the cookie became host-only at the broker and never reached the Gateway. Browsers correctly refused to send it.
- A previous design had `Path=/admin` but used the cookie to authenticate `/v1/*` SPA calls. Browsers correctly refused to send the `/admin` cookie to `/v1/*`.
- The same-origin model fixes both: the Gateway sets the cookie on its own origin with `Path=/`, so every authenticated request from the SPA carries the cookie regardless of whether it lands on `/admin/*` or `/v1/*`.

### Step 6 — `BrowserSessionPlug` on the Gateway

For every request under `/admin/*` and `/v1/*` (the SPA's authenticated API paths):

1. Read `r5e_session` cookie. Absent → for `/admin/*` HTML requests, 302 to `/admin/login/start` (per Step 1); for `/v1/*` API requests, return `401 {"error_code": "session_missing"}` so the SPA's `useAuth` hook handles the redirect client-side.
2. Decrypt + verify cookie via `Plug.Crypto.MessageEncryptor`. Tampering / wrong-key → drop cookie + 401/302 with `cookie_invalid`.
3. **Cookie envelope expiry** (8h absolute). Read `issued_at` from payload. Compute `now - issued_at`:
   - `> 28800s` (8h) — **absolute timeout**. Drop cookie + emit `:ui_session` with `event: "absolute_timeout"` + 401/302.
   - `> 3600s` since `last_activity_at` (60-minute idle, refreshed by mutation-rotation — see step 6) — **idle timeout**. Drop cookie + emit `:ui_session` with `event: "idle_timeout"` + 401/302.
4. **JWT validity check** (independent of cookie envelope expiry — addresses cookie-outliving-JWT replay). Decode `payload.jwt` (no signature verify yet — `JwtValidator` does that downstream). Read the `exp` claim. If `exp <= now()`:
   - Attempt **silent refresh** server-side: call the broker's RFC 8693 re-issue path with the cached `subject_token`. On success, replace `payload.jwt` with the freshly minted JWT and continue.
   - On refresh failure (broker unreachable, refresh token expired, IdP revoked): drop cookie + emit `:ui_session` with `event: "jwt_expired_refresh_failed"` + return `401 {"error_code": "session_expired"}` (or 302 for HTML routes). The SPA's `useAuth` hook reacts by redirecting to `/admin/login/start`.
   - **Two independent expiration layers**: the cookie envelope (8h absolute, 60min idle) and the JWT (15-min TTL with silent refresh) are independent. **Both must pass** for a request to be authenticated. This closes the cookie-outlives-JWT replay window: an exfiltrated cookie cannot carry an expired JWT past TTL because the plug rejects requests whose JWT `exp <= now` even when the cookie envelope is still valid.
5. Lift `payload.jwt` into the `Authorization: Bearer <jwt>` request header (overwriting any client-supplied header).
6. **Cookie rotation policy** (mutation-only — addresses tab-restore race):
   - **GET / HEAD / OPTIONS** requests: do NOT rotate. The cookie's `issued_at` and `last_activity_at` are read-only on these methods. Rationale: tab-restore commonly fires 10+ parallel GETs (page load, asset prefetch, `/v1/auth/me`, `/v1/audit/...` etc.); rotating each would force the per-browser-session "latest issued_at" cache through a single-writer queue and most parallel requests would lose the race, producing spurious "you've been signed out" toasts.
   - **POST / PATCH / PUT / DELETE** requests: rotate. Write a new `Set-Cookie` header with bumped `issued_at = now` and `last_activity_at = now`. These are user-initiated and don't fire 10 in parallel.
   - **Tradeoff (documented explicitly)**: this trades a slightly larger replay window for a stolen cookie (an attacker can re-use the same `issued_at` across multiple GETs until the user issues a mutation, after which the old cookie is dead) for tab-restore reliability and lower contention on the per-session cache. The replay window is bounded by the user's next mutation in practice — typically seconds to minutes for an active user. For an idle session the cookie envelope's 60-minute idle timeout is the upper bound.
   - On every authenticated request (GET or mutation), `last_activity_at` IS bumped in the in-memory session cache for idle-timeout enforcement; only the cookie's encrypted payload is left untouched on GETs.
7. Pass control to the next plug (`JwtValidator`) — full signature verification + JTI deny-list check + scope enforcement, per F002.

**Idle vs absolute distinguishability** (per FR-003): the timeouts emit distinct `:ui_session` event subtypes (`event: "idle_timeout"` vs `"absolute_timeout"` vs `"jwt_expired_refresh_failed"`) so an auditor can filter the audit log to see which expired and when.

**Silent JWT refresh** (per Q1): proactive refresh — when the BrokerJWT inside the cookie is within 60 seconds of expiring (`exp - now < 60`) and the request is a mutation (so we're rotating the cookie anyway), the BrowserSessionPlug fires an internal RFC 8693 token-exchange call, updates the cookie payload, and re-rotates. Reactive refresh — step 4 above handles the case where a GET request arrives with an already-expired JWT (rotation skipped, but cookie payload's `jwt` field is updated in-place via a `Set-Cookie` write only on the refresh path). The user-visible session remains uninterrupted.

---

## Sign-out

### `POST /admin/logout`

**HTTP**: `POST /admin/logout` (same-origin, mutation method — `SameSite=Lax` blocks cross-origin POSTs; an additional CSRF token in a custom header `X-Recurse-CSRF` echoed from `/v1/auth/me` defends against same-origin XSS-injected POSTs).

Logic:
1. Read cookie; if absent, treat as already-logged-out (idempotent, return 200).
2. Decrypt cookie; extract JWT + browser_session_id.
3. **Invalidate JWT replay-cache** (per FR-004): the broker maintains a JTI deny-list in its replay cache; logout adds the JTI to the deny-list with TTL = remaining `exp` time. F002's JwtValidator already checks the deny-list on every JTI; the JWT cannot be replayed.
4. Emit attested `:ui_session` receipt with `event: "logout"`, `principal_subject`, `browser_session_id`.
5. Clear cookie at the Gateway origin (matches Set-Cookie attributes from Step 5):
   ```
   Set-Cookie: r5e_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0
   ```
6. Return 200 with `{redirect_to: "/admin/login?logged_out=1"}`.

The SPA receives the 200, navigates to the login page, and shows a "You've been signed out" toast.

---

## Error states and recovery

| State | UX | Backend behavior |
|---|---|---|
| IdP unreachable | Gateway error page with "Try again." | `:ui_login` `outcome: idp_unreachable`. Auto-retry NOT performed; user-driven retry. |
| `state` expired (10-min window) | Gateway error page "Sign-in attempt expired; please try again." | `:ui_login` `outcome: state_expired` (`expires_at <= now()` on lookup). |
| State mismatch (not found in `oidc_login_nonces`) | Gateway error page "Sign-in flow corrupted (possible CSRF); please try again." | `:ui_login` `outcome: state_invalid`. |
| State replay (`used_at IS NOT NULL`) | Gateway error page "Sign-in flow already completed; if this is unexpected, contact your admin." | `:ui_login` `outcome: state_already_used`. |
| JWT mint fails (no role) | Gateway error page "Your account has no audit-console role; contact your admin." | `:ui_login` `outcome: jwt_mint_failed`. |
| Cookie tampered | SPA experiences a redirect loop fixed at first 302; no error message; an attested `:ui_session` `event: cookie_tampered` is emitted. | Receipt visible to operators in audit log. |

---

## Key rotation

Tier-config supports `[primary, [secondary]]` shape per D6:

```yaml
gateway:
  admin:
    session_secret_key_base: "<base64-32-bytes>"      # primary
    session_secret_keys_secondary: ["<base64-...>"]    # rotated-out keys still accepted for decrypt
```

Operator workflow:
1. Generate new key.
2. Edit tier-config: move existing primary into `secondary`, set new key as primary.
3. SIGHUP / restart Gateway.
4. After 8 hours (absolute timeout window has flushed), remove the now-stale `secondary` entries.

All currently active Browser Sessions silently re-encrypt their cookies under the new primary key on their next mutating request (rotation on POST/PATCH/PUT/DELETE — Step 6). For long-idle sessions, the silent JWT refresh path during an authenticated GET also re-encrypts under the current primary. After the 8-hour absolute window flushes, no remaining cookie can still be encrypted under the now-stale secondary; it is then safe to remove.

---

## Property-test surface (Surface V — see `property_test_surface_catalog_f004.md`)

- Round-trip: `(jwt, issued_at) → encrypt → decrypt → equals original`.
- Tampering rejection: any single-byte mutation of cookie ciphertext → decryption fails with structured error.
- Expiry enforcement: cookie with `issued_at = now - 8h - 1s` rejected; cookie with valid envelope but JWT `exp <= now` AND silent refresh disabled MUST also be rejected (two-layer expiration).
- Cross-key compatibility: cookie encrypted with primary AND with secondary both decrypt successfully when both keys are configured; secondary-only after primary rotation also works.
- **Replay (mutation-only rotation)**: concurrent GETs carrying the same cookie all succeed (cookie is read-only on GETs); concurrent mutations carrying the same cookie all succeed in their first-pass auth check, but only one wins the rotation race in the per-session `(browser_session_id, latest_issued_at)` cache — the others receive a fresh cookie chain with the post-rotation `issued_at`. A subsequent mutation that re-uses a *previous* mutation's `issued_at` (i.e., a true replay) MUST be rejected.

---

## Out of scope

- SAML 2.0 SSO. F004 supports OIDC only via the Gateway's `/admin/login/start` flow; SAML is deferred to F005+ (the broker may be extended to SAML at a later slice).
- IdP-initiated sign-on (SP-initiated only).
- Step-up authentication (e.g., for high-stakes policy operations). Day-2+.
- Multiple identity providers per deployment. The broker assumes one primary IdP per tenant in F004 (matches F002 broker assumption).
