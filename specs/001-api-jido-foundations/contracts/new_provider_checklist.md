# Deliverable C — New-Provider Acceptance Checklist

**Feature**: 001-api-jido-foundations
**User Story**: US2 — Add a new provider without touching core
**Enforces**: FR-003, FR-004, Constitution v1.3.0 Principle V
**Satisfies success criteria**: SC-002, SC-017

This checklist is the code-review gate for any PR that adds or modifies a
concrete Provider Interface implementation (an `impls/*` module under
`apps/recurse_providers/`). It is **binding** — a PR that fails any section
below does NOT merge until remediated. Reviewers are explicitly authorised
(and expected) to request change on the first violation rather than invent
a "mostly good enough" path.

The static counterpart to this human review is the custom Credo check
`Recurse.Credo.ProviderNeutrality`
(`apps/recurse_shared/lib/recurse_shared/credo/provider_neutrality.ex`).
Running `mix credo --strict` catches most "prohibited-path edits" before
the PR lands; this checklist catches the structural / contract-level
issues that static analysis cannot.

---

## 1. Allowed add / register files

A conformant new-provider PR touches **only** the following paths. Any
diff outside this set is a prima-facie violation of FR-004.

| Path | Allowed change |
|---|---|
| `apps/recurse_providers/lib/recurse_providers/impls/<name>_<interface>.ex` | **Add** — the concrete implementation module |
| `apps/recurse_providers/lib/recurse_providers/impls/<name>_<interface>/*.ex` | **Add** — helpers scoped to this impl (e.g. request building, decoder) |
| `apps/recurse_providers/test/impls/<name>_<interface>_test.exs` | **Add** — per-impl unit tests |
| `apps/recurse_providers/test/contract/<interface>_test.exs` | **Modify only to add a per-impl test case** that wires the new impl into the existing contract harness (T061). Do not edit the shared assertions. |
| `apps/recurse_providers/lib/recurse_providers/application.ex` | **Modify** — exactly one line adding the impl to the child list or provider registry (example diff in §6) |
| `config/*.exs` (tier-config stubs) | **Modify** — tier-config wiring only (which impl a tier uses); no business logic |
| `mix.lock` | **Modify** — only the transitive deps introduced by this PR |
| `apps/recurse_providers/mix.exs` | **Modify** — only if a *new* vendor SDK dep is required (e.g. `:hackney` for a Cloudflare impl). The dep MUST be scoped so it cannot escape this umbrella app. |
| `specs/001-api-jido-foundations/contracts/provider_matrix/<name>.md` (optional) | **Add** — impl-specific notes, IdP quirks, required env vars |

> **Pattern recap** — `<name>` is the vendor / distro tag (e.g.
> `openai`, `anthropic`, `bedrock`, `vault`, `okta`, `trillian`,
> `postgres_merkle`). `<interface>` is one of `llm`, `ledger`, `storage`,
> `secrets`, `identity`, `principal`, `policy`. Example:
> `impls/openai_llm.ex`.

## 2. Prohibited edits

Any of the following is a blocking review finding:

- **Any change** under `apps/recurse_gateway/lib/recurse_gateway/`.
  Business logic lives here and is provider-agnostic. Adding a provider
  must never require editing Gateway code. Exception: the tier-config
  loader in Gateway may gain a new well-known tier-config key only via a
  separate, non-provider PR. Do not combine.
- **Any change** under `apps/recurse_runtime/lib/recurse_runtime/`. Same
  rationale as Gateway.
- **Any edit** to a Provider Interface *behaviour* file
  (`apps/recurse_providers/lib/recurse_providers/*_provider.ex`). A new
  impl that thinks the behaviour needs a new callback must open a
  separate RFC; behaviours evolve by review, not by impl-PR fiat
  (Constitution Principle V).
- **Any edit** to `apps/recurse_shared/lib/recurse_shared/`. Shared types
  (IdentityContext, Principal, Envelope, etc.) are immutable contracts
  downstream of this PR. If a new impl needs a new shared type, file a
  separate `recurse_shared` PR first.
- **Any edit** to
  `apps/recurse_shared/lib/recurse_shared/credo/provider_neutrality.ex`.
  If the check is flagging a false positive, update its allow-list via a
  security-reviewed PR — do **not** silence it.
- Adding a vendor SDK to `apps/recurse_shared/mix.exs` or
  `apps/recurse_gateway/mix.exs` or `apps/recurse_runtime/mix.exs`.
  Vendor deps live in `apps/recurse_providers/mix.exs` **only**.
- Editing `.credo.exs` to exclude the new impl from PI-neutrality
  scanning. The impl tree (`.../impls/`) is already exempt from the
  check; any attempt to widen the exclusion is a blocking finding.
- Skipping, renaming, or deleting a contract-test case from the
  behaviour-level contract suite at
  `apps/recurse_providers/test/contract/<interface>_test.exs`. Adding a
  new test case for impl-specific behaviour is fine; removing the
  baseline suite is not.

## 3. Required artifacts in the PR

Reviewer MUST verify each line item is present and green before approving.

### 3.1 Behaviour conformance

- [ ] Module declares `@behaviour Recurse.Providers.<Interface>Provider`
      at the top.
- [ ] Every `@callback` in the interface has a matching `def` with the
      correct arity. `mix compile --warnings-as-errors` is green (the
      compiler flags missing callback implementations).
- [ ] The Mox-driven contract test
      `apps/recurse_providers/test/contract/<interface>_test.exs`
      includes a new case wired to this impl, and passes:
      `mix test apps/recurse_providers/test/contract/<interface>_test.exs`.

### 3.2 Capability flags

- [ ] `capabilities/1` is implemented.
- [ ] The advertised capabilities are a subset of
      `Recurse.Providers.<Interface>Provider.capability/0` — no
      home-rolled atoms.
- [ ] Capabilities match reality — if the impl advertises
      `:streaming` but `chat_complete_stream/3` returns
      `{:error, :not_implemented}`, that's a blocking finding.
- [ ] For `PrincipalProvider`: `supports_rfc8693?/1` returns `true` if
      and only if the paired `SecretsProvider` in the same tier config
      implements `exchange_for_downstream_token/4`. Cross-check the
      tier-config wiring (FR-047 composition rule).

### 3.3 Telemetry events

- [ ] Emits `:telemetry.execute([:recurse, :providers, :<interface>,
      :<operation>], measurements, metadata)` for every public
      callback it implements. Measurement map MUST include
      `:duration_native`; metadata MUST include
      `:provider` (the impl-module atom) and
      `:result` (`:ok` / `:error`).
- [ ] Error metadata MUST include an error-code string drawn from the
      canonical wire vocabulary (per-domain mappers in
      `apps/recurse_gateway/lib/recurse_gateway/identity/auth_failure_reason.ex`,
      `apps/recurse_gateway/lib/recurse_gateway/audit_plane/authz.ex`,
      `apps/recurse_gateway/lib/recurse_gateway/admin/browser_session_plug.ex`)
      — no raw exception messages. (The legacy `Recurse.Shared.ErrorCodes`
      atom enum was retired in MR #30/Task M.)
- [ ] Telemetry event names are documented in the impl's
      `@moduledoc` under a `## Telemetry` section.

### 3.4 Metrics registration

- [ ] Adds Prometheus metric definitions to
      `apps/recurse_providers/lib/recurse_providers/metrics.ex` (or the
      equivalent central metrics module) — **not** inline in the impl
      itself. This keeps the metrics registry centralised.
- [ ] Metric names follow the convention
      `recurse_providers_<interface>_<operation>_*` — e.g.
      `recurse_providers_llm_chat_complete_duration_seconds`.
- [ ] Counters for error rates MUST carry an `error_code` label
      drawn from the canonical wire vocabulary (see Telemetry-events
      checklist item above for source modules).

### 3.5 Healthcheck

- [ ] `healthcheck/1` is implemented and returns `:ok`,
      `{:degraded, reason}`, or `{:down, reason}` per the interface
      spec. No raising / crashing.
- [ ] The impl is registered with the Gateway `/healthz` aggregator
      (FR-014) via the tier-config wiring — verify the aggregator
      includes this impl in at least one reference tier config.
- [ ] `healthcheck/1` has a bounded execution time. The Gateway
      aggregator times out individual checks at 5 seconds; impls that
      can take longer must implement internal timeouts and fall back to
      `{:degraded, :healthcheck_timeout}`.

### 3.6 Identity handling (defense-in-depth)

- [ ] The impl accepts `Recurse.Shared.IdentityContext.t()` on every
      callback where the interface spec says it does, and **does not**
      modify it (SC-016).
- [ ] The impl does NOT inject principal / identity claims into outbound
      request bodies (FR-026: that is the Gateway's job, not the impl's).
      A request builder that copies `identity_ctx.principal` into a
      custom HTTP header for the upstream is a blocking finding.
- [ ] For `SecretsProvider` specifically: signing key *material* never
      crosses the provider boundary. `sign/3` routes bytes through the
      KMS backend — no `private_key: <pem>` return values.

### 3.7 Security sign-off artifacts (SecretsProvider / PrincipalProvider / IdentityProvider only)

- [ ] A security-review note under `docs/security/provider_reviews/<name>.md`
      summarising: the backend's auth model, which secrets are cached
      and for how long, failure modes (including "what happens if the
      backend becomes unreachable mid-request"), and the incident-runbook
      entry.
- [ ] No hard-coded secrets in the impl source. Token strings, client
      IDs, bearer tokens, etc. all load from tier config (which in turn
      reads from customer-provided Secret Store).

### 3.8 Documentation

- [ ] `@moduledoc` declares WHICH behaviour, names the reference
      deployment shape ("AWS Managed SaaS", "Air-Gapped Appliance",
      etc.), lists all env / tier-config keys the impl reads, and
      references the behaviour's contract-test file.
- [ ] README stub under
      `apps/recurse_providers/lib/recurse_providers/impls/<name>_<interface>/README.md`
      (or inline in `@moduledoc`) explaining: one-line purpose, config
      keys, capabilities advertised, known limitations.

## 4. Grep-able anti-patterns

Reviewer runs this table against the PR diff. A hit is a blocking
finding unless explicitly justified in a PR comment and signed off per
§6.

| # | Pattern (ripgrep regex) | Scope | Finding |
|---|---|---|---|
| 1 | `^import ExAws` | `apps/recurse_gateway/`, `apps/recurse_runtime/`, `apps/recurse_shared/` | FR-004 violation — AWS SDK outside provider impls |
| 2 | `^alias ExAws` | same | same |
| 3 | `^alias Finch` | `apps/recurse_gateway/`, `apps/recurse_runtime/` | FR-004 violation — HTTP client outside provider impls |
| 4 | `^alias HTTPoison\|^alias Tesla\|^alias Mint` | `apps/recurse_gateway/`, `apps/recurse_runtime/` | FR-004 violation |
| 5 | `^alias Postgrex` | `apps/recurse_gateway/`, `apps/recurse_runtime/` | FR-004 violation — DB driver outside provider impls / Ecto boundary |
| 6 | `private_key.*=>.*<<` or `:private_key, <<` | any provider impl | Likely raw key material leaking the provider boundary (SecretsProvider §3.6) |
| 7 | `System.get_env\|System.fetch_env!` | any provider impl | Blocking unless paired with a tier-config fallback. All impl config must route through tier config, not direct env reads. |
| 8 | `IO.puts\|IO.inspect\|Logger.debug(.*identity` | any provider impl | Identity / principal must never be logged at debug level in plaintext |
| 9 | `defmodule.*do(?:[\s\S](?!@behaviour))*defp? init\(` (multiline) | any `impls/*.ex` | Impl lacks `@behaviour` declaration |
| 10 | `Recurse\.Shared\.IdentityContext\.new` | `impls/` | Only the Gateway ingress constructs IdentityContext; impls receiving one and rebuilding a new one violates SC-016 immutability |
| 11 | `Recurse\.Providers\..*Provider\b` in `apps/recurse_gateway/lib/`, direct call | Gateway | Gateway MUST call the behaviour module via a configured tuple (e.g. `{impl_mod, state}`), never the behaviour module directly — this is what makes hot-swapping impls possible |
| 12 | `@callback.*def ` | any `impls/*.ex` | Adding `@callback` to an impl suggests the impl is reshaping the behaviour — see §2 prohibited edits |

Reviewer command template:

```bash
# Run from repo root against the PR branch diff:
git diff main --name-only | xargs rg --no-heading '^import ExAws|^alias ExAws|^alias Finch|^alias HTTPoison|^alias Tesla|^alias Mint|^alias Postgrex'
```

## 5. Tier-config wiring

Provider impls are activated via tier config (FR-013), not by
compile-time registration. Reviewer verifies:

- [ ] At least one reference tier config under `config/*.reference.yml`
      is updated to demonstrate how to wire the new impl. If the impl is
      not yet intended for any reference tier (experimental only), the
      PR description states that explicitly and the tier-config diff is
      omitted — but the impl is still registered in
      `apps/recurse_providers/lib/recurse_providers/application.ex` as
      a no-op child.
- [ ] Tier-config keys consumed by the impl are documented in the
      `tier_config.schema.json` — if the impl requires a new key, that's
      a schema-change PR that must land first (separate review).

## 6. Sign-off bar

Two-person review is mandatory for all Provider-Interface PRs. Roles:

- **Primary reviewer (always required)**: one senior Recurse
  engineer with Provider Interface authoring experience (has landed at
  least one prior impl, or is on the Provider-Interface steward rotation).
  Primary reviewer owns §1 through §4 and §8 (docs).
- **Security reviewer (required for SecretsProvider, PrincipalProvider,
  IdentityProvider)**: one member of the Security team. Security
  reviewer owns §3.6 and §3.7 and has explicit authority to block merge
  on identity / secrets / auth concerns.
- **Both reviewers must approve** the `application.ex` registry change —
  a one-line diff that nevertheless changes the Gateway's active
  dependency graph.

If an anti-pattern hit from §4 is intentional (e.g. a new impl that
genuinely needs `ExAws` — normal for an S3-backed StorageProvider), the
PR description MUST note each hit explicitly with a one-sentence
justification. Silent pattern-matching around the Credo check is a
trust-break.

### Single-line application.ex diff — the reference shape

The following is the **only** expected shape of an `application.ex`
diff. Anything more elaborate requires explanation in the PR body.

```diff
   def start(_type, _args) do
     children = [
       # ...existing children...
+      {Recurse.Providers.Impls.OpenAILLM, tier_config[:llm_provider_config]}
     ]

     opts = [strategy: :one_for_one, name: RecurseProviders.Supervisor]
     Supervisor.start_link(children, opts)
   end
```

---

## Appendix — "Before you open the PR" preflight

Run locally:

```bash
# From repo root:
mix compile --warnings-as-errors
mix credo --strict
mix test apps/recurse_providers/
mix test apps/recurse_providers/test/contract/<interface>_test.exs
```

All four must exit 0 before review is requested. A PR that opens with
any of these red is a distraction tax on reviewer time.
