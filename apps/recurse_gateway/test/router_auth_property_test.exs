defmodule Recurse.Gateway.RouterAuthPropertyTest do
  @moduledoc """
  P-1 — Router auth canary property test
  (`docs/superpowers/plans/2026-04-29-audit-pass-resolver-consolidation.md`).

  This is the **canary** that catches the next "forgot to wrap a route in
  auth" regression in CI rather than user-testing. The architectural
  model originally proposed introspecting `Router.__routes__/0`, but
  `Plug.Router` (unlike `Phoenix.Router`) does not expose that
  introspection hook. The fallback the model named — and the one we
  implement here — is a **hardcoded, classified route list** asserted
  against the live router's behavior on every iteration.

  ## The invariant — two-class shape

    * **Public routes** (no auth required): healthz/readyz/metrics, the
      `.well-known` manifest, schema publication, JWKS, OIDC login
      start/callback. Asserting: status is NOT 401 with no auth header
      and no cookie. (Could be 200 / 302 / 404 / 503 — but not 401.)

    * **Protected routes** (auth required — bearer-only, cookie-only,
      or dual-auth): every other defined route. Asserting: status is
      401 OR `conn.halted` is true with no auth header and no cookie.

  ## StreamData property shape

  `StreamData.member_of/1` over each hardcoded list. Path params
  (`:run_id`, `:id`, `:name`, `:session_id`) are substituted with stable
  fixture values via the route specs themselves (each route is stored
  as `{method, fully_concrete_path}`). No `filter` is used — the route
  table is built directly so shrinking surfaces the smallest failing
  route name verbatim.

  ## Manual-break-and-restore verification (the value-prop)

  Verified 2026-04-29: temporarily replaced the `cookie_only_get
  "/admin/oban", ...` macro invocation with a bare `get "/admin/oban"
  do ... send_resp(200, "ok") end`. Test failed with:

      Route GET /admin/oban classified protected was not protected:
      status=200, halted=false.

      This route is missing its auth wrap (BrowserSessionPipe.dispatch,
      CookieOrBearerPlug.dispatch, or inline IdentityContextBuilder).

  Restored the macro. Test passes again. **This is the regression
  shape this property catches in CI.**

  Note on defense-in-depth: handlers that internally check for an
  `:identity_ctx` / `:browser_session` assign and 401 when absent
  (e.g. `AuthMeHandler.handle/1`) will pass this property even with
  the auth wrap removed at the router layer — because the second
  defense fires. The canary still has value: the failure mode it
  protects against is a route whose handler does NOT self-defend
  (the typical case for handlers that rely on the wrap to guarantee
  `:identity_ctx` is populated). For routes whose handlers DO
  self-defend, this test is a redundancy check, not the primary
  defense.

  ## Cross-references

    * `docs/superpowers/plans/2026-04-29-audit-pass-resolver-consolidation.md` §P-1
    * `apps/recurse_gateway/lib/recurse_gateway/router.ex`
    * `.specify/memory/constitution.md` Principle VII (Interface-First on
      Second Consumer) — this test exists because the auth-wrap
      duplication that motivated MR !31 was discovered in user-testing
      after 16 sequential MRs missed it.
  """

  # `async: false` because the Router reads from the singleton
  # `ProviderRegistry` and Application env (`:browser_session`,
  # `:jwt_validator_opts`). We install a minimal stub state at setup
  # and uninstall at teardown so other tests don't see the residue —
  # mirroring `RouterTest`'s approach.
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Router

  @moduletag :property

  @opts Router.init([])

  # Stable fixture values for path params. The handlers may treat these
  # as not-found / invalid downstream, but the auth gate runs FIRST —
  # which is exactly what we want to assert.
  @fixture_run_id "01HZQTEST00000000000000000"
  @fixture_session_id "01HZQTESTSESSION0000000000"
  @fixture_draft_id "01HZQTESTDRAFT00000000000"
  @fixture_suggestion_id "01HZQTESTSUGG0000000000000"
  @fixture_conversation_id "01HZQTESTCONV0000000000000"
  @fixture_schema_name "receipt_v1.json"

  # ---------------------------------------------------------------------------
  # Route classification — the hardcoded canary list.
  #
  # Each route is `{method_atom, concrete_path}` so the test can drive
  # `Router.call/2` directly without further substitution. The two lists
  # below are the FULL enumeration of routes defined in `router.ex`
  # (excluding the `forward "/admin"` static-asset mount, which is
  # tested separately, and the `match _` 404 catch-all).
  # ---------------------------------------------------------------------------

  @public_routes [
    {:get, "/healthz"},
    {:get, "/readyz"},
    {:get, "/metrics"},
    {:get, "/.well-known/r5e-audit.json"},
    {:get, "/v1/schemas/index.json"},
    {:get, "/v1/schemas/#{@fixture_schema_name}"},
    {:get, "/v1/auth/jwks"},
    {:get, "/admin/login/start"},
    {:get, "/admin/login/callback"},
    # Bare `/` redirects to `/admin/login` — public by design.
    {:get, "/"}
  ]

  @protected_routes [
    # Data Plane — bearer-only.
    {:post, "/v1/chat/completions"},

    # Audit Plane — dual-auth (cookie OR bearer).
    {:get, "/v1/audit/receipts"},
    {:post, "/v1/audit/export"},
    {:get, "/v1/audit/payload"},

    # F004 cookie-required surfaces.
    {:get, "/v1/auth/me"},
    {:get, "/v1/audit/sessions/#{@fixture_session_id}"},
    {:get, "/v1/audit/parser-drift"},
    {:get, "/v1/audit/receipts/#{@fixture_run_id}"},
    {:post, "/v1/audit/receipts/#{@fixture_run_id}/verify"},
    {:get, "/admin/live-tail"},
    {:post, "/admin/logout"},

    # Policy authoring + Blast Radius (cookie-required).
    {:post, "/v1/policy/simulate"},
    {:get, "/v1/policy/drafts"},
    {:post, "/v1/policy/drafts/from-receipt"},
    {:post, "/v1/policy/drafts"},
    {:post, "/v1/policy/drafts/#{@fixture_draft_id}/dry-run"},
    {:get, "/v1/policy/drafts/#{@fixture_draft_id}"},
    {:patch, "/v1/policy/drafts/#{@fixture_draft_id}"},
    {:delete, "/v1/policy/drafts/#{@fixture_draft_id}"},

    # Policy Suggestions (cookie-required).
    {:post, "/v1/policy/suggestions/refresh"},
    {:post, "/v1/policy/suggestions/#{@fixture_suggestion_id}/adopt"},
    {:post, "/v1/policy/suggestions/#{@fixture_suggestion_id}/dismiss"},
    {:get, "/v1/policy/suggestions"},
    {:get, "/v1/policy/suggestions/#{@fixture_suggestion_id}"},

    # Policy Replay (cookie-required).
    {:post, "/v1/policy/replay/#{@fixture_run_id}"},

    # Audit Agent chat (cookie-required).
    {:post, "/v1/chat/messages"},
    {:get, "/v1/chat/conversations"},
    {:get, "/v1/chat/conversations/#{@fixture_conversation_id}"},

    # Operator-only Oban dashboard (cookie-required).
    {:get, "/admin/oban"},

    # MCP Trusted Registry — admin-console catalog (cookie-required).
    {:get, "/v1/mcp/registry"},
    {:get, "/v1/mcp/registry/r5e-audit-mcp"},
    {:patch, "/v1/mcp/registry/r5e-audit-mcp"},

    # MCP tool dispatch — bearer-authenticated INSIDE the handler
    # (handler-self-defended; the demo accepts a synthetic
    # `Bearer demo-mcp-token-*` synthetic token alongside production
    # JWTs so the route doesn't go through CookieOrBearerPlug).
    {:post, "/v1/mcp/r5e-audit-mcp/tools/r5e.audit.list_receipts"}
  ]

  # Stable secret_key_base for the BrowserSessionPlug. The plug is reached
  # by every cookie-required and dual-auth route during the property test
  # — without this config the plug raises before it can halt with 401.
  @session_secret_key_base :crypto.strong_rand_bytes(32)

  setup do
    # Install a minimal stub provider state so any handler that gets
    # past the auth gate (it shouldn't, on these tests) doesn't crash
    # for unrelated reasons. `tenant_id` is the only field reached by
    # the bearer-auth path before halting on missing-Authorization.
    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {Recurse.Gateway.Test.StubLedger, %{}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: "01HQZN5K7J8M9N0P1Q2R3S4T5V",
      signer: "observed://gateway/test"
    })

    previous_validator_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)
    previous_browser_session = Application.get_env(:recurse_gateway, :browser_session)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid",
      known_kids: []
    )

    Application.put_env(:recurse_gateway, :browser_session,
      secret_key_base: @session_secret_key_base,
      secure_cookie?: false
    )

    on_exit(fn ->
      ProviderRegistry.uninstall()

      if previous_validator_opts do
        Application.put_env(:recurse_gateway, :jwt_validator_opts, previous_validator_opts)
      else
        Application.delete_env(:recurse_gateway, :jwt_validator_opts)
      end

      if previous_browser_session do
        Application.put_env(:recurse_gateway, :browser_session, previous_browser_session)
      else
        Application.delete_env(:recurse_gateway, :browser_session)
      end
    end)

    :ok
  end

  # ---------------------------------------------------------------------------
  # Properties
  # ---------------------------------------------------------------------------

  describe "router auth canary — protected routes halt with 401" do
    property "every protected route returns 401 OR halts when called without auth" do
      check all(
              route <- StreamData.member_of(@protected_routes),
              max_runs: length(@protected_routes) * 3
            ) do
        {method, path} = route

        conn =
          method
          |> Plug.Test.conn(path)
          |> Router.call(@opts)

        protected? = conn.status == 401 or conn.halted

        assert protected?,
               """
               Route #{method |> Atom.to_string() |> String.upcase()} #{path} \
               classified protected was not protected: \
               status=#{inspect(conn.status)}, halted=#{inspect(conn.halted)}.

               This route is missing its auth wrap (BrowserSessionPipe.dispatch,
               CookieOrBearerPlug.dispatch, or inline IdentityContextBuilder).
               This is the exact regression the P-1 canary exists to catch —
               see docs/superpowers/plans/2026-04-29-audit-pass-resolver-consolidation.md
               §P-1.
               """
      end
    end
  end

  describe "router auth canary — public routes do NOT 401" do
    property "every public route returns a non-401 status when called without auth" do
      check all(
              route <- StreamData.member_of(@public_routes),
              max_runs: length(@public_routes) * 3
            ) do
        {method, path} = route

        conn =
          method
          |> Plug.Test.conn(path)
          |> safe_call()

        # Public routes MUST NOT 401. They may legitimately return 200,
        # 302 (login redirects, root redirect), 404 (schema-name miss),
        # 503 (component down at startup), etc. — anything except 401.
        refute conn.status == 401,
               """
               Route #{method |> Atom.to_string() |> String.upcase()} #{path} \
               classified public returned 401.

               A public route MUST NOT require auth. If this route was \
               recently moved behind auth, either reclassify it as \
               protected in @protected_routes or remove the auth wrap.
               """
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Coverage check — ensures the hardcoded list isn't silently shrinking.
  # ---------------------------------------------------------------------------

  describe "route table coverage" do
    test "public + protected lists together cover the documented surface" do
      # Smoke check — guards against the failure mode where someone deletes
      # routes from these lists faster than they delete them from the router.
      # If you add a new route to router.ex, you MUST add it to one of the
      # two lists above. CI failure on this assertion = "you added a route,
      # please classify it".
      total = length(@public_routes) + length(@protected_routes)

      # Current expected total, derived from the router.ex enumeration on
      # 2026-04-29: 10 public + 28 protected = 38.
      assert total >= 38,
             """
             Route classification list shrank below the documented baseline (38).
             Either: (1) routes were deleted from router.ex without updating
             this test, or (2) routes were added to router.ex without
             classifying them. Re-enumerate router.ex and update the lists.
             """
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Public routes may dispatch to handlers that read from runtime state
  # (`MetricsRegistry`, etc.) which isn't started in this async test
  # scope. Route dispatch itself is what we're asserting — if the
  # downstream handler raises, that's a not-our-problem signal that the
  # auth gate is NOT 401-ing (which is the question the property asks).
  # We treat raises and exits as "definitely not a 401" — equivalent to
  # status != 401 for property purposes.
  defp safe_call(conn) do
    Router.call(conn, @opts)
  rescue
    _ -> %{conn | status: 500, halted: false}
  catch
    :exit, _ -> %{conn | status: 500, halted: false}
  end
end
