defmodule Recurse.Gateway.Router.AdminStaticAllowlistTest do
  @moduledoc """
  Regression test for issue #61 (Monaco initialization fails on Policy
  Simulator).

  Background — recap of the failure mode:

    1. The admin SPA is served behind a strict CSP set by
       `Recurse.Gateway.Plug.SecurityHeaders`:

           script-src 'self' 'wasm-unsafe-eval'

    2. The Policy Simulator embeds Monaco for Cedar editing.
       `@monaco-editor/loader` defaults to fetching Monaco's AMD
       bootstrap from `https://cdn.jsdelivr.net/...` — blocked by CSP.

    3. MR !67 (B6 fix) shipped Monaco's `min/vs/` directory as a
       same-origin static asset under `/admin/vs/`, with the SPA
       configuring `loader.config({ paths: { vs: "/admin/vs" } })` at
       boot. The build chain (`pnpm copy:monaco` → `vite build` →
       `pnpm sync-to-priv`) populates
       `apps/recurse_gateway/priv/static/admin/vs/loader.js`.

    4. **Issue #61 root cause:** `Plug.Static`'s `:only` allowlist on
       the `/admin` forward in `Recurse.Gateway.Router` did NOT include
       `vs`. Anything not in the allowlist falls through to
       `Plug.AdminStatic`'s SPA-fallback, which sends `index.html` as
       `text/html`. Browser receives HTML for a `.js` URL, fails to
       evaluate it, Monaco's `loader.init()` Promise never resolves,
       and the editor hangs on its default "Loading..." placeholder.

  This test asserts the allowlist directly so a future edit (eg
  removing `vs` to "tidy up the list") fails fast at unit-test time
  rather than at production-deploy time.

  Note: end-to-end "GET /admin/vs/loader.js returns the file" is
  covered by the post-build CI assertion in `.gitlab-ci.yml` (the
  release tarball must contain the path) and by Plug.Static's own
  contract; we keep the unit-level assertion at the route-config
  level so the test does not depend on a populated `priv/static/`
  directory at test time.
  """

  use ExUnit.Case, async: true

  @router_source Path.expand(
                   "../../lib/recurse_gateway/router.ex",
                   __DIR__
                 )

  describe "admin static asset allowlist (issue #61 regression)" do
    test "router.ex `Plug.Static :only` allowlist includes `vs`" do
      source = File.read!(@router_source)

      assert source =~ ~r/only:\s*~w\([^)]*\bvs\b[^)]*\)/,
             """
             Expected `Plug.Static :only` allowlist in router.ex to
             include `vs` so /admin/vs/loader.js (Monaco AMD bundle)
             is served as a same-origin static asset.

             Without `vs` in the allowlist, requests for
             /admin/vs/* fall through to the SPA fallback and Monaco
             initialization hangs forever. See issue #61 (regression
             of MR !67).
             """
    end

    test "router.ex still allowlists the other established static prefixes" do
      # Defensive: a future edit must not silently drop `assets`,
      # `recurse-logo.svg`, `index.html` etc — those are how the SPA's
      # JS bundle, favicon, and deep-link fallback are served. Listing
      # them here keeps the regression surface tight.
      source = File.read!(@router_source)

      [
        "assets",
        "recurse-logo.svg",
        "favicon.ico",
        "vite.svg",
        "index.html"
      ]
      |> Enum.each(fn entry ->
        assert source =~ ~r/only:\s*~w\([^)]*\b#{Regex.escape(entry)}\b[^)]*\)/,
               "Expected `Plug.Static :only` allowlist to include `#{entry}`."
      end)
    end
  end
end
