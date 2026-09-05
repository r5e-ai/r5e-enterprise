#
# Root-level ExUnit helper for repo-root `test/` .exs files.
#
# ## Why this file exists (and why it's currently unused by the F002 suite)
#
# The Recurse umbrella's default `mix test` recurses into each child app
# under `apps/`. Repo-root .exs tests are NOT auto-discovered — they
# need explicit invocation:
#
#     mix test test/integration/<file>.exs
#
# The F002 Phase-10 integration tests (`quickstart_walkthrough_test.exs`,
# `sc005_throughput_soak_test.exs`, `sc012_restore_drill_test.exs`) live
# under `apps/recurse_gateway/test/integration/` — NOT at the repo root
# — because they need access to Gateway test-support modules
# (`Recurse.Gateway.Test.MockHttpUpstream`, etc.) which live under
# `apps/recurse_gateway/test/support/` and are only compiled when
# running tests for `:recurse_gateway` (`elixirc_paths(:test)` in that
# app's mix.exs).
#
# The Phase-10 excludes for the three tagged moduletags live in
# `apps/recurse_gateway/test/test_helper.exs` instead.
#
# This root helper is retained for future repo-root .exs tests that
# DON'T need umbrella-app test-support modules (e.g. pure-function tests
# that only touch `:recurse_shared` or validate repo-layout invariants).
# The `:soak`, `:restore_drill`, `:quickstart` tags are pre-excluded so
# future tests can tag themselves consistently without reconfiguring.
#
# Co-located with `test/integration/us4_vector_forwarder_test.sh`
# (bash-only; invoked directly, not via ExUnit).
#
ExUnit.start(exclude: [:soak, :restore_drill, :quickstart])
