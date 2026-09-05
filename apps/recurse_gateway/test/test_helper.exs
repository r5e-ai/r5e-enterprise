# F002 T028: the property-test surface skeleton tests are tagged `:pending`
# so default `mix test` runs skip them (they are designed to fail until the
# real property impls land in T031/T058/T068/T080/T096/T030). The canonical
# way to un-skip is `mix test --include pending`, which ExUnit translates
# into overriding the exclude list for that invocation.
#
# F002 T099 / T101 / T103 — Phase-10 integration tests (`:quickstart`,
# `:soak`, `:restore_drill`) are also excluded from default runs because
# they boot both Gateway + Broker, drive large numbers of requests, and
# shell out to `docs/auditor/recurse-verify`. The `:soak` suite runs for
# 10 minutes by default (override with `SOAK_DURATION_SEC=30` for quick
# local smoke). Opt in via `mix test --include <tag>`.
#
# 009 T038b — `:slow` excludes the LLM-proxy CT-006 11-minute memory-
# stability test from default runs (also pre-existing live_tail
# backfill test tagged `:slow` was previously running by oversight;
# the canonical `:slow` semantic is now exclude-by-default). Opt in
# locally via
# `mix test --include slow apps/recurse_gateway/test/recurse_gateway/llm_proxy/`.
# 009 T038 — `:perf` excludes the LLM-proxy P-001/P-002 latency budget
# checks; same shape as `:slow`. Run via `mix test --include perf`.
ExUnit.start(exclude: [:pending, :quickstart, :soak, :restore_drill, :slow, :perf])

# Mox mocks for Gateway-scoped Provider Interface contract tests (Wave 3E-2).
# Sibling `:recurse_providers` owns `Recurse.Providers.Mocks.*` for its own
# contract tests; those don't cross the umbrella-app boundary, so the Gateway
# app declares its own mocks against the same behaviours. Each mock is a
# lightweight behaviour impl that routes through Mox's expectation engine.
Mox.defmock(Recurse.Gateway.Test.Mocks.LLMProvider, for: Recurse.Providers.LLMProvider)
Mox.defmock(Recurse.Gateway.Test.Mocks.LedgerProvider, for: Recurse.Providers.LedgerProvider)
Mox.defmock(Recurse.Gateway.Test.Mocks.StorageProvider, for: Recurse.Providers.StorageProvider)
Mox.defmock(Recurse.Gateway.Test.Mocks.SecretsProvider, for: Recurse.Providers.SecretsProvider)

# Pre-seed JwtTestHelper keypairs at test-suite init.
#
# Rationale: `JwtTestHelper.keypair/1` uses a `:persistent_term.get → :undefined
# → generate → :persistent_term.put` pattern. Two async tests that both cache-
# miss simultaneously BOTH call `generate_keypair/1` and BOTH call
# `:persistent_term.put`. Last writer wins. The test that signed FIRST now has
# a JWT whose public counterpart no longer matches the `:persistent_term`
# cache, yielding a spurious `:invalid_signature` at validate time.
#
# Seeding here — serially, before any async tests run — guarantees the first
# cache-miss happens in THIS process. All subsequent `keypair/1` calls hit the
# pre-seeded cache. `:persistent_term.put` with the same value is a no-op,
# so parallel writes of the SAME keypair are safe.
for alg <- [:rs256, :es256, :eddsa] do
  _ = Recurse.Gateway.Test.JwtTestHelper.public_jwk(alg)
end
