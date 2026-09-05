# Test helper for recurse_providers — owns Mox mock declarations (T061) and
# the ExUnit boot dance.
#
# Mox design:
#   * ONE `Mox.defmock/2` per Provider Interface behaviour. The generated
#     mock module (e.g. `Recurse.Providers.Mocks.LLMProvider`) is a
#     proper `@behaviour Recurse.Providers.LLMProvider` impl that routes
#     every callback through Mox's expectation engine.
#   * Contract tests use `Mox.stub_with/2` (or `Mox.stub/3`) to install
#     the companion helper module (`MockLLMProvider`, etc. — defined under
#     `test/support/mock_*_provider.ex`) as the default fallback. This
#     keeps each test's expectation list small and declarative.
#
# Naming: the GENERATED Mox mock is `Recurse.Providers.Mocks.<Interface>`.
# The STUB-DEFAULT helper (fixed round-trip data) is
# `Recurse.Providers.Support.Mock<Interface>`. They are NOT the same
# module — Mox's doc-recommended pattern keeps the generated mock and
# the stub-logic separate.

ExUnit.start()

# F002 stub-era tests tagged `@tag :pending` mark the full Phase-3 assertion
# shape; they are excluded by default. Phase-3 implementers flip them on by
# deleting `@tag :pending` from the test, or run the full suite with
# `mix test --include pending`.
ExUnit.configure(exclude: [:pending])

# Generated Mox mocks — one per behaviour.
Mox.defmock(Recurse.Providers.Mocks.LLMProvider,
  for: Recurse.Providers.LLMProvider
)

Mox.defmock(Recurse.Providers.Mocks.LedgerProvider,
  for: Recurse.Providers.LedgerProvider
)

Mox.defmock(Recurse.Providers.Mocks.StorageProvider,
  for: Recurse.Providers.StorageProvider
)

Mox.defmock(Recurse.Providers.Mocks.SecretsProvider,
  for: Recurse.Providers.SecretsProvider
)

Mox.defmock(Recurse.Providers.Mocks.IdentityProvider,
  for: Recurse.Providers.IdentityProvider
)

Mox.defmock(Recurse.Providers.Mocks.PrincipalProvider,
  for: Recurse.Providers.PrincipalProvider
)

Mox.defmock(Recurse.Providers.Mocks.PolicyProvider,
  for: Recurse.Providers.PolicyProvider
)

# ExAws HTTP client mock — used by AwsKmsSecretsProvider contract tests to
# intercept `ExAws.request/2` at the HTTP boundary without booting the
# ex_aws OTP app or reaching AWS. Injected per-state via the `:http_client`
# config knob introduced in T036/T037.
Mox.defmock(Recurse.Providers.Mocks.ExAwsHttpClient,
  for: ExAws.Request.HttpClient
)
