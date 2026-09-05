defmodule Recurse.Providers.ContractTest do
  @moduledoc """
  Mox-backed contract-test harness for Provider Interface behaviours
  (T061 / Deliverable C).

  Reference intent: every concrete provider impl in
  `apps/recurse_providers/lib/recurse_providers/impls/` should be
  verifiable against its Provider Interface by sharing the same set of
  round-trip assertions. Feature 002+ impls `use` this harness from
  their per-interface contract-test file; the test cases here are the
  portable ones that must pass regardless of which backend is wired up.

  ## Shape

      # apps/recurse_providers/test/contract/llm_provider_test.exs
      defmodule Recurse.Providers.ContractTest.LLMProviderTest do
        use Recurse.Providers.ContractTest,
          for: Recurse.Providers.LLMProvider,
          mock: Recurse.Providers.Mocks.LLMProvider,
          stub_with: Recurse.Providers.Support.MockLLMProvider

        # Per-behaviour-specific tests live in sibling modules and `import`
        # the setup context from this harness.
      end

  The `use` macro injects:

    * `Mox.setup_all` wiring that stubs the generated Mox mock with the
      fixed-data helper module (keeps each test's expectation list short).
    * One test per universal callback: `init/1`, `capabilities/1`,
      `healthcheck/1`, `terminate/2`. Each asserts the callback exists,
      round-trips a canonical input, and returns a shape compatible
      with the behaviour's typespec.
    * Hooks (`@before_compile`) for the per-behaviour sub-helper to
      append additional test cases (see T062–T068 sub-helpers for the
      behaviour-specific cases).

  The harness deliberately keeps its universal suite small — FR-004 is
  about *structural* conformance (does the impl implement every
  callback, does it round-trip without raising). Deep semantic tests
  (RFC 9162 proof shapes, DSSE signature structure) belong to Feature
  002+ per-impl test modules, not here.

  ## Composition with per-behaviour sub-helpers

  Callers that need behaviour-specific test coverage compose multiple
  `use` directives — one for the shared harness (this module) and one
  for the per-behaviour helper:

      defmodule Recurse.Providers.ContractTest.LLMProviderTest do
        use Recurse.Providers.ContractTest, for: LLMProvider, ...
        use Recurse.Providers.ContractTest.LLMSuite, ...
      end

  Sub-helper modules (`Recurse.Providers.ContractTest.*Suite`) live
  alongside the per-interface mock files under
  `apps/recurse_providers/test/contract/suites/*.ex`. Phase-1 ships
  empty scaffolds — Feature 002+ grows the suites as concrete impls
  land.
  """

  @doc false
  defmacro __using__(opts) do
    behaviour = Keyword.fetch!(opts, :for)
    mock_mod = Keyword.fetch!(opts, :mock)
    stub_with = Keyword.fetch!(opts, :stub_with)

    quote location: :keep do
      use ExUnit.Case, async: true

      import Mox

      @harness_behaviour unquote(behaviour)
      @harness_mock unquote(mock_mod)
      @harness_stub_with unquote(stub_with)

      setup :set_mox_from_context
      setup :verify_on_exit!

      setup do
        # Stub every callback through the fixed-data helper. Individual
        # test cases may override with `expect/4` for tighter assertions.
        Mox.stub_with(@harness_mock, @harness_stub_with)
        :ok
      end

      # --- Universal round-trip tests (required of every impl) --------

      describe "Provider Interface structural conformance (#{inspect(unquote(behaviour))})" do
        test "mock implements @behaviour" do
          assert @harness_behaviour in (@harness_mock.__info__(:attributes)[:behaviour] || []),
                 "generated Mox mock does not declare @behaviour #{inspect(@harness_behaviour)}"
        end

        test "init/1 returns {:ok, state} on canonical config" do
          assert {:ok, _state} = @harness_mock.init(%{})
        end

        test "capabilities/1 returns a list of atoms" do
          state = init_state()
          caps = @harness_mock.capabilities(state)
          assert is_list(caps)
          assert Enum.all?(caps, &is_atom/1)
        end

        test "healthcheck/1 returns :ok | {:degraded, _} | {:down, _}" do
          state = init_state()
          result = @harness_mock.healthcheck(state)

          assert result == :ok or
                   match?({:degraded, _}, result) or
                   match?({:down, _}, result),
                 "healthcheck/1 returned unexpected shape: #{inspect(result)}"
        end

        test "terminate/2 returns :ok" do
          state = init_state()
          assert :ok = @harness_mock.terminate(state, :normal)
        end
      end

      # Subclasses override by re-defining `init_state/0` or appending
      # describe blocks in the test module body.
      defp init_state do
        {:ok, state} = @harness_mock.init(%{})
        state
      end

      defoverridable init_state: 0
    end
  end
end
