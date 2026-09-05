# Credo's test-case helpers (used by the
# `Recurse.Credo.ProviderNeutralityTest` module) depend on the Credo
# application being started — `Credo.Service.SourceFileAST` is a worker
# inside `Credo.Application`'s supervision tree, and `to_source_file/2`
# `GenServer.call`s into it on first invocation. Credo is `runtime:
# false` in mix.exs (dev/test tool, not an app dep), so we start it
# here only for the test suite.
{:ok, _} = Application.ensure_all_started(:credo)

# `:perf` and `:slow` are opt-in here as in recurse_gateway: a shared CI
# runner cannot honour a wall-clock budget, and the local full run opts in
# with `mix test --include perf --include slow`.
ExUnit.start(exclude: [:perf, :slow])
