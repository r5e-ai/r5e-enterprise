defmodule Recurse.Gateway.RateLimit.Backend do
  @moduledoc """
  Hammer 7 rate-limit backend for the Gateway (F002 T092 / FR-030).

  ## Why ETS

  Hammer offers several backends (Redis, Mnesia, ETS, ...). We pick
  `:ets` because:

    * **Standalone is single-node** (F002 plan.md + Constitution v1.3.0
      "Phase-1 is single-node only"). There is no cluster-wide bucket
      to coordinate, so Redis / Mnesia are unnecessary complexity.
    * **No process bottleneck.** The ETS backend serializes writes
      through the table's write-lock but reads bypass any GenServer.
      Per `elixir:phoenix-thinking` Iron-Law-adjacent principle
      ("no process without reason"), a GenServer-backed Hammer
      backend would funnel every Data Plane request through one
      mailbox, defeating the purpose of per-connection parallelism
      in Bandit.

  ## Supervision

  `Hammer.use/1` generates a `child_spec/1` on this module so it slots
  into the Gateway's `RecurseGateway.Supervisor` `:one_for_one` tree.
  The ETS table is owned by a Hammer-internal process; if it crashes
  the supervisor restarts it, and buckets reset (accepted under
  single-node semantics — a Gateway crash is not a security boundary
  we defend behind).

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-030.
    * `apps/recurse_gateway/lib/recurse_gateway/plug/rate_limiter.ex`
      — the Plug that calls `hit/3` via this module.
  """

  use Hammer, backend: :ets
end
