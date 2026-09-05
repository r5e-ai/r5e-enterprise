defmodule RecurseShared.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Serializes ULID randomness generation so concurrent callers within
      # the same millisecond see strictly-increasing randomness. See the
      # moduledoc on Recurse.Shared.Ulid.Monotonic for the invariant.
      Recurse.Shared.Ulid.Monotonic
    ]

    opts = [strategy: :one_for_one, name: RecurseShared.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
