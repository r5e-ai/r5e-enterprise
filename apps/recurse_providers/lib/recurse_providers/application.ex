defmodule RecurseProviders.Application do
  @moduledoc """
  Supervises the Provider Interface infrastructure that all concrete impls share.

  Children:
    * `Recurse.Providers.Repo` — Ecto Repo for the Postgres-Merkle
      LedgerProvider impl. Test env uses `Ecto.Adapters.SQL.Sandbox`
      (configured in `config/test.exs`); sandbox mode still requires the
      Repo to be started — checkouts swap connection ownership per-test.
    * `Phoenix.PubSub` named `Recurse.PubSub` — the intra-node bus per
      FR-034. Added in F002 T033 so the Postgres-Merkle ledger impl can
      broadcast `recurse:attestation_first_committed` after a successful
      commit. Other provider impls + the Gateway subscribe here too
      (SIEM forwarder, first-committer, etc.).

  Other provider impls (OpenAI HTTP, AWS KMS, AWS S3) hold no top-level
  state — they dispatch through the Gateway's named Finch pools and are
  stateless from a supervision-tree POV.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      Recurse.Providers.Repo,
      {Phoenix.PubSub, name: Recurse.PubSub}
    ]

    opts = [strategy: :one_for_one, name: RecurseProviders.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
