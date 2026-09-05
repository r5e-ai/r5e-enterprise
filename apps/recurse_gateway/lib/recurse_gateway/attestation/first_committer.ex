defmodule Recurse.Gateway.Attestation.FirstCommitter do
  @moduledoc """
  Named observer for the `recurse:attestation_first_committed` PubSub
  topic per F002 FR-024 / T049.

  ## Why a GenServer (Iron Law check, `elixir:otp-thinking`)

    1. Mutable state persisting across calls? **Yes** — the subscription
       itself is runtime state owned by this process (a GenServer started
       in the Gateway supervision tree). Unsubscribing on shutdown and
       a monotonically-advancing `observed_count` both require process
       identity.
    2. Concurrent execution? No — PubSub delivers sequentially to a
       single subscriber; the broker handler and the SIEM forwarder
       subscribe separately (one subscriber per process is the correct
       topology).
    3. Fault isolation? Yes — if this observer crashes, the supervisor
       restarts it without taking down the Gateway. An observer that
       vanishes silently would be an operational cliff.

  Yes + Yes → GenServer is legitimate. This is NOT a "wrapping stateless
  code in a process for organization" anti-pattern.

  ## Responsibilities (minimal, by design)

  The FirstCommitter is the Gateway's architectural seam for the first
  commit event. In T049 its only job is:

    1. Subscribe to `recurse:attestation_first_committed` at boot.
    2. On each `{:first_committed, run_id, payload}` message emit a
       `[:recurse, :attestation, :first_committed]` telemetry event +
       increment the observed counter.

  The SIEM forwarder (T053) subscribes to the same topic directly; the
  FirstCommitter does NOT fan-out to it. Keeping the responsibilities
  orthogonal means T053 can evolve (NDJSON schema changes, forwarder
  buffering) without touching this module, and future first-commit
  hooks (audit broker cache invalidation, metrics, webhooks) can land
  here without touching the SIEM path.

  ## Message contract

  The LedgerProvider broadcasts
  `{:first_committed, run_id :: String.t(), payload :: map()}` exactly
  once per attestation, per `Recurse.Providers.Impls.PostgresMerkleLedger.
  broadcast_first_committed/3`. The payload map includes an `:attestation`
  key carrying the Ecto schema (as a map) + `run_id`, `verification_level`,
  `session_chain_root`, `global_inclusion_proof`. This module does not
  mutate the payload; downstream consumers are responsible for their own
  projections.
  """

  use GenServer

  require Logger

  @topic "recurse:attestation_first_committed"

  @typedoc "Internal state — observed count of first-commit events since boot."
  @type state :: %{observed_count: non_neg_integer()}

  @doc """
  Start the observer. Name-registered so tests + supervision introspection
  can find it without an owned registry.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Return the count of `{:first_committed, ...}` messages observed since
  boot. Used by tests to assert the subscription wiring; also useful for
  operational spot-checks via `:sys.get_state/1`.
  """
  @spec observed_count(GenServer.server()) :: non_neg_integer()
  def observed_count(server \\ __MODULE__) do
    GenServer.call(server, :observed_count)
  end

  @impl GenServer
  def init(opts) do
    pubsub = Keyword.get(opts, :pubsub, Recurse.PubSub)
    topic = Keyword.get(opts, :topic, @topic)
    :ok = Phoenix.PubSub.subscribe(pubsub, topic)
    {:ok, %{observed_count: 0}}
  end

  @impl GenServer
  def handle_info({:first_committed, run_id, payload}, state) when is_map(payload) do
    :telemetry.execute(
      [:recurse, :attestation, :first_committed],
      %{count: 1},
      %{
        run_id: run_id,
        tenant_id: tenant_id_from_payload(payload),
        verification_level: Map.get(payload, :verification_level)
      }
    )

    {:noreply, %{state | observed_count: state.observed_count + 1}}
  end

  # Defensively log + ignore anything that doesn't match the documented
  # broadcast shape. Not crashing here is deliberate — a rogue publisher
  # should not be able to take down the subscriber and halt all future
  # first-commit observations.
  def handle_info(other, state) do
    Logger.warning(fn ->
      "FirstCommitter ignored unexpected message: " <> inspect(other)
    end)

    {:noreply, state}
  end

  @impl GenServer
  def handle_call(:observed_count, _from, state) do
    {:reply, state.observed_count, state}
  end

  # The `broadcast_first_committed/3` publisher nests the attestation's
  # tenant_id inside either `payload.attestation.tenant_id` (the Ecto
  # struct projection) or `payload.tenant_id` directly (future shapes).
  # Tolerate both and return nil when neither is present — telemetry
  # handlers MUST cope with missing metadata.
  defp tenant_id_from_payload(%{attestation: %{tenant_id: tid}}) when is_binary(tid), do: tid
  defp tenant_id_from_payload(%{tenant_id: tid}) when is_binary(tid), do: tid
  defp tenant_id_from_payload(_), do: nil
end
