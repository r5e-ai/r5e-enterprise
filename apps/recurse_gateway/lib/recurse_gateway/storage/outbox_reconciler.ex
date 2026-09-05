defmodule Recurse.Gateway.Storage.OutboxReconciler do
  @moduledoc """
  Periodic reconciler for the Postgres `payload_outbox` table per F002
  FR-032 / T090.

  ## Responsibility

  When an inbound Data-Plane request cannot durably write its detached
  payload to S3 at call time, the Gateway enqueues a row in
  `payload_outbox` with `status = "pending"`. This process polls those
  rows on a fixed interval, retries the storage put via the configured
  `StorageProvider`, commits the attestation to the ledger on success,
  and promotes the row to `dead_letter` once `attempts >= max_attempts`.

  The outbox-then-commit sequence is **monotonic**: an attestation is
  never committed to the ledger before its payload bytes are observed
  in storage (FR-032). Re-running this reconciler after a crash is safe
  — the worst case is a duplicate `StorageProvider.put_payload/3` call,
  which is idempotent for S3 (same key + same hash).

  ## Iron Law check (`elixir:otp-thinking`)

  GenServer is justified. All three criteria met:

    1. **Mutable state across calls**: the scheduled-tick timer reference,
       running attempt counts for telemetry, and the serialized-writer
       invariant all live in process state.
    2. **Serialized access required**: the reconciler MUST be the sole
       writer or N concurrent reconcilers produce duplicate storage
       puts + retry-storms. A single GenServer tick gates the pipeline;
       multi-node deployments add a DB-level advisory lock (out of scope
       for F002's single-instance constraint per FR-002).
    3. **Fault isolation required**: a malformed outbox row or transient
       DB error must not drag Data Plane down. Supervisor restarts this
       process with a clean state.

  ## Tick lifecycle

  Each `handle_info(:tick, state)` fetches up to `batch_size` eligible
  rows via `PostgresMerkleLedger.query_pending_outbox/1`:

    1. For each row where `attempts >= max_attempts` — transition to
       `dead_letter` via `mark_dead_letter/2`. No retry.
    2. Otherwise call `StorageProvider.put_payload/3`. On success invoke
       `commit_outbox_success/3`, broadcast `{:outbox_committed, run_id}`
       on the configured PubSub, and emit a telemetry event.
    3. On failure call `retry_outbox_entry/3` with an updated
       `next_attempt_at` computed via exponential backoff.

  The tick emits `[:recurse, :outbox, :tick]` with counts and schedules
  the next tick via `Process.send_after/3`. Startup sends `:tick`
  immediately so a freshly-booted Gateway catches up on any backlog
  accumulated while offline.

  ## Backoff

  Default `backoff(attempt)` = `min(2 ^ attempt, 300)` seconds. Attempt 1
  waits 2s; attempt 2, 4s; attempt 8 hits the 300s cap.

  ## Configuration

  Boot options (all optional):

    * `:poll_interval_ms` — default `30_000`.
    * `:batch_size` — default `50` rows per tick.
    * `:max_attempts` — default `10`.
    * `:ledger` — module implementing the T090 outbox helpers. Defaults
      to `Recurse.Providers.Impls.PostgresMerkleLedger`. Tests override
      with a stub.
    * `:storage` — `{module, state}` tuple. Defaults to the runtime
      `Recurse.Gateway.ProviderRegistry.storage_provider/0` lookup.
    * `:pubsub` — PubSub name for `outbox_committed` broadcasts.
      Defaults to `Recurse.PubSub`.
    * `:backoff_fun` — `(attempt -> non_neg_integer)` — override for
      testing backoff progression without sleeping.
    * `:name` — process registration name. Defaults to `__MODULE__`;
      pass `nil` for an unregistered process (test isolation).

  ## Telemetry

    * `[:recurse, :outbox, :tick]` — per-tick summary.
      Measurements: `%{processed, dead_letters, failures}`.
    * `[:recurse, :outbox, :row_committed]` — `%{count: 1}`,
      metadata `%{run_id}`.
    * `[:recurse, :outbox, :row_dead_letter]` — `%{count: 1}`,
      metadata `%{run_id, last_error}`.
    * `[:recurse, :outbox, :row_retry]` — `%{count: 1, next_attempt_s}`,
      metadata `%{run_id}`.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-032.
    * `apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger.ex`
      — the AD-001 c' public methods this process depends on.
    * `apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger/schemas/payload_outbox.ex`
      — the row schema.
  """

  use GenServer

  require Logger

  @default_poll_interval_ms 30_000
  @default_batch_size 50
  @default_max_attempts 10
  @backoff_cap_seconds 300

  @type option ::
          {:poll_interval_ms, pos_integer()}
          | {:batch_size, pos_integer()}
          | {:max_attempts, pos_integer()}
          | {:ledger, module()}
          | {:storage, {module(), term()}}
          | {:pubsub, atom()}
          | {:backoff_fun, (non_neg_integer() -> non_neg_integer())}
          | {:name, GenServer.name() | nil}

  @doc """
  Start and link the reconciler. Passes all opts through to `init/1`.
  """
  @spec start_link([option()]) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, init_opts} = Keyword.pop(opts, :name, __MODULE__)

    case name do
      nil -> GenServer.start_link(__MODULE__, init_opts)
      name -> GenServer.start_link(__MODULE__, init_opts, name: name)
    end
  end

  @doc """
  Return the reconciler's current state. Useful for tests + sys
  introspection (`:sys.get_state/1` also works).
  """
  @spec inspect_state(GenServer.server()) :: map()
  def inspect_state(server \\ __MODULE__), do: GenServer.call(server, :inspect_state)

  @impl true
  def init(opts) do
    configured_poll =
      opts[:poll_interval_ms] ||
        Application.get_env(:recurse_gateway, :outbox_reconciler, [])
        |> Keyword.get(:poll_interval_ms, @default_poll_interval_ms)

    state = %{
      poll_interval_ms: configured_poll,
      batch_size: Keyword.get(opts, :batch_size, @default_batch_size),
      max_attempts: Keyword.get(opts, :max_attempts, @default_max_attempts),
      ledger: Keyword.get(opts, :ledger, Recurse.Providers.Impls.PostgresMerkleLedger),
      storage: Keyword.get(opts, :storage),
      pubsub: Keyword.get(opts, :pubsub, Recurse.PubSub),
      backoff_fun: Keyword.get(opts, :backoff_fun, &default_backoff_seconds/1),
      processed_total: 0,
      dead_letter_total: 0,
      failure_total: 0
    }

    # Catch-up tick on boot — do not wait `poll_interval_ms` to drain any
    # accumulated backlog.
    send(self(), :tick)
    {:ok, state}
  end

  @impl true
  def handle_call(:inspect_state, _from, state) do
    {:reply, state, state}
  end

  @impl true
  def handle_info(:tick, state) do
    {processed, dead_letters, failures} = run_tick(state)

    :telemetry.execute(
      [:recurse, :outbox, :tick],
      %{
        processed: processed,
        dead_letters: dead_letters,
        failures: failures
      },
      %{}
    )

    next_state = %{
      state
      | processed_total: state.processed_total + processed,
        dead_letter_total: state.dead_letter_total + dead_letters,
        failure_total: state.failure_total + failures
    }

    Process.send_after(self(), :tick, state.poll_interval_ms)
    {:noreply, next_state}
  end

  # Defensive: ignore stray messages rather than crashing.
  def handle_info(_other, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Internals
  # ---------------------------------------------------------------------------

  defp run_tick(state) do
    case state.ledger.query_pending_outbox(
           limit: state.batch_size,
           before: DateTime.utc_now()
         ) do
      {:ok, rows} -> reduce_rows(rows, state)
      {:error, reason} -> log_tick_failure(reason)
    end
  end

  defp reduce_rows(rows, state) do
    Enum.reduce(rows, {0, 0, 0}, fn row, acc -> tally(process_row(row, state), acc) end)
  end

  defp tally(:committed, {p, d, f}), do: {p + 1, d, f}
  defp tally(:dead_letter, {p, d, f}), do: {p, d + 1, f}
  defp tally(:retry, {p, d, f}), do: {p, d, f + 1}

  defp log_tick_failure(reason) do
    Logger.error(fn ->
      "OutboxReconciler tick: query_pending_outbox failed: #{inspect(reason)}"
    end)

    {0, 0, 0}
  end

  defp process_row(%{attempts: attempts} = row, state) when attempts >= 0 do
    if attempts >= state.max_attempts do
      promote_to_dead_letter(row, state, :max_attempts_exceeded)
    else
      attempt_retry(row, state)
    end
  end

  defp promote_to_dead_letter(row, state, reason) do
    case state.ledger.mark_dead_letter(row.id, reason) do
      {:ok, _} ->
        :telemetry.execute(
          [:recurse, :outbox, :row_dead_letter],
          %{count: 1},
          %{run_id: row.run_id, last_error: inspect(reason)}
        )

        :dead_letter

      {:error, err} ->
        Logger.error(fn ->
          "OutboxReconciler mark_dead_letter failed for #{inspect(row.id)}: #{inspect(err)}"
        end)

        :retry
    end
  end

  defp attempt_retry(row, state) do
    case do_put_payload(row, state) do
      {:ok, storage_result} ->
        record_success(row, storage_result, state)

      {:error, reason} ->
        record_failure(row, reason, state)
    end
  end

  defp do_put_payload(row, state) do
    identity_ctx = reconciler_identity_context(row)
    {storage_mod, storage_state} = resolve_storage(state)
    storage_mod.put_payload(storage_state, row.payload_bytes, identity_ctx)
  rescue
    err -> {:error, err}
  end

  defp record_success(row, storage_result, state) do
    case state.ledger.commit_outbox_success(row.id, storage_result) do
      {:ok, _} ->
        :telemetry.execute(
          [:recurse, :outbox, :row_committed],
          %{count: 1},
          %{run_id: row.run_id}
        )

        Phoenix.PubSub.broadcast(
          state.pubsub,
          "recurse:outbox_committed",
          {:outbox_committed, row.run_id}
        )

        :committed

      {:error, reason} ->
        Logger.error(fn ->
          "OutboxReconciler commit_outbox_success failed for #{inspect(row.id)}: " <>
            inspect(reason)
        end)

        :retry
    end
  end

  defp record_failure(row, reason, state) do
    next_attempt_s = state.backoff_fun.(row.attempts + 1)
    next_at = DateTime.add(DateTime.utc_now(), next_attempt_s, :second)

    _ =
      state.ledger.retry_outbox_entry(row.id, %{
        attempts: row.attempts + 1,
        next_attempt_at: next_at,
        last_error: inspect(reason)
      })

    :telemetry.execute(
      [:recurse, :outbox, :row_retry],
      %{count: 1, next_attempt_s: next_attempt_s},
      %{run_id: row.run_id}
    )

    :retry
  end

  # When the storage tuple is omitted at boot, fall back to the runtime
  # registry. The boot-time override hook keeps tests deterministic
  # without mutating the `ProviderRegistry` singleton.
  defp resolve_storage(%{storage: {mod, state}}) when is_atom(mod), do: {mod, state}

  defp resolve_storage(_state) do
    Recurse.Gateway.ProviderRegistry.storage_provider()
  end

  # The reconciler runs out-of-band from any user request — stamp a
  # synthetic "autonomous reconciler" principal so downstream provider
  # impls that log caller principals see a deterministic value.
  defp reconciler_identity_context(row) do
    %Recurse.Shared.IdentityContext{
      machine_identity: {:observed_identity, %{"source" => "outbox_reconciler"}},
      principal: reconciler_principal(),
      tenant_id: tenant_id_for(row),
      correlation_id: "outbox-#{row.id}",
      resolved_at_usec: System.system_time(:microsecond)
    }
  end

  defp reconciler_principal do
    %Recurse.Shared.Principal{
      kind: :autonomous,
      schema_version: "1.0",
      issuer: "recurse.gateway",
      subject: "recurse://gateway/outbox_reconciler",
      recurse_role: "platform_operator"
    }
  end

  # Best-effort tenant resolution — the row carries `run_id` but not
  # `tenant_id` directly. The `ProviderRegistry` carries the deployment's
  # pinned tenant (Standalone is single-tenant per F002 FR-002).
  defp tenant_id_for(_row) do
    case Recurse.Gateway.ProviderRegistry.fetch() do
      {:ok, %{tenant_id: tid}} when is_binary(tid) -> tid
      _ -> "unknown"
    end
  end

  # Exponential: `2 ^ attempt` seconds, capped at 300 (5 min).
  defp default_backoff_seconds(attempt) when is_integer(attempt) and attempt >= 1 do
    :math.pow(2, attempt)
    |> trunc()
    |> min(@backoff_cap_seconds)
  end
end
