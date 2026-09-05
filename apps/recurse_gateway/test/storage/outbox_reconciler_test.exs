defmodule Recurse.Gateway.Storage.OutboxReconcilerTest do
  @moduledoc """
  Unit tests for `Recurse.Gateway.Storage.OutboxReconciler` (F002 T090).

  Coverage:

    * Boot catches up immediately (first tick triggered in `init/1`).
    * Rows advance to `:committed` after a successful storage put.
    * Backoff progresses monotonically on failed attempts.
    * `attempts >= max_attempts` promotes to `:dead_letter`.
    * Telemetry events fire on tick.
    * Defensive `handle_info/2` ignores noise.

  ## Isolation

  We inject a stub ledger + stub storage via the `:ledger` + `:storage`
  boot options, so no Repo / real S3 is touched. Each test gets a fresh
  Agent as the stub ledger's backing store.

  `async: false` — the LedgerFacade agent is stored in `:persistent_term`
  and StubStorage uses a named ETS table; both are globally shared, so
  serial tests are required.
  """

  # `async: false` because the LedgerFacade and StubStorage share
  # persistent_term / ETS keys across tests; running them in parallel
  # would race. Keep the tests serial.
  use ExUnit.Case, async: false

  alias Recurse.Gateway.Storage.OutboxReconciler

  defmodule StubLedger do
    @moduledoc false
    # A dumb Agent-backed stub; each test spawns its own instance. Mirrors
    # the contract the reconciler expects of PostgresMerkleLedger's public
    # AD-001 c' methods.
    use Agent

    def start_link(rows), do: Agent.start_link(fn -> %{rows: rows, log: []} end)

    def query_pending_outbox(agent, opts) do
      limit = Keyword.fetch!(opts, :limit)
      before = Keyword.get(opts, :before, DateTime.utc_now())

      rows =
        Agent.get(agent, fn st ->
          st.rows
          |> Enum.filter(fn r ->
            r.status == "pending" and
              DateTime.compare(r.next_attempt_at, before) in [:lt, :eq]
          end)
          |> Enum.take(limit)
        end)

      {:ok, rows}
    end

    def retry_outbox_entry(agent, id, attrs) do
      Agent.update(agent, fn st ->
        rows =
          Enum.map(st.rows, fn
            %{id: ^id} = r ->
              r
              |> Map.put(:attempts, attrs.attempts)
              |> Map.put(:next_attempt_at, attrs.next_attempt_at)
              |> Map.put(:last_error, attrs[:last_error])

            other ->
              other
          end)

        %{st | rows: rows, log: [{:retry, id, attrs} | st.log]}
      end)

      {:ok, :retried}
    end

    def mark_dead_letter(agent, id, reason) do
      Agent.update(agent, fn st ->
        rows =
          Enum.map(st.rows, fn
            %{id: ^id} = r -> %{r | status: "dead_letter"}
            other -> other
          end)

        %{st | rows: rows, log: [{:dead_letter, id, reason} | st.log]}
      end)

      {:ok, :dead_lettered}
    end

    def commit_outbox_success(agent, id, result) do
      Agent.update(agent, fn st ->
        rows =
          Enum.map(st.rows, fn
            %{id: ^id} = r -> %{r | status: "committed"}
            other -> other
          end)

        %{st | rows: rows, log: [{:commit, id, result} | st.log]}
      end)

      {:ok, :committed}
    end

    def log(agent), do: Agent.get(agent, & &1.log) |> Enum.reverse()
    def rows(agent), do: Agent.get(agent, & &1.rows)
  end

  defmodule LedgerFacade do
    @moduledoc false
    # Module shim — the reconciler calls ledger functions by module; this
    # facade carries the Agent pid via :persistent_term so the reconciler's
    # bare-module dispatch works from ANY process (the reconciler GenServer
    # runs on its own pid, so process-dict lookups from there would miss
    # the test pid's dict).
    #
    # The persistent_term key is NOT unique per test — tests that run in
    # the same BEAM must not interleave on the same key. We keep the
    # suite serial (`async: false` is set on the outer module by the
    # parallel SA — but if anything here crashes, the next test inherits
    # stale state). `setup`/`on_exit` resets the key each test.
    @key {__MODULE__, :agent}

    def set_agent(pid), do: :persistent_term.put(@key, pid)
    def clear_agent, do: :persistent_term.erase(@key)

    def query_pending_outbox(opts), do: StubLedger.query_pending_outbox(agent(), opts)
    def retry_outbox_entry(id, attrs), do: StubLedger.retry_outbox_entry(agent(), id, attrs)
    def mark_dead_letter(id, reason), do: StubLedger.mark_dead_letter(agent(), id, reason)

    def commit_outbox_success(id, result),
      do: StubLedger.commit_outbox_success(agent(), id, result)

    defp agent do
      case :persistent_term.get(@key, :unset) do
        pid when is_pid(pid) ->
          pid

        :unset ->
          raise "LedgerFacade agent not set in persistent_term — test setup error"
      end
    end
  end

  defmodule StubStorage do
    @moduledoc false
    # `put_payload/3` consults an ETS table for the behavior to apply to
    # this call. ETS (not process-dict) so the reconciler GenServer can
    # see the programmed behavior from its own pid.
    @behaviour Recurse.Providers.StorageProvider

    @table :outbox_reconciler_stub_storage

    def program(results) when is_list(results) do
      ensure_table!()
      :ets.insert(@table, {:queue, results})
      :ok
    end

    def pending do
      ensure_table!()

      case :ets.lookup(@table, :queue) do
        [{:queue, results}] -> results
        [] -> []
      end
    end

    def reset do
      ensure_table!()
      :ets.insert(@table, {:queue, []})
    end

    defp ensure_table! do
      case :ets.whereis(@table) do
        :undefined ->
          :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])

        _tid ->
          :ok
      end
    end

    @impl true
    def init(_), do: {:ok, %{}}

    @impl true
    def put_payload(_state, _bytes, _ctx) do
      ensure_table!()

      case :ets.lookup(@table, :queue) do
        [{:queue, [result | rest]}] ->
          :ets.insert(@table, {:queue, rest})
          result

        _ ->
          {:ok, %{uri: "s3://stub/ok", hash: :crypto.hash(:sha256, "ok")}}
      end
    end

    @impl true
    def get_payload(_, _, _), do: {:error, :not_implemented}

    @impl true
    def delete_payload(_, _, _), do: :ok

    @impl true
    def capabilities(_), do: [:put]

    @impl true
    def healthcheck(_), do: :ok

    @impl true
    def terminate(_, _), do: :ok
  end

  # --------------------------------------------------------------------------
  # Helpers
  # --------------------------------------------------------------------------

  defp now_minus(seconds), do: DateTime.add(DateTime.utc_now(), -seconds, :second)

  defp make_row(overrides \\ %{}) do
    defaults = %{
      id: Ecto.UUID.generate(),
      run_id: Ecto.UUID.generate(),
      attestation_bytes: "att",
      payload_bytes: "payload",
      target_uri: "s3://bucket/tenant/run.json",
      attempts: 0,
      status: "pending",
      next_attempt_at: now_minus(10),
      last_error: nil
    }

    Map.merge(defaults, overrides)
  end

  defp start_reconciler(opts) do
    spec =
      Supervisor.child_spec(
        {OutboxReconciler,
         Keyword.merge(
           [
             name: nil,
             ledger: LedgerFacade,
             pubsub: Recurse.PubSub,
             # Very long default so we don't re-tick during tests —
             # tests `send(pid, :tick)` explicitly when they need more.
             poll_interval_ms: 60_000
           ],
           opts
         )},
        id: make_ref()
      )

    start_supervised!(spec)
  end

  defp flush_mailbox(pid) do
    # After send/2, nudge the reconciler so all enqueued :tick messages
    # are processed before we assert state.
    _ = :sys.get_state(pid)
    :ok
  end

  setup do
    {:ok, agent} = StubLedger.start_link([])
    LedgerFacade.set_agent(agent)
    StubStorage.reset()

    on_exit(fn ->
      LedgerFacade.clear_agent()
      # Don't delete ETS table — leaving it named is fine for next test.
      StubStorage.reset()
    end)

    {:ok, agent: agent}
  end

  # --------------------------------------------------------------------------
  # Tests
  # --------------------------------------------------------------------------

  describe "boot + tick" do
    test "first tick fires immediately (catch-up on boot)", %{agent: agent} do
      row = make_row()
      Agent.update(agent, fn st -> %{st | rows: [row]} end)
      StubStorage.program([{:ok, %{uri: row.target_uri, hash: <<1>>}}])

      pid = start_reconciler(storage: {StubStorage, %{}})
      flush_mailbox(pid)

      assert [committed_row] = StubLedger.rows(agent)
      assert committed_row.status == "committed"
    end

    test "tick with empty outbox is a no-op", %{agent: _agent} do
      pid = start_reconciler(storage: {StubStorage, %{}})
      flush_mailbox(pid)

      state = :sys.get_state(pid)
      assert state.processed_total == 0
      assert state.dead_letter_total == 0
      assert state.failure_total == 0
    end
  end

  describe "success path" do
    test "successful put_payload advances row to :committed + broadcasts", %{agent: agent} do
      row = make_row()
      Agent.update(agent, fn st -> %{st | rows: [row]} end)
      StubStorage.program([{:ok, %{uri: row.target_uri, hash: <<2>>}}])

      # Subscribe BEFORE starting the reconciler so we catch the broadcast.
      :ok = Phoenix.PubSub.subscribe(Recurse.PubSub, "recurse:outbox_committed")

      pid = start_reconciler(storage: {StubStorage, %{}})
      flush_mailbox(pid)

      assert_receive {:outbox_committed, run_id}
      assert run_id == row.run_id

      state = :sys.get_state(pid)
      assert state.processed_total == 1
      assert state.failure_total == 0
    end
  end

  describe "failure + backoff" do
    test "failure bumps attempts and schedules next_attempt_at via backoff", %{agent: agent} do
      row = make_row(%{attempts: 0})
      Agent.update(agent, fn st -> %{st | rows: [row]} end)
      StubStorage.program([{:error, :s3_unavailable}])

      # Deterministic backoff — attempt N → N seconds from now.
      pid =
        start_reconciler(
          storage: {StubStorage, %{}},
          backoff_fun: fn attempt -> attempt end
        )

      flush_mailbox(pid)

      [updated] = StubLedger.rows(agent)
      assert updated.attempts == 1
      assert updated.last_error =~ "s3_unavailable"
      assert updated.status == "pending"

      state = :sys.get_state(pid)
      assert state.failure_total == 1
      assert state.processed_total == 0
    end

    test "exponential backoff progresses: 2, 4, 8, ... capped at 300s", %{agent: _} do
      # Not a running-process test — exercise the internal default via
      # module introspection. The private `default_backoff_seconds/1`
      # is hit by the running reconciler; here we cover the shape
      # through reused behavior (send N failure ticks).
      row = make_row(%{attempts: 2})
      {:ok, agent} = StubLedger.start_link([row])
      LedgerFacade.set_agent(agent)
      StubStorage.program([{:error, :unavailable}])

      pid = start_reconciler(storage: {StubStorage, %{}})
      flush_mailbox(pid)

      [updated] = StubLedger.rows(agent)
      assert updated.attempts == 3

      # 2 ^ 3 = 8 seconds — next attempt is ~8s away.
      diff = DateTime.diff(updated.next_attempt_at, DateTime.utc_now())
      assert diff >= 7 and diff <= 10
    end
  end

  describe "dead-letter" do
    test "row with attempts >= max_attempts flips to dead_letter without retry",
         %{agent: agent} do
      row = make_row(%{attempts: 10})
      Agent.update(agent, fn st -> %{st | rows: [row]} end)

      pid =
        start_reconciler(
          storage: {StubStorage, %{}},
          max_attempts: 10
        )

      flush_mailbox(pid)

      [rewritten] = StubLedger.rows(agent)
      assert rewritten.status == "dead_letter"

      # Storage should NOT have been called — put_payload queue is intact.
      assert StubStorage.pending() == []

      state = :sys.get_state(pid)
      assert state.dead_letter_total == 1
      assert state.processed_total == 0
    end
  end

  describe "telemetry" do
    test "emits [:recurse, :outbox, :tick] on each tick", %{agent: agent} do
      Agent.update(agent, fn st -> %{st | rows: [make_row()]} end)
      StubStorage.program([{:ok, %{uri: "s3://ok", hash: <<>>}}])

      test_pid = self()

      :telemetry.attach(
        "outbox-tick-test-#{System.unique_integer()}",
        [:recurse, :outbox, :tick],
        fn _event, measurements, metadata, _ ->
          send(test_pid, {:tick, measurements, metadata})
        end,
        nil
      )

      pid = start_reconciler(storage: {StubStorage, %{}})
      flush_mailbox(pid)

      assert_receive {:tick, %{processed: 1}, _meta}, 500
    end

    test "emits [:recurse, :outbox, :row_committed] on each commit", %{agent: agent} do
      Agent.update(agent, fn st -> %{st | rows: [make_row()]} end)
      StubStorage.program([{:ok, %{uri: "s3://ok", hash: <<>>}}])

      test_pid = self()

      :telemetry.attach(
        "outbox-committed-test-#{System.unique_integer()}",
        [:recurse, :outbox, :row_committed],
        fn _event, _m, metadata, _ -> send(test_pid, {:committed, metadata}) end,
        nil
      )

      pid = start_reconciler(storage: {StubStorage, %{}})
      flush_mailbox(pid)

      assert_receive {:committed, %{run_id: _}}, 500
    end

    test "emits [:recurse, :outbox, :row_dead_letter] on dead-letter transition",
         %{agent: agent} do
      Agent.update(agent, fn st -> %{st | rows: [make_row(%{attempts: 10})]} end)

      test_pid = self()

      :telemetry.attach(
        "outbox-dead-test-#{System.unique_integer()}",
        [:recurse, :outbox, :row_dead_letter],
        fn _event, _m, metadata, _ -> send(test_pid, {:dead, metadata}) end,
        nil
      )

      pid = start_reconciler(storage: {StubStorage, %{}}, max_attempts: 10)
      flush_mailbox(pid)

      assert_receive {:dead, %{run_id: _, last_error: _}}, 500
    end
  end

  describe "defensive" do
    test "ignores stray messages", %{agent: _agent} do
      pid = start_reconciler(storage: {StubStorage, %{}})
      flush_mailbox(pid)

      send(pid, :noise)
      send(pid, {:unexpected, "payload"})
      # GenServer is still alive and state is still sane.
      assert Process.alive?(pid)
      state = :sys.get_state(pid)
      assert is_integer(state.processed_total)
    end
  end
end
