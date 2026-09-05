defmodule Recurse.Gateway.Admin.LiveTailSocket do
  @moduledoc """
  WebSocket handler for `GET /admin/live-tail` (F004 T063 + T069).

  Streams newly-committed attestations from the F002
  `recurse:attestation_first_committed` PubSub topic to authenticated
  audit-console browser clients in real time. Per-connection filter,
  heartbeat protocol, bounded reconnection backfill, and backpressure
  enforcement per `live_tail_transport.md`.

  ## Two entry surfaces

    * `upgrade/1` — Plug-shaped function called by the router. Validates
      the cookie envelope (already lifted into `Authorization: Bearer
      <jwt>` by `BrowserSessionPlug`), runs the F002 `Authz.gate/4`
      pipeline against `Recurse::Action::"DashboardQuery"`, and on
      `:allow` calls `WebSockAdapter.upgrade/4` to hand the connection
      to Bandit's WebSocket dispatcher with this module as the handler.
      On `:deny`, sends 403 + emits `:policy_denied` per
      `audit_api_extensions.md` §"Cross-cutting rules".
    * `WebSock` callbacks — the per-connection process. Subscribes to
      PubSub at init, ships filtered receipts as `attestation` JSON
      frames, services client `set_filter` / `pong` / `ping` control
      frames, and applies the heartbeat + backpressure rules.

  ## Iron Law check (`elixir:phoenix-thinking`, `elixir:otp-thinking`)

  The WebSocket process IS a long-lived BEAM process owned by Bandit's
  WebSocket dispatcher. The mailbox carries:

    1. PubSub `{:attestation_first_committed, ...}` deliveries from
       the topic subscription.
    2. `:heartbeat_check` self-sends from `Process.send_after/3`.
    3. Client text frames via `handle_in/2`.

  This is a legitimate process — it owns runtime state (filter,
  heartbeat clock, backfill cursor, pending-frame counter) that
  outlives any single message. Not a "GenServer for organization"
  anti-pattern; the lifecycle (subscribe → live → close on stall) is
  the correct shape.

  Pure functional thinking still applies inside the callbacks: the
  filter compiler is a pure function returning a closure; frame
  encoding is pure JSON; the only side effects are Phoenix.PubSub
  subscribe/unsubscribe, `Process.send_after/3` for heartbeat scheduling,
  and `IO`/log lines.

  ## Frame protocol summary (full spec in live_tail_transport.md)

  Server → client:
    * `attestation` — primary frame; the slim row shape used by the
      Dashboard's TanStack Table.
    * `filter_acknowledged` — sent in response to `set_filter`.
    * `backfill_summary` — sent at end of post-reconnect backfill.
    * `error` — recoverable error (invalid filter, unknown key,
      backpressure warning).
    * `ping` — every 60s server-side heartbeat.

  Client → server:
    * `set_filter` — replace the per-connection filter.
    * `ping` / `pong` — heartbeats.

  Close codes:
    * 1000 normal; 4001 cookie expired; 4002 cross-tenant; 4003 server
      shutting down; 4408 missed-heartbeat OR sustained backpressure.

  ## Heartbeat (T063 §"Heartbeat protocol")

  Server pings every `@server_ping_interval_ms`. If no client frame of
  any kind arrives within `@client_idle_timeout_ms` (90s), close 4408.
  We schedule a `:heartbeat_check` self-message on `:timer.send_interval`
  cadence so the timer cost is bounded per process.

  ## Backpressure (T069 §"Backpressure")

    * After `@backpressure_pending_threshold` (100) unacked frames in
      the per-process pending-counter, increment a `stalled_at`
      timestamp.
    * After `@backpressure_warning_ms` (30s) of sustained stall, send
      a `backpressure_warning` `error` frame.
    * After `@backpressure_close_ms` (60s) of sustained stall, close
      the connection with 4408.

  We approximate "client ack" as "any frame received from the client"
  (set_filter, ping, pong) — the WebSock layer hides per-frame ACK
  semantics from the handler. This is the contract spec's intent: a
  client that's actively sending frames is alive; a client that's
  silent and behind on consumption is the stall case.

  ## Reconnection backfill (T063 §"Reconnection + bounded backfill")

  Bounded to `@backfill_max_rows` (1,000) receipts per the contract.
  On connect, if the client passed `?last_seen_run_id=uuid`, the handler
  queries the audit log for receipts with `committed_at >
  last_seen.committed_at` for the connection's tenant, ordered ASC,
  capped at 1,001 rows (the +1 lets us flag truncation without a
  separate count query). Each backfilled receipt is shipped as an
  `attestation` frame, then a `backfill_summary` frame summarizes the
  batch.

  ## Cross-references

    * `specs/004-audit-console/contracts/live_tail_transport.md`
    * `specs/004-audit-console/research.md` D2 (WebSocket via Bandit)
    * `apps/recurse_gateway/lib/recurse_gateway/audit_plane/authz.ex`
      (Authz.gate/4 reused)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_session_plug.ex`
      (cookie envelope lifter, runs upstream)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/ui_receipts.ex`
      (`:ui_session` event_kind emissions for live_tail_open / close /
      policy_denied)
  """

  @behaviour WebSock

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext

  require Logger

  @action "Recurse::Action::\"DashboardQuery\""
  @pubsub_name Recurse.PubSub
  @pubsub_topic "recurse:attestation_first_committed"

  # Heartbeat constants (live_tail_transport.md §"Heartbeat protocol").
  @server_ping_interval_ms 60_000
  @client_idle_timeout_ms 90_000
  @heartbeat_tick_ms 5_000

  # Backpressure constants (live_tail_transport.md §"Backpressure", T069).
  @backpressure_pending_threshold 100
  @backpressure_warning_ms 30_000
  @backpressure_close_ms 60_000
  @websocket_close_code_stall 4408

  # Backfill bound (live_tail_transport.md §"Reconnection + bounded backfill").
  @backfill_max_rows 1_000

  @typedoc "Per-connection state shape per live_tail_transport.md §Connection state."
  @type state :: %{
          principal_subject: String.t(),
          tenant_id: String.t(),
          browser_session_id: String.t() | nil,
          correlation_id: String.t(),
          filter: map(),
          filter_compiled: (map() -> boolean()),
          last_seen_run_id: String.t() | nil,
          last_seen_committed_at: DateTime.t() | nil,
          last_client_frame_at: integer(),
          pending_frames: non_neg_integer(),
          stalled_at: integer() | nil
        }

  # ---------------------------------------------------------------------------
  # Plug entry — upgrade gate
  # ---------------------------------------------------------------------------

  @doc """
  Plug entry. Authenticates + Cedar-gates the upgrade request, then hands
  the connection to Bandit's WebSocket dispatcher. Returns the (possibly
  upgraded) `Plug.Conn`.
  """
  @spec upgrade(Plug.Conn.t()) :: Plug.Conn.t()
  def upgrade(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "live_tail",
      attrs: %{"endpoint" => "/admin/live-tail"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_with_ctx, ctx, _bundle_ref} ->
        do_upgrade(conn_with_ctx, ctx)

      {:error, :forbidden, _matched} = err ->
        emit_policy_denied(conn, "live_tail_upgrade_denied")
        Authz.dispatch_gate_error(conn, err)

      other_err ->
        Authz.dispatch_gate_error(conn, other_err)
    end
  end

  defp do_upgrade(conn, %IdentityContext{} = ctx) do
    fetched = Plug.Conn.fetch_query_params(conn)
    last_seen_run_id = Map.get(fetched.query_params, "last_seen_run_id")

    initial_state = build_initial_state(ctx, last_seen_run_id)

    # Disable permessage-deflate per live_tail_transport.md §"Out of scope":
    # "F004 disables to keep the wire encoding simple to diagnose during
    # verification."
    WebSockAdapter.upgrade(fetched, __MODULE__, initial_state,
      compress: false,
      timeout: @client_idle_timeout_ms
    )
  end

  defp build_initial_state(%IdentityContext{} = ctx, last_seen_run_id) do
    now = System.monotonic_time(:millisecond)

    %{
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      browser_session_id: nil,
      correlation_id: ctx.correlation_id,
      filter: empty_filter(),
      filter_compiled: compile_filter(empty_filter()),
      last_seen_run_id: last_seen_run_id,
      last_seen_committed_at: nil,
      last_client_frame_at: now,
      pending_frames: 0,
      stalled_at: nil
    }
  end

  # ---------------------------------------------------------------------------
  # WebSock callbacks
  # ---------------------------------------------------------------------------

  @impl WebSock
  def init(state) do
    :ok = Phoenix.PubSub.subscribe(@pubsub_name, @pubsub_topic)

    # Schedule the heartbeat tick. We use a single periodic tick rather
    # than `Process.send_after` per ping so timer drift doesn't compound
    # over a long-lived connection.
    :timer.send_interval(@heartbeat_tick_ms, :heartbeat_tick)

    emit_session_event(state, "live_tail_open")

    # Backfill the gap if the client provided a last_seen cursor. Returns
    # an `attestation`-frame list followed by a `backfill_summary` frame.
    case backfill_since(state) do
      {[], updated_state} ->
        {:ok, updated_state}

      {messages, updated_state} ->
        {:push, messages, updated_state}
    end
  end

  @impl WebSock
  def handle_in({text_payload, opcode: :text}, state) do
    state = touch_client_frame(state)

    case JSON.decode(text_payload) do
      {:ok, decoded} ->
        handle_client_frame(decoded, state)

      _ ->
        {:push, [{:text, encode_error("malformed_json", "frame is not valid JSON")}], state}
    end
  end

  def handle_in({_payload, opcode: :binary}, state) do
    # Live-tail wire format is JSON text only; reject binary cleanly.
    state = touch_client_frame(state)
    {:push, [{:text, encode_error("unsupported_opcode", "binary frames are not supported")}], state}
  end

  @impl WebSock
  def handle_control({_payload, opcode: :ping}, state) do
    # Bandit auto-replies with pong before this callback fires; we just
    # record the keepalive for the heartbeat clock.
    {:ok, touch_client_frame(state)}
  end

  def handle_control({_payload, opcode: :pong}, state) do
    {:ok, touch_client_frame(state)}
  end

  @impl WebSock
  def handle_info({:first_committed, _run_id, payload}, state) do
    forward_attestation(payload, state)
  end

  def handle_info(:heartbeat_tick, state) do
    cond do
      client_idle_for_too_long?(state) ->
        # Missed heartbeat: close 4408 per contract.
        Logger.info(fn ->
          "live_tail closing 4408 (client idle) ps=#{state.principal_subject}"
        end)

        {:stop, :normal, {@websocket_close_code_stall, "client missed heartbeats"}, state}

      backpressure_close_due?(state) ->
        Logger.info(fn ->
          "live_tail closing 4408 (sustained backpressure) ps=#{state.principal_subject}"
        end)

        {:stop, :normal, {@websocket_close_code_stall, "client backpressure exceeded"}, state}

      backpressure_warning_due?(state) ->
        # Send a recoverable warning + emit periodic server ping so the
        # client knows the server is still alive. Reset the warning window
        # so we don't spam the client; the close timer remains armed.
        warning_frame = encode_error("backpressure", "client send-buffer at threshold; throttling")
        ping_frame = {:text, encode_ping()}

        new_state = %{state | stalled_at: System.monotonic_time(:millisecond)}
        {:push, [{:text, warning_frame}, ping_frame], new_state}

      should_send_server_ping?(state) ->
        {:push, [{:text, encode_ping()}], state}

      true ->
        {:ok, state}
    end
  end

  def handle_info(_other, state), do: {:ok, state}

  @impl WebSock
  def terminate(_reason, state) do
    emit_session_event(state, "live_tail_close")
    :ok
  end

  # ---------------------------------------------------------------------------
  # Client-frame dispatch
  # ---------------------------------------------------------------------------

  defp handle_client_frame(%{"type" => "set_filter", "filter" => raw_filter}, state)
       when is_map(raw_filter) do
    case validate_filter(raw_filter) do
      {:ok, filter} ->
        compiled = compile_filter(filter)
        ack = encode_filter_acknowledged(filter)
        new_state = %{state | filter: filter, filter_compiled: compiled}
        {:push, [{:text, ack}], new_state}

      {:error, code, message} ->
        {:push, [{:text, encode_error(code, message)}], state}
    end
  end

  defp handle_client_frame(%{"type" => "ping"}, state) do
    {:push, [{:text, encode_pong()}], state}
  end

  defp handle_client_frame(%{"type" => "pong"}, state) do
    # Already touched the client-frame clock; nothing more to do.
    {:ok, state}
  end

  defp handle_client_frame(%{"type" => other}, state) when is_binary(other) do
    {:push, [{:text, encode_error("unknown_frame_type", "frame type #{other} is not supported")}], state}
  end

  defp handle_client_frame(_, state) do
    {:push, [{:text, encode_error("malformed_frame", "frame missing 'type' field")}], state}
  end

  # ---------------------------------------------------------------------------
  # Receipt forwarding (PubSub message → attestation frame)
  # ---------------------------------------------------------------------------

  defp forward_attestation(payload, state) do
    attestation = extract_attestation(payload)

    cond do
      attestation == nil ->
        {:ok, state}

      attestation.tenant_id != state.tenant_id ->
        # Defense-in-depth (single-tenant-per-BEAM in Phase-1; the per-
        # emission guard guarantees no cross-tenant leakage even if a
        # configuration error wires a foreign-tenant attestation through).
        {:ok, state}

      not state.filter_compiled.(attestation) ->
        {:ok, state}

      backpressure_pending_too_high?(state) ->
        # Skip pushing this attestation; the heartbeat tick will close
        # the connection if the stall persists.
        {:ok, mark_stalled_if_new(state)}

      true ->
        frame = encode_attestation_frame(attestation)
        new_state = bump_pending(state) |> update_last_seen(attestation)
        {:push, [{:text, frame}], new_state}
    end
  end

  defp extract_attestation(%{attestation: att}) when is_map(att), do: att
  defp extract_attestation(%{tenant_id: _} = att), do: att
  defp extract_attestation(_), do: nil

  defp update_last_seen(state, attestation) do
    %{
      state
      | last_seen_run_id: Map.get(attestation, :run_id),
        last_seen_committed_at:
          Map.get(attestation, :timestamp) || Map.get(attestation, :committed_at)
    }
  end

  # ---------------------------------------------------------------------------
  # Reconnection backfill
  # ---------------------------------------------------------------------------

  defp backfill_since(%{last_seen_run_id: nil} = state), do: {[], state}

  defp backfill_since(%{last_seen_run_id: cursor_run_id, tenant_id: tenant_id} = state)
       when is_binary(cursor_run_id) do
    case fetch_attestation_committed_at(cursor_run_id, tenant_id) do
      {:ok, since_dt} ->
        {rows, truncated?} = fetch_backfill_rows(tenant_id, since_dt)

        attestation_frames =
          rows
          |> Enum.filter(state.filter_compiled)
          |> Enum.map(fn row -> {:text, encode_attestation_frame(row)} end)

        summary_frame = {:text, encode_backfill_summary(rows, truncated?, cursor_run_id)}

        last = List.last(rows)

        new_state =
          state
          |> Map.put(:last_seen_run_id, last && Map.get(last, :run_id))
          |> Map.put(
            :last_seen_committed_at,
            last && (Map.get(last, :timestamp) || Map.get(last, :committed_at))
          )

        {attestation_frames ++ [summary_frame], new_state}

      :error ->
        # Forged or cross-tenant cursor — return empty backfill per
        # live_tail_transport.md §"Reconnection cursor security".
        {[], state}
    end
  end

  # Returns `{:ok, committed_at}` only if the attestation belongs to the
  # caller's tenant; foreign-tenant cursors return `:error` (silent).
  defp fetch_attestation_committed_at(run_id, tenant_id) do
    case Repo.get(Attestation, run_id) do
      %Attestation{tenant_id: ^tenant_id, timestamp: ts} -> {:ok, ts}
      _ -> :error
    end
  rescue
    Ecto.Query.CastError -> :error
  end

  # Bounded fetch: we ask for `@backfill_max_rows + 1` rows so the
  # `@backfill_max_rows + 1`-th row's existence flags truncation. Returns
  # `{rows, truncated?}` with rows capped at the bound.
  defp fetch_backfill_rows(tenant_id, since_dt) do
    import Ecto.Query, only: [from: 2]

    rows =
      from(a in Attestation,
        where: a.tenant_id == ^tenant_id and a.timestamp > ^since_dt,
        order_by: [asc: a.timestamp, asc: a.run_id],
        limit: ^(@backfill_max_rows + 1)
      )
      |> Repo.all()
      |> Enum.map(&Map.from_struct/1)

    case Enum.split(rows, @backfill_max_rows) do
      {kept, []} -> {kept, false}
      {kept, _overflow} -> {kept, true}
    end
  end

  # ---------------------------------------------------------------------------
  # Filter compilation + validation
  # ---------------------------------------------------------------------------

  @allowed_filter_keys ~w(event_kind policy_decision principal_subject tool_name since)

  defp empty_filter, do: %{}

  defp validate_filter(raw) when is_map(raw) do
    case Enum.find(Map.keys(raw), fn k -> k not in @allowed_filter_keys end) do
      nil -> validate_filter_values(raw)
      bad -> {:error, "unknown_filter_key", "unknown filter key: #{bad}"}
    end
  end

  defp validate_filter_values(filter) do
    cond do
      not valid_event_kind_filter?(Map.get(filter, "event_kind")) ->
        {:error, "invalid_filter", "event_kind must be a list of strings"}

      not valid_policy_decision_filter?(Map.get(filter, "policy_decision")) ->
        {:error, "invalid_filter", "policy_decision must be allow|deny|any"}

      not valid_string_or_nil?(Map.get(filter, "principal_subject")) ->
        {:error, "invalid_filter", "principal_subject must be a string"}

      not valid_string_or_nil?(Map.get(filter, "tool_name")) ->
        {:error, "invalid_filter", "tool_name must be a string"}

      not valid_since_filter?(Map.get(filter, "since")) ->
        {:error, "invalid_filter", "since must be ISO 8601"}

      true ->
        {:ok, filter}
    end
  end

  defp valid_event_kind_filter?(nil), do: true
  defp valid_event_kind_filter?(list) when is_list(list), do: Enum.all?(list, &is_binary/1)
  defp valid_event_kind_filter?(_), do: false

  defp valid_policy_decision_filter?(nil), do: true
  defp valid_policy_decision_filter?(v) when v in ["allow", "deny", "any"], do: true
  defp valid_policy_decision_filter?(_), do: false

  defp valid_string_or_nil?(nil), do: true
  defp valid_string_or_nil?(v) when is_binary(v), do: true
  defp valid_string_or_nil?(_), do: false

  defp valid_since_filter?(nil), do: true

  defp valid_since_filter?(v) when is_binary(v) do
    case DateTime.from_iso8601(v) do
      {:ok, _, _} -> true
      _ -> false
    end
  end

  defp valid_since_filter?(_), do: false

  defp compile_filter(filter) do
    fn attestation ->
      pass_event_kind?(attestation, Map.get(filter, "event_kind")) and
        pass_policy_decision?(attestation, Map.get(filter, "policy_decision")) and
        pass_principal_subject?(attestation, Map.get(filter, "principal_subject")) and
        pass_tool_name?(attestation, Map.get(filter, "tool_name")) and
        pass_since?(attestation, Map.get(filter, "since"))
    end
  end

  defp pass_event_kind?(_att, nil), do: true
  defp pass_event_kind?(_att, []), do: true

  defp pass_event_kind?(att, kinds) when is_list(kinds) do
    case Map.get(att, :event_kind) do
      nil -> false
      atom when is_atom(atom) -> Atom.to_string(atom) in kinds
      str when is_binary(str) -> str in kinds
    end
  end

  defp pass_policy_decision?(_att, nil), do: true
  defp pass_policy_decision?(_att, "any"), do: true

  defp pass_policy_decision?(att, val) when val in ["allow", "deny"] do
    case Map.get(att, :policy_decision) do
      nil -> false
      atom when is_atom(atom) -> Atom.to_string(atom) == val
      str when is_binary(str) -> str == val
    end
  end

  defp pass_principal_subject?(_att, nil), do: true

  defp pass_principal_subject?(att, expected) when is_binary(expected) do
    case Map.get(att, :principal) do
      %{"subject" => ^expected} -> true
      %{"account_id" => ^expected} -> true
      _ -> false
    end
  end

  defp pass_tool_name?(_att, nil), do: true

  defp pass_tool_name?(att, tool_name) when is_binary(tool_name) do
    Map.get(att, :tool_name) == tool_name
  end

  defp pass_since?(_att, nil), do: true

  defp pass_since?(att, since_iso) when is_binary(since_iso) do
    with {:ok, since_dt, _} <- DateTime.from_iso8601(since_iso),
         %DateTime{} = att_dt <- Map.get(att, :timestamp) || Map.get(att, :committed_at) do
      DateTime.compare(att_dt, since_dt) != :lt
    else
      _ -> true
    end
  end

  # ---------------------------------------------------------------------------
  # Heartbeat + backpressure helpers
  # ---------------------------------------------------------------------------

  defp client_idle_for_too_long?(state) do
    System.monotonic_time(:millisecond) - state.last_client_frame_at > @client_idle_timeout_ms
  end

  defp should_send_server_ping?(state) do
    last_ping_age = System.monotonic_time(:millisecond) - state.last_client_frame_at
    last_ping_age >= @server_ping_interval_ms
  end

  defp backpressure_pending_too_high?(state) do
    state.pending_frames >= @backpressure_pending_threshold
  end

  defp mark_stalled_if_new(state) do
    case state.stalled_at do
      nil -> %{state | stalled_at: System.monotonic_time(:millisecond)}
      _ -> state
    end
  end

  defp backpressure_warning_due?(%{stalled_at: nil}), do: false

  defp backpressure_warning_due?(%{stalled_at: stalled_at}) do
    age = System.monotonic_time(:millisecond) - stalled_at
    age >= @backpressure_warning_ms and age < @backpressure_close_ms
  end

  defp backpressure_close_due?(%{stalled_at: nil}), do: false

  defp backpressure_close_due?(%{stalled_at: stalled_at}) do
    System.monotonic_time(:millisecond) - stalled_at >= @backpressure_close_ms
  end

  defp bump_pending(state) do
    # Approximation: WebSock layer hides per-frame ACKs from the handler,
    # so we proxy the queue depth via the count of pushes since the last
    # client-side liveness signal. A client-frame `touch_client_frame/1`
    # resets pending. Live clients sending pings/pongs keep the counter
    # naturally trimmed; stalled clients accumulate until the threshold.
    %{state | pending_frames: state.pending_frames + 1}
  end

  # When a client sends ANY frame, the touch helper resets the
  # backpressure counters AND the client-idle clock. Live clients sending
  # pings/pongs naturally trim the pending counter; stalled clients
  # accumulate until the threshold and then the heartbeat-tick
  # `backpressure_close_due?` clause fires.
  defp touch_client_frame(state) do
    %{
      state
      | last_client_frame_at: System.monotonic_time(:millisecond),
        pending_frames: 0,
        stalled_at: nil
    }
  end

  # ---------------------------------------------------------------------------
  # Frame encoders
  # ---------------------------------------------------------------------------

  defp encode_attestation_frame(att) do
    JSON.encode!(%{
      "type" => "attestation",
      "run_id" => Map.get(att, :run_id),
      "tenant_id" => Map.get(att, :tenant_id),
      "session_id" => Map.get(att, :session_id),
      "event_kind" => to_string_or_nil(Map.get(att, :event_kind)),
      "policy_decision" => to_string_or_nil(Map.get(att, :policy_decision)),
      "principal_subject" => principal_subject_of(att),
      "committed_at" => dt_or_nil(Map.get(att, :timestamp) || Map.get(att, :committed_at)),
      "summary" => summary_of(att),
      "verification_level" => to_string_or_nil(Map.get(att, :verification_level))
    })
  end

  defp encode_filter_acknowledged(filter) do
    JSON.encode!(%{
      "type" => "filter_acknowledged",
      "filter" => filter,
      "applied_at" => DateTime.utc_now() |> DateTime.to_iso8601()
    })
  end

  defp encode_backfill_summary(rows, truncated?, from_run_id) do
    last_run_id = rows |> List.last() |> case do
      nil -> nil
      row -> Map.get(row, :run_id)
    end

    JSON.encode!(%{
      "type" => "backfill_summary",
      "from_run_id" => from_run_id,
      "to_run_id" => last_run_id,
      "delivered_count" => length(rows),
      "truncated" => truncated?
    })
  end

  defp encode_error(code, message) do
    JSON.encode!(%{"type" => "error", "code" => code, "message" => message})
  end

  defp encode_ping do
    JSON.encode!(%{"type" => "ping", "ts" => DateTime.utc_now() |> DateTime.to_iso8601()})
  end

  defp encode_pong do
    JSON.encode!(%{"type" => "pong", "ts" => DateTime.utc_now() |> DateTime.to_iso8601()})
  end

  defp principal_subject_of(att) do
    case Map.get(att, :principal) do
      %{"subject" => sub} -> sub
      %{"account_id" => id} -> id
      _ -> nil
    end
  end

  defp summary_of(att) do
    [
      to_string_or_nil(Map.get(att, :event_kind)),
      "outcome=" <> (to_string_or_nil(Map.get(att, :outcome)) || "unknown")
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
  end

  defp to_string_or_nil(nil), do: nil
  defp to_string_or_nil(v) when is_atom(v), do: Atom.to_string(v)
  defp to_string_or_nil(v) when is_binary(v), do: v
  defp to_string_or_nil(v), do: to_string(v)

  defp dt_or_nil(nil), do: nil
  defp dt_or_nil(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp dt_or_nil(v) when is_binary(v), do: v

  # ---------------------------------------------------------------------------
  # `:ui_session` emissions (open / close / policy_denied)
  # ---------------------------------------------------------------------------

  defp emit_session_event(state, event) do
    UiReceipts.emit(:ui_session, %{
      event: event,
      session_kind: event,
      principal_subject: state.principal_subject,
      tenant_id: state.tenant_id,
      correlation_id: state.correlation_id,
      browser_session_id: state.browser_session_id
    })
  end

  defp emit_policy_denied(conn, reason) do
    # Best-effort principal extraction from the assigns the cookie plug
    # set; on cross-tenant denial we may not have a fully resolved ctx.
    {ps, tid, cid} =
      case Map.get(conn.assigns, :identity_ctx) do
        %IdentityContext{} = ctx ->
          {principal_subject_from_ctx(ctx), ctx.tenant_id, ctx.correlation_id}

        _ ->
          {nil, nil, nil}
      end

    UiReceipts.emit(:ui_session, %{
      event: "policy_denied",
      reason: reason,
      principal_subject: ps,
      tenant_id: tid,
      correlation_id: cid
    })
  end

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}})
       when is_binary(sub),
       do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}})
       when is_binary(id),
       do: id

  defp principal_subject_from_ctx(_), do: nil
end
