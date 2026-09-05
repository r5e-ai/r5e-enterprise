defmodule Recurse.Gateway.Policy.BundleLoader do
  @moduledoc """
  Filesystem-path Cedar policy bundle loader (F002 T046, FR-010; spec 012
  S5 adds mtime polling + reload status).

  ## Role

  One of several loaders that populate the canonical
  `Recurse.Gateway.Policy.Active` store. This loader handles the
  filesystem path (dev, air-gapped, customer-mounted bundles, and the
  compose quickstart's `policy-sync` sidecar); the OCI-registry path is
  handled by `Recurse.Gateway.Policy.OciBundleManager`. ALL
  Cedar-evaluating call sites read from `Active.current/0`, NOT from any
  specific loader.

  The `BundleLoader` is a singleton GenServer that:

    1. Loads the Cedar bundle at boot via
       `Recurse.Providers.Impls.FilesystemPolicyProvider.init/1` +
       `fetch_active_bundle/1`, wraps the result in a
       `%Recurse.Gateway.PolicyBundleRef{}`, and writes that bundle to
       the canonical store via
       `Recurse.Gateway.Policy.Active.update/1` with
       `source: :filesystem`.
    2. On SIGHUP (Erlang's `:sighup`) — trapped via `System.trap_signal/3`
       — casts itself a reload message. The handler re-reads the bundle
       from disk. On success, it calls `Active.update/1` to atomically
       swap the canonical entry. On failure, it KEEPS the previous
       reference, emits a structured warning log, and emits a
       `[:recurse, :policy, :reload_failure]` telemetry event.
    3. Optionally (`:poll_ms` > 0, env `R5E_POLICY_BUNDLE_POLL_MS`) polls
       the bundle file's `{mtime, size, inode}` and runs the SAME reload
       path when the signature changes. This is how a sidecar in another
       container (compose `policy-sync`) hands over a new bundle without
       a cross-container SIGHUP: it writes a temp file and `mv`s it over
       `bundle.cedar`; the rename shows up as a new inode on the next
       tick. A file that fails to parse is not retried every tick — its
       signature is remembered, so the next attempt happens when the file
       changes again (or on SIGHUP / `reload/1`).
    4. Records reload status (`active_hash_hex`, `last_reload_at`,
       `last_reload_error`) in its state and exposes it through
       `status/2` so `/readyz` can report the policy line
       (`Recurse.Gateway.Observability.Readyz`).
    5. Exposes `current_bundle/0` — a `:persistent_term.get/1` read path
       (DEPRECATED; new callers should use
       `Recurse.Gateway.Policy.Active.current/0`). Backwards-compat
       wrapper that unwraps the `Active` envelope to return a bare
       `%PolicyBundleRef{}` for the 8 pre-existing callers.

  ## Why a GenServer (Iron Law check — `elixir:otp-thinking`)

  The BundleLoader owns the **write** side of a shared resource
  (the currently-active bundle reference), handles OS signals
  asynchronously, runs a timer, and must survive independently of any
  single caller. That's state + isolation + a periodic task — the
  runtime justifications. Readers are plain function calls through
  `Active.current/0`, which goes straight to `:persistent_term`.

  ## Why `:persistent_term`

  Per the OTP docs, `:persistent_term` reads are constant-time and
  lock-free — faster than ETS for write-rarely/read-often data, and
  faster than a GenServer.call for hot-path reads. Bundle reloads happen
  on operator SIGHUP or a policy push (minutes to hours apart); request
  reads happen at request QPS (hundreds per second). This is exactly the
  shape `:persistent_term` is designed for.

  Note: `:persistent_term` writes trigger a global GC of processes
  referencing the prior term. The poller only writes when the file
  signature changed AND the new bundle parsed, so an idle tick costs one
  `stat(2)` and nothing else.

  ## Polling granularity

  `File.stat/2` exposes mtime at one-second resolution. The signature
  therefore also carries size and inode: an atomic replace (rename)
  always changes the inode, and an in-place rewrite almost always
  changes size or mtime. The one blind spot — an in-place rewrite within
  the same second that keeps the byte count — is caught by the next edit
  or by SIGHUP.

  ## SIGHUP trapping

  `System.trap_signal/3` (Elixir 1.19 + OTP 26+) installs a signal
  handler that runs on the shared signal-trap process. The handler
  body MUST be short because it serializes with every other trap; we
  only do `GenServer.cast/2` and return `:ok`. The GenServer handles
  the actual reload off the signal path.

  ## Telemetry

  Emits three `telemetry:execute/3` events:

    * `[:recurse, :policy, :load]` — boot-time initial load.
    * `[:recurse, :policy, :reload_success]` — reload succeeded;
      `measurements: %{load_ms}`, `metadata: %{canonical_hash_hex, trigger}`.
    * `[:recurse, :policy, :reload_failure]` — reload failed;
      `metadata: %{reason, trigger}`. The previous bundle remains active.

  `trigger` is `:sighup`, `:poll`, or `:manual` (`reload/1`).

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/policy/policy_bundle_ref.ex`
    * `apps/recurse_providers/lib/recurse_providers/impls/filesystem_policy_provider.ex` (T045)
    * `apps/recurse_gateway/lib/recurse_gateway/observability/readyz.ex` (status consumer)
    * `docker-compose/policy-sync.sh` (the writer this poller pairs with)
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T046
    * `specs/012-compose-quickstart/plan.md` §4 D5, §5 S5
  """

  use GenServer

  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.Policy.BundleArchive
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Providers.Impls.FilesystemPolicyProvider

  require Logger

  @signal_trap_id {__MODULE__, :sighup}

  @typedoc """
  Reload status as reported by `status/2`.

    * `:active_hash_hex` — canonical hash (lower-case hex) of the bundle
      this loader last activated. `nil` only if the loader has never
      loaded (it cannot be running in that case; boot is fail-closed).
    * `:last_reload_at` — when the active bundle was (re)loaded; the
      boot load counts.
    * `:last_reload_error` — `nil`, or `%{reason: term(), at: DateTime.t()}`
      for the most recent FAILED reload attempt. Cleared by the next
      successful reload.
    * `:poll_ms` — `0` when polling is off.
    * `:bundle_path` — the file being watched.
  """
  @type status :: %{
          active_hash_hex: String.t() | nil,
          last_reload_at: DateTime.t() | nil,
          last_reload_error: %{reason: term(), at: DateTime.t()} | nil,
          poll_ms: non_neg_integer(),
          bundle_path: Path.t()
        }

  @type trigger :: :sighup | :poll | :manual

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Start the BundleLoader. Required options:

    * `:bundle_path` — path to the Cedar bundle file.
    * `:entity_schema_path` — path to the Cedar entity-schema JSON.

  Optional options:

    * `:trap_sighup` — `true` | `false`, default `true`. Set `false` in
      tests to avoid racing with other signal handlers in the test VM.
    * `:poll_ms` — non-negative integer, default `0` (off). When > 0 the
      loader stats the bundle every `poll_ms` milliseconds and reloads on
      a changed `{mtime, size, inode}` signature (spec 012 S5).
    * `:name` — process name registration, defaults to `__MODULE__`.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Return the active `%PolicyBundleRef{}`.

  DEPRECATED in favor of `Recurse.Gateway.Policy.Active.current/0`.
  This wrapper exists so the 8 pre-canonical-Active callers don't all
  break in one MR; new callers MUST use `Active.current/0` and accept
  the `%Active{}` envelope so they can also see provenance
  (loader source, source ref, loaded_at).

  Reads through `Active.current/0` and unwraps the inner
  `%PolicyBundleRef{}`. Returns `{:error, :not_loaded}` if no loader
  has populated the canonical entry yet — the OCI-policy-provider
  deploy now writes through `Active`, so this function returns the
  active bundle regardless of which loader produced it.
  """
  @deprecated "Use Recurse.Gateway.Policy.Active.current/0 instead."
  @spec current_bundle() :: {:ok, PolicyBundleRef.t()} | {:error, :not_loaded}
  def current_bundle do
    case Active.current() do
      {:ok, %Active{bundle: %PolicyBundleRef{} = ref}} -> {:ok, ref}
      {:error, :not_loaded} -> {:error, :not_loaded}
    end
  end

  @doc """
  Trigger a bundle reload. Returns `:ok` immediately; the caller is NOT
  notified of reload success/failure — subscribe to telemetry events
  `[:recurse, :policy, :reload_success]` /
  `[:recurse, :policy, :reload_failure]`, or read `status/2` afterwards.
  """
  @spec reload(GenServer.server()) :: :ok
  def reload(server \\ __MODULE__) do
    GenServer.cast(server, {:reload, :manual})
  end

  @doc """
  Reload status (see `t:status/0`). Bounded by `timeout` (default 250 ms)
  so a health probe cannot block on a busy loader. Returns
  `{:error, :not_running}` when no loader is registered under `server`
  (e.g. the OCI loader owns the bundle) and `{:error, :timeout}` if the
  call did not complete in time.
  """
  @spec status(GenServer.server(), timeout()) ::
          {:ok, status()} | {:error, :not_running | :timeout}
  def status(server \\ __MODULE__, timeout \\ 250) do
    {:ok, GenServer.call(server, :status, timeout)}
  catch
    :exit, {:noproc, _} -> {:error, :not_running}
    :exit, {:timeout, _} -> {:error, :timeout}
    :exit, {reason, _} when reason in [:normal, :shutdown] -> {:error, :not_running}
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    bundle_path = Keyword.fetch!(opts, :bundle_path)
    entity_schema_path = Keyword.fetch!(opts, :entity_schema_path)
    trap_sighup? = Keyword.get(opts, :trap_sighup, true)
    poll_ms = opts |> Keyword.get(:poll_ms, 0) |> normalize_poll_ms()

    provider_config = %{
      bundle_path: bundle_path,
      entity_schema_path: entity_schema_path,
      reload_on_sighup: trap_sighup?
    }

    case load_into_persistent_term(provider_config, :load, nil) do
      {:ok, provider_state, ref} ->
        if trap_sighup? do
          install_sighup_trap()
        end

        state = %{
          provider_config: provider_config,
          provider_state: provider_state,
          poll_ms: poll_ms,
          file_sig: stat_signature(bundle_path),
          active_hash_hex: ref.bundle_id,
          last_reload_at: ref.loaded_at,
          last_reload_error: nil
        }

        if poll_ms > 0 do
          Logger.info(
            "policy bundle polling enabled: #{bundle_path} every #{poll_ms}ms (R5E_POLICY_BUNDLE_POLL_MS)"
          )
        end

        {:ok, schedule_poll(state)}

      {:error, reason} ->
        # Boot-time bundle load is fail-closed: if the operator can't
        # ship a valid bundle, the Gateway MUST NOT come up. Constitution
        # Principle III (Fail-Closed on Policy).
        {:stop, {:policy_bundle_load_failure, reason}}
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    reply = %{
      active_hash_hex: state.active_hash_hex,
      last_reload_at: state.last_reload_at,
      last_reload_error: state.last_reload_error,
      poll_ms: state.poll_ms,
      bundle_path: state.provider_config.bundle_path
    }

    {:reply, reply, state}
  end

  @impl true
  def handle_cast(:reload, state), do: handle_cast({:reload, :manual}, state)

  def handle_cast({:reload, trigger}, state) do
    # Re-stat after an explicit reload so the poller does not immediately
    # re-run the same reload for a change the operator just asked for.
    state =
      state
      |> do_reload(trigger)
      |> Map.put(:file_sig, stat_signature(state.provider_config.bundle_path))

    {:noreply, state}
  end

  @impl true
  def handle_info(:poll, %{poll_ms: poll_ms} = state) when poll_ms > 0 do
    path = state.provider_config.bundle_path

    state =
      case stat_signature(path) do
        nil ->
          # Missing or unreadable mid-swap (a rename in flight, a volume
          # being re-mounted). Keep the active bundle and the previous
          # signature so the next tick sees the new file as a change.
          state

        sig when sig == state.file_sig ->
          state

        sig ->
          state
          |> do_reload(:poll)
          |> Map.put(:file_sig, sig)
      end

    {:noreply, schedule_poll(state)}
  end

  def handle_info(:poll, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, _state) do
    # Best-effort remove the signal trap so repeated test restarts don't
    # accumulate registrations. Ignore errors — the VM tears these down
    # on shutdown anyway.
    _ = System.untrap_signal(:sighup, @signal_trap_id)
    :ok
  end

  # ---------------------------------------------------------------------------
  # Internal helpers
  # ---------------------------------------------------------------------------

  defp normalize_poll_ms(ms) when is_integer(ms) and ms >= 0, do: ms
  defp normalize_poll_ms(nil), do: 0

  defp normalize_poll_ms(other) do
    raise ArgumentError,
          "BundleLoader :poll_ms must be a non-negative integer (got #{inspect(other)})"
  end

  defp schedule_poll(%{poll_ms: poll_ms} = state) when poll_ms > 0 do
    Process.send_after(self(), :poll, poll_ms)
    state
  end

  defp schedule_poll(state), do: state

  # `{mtime, size, inode}` or nil when the file cannot be stat'ed.
  defp stat_signature(path) do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{mtime: mtime, size: size, inode: inode}} -> {mtime, size, inode}
      {:error, _} -> nil
    end
  end

  defp do_reload(%{provider_config: provider_config} = state, trigger) do
    case load_into_persistent_term(provider_config, :reload, trigger) do
      {:ok, provider_state, ref} ->
        %{
          state
          | provider_state: provider_state,
            active_hash_hex: ref.bundle_id,
            last_reload_at: ref.loaded_at,
            last_reload_error: nil
        }

      {:error, reason} ->
        Logger.warning(fn ->
          "policy bundle reload (#{trigger}) failed; keeping previous bundle " <>
            "#{state.active_hash_hex} active. reason=#{inspect(reason)}"
        end)

        :telemetry.execute(
          [:recurse, :policy, :reload_failure],
          %{count: 1},
          %{reason: reason, trigger: trigger}
        )

        %{state | last_reload_error: %{reason: reason, at: DateTime.utc_now()}}
    end
  end

  defp install_sighup_trap do
    :sighup
    |> System.trap_signal(@signal_trap_id, &sighup_trap_handler/0)
    |> handle_trap_result()
  end

  defp sighup_trap_handler do
    # Keep the trap body minimal — cast + return :ok so subsequent
    # traps in the chain can run. Name lookup tolerates the GenServer
    # being mid-restart.
    if Process.whereis(__MODULE__) do
      GenServer.cast(__MODULE__, {:reload, :sighup})
    end

    :ok
  end

  defp handle_trap_result({:ok, _id}), do: :ok
  # Idempotent on repeated boots — the prior trap survives VM-internal
  # restarts of this GenServer.
  defp handle_trap_result({:error, :already_registered}), do: :ok

  defp handle_trap_result({:error, :not_sup}) do
    Logger.info(
      "SIGHUP trapping not supported by the OS; filesystem policy provider will only load at boot"
    )

    :ok
  end

  defp load_into_persistent_term(provider_config, kind, trigger) do
    started_mono = System.monotonic_time()

    with {:ok, provider_state} <- FilesystemPolicyProvider.init(provider_config),
         {:ok, fetched} <- FilesystemPolicyProvider.fetch_active_bundle(provider_state) do
      ref = %PolicyBundleRef{
        bundle_id: Base.encode16(fetched.canonical_hash, case: :lower),
        canonical_hash: fetched.canonical_hash,
        loaded_at: fetched.loaded_at,
        evaluator_handle: fetched.bytes,
        bundle_bytes: fetched.bytes
      }

      active_envelope = %Active{
        source: :filesystem,
        source_ref: Map.get(provider_config, :bundle_path),
        loaded_at: fetched.loaded_at,
        metadata: %{
          file_path: Map.get(provider_config, :bundle_path),
          entity_schema_path: Map.get(provider_config, :entity_schema_path)
        },
        bundle: ref
      }

      with :ok <- Active.update(active_envelope) do
        # Archive only the admitted activation. Failure preserves the prior policy.
        _ = BundleArchive.archive(active_envelope)

        load_ms =
          System.convert_time_unit(System.monotonic_time() - started_mono, :native, :millisecond)

        emit_load_telemetry(kind, ref, load_ms, trigger)
        {:ok, provider_state, ref}
      end
    end
  end

  defp emit_load_telemetry(:load, ref, load_ms, _trigger) do
    :telemetry.execute(
      [:recurse, :policy, :load],
      %{load_ms: load_ms},
      %{canonical_hash_hex: ref.bundle_id}
    )
  end

  defp emit_load_telemetry(:reload, ref, load_ms, trigger) do
    Logger.info("policy bundle reloaded (#{trigger}): active canonical_hash=#{ref.bundle_id}")

    :telemetry.execute(
      [:recurse, :policy, :reload_success],
      %{load_ms: load_ms},
      %{canonical_hash_hex: ref.bundle_id, trigger: trigger}
    )
  end
end
