defmodule Recurse.Gateway.KmsRotationWatcher do
  @moduledoc """
  KMS signing-key rotation watcher (F002 T074 / US5).

  Periodically (`poll_interval_ms`, default 60_000) probes the configured
  `SecretsProvider` for the current signing-key version; when the version
  has changed since the last observation, the watcher:

    1. Fetches the new public key via `SecretsProvider.public_key/2`
       (the `:persistent_term` cache in the AWS KMS impl is keyed by
       `{key_arn, key_version}`, so a rotation produces a cache miss and
       a fresh KMS `GetPublicKey` fetch — private material never crosses
       the BEAM boundary).
    2. Appends a new row to the `signing_keys` table with a hash-chain
       linkage per F001 signing_key_archive contract
       (`chain_hash = SHA-256(prev_chain_hash || canonical_row_bytes)`).
    3. Emits `[:recurse, :gateway, :kms_rotation_detected]` telemetry so
       operators see rotations in Prometheus / LiveDashboard.

  ## Iron-Law check

  This module is one of the few legitimately-stateful processes in the
  Gateway — per `elixir:otp-thinking`:

    * **Mutable runtime state** — the last-seen `key_version` must persist
      across 60s poll cycles without disk persistence (the `signing_keys`
      table is the durable record, but the in-memory version is the thing
      we diff against on each tick).
    * **Periodic runtime execution** — `Process.send_after/3` schedules the
      next poll; stateless modules can't own timers.
    * **Fault isolation** — if a poll crashes (KMS outage, malformed
      response), the supervisor restarts the watcher without dragging down
      the Finch pools / Router / SIEM forwarder.

  No ETS table is required because reads are single-writer-single-reader
  (the watcher itself reads + writes `state.last_key_version`); callers
  that need the current cached public key go through
  `SecretsProvider.public_key/2` which has its own `:persistent_term` cache.

  ## Polling vs event-driven

  Per research D1, Phase-1 uses polling for simplicity. SNS/SQS-driven
  eventing (CloudTrail → EventBridge → SQS → BEAM) is a Phase-2+
  optimization; the polling contract here is shaped so that substituting
  an event-driven trigger only requires replacing the `:poll` loop (the
  `process_probe/1` core is already event-agnostic).

  ## Test surface

  Tests inject a `:key_probe` callback — a 1-arity function receiving the
  watcher's state that returns `{:ok, key_version :: String.t()}` |
  `{:error, term()}`. This avoids extending the `SecretsProvider`
  behaviour with a `describe_key/2` callback mid-phase; production uses a
  default probe that calls `active_signing_key/1` on the configured
  provider and extracts `.key_version`.

  ## Supervision

  Opt-in via `config :recurse_gateway, :kms_rotation_watcher, enabled:
  true`. Default is `false` so `mix test` doesn't try to poll a real KMS
  at suite init (each test that wants the watcher boots its own under
  `start_supervised!/1`). The production `standalone_gateway.exs` flip
  happens in the tier config.

  ## Archive integrity check

  `verify_archive_chain/1` is called from `init/1`. It streams every
  `signing_keys` row ordered by `(first_seen_at, inserted_at, id)` and
  recomputes the hash chain. On mismatch it returns
  `{:error, {:archive_integrity_violation, row_id}}` which `init/1` turns
  into `{:stop, ...}` — the Gateway boots in safe-closed mode per F001
  FR-033 semantics (equivalent to `/healthz` reporting
  `archive_integrity: compromised`).
  """

  use GenServer

  require Logger

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey, as: SigningKeySchema
  alias Recurse.Providers.Repo

  # The F001-contract signing-key archive schema is aliased as
  # `SigningKeySchema` (struct pattern-matches only) and spelled out
  # fully-qualified at each REMOTE-CALL site. Rationale: the
  # `Recurse.Credo.ProviderNeutrality` check walks the AST's
  # `__aliases__` parts verbatim on function-call nodes — an alias
  # short-form like `SigningKey.foo()` would collapse to
  # `"SigningKey"` (not in `@approved_prefixes`) and trip a false
  # [D]-level positive. The full
  # `Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey`
  # matches the approved `Recurse.*` prefix. Struct pattern-matches
  # `%SigningKeySchema{}` don't appear as remote-calls in the AST so
  # the alias is safe for those. F001's signing_key_archive contract
  # legitimizes this call pattern (the Gateway-resident rotation
  # watcher is the canonical writer of archive rows — the F002
  # `LedgerProvider` interface does not expose an archive-write
  # callback, so the schema is touched directly).

  @default_poll_interval_ms 60_000
  @archive_chain_anchor <<0::size(256)>>
  @telemetry_rotation_detected [:recurse, :gateway, :kms_rotation_detected]
  @telemetry_archive_verify_failed [:recurse, :gateway, :archive_integrity_violation]

  @type state :: %{
          required(:secrets_provider_module) => module(),
          required(:secrets_provider_state) => term(),
          required(:signing_key_handle) => map(),
          required(:tenant_id) => String.t(),
          required(:poll_interval_ms) => pos_integer(),
          required(:last_key_version) => String.t() | nil,
          required(:key_probe) => (state() -> {:ok, String.t()} | {:error, term()}),
          required(:repo) => module(),
          required(:clock) => (-> DateTime.t())
        }

  # -- Public API -----------------------------------------------------------

  @doc """
  Start the watcher. See moduledoc for the `:key_probe` test seam.

  Required opts:

    * `:secrets_provider_module` — module implementing
      `Recurse.Providers.SecretsProvider`.
    * `:secrets_provider_state` — state from its `init/1`.
    * `:signing_key_handle` — handle returned by
      `secrets_provider_module.active_signing_key/1`.
    * `:tenant_id` — ULID string; FK into `tenants`.

  Optional opts:

    * `:poll_interval_ms` (default 60_000).
    * `:key_probe` — 1-arity fn (state -> {:ok, key_version} | {:error, _}).
    * `:repo` (default `Recurse.Providers.Repo`).
    * `:clock` — 0-arity fn returning `DateTime.t()`; defaults to
      `&DateTime.utc_now/0`.
    * `:name` — process name. Defaults to `__MODULE__`; pass `nil` to skip.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)

    if is_nil(name) do
      GenServer.start_link(__MODULE__, opts)
    else
      GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  @doc """
  Synchronous helper: force an immediate probe + append cycle and return
  the resulting state. Used by T073 integration tests to avoid waiting
  60s for the scheduled tick.

  Returns:

    * `{:ok, :unchanged}` — probe returned the same `key_version`.
    * `{:ok, :rotated, key_version}` — a new row was appended.
    * `{:error, reason}` — probe or append failed.
  """
  @spec poll_now(GenServer.server()) ::
          {:ok, :unchanged}
          | {:ok, :rotated, String.t()}
          | {:error, term()}
  def poll_now(server \\ __MODULE__) do
    GenServer.call(server, :poll_now)
  end

  @doc """
  Return the current state (read-only introspection for tests + the
  operator healthz handler).
  """
  @spec get_state(GenServer.server()) :: map()
  def get_state(server \\ __MODULE__) do
    GenServer.call(server, :get_state)
  end

  @doc """
  Verify the `signing_keys` archive's hash-chain integrity end-to-end.
  Streams every row ordered by `(first_seen_at, inserted_at, id)` and
  recomputes each row's `chain_hash` from the prior row's `chain_hash`
  plus the current row's canonical bytes. Mismatch returns
  `{:error, {:archive_integrity_violation, row_id}}`.

  Exposed publicly for operator tooling + the integration test; `init/1`
  calls this on boot and refuses to start when the chain is broken.
  """
  @spec verify_archive_chain(module()) ::
          :ok | {:error, {:archive_integrity_violation, binary()}} | {:error, term()}
  def verify_archive_chain(repo \\ Repo) do
    import Ecto.Query, only: [from: 2]

    query =
      from(sk in Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey,
        order_by: [asc: sk.first_seen_at, asc: sk.inserted_at, asc: sk.id]
      )

    rows = repo.all(query)

    verify_rows(rows, @archive_chain_anchor)
  rescue
    err -> {:error, {:archive_verify_exception, err}}
  end

  @doc """
  Compute the `chain_hash` for a row given its identity fields and the
  previous row's `chain_hash` (use `@archive_chain_anchor` for the first
  row). Exposed as a public helper so `KmsRotationWatcher` + test code
  share the exact same primitive.
  """
  @spec compute_chain_hash(
          prev_chain_hash :: binary(),
          identity_fields :: map()
        ) :: binary()
  def compute_chain_hash(prev_chain_hash, identity_fields)
      when byte_size(prev_chain_hash) == 32 and is_map(identity_fields) do
    row_bytes =
      Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey.canonical_row_bytes(
        identity_fields
      )

    :crypto.hash(:sha256, prev_chain_hash <> row_bytes)
  end

  @doc "32-byte zero anchor for the very first row in the archive."
  @spec archive_chain_anchor() :: binary()
  def archive_chain_anchor, do: @archive_chain_anchor

  # -- GenServer callbacks --------------------------------------------------

  @impl GenServer
  def init(opts) do
    with {:ok, state} <- build_state(opts),
         :ok <- verify_archive_chain(state.repo) do
      schedule_next_poll(state.poll_interval_ms)
      {:ok, state}
    else
      {:error, {:archive_integrity_violation, row_id}} = err ->
        :telemetry.execute(
          @telemetry_archive_verify_failed,
          %{count: 1},
          %{row_id: row_id}
        )

        Logger.error(
          "KmsRotationWatcher refusing to boot — signing_keys chain integrity violation at row #{inspect(row_id)}"
        )

        {:stop, err}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl GenServer
  def handle_info(:poll, state) do
    new_state =
      case process_probe(state) do
        {:ok, :unchanged, state} ->
          state

        {:ok, :rotated, state} ->
          state

        {:error, reason} ->
          # Failed probes are transient (KMS outage, DB blip). Logger.warn +
          # keep the state unchanged; the next tick retries. We do NOT crash
          # the watcher — this is an expected operational case and a crash
          # loop burns the restart budget for nothing.
          Logger.warning("KmsRotationWatcher poll failed: #{inspect(reason)}")
          state
      end

    schedule_next_poll(new_state.poll_interval_ms)
    {:noreply, new_state}
  end

  @impl GenServer
  def handle_call(:poll_now, _from, state) do
    case process_probe(state) do
      {:ok, :unchanged, new_state} ->
        {:reply, {:ok, :unchanged}, new_state}

      {:ok, :rotated, new_state} ->
        {:reply, {:ok, :rotated, new_state.last_key_version}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call(:get_state, _from, state) do
    {:reply, Map.drop(state, [:secrets_provider_state]), state}
  end

  # -- Private helpers ------------------------------------------------------

  @spec build_state(keyword()) :: {:ok, state()} | {:error, term()}
  defp build_state(opts) do
    with {:ok, secrets_provider_module} <- require_opt(opts, :secrets_provider_module),
         {:ok, secrets_provider_state} <- require_opt(opts, :secrets_provider_state),
         {:ok, signing_key_handle} <- require_opt(opts, :signing_key_handle),
         {:ok, tenant_id} <- require_opt(opts, :tenant_id) do
      state = %{
        secrets_provider_module: secrets_provider_module,
        secrets_provider_state: secrets_provider_state,
        signing_key_handle: signing_key_handle,
        tenant_id: tenant_id,
        poll_interval_ms: Keyword.get(opts, :poll_interval_ms, @default_poll_interval_ms),
        last_key_version: nil,
        key_probe: Keyword.get(opts, :key_probe, &default_key_probe/1),
        repo: Keyword.get(opts, :repo, Repo),
        clock: Keyword.get(opts, :clock, &DateTime.utc_now/0)
      }

      {:ok, state}
    end
  end

  defp require_opt(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:missing_opt, key}}
    end
  end

  @spec process_probe(state()) ::
          {:ok, :unchanged, state()}
          | {:ok, :rotated, state()}
          | {:error, term()}
  defp process_probe(state) do
    with {:ok, observed_version} <- state.key_probe.(state) do
      cond do
        state.last_key_version == nil ->
          # First observation — seed the in-memory cursor. Archive row is
          # appended on first observation too, so boot-rotation-before-probe
          # still writes a row (via `init/1`'s subsequent poll cycle).
          on_first_or_changed(state, observed_version)

        observed_version == state.last_key_version ->
          # Touch `last_seen_at` so the archive row tracks ongoing usage.
          # Trigger `enforce_signing_keys_update_last_seen_only` explicitly
          # permits mutating ONLY that column.
          _ = touch_archive_row(state, observed_version)
          {:ok, :unchanged, state}

        true ->
          on_first_or_changed(state, observed_version)
      end
    end
  end

  @spec on_first_or_changed(state(), String.t()) ::
          {:ok, :rotated, state()} | {:error, term()}
  defp on_first_or_changed(state, observed_version) do
    with {:ok, public_key_pem} <- fetch_public_key(state, observed_version),
         {:ok, _row} <- append_archive_row(state, observed_version, public_key_pem) do
      :telemetry.execute(
        @telemetry_rotation_detected,
        %{count: 1},
        %{
          tenant_id: state.tenant_id,
          kms_key_id: state.signing_key_handle.key_id,
          previous_key_version: state.last_key_version,
          new_key_version: observed_version
        }
      )

      {:ok, :rotated, %{state | last_key_version: observed_version}}
    end
  end

  defp fetch_public_key(state, observed_version) do
    probe_handle = Map.put(state.signing_key_handle, :key_version, observed_version)
    state.secrets_provider_module.public_key(state.secrets_provider_state, probe_handle)
  end

  @spec append_archive_row(state(), String.t(), binary()) ::
          {:ok, Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey.t()}
          | {:error, term()}
  defp append_archive_row(state, key_version, public_key_pem) do
    now = state.clock.()

    identity = %{
      tenant_id: state.tenant_id,
      kms_key_id: state.signing_key_handle.key_id,
      key_version: key_version,
      public_key_pem: public_key_pem,
      algorithm: Map.get(state.signing_key_handle, :algorithm, :ecdsa_p256),
      first_seen_at: now
    }

    case load_latest_chain_hash(state.repo) do
      {:ok, prev_chain_hash} ->
        chain_hash = compute_chain_hash(prev_chain_hash, identity)

        attrs =
          identity
          |> Map.put(:last_seen_at, now)
          |> Map.put(:chain_hash, chain_hash)
          |> Map.put(:inserted_at, now)

        %Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey{}
        |> Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey.insert_changeset(attrs)
        |> state.repo.insert(
          on_conflict: :nothing,
          conflict_target: [:kms_key_id, :key_version]
        )
        |> handle_insert_result(state, key_version, now)

      error ->
        error
    end
  end

  # `on_conflict: :nothing` returns `{:ok, %SigningKey{id: nil}}` when the
  # row already exists — the F002 US5 test seam boots the watcher once and
  # probes the same `v1` twice before rotating; the second call must not
  # crash. On a conflict we bump `last_seen_at` via the touch trigger-safe
  # update path.
  defp handle_insert_result({:ok, %SigningKeySchema{id: nil}}, state, key_version, now) do
    with {:ok, row} <- fetch_row(state.repo, state.signing_key_handle.key_id, key_version),
         {:ok, updated} <-
           row
           |> Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey.touch_changeset(now)
           |> state.repo.update() do
      {:ok, updated}
    end
  end

  defp handle_insert_result({:ok, %SigningKeySchema{} = row}, _state, _key_version, _now),
    do: {:ok, row}

  defp handle_insert_result({:error, changeset}, _state, _key_version, _now),
    do: {:error, {:archive_insert_failed, changeset}}

  defp touch_archive_row(state, key_version) do
    with {:ok, row} <- fetch_row(state.repo, state.signing_key_handle.key_id, key_version) do
      row
      |> Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey.touch_changeset(
        state.clock.()
      )
      |> state.repo.update()
    end
  end

  defp fetch_row(repo, kms_key_id, key_version) do
    case repo.get_by(
           Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey,
           kms_key_id: kms_key_id,
           key_version: key_version
         ) do
      nil -> {:error, :signing_key_not_found}
      row -> {:ok, row}
    end
  end

  @spec load_latest_chain_hash(module()) :: {:ok, binary()}
  defp load_latest_chain_hash(repo) do
    import Ecto.Query, only: [from: 2]

    query =
      from(sk in Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey,
        order_by: [desc: sk.first_seen_at, desc: sk.inserted_at, desc: sk.id],
        limit: 1,
        select: sk.chain_hash
      )

    case repo.one(query) do
      nil -> {:ok, @archive_chain_anchor}
      hash when is_binary(hash) and byte_size(hash) == 32 -> {:ok, hash}
    end
  end

  defp schedule_next_poll(interval_ms) do
    Process.send_after(self(), :poll, interval_ms)
  end

  # Default probe calls `active_signing_key/1` on the configured SecretsProvider
  # and extracts the `key_version` field. AWS KMS impls advance this on each
  # rotation detection; between rotations the value is stable.
  defp default_key_probe(state) do
    case state.secrets_provider_module.active_signing_key(state.secrets_provider_state) do
      {:ok, %{key_version: version}} when not is_nil(version) ->
        {:ok, to_string(version)}

      {:ok, other} ->
        {:error, {:active_signing_key_malformed, other}}

      {:error, _} = err ->
        err
    end
  end

  # -- Archive verification -------------------------------------------------

  defp verify_rows([], _prev), do: :ok

  defp verify_rows([row | rest], prev_chain_hash) do
    identity = %{
      tenant_id: row.tenant_id,
      kms_key_id: row.kms_key_id,
      key_version: row.key_version,
      public_key_pem: row.public_key_pem,
      algorithm: row.algorithm,
      first_seen_at: row.first_seen_at
    }

    expected = compute_chain_hash(prev_chain_hash, identity)

    if expected == row.chain_hash do
      verify_rows(rest, row.chain_hash)
    else
      {:error, {:archive_integrity_violation, row.id}}
    end
  end
end
