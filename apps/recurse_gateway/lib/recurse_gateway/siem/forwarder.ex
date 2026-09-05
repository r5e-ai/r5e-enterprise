defmodule Recurse.Gateway.Siem.Forwarder do
  @moduledoc """
  SIEM Log Forwarder — NDJSON-to-stdout emitter (F002 T053, FR-024/FR-025).

  ## Responsibility

  Subscribe to the `recurse:attestation_first_committed` Phoenix.PubSub
  topic and emit exactly one NDJSON line per attestation, per FR-024:

      > Cardinality is one SIEM event per attestation, full stop.
      > Subsequent outer-container state advances (global inclusion,
      > commit_retry, commit_retry_exhausted) do NOT re-fire SIEM events.

  The `Recurse.Providers.Impls.PostgresMerkleLedger.commit_attestation/2`
  impl broadcasts the topic exactly once, after the SERIALIZABLE commit
  transaction succeeds; if the transaction rolls back nothing is
  broadcast. This Forwarder trusts that cardinality property and does
  not deduplicate itself.

  ## Iron Law check (otp-thinking)

  A GenServer is justified. All three criteria met:

    1. **Mutable state persisting across calls**: emitted-count +
       emit-errors-count accumulate across PubSub messages (operator
       sanity-check in `:sys.get_state/1`; Prometheus metrics are
       exported via `:telemetry`).
    2. **Fault isolation**: a malformed attestation or IO failure must
       not drag the Data Plane down. Let it crash; the supervisor
       restarts the subscriber with a clean slate.
    3. **Serialized access**: stdout writes MUST interleave cleanly
       with the IO driver — batching N concurrent emitters on the
       same `IO.puts/2` would require a mutex anyway. The GenServer
       IS that mutex.

  ## Delivery boundary (FR-026)

  This Forwarder writes to stdout via `IO.puts/2` and STOPS. The
  reliable-delivery concern — bounded retry, on-disk spool, HEC / HTTP
  push, per-SIEM field flattening — is a **deployment-time concern
  handled by the Vector sidecar** per FR-026. The reference
  `docker-compose.yaml` ships Vector tailing the Gateway container's
  stdout. Do NOT add buffering, batching, or HTTP push here.

  ## Schema (FR-025 — shape-equivalent, jointly versioned)

  Each NDJSON line is a flat JSON object mirroring F001 FR-048 surface-1:

      {
        "run_id":                    "<ulid>",
        "session_id":                "<ulid>",
        "turn_id":                   "<ulid>" | null,
        "principal":                 { kind, issuer?, subject?, ... },
        "machine_identity":          { kind, spiffe_id? |
                                       observed_jwt_subject + issuer },
        "tool_called":               null,
        "policy_decision":           "allow" | "deny",
        "policy_canonical_hash":     "sha256:<hex>",
        "verification_level":        "local_inclusion_verified" | ...,
        "tier_completeness_advisory":"partial",
        "outcome":                   "success" | "upstream_error" | "cancelled",
        "upstream_status_code":      <int> | null,
        "correlation_id":            "<ulid>",
        "timestamp":                 "<ISO-8601 UTC>"
      }

  `outcome` + `upstream_status_code` make US6's distinguishability
  contract concrete: an upstream 503 has `policy_decision: "allow"` +
  `outcome: "upstream_error"` + `upstream_status_code: 503`, while a
  policy denial has `policy_decision: "deny"` + `outcome: "success"`
  (the request completed, it just produced a denial receipt).

  `tool_called` is always `null` in the Standalone slice (no tool-call
  surfaces land until F003+). `tier_completeness_advisory` is always
  `"partial"` for Standalone per FR-038 axis 2.

  Shape-equivalence with the signed receipt is the FR-025 invariant —
  breaking changes to either side require a Recurse schema-version bump
  and coordinated updates. The property test at
  `test/siem/forwarder_property_test.exs` asserts schema conformance.

  ## Telemetry

    * `[:recurse, :siem, :event_emitted]` — measurement `%{count: 1}`,
      metadata `%{run_id, verification_level}`. Feeds FR-029's implicit
      throughput counter.
    * `[:recurse, :siem, :emit_error]` — measurement `%{count: 1}`,
      metadata `%{reason}`. Feeds FR-029's
      `recurse_siem_forwarder_emit_errors_total` counter.

  ## Boot options

    * `:io_device` — where to write NDJSON lines. Defaults to `:stdio`
      for production (Vector tails the container's stdout). Tests pass
      a `StringIO`-backed device to capture output without racing the
      ExUnit harness's stdout.
    * `:pubsub` — PubSub name to subscribe on. Defaults to
      `Recurse.PubSub` (started by `:recurse_providers`).
    * `:name` — process registration name. Defaults to the module.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-024,
      FR-025, FR-026.
    * `specs/001-api-jido-foundations/contracts/siem_log_forwarder.md`
      — F001 canonical schema + GRC alert recipes.
    * `apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger.ex`
      `broadcast_first_committed/3` — the single upstream publisher.
  """

  use GenServer

  require Logger

  @topic "recurse:attestation_first_committed"

  @type option ::
          {:io_device, :stdio | pid() | atom()}
          | {:pubsub, atom()}
          | {:name, GenServer.name()}

  @doc """
  Start and link the SIEM forwarder GenServer.

  Passing `name: nil` starts an unregistered process (caller must hold
  the pid). The test suite uses this to start per-test forwarders with
  isolated `StringIO` devices without creating atoms at runtime.
  """
  @spec start_link([option()]) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, init_opts} = Keyword.pop(opts, :name, __MODULE__)

    case name do
      nil -> GenServer.start_link(__MODULE__, init_opts)
      name -> GenServer.start_link(__MODULE__, init_opts, name: name)
    end
  end

  @impl true
  def init(opts) do
    pubsub = Keyword.get(opts, :pubsub, Recurse.PubSub)
    io_device = Keyword.get(opts, :io_device, :stdio)

    :ok = Phoenix.PubSub.subscribe(pubsub, @topic)

    {:ok,
     %{
       io_device: io_device,
       pubsub: pubsub,
       emitted_count: 0,
       emit_errors_count: 0
     }}
  end

  @impl true
  def handle_info({:first_committed, _run_id, payload}, state) do
    case build_ndjson_event(payload) do
      {:ok, ndjson_line, meta} ->
        IO.puts(state.io_device, ndjson_line)
        :telemetry.execute([:recurse, :siem, :event_emitted], %{count: 1}, meta)
        {:noreply, %{state | emitted_count: state.emitted_count + 1}}

      {:error, reason} ->
        Logger.error("SIEM forwarder skipping malformed attestation: #{inspect(reason)}")

        :telemetry.execute([:recurse, :siem, :emit_error], %{count: 1}, %{
          reason: reason
        })

        {:noreply, %{state | emit_errors_count: state.emit_errors_count + 1}}
    end
  end

  # Ignore non-subscription messages rather than crashing — defensive
  # against accidental `send/2` by sibling processes. The subscribed
  # topic is narrow; anything else is noise.
  def handle_info(_other, state), do: {:noreply, state}

  # -- Building the NDJSON event --------------------------------------------

  # The ledger broadcast payload is:
  #
  #   %{
  #     run_id:                  <ulid>,
  #     verification_level:      :local_inclusion_verified | ...,
  #     session_chain_root:      <bytes>,
  #     global_inclusion_proof:  <bytes>,
  #     attestation:             <Map.from_struct of Ecto Attestation row>
  #   }
  #
  # The `:attestation` map carries the signed-predicate + outer-container
  # columns we project into the FR-025 schema.
  @spec build_ndjson_event(map()) :: {:ok, String.t(), map()} | {:error, term()}
  defp build_ndjson_event(payload) do
    with {:ok, att} <- fetch_attestation(payload),
         {:ok, run_id} <- fetch(att, :run_id),
         {:ok, session_id} <- fetch(att, :session_id),
         {:ok, principal} <- fetch(att, :principal),
         {:ok, machine_identity} <- fetch(att, :machine_identity),
         {:ok, policy_decision} <- fetch(att, :policy_decision),
         {:ok, policy_canonical_hash} <- fetch(att, :policy_canonical_hash),
         {:ok, verification_level} <- fetch(att, :verification_level),
         {:ok, tier_completeness_advisory} <-
           fetch(att, :tier_completeness_advisory),
         {:ok, outcome} <- fetch(att, :outcome),
         {:ok, correlation_id} <- fetch(att, :correlation_id),
         {:ok, timestamp} <- fetch(att, :timestamp) do
      upstream_status_code =
        Map.get(att, :upstream_status_code, Map.get(att, "upstream_status_code"))

      event = %{
        "run_id" => run_id,
        "session_id" => session_id,
        "turn_id" => Map.get(att, :turn_id),
        "principal" => principal_to_wire(principal),
        "machine_identity" => machine_identity_to_wire(machine_identity),
        "tool_called" => nil,
        "policy_decision" => atom_or_string(policy_decision),
        "policy_canonical_hash" => hash_to_wire(policy_canonical_hash),
        "verification_level" => atom_or_string(verification_level),
        "tier_completeness_advisory" => atom_or_string(tier_completeness_advisory),
        "outcome" => atom_or_string(outcome),
        "upstream_status_code" => upstream_status_code,
        "correlation_id" => correlation_id,
        "timestamp" => timestamp_to_wire(timestamp)
      }

      meta = %{run_id: run_id, verification_level: verification_level}
      {:ok, JSON.encode!(event), meta}
    end
  rescue
    # JSON.encode! raises on non-encodable shapes (e.g. a stray pid,
    # reference, or binary that's not valid UTF-8). Surface as
    # structured error rather than crashing the subscriber.
    e in [Protocol.UndefinedError, ArgumentError] ->
      {:error, {:json_encode_failed, Exception.message(e)}}
  end

  # Principal is stored as JSONB (string keys). Normalize for wire:
  # drop nils, keep only keys the FR-025 schema declares, coerce atom
  # values to strings.
  defp principal_to_wire(%{} = principal) do
    principal
    |> normalize_map()
    |> Map.take([
      "kind",
      "schema_version",
      "issuer",
      "subject",
      "display_name",
      "groups",
      "account_id",
      "scope",
      "spiffe_id",
      "recurse_role"
    ])
    |> Map.reject(fn {_, v} -> is_nil(v) end)
    |> Map.new(fn {k, v} -> {k, atom_or_string(v)} end)
  end

  defp machine_identity_to_wire(%{} = mi) do
    mi
    |> normalize_map()
    |> Map.take(["kind", "spiffe_id", "observed_jwt_subject", "issuer"])
    |> Map.reject(fn {_, v} -> is_nil(v) end)
    |> Map.new(fn {k, v} -> {k, atom_or_string(v)} end)
  end

  # Accept both atom-keyed and string-keyed maps; emit string-keyed.
  defp normalize_map(%{} = m) do
    Map.new(m, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  # `policy_canonical_hash` is stored as raw bytes in the Ecto row.
  # Render as `"sha256:<hex>"` per F001 SignedPredicate `to_map` convention.
  defp hash_to_wire(bin) when is_binary(bin) do
    case String.valid?(bin) and String.starts_with?(bin, "sha256:") do
      true -> bin
      false -> "sha256:" <> Base.encode16(bin, case: :lower)
    end
  end

  defp hash_to_wire(nil), do: nil

  defp timestamp_to_wire(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp timestamp_to_wire(bin) when is_binary(bin), do: bin
  defp timestamp_to_wire(nil), do: nil

  defp atom_or_string(v) when is_atom(v) and not is_nil(v) and not is_boolean(v),
    do: Atom.to_string(v)

  defp atom_or_string(v), do: v

  # The attestation sub-map is structurally required — without it
  # there's nothing to project. Surface a dedicated error tag so the
  # Logger message is readable.
  defp fetch_attestation(payload) do
    case Map.get(payload, :attestation, Map.get(payload, "attestation")) do
      nil -> {:error, {:missing, :attestation}}
      %{} = att -> {:ok, att}
      other -> {:error, {:invalid_attestation, other}}
    end
  end

  # Fetch from either atom-keyed struct-as-map or string-keyed map.
  # Returns `{:error, {:missing, key}}` when the key is absent OR
  # present-but-nil for required fields.
  @required_nonnil_keys [
    :run_id,
    :session_id,
    :principal,
    :machine_identity,
    :policy_decision,
    :policy_canonical_hash,
    :verification_level,
    :tier_completeness_advisory,
    :outcome,
    :correlation_id,
    :timestamp
  ]

  defp fetch(map, key) do
    value = Map.get(map, key, Map.get(map, to_string(key)))
    required? = key in @required_nonnil_keys

    if required? and is_nil(value) do
      {:error, {:missing, key}}
    else
      {:ok, value}
    end
  end
end
