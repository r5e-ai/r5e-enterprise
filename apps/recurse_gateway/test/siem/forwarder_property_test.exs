defmodule Recurse.Gateway.Siem.ForwarderPropertyTest do
  @moduledoc """
  Property tests for `Recurse.Gateway.Siem.Forwarder` (F002 T053).

  ## Invariant

  For any valid `{:first_committed, run_id, payload}` broadcast:

    1. The emitted line parses as valid JSON (`JSON.decode/1` → `{:ok, _}`).
    2. The decoded object's key-set equals the FR-025 canonical key set.
    3. `policy_decision` is one of `"allow" | "deny"`.
    4. `tier_completeness_advisory` is `"partial"` (always, for Standalone).
    5. `tool_called` is `null` (always, for Standalone — no tool-call events).
    6. `policy_canonical_hash` is a `"sha256:<64-hex>"` string.

  ## Generators

  Bound over:

    * `principal.kind` — `:obo_human` | `:service_account` | `:autonomous`
      (with kind-dependent field sets matching the F001 Principal struct).
    * `policy_decision` — `:allow` | `:deny`.
    * `verification_level` — `:local_inclusion_verified` | `:global_inclusion_verified`
      (the FR-024 cardinality fires AT `:local_inclusion_verified`; later
      advances don't re-fire, but the schema must accept either on wire).
    * `tier_completeness_advisory` — always `:partial` in Standalone.

  ## Run count

  300 iterations per the task contract (ample to exercise the three
  principal shapes + decision x level cross-product).

  ## Why this is a property test, not an example test

  The FR-025 schema has 12 keys and the `principal` sub-object has a
  kind-dependent 3-variant shape. An example test covers 1 path per
  kind; a property test forces the Forwarder to round-trip the full
  cross-product consistently — catches regressions where, say, a new
  optional principal field sneaks onto the wire without being filtered
  through the FR-025 schema projection.
  """

  use ExUnit.Case, async: false
  use ExUnitProperties

  import ExUnit.CaptureIO
  import ExUnit.CaptureLog

  alias Recurse.Gateway.Siem.Forwarder
  alias Recurse.Shared.Ulid

  @topic "recurse:attestation_first_committed"

  @expected_keys MapSet.new([
                   "run_id",
                   "session_id",
                   "turn_id",
                   "principal",
                   "machine_identity",
                   "tool_called",
                   "policy_decision",
                   "policy_canonical_hash",
                   "verification_level",
                   "tier_completeness_advisory",
                   "outcome",
                   "upstream_status_code",
                   "correlation_id",
                   "timestamp"
                 ])

  setup do
    {:ok, string_io} = StringIO.open("")

    spec =
      Supervisor.child_spec(
        {Forwarder, io_device: string_io, pubsub: Recurse.PubSub, name: nil},
        id: make_ref()
      )

    pid = start_supervised!(spec)

    %{pid: pid, string_io: string_io}
  end

  # -- Generators ------------------------------------------------------------

  # Principal shapes mirror F001 FR-026. We stick to the string-keyed map
  # form (matches JSONB storage in the Attestation row) to exercise the
  # forwarder's string-key → wire-schema projection.
  defp obo_human_principal do
    gen all(
          subject <- nonempty_string(),
          issuer <- issuer_url(),
          display_name <- optional(nonempty_string()),
          groups <- optional(list_of(nonempty_string(), max_length: 5))
        ) do
      base = %{
        "kind" => "obo_human",
        "schema_version" => "1.0",
        "issuer" => issuer,
        "subject" => subject
      }

      base
      |> maybe_put("display_name", display_name)
      |> maybe_put("groups", groups)
    end
  end

  defp service_account_principal do
    gen all(
          account_id <- nonempty_string(),
          issuer <- issuer_url(),
          scope <- optional(list_of(nonempty_string(), max_length: 5))
        ) do
      %{
        "kind" => "service_account",
        "schema_version" => "1.0",
        "issuer" => issuer,
        "account_id" => account_id
      }
      |> maybe_put("scope", scope)
    end
  end

  defp autonomous_principal do
    gen all(path <- nonempty_string()) do
      %{
        "kind" => "autonomous",
        "schema_version" => "1.0",
        "spiffe_id" => "spiffe://example.corp/agent/" <> path
      }
    end
  end

  defp principal_gen do
    one_of([
      obo_human_principal(),
      service_account_principal(),
      autonomous_principal()
    ])
  end

  defp machine_identity_gen do
    # Standalone shape (FR-017): observed-JWT, no SPIFFE.
    gen all(
          subject <- nonempty_string(),
          issuer <- issuer_url()
        ) do
      %{
        "kind" => "observed_jwt",
        "observed_jwt_subject" => subject,
        "issuer" => issuer
      }
    end
  end

  defp attestation_gen do
    gen all(
          principal <- principal_gen(),
          machine_identity <- machine_identity_gen(),
          policy_decision <- member_of([:allow, :deny]),
          verification_level <-
            member_of([:local_inclusion_verified, :global_inclusion_verified]),
          outcome <- member_of([:success, :upstream_error, :cancelled]),
          upstream_status_code <- one_of([constant(nil), integer(500..599)]),
          hash_seed <- binary(min_length: 1, max_length: 64)
        ) do
      %{
        run_id: Ulid.generate(),
        session_id: Ulid.generate(),
        turn_id: nil,
        principal: principal,
        machine_identity: machine_identity,
        policy_decision: policy_decision,
        policy_canonical_hash: :crypto.hash(:sha256, hash_seed),
        verification_level: verification_level,
        tier_completeness_advisory: :partial,
        outcome: outcome,
        upstream_status_code: upstream_status_code,
        correlation_id: Ulid.generate(),
        timestamp: DateTime.utc_now()
      }
    end
  end

  defp payload_gen do
    gen all(attestation <- attestation_gen()) do
      %{
        run_id: attestation.run_id,
        verification_level: attestation.verification_level,
        session_chain_root: :crypto.hash(:sha256, attestation.run_id),
        global_inclusion_proof: <<>>,
        attestation: attestation
      }
    end
  end

  # -- Properties ------------------------------------------------------------

  describe "NDJSON emission conforms to FR-025" do
    property "valid payload → valid JSON + canonical key set", %{
      pid: pid,
      string_io: string_io
    } do
      check all(payload <- payload_gen(), max_runs: 300) do
        capture_log(fn ->
          capture_io(fn ->
            :ok =
              Phoenix.PubSub.broadcast(
                Recurse.PubSub,
                @topic,
                {:first_committed, payload.run_id, payload}
              )
          end)
        end)

        # Force the forwarder to process the message before draining.
        _ = :sys.get_state(pid)

        output = drain_and_reset(string_io)

        [line] = String.split(output, "\n", trim: true)

        assert {:ok, decoded} = JSON.decode(line)
        assert is_map(decoded)
        assert MapSet.new(Map.keys(decoded)) == @expected_keys

        # Invariants per spec FR-024/FR-025.
        assert decoded["tool_called"] == nil
        assert decoded["tier_completeness_advisory"] == "partial"
        assert decoded["policy_decision"] in ["allow", "deny"]

        assert decoded["verification_level"] in [
                 "local_inclusion_verified",
                 "global_inclusion_verified"
               ]

        assert is_map(decoded["principal"])
        assert decoded["principal"]["kind"] in ["obo_human", "service_account", "autonomous"]

        assert Regex.match?(
                 ~r/^sha256:[0-9a-f]{64}$/,
                 decoded["policy_canonical_hash"]
               )

        # run_id / session_id / correlation_id / timestamp — all non-empty strings.
        for key <- ["run_id", "session_id", "correlation_id", "timestamp"] do
          assert is_binary(decoded[key]) and decoded[key] != ""
        end
      end
    end
  end

  # -- Helpers ---------------------------------------------------------------

  # Drain-and-reset the StringIO device in one call. `StringIO.flush/1`
  # returns the accumulated output and empties the buffer so the next
  # iteration's assertion sees only the freshly-emitted line.
  defp drain_and_reset(string_io) do
    StringIO.flush(string_io)
  end

  defp nonempty_string do
    string(:alphanumeric, min_length: 1, max_length: 32)
  end

  defp issuer_url do
    gen all(host <- nonempty_string()) do
      "https://" <> host <> ".example"
    end
  end

  defp optional(gen) do
    frequency([
      {3, gen},
      {1, constant(nil)}
    ])
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
