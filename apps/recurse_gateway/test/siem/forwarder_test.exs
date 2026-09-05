defmodule Recurse.Gateway.Siem.ForwarderTest do
  @moduledoc """
  Unit tests for `Recurse.Gateway.Siem.Forwarder` (F002 T053).

  ## Coverage

    * Boots and subscribes to the PubSub topic `recurse:attestation_first_committed`.
    * Emits exactly one NDJSON line per `{:first_committed, run_id, payload}` broadcast.
    * NDJSON line is valid JSON and conforms to the FR-025 key set.
    * Malformed payload (missing required field) increments the
      `emit_errors_count` state + fires a telemetry error event,
      does NOT crash the forwarder.
    * Cardinality invariant: two broadcasts yield two NDJSON lines.

  ## Async

  `async: false` — the module-level forwarder already started by the
  application supervisor subscribes to the same PubSub topic; we start
  private forwarders with isolated `StringIO`-backed io devices to
  avoid touching shared stdout. PubSub broadcasts in this test are
  scoped to private topics via the subscription — but broadcasts are
  topic-scoped and BOTH the module-level forwarder AND our private
  one would receive them. So we use a unique synthetic payload-shape
  per test that the module-level forwarder will ignore (because it's
  safe to stdout and we only assert on OUR device).

  Emits to `:stdio` in the module-level forwarder are harmless to this
  test (the ExUnit harness captures stdout), but noisy; we use
  `capture_io/1` around test bodies that broadcast.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO
  import ExUnit.CaptureLog

  alias Recurse.Gateway.Siem.Forwarder
  alias Recurse.Shared.Ulid

  @topic "recurse:attestation_first_committed"

  setup do
    {:ok, string_io} = StringIO.open("")

    # Start a private forwarder with its own io_device and NO registered
    # name (so it doesn't collide with the application-supervised
    # instance and we don't mint atoms at runtime). The test holds the
    # pid directly; start_supervised!/1 gets a unique `id` via a ref.
    spec =
      Supervisor.child_spec(
        {Forwarder, io_device: string_io, pubsub: Recurse.PubSub, name: nil},
        id: make_ref()
      )

    pid = start_supervised!(spec)

    %{pid: pid, string_io: string_io}
  end

  defp drain_contents(string_io) do
    {_input, output} = StringIO.contents(string_io)
    output
  end

  defp well_formed_payload(overrides \\ %{}) do
    att =
      Map.merge(
        %{
          run_id: Ulid.generate(),
          session_id: Ulid.generate(),
          turn_id: nil,
          principal: %{
            "kind" => "service_account",
            "schema_version" => "1.0",
            "issuer" => "https://broker.example",
            "account_id" => "svc-test"
          },
          machine_identity: %{
            "kind" => "observed_jwt",
            "observed_jwt_subject" => "svc-test",
            "issuer" => "https://broker.example"
          },
          policy_decision: :allow,
          policy_canonical_hash: :crypto.hash(:sha256, "cedar-policy-bundle"),
          verification_level: :local_inclusion_verified,
          tier_completeness_advisory: :partial,
          outcome: :success,
          upstream_status_code: nil,
          correlation_id: Ulid.generate(),
          timestamp: DateTime.utc_now()
        },
        Map.get(overrides, :attestation, %{})
      )

    %{
      run_id: att.run_id,
      verification_level: att.verification_level,
      session_chain_root: :crypto.hash(:sha256, "epoch-root"),
      global_inclusion_proof: <<>>,
      attestation: att
    }
  end

  defp broadcast(payload) do
    :ok =
      Phoenix.PubSub.broadcast(
        Recurse.PubSub,
        @topic,
        {:first_committed, payload.run_id, payload}
      )
  end

  describe "init/1" do
    test "subscribes to recurse:attestation_first_committed", %{pid: pid} do
      # If the subscription took, broadcasting to the topic reaches this pid.
      payload = well_formed_payload()

      capture_io(fn -> broadcast(payload) end)

      # The state count advancing is the proxy for "message was delivered".
      state = :sys.get_state(pid)
      assert state.emitted_count == 1
    end

    test "starts with zeroed counters and known io_device", %{
      pid: pid,
      string_io: string_io
    } do
      state = :sys.get_state(pid)
      assert state.emitted_count == 0
      assert state.emit_errors_count == 0
      assert state.io_device == string_io
      assert state.pubsub == Recurse.PubSub
    end
  end

  describe "handle_info/2 — happy path" do
    test "emits exactly one NDJSON line per {:first_committed, ...} broadcast",
         %{pid: pid, string_io: string_io} do
      payload = well_formed_payload()

      # The module-level Forwarder also writes to :stdio — capture so the
      # ExUnit output stays clean.
      capture_io(fn -> broadcast(payload) end)

      # Wait for the private forwarder to process the message.
      _state = :sys.get_state(pid)

      output = drain_contents(string_io)
      lines = String.split(output, "\n", trim: true)
      assert [_single_line] = lines
    end

    test "emitted line is valid JSON", %{pid: pid, string_io: string_io} do
      payload = well_formed_payload()
      capture_io(fn -> broadcast(payload) end)
      _ = :sys.get_state(pid)

      [line] = drain_contents(string_io) |> String.split("\n", trim: true)
      assert {:ok, %{}} = JSON.decode(line)
    end

    test "emitted schema conforms to FR-025 key set", %{
      pid: pid,
      string_io: string_io
    } do
      payload = well_formed_payload()
      capture_io(fn -> broadcast(payload) end)
      _ = :sys.get_state(pid)

      [line] = drain_contents(string_io) |> String.split("\n", trim: true)
      {:ok, decoded} = JSON.decode(line)

      expected_keys =
        MapSet.new([
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

      assert MapSet.new(Map.keys(decoded)) == expected_keys

      # Standalone-slice invariants.
      assert decoded["tool_called"] == nil
      assert decoded["tier_completeness_advisory"] == "partial"
      assert decoded["policy_decision"] in ["allow", "deny"]

      assert decoded["verification_level"] in [
               "local_inclusion_verified",
               "global_inclusion_verified",
               "signed"
             ]

      # policy_canonical_hash carries the `sha256:<hex>` prefix.
      assert String.starts_with?(decoded["policy_canonical_hash"], "sha256:")
    end

    test "principal is emitted as a structured object (not a flat string)",
         %{pid: pid, string_io: string_io} do
      payload = well_formed_payload()
      capture_io(fn -> broadcast(payload) end)
      _ = :sys.get_state(pid)

      [line] = drain_contents(string_io) |> String.split("\n", trim: true)
      {:ok, decoded} = JSON.decode(line)

      assert is_map(decoded["principal"])
      assert decoded["principal"]["kind"] == "service_account"
      assert decoded["principal"]["issuer"] == "https://broker.example"
      assert decoded["principal"]["account_id"] == "svc-test"
    end

    test "emitted_count increments to 1 after one broadcast", %{pid: pid} do
      payload = well_formed_payload()
      capture_io(fn -> broadcast(payload) end)

      state = :sys.get_state(pid)
      assert state.emitted_count == 1
      assert state.emit_errors_count == 0
    end
  end

  describe "handle_info/2 — cardinality" do
    test "two distinct broadcasts emit exactly two NDJSON lines", %{
      pid: pid,
      string_io: string_io
    } do
      payload_a = well_formed_payload()
      payload_b = well_formed_payload()

      capture_io(fn ->
        broadcast(payload_a)
        broadcast(payload_b)
      end)

      # Ensure both messages processed by the private forwarder.
      state = :sys.get_state(pid)
      assert state.emitted_count == 2

      lines = drain_contents(string_io) |> String.split("\n", trim: true)
      assert length(lines) == 2
      assert Enum.all?(lines, &match?({:ok, %{}}, JSON.decode(&1)))
    end
  end

  describe "handle_info/2 — malformed payload" do
    test "missing :principal increments emit_errors_count + logs + does not crash",
         %{pid: pid, string_io: string_io} do
      bad_attestation =
        well_formed_payload().attestation
        |> Map.put(:principal, nil)

      bad_payload = %{
        run_id: bad_attestation.run_id,
        verification_level: :local_inclusion_verified,
        session_chain_root: <<>>,
        global_inclusion_proof: <<>>,
        attestation: bad_attestation
      }

      log =
        capture_log(fn ->
          capture_io(fn -> broadcast(bad_payload) end)
          # Force processing.
          _ = :sys.get_state(pid)
        end)

      assert log =~ "SIEM forwarder skipping malformed attestation"
      assert log =~ "missing"

      state = :sys.get_state(pid)
      assert Process.alive?(pid)
      assert state.emit_errors_count == 1
      assert state.emitted_count == 0

      # No line was emitted.
      assert drain_contents(string_io) == ""
    end

    test "missing :attestation key is surfaced as a structured error", %{
      pid: pid,
      string_io: string_io
    } do
      bad_payload = %{
        run_id: Ulid.generate(),
        verification_level: :local_inclusion_verified,
        session_chain_root: <<>>,
        global_inclusion_proof: <<>>
        # no :attestation key at all
      }

      capture_log(fn ->
        capture_io(fn -> broadcast(bad_payload) end)
        _ = :sys.get_state(pid)
      end)

      state = :sys.get_state(pid)
      assert Process.alive?(pid)
      assert state.emit_errors_count == 1
      assert drain_contents(string_io) == ""
    end
  end

  describe "handle_info/2 — unrelated messages" do
    test "ignores send/2 from siblings without crashing", %{pid: pid} do
      send(pid, :arbitrary_noise)
      send(pid, {:not_a_first_committed_tuple, :data})

      # sys.get_state sends a :system message; if the forwarder
      # crashed it would raise.
      state = :sys.get_state(pid)
      assert state.emitted_count == 0
      assert state.emit_errors_count == 0
    end
  end
end
