defmodule Recurse.Gateway.Attestation.FirstCommitterTest do
  @moduledoc """
  Tests for `Recurse.Gateway.Attestation.FirstCommitter` (F002 T049).

  ## Coverage

    * Boots, subscribes to `recurse:attestation_first_committed`, and
      increments `observed_count` on broadcasts.
    * Emits a `[:recurse, :attestation, :first_committed]` telemetry
      event with `run_id` + `tenant_id` metadata.
    * Ignores unexpected message shapes without crashing (defense in
      depth — a rogue publisher must not take the observer offline).

  ## Async

  `async: false` — broadcasts are topic-scoped on the shared
  `Recurse.PubSub`; the application-supervised FirstCommitter subscribes
  to the same topic. We start private unregistered instances
  (`name: nil`, ref-based child id) so they pick up broadcasts
  alongside the app singleton without name collisions; `observed_count`
  is queried by pid so tests are still isolated (the singleton's
  counter is separate). Concurrent tests on the same topic are not
  async-safe, hence `async: false`.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Recurse.Gateway.Attestation.FirstCommitter
  alias Recurse.Shared.Ulid

  @topic "recurse:attestation_first_committed"

  setup do
    # Start a private FirstCommitter unregistered (name: nil) so it
    # doesn't collide with the application-supervised singleton AND
    # we don't mint atoms at runtime. Each test holds the pid; the
    # child spec gets a ref-based id so multiple parallel specs don't
    # clash inside `start_supervised!`.
    spec =
      Supervisor.child_spec(
        {FirstCommitter, name: nil, pubsub: Recurse.PubSub},
        id: make_ref()
      )

    pid = start_supervised!(spec)
    %{pid: pid}
  end

  describe "first-commit observation" do
    test "increments observed_count on broadcast", %{pid: pid} do
      ref = attach_handler([:recurse, :attestation, :first_committed])

      assert 0 == FirstCommitter.observed_count(pid)

      run_id = Ulid.generate()
      broadcast({:first_committed, run_id, sample_payload(run_id)})

      assert_receive {^ref, _measurements, _metadata}, 500
      assert 1 == FirstCommitter.observed_count(pid)
    end

    test "emits telemetry with run_id + tenant_id metadata", %{pid: pid} do
      ref = attach_handler([:recurse, :attestation, :first_committed])
      run_id = Ulid.generate()
      tenant_id = Ulid.generate()

      broadcast({:first_committed, run_id, sample_payload(run_id, tenant_id)})

      assert_receive {^ref, %{count: 1},
                      %{
                        run_id: ^run_id,
                        tenant_id: ^tenant_id,
                        verification_level: :local_inclusion_verified
                      }},
                     500

      # Ensure observed_count also advanced so telemetry and counter
      # stay in lock-step.
      assert 1 == FirstCommitter.observed_count(pid)
    end

    test "supports multiple broadcasts", %{pid: pid} do
      ref = attach_handler([:recurse, :attestation, :first_committed])

      for _ <- 1..3 do
        run_id = Ulid.generate()
        broadcast({:first_committed, run_id, sample_payload(run_id)})
        assert_receive {^ref, _m, _meta}, 500
      end

      assert 3 == FirstCommitter.observed_count(pid)
    end
  end

  describe "defense in depth" do
    test "ignores unexpected messages without crashing", %{pid: pid} do
      assert 0 == FirstCommitter.observed_count(pid)

      # Sending a malformed message directly to the process (not via
      # PubSub) should be logged + ignored.
      log =
        capture_log(fn ->
          send(pid, :rogue_message)
          # Give the GenServer a moment to process + log.
          Process.sleep(50)
        end)

      assert log =~ "FirstCommitter ignored unexpected message"
      assert Process.alive?(pid)
      assert 0 == FirstCommitter.observed_count(pid)
    end

    test "tolerates payload without tenant_id", %{pid: pid} do
      ref = attach_handler([:recurse, :attestation, :first_committed])
      run_id = Ulid.generate()

      # Deliberately missing both `:attestation.tenant_id` and top-level
      # `:tenant_id` — telemetry should still fire with tenant_id: nil.
      payload = %{
        run_id: run_id,
        verification_level: :signed,
        session_chain_root: <<0::256>>,
        global_inclusion_proof: <<>>
      }

      broadcast({:first_committed, run_id, payload})

      assert_receive {^ref, _m, %{run_id: ^run_id, tenant_id: nil}}, 500
      assert 1 == FirstCommitter.observed_count(pid)
    end
  end

  # --- helpers --------------------------------------------------------------

  defp sample_payload(run_id, tenant_id \\ Ulid.generate()) do
    %{
      run_id: run_id,
      verification_level: :local_inclusion_verified,
      session_chain_root: :crypto.hash(:sha256, "epoch-root-" <> run_id),
      global_inclusion_proof: <<>>,
      attestation: %{
        run_id: run_id,
        session_id: run_id,
        tenant_id: tenant_id,
        turn_id: nil
      }
    }
  end

  defp broadcast(message) do
    Phoenix.PubSub.broadcast(Recurse.PubSub, @topic, message)
  end

  # Attach a unique telemetry handler that forwards every measurement +
  # metadata to `self()` keyed by a reference. Handler is auto-detached
  # on test exit so we don't leak between tests.
  defp attach_handler(event_name) do
    ref = make_ref()
    handler_id = "test-handler-#{inspect(ref)}"
    test_pid = self()

    :telemetry.attach(
      handler_id,
      event_name,
      fn _event, measurements, metadata, _ ->
        send(test_pid, {ref, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    ref
  end
end
