defmodule Recurse.Gateway.AuditPlane.PredicateOnlyUriTest do
  @moduledoc """
  Issue #29 / B4 / AD-1 Option A. Pure unit tests; no Repo, no JOSE.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.AuditPlane.PredicateOnlyUri

  describe "uri_scheme_prefix/0" do
    test "returns the canonical scheme prefix" do
      assert PredicateOnlyUri.uri_scheme_prefix() ==
               "recurse://system/predicate-only/"
    end
  end

  describe "match?/1" do
    test "true for the canonical prefix + suffix" do
      assert PredicateOnlyUri.match?("recurse://system/predicate-only/run_01HZQ")
    end

    test "true for the prefix-only edge case" do
      assert PredicateOnlyUri.match?("recurse://system/predicate-only/")
    end

    test "false for nil" do
      refute PredicateOnlyUri.match?(nil)
    end

    test "false for empty string" do
      refute PredicateOnlyUri.match?("")
    end

    test "false for non-binary input" do
      refute PredicateOnlyUri.match?(42)
      refute PredicateOnlyUri.match?(%{})
      refute PredicateOnlyUri.match?(:atom)
    end

    test "false for s3:// URIs" do
      refute PredicateOnlyUri.match?("s3://recurse-payloads/run_01HZQ/payload.json")
    end

    test "false for sibling system URIs" do
      refute PredicateOnlyUri.match?("recurse://system/metrics/run_01HZQ")
      refute PredicateOnlyUri.match?("recurse://system/predicate_only/run_01HZQ")
    end
  end

  describe "build/1" do
    test "concatenates prefix + run_id" do
      assert PredicateOnlyUri.build("run_01HZQ3R5E0") ==
               "recurse://system/predicate-only/run_01HZQ3R5E0"
    end

    test "round-trips with match?/1" do
      run_id = "run_01TEST"
      uri = PredicateOnlyUri.build(run_id)

      assert PredicateOnlyUri.match?(uri)
    end
  end

  describe "system_event_no_policy_hash/0" do
    test "returns a stable 32-byte SHA-256 sentinel" do
      hash = PredicateOnlyUri.system_event_no_policy_hash()
      assert byte_size(hash) == 32
      assert hash == :crypto.hash(:sha256, "recurse.system.no-policy.v1")
    end

    test "is identical across calls (deterministic)" do
      assert PredicateOnlyUri.system_event_no_policy_hash() ==
               PredicateOnlyUri.system_event_no_policy_hash()
    end
  end

  describe "predicate_only_response_body/1" do
    test "returns JSON-encoded body with predicate_only=true + run_id + event_kind" do
      body =
        PredicateOnlyUri.predicate_only_response_body(%{
          run_id: "run_01HZQ",
          event_kind: :ui_login,
          payload_uri: "recurse://system/predicate-only/run_01HZQ"
        })

      assert {:ok, decoded} = JSON.decode(body)

      assert %{
               "predicate_only" => true,
               "run_id" => "run_01HZQ",
               "event_kind" => "ui_login",
               "payload_uri" => "recurse://system/predicate-only/run_01HZQ"
             } = decoded

      assert is_binary(decoded["explanation"])
    end

    test "stringifies atom event_kind" do
      body =
        PredicateOnlyUri.predicate_only_response_body(%{
          run_id: "r",
          event_kind: :ui_query,
          payload_uri: "recurse://system/predicate-only/r"
        })

      assert {:ok, %{"event_kind" => "ui_query"}} = JSON.decode(body)
    end

    test "passes through string event_kind" do
      body =
        PredicateOnlyUri.predicate_only_response_body(%{
          run_id: "r",
          event_kind: "ui_query",
          payload_uri: "recurse://system/predicate-only/r"
        })

      assert {:ok, %{"event_kind" => "ui_query"}} = JSON.decode(body)
    end

    test "renders nil event_kind as null" do
      body =
        PredicateOnlyUri.predicate_only_response_body(%{
          run_id: "r",
          event_kind: nil,
          payload_uri: "recurse://system/predicate-only/r"
        })

      assert {:ok, %{"event_kind" => nil}} = JSON.decode(body)
    end
  end

  describe "evidence_zip_payload_marker/0" do
    test "returns a JSON-encoded marker with predicate_only=true" do
      body = PredicateOnlyUri.evidence_zip_payload_marker()

      assert {:ok, %{"predicate_only" => true} = decoded} = JSON.decode(body)
      assert is_binary(decoded["explanation"])
    end
  end
end
