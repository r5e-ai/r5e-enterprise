defmodule Recurse.Gateway.AuditPlane.ErrorEnvelopeTest do
  @moduledoc """
  Issue #29 / B8. Closes live bug LB-1: SPA's `ApiError` parser at
  `ui/src/lib/api.ts:19-43` expects flat `{error, error_description,
  correlation_id, attested_run_id}`. These tests pin the shape.
  """

  use ExUnit.Case, async: true
  import Plug.Test

  alias Recurse.Gateway.AuditPlane.ErrorEnvelope

  describe "build/3" do
    test "emits the canonical flat shape" do
      assert %{
               "error" => "ERR_TEST",
               "error_description" => "test message",
               "correlation_id" => "unknown",
               "attested_run_id" => nil
             } = ErrorEnvelope.build("ERR_TEST", "test message")
    end

    test "uses provided correlation_id" do
      assert %{"correlation_id" => "corr-123"} =
               ErrorEnvelope.build("ERR_X", "msg", correlation_id: "corr-123")
    end

    test "uses provided attested_run_id" do
      assert %{"attested_run_id" => "run_01HZQ"} =
               ErrorEnvelope.build("ERR_DENIED", "denied", attested_run_id: "run_01HZQ")
    end
  end

  describe "send_unauthorized/4" do
    test "responds 401 with canonical envelope" do
      conn = conn(:get, "/v1/audit/receipts")

      response =
        ErrorEnvelope.send_unauthorized(conn, "ERR_UNAUTHORIZED", "JWT expired")

      assert response.status == 401
      assert {"content-type", "application/json; charset=utf-8"} in response.resp_headers

      assert {:ok,
              %{
                "error" => "ERR_UNAUTHORIZED",
                "error_description" => "JWT expired",
                "correlation_id" => _,
                "attested_run_id" => nil
              }} = JSON.decode(response.resp_body)
    end
  end

  describe "send_forbidden/4 with attested_run_id" do
    test "the SPA's deep-link field is populated" do
      conn = conn(:post, "/v1/policy/simulate")

      response =
        ErrorEnvelope.send_forbidden(conn, "ERR_FORBIDDEN", "denied",
          attested_run_id: "run_01HZQ"
        )

      assert response.status == 403
      assert {:ok, %{"attested_run_id" => "run_01HZQ"}} = JSON.decode(response.resp_body)
    end
  end

  describe "send_bad_request/4 / send_not_found/4 / send_internal_error/4" do
    test "all use the same envelope shape, differ only in status" do
      conn = conn(:get, "/v1/audit/payload?run_id=missing")

      bad = ErrorEnvelope.send_bad_request(conn, "ERR_BAD_REQUEST", "x")
      not_found = ErrorEnvelope.send_not_found(conn, "ERR_NOT_FOUND", "y")
      err500 = ErrorEnvelope.send_internal_error(conn, "ERR_INTERNAL", "z")

      assert bad.status == 400
      assert not_found.status == 404
      assert err500.status == 500

      assert {:ok, %{"error" => "ERR_BAD_REQUEST"}} = JSON.decode(bad.resp_body)
      assert {:ok, %{"error" => "ERR_NOT_FOUND"}} = JSON.decode(not_found.resp_body)
      assert {:ok, %{"error" => "ERR_INTERNAL"}} = JSON.decode(err500.resp_body)
    end
  end

  describe "correlation_id_from_conn/1" do
    test "reads the x-recurse-correlation-id resp header" do
      conn =
        :get
        |> conn("/")
        |> Plug.Conn.put_resp_header("x-recurse-correlation-id", "corr-abc")

      assert ErrorEnvelope.correlation_id_from_conn(conn) == "corr-abc"
    end

    test "returns 'unknown' when header absent" do
      conn = conn(:get, "/")
      assert ErrorEnvelope.correlation_id_from_conn(conn) == "unknown"
    end
  end

  describe "schema conformance (issue #30 / Task L)" do
    @schema_path Path.expand(
                   "../../priv/schemas/error_envelope.json",
                   __DIR__
                 )

    test "build/3 produces JSON conforming to priv/schemas/error_envelope.json" do
      schema = @schema_path |> File.read!() |> JSON.decode!()

      # Pin the canonical shape against the published schema. We don't pull in
      # ExJsonSchema for one test; spot-check that every required key in the
      # schema is present in the builder output, that no unexpected keys
      # appear (mirrors the schema's `additionalProperties: false`), and that
      # the property types match.
      assert schema["x-status"] == "stable",
             "schema must remain marked stable; placeholder shape was retired in Task L"

      assert schema["additionalProperties"] == false,
             "schema must keep additionalProperties:false; build/3 must not emit extra keys"

      body = ErrorEnvelope.build("ERR_TEST", "test description")

      required = schema["required"]
      assert is_list(required) and required != []

      for key <- required do
        assert Map.has_key?(body, key), "build/3 missing required schema key: #{key}"
      end

      schema_keys = schema["properties"] |> Map.keys() |> MapSet.new()
      body_keys = body |> Map.keys() |> MapSet.new()

      assert MapSet.subset?(body_keys, schema_keys),
             "build/3 emitted keys not declared in schema: " <>
               (MapSet.difference(body_keys, schema_keys) |> MapSet.to_list() |> inspect())

      # Type spot-checks aligned with schema property types.
      assert is_binary(body["error"])
      assert is_binary(body["error_description"])
      assert is_binary(body["correlation_id"])
      assert is_nil(body["attested_run_id"]) or is_binary(body["attested_run_id"])

      # The `error` code pattern in the schema requires ERR_ prefix.
      assert Regex.match?(~r/^ERR_[A-Z_]+$/, body["error"])
    end

    test "manifest advertises the error_envelope schema as version 1.0.0" do
      manifest_path =
        Path.expand("../../priv/schemas/manifest.json", __DIR__)

      manifest = manifest_path |> File.read!() |> JSON.decode!()

      assert %{"name" => "error_envelope", "version" => "1.0.0"} =
               Enum.find(manifest["schemas"], fn s -> s["name"] == "error_envelope" end)
    end
  end
end
