defmodule Recurse.Gateway.LlmProxy.WebSocketAdmissionBoundaryTest do
  use ExUnit.Case, async: true

  alias Recurse.Gateway.LlmProxy.WebSocketBridge

  test "an active turn rejects another request before touching the upstream socket" do
    state = %{turn_active?: true}
    request = Jason.encode!(%{type: "response.create", model: "test", input: []})

    assert {:stop, :normal, {1008, "overlapping model requests are unsupported"}, ^state} =
             WebSocketBridge.handle_in({request, opcode: :text}, state)
  end

  test "malformed and unsupported request frames cannot reach upstream" do
    state = %{turn_active?: false}

    for payload <- [
          "hello",
          "[]",
          "null",
          "{}",
          ~s({"type":"response.cancel"}),
          ~s({"type":"response.create","model":""})
        ] do
      assert {:stop, :normal, {1008, "model request was not admitted"}, ^state} =
               WebSocketBridge.handle_in({payload, opcode: :text}, state)
    end
  end
end
