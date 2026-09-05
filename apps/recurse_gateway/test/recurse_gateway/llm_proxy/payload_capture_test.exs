defmodule Recurse.Gateway.LlmProxy.PayloadCaptureTest do
  @moduledoc "Spec 012 S6b — bounded capture semantics."

  use ExUnit.Case, async: true

  alias Recurse.Gateway.LlmProxy.PayloadCapture

  test "disabled captures ignore every chunk" do
    capture = PayloadCapture.init(enabled?: false) |> PayloadCapture.append("abc")
    assert PayloadCapture.result(capture) == :disabled
  end

  test "enabled captures concatenate chunks in order" do
    capture =
      PayloadCapture.init(enabled?: true, max_bytes: 100)
      |> PayloadCapture.append("ab")
      |> PayloadCapture.append("")
      |> PayloadCapture.append("cd")

    assert PayloadCapture.result(capture) == {:ok, "abcd"}
  end

  test "exceeding the cap drops everything and reports :truncated (memory stays bounded)" do
    capture =
      PayloadCapture.init(enabled?: true, max_bytes: 5)
      |> PayloadCapture.append("abc")
      |> PayloadCapture.append("def")

    assert capture.size == 0
    assert capture.chunks == []
    assert PayloadCapture.result(capture) == :truncated
    # Later chunks do not resurrect it.
    assert PayloadCapture.result(PayloadCapture.append(capture, "x")) == :truncated
  end

  test "exactly the cap is kept" do
    capture = PayloadCapture.init(enabled?: true, max_bytes: 3) |> PayloadCapture.append("abc")
    assert PayloadCapture.result(capture) == {:ok, "abc"}
  end

  test "defaults come from application config" do
    previous = Application.get_env(:recurse_gateway, :retain_payloads?)
    Application.put_env(:recurse_gateway, :retain_payloads?, true)

    try do
      assert %PayloadCapture{enabled?: true} = PayloadCapture.init()
      assert PayloadCapture.init().max_bytes == PayloadCapture.default_max_bytes()
    after
      if is_nil(previous),
        do: Application.delete_env(:recurse_gateway, :retain_payloads?),
        else: Application.put_env(:recurse_gateway, :retain_payloads?, previous)
    end

    assert %PayloadCapture{enabled?: false} = PayloadCapture.init()
  end
end
