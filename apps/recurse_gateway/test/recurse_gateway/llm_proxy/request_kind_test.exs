defmodule Recurse.Gateway.LlmProxy.RequestKindTest do
  @moduledoc """
  Fixture-driven tests for the receipt classifier (spec 012 plan §9 D2).
  Every captured Claude Code request in
  `apps/recurse_shared/test/fixtures/anthropic_messages/` must classify
  the way the spike documented it.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.LlmProxy.RequestKind

  @fixtures Path.expand("../../../../recurse_shared/test/fixtures/anthropic_messages", __DIR__)

  defp fixture(name), do: File.read!(Path.join(@fixtures, name))

  test "the real agent turn (29 tools, stream: true) is agent_turn" do
    assert RequestKind.classify_body(fixture("single_tool_use_bash.request.json")) == :agent_turn
    assert RequestKind.classify_body(fixture("text_only.request.json")) == :agent_turn
    assert RequestKind.classify_body(fixture("parallel_tool_use.request.json")) == :agent_turn
    assert RequestKind.classify_body(fixture("hook_denied_followup.request.json")) == :agent_turn
  end

  test "tools win over output_config (error_not_found carries both)" do
    assert RequestKind.classify_body(fixture("error_not_found.request.json")) == :agent_turn
  end

  test "generate_session_title (tools: [], output_config json_schema) is session_title" do
    body = fixture("session_title.request.json")
    assert %{"tools" => [], "output_config" => %{"format" => _}} = JSON.decode!(body)
    assert RequestKind.classify_body(body) == :session_title
  end

  test "the non-streaming side query (no stream key, no tools) is side_query" do
    body = fixture("non_streaming_state_summary.request.json")
    refute Map.has_key?(JSON.decode!(body), "stream")
    assert RequestKind.classify_body(body) == :side_query
  end

  test "rule order on synthetic bodies" do
    assert RequestKind.classify(%{"tools" => [%{"name" => "Bash"}]}) == :agent_turn
    assert RequestKind.classify(%{"tools" => [], "output_config" => %{}}) == :session_title
    assert RequestKind.classify(%{"stream" => true}) == :agent_turn
    assert RequestKind.classify(%{"stream" => false}) == :side_query
    assert RequestKind.classify(%{"model" => "x"}) == :side_query
    assert RequestKind.classify(%{"tools" => [], "stream" => true}) == :agent_turn
  end

  test "unparseable or empty bodies default to agent_turn" do
    assert RequestKind.classify_body("") == :agent_turn
    assert RequestKind.classify_body(nil) == :agent_turn
    assert RequestKind.classify_body("not json") == :agent_turn
    assert RequestKind.classify_body("[1,2]") == :agent_turn
    assert RequestKind.classify("nope") == :agent_turn
  end

  test "to_string/1" do
    assert RequestKind.to_string(:agent_turn) == "agent_turn"
    assert RequestKind.to_string(:session_title) == "session_title"
    assert RequestKind.to_string(:side_query) == "side_query"
    assert RequestKind.to_string(nil) == nil
    assert Enum.sort(RequestKind.kinds()) == [:agent_turn, :session_title, :side_query]
  end
end
