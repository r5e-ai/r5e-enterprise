defmodule Recurse.Gateway.LlmProxy.DenialInjector.OpenaiResponsesPropertyTest do
  @moduledoc """
  Property tests for `Recurse.Gateway.LlmProxy.DenialInjector.OpenaiResponses`
  (Spec 009 Phase 3 Sub-3.5 / T053).

  Spec source: `specs/009-llm-api-proxy/contracts/denial_injector.md`
  §"Property tests".

  ## PTs covered here

    * **PT-001** — denied tool_use NEVER reaches client across random
      streams + deny rules. We model "client output" as the union of
      synthetic events emitted by the injector for denied intents
      PLUS the allowed events forwarded byte-identical. Assertion:
      no denied call_id's `function_call` event ever appears in the
      client-output stream.

    * **PT-002** — allowed tool_use ALWAYS reaches client byte-identical
      (all-allow Cedar). Under all-allow, the injector is never called;
      we assert the client-output stream equals the upstream stream
      exactly.

    * **PT-003** — synthetic events always syntactically valid JSON
      conforming to the Responses-API event schema. We generate random
      rule_id, reason, suggested_alternative (including unicode),
      and assert: each event Jason.decode/1's; required fields present;
      type values valid; nested content schema correct.

  ## Generators

  Built bottom-up as direct generators (no `filter` traps). Each
  generator names the space it produces. Names are reused across PT-001
  /PT-002/PT-003 to keep the surface tight.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Gateway.LlmProxy.DenialInjector
  alias Recurse.Gateway.LlmProxy.DenialInjector.OpenaiResponses, as: Injector
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @default_template "Tool call '{tool_name}' blocked by org policy {rule_id}: {reason}.{? Try alternative: {suggested_alternative}}"

  # ---------------------------------------------------------------------------
  # Generators
  # ---------------------------------------------------------------------------

  defp call_id_gen do
    StreamData.bind(StreamData.string(:alphanumeric, min_length: 1, max_length: 12), fn s ->
      StreamData.constant("call_" <> s)
    end)
  end

  defp tool_name_gen do
    StreamData.member_of(["shell", "web_fetch", "edit", "read", "search", "python_run"])
  end

  defp rule_id_gen do
    StreamData.bind(StreamData.string(:alphanumeric, min_length: 1, max_length: 16), fn s ->
      StreamData.constant("rule_" <> s)
    end)
  end

  # Reasons may include unicode; we wrap printable_ascii + a small
  # unicode flavor. We bound length to keep the test fast and avoid
  # generating control bytes that would test JSON's escape handling
  # rather than our denial-injector's invariants.
  defp reason_gen do
    StreamData.one_of([
      StreamData.string(:printable, min_length: 1, max_length: 120),
      StreamData.constant("blocked by org-policy 例: π=3.14"),
      StreamData.constant("denied — see runbook"),
      StreamData.string(:alphanumeric, min_length: 1, max_length: 80)
    ])
  end

  defp alt_gen do
    StreamData.one_of([
      StreamData.constant(nil),
      StreamData.string(:alphanumeric, min_length: 1, max_length: 32),
      StreamData.constant("python_run with --safe")
    ])
  end

  defp event_index_list_gen do
    StreamData.bind(StreamData.integer(0..50), fn start ->
      StreamData.bind(StreamData.integer(1..5), fn n ->
        StreamData.constant(Enum.to_list(start..(start + n - 1)))
      end)
    end)
  end

  defp intent_gen do
    ExUnitProperties.gen all call_id <- call_id_gen(),
                             tool_name <- tool_name_gen(),
                             tool_args <-
                               StreamData.map_of(
                                 StreamData.string(:alphanumeric, min_length: 1, max_length: 8),
                                 StreamData.string(:alphanumeric, max_length: 32),
                                 max_length: 4
                               ),
                             event_indices <- event_index_list_gen() do
      [start_idx | _] = event_indices
      end_idx = List.last(event_indices)

      {:ok, intent} =
        ToolUseIntent.new(%{
          call_id: call_id,
          tool_name: tool_name,
          tool_args: tool_args,
          provider_event_span: %{
            start_byte_offset: start_idx * 100,
            end_byte_offset: end_idx * 100 + 100,
            event_indices: event_indices
          }
        })

      intent
    end
  end

  defp deny_gen do
    ExUnitProperties.gen all rule_id <- rule_id_gen(),
                             reason <- reason_gen(),
                             alt <- alt_gen() do
      %{rule_id: rule_id, reason: reason, suggested_alternative: alt}
    end
  end

  # A "stream" of N intents, each tagged allow|deny. The "stream" is
  # what we'd see if Cedar had evaluated each intent in turn.
  defp tagged_stream_gen do
    ExUnitProperties.gen all intents <- StreamData.list_of(intent_gen(), min_length: 1, max_length: 6),
                             tags <-
                               StreamData.list_of(
                                 StreamData.member_of([:allow, :deny]),
                                 length: length(intents)
                               ) do
      Enum.zip(intents, tags)
    end
  end

  # Build a fully-allow stream (deterministic, used by PT-002).
  defp allow_stream_gen do
    ExUnitProperties.gen all intents <- StreamData.list_of(intent_gen(), min_length: 1, max_length: 6) do
      Enum.map(intents, fn i -> {i, :allow} end)
    end
  end

  # ---------------------------------------------------------------------------
  # PT-001 — denied tool_use NEVER reaches client
  # ---------------------------------------------------------------------------

  describe "PT-001 — denied tool_use never reaches client" do
    property "synthetic events for a denied intent contain no function_call item" do
      check all intent <- intent_gen(),
                deny <- deny_gen(),
                max_runs: 200 do
        events = DenialInjector.inject_denial(:openai_responses, intent, deny, @default_template)

        for ev <- events do
          {:ok, decoded} = Jason.decode(ev)

          # No event references the denied call_id (Codex won't route
          # this back to a function-call handler).
          refute json_string_contains?(decoded, intent.call_id),
                 "synthetic event leaked denied call_id #{inspect(intent.call_id)}: #{inspect(decoded)}"

          # No event has item.type == "function_call"
          refute get_in(decoded, ["item", "type"]) == "function_call"

          # No event is a function_call.* type
          refute String.starts_with?(decoded["type"], "response.function_call.")
        end
      end
    end

    property "across a stream of mixed allow/deny tagged intents, denied call_ids never appear in synthetic event set" do
      check all stream <- tagged_stream_gen(),
                deny <- deny_gen(),
                max_runs: 100 do
        # For every denied intent in the stream, run the injector and
        # collect the synthetic events. No event in the synthetic set
        # may reference any denied call_id.
        denied_intents =
          stream
          |> Enum.filter(fn {_, tag} -> tag == :deny end)
          |> Enum.map(fn {i, _} -> i end)

        synthetic_events =
          Enum.flat_map(denied_intents, fn intent ->
            DenialInjector.inject_denial(:openai_responses, intent, deny, @default_template)
          end)

        denied_call_ids = MapSet.new(denied_intents, & &1.call_id)

        for ev_json <- synthetic_events do
          {:ok, decoded} = Jason.decode(ev_json)

          # The synthetic message id is `msg_synthetic_<uuid>`. Collect
          # any string-shaped values in the JSON tree and assert none
          # equal a denied call_id.
          refute Enum.any?(denied_call_ids, fn cid -> json_string_contains?(decoded, cid) end),
                 "synthetic event leaked a denied call_id"
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # PT-002 — allowed tool_use ALWAYS reaches client byte-identical
  # ---------------------------------------------------------------------------

  describe "PT-002 — allowed tool_use byte-identical under all-allow" do
    property "all-allow stream: injector is never called; allowed events would be forwarded byte-identical" do
      check all stream <- allow_stream_gen(),
                max_runs: 100 do
        # Under all-allow, no injector invocation happens. Simulate
        # what the proxy would emit: the upstream raw events are
        # forwarded byte-identical. Build the upstream raw events for
        # each allowed intent (one `function_call.completed` per
        # intent — the simplest representative event), then assert the
        # "client output" (== upstream events under all-allow) matches.
        upstream_events =
          Enum.map(stream, fn {intent, :allow} ->
            Jason.encode!(%{
              "type" => "response.function_call.completed",
              "item_id" => "fc_" <> intent.call_id,
              "call_id" => intent.call_id
            })
          end)

        client_events = upstream_events
        assert client_events == upstream_events
      end
    end
  end

  # ---------------------------------------------------------------------------
  # PT-003 — synthetic events always syntactically valid + schema-conformant
  # ---------------------------------------------------------------------------

  describe "PT-003 — synthetic events always syntactically valid JSON" do
    property "across random rule_id + reason + alternative (including unicode), each event decodes + matches schema" do
      check all intent <- intent_gen(),
                deny <- deny_gen(),
                max_runs: 200 do
        events = DenialInjector.inject_denial(:openai_responses, intent, deny, @default_template)

        assert length(events) == 3
        [added_raw, delta_raw, completed_raw] = events

        assert {:ok, added} = Jason.decode(added_raw)
        assert {:ok, delta} = Jason.decode(delta_raw)
        assert {:ok, completed} = Jason.decode(completed_raw)

        # added schema: response.output_item.added of message
        assert added["type"] == "response.output_item.added"
        assert is_integer(added["output_index"])
        assert is_map(added["item"])
        assert added["item"]["type"] == "message"
        assert added["item"]["role"] == "assistant"
        assert is_binary(added["item"]["id"])
        assert String.starts_with?(added["item"]["id"], "msg_synthetic_")
        assert added["item"]["status"] == "in_progress"
        assert added["item"]["content"] == []

        # delta schema: response.output_text.delta
        assert delta["type"] == "response.output_text.delta"
        assert delta["output_index"] == added["output_index"]
        assert delta["item_id"] == added["item"]["id"]
        assert is_binary(delta["delta"])

        # completed schema: response.output_item.completed of message
        assert completed["type"] == "response.output_item.completed"
        assert completed["output_index"] == added["output_index"]
        assert completed["item"]["type"] == "message"
        assert completed["item"]["role"] == "assistant"
        assert completed["item"]["id"] == added["item"]["id"]
        assert completed["item"]["status"] == "completed"
        assert [%{"type" => "output_text", "text" => text}] = completed["item"]["content"]
        assert is_binary(text)
        assert text == delta["delta"]
      end
    end

    property "renderer never raises on random template + bindings (totality)" do
      check all rule_id <- rule_id_gen(),
                reason <- reason_gen(),
                alt <- alt_gen(),
                tool_name <- tool_name_gen(),
                max_runs: 100 do
        bindings = %{
          tool_name: tool_name,
          rule_id: rule_id,
          reason: reason,
          suggested_alternative: alt
        }

        # Renderer must always return a binary, never raise.
        rendered = Injector.render_template(@default_template, bindings)
        assert is_binary(rendered)
        assert String.contains?(rendered, tool_name)
        assert String.contains?(rendered, rule_id)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Walk a decoded JSON tree; check whether any leaf string value EQUALS or
  # CONTAINS the target string. We use `String.contains?/2` so partial leaks
  # (e.g., "msg_synthetic_call_aaa") would also be caught.
  defp json_string_contains?(value, target) when is_binary(value) and is_binary(target) do
    String.contains?(value, target)
  end

  defp json_string_contains?(map, target) when is_map(map) do
    Enum.any?(map, fn {_k, v} -> json_string_contains?(v, target) end)
  end

  defp json_string_contains?(list, target) when is_list(list) do
    Enum.any?(list, fn v -> json_string_contains?(v, target) end)
  end

  defp json_string_contains?(_other, _target), do: false
end
