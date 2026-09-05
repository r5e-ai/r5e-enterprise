defmodule Recurse.Gateway.LlmProxy.DenialInjector.AnthropicMessages do
  @moduledoc """
  Anthropic Messages API denial-injector implementation (spec 012 S4;
  `specs/009-llm-api-proxy/contracts/denial_injector.md` §"Anthropic
  Messages").

  Given a denied `ToolUseIntent` (a `tool_use` content block the Cedar
  gate rejected) emit the three events that REPLACE the suppressed
  block in the stream:

      1. content_block_start  {index, content_block: {type: "text", text: ""}}
      2. content_block_delta  {index, delta: {type: "text_delta", text: <denial>}}
      3. content_block_stop   {index}

  ## Index reuse (parallel calls)

  The replacement block reuses the suppressed block's `index`
  (`opts[:output_index]`, supplied by the parser's `denial_opts/2`).
  The Anthropic SDKs accumulate content blocks by index, so replacing
  index N in place keeps the message's indices contiguous whether the
  denied block was the first, the last, or the only one of a parallel
  call; no re-indexing of the surviving blocks is needed.

  ## Valid content block, no `signature`

  Claude Code echoes every assistant block back verbatim on the next
  turn (`hook_denied_followup.request.json` shows the shape). A `text`
  block with only `type` + `text` round-trips; a `signature` (which
  only `thinking` blocks carry, and which the upstream validates) would
  make the next request fail with a 400. The injected block therefore
  never carries one.

  ## SSE framing

  The Anthropic SDK dispatches on the SSE `event:` line and silently
  drops frames without one, so `sse_frame/1` emits
  `event: <type>\\ndata: <json>\\n\\n`, with the type read from the event's
  own `"type"`.

  Pure-functional; total. JSON encoding runs only on maps this module
  constructs.
  """

  @behaviour Recurse.Gateway.LlmProxy.DenialInjector

  alias Recurse.Gateway.LlmProxy.DenialInjector
  alias Recurse.Gateway.LlmProxy.DenialInjector.Template
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @impl DenialInjector
  @spec inject_denial(ToolUseIntent.t(), DenialInjector.deny_payload(), String.t(), keyword()) ::
          [binary()]
  def inject_denial(%ToolUseIntent{} = intent, deny, template, opts \\ [])
      when is_map(deny) and is_binary(template) and is_list(opts) do
    index = Keyword.get(opts, :output_index, 0)
    text = Keyword.get(opts, :denial_text) || Template.render(intent, deny, template, opts)

    [
      Jason.encode!(%{
        "type" => "content_block_start",
        "index" => index,
        "content_block" => %{"type" => "text", "text" => ""}
      }),
      Jason.encode!(%{
        "type" => "content_block_delta",
        "index" => index,
        "delta" => %{"type" => "text_delta", "text" => text}
      }),
      Jason.encode!(%{"type" => "content_block_stop", "index" => index})
    ]
  end

  @doc """
  Frame one event JSON for the Anthropic SSE stream:
  `event: <type>\\ndata: <json>\\n\\n`.
  """
  @spec sse_frame(binary()) :: binary()
  def sse_frame(event_json) when is_binary(event_json) do
    type =
      case Jason.decode(event_json) do
        {:ok, %{"type" => t}} when is_binary(t) -> t
        _ -> "message"
      end

    "event: " <> type <> "\ndata: " <> event_json <> "\n\n"
  end
end
