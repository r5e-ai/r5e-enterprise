defmodule Recurse.Gateway.LlmProxy.DenialInjector.OpenaiResponses do
  @moduledoc """
  OpenAI Responses API denial-injector implementation
  (Spec 009 Phase 3 Sub-3.5 / T047, T048).

  Spec source: `specs/009-llm-api-proxy/contracts/denial_injector.md`
  §"OpenAI Responses API".

  ## Behaviour summary

  Given a denied `ToolUseIntent` (i.e., a `function_call` item the
  Cedar gate rejected) + the deny payload + a denial template, emit
  the **3-event synthetic-message sequence** that REPLACES the
  upstream's `function_call` events:

      1. response.output_item.added (item.type=message, status=in_progress)
      2. response.output_text.delta (the rendered denial text)
      3. response.output_item.completed (item.type=message,
         status=completed, with content[output_text])

  The Codex agent loop interprets this as the model deciding to send
  a text message instead of calling a tool — agent loop continues
  naturally without a `function_call` -> `function_call_output`
  round-trip.

  ## output_index preservation

  Per spec, the synthetic events SHOULD reuse the `output_index` of
  the suppressed `response.output_item.added` (function_call) event.
  The current `ToolUseIntent` struct does NOT carry `output_index`
  (the parser captures byte spans + event indices but not the
  semantic output_index field — that's a Codex-numbering concept).

  We accept `output_index:` via the `opts` keyword. The proxy can
  thread it from the parser's accumulator state when wiring this in.
  Default: 0 — the agent loop tolerates index reuse / collision
  because synthetic events also reuse the prior reasoning/message
  output_index slots (R-007 edge case: reasoning items interleave
  with function_calls, so output_index is not strictly monotonic in
  upstream traffic anyway).

  ## msg_synthetic_<uuid>

  The 3 events share one `msg_synthetic_<uuid>` id (generated once
  per `inject_denial/4` call). The id format is
  `msg_synthetic_<base64url-encoded-16-random-bytes>` — opaque to the
  client, distinct from any upstream-issued `msg_*` id.

  ## Iron-Law check (`elixir:elixir-thinking`)

  Pure-functional. No process. No state. Each call is independent.

  ## Totality

  `inject_denial/4` is total — no raises on any input. JSON encoding
  uses `Jason.encode!/1` only on maps we just constructed (no
  reflective input), so the bang is safe.
  """

  @behaviour Recurse.Gateway.LlmProxy.DenialInjector

  alias Recurse.Gateway.LlmProxy.DenialInjector
  alias Recurse.Gateway.LlmProxy.DenialInjector.Template
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  # ---------------------------------------------------------------------------
  # Behaviour callback
  # ---------------------------------------------------------------------------

  @impl DenialInjector
  @spec inject_denial(
          ToolUseIntent.t(),
          DenialInjector.deny_payload(),
          String.t(),
          keyword()
        ) :: [binary()]
  def inject_denial(%ToolUseIntent{} = intent, deny, template, opts \\ [])
      when is_map(deny) and is_binary(template) and is_list(opts) do
    output_index = Keyword.get(opts, :output_index, 0)
    msg_id = synthetic_message_id()

    # Audit-context bindings — radical-transparency over policy (R5E-102);
    # the renderer moved to `DenialInjector.Template` when the Anthropic
    # injector became its second consumer (spec 012 S4).
    denial_text = Keyword.get(opts, :denial_text) || Template.render(intent, deny, template, opts)

    [
      Jason.encode!(%{
        "type" => "response.output_item.added",
        "output_index" => output_index,
        "item" => %{
          "type" => "message",
          "role" => "assistant",
          "id" => msg_id,
          "status" => "in_progress",
          "content" => []
        }
      }),
      Jason.encode!(%{
        "type" => "response.output_text.delta",
        "output_index" => output_index,
        "item_id" => msg_id,
        "delta" => denial_text
      }),
      Jason.encode!(%{
        "type" => "response.output_item.completed",
        "output_index" => output_index,
        "item" => %{
          "type" => "message",
          "role" => "assistant",
          "id" => msg_id,
          "status" => "completed",
          "content" => [
            %{"type" => "output_text", "text" => denial_text}
          ]
        }
      })
    ]
  end

  # ---------------------------------------------------------------------------
  # Template renderer (T048) — now `DenialInjector.Template`; kept here as
  # a delegate for existing callers and doctests.
  # ---------------------------------------------------------------------------

  @doc """
  Render the denial template with variable substitution. See
  `Recurse.Gateway.LlmProxy.DenialInjector.Template.render_template/2`.

      iex> Recurse.Gateway.LlmProxy.DenialInjector.OpenaiResponses.render_template(
      ...>   "Tool '{tool_name}' blocked: {reason}.{? Alt: {suggested_alternative}}",
      ...>   %{tool_name: "shell", rule_id: "r1", reason: "denied", suggested_alternative: nil}
      ...> )
      "Tool 'shell' blocked: denied."

      iex> Recurse.Gateway.LlmProxy.DenialInjector.OpenaiResponses.render_template(
      ...>   "Tool '{tool_name}' blocked: {reason}.{? Alt: {suggested_alternative}}",
      ...>   %{tool_name: "shell", rule_id: "r1", reason: "denied", suggested_alternative: "py"}
      ...> )
      "Tool 'shell' blocked: denied. Alt: py"
  """
  @spec render_template(String.t(), map()) :: String.t()
  defdelegate render_template(template, bindings), to: Template

  # ---------------------------------------------------------------------------
  # Synthetic message id
  # ---------------------------------------------------------------------------

  # 16 random bytes, base64url-encoded (no padding) → 22 chars.
  # Format: `msg_synthetic_<22-char-base64url>`. Opaque to client.
  defp synthetic_message_id do
    suffix =
      :crypto.strong_rand_bytes(16)
      |> Base.url_encode64(padding: false)

    "msg_synthetic_" <> suffix
  end
end
