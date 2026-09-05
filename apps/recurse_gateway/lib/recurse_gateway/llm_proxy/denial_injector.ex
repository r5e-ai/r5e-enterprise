defmodule Recurse.Gateway.LlmProxy.DenialInjector do
  @moduledoc """
  Behaviour + dispatcher for per-API denial-event synthesis
  (Spec 009 Phase 3 Sub-3.5 / T046).

  Spec source of truth: `specs/009-llm-api-proxy/contracts/denial_injector.md`.

  ## Purpose

  When `Recurse.Gateway.Fold.Admission.admit_tool/3` returns
  `{:deny, deny_payload}` for a `ToolUseIntent`, the proxy needs to
  rewrite the response stream so the client receives a *structured
  denial in the upstream's expected format*. The agent loop sees the
  denial as model output (assistant text), continues iteration
  naturally, and never receives a `tool_use` event for the denied
  call.

  The rewrite shape is **format-faithful per upstream API** (R-003):
  for OpenAI Responses, denial = synthetic `message` item; for
  Anthropic Messages, denial = synthetic `text` content_block; etc.
  This module is the dispatcher; per-API impls (`./denial/*.ex`)
  produce the actual synthetic event bytes.

  ## Constitution Principle VII (Interface-First)

  Phase 3 ships only the OpenAI Responses impl (Codex CLI's path).
  Phase 6 brings 3 more impls (Anthropic Messages, OpenAI Chat
  Completions, Google Gemini). Defining the behaviour upfront prevents
  inlining OpenAI-specific event suppression at the proxy call sites:
  the proxy speaks `DenialInjector.inject_denial/4` and the per-API
  impl is selected by the dispatcher.

  ## Iron-Law check (`elixir:elixir-thinking`)

  No GenServer. The injector is purely functional: takes intent +
  deny payload + template, returns a list of synthetic event bytes.
  No state, no concurrency, no fault isolation needed.

  ## API

      @spec inject_denial(
              api_format :: atom(),
              intent :: ToolUseIntent.t(),
              deny :: deny_payload(),
              template :: String.t()
            ) :: [synthetic_event :: binary()]

  Optional opts (impl-specific) include `:output_index` (preserve the
  output_index from the suppressed event, per spec).
  """

  alias Recurse.Gateway.LlmProxy.DenialInjector.AnthropicMessages, as: AnthropicImpl
  alias Recurse.Gateway.LlmProxy.DenialInjector.OpenaiResponses, as: OpenaiImpl
  alias Recurse.Gateway.LlmProxy.DenialInjector.Template
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @typedoc """
  Decision payload in `Recurse.Gateway.LlmProxy.CedarToolUseGate`'s
  `{:deny, deny_payload()}` return — the shape consumed by the
  injector.
  """
  @type deny_payload :: %{
          required(:rule_id) => String.t(),
          required(:reason) => String.t(),
          required(:suggested_alternative) => String.t() | nil
        }

  @typedoc """
  api_format atoms recognised by the dispatcher. The
  `LlmProviderConfig.api_format` Ecto.Enum produces values from this
  set. Phase-3 wires only `:openai_responses`; the others are reserved
  for Phase-6 polish and currently fall through to `:not_implemented`.
  """
  @type api_format ::
          :openai_responses
          | :openai_chat_completions
          | :anthropic_messages
          | :google_gemini

  @doc """
  Synthesise the per-API denial-event sequence that REPLACES the
  upstream's tool_use events for the denied intent.

  Returns a list of binary events ready to be SSE-framed (`data: <ev>\\n\\n`)
  or pushed as a WS text frame (one event per frame). The list is
  ordered: emit them in the returned order to preserve the client's
  agent-loop interpretation.

  Per-API impls MUST be total — no raises — so callers can map without
  rescue. Unknown api_format returns `[]` (the dispatcher logs).
  """
  @callback inject_denial(
              intent :: ToolUseIntent.t(),
              deny :: deny_payload(),
              template :: String.t(),
              opts :: keyword()
            ) :: [binary()]

  @doc """
  Dispatcher: select per-API impl via `api_format`, invoke the
  behaviour callback. Phase-3 wires `:openai_responses`; other
  api_formats return `[]` (Phase-6 will implement them).
  """
  @spec inject_denial(
          api_format(),
          ToolUseIntent.t(),
          deny_payload(),
          String.t(),
          keyword()
        ) :: [binary()]
  def inject_denial(api_format, intent, deny, template, opts \\ [])

  def inject_denial(:openai_responses, %ToolUseIntent{} = intent, deny, template, opts) do
    OpenaiImpl.inject_denial(intent, deny, template, opts)
  end

  # Spec 012 S4 — Claude Code's wire format.
  def inject_denial(:anthropic_messages, %ToolUseIntent{} = intent, deny, template, opts) do
    AnthropicImpl.inject_denial(intent, deny, template, opts)
  end

  def inject_denial(_other, %ToolUseIntent{} = _intent, _deny, _template, _opts) do
    # openai_chat_completions, google_gemini — not yet implemented.
    # Returning [] (no synthetic events) means the proxy will fall
    # back to "log + suppress original frames" with no replacement
    # text — agent loop sees nothing for the denied call, may stall.
    []
  end

  @doc """
  Render only the denial text (the template with its bindings) for
  `intent`. Parsers that rewrite a non-streaming body themselves
  (`AnthropicMessages` JSON mode) receive this via `apply_verdict/4`'s
  `denial_text:` so the proxy renders once and the same wording lands
  in the receipt, the stream, and the body.
  """
  @spec render_text(api_format(), ToolUseIntent.t(), deny_payload(), String.t(), keyword()) ::
          String.t()
  def render_text(_api_format, %ToolUseIntent{} = intent, deny, template, opts \\ []) do
    Template.render(intent, deny, template, opts)
  end

  @doc """
  Frame one synthetic event for the client's SSE stream. The Anthropic
  SDK dispatches on the `event:` line (and drops frames without one);
  every other format uses bare `data:` frames.
  """
  @spec sse_frame(api_format(), binary()) :: binary()
  def sse_frame(:anthropic_messages, event_json) when is_binary(event_json),
    do: AnthropicImpl.sse_frame(event_json)

  def sse_frame(_api_format, event_json) when is_binary(event_json),
    do: "data: " <> event_json <> "\n\n"
end
