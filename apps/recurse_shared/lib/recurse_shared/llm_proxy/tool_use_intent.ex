defmodule Recurse.Shared.LlmProxy.ToolUseIntent do
  @moduledoc """
  Canonical, provider-agnostic representation of a single `tool_use` intent
  extracted from an LLM response stream.

  Spec source of truth: `specs/009-llm-api-proxy/contracts/tool_use_intent.md`.

  Per-provider parsers (Phase 3+) decode their wire-format-specific event
  taxonomies into instances of this struct. Downstream consumers — the Cedar
  gate (Phase 3), the denial injector (Phase 4), and the attestation emitter
  (Phase 5) — see only this canonical shape, so the proxy core stays
  provider-neutral.

  ## Invariants (from contract)

    * **I-001** — `tool_args_hash` is `:crypto.hash(:sha256, ...)` over either
      `Jason.encode!(tool_args)` (when `tool_args` is a decoded map) or the
      original raw JSON bytes (when `tool_args` is the `:too_large` sentinel).
      The sentinel atom is NEVER itself fed through `Jason.encode!/1` — that
      would hash the literal string `"too_large"`, which would collide
      across every oversize argument blob and silently destroy auditability.
    * **I-002** — `provider_event_span` precisely identifies the byte range +
      raw event indices that constitute the intent in the upstream wire
      stream. The denial injector reads this span to know what to suppress.
    * **I-003** — `call_id` is provider-issued (e.g. OpenAI's `"call_abc123"`).
      We do NOT generate it locally; round-tripping the upstream id preserves
      correlation with the provider's own audit logs and the agent's
      `function_call_output` echo.
    * **I-004** — `parallel_index` is the position in the
      `parallel_tool_calls` array when the provider is emitting parallel
      tool calls; `nil` for non-parallel (sequential) calls.

  ## Construction

  Use `new/1` to build instances. It computes `tool_args_hash` and
  `tool_args_size_bytes` from `tool_args` + the `:raw_json` option, and
  defaults `extracted_at` to `DateTime.utc_now/1` when not supplied.
  """

  @typedoc """
  Byte/event span that identifies which raw upstream events constituted this
  intent. Used by the denial injector to know exactly what to splice out
  before substituting a synthetic deny payload.
  """
  @type provider_span :: %{
          start_byte_offset: non_neg_integer(),
          end_byte_offset: non_neg_integer(),
          event_indices: [non_neg_integer()]
        }

  @type t :: %__MODULE__{
          call_id: String.t(),
          tool_name: String.t(),
          tool_args: map() | :too_large,
          tool_args_hash: binary(),
          tool_args_size_bytes: pos_integer(),
          parallel_index: non_neg_integer() | nil,
          provider_event_span: provider_span(),
          extracted_at: DateTime.t()
        }

  @enforce_keys [
    :call_id,
    :tool_name,
    :tool_args,
    :tool_args_hash,
    :tool_args_size_bytes,
    :provider_event_span,
    :extracted_at
  ]

  defstruct [
    :call_id,
    :tool_name,
    :tool_args,
    :tool_args_hash,
    :tool_args_size_bytes,
    :parallel_index,
    :provider_event_span,
    :extracted_at
  ]

  @typedoc """
  Constructor input. `tool_args` is either:

    * a decoded map (the parser successfully `Jason.decode/1`d the
      arguments JSON), in which case `tool_args_hash` is computed over
      `Jason.encode!(tool_args)`; OR
    * the `:too_large` sentinel atom, in which case the caller MUST also
      supply `:raw_json` carrying the original argument bytes — the hash
      is computed over those raw bytes per I-001.
  """
  @type new_input :: %{
          required(:call_id) => String.t(),
          required(:tool_name) => String.t(),
          required(:tool_args) => map() | :too_large,
          required(:provider_event_span) => provider_span(),
          optional(:parallel_index) => non_neg_integer() | nil,
          optional(:extracted_at) => DateTime.t(),
          optional(:raw_json) => binary()
        }

  @doc """
  Build a `t:t/0` from parsed parser output.

  Computes:

    * `tool_args_hash` — SHA-256 over canonical bytes per I-001.
    * `tool_args_size_bytes` — `byte_size/1` of those same bytes.

  Defaults:

    * `parallel_index` defaults to `nil` (non-parallel call).
    * `extracted_at` defaults to `DateTime.utc_now/1` (microsecond precision).

  ## Examples

      iex> {:ok, intent} = Recurse.Shared.LlmProxy.ToolUseIntent.new(%{
      ...>   call_id: "call_abc",
      ...>   tool_name: "shell",
      ...>   tool_args: %{"cmd" => "ls"},
      ...>   provider_event_span: %{
      ...>     start_byte_offset: 0, end_byte_offset: 100, event_indices: [3, 4]
      ...>   }
      ...> })
      iex> intent.call_id
      "call_abc"
      iex> byte_size(intent.tool_args_hash)
      32
  """
  @spec new(new_input()) :: {:ok, t()} | {:error, atom()}
  def new(input) when is_map(input) do
    with {:ok, call_id} <- fetch_required(input, :call_id, &is_binary/1),
         {:ok, tool_name} <- fetch_required(input, :tool_name, &is_binary/1),
         {:ok, span} <- fetch_required(input, :provider_event_span, &valid_span?/1),
         {:ok, canonical_bytes} <- canonicalize_args(input) do
      args = Map.fetch!(input, :tool_args)
      hash = :crypto.hash(:sha256, canonical_bytes)
      size = byte_size(canonical_bytes)
      parallel_index = Map.get(input, :parallel_index)
      extracted_at = Map.get_lazy(input, :extracted_at, fn -> DateTime.utc_now() end)

      {:ok,
       %__MODULE__{
         call_id: call_id,
         tool_name: tool_name,
         tool_args: args,
         tool_args_hash: hash,
         tool_args_size_bytes: size,
         parallel_index: parallel_index,
         provider_event_span: span,
         extracted_at: extracted_at
       }}
    end
  end

  defp fetch_required(map, key, validate?) do
    case Map.fetch(map, key) do
      {:ok, value} ->
        if validate?.(value), do: {:ok, value}, else: {:error, {:invalid, key}}

      :error ->
        {:error, {:missing, key}}
    end
  end

  defp valid_span?(%{
         start_byte_offset: s,
         end_byte_offset: e,
         event_indices: indices
       })
       when is_integer(s) and s >= 0 and is_integer(e) and e >= s and is_list(indices) do
    Enum.all?(indices, &(is_integer(&1) and &1 >= 0))
  end

  defp valid_span?(_), do: false

  # I-001: when tool_args is a decoded map, hash Jason.encode!(map).
  # When :too_large, hash the original raw JSON bytes (NOT Jason.encode!(:too_large)).
  defp canonicalize_args(%{tool_args: :too_large} = input) do
    case Map.fetch(input, :raw_json) do
      {:ok, raw} when is_binary(raw) and byte_size(raw) > 0 -> {:ok, raw}
      _ -> {:error, {:missing, :raw_json}}
    end
  end

  defp canonicalize_args(%{tool_args: args}) when is_map(args) do
    {:ok, Jason.encode!(args)}
  end

  defp canonicalize_args(_), do: {:error, {:invalid, :tool_args}}
end
