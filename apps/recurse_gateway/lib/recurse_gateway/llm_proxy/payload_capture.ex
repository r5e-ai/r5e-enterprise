defmodule Recurse.Gateway.LlmProxy.PayloadCapture do
  @moduledoc """
  Bounded byte capture for the LLM proxy's request + response bodies
  (spec 012 S6b; spec 009 `streaming_proxy.md` "detached payloads").

  `BodyHasher` computes `prompt_hash` / `response_hash` while the bytes
  flow past and never keeps them. That leaves the signed hash pointing
  at bytes nobody retained (plan §16). This module sits next to the
  hasher: fed the same chunks in the same order, it keeps them so the
  emitter can put them in the StorageProvider under the hash the
  predicate commits to.

  ## Bounds (`R5E_RETAIN_PAYLOADS_MAX_BYTES`, default 8 MiB per direction)

  A capture that would exceed `max_bytes` drops what it holds and marks
  itself `:truncated`. A partial payload can never be checked against
  the hash, so storing a prefix would be evidence-shaped noise; the
  receipt instead records `payload_truncated: true` and no URI for that
  direction. Memory stays bounded at `max_bytes` per direction per
  in-flight call. Write-through to a temp file was considered and not
  chosen: the request body is already fully in memory (Plug reads it),
  and a response over the cap is the case where an operator raises the
  cap deliberately rather than one the proxy should absorb silently.

  ## Off switch (`R5E_RETAIN_PAYLOADS`, default false; compose sets true)

  `init/1` with `enabled?: false` yields a capture that ignores every
  `append/2` and reports `:disabled`. Payloads carry prompt content —
  the StorageProvider is the operator's own store — so production
  defaults to off and the quickstart opts in.

  ## Iron Law

  Plain functions over an immutable struct threaded through the proxy
  state, exactly like `BodyHasher`.
  """

  @default_max_bytes 8 * 1024 * 1024

  @type t :: %__MODULE__{
          enabled?: boolean(),
          max_bytes: non_neg_integer(),
          size: non_neg_integer(),
          chunks: [binary()],
          truncated?: boolean()
        }

  @typedoc """
  What the capture holds at close: the bytes, `:truncated` (cap
  exceeded — nothing kept), or `:disabled` (retention off).
  """
  @type result :: {:ok, binary()} | :truncated | :disabled

  defstruct enabled?: false, max_bytes: @default_max_bytes, size: 0, chunks: [], truncated?: false

  @doc """
  Start a capture. `opts`:

    * `:enabled?` — default `Application.get_env(:recurse_gateway, :retain_payloads?, false)`.
    * `:max_bytes` — default `Application.get_env(:recurse_gateway, :retain_payloads_max_bytes, 8 MiB)`.
  """
  @spec init(keyword()) :: t()
  def init(opts \\ []) do
    enabled? =
      Keyword.get_lazy(opts, :enabled?, fn ->
        Application.get_env(:recurse_gateway, :retain_payloads?, false) == true
      end)

    max_bytes =
      Keyword.get_lazy(opts, :max_bytes, fn ->
        Application.get_env(:recurse_gateway, :retain_payloads_max_bytes, @default_max_bytes)
      end)

    %__MODULE__{enabled?: enabled? == true, max_bytes: normalize_max(max_bytes)}
  end

  @doc "Append a chunk. No-op when disabled or already truncated."
  @spec append(t(), binary()) :: t()
  def append(%__MODULE__{enabled?: false} = capture, _bytes), do: capture
  def append(%__MODULE__{truncated?: true} = capture, _bytes), do: capture
  def append(capture, ""), do: capture

  def append(%__MODULE__{size: size, max_bytes: max} = capture, bytes) when is_binary(bytes) do
    if size + byte_size(bytes) > max do
      %{capture | chunks: [], size: 0, truncated?: true}
    else
      %{capture | chunks: [bytes | capture.chunks], size: size + byte_size(bytes)}
    end
  end

  @doc "Finish the capture."
  @spec result(t()) :: result()
  def result(%__MODULE__{enabled?: false}), do: :disabled
  def result(%__MODULE__{truncated?: true}), do: :truncated

  def result(%__MODULE__{chunks: chunks}),
    do: {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

  @doc "Default per-direction cap in bytes."
  @spec default_max_bytes() :: pos_integer()
  def default_max_bytes, do: @default_max_bytes

  defp normalize_max(n) when is_integer(n) and n >= 0, do: n
  defp normalize_max(_), do: @default_max_bytes
end
