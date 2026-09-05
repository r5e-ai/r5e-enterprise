defmodule Recurse.Shared.CorrelationId do
  @moduledoc """
  `X-Correlation-ID` helper per FR-018.

  Every request accepts `X-Correlation-ID` (ULID preferred). If absent,
  the Gateway generates one. The generated value propagates to logs,
  attestation envelopes, error envelopes, and Data-Plane response
  annotations.

  This module is intentionally thin — it is a named wrapper around
  `Recurse.Shared.Ulid.generate/0` so that call sites document their
  intent ("I'm minting a correlation ID", not just "I'm minting a ULID").
  """

  alias Recurse.Shared.Ulid

  @doc """
  Generate a new correlation ID (canonical ULID string).
  """
  @spec generate() :: String.t()
  def generate, do: Ulid.generate()

  @doc """
  Validate an inbound correlation-ID header value.

  Per FR-018 the wire contract says "ULID preferred" — NOT "ULID required."
  External distributed-tracing systems (Jaeger, Zipkin, OpenTelemetry,
  AWS X-Ray, etc.) send their own trace-id shapes; rejecting them would
  break cross-system correlation, which is the whole point of
  `X-Correlation-ID`. So this function accepts any syntactically
  reasonable identifier and classifies it:

    * `{:ok, :ulid, canonical_string}` — value is a valid ULID; returned
      upper-cased (canonical form).
    * `{:ok, :foreign, original_string}` — value is non-ULID but within
      reasonable syntactic bounds (printable ASCII, length 8..128); the
      Gateway plug layer SHOULD still propagate it through the request
      and into attestations, while emitting telemetry so operators can
      see how much cross-system correlation is flowing.
    * `:error` — value is nil, empty, too long, or contains
      non-printable bytes. Callers mint a fresh ID via `generate/0`.

  Speckit-pr-review iteration-3 F001 caught this: the earlier
  implementation returned `:error` for anything non-ULID, silently
  breaking external distributed tracing.
  """
  @spec validate(String.t() | nil) ::
          {:ok, :ulid, String.t()} | {:ok, :foreign, String.t()} | :error
  def validate(nil), do: :error

  def validate(value) when is_binary(value) do
    cond do
      Ulid.valid?(value) -> {:ok, :ulid, String.upcase(value)}
      foreign_ok?(value) -> {:ok, :foreign, value}
      true -> :error
    end
  end

  def validate(_), do: :error

  # Reasonable bounds for a distributed-tracing identifier: printable
  # ASCII (no control chars, no multi-byte unicode) between 8 and 128
  # bytes. Covers Jaeger (32-hex), W3C traceparent (55-char), X-Ray
  # (35-char), most custom systems. Rejects empty, huge, or binary-junk.
  defp foreign_ok?(value) do
    size = byte_size(value)
    size >= 8 and size <= 128 and printable_ascii?(value)
  end

  defp printable_ascii?(<<>>), do: true
  defp printable_ascii?(<<c, rest::binary>>) when c in 0x20..0x7E, do: printable_ascii?(rest)
  defp printable_ascii?(_), do: false

  @doc """
  Header name constant for the Recurse-standard correlation ID.
  """
  @spec header_name() :: String.t()
  def header_name, do: "x-correlation-id"
end
