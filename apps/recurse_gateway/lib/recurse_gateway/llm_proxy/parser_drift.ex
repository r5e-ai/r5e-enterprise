defmodule Recurse.Gateway.LlmProxy.ParserDrift do
  @moduledoc """
  Gateway-side parser-drift recorder (spec 012 S4, plan §10).

  After every attested LLM call the proxy hands the parser's summary
  here. Each `unhandled_types` discriminator (`event:<type>`,
  `block:<type>`, `delta:<type>`, `output_item:<type>`) is upserted into
  `parser_drift_events` through `Recurse.Providers.ParserDrift.record/1`
  with the parser's keys-only sample. Discriminators inserted for the
  first time since this node booted bump an `:atomics` counter that
  `/readyz` reports as `parser_drift`, so an operator notices new drift
  without opening the dashboard.

  Recording never raises and never blocks the client stream: it runs
  after the response has been fully forwarded, and any store failure is
  logged and dropped (the attestation already carries the counts).
  """

  alias Recurse.Providers.ParserDrift, as: Store

  require Logger

  @counter_key {__MODULE__, :new_since_boot}

  @doc """
  Record every unhandled type in `summary` for `tenant_id` /
  `api_format`. Returns the number of discriminators that were new to
  the store.
  """
  @spec record_summary(String.t(), atom() | String.t(), map()) :: non_neg_integer()
  def record_summary(tenant_id, api_format, summary)
      when is_binary(tenant_id) and is_map(summary) do
    types = Map.get(summary, :unhandled_types) || []
    samples = Map.get(summary, :unhandled_samples) || %{}
    format = to_string(api_format)
    now = DateTime.utc_now()

    Enum.count(types, fn type ->
      sighting = %{
        tenant_id: tenant_id,
        api_format: format,
        event_type: type,
        sample_redacted: Map.get(samples, type),
        seen_at: now
      }

      record_one(sighting) == :new
    end)
  end

  def record_summary(_tenant_id, _api_format, _summary), do: 0

  defp record_one(sighting) do
    case Store.record(sighting) do
      {:ok, :new, _row} ->
        bump()
        :new

      {:ok, :seen, _row} ->
        :seen

      {:error, reason} ->
        Logger.warning(fn ->
          "parser_drift: store write failed type=#{inspect(sighting.event_type)} reason=#{inspect(reason)}"
        end)

        :error
    end
  end

  @doc "Distinct drift discriminators first recorded since this node booted."
  @spec new_since_boot() :: non_neg_integer()
  def new_since_boot, do: :persistent_term.get(@counter_key, 0)

  @doc "Test seam: reset the boot counter."
  @spec reset_counter() :: :ok
  def reset_counter, do: :persistent_term.put(@counter_key, 0)

  # A `:persistent_term` write per NEW discriminator — bounded by the number
  # of distinct types the parsers have not seen since boot (normally zero),
  # so the global-GC cost of the write never lands on the hot path. Two
  # concurrent first sightings could lose one increment; the store row is
  # the record, this is the operator's glance.
  defp bump, do: :persistent_term.put(@counter_key, new_since_boot() + 1)
end
