defmodule Recurse.Gateway.LlmProxy.ParserDriftTest do
  @moduledoc """
  Drift store tests (spec 012 S4, plan §10): the providers-side upsert
  (`Recurse.Providers.ParserDrift`) and the gateway-side recorder +
  boot counter (`Recurse.Gateway.LlmProxy.ParserDrift`).

  `async: false` — the boot counter is node-global.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.LlmProxy.ParserDrift
  alias Recurse.Providers.ParserDrift, as: Store
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.ParserDriftEvent

  @tenant "01TEN_S4_DRIFT"

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    ParserDrift.reset_counter()
    :ok
  end

  describe "Recurse.Providers.ParserDrift.record/1" do
    test "first sighting inserts; later sightings bump count and last_seen, keep the sample" do
      t0 = ~U[2026-09-02 10:00:00.000000Z]
      t1 = ~U[2026-09-02 10:05:00.000000Z]

      assert {:ok, :new, row} =
               Store.record(%{
                 tenant_id: @tenant,
                 api_format: "anthropic_messages",
                 event_type: "block:widget",
                 sample_redacted: "keys=payload,type",
                 seen_at: t0
               })

      assert row.count == 1
      assert row.first_seen == t0

      assert {:ok, :seen, row2} =
               Store.record(%{
                 tenant_id: @tenant,
                 api_format: "anthropic_messages",
                 event_type: "block:widget",
                 sample_redacted: "keys=other",
                 seen_at: t1
               })

      assert row2.id == row.id
      assert row2.count == 2
      assert row2.first_seen == t0
      assert row2.last_seen == t1
      assert row2.sample_redacted == "keys=payload,type"

      assert [%ParserDriftEvent{event_type: "block:widget", count: 2}] = Store.list(@tenant)
    end

    test "samples are truncated to 200 bytes and the row is per tenant/format/type" do
      long = String.duplicate("k", 500)

      assert {:ok, :new, row} =
               Store.record(%{
                 tenant_id: @tenant,
                 api_format: "openai_responses",
                 event_type: "event:x",
                 sample_redacted: long
               })

      assert byte_size(row.sample_redacted) == 200

      assert {:ok, :new, _} =
               Store.record(%{
                 tenant_id: @tenant,
                 api_format: "anthropic_messages",
                 event_type: "event:x"
               })

      assert length(Store.list(@tenant)) == 2

      assert [%{api_format: "openai_responses"}] =
               Store.list(@tenant, api_format: "openai_responses")

      assert Store.list("someone-else") == []
    end

    test "invalid sightings are rejected without raising" do
      assert {:error, _} = Store.record(%{tenant_id: @tenant, api_format: "x", event_type: ""})
      assert {:error, :invalid_sighting} = Store.record(%{})
    end
  end

  describe "Recurse.Gateway.LlmProxy.ParserDrift.record_summary/3" do
    test "records every unhandled type from a parser summary and counts new ones since boot" do
      summary = %{
        events_total: 9,
        events_unhandled: 3,
        unhandled_types: ["block:widget", "event:telemetry"],
        unhandled_samples: %{
          "block:widget" => "keys=payload,type",
          "event:telemetry" => "keys=k,type"
        }
      }

      assert ParserDrift.new_since_boot() == 0
      assert ParserDrift.record_summary(@tenant, :anthropic_messages, summary) == 2
      assert ParserDrift.new_since_boot() == 2

      # Same types again: seen, not new.
      assert ParserDrift.record_summary(@tenant, :anthropic_messages, summary) == 0
      assert ParserDrift.new_since_boot() == 2

      rows = Store.list(@tenant)
      assert Enum.map(rows, & &1.event_type) |> Enum.sort() == ["block:widget", "event:telemetry"]
      assert Enum.all?(rows, &(&1.count == 2 and &1.api_format == "anthropic_messages"))

      assert Enum.find(rows, &(&1.event_type == "block:widget")).sample_redacted ==
               "keys=payload,type"
    end

    test "a summary without unhandled types is a no-op" do
      assert ParserDrift.record_summary(@tenant, :anthropic_messages, %{events_unhandled: 0}) == 0
      assert ParserDrift.record_summary(nil, :anthropic_messages, %{}) == 0
      assert Store.list(@tenant) == []
    end
  end
end
