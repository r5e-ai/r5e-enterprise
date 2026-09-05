defmodule Recurse.Providers.Repo.Migrations.ParserDriftEvents do
  @moduledoc """
  Spec 012 S4 (plan §10 "parser drift is a product surface").

  Creates `parser_drift_events` — one row per `(tenant_id, api_format,
  event_type)` the LLM-proxy parsers reported as unrecognised. A parser
  that meets an event / content-block / delta type outside the set it is
  exhaustive for forwards the bytes unchanged, counts it on the
  attestation (`parse.events_unhandled`), and upserts here so the
  dashboard's "Parser drift" panel and `/readyz` (`parser_drift:
  n_new_since_boot`) can surface it.

  `sample_redacted` is keys-only (`keys=a,b,c`, ≤ 200 bytes) — never
  payload content. `count` accumulates across calls; `first_seen` /
  `last_seen` bracket the observations.
  """

  use Ecto.Migration

  def change do
    create table(:parser_drift_events) do
      add :tenant_id, :string, null: false
      add :api_format, :string, null: false
      add :event_type, :string, null: false
      add :sample_redacted, :string
      add :first_seen, :utc_datetime_usec, null: false
      add :last_seen, :utc_datetime_usec, null: false
      add :count, :bigint, null: false, default: 1

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:parser_drift_events, [:tenant_id, :api_format, :event_type],
             name: :parser_drift_events_tenant_format_type_index
           )

    create index(:parser_drift_events, [:tenant_id, "last_seen DESC"],
             name: :parser_drift_events_tenant_last_seen_index
           )

    create constraint(:parser_drift_events, :parser_drift_events_count_check, check: "count >= 1")

    create constraint(:parser_drift_events, :parser_drift_events_sample_len_check,
             check: "sample_redacted IS NULL OR octet_length(sample_redacted) <= 200"
           )
  end
end
