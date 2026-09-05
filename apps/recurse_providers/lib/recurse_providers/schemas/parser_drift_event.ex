defmodule Recurse.Providers.Schemas.ParserDriftEvent do
  @moduledoc """
  Ecto schema for `parser_drift_events` (spec 012 S4, plan §10): one row
  per `(tenant_id, api_format, event_type)` an LLM-proxy parser reported
  as unrecognised.

  Migration: `priv/repo/migrations/20260902000002_parser_drift_events.exs`.
  Writer: `Recurse.Providers.ParserDrift.record/1` (upsert; `count` and
  `last_seen` advance on every sighting). `sample_redacted` is a
  keys-only string (`keys=a,b,c`, ≤ 200 bytes), never payload content.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @sample_max_bytes 200

  @derive {Jason.Encoder,
           only: [
             :id,
             :tenant_id,
             :api_format,
             :event_type,
             :sample_redacted,
             :first_seen,
             :last_seen,
             :count
           ]}

  schema "parser_drift_events" do
    field :tenant_id, :string
    field :api_format, :string
    field :event_type, :string
    field :sample_redacted, :string
    field :first_seen, :utc_datetime_usec
    field :last_seen, :utc_datetime_usec
    field :count, :integer, default: 1

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required [:tenant_id, :api_format, :event_type, :first_seen, :last_seen]

  @doc "Changeset for a fresh sighting (the upsert bumps `count` on conflict)."
  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(%__MODULE__{} = row, attrs) do
    row
    |> cast(attrs, [:tenant_id, :api_format, :event_type, :sample_redacted, :first_seen, :last_seen, :count])
    |> update_change(:sample_redacted, &truncate_sample/1)
    |> validate_required(@required)
    |> validate_length(:event_type, min: 1, max: 255)
    |> validate_number(:count, greater_than_or_equal_to: 1)
    |> unique_constraint([:tenant_id, :api_format, :event_type],
      name: :parser_drift_events_tenant_format_type_index
    )
  end

  @doc "Maximum stored sample length in bytes (mirrors the DB CHECK)."
  @spec sample_max_bytes() :: pos_integer()
  def sample_max_bytes, do: @sample_max_bytes

  defp truncate_sample(nil), do: nil

  defp truncate_sample(sample) when is_binary(sample) do
    if byte_size(sample) > @sample_max_bytes,
      do: binary_part(sample, 0, @sample_max_bytes),
      else: sample
  end
end
