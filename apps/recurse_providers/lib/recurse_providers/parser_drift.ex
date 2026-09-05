defmodule Recurse.Providers.ParserDrift do
  @moduledoc """
  Store for parser-drift sightings (spec 012 S4, plan §10): the
  `(api_format, event_type)` discriminators an LLM-proxy parser could
  not classify, with a keys-only sample, first/last seen and a count.

  `record/1` is an upsert keyed on `(tenant_id, api_format, event_type)`:
  the first sighting inserts the row (`{:ok, :new, row}`); later
  sightings bump `count`, move `last_seen`, and keep the original
  sample (`{:ok, :seen, row}`). The gateway's boot counter
  (`Recurse.Gateway.LlmProxy.ParserDrift`) uses the `:new` / `:seen`
  distinction for `/readyz`'s `parser_drift: n_new_since_boot`.
  """

  import Ecto.Query, only: [from: 2]

  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.ParserDriftEvent

  @type sighting :: %{
          required(:tenant_id) => String.t(),
          required(:api_format) => String.t(),
          required(:event_type) => String.t(),
          optional(:sample_redacted) => String.t() | nil,
          optional(:seen_at) => DateTime.t()
        }

  @doc "Upsert one sighting. See the module doc for the return shape."
  @spec record(sighting()) ::
          {:ok, :new | :seen, ParserDriftEvent.t()} | {:error, Ecto.Changeset.t() | term()}
  def record(%{tenant_id: tenant_id, api_format: api_format, event_type: event_type} = sighting)
      when is_binary(tenant_id) and is_binary(api_format) and is_binary(event_type) do
    seen_at = Map.get(sighting, :seen_at) || DateTime.utc_now()

    changeset =
      ParserDriftEvent.changeset(%ParserDriftEvent{}, %{
        tenant_id: tenant_id,
        api_format: api_format,
        event_type: event_type,
        sample_redacted: Map.get(sighting, :sample_redacted),
        first_seen: seen_at,
        last_seen: seen_at,
        count: 1
      })

    with true <- changeset.valid? || {:error, changeset},
         {:ok, row} <-
           Repo.insert(changeset,
             on_conflict: [inc: [count: 1], set: [last_seen: seen_at, updated_at: seen_at]],
             conflict_target: [:tenant_id, :api_format, :event_type],
             returning: true
           ) do
      {:ok, if(row.count == 1, do: :new, else: :seen), row}
    end
  rescue
    e -> {:error, e}
  end

  def record(_), do: {:error, :invalid_sighting}

  @doc """
  List sightings for a tenant, most recently seen first. Options:
  `:limit` (default 100), `:api_format`.
  """
  @spec list(String.t(), keyword()) :: [ParserDriftEvent.t()]
  def list(tenant_id, opts \\ []) when is_binary(tenant_id) do
    limit = Keyword.get(opts, :limit, 100)

    query =
      from(e in ParserDriftEvent,
        where: e.tenant_id == ^tenant_id,
        order_by: [desc: e.last_seen],
        limit: ^limit
      )

    query =
      case Keyword.get(opts, :api_format) do
        nil -> query
        format -> from(e in query, where: e.api_format == ^format)
      end

    Repo.all(query)
  end
end
