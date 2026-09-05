defmodule Recurse.Gateway.LlmProxy.UpstreamSeed do
  @moduledoc """
  Boot-time, idempotent seeding of `LlmProviderConfig` rows from named
  presets (spec 012 S2).

  `R5E_LLM_PROXY_UPSTREAMS=anthropic[,openai_api]` (parsed in
  `config/runtime.exs` into `:llm_proxy_upstreams`) names the presets to
  upsert under the proxy's tenant (`:llm_proxy_default_tenant_id`, i.e.
  `R5E_TENANT_ID`). The compose quickstart sets `anthropic`; this is what
  makes `ANTHROPIC_BASE_URL=http://localhost:4443` work on first boot
  without a `mix run scripts/...` step. It replaces
  `scripts/fable_demo/seed_real_upstreams.exs` for the compose path.

  ## Presets

    * `anthropic` — `api.anthropic.com:443`, `https-sse`,
      `api_format: :anthropic_messages`, `auth_mode: :passthrough` (the
      gateway stores no key; the client's `Authorization` / `x-api-key`
      is forwarded verbatim).
    * `openai_api` — `api.openai.com:443`, `wss` + `https-sse`,
      `api_format: :openai_responses`, `auth_mode: :bearer`.

  ## Idempotence and operator ownership

  Keyed on the table's unique `(tenant_id, provider, upstream_host)`. A
  missing row is inserted with `metadata.seed = "upstream_seed"`. An
  existing row is only refreshed while it still carries that marker AND
  its `auth_mode` matches the preset: then the preset fields
  (`upstream_port`, `transport_modes`, `auth_mode`, `api_format`,
  `metadata.scheme`) are brought back in line and every field that
  actually changed is logged at `warning`, while the operator's `enabled`
  flag and extra `metadata` keys (`denial_template`, `appeal_uri`, ...)
  are kept. If the operator removed the seed marker or changed
  `auth_mode`, the row is theirs: it is left untouched and the skip is
  logged at `info`. A reboot must never undo an operator's edit. The
  tenant row is created with `on_conflict: :nothing` so the FK is
  satisfied on an empty database.

  ## Database availability at boot

  Postgres in the compose stack may still be accepting connections when
  the gateway reaches this child. Connection-level failures
  (`DBConnection.ConnectionError`, or `Postgrex.Error` with
  `cannot_connect_now`) are retried three times with 1s / 2s / 4s
  backoff before the exception propagates and fails the boot.

  ## Supervision shape

  Runs synchronously inside `start_link/1` and returns `:ignore`, so the
  application supervisor blocks on it — positioned before the proxy
  listener (`Recurse.Gateway.Application.llm_proxy_endpoint_children/0`),
  the first proxied request always finds its row. An unknown preset
  name raises and fails the boot: a typo in `R5E_LLM_PROXY_UPSTREAMS`
  is a configuration error, not something to log and forget. No process
  survives (Iron Law: no state, no concurrency, no fault domain of its
  own — the Repo owns the fault domain).
  """

  import Ecto.Query, only: [from: 2]

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmProviderConfig

  require Logger

  @seed_marker "upstream_seed"
  @refresh_fields [:upstream_port, :transport_modes, :auth_mode, :api_format]
  @default_retry_delays_ms [1_000, 2_000, 4_000]

  @presets %{
    "anthropic" => %{
      provider: "anthropic",
      upstream_host: "api.anthropic.com",
      upstream_port: 443,
      transport_modes: ["https-sse"],
      auth_mode: :passthrough,
      api_format: :anthropic_messages,
      metadata: %{"scheme" => "https", "seed" => "upstream_seed", "preset" => "anthropic"}
    },
    "openai_api" => %{
      provider: "openai_api",
      upstream_host: "api.openai.com",
      upstream_port: 443,
      transport_modes: ["wss", "https-sse"],
      auth_mode: :bearer,
      api_format: :openai_responses,
      metadata: %{"scheme" => "https", "seed" => "upstream_seed", "preset" => "openai_api"}
    }
  }

  @typedoc "A preset name accepted in `R5E_LLM_PROXY_UPSTREAMS`."
  @type preset_name :: String.t()

  @doc "All shipped presets, keyed by name."
  @spec presets() :: %{preset_name() => map()}
  def presets, do: @presets

  @doc """
  Parse the `R5E_LLM_PROXY_UPSTREAMS` value: comma-separated, whitespace
  and empty entries ignored, order preserved, duplicates removed.

      iex> Recurse.Gateway.LlmProxy.UpstreamSeed.parse_upstreams(" anthropic, openai_api ,,anthropic")
      ["anthropic", "openai_api"]

      iex> Recurse.Gateway.LlmProxy.UpstreamSeed.parse_upstreams(nil)
      []
  """
  @spec parse_upstreams(String.t() | nil) :: [preset_name()]
  def parse_upstreams(value) when is_binary(value) do
    value
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  def parse_upstreams(_), do: []

  @doc """
  Upsert the named presets for `tenant_id`. Returns the resulting rows in
  preset order, or `{:error, {:unknown_preset, name}}` before touching
  the database when any name is not a shipped preset.

  Options:

    * `:retry_delays_ms` — backoff schedule for connection errors
      (default `#{inspect(@default_retry_delays_ms)}`; `[]` disables retries).
  """
  @spec run(String.t(), [preset_name()], keyword()) ::
          {:ok, [LlmProviderConfig.t()]} | {:error, {:unknown_preset, preset_name()}}
  def run(tenant_id, names, opts \\ []) when is_binary(tenant_id) and is_list(names) do
    case Enum.find(names, &(not Map.has_key?(@presets, &1))) do
      nil ->
        delays = Keyword.get(opts, :retry_delays_ms, @default_retry_delays_ms)

        rows =
          with_db_retry(delays, fn ->
            :ok = ensure_tenant(tenant_id)
            Enum.map(names, &upsert(tenant_id, Map.fetch!(@presets, &1)))
          end)

        {:ok, rows}

      unknown ->
        {:error, {:unknown_preset, unknown}}
    end
  end

  @doc false
  # Run `fun`, retrying once per entry in `delays_ms` (sleeping that long
  # first) when it raises a connection-level error. Any other exception,
  # or a connection error after the schedule is exhausted, propagates.
  @spec with_db_retry([non_neg_integer()], (-> result)) :: result when result: term()
  def with_db_retry(delays_ms, fun) when is_list(delays_ms) and is_function(fun, 0) do
    fun.()
  rescue
    error ->
      case delays_ms do
        [delay | rest] ->
          if connection_error?(error) do
            Logger.warning(
              "upstream_seed: database unavailable (#{Exception.message(error)}); " <>
                "retrying in #{delay}ms (#{length(rest)} retries left)"
            )

            Process.sleep(delay)
            with_db_retry(rest, fun)
          else
            reraise error, __STACKTRACE__
          end

        [] ->
          reraise error, __STACKTRACE__
      end
  end

  defp connection_error?(%DBConnection.ConnectionError{}), do: true
  defp connection_error?(%Postgrex.Error{postgres: %{code: :cannot_connect_now}}), do: true
  defp connection_error?(_), do: false

  @doc false
  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      restart: :transient,
      type: :worker
    }
  end

  @doc """
  Supervisor entry point. Seeds synchronously and returns `:ignore` (no
  process is left behind). Raises on an unknown preset name so the boot
  fails loudly.
  """
  @spec start_link(keyword()) :: :ignore
  def start_link(opts \\ []) do
    tenant_id =
      Keyword.get(opts, :tenant_id) ||
        Application.get_env(:recurse_gateway, :llm_proxy_default_tenant_id, "default")

    names =
      Keyword.get(opts, :upstreams) ||
        Application.get_env(:recurse_gateway, :llm_proxy_upstreams, [])

    case run(tenant_id, names, Keyword.take(opts, [:retry_delays_ms])) do
      {:ok, rows} ->
        Logger.info(fn ->
          hosts = Enum.map_join(rows, ", ", &"#{&1.upstream_host} (#{&1.provider})")
          "upstream_seed: tenant=#{tenant_id} upstreams=[#{hosts}]"
        end)

        :ignore

      {:error, {:unknown_preset, name}} ->
        raise ArgumentError,
              "R5E_LLM_PROXY_UPSTREAMS names unknown preset #{inspect(name)}; " <>
                "known: #{inspect(Map.keys(@presets))}"
    end
  end

  # ---------------------------------------------------------------------------

  defp ensure_tenant(tenant_id) do
    %Tenant{}
    |> Tenant.changeset(%{
      tenant_id: tenant_id,
      display_name: "Tenant #{tenant_id}",
      tier: :standalone_gateway,
      created_at: DateTime.utc_now()
    })
    |> Repo.insert!(on_conflict: :nothing, conflict_target: :tenant_id)

    :ok
  end

  defp upsert(tenant_id, preset) do
    query =
      from(c in LlmProviderConfig,
        where:
          c.tenant_id == ^tenant_id and c.provider == ^preset.provider and
            c.upstream_host == ^preset.upstream_host
      )

    case Repo.one(query) do
      nil ->
        attrs = preset |> Map.put(:tenant_id, tenant_id) |> Map.put(:enabled, true)
        row = Repo.insert!(LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs))
        Logger.info("upstream_seed: inserted #{describe(row)}")
        row

      %LlmProviderConfig{} = existing ->
        reconcile(existing, preset)
    end
  end

  # An existing row is refreshed only while it is still ours (seed marker
  # present, auth_mode unchanged); otherwise the operator owns it.
  defp reconcile(%LlmProviderConfig{} = existing, preset) do
    metadata = existing.metadata || %{}

    cond do
      Map.get(metadata, "seed") != @seed_marker ->
        Logger.info(
          "upstream_seed: skipped #{describe(existing)}: metadata.seed is " <>
            "#{inspect(Map.get(metadata, "seed"))}, not #{inspect(@seed_marker)} (operator-owned)"
        )

        existing

      existing.auth_mode != preset.auth_mode ->
        Logger.info(
          "upstream_seed: skipped #{describe(existing)}: auth_mode is " <>
            "#{inspect(existing.auth_mode)}, preset is #{inspect(preset.auth_mode)} (operator-owned)"
        )

        existing

      true ->
        refresh(existing, preset, metadata)
    end
  end

  defp refresh(existing, preset, metadata) do
    changes = changed_fields(existing, preset, metadata)

    if changes == [] do
      existing
    else
      Enum.each(changes, fn {field, from, to} ->
        Logger.warning(
          "upstream_seed: refreshed #{describe(existing)} #{field}: " <>
            "#{inspect(from)} -> #{inspect(to)} (preset #{preset.metadata["preset"]})"
        )
      end)

      attrs =
        preset
        |> Map.take(@refresh_fields)
        |> Map.put(:metadata, Map.merge(metadata, preset.metadata))

      Repo.update!(LlmProviderConfig.changeset(existing, attrs))
    end
  end

  defp changed_fields(existing, preset, metadata) do
    scalar =
      for field <- @refresh_fields,
          from = Map.fetch!(existing, field),
          to = Map.fetch!(preset, field),
          from != to,
          do: {field, from, to}

    scheme_from = Map.get(metadata, "scheme")
    scheme_to = preset.metadata["scheme"]

    if scheme_from == scheme_to,
      do: scalar,
      else: scalar ++ [{"metadata.scheme", scheme_from, scheme_to}]
  end

  defp describe(%LlmProviderConfig{} = row) do
    "tenant=#{row.tenant_id} #{row.upstream_host} (#{row.provider})"
  end
end
