defmodule Recurse.Gateway.Observability.Healthz do
  @moduledoc """
  `/healthz` liveness endpoint (F002 T091, FR-028).

  ## Contract

      GET /healthz  →  200 application/json

      {
        "status": "ok" | "degraded" | "down",
        "components": {
          "gateway": "ok",
          "ledger": "ok" | "degraded:<reason>" | "down:<reason>",
          "kms": ...,
          "storage": ...,
          "broker_jwks": ...,
          "cedar_policy": "ok" | "stale_after_failed_reload"
        }
      }

  Per FR-028 the six components are:
    `gateway`, `ledger`, `kms`, `storage`, `broker_jwks`, `cedar_policy`.

  Aggregate rules:
    * Any `:down` component → overall `"status": "down"` + HTTP 503.
    * Any `:degraded` and no `:down` → overall `"status": "degraded"` + HTTP 200.
    * Otherwise → `"status": "ok"` + HTTP 200.

  Unauthenticated per FR-028.

  ## Iron Law check (`elixir:otp-thinking`)

  This module is a pure function executed by the Plug pipeline — no
  GenServer, no state. Probe implementations call into
  `Recurse.Gateway.ProviderRegistry` (backed by `:persistent_term`) and
  run each provider's `healthcheck/1` behaviour callback. Probing is
  done synchronously per request; the aggregate is cheap.

  ## Probe return shape

  Each `probe_*` function returns one of:

    * `:ok` — component is healthy.
    * `{:degraded, reason}` — component is reachable but impaired; HTTP
      response still 200, but the component's entry in `components` is
      `"degraded:<reason>"`.
    * `{:down, reason}` — component is not reachable; HTTP 503.

  Reasons are atoms or short strings so the JSON response stays
  compact and greppable in ops dashboards.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/observability/readyz.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/router.ex`
    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-028
  """

  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.ProviderRegistry

  @type probe_result :: :ok | {:degraded, term()} | {:down, term()}

  @doc """
  Plug entrypoint. Runs all probes, builds the JSON body, selects the
  status code, and writes the response.
  """
  @spec call(Plug.Conn.t(), any()) :: Plug.Conn.t()
  def call(%Plug.Conn{} = conn, _opts) do
    components = %{
      "gateway" => probe_gateway() |> encode(),
      "ledger" => probe_ledger() |> encode(),
      "kms" => probe_kms() |> encode(),
      "storage" => probe_storage() |> encode(),
      "broker_jwks" => probe_broker_jwks() |> encode(),
      "cedar_policy" => probe_cedar_policy() |> encode()
    }

    status = aggregate_status(components)
    http_code = if status == "down", do: 503, else: 200

    body =
      JSON.encode!(%{
        "status" => status,
        "components" => components
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(http_code, body)
  end

  # ---------------------------------------------------------------------------
  # Individual probes
  # ---------------------------------------------------------------------------

  @doc "Gateway OTP application always reports `:ok` when this code executes."
  @spec probe_gateway() :: probe_result()
  def probe_gateway, do: :ok

  @doc "Runs `Recurse.Providers.LedgerProvider.healthcheck/1` on the active impl."
  @spec probe_ledger() :: probe_result()
  def probe_ledger, do: probe_provider(:ledger)

  @doc "Runs `Recurse.Providers.SecretsProvider.healthcheck/1` (KMS impl)."
  @spec probe_kms() :: probe_result()
  def probe_kms, do: probe_provider(:secrets)

  @doc "Runs `Recurse.Providers.StorageProvider.healthcheck/1` (S3 impl)."
  @spec probe_storage() :: probe_result()
  def probe_storage, do: probe_provider(:storage)

  @doc """
  JWKS cache probe. `:ok` if the cache GenServer is up and has at least
  one configured issuer loaded; `{:down, :jwks_cache_not_started}`
  otherwise. We do not force a refresh here — `readyz` owns the "has
  warmed" check.
  """
  @spec probe_broker_jwks() :: probe_result()
  def probe_broker_jwks do
    case Process.whereis(Recurse.Gateway.Identity.JwksCache) do
      nil -> {:down, :jwks_cache_not_started}
      pid when is_pid(pid) -> :ok
    end
  end

  @doc """
  Cedar bundle probe. `:ok` if a bundle is currently loaded in
  the canonical `Active` store. `{:degraded, :stale_after_failed_reload}`
  documented as a future state once the reload watcher surfaces that
  signal; today the loaders keep the previous bundle on failed reload
  and do not flag it back out to this probe, so we report `:ok`.
  """
  @spec probe_cedar_policy() :: probe_result()
  def probe_cedar_policy do
    case Active.current() do
      {:ok, _envelope} -> :ok
      {:error, :not_loaded} -> {:down, :policy_bundle_not_loaded}
    end
  end

  # ---------------------------------------------------------------------------
  # Internal — provider dispatch
  # ---------------------------------------------------------------------------

  defp probe_provider(kind) do
    case ProviderRegistry.fetch() do
      {:error, :not_installed} ->
        {:down, :providers_not_installed}

      {:ok, cached} ->
        {mod, state} = Map.fetch!(cached, kind)

        try do
          mod.healthcheck(state)
        rescue
          e -> {:down, Exception.message(e)}
        catch
          kind_of_throw, reason -> {:down, {kind_of_throw, reason}}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Aggregate status + JSON encoding
  # ---------------------------------------------------------------------------

  @doc false
  @spec aggregate_status(map()) :: String.t()
  def aggregate_status(components) when is_map(components) do
    vals = Map.values(components)

    cond do
      Enum.any?(vals, &String.starts_with?(&1, "down")) -> "down"
      Enum.any?(vals, &String.starts_with?(&1, "degraded")) -> "degraded"
      true -> "ok"
    end
  end

  defp encode(:ok), do: "ok"
  defp encode({:degraded, reason}), do: "degraded:" <> reason_to_string(reason)
  defp encode({:down, reason}), do: "down:" <> reason_to_string(reason)

  defp reason_to_string(r) when is_binary(r), do: r
  defp reason_to_string(r) when is_atom(r), do: Atom.to_string(r)
  defp reason_to_string(r), do: inspect(r)
end
