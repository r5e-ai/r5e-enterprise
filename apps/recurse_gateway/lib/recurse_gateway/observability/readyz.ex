defmodule Recurse.Gateway.Observability.Readyz do
  @moduledoc """
  `/readyz` readiness endpoint (F002 T091, FR-028).

  ## Contract

      GET /readyz  →  200 | 503 application/json

      {
        "ready": true | false,
        "checks": {
          "llm_pool":        "ready" | "pending:<reason>",
          "jwks_warm":       "ready" | "pending:<reason>",
          "policy_bundle":   "ready" | "pending:<reason>",
          "db_pool":         "ready" | "pending:<reason>"
        },
        "policy": {
          "active_hash":     "<canonical hash, lower-case hex>" | null,
          "last_reload_at":  "<ISO 8601>" | null,
          "last_error":      "<reason of the most recent failed reload>" | null,
          "last_error_at":   "<ISO 8601>" | null
        },
        "fold": {
          "enabled":             true | false,
          "kernel":              "running" | "stopped" | "absent",
          "authority_effective": true | false,
          "last_refusal":        {"reason": "...", "at": "<ISO 8601>"} | null,
          "calls_submitted":     N,      // S9b: submitter counters since boot
          "acts_admitted":       N,
          "acts_denied":         N,
          "refusals":            N,
          "decision_mismatches": N,      // gateway and fold disagreed on a ToolCall
          "calls_without_bytes": N,      // no retained request bytes → no LlmCall
          "submitter_errors":    N,
          "active_bundle_object": {"canonical_hash": "<hex>", "object": "bytes:sha256:…"} | null
        }
      }

  Unlike `/healthz` (liveness — "process is running"), `/readyz` is
  **stricter**: the Gateway must have warmed its upstream connection
  pools + caches before it reports `ready`. Load balancers gate traffic
  on this endpoint; returning `ready: true` too early means routing
  requests into cold pools and violating the p95 latency budget (FR-019a).

  Per FR-028:
    > `/readyz` reports ready-or-pending list (includes pool warmth
    > for ledger/KMS/S3).

  Check list:
    * `llm_pool` — the `:openai_pool` Finch pool process is alive.
    * `jwks_warm` — `JwksCache` has at least one issuer with a non-nil
      `last_fetch` (i.e., a successful refresh has landed). We check the
      GenServer state directly via `:sys.get_state/1` with a short
      timeout. If any configured issuer has been refreshed we consider
      the cache warm — downstream auth still handles per-issuer misses
      via the cache's coalescing path.
    * `policy_bundle` — `BundleLoader` has a bundle in `:persistent_term`.
    * `db_pool` — the `Recurse.Providers.Repo` pool has at least one
      active connection (verified via a trivial `SELECT 1`).

  A single `pending:<reason>` toggles the overall `ready: false` and
  HTTP 503.

  ## `policy` (spec 012 S5)

  Reports which Cedar bundle is active and how the last reload went, so
  an operator pushing policy through `policy-sync` can watch the hash
  change here. `active_hash` comes from the canonical `Active` store
  (whichever loader wrote it); `last_reload_at` / `last_error` come
  from `Recurse.Gateway.Policy.BundleLoader.status/2` and are `null`
  when the filesystem loader is not the one running (OCI path). A failed
  reload does NOT flip `ready`: the previous bundle stays active and
  enforcement continues; the failure is surfaced, not fatal.

  ## `fold` (spec 012 S9a)

  The standing of the fold (`apps/recurse_fold`) — the r5e kernel the
  gateway records into. This block is a **report**, but do not read that
  as "the fold cannot fail readiness": the `admission` check above is a
  gate, and it goes `pending` (503) whenever `Fold.Admission.ready?/0` is
  false, which includes a fold whose authority is not effective. The two
  say different things — one whether requests can be admitted, the other
  why not.

  `enabled` is `R5E_FOLD_ENABLED`; `kernel` says whether the `:r5e`
  application is up (`absent` when the fold is not in this build at all);
  `authority_effective` is whether the fold's role Endorsement is
  effective *now*; `role_standing` says what a restart would and would not
  fix — a revoked role reads `role revoked; explicit re-endorsement
  required` and stays that way across reboots, because boot mints only for
  a role this chain has never endorsed (RC review 2026-09-05, K4);
  `last_refusal` is the most recent `{:refused, reason}`
  `Recurse.Fold.admit/3` or `put_cas/2` returned since boot. The gateway
  does not depend on the fold app, so it is reached by name at request
  time and its absence is reported, not raised.

  ## Iron Law check (`elixir:otp-thinking`)

  Pure plug function — no state, called per-request. Each check is a
  lightweight probe; total cost is dominated by the `SELECT 1` RTT to
  Postgres (sub-millisecond on a warmed pool).

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/observability/healthz.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/identity/jwks_cache.ex`
    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-028
  """

  alias Recurse.Gateway.Identity.JwksCache
  alias Recurse.Gateway.LlmProxy.ParserDrift
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.Policy.BundleLoader

  @type check_result :: :ready | {:pending, term()}

  @doc """
  Plug entrypoint.
  """
  @spec call(Plug.Conn.t(), any()) :: Plug.Conn.t()
  def call(%Plug.Conn{} = conn, _opts) do
    checks = %{
      "llm_pool" => check_llm_pool() |> encode(),
      "jwks_warm" => check_jwks_warm() |> encode(),
      "policy_bundle" => check_policy_bundle() |> encode(),
      "db_pool" => check_db_pool() |> encode(),
      "admission" =>
        if(Recurse.Gateway.Fold.Admission.ready?(),
          do: "ready",
          else: "pending:admission_unavailable"
        )
    }

    ready? = Enum.all?(Map.values(checks), &(&1 == "ready"))
    http_code = if ready?, do: 200, else: 503

    body =
      JSON.encode!(%{
        "ready" => ready?,
        "checks" => checks,
        "policy" => policy_status(),
        # Historical drift counts do not disable the whole listener. Each
        # request independently fails closed on unsupported executable data
        # or parser failure; readiness is not permission to forward it.
        "parser_drift" => ParserDrift.new_since_boot(),
        "fold" => fold_status()
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(http_code, body)
  end

  # ---------------------------------------------------------------------------
  # Individual checks
  # ---------------------------------------------------------------------------

  @doc "Verify the `:openai_pool` Finch pool is started."
  @spec check_llm_pool() :: check_result()
  def check_llm_pool do
    case Process.whereis(:openai_pool) do
      nil -> {:pending, :llm_pool_not_started}
      pid when is_pid(pid) -> :ready
    end
  end

  @doc """
  Verify that `JwksCache` has refreshed at least one issuer's JWKS.
  Peeks at the cache's state via `:sys.get_state/2`.

  `:sys.get_state/2` serializes through the cache's mailbox; the short
  timeout (250ms) keeps readyz's latency bounded even if the cache is
  busy with a refresh.
  """
  @spec check_jwks_warm() :: check_result()
  def check_jwks_warm do
    case Process.whereis(JwksCache) do
      nil ->
        {:pending, :jwks_cache_not_started}

      pid ->
        try do
          state = :sys.get_state(pid, 250)
          issuers = Map.get(state, :issuers, %{})

          if map_size(issuers) == 0 do
            # No issuers configured — trivially "warm".
            :ready
          else
            any_fetched? =
              Enum.any?(issuers, fn {_url, cfg} -> cfg.last_fetch != nil end)

            if any_fetched?, do: :ready, else: {:pending, :no_issuer_refreshed_yet}
          end
        catch
          :exit, _reason -> {:pending, :jwks_cache_timeout}
        end
    end
  end

  @doc "Verify a Cedar policy bundle has been loaded into the canonical Active store."
  @spec check_policy_bundle() :: check_result()
  def check_policy_bundle do
    case Active.current() do
      {:ok, _envelope} -> :ready
      {:error, :not_loaded} -> {:pending, :policy_bundle_not_loaded}
    end
  end

  @doc """
  Active bundle hash + last reload outcome (spec 012 S5). Never raises
  and never blocks longer than the loader's status timeout (250 ms).
  """
  @spec policy_status() :: %{String.t() => String.t() | nil}
  def policy_status do
    active_hash =
      case Active.current() do
        {:ok, %Active{bundle: %{canonical_hash: hash}}} when is_binary(hash) ->
          Base.encode16(hash, case: :lower)

        _ ->
          nil
      end

    {last_reload_at, last_error, last_error_at} =
      case BundleLoader.status() do
        {:ok, %{last_reload_at: at, last_reload_error: nil}} ->
          {at, nil, nil}

        {:ok, %{last_reload_at: at, last_reload_error: %{reason: reason, at: err_at}}} ->
          {at, truncate(inspect(reason)), err_at}

        {:error, _not_running_or_timeout} ->
          {nil, nil, nil}
      end

    %{
      "active_hash" => active_hash,
      "last_reload_at" => iso8601(last_reload_at),
      "last_error" => last_error,
      "last_error_at" => iso8601(last_error_at)
    }
  end

  @doc """
  The fold's standing, with an `absent` block for a missing or failed
  service. The released gateway depends on the fold; this defensive lookup
  preserves diagnostics when admission is unavailable. Never raises.
  """
  @spec fold_status() :: map()
  def fold_status do
    fold = Recurse.Fold

    base =
      if Code.ensure_loaded?(fold) and function_exported?(fold, :status, 0) do
        try do
          apply(fold, :status, [])
        rescue
          e -> fold_absent("error:" <> truncate(Exception.message(e)))
        catch
          :exit, reason -> fold_absent("exit:" <> truncate(inspect(reason)))
        end
      else
        fold_absent("absent")
      end

    # Spec 012 S9b — the submitter's counters since boot (`decision_mismatches`
    # among them, plan §14: a fold answer is never dropped, so each kind of
    # answer has a number here). Zeros when the fold is absent.
    Map.merge(base, Recurse.Gateway.Fold.Submitter.stats())
  end

  defp fold_absent(kernel) do
    %{
      "enabled" => false,
      "kernel" => kernel,
      "authority_effective" => false,
      "role_standing" => "unknown (the fold did not answer)",
      "last_refusal" => nil
    }
  end

  @doc """
  Verify the Providers Repo pool is reachable by issuing a `SELECT 1`.
  Uses a short 250ms query timeout so readyz cannot block load-balancer
  health checks.
  """
  @spec check_db_pool() :: check_result()
  def check_db_pool do
    case Ecto.Adapters.SQL.query(Recurse.Providers.Repo, "SELECT 1", [], timeout: 250) do
      {:ok, %{rows: [[1]]}} -> :ready
      {:ok, _other} -> {:pending, :unexpected_db_result}
      {:error, reason} -> {:pending, reason_to_atom(reason)}
    end
  rescue
    e -> {:pending, Exception.message(e)}
  catch
    :exit, _reason -> {:pending, :db_pool_timeout}
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp iso8601(nil), do: nil
  defp iso8601(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  # A Cedar parse error carries the offending source span; keep the
  # readiness body bounded.
  @max_error_chars 512
  defp truncate(str) when byte_size(str) <= @max_error_chars, do: str
  defp truncate(str), do: String.slice(str, 0, @max_error_chars) <> "…"

  defp encode(:ready), do: "ready"
  defp encode({:pending, reason}), do: "pending:" <> reason_to_string(reason)

  # Reduce arbitrary DB error terms into a small closed set of well-known atoms.
  # Using `String.to_atom/1` on unbounded strings is the Credo-flagged atom-
  # exhaustion hazard; instead, we inspect known struct names and fall back to
  # `:db_error` for everything else.
  defp reason_to_atom(%DBConnection.ConnectionError{}), do: :db_connection_error
  defp reason_to_atom(%Postgrex.Error{}), do: :postgrex_error
  defp reason_to_atom(r) when is_atom(r), do: r
  defp reason_to_atom(_), do: :db_error

  defp reason_to_string(r) when is_binary(r), do: r
  defp reason_to_string(r) when is_atom(r), do: Atom.to_string(r)
  defp reason_to_string(r), do: inspect(r)
end
