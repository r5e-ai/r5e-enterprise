defmodule Recurse.Gateway.Plug.RateLimiter do
  @moduledoc """
  Rate-limiting plug for Data Plane + Audit Plane per F002 FR-030.

  ## Limits

    * **Data Plane** — per-JWT-subject, default **60 req/min per subject**
      (configurable). Breach → HTTP 429 **protocol-native** OpenAI-shape
      error body + `Retry-After` header + `RateLimit-*` headers.
    * **Audit Plane** — per-tenant, default **120 req/min** (configurable).
      Breach → HTTP 429 **F001 error envelope** (`ERR_RATE_LIMITED`) +
      `Retry-After` header + `RateLimit-*` headers.
    * **No IP-based limits** — JWT-subject is the correct granularity
      for a single-tenant deployment with multiple enterprise users
      (FR-030 last sentence).

  ## Iron Law check (`elixir:phoenix-thinking`)

  This is a **pure module-plug**:

    1. Mutable state persisting across calls? No — all bucket state
       lives in the Hammer backend's ETS table, NOT this module.
    2. Concurrent execution? No — the plug is called in-process by
       Bandit; ETS backend handles concurrency below.
    3. Fault isolation? No — a bad input returns 429 or passes through;
       nothing crashes here.

  All three NO → plain functions. No GenServer.

  ## Key derivation

    * `plane: :data` — reads `conn.assigns[:identity_ctx]` (built by
      `Recurse.Gateway.Identity.IdentityContextBuilder`) and uses
      `identity_ctx.principal.subject`. Missing → **fail closed** with
      429 "principal missing".
    * `plane: :audit` — reads `conn.assigns[:identity_ctx]` and uses
      `identity_ctx.tenant_id`. Missing → fail closed with 429
      "tenant missing".

  The Router populates `:identity_ctx` BEFORE dispatching to the
  handler. Mount this plug AFTER the auth hop but BEFORE the handler.

  ## Options

    * `:plane` — `:data | :audit` (required).
    * `:limit` — max requests per `scale_ms` window (required).
    * `:scale_ms` — window size; default 60_000 (1 minute).
    * `:backend` — Hammer backend module; default
      `Recurse.Gateway.RateLimit.Backend`.
    * `:error_style` — `:protocol_native` (default for Data plane) or
      `:envelope` (default for Audit plane). Auto-selected from
      `:plane` if omitted.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-030.
    * `apps/recurse_gateway/lib/recurse_gateway/rate_limit/backend.ex`.
    * `apps/recurse_gateway/lib/recurse_gateway/router.ex` — the wire-in.
  """

  @behaviour Plug

  import Plug.Conn

  alias Recurse.Shared.IdentityContext

  @default_scale_ms 60_000

  @typedoc "Rate-limit plane selector."
  @type plane :: :data | :audit

  @typedoc "Error-body shape selector."
  @type error_style :: :protocol_native | :envelope

  @typedoc "Initialized plug options."
  @type opts :: %{
          plane: plane(),
          limit: pos_integer(),
          scale_ms: pos_integer(),
          backend: module(),
          error_style: error_style()
        }

  @impl Plug
  @spec init(keyword()) :: opts()
  def init(opts) do
    plane = Keyword.fetch!(opts, :plane)
    _ = validate_plane!(plane)
    limit = Keyword.fetch!(opts, :limit)

    unless is_integer(limit) and limit > 0 do
      raise ArgumentError, "RateLimiter :limit must be a positive integer, got #{inspect(limit)}"
    end

    %{
      plane: plane,
      limit: limit,
      scale_ms: Keyword.get(opts, :scale_ms, @default_scale_ms),
      backend: Keyword.get(opts, :backend, Recurse.Gateway.RateLimit.Backend),
      error_style: Keyword.get(opts, :error_style, default_error_style(plane))
    }
  end

  @impl Plug
  @spec call(Plug.Conn.t(), opts()) :: Plug.Conn.t()
  def call(conn, %{plane: plane} = opts) do
    case derive_key(conn, plane) do
      {:ok, key} -> check_rate(conn, key, opts)
      {:error, reason} -> reject(conn, opts, reason, 0)
    end
  end

  # ---------------------------------------------------------------------------
  # Private — key derivation
  # ---------------------------------------------------------------------------

  @spec derive_key(Plug.Conn.t(), plane()) :: {:ok, String.t()} | {:error, atom()}
  defp derive_key(conn, :data) do
    case conn.assigns[:identity_ctx] do
      %IdentityContext{principal: %{subject: subject}}
      when is_binary(subject) and subject != "" ->
        {:ok, "ratelimit:data:" <> subject}

      _ ->
        {:error, :principal_missing}
    end
  end

  defp derive_key(conn, :audit) do
    case conn.assigns[:identity_ctx] do
      %IdentityContext{tenant_id: tenant_id} when is_binary(tenant_id) and tenant_id != "" ->
        {:ok, "ratelimit:audit:" <> tenant_id}

      _ ->
        {:error, :tenant_missing}
    end
  end

  # ---------------------------------------------------------------------------
  # Private — Hammer dispatch + response
  # ---------------------------------------------------------------------------

  @spec check_rate(Plug.Conn.t(), String.t(), opts()) :: Plug.Conn.t()
  defp check_rate(conn, key, %{backend: backend, limit: limit, scale_ms: scale_ms} = opts) do
    case backend.hit(key, scale_ms, limit, 1) do
      {:allow, count} ->
        conn
        |> put_rate_limit_headers(limit, count, scale_ms)

      {:deny, retry_after_ms} ->
        reject(conn, opts, :limit_exceeded, retry_after_ms)
    end
  end

  @spec put_rate_limit_headers(Plug.Conn.t(), pos_integer(), non_neg_integer(), pos_integer()) ::
          Plug.Conn.t()
  defp put_rate_limit_headers(conn, limit, count, scale_ms) do
    remaining = max(limit - count, 0)
    reset_seconds = max(div(scale_ms, 1000), 1)

    conn
    |> put_resp_header("ratelimit-limit", Integer.to_string(limit))
    |> put_resp_header("ratelimit-remaining", Integer.to_string(remaining))
    |> put_resp_header("ratelimit-reset", Integer.to_string(reset_seconds))
  end

  @spec reject(Plug.Conn.t(), opts(), atom(), non_neg_integer()) :: Plug.Conn.t()
  defp reject(conn, opts, reason, retry_after_ms) do
    retry_seconds =
      retry_after_ms
      |> max(opts.scale_ms)
      |> div(1000)
      |> max(1)

    body =
      case opts.error_style do
        :protocol_native -> protocol_native_body(reason)
        :envelope -> envelope_body(reason)
      end

    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("retry-after", Integer.to_string(retry_seconds))
    |> put_resp_header("ratelimit-limit", Integer.to_string(opts.limit))
    |> put_resp_header("ratelimit-remaining", "0")
    |> put_resp_header("ratelimit-reset", Integer.to_string(retry_seconds))
    |> send_resp(429, body)
    |> halt()
  end

  # FR-016d — Data Plane uses OpenAI-shape protocol-native errors.
  defp protocol_native_body(reason) do
    JSON.encode!(%{
      "error" => %{
        "message" => protocol_native_message(reason),
        "type" => "rate_limit_error",
        "code" => "rate_limit_exceeded"
      }
    })
  end

  defp protocol_native_message(:limit_exceeded),
    do: "Rate limit exceeded for this identity"

  defp protocol_native_message(:principal_missing),
    do: "Rate limit gate cannot identify caller (no principal present)"

  defp protocol_native_message(:tenant_missing),
    do: "Rate limit gate cannot identify caller (no tenant present)"

  # FR-023 — Audit Plane uses the F001 error envelope.
  defp envelope_body(reason) do
    JSON.encode!(%{
      "error" => %{
        "code" => "ERR_RATE_LIMITED",
        "message" => envelope_message(reason)
      }
    })
  end

  defp envelope_message(:limit_exceeded),
    do: "Rate limit exceeded for this tenant"

  defp envelope_message(:tenant_missing),
    do: "Rate limit gate cannot identify tenant"

  defp envelope_message(:principal_missing),
    do: "Rate limit gate cannot identify caller"

  # ---------------------------------------------------------------------------
  # Private — validation + defaults
  # ---------------------------------------------------------------------------

  @spec validate_plane!(term()) :: :ok
  defp validate_plane!(plane) when plane in [:data, :audit], do: :ok

  defp validate_plane!(plane) do
    raise ArgumentError,
          "RateLimiter :plane must be :data or :audit, got #{inspect(plane)}"
  end

  @spec default_error_style(plane()) :: error_style()
  defp default_error_style(:data), do: :protocol_native
  defp default_error_style(:audit), do: :envelope
end
