defmodule Recurse.Providers.Impls.S3StorageProvider do
  @moduledoc """
  F002 T038 — `Recurse.Providers.StorageProvider` backed by AWS S3 with
  Object Lock Compliance-mode retention (default 7 years per FR-027).

  Contract:
    * Contract doc — `specs/002-standalone-gateway-vertical-slice/contracts/provider_impls.md`
      (§ `S3StorageProvider`).
    * Behaviour — `Recurse.Providers.StorageProvider` (F001).

  ## Key layout (FR-019)

      s3://<bucket>/tenants/<tenant_id>/runs/<yyyymmdd>/<run_id>.json

  The `tenant_id` is read from `identity_ctx.tenant_id`. The `run_id` is
  read from `identity_ctx.correlation_id` — in the Phase-1 1-run-per-session
  model (see `r5e-memory/gtm_sequencing.md`) the correlation ULID is the
  run ULID; a future feature may grow an explicit `run_id` field on
  `IdentityContext` at which point this source will change without the
  behaviour contract changing. The `<yyyymmdd>` prefix is UTC.

  ## Headers emitted on PUT

    * `x-amz-server-side-encryption: aws:kms` — SSE-KMS using the bucket's
      configured default KMS key (FR-027).
    * `x-amz-object-lock-mode: COMPLIANCE` — Compliance-mode retention
      (immutable; cannot be shortened even by root).
    * `x-amz-object-lock-retain-until-date: <ISO8601>` — computed as
      `now + object_lock_compliance_days` (default 2555 days ≈ 7 years).

  ## Failure classification (FR-032)

  The `payload_outbox` reconciliation loop retries on `:transient` only:

    * 2xx → `{:ok, %{uri, hash}}`
    * 5xx / connection timeout / DNS / econnrefused / closed → `{:error, :transient, reason}`
    * 403 / 404 / 400 → `{:error, :permanent, reason}`
    * anything else → `{:error, :permanent, {:unexpected, reason}}` (fail-closed)

  ## HTTP pool

  Production wires `ExAws.Request.Req` over the `:s3_pool` named Finch pool
  (Gateway supervises the pool). Tests inject a custom `http_client` via
  init-time config so no ExAws global state is mutated and `async: true`
  is preserved. Config keys honored at init:

      %{
        bucket: "my-recurse-payloads",
        region: "us-east-1",
        kms_encryption: true,
        object_lock_compliance_days: 2555,
        finch_pool: :s3_pool,
        # Test-only overrides (never used in prod):
        http_client: ExAws.Request.Mock,
        access_key_id: "test",
        secret_access_key: "test",
        endpoint_url: "http://127.0.0.1:PORT"
      }
  """

  @behaviour Recurse.Providers.StorageProvider

  alias Recurse.Shared.IdentityContext

  @default_object_lock_days 2555
  @seconds_per_day 86_400

  @typedoc "Opaque provider state."
  @type state :: %{
          required(:bucket) => String.t(),
          required(:region) => String.t(),
          required(:kms_encryption) => boolean(),
          required(:object_lock_compliance_days) => pos_integer(),
          required(:config_overrides) => keyword()
        }

  @typep http_response :: %{required(:status_code) => pos_integer(), optional(atom()) => term()}

  # --- Lifecycle -----------------------------------------------------------

  @impl true
  @spec init(Recurse.Providers.StorageProvider.config()) :: {:ok, state()} | {:error, term()}
  def init(config) when is_map(config) do
    with {:ok, bucket} <- fetch_required(config, :bucket),
         {:ok, region} <- fetch_required(config, :region) do
      state = %{
        bucket: bucket,
        region: region,
        kms_encryption: Map.get(config, :kms_encryption, true),
        object_lock_compliance_days:
          Map.get(config, :object_lock_compliance_days, @default_object_lock_days),
        config_overrides: build_config_overrides(config, region)
      }

      {:ok, state}
    end
  end

  @impl true
  @spec terminate(state(), reason :: term()) :: :ok
  def terminate(_state, _reason), do: :ok

  # --- Callbacks -----------------------------------------------------------

  @impl true
  @spec put_payload(state(), payload :: binary(), IdentityContext.t()) ::
          {:ok,
           %{
             uri: Recurse.Providers.StorageProvider.payload_uri(),
             hash: Recurse.Providers.StorageProvider.payload_hash()
           }}
          | {:error, :transient, term()}
          | {:error, :permanent, term()}
  def put_payload(%{bucket: bucket} = state, payload, %IdentityContext{} = identity_ctx)
      when is_binary(payload) do
    key = build_key(identity_ctx, DateTime.utc_now())
    headers = build_put_headers(state)
    hash = :crypto.hash(:sha256, payload)

    operation =
      bucket
      |> ExAws.S3.put_object(key, payload)
      |> merge_headers(headers)

    case ExAws.request(operation, state.config_overrides) do
      {:ok, %{status_code: status}} when status in 200..299 ->
        {:ok, %{uri: "s3://#{bucket}/#{key}", hash: hash}}

      {:ok, %{status_code: status} = resp} ->
        classify_status(status, resp)

      {:error, reason} ->
        classify_error(reason)
    end
  end

  @impl true
  @spec get_payload(state(), Recurse.Providers.StorageProvider.payload_uri(), IdentityContext.t()) ::
          {:ok, binary()}
          | {:error, :transient, term()}
          | {:error, :permanent, term()}
  def get_payload(%{bucket: bucket} = state, payload_uri, %IdentityContext{})
      when is_binary(payload_uri) do
    with {:ok, ^bucket, key} <- parse_uri(payload_uri, bucket) do
      case ExAws.request(ExAws.S3.get_object(bucket, key), state.config_overrides) do
        {:ok, %{status_code: status, body: body}} when status in 200..299 ->
          {:ok, body}

        {:ok, %{status_code: status} = resp} ->
          classify_status(status, resp)

        {:error, reason} ->
          classify_error(reason)
      end
    end
  end

  @impl true
  @spec delete_payload(
          state(),
          Recurse.Providers.StorageProvider.payload_uri(),
          IdentityContext.t()
        ) :: :ok | {:error, term()}
  def delete_payload(_state, _payload_uri, %IdentityContext{}) do
    # Deliberately left for a later task (GDPR / DSA right-to-be-forgotten).
    # Under Compliance-mode Object Lock, retention must expire before a
    # DELETE can succeed; the operator-facing deletion pathway is its own
    # feature.
    {:error, :not_implemented_yet}
  end

  @impl true
  @spec capabilities(state()) :: [Recurse.Providers.StorageProvider.capability()]
  def capabilities(_state), do: [:put, :get, :streaming, :versioned]

  @impl true
  @spec healthcheck(state()) :: :ok | {:degraded, term()} | {:down, term()}
  def healthcheck(%{bucket: bucket} = state) do
    case ExAws.request(ExAws.S3.head_bucket(bucket), state.config_overrides) do
      {:ok, %{status_code: status}} when status in 200..299 ->
        :ok

      {:error, {:http_error, status, _}} when status in 500..599 ->
        {:degraded, {:http_status, status}}

      {:error, {:http_error, status, _}} ->
        {:down, {:http_status, status}}

      {:error, reason} ->
        {:down, reason}
    end
  end

  # --- Internals: URI + key scheme ----------------------------------------

  @spec build_key(IdentityContext.t(), DateTime.t()) :: String.t()
  defp build_key(
         %IdentityContext{tenant_id: tenant_id, correlation_id: run_id},
         %DateTime{} = now
       ) do
    "tenants/#{tenant_id}/runs/#{format_date(now)}/#{run_id}.json"
  end

  @spec format_date(DateTime.t()) :: String.t()
  defp format_date(%DateTime{year: y, month: m, day: d}) do
    :io_lib.format("~4..0B~2..0B~2..0B", [y, m, d]) |> IO.iodata_to_binary()
  end

  @spec parse_uri(String.t(), String.t()) ::
          {:ok, String.t(), String.t()} | {:error, :permanent, term()}
  defp parse_uri("s3://" <> rest, expected_bucket) do
    case String.split(rest, "/", parts: 2) do
      [^expected_bucket, key] when key != "" ->
        {:ok, expected_bucket, key}

      [bucket, _] ->
        {:error, :permanent, {:bucket_mismatch, %{expected: expected_bucket, got: bucket}}}

      _ ->
        {:error, :permanent, {:malformed_uri, rest}}
    end
  end

  defp parse_uri(other, _bucket), do: {:error, :permanent, {:malformed_uri, other}}

  # --- Internals: headers --------------------------------------------------

  @spec build_put_headers(state()) :: map()
  defp build_put_headers(%{kms_encryption: kms?, object_lock_compliance_days: days}) do
    retain_until =
      DateTime.utc_now()
      |> DateTime.add(days * @seconds_per_day, :second)
      |> DateTime.to_iso8601()

    base = %{
      "x-amz-object-lock-mode" => "COMPLIANCE",
      "x-amz-object-lock-retain-until-date" => retain_until
    }

    if kms?, do: Map.put(base, "x-amz-server-side-encryption", "aws:kms"), else: base
  end

  @spec merge_headers(ExAws.Operation.S3.t(), map()) :: ExAws.Operation.S3.t()
  defp merge_headers(%ExAws.Operation.S3{headers: existing} = op, new_headers) do
    %{op | headers: Map.merge(existing, new_headers)}
  end

  # --- Internals: error classification ------------------------------------

  # ExAws 5xx surfaces the body as a binary; 4xx surfaces the full response
  # map. Normalize either shape to just the body bytes before building the
  # `{:http_status, status, body}` sentinel the outbox (FR-032) inspects.
  @spec classify_status(pos_integer(), http_response() | binary() | term()) ::
          {:error, :transient, term()} | {:error, :permanent, term()}
  defp classify_status(status, resp_or_body) when status in 500..599 do
    {:error, :transient, {:http_status, status, extract_body(resp_or_body)}}
  end

  defp classify_status(429, resp_or_body) do
    {:error, :transient, {:http_status, 429, extract_body(resp_or_body)}}
  end

  defp classify_status(status, resp_or_body) when status in [400, 403, 404, 409] do
    {:error, :permanent, {:http_status, status, extract_body(resp_or_body)}}
  end

  defp classify_status(status, resp_or_body) do
    {:error, :permanent, {:unexpected_status, status, extract_body(resp_or_body)}}
  end

  defp extract_body(%{body: body}), do: body
  defp extract_body(body) when is_binary(body), do: body
  defp extract_body(other), do: other

  @transient_reasons [
    :timeout,
    :connect_timeout,
    :closed,
    :econnrefused,
    :nxdomain,
    :ehostunreach,
    :enetunreach,
    :eaddrnotavail
  ]

  # ExAws surfaces non-2xx as `{:error, {:http_error, status, response_map}}`
  # after its retry exhaustion, and transport-layer failures as
  # `{:error, %{reason: atom}}`. Classify both into our transient/permanent
  # split so `payload_outbox` reconciliation (FR-032) can retry only what
  # genuinely recovers.
  @spec classify_error(term()) :: {:error, :transient, term()} | {:error, :permanent, term()}
  defp classify_error({:http_error, status, response}) do
    classify_status(status, response)
  end

  defp classify_error(%{reason: reason}) when reason in @transient_reasons do
    {:error, :transient, reason}
  end

  defp classify_error(reason) when reason in @transient_reasons do
    {:error, :transient, reason}
  end

  defp classify_error(reason), do: {:error, :permanent, reason}

  # --- Internals: config --------------------------------------------------

  @spec fetch_required(map(), atom()) :: {:ok, term()} | {:error, {:missing_config, atom()}}
  defp fetch_required(config, key) do
    case Map.fetch(config, key) do
      {:ok, value} when is_binary(value) and value != "" -> {:ok, value}
      {:ok, value} when not is_nil(value) -> {:ok, value}
      _ -> {:error, {:missing_config, key}}
    end
  end

  # Build ExAws.request/2 overrides. Only test-wiring knobs are propagated —
  # in production, credentials come from the instance role / environment and
  # `http_client` comes from application-wide config (`ExAws.Request.Req` on
  # `:s3_pool`).
  @spec build_config_overrides(map(), String.t()) :: keyword()
  defp build_config_overrides(config, region) do
    [region: region]
    |> maybe_put(:http_client, Map.get(config, :http_client))
    |> maybe_put(:access_key_id, Map.get(config, :access_key_id))
    |> maybe_put(:secret_access_key, Map.get(config, :secret_access_key))
    |> maybe_put(:retries, Map.get(config, :retries))
    |> maybe_put_endpoint(Map.get(config, :endpoint_url))
  end

  defp maybe_put(overrides, _key, nil), do: overrides
  defp maybe_put(overrides, key, value), do: Keyword.put(overrides, key, value)

  # `endpoint_url` → ExAws `host`/`port`/`scheme` triple. Only parsed when
  # present (tests against a local Plug.Cowboy mock).
  defp maybe_put_endpoint(overrides, nil), do: overrides

  defp maybe_put_endpoint(overrides, url) when is_binary(url) do
    uri = URI.parse(url)

    overrides
    |> Keyword.put(:scheme, "#{uri.scheme}://")
    |> Keyword.put(:host, uri.host)
    |> Keyword.put(:port, uri.port)
  end
end
