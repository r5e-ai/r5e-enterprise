defmodule Recurse.Providers.Impls.AwsKmsSecretsProvider.FinchHttpClient do
  @moduledoc """
  `ExAws.Request.HttpClient` adapter that routes over a named `Finch` pool.

  Rationale (research D1): KMS Sign is on the attestation hot path and
  must not contend with other AWS traffic (S3 payload PUTs, etc.). The
  Gateway supervision tree owns a dedicated `:kms_pool` Finch instance
  (HTTP/2, size 50, tight timeouts); this adapter plumbs `ex_aws_kms`
  through that pool so signing calls get pool isolation + HTTP/2 multiplexing.

  ### Pool selection

  The Finch pool name is taken from the per-call `http_opts` plumbed by
  the caller (`:finch_pool` key). Falling back to `:kms_pool` keeps the
  zero-config default aligned with the supervision tree. Keeping pool
  selection in `http_opts` (not `Application` env) is the one-flag path
  that lets tests install a test-scoped Finch pool without mutating
  global config.

  ExAws credential refreshes also use this adapter. EC2 IMDS
  (`169.254.169.254`) and ECS task-role metadata (`169.254.170.2`) only
  speak HTTP/1.1, so those link-local metadata calls are routed to the
  dedicated `:imds_pool` instead of the HTTP/2-only KMS pool. Tests can
  override that with `:finch_imds_pool`.

  ### Why not the upstream `ExAws.Request.Req`?

  `ExAws.Request.Req` is bundled with `ex_aws ~> 2.6`, but its pool
  routing is controlled by global `Application.get_env(:ex_aws, :req_opts)`
  — impossible to steer KMS calls to `:kms_pool` while leaving other
  AWS calls on their own pool from the same BEAM node. This adapter is
  ~25 lines; the custom-HTTP-client path is documented in
  `ExAws.Request.HttpClient` and is the prescribed extension point.

  ### Scope

  Used exclusively by the KMS SecretsProvider hot path. `S3StorageProvider`
  gets its own adapter (similar shape, different pool) when T038+ land.
  """

  @behaviour ExAws.Request.HttpClient

  @default_pool :kms_pool

  @spec request(atom(), String.t(), iodata(), [{String.t(), String.t()}], keyword()) ::
          {:ok, %{status_code: non_neg_integer(), headers: list(), body: binary()}}
          | {:error, %{reason: term()}}
  @impl ExAws.Request.HttpClient
  def request(method, url, body, headers, http_opts) do
    pool = pool_for_url(url, http_opts)
    receive_timeout = Keyword.get(http_opts, :receive_timeout, 5_000)

    method
    |> Finch.build(url, headers, body)
    |> Finch.request(pool, receive_timeout: receive_timeout)
    |> normalize()
  end

  @doc false
  @spec pool_for_url(String.t(), keyword()) :: atom()
  def pool_for_url(url, http_opts) when is_binary(url) and is_list(http_opts) do
    if metadata_url?(url) do
      Keyword.get(http_opts, :finch_imds_pool, :imds_pool)
    else
      Keyword.get(http_opts, :finch_pool, @default_pool)
    end
  end

  # Finch's success shape is `%Finch.Response{status, body, headers, trailers}`.
  # ExAws's `HttpClient` contract wants `{:ok, %{status_code, headers, body}}`
  # or `{:error, %{reason: term}}`.
  defp normalize({:ok, %Finch.Response{status: status, headers: headers, body: body}}) do
    {:ok, %{status_code: status, headers: headers, body: body}}
  end

  defp normalize({:error, reason}) do
    {:error, %{reason: reason}}
  end

  defp metadata_url?(url) do
    case URI.parse(url) do
      %URI{host: host} when host in ["169.254.169.254", "169.254.170.2"] -> true
      _ -> false
    end
  end
end
