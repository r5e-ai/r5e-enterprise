defmodule Recurse.Providers.Impls.AwsSecretsManagerRefResolver do
  @moduledoc """
  Resolves AWS Secrets Manager ARNs to plaintext secret values.

  Values are cached in `:persistent_term` keyed by ARN because Tier Config
  refs are immutable for the lifetime of a node and may be reused by multiple
  provider configs during boot.
  """

  @behaviour Recurse.Providers.SecretsManagerRefResolver

  alias Recurse.Providers.Impls.ExAwsSecretsManagerClient

  @cache_prefix {__MODULE__, :secret_value}

  @impl true
  @spec resolve_arn!(String.t()) :: String.t()
  def resolve_arn!(arn) when is_binary(arn) do
    unless arn?(arn) do
      raise ArgumentError, "expected AWS Secrets Manager ARN, got: #{inspect(arn)}"
    end

    key = cache_key(arn)

    case :persistent_term.get(key, :miss) do
      :miss ->
        arn
        |> fetch_secret_value!()
        |> tap(&:persistent_term.put(key, &1))

      value when is_binary(value) ->
        value
    end
  end

  @spec arn?(String.t()) :: boolean()
  def arn?(value) when is_binary(value) do
    case String.split(value, ":", parts: 6) do
      ["arn", _partition, "secretsmanager", region, account, "secret:" <> _resource]
      when region != "" and account != "" ->
        true

      _ ->
        false
    end
  end

  def arn?(_other), do: false

  @spec clear_cache!(String.t()) :: :ok
  def clear_cache!(arn) when is_binary(arn) do
    _ = :persistent_term.erase(cache_key(arn))
    :ok
  end

  defp fetch_secret_value!(arn) do
    case client().get_secret_value(arn, config_overrides: config_overrides(arn)) do
      {:ok, response} ->
        extract_secret_value!(arn, response)

      {:error, reason} ->
        raise RuntimeError,
              "AWS Secrets Manager ref #{inspect(arn)} could not be resolved: " <>
                inspect(reason)
    end
  end

  defp client do
    Application.get_env(
      :recurse_providers,
      :secrets_manager_client,
      ExAwsSecretsManagerClient
    )
  end

  defp extract_secret_value!(_arn, %{"SecretString" => secret})
       when is_binary(secret) and secret != "" do
    secret
  end

  defp extract_secret_value!(_arn, %{secret_string: secret})
       when is_binary(secret) and secret != "" do
    secret
  end

  defp extract_secret_value!(arn, %{"SecretBinary" => encoded}) when is_binary(encoded) do
    decode_secret_binary!(arn, encoded)
  end

  defp extract_secret_value!(arn, %{secret_binary: encoded}) when is_binary(encoded) do
    decode_secret_binary!(arn, encoded)
  end

  defp extract_secret_value!(arn, response) do
    raise RuntimeError,
          "AWS Secrets Manager ref #{inspect(arn)} returned no SecretString or SecretBinary: " <>
            inspect(response)
  end

  defp decode_secret_binary!(arn, encoded) do
    case Base.decode64(encoded) do
      {:ok, bytes} ->
        bytes

      :error ->
        raise RuntimeError,
              "AWS Secrets Manager ref #{inspect(arn)} returned invalid base64 SecretBinary"
    end
  end

  defp config_overrides(arn), do: [region: arn_region(arn)]

  defp arn_region(arn) do
    ["arn", _partition, "secretsmanager", region, _account, "secret:" <> _resource] =
      String.split(arn, ":", parts: 6)

    region
  end

  defp cache_key(arn), do: {@cache_prefix, arn}
end
