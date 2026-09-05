defmodule Recurse.Providers.Impls.AwsSecretsManagerRefResolverTest do
  use ExUnit.Case, async: false

  alias Recurse.Providers.Impls.AwsSecretsManagerRefResolver

  @secret_arn "arn:aws:secretsmanager:us-west-2:123456789012:secret:recurse/openai-api-key-AbCdEf"
  @binary_arn "arn:aws:secretsmanager:us-east-1:123456789012:secret:recurse/binary-AbCdEf"
  @denied_arn "arn:aws:secretsmanager:us-west-2:123456789012:secret:recurse/denied-AbCdEf"

  setup do
    prior_client = Application.get_env(:recurse_providers, :secrets_manager_client)
    Application.put_env(:recurse_providers, :secrets_manager_client, __MODULE__.StubClient)

    for arn <- [@secret_arn, @binary_arn, @denied_arn] do
      AwsSecretsManagerRefResolver.clear_cache!(arn)
    end

    Process.put(:secrets_manager_calls, [])

    on_exit(fn ->
      restore_app_env(:secrets_manager_client, prior_client)

      for arn <- [@secret_arn, @binary_arn, @denied_arn] do
        AwsSecretsManagerRefResolver.clear_cache!(arn)
      end

      Process.delete(:secrets_manager_calls)
    end)

    :ok
  end

  test "resolves SecretString and caches by ARN" do
    assert AwsSecretsManagerRefResolver.resolve_arn!(@secret_arn) == "sk-live-secret"
    assert AwsSecretsManagerRefResolver.resolve_arn!(@secret_arn) == "sk-live-secret"

    assert [{@secret_arn, [config_overrides: [region: "us-west-2"]]}] =
             Enum.reverse(Process.get(:secrets_manager_calls))
  end

  test "resolves SecretBinary values" do
    assert AwsSecretsManagerRefResolver.resolve_arn!(@binary_arn) == "binary-secret"
  end

  test "IAM denied errors raise fail-closed message" do
    assert_raise RuntimeError, ~r/AccessDeniedException/, fn ->
      AwsSecretsManagerRefResolver.resolve_arn!(@denied_arn)
    end
  end

  test "rejects non-Secrets Manager ARNs" do
    refute AwsSecretsManagerRefResolver.arn?("arn:aws:kms:us-west-2:123:key/x")

    assert_raise ArgumentError, ~r/expected AWS Secrets Manager ARN/, fn ->
      AwsSecretsManagerRefResolver.resolve_arn!("not-an-arn")
    end
  end

  defp restore_app_env(key, nil), do: Application.delete_env(:recurse_providers, key)
  defp restore_app_env(key, value), do: Application.put_env(:recurse_providers, key, value)

  defmodule StubClient do
    @behaviour Recurse.Providers.SecretsManagerClient

    @secret_arn "arn:aws:secretsmanager:us-west-2:123456789012:secret:recurse/openai-api-key-AbCdEf"
    @binary_arn "arn:aws:secretsmanager:us-east-1:123456789012:secret:recurse/binary-AbCdEf"
    @denied_arn "arn:aws:secretsmanager:us-west-2:123456789012:secret:recurse/denied-AbCdEf"

    @impl true
    def get_secret_value(arn, opts) do
      calls = Process.get(:secrets_manager_calls, [])
      Process.put(:secrets_manager_calls, [{arn, opts} | calls])

      case arn do
        @secret_arn ->
          {:ok, %{"SecretString" => "sk-live-secret"}}

        @binary_arn ->
          {:ok, %{"SecretBinary" => Base.encode64("binary-secret")}}

        @denied_arn ->
          {:error, {:http_error, 400, %{"__type" => "AccessDeniedException"}}}
      end
    end
  end
end
