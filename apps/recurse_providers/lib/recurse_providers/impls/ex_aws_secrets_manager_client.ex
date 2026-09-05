defmodule Recurse.Providers.Impls.ExAwsSecretsManagerClient do
  @moduledoc """
  ExAws-backed `SecretsManagerClient` implementation.
  """

  @behaviour Recurse.Providers.SecretsManagerClient

  @impl true
  def get_secret_value(secret_id, opts) when is_binary(secret_id) and is_list(opts) do
    secret_opts = Keyword.get(opts, :secret_opts, [])
    config_overrides = Keyword.get(opts, :config_overrides, [])

    secret_id
    |> ExAws.SecretsManager.get_secret_value(secret_opts)
    |> ExAws.request(config_overrides)
  end
end
