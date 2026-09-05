defmodule Recurse.Providers.SecretsManagerRefResolver do
  @moduledoc """
  Behaviour for resolving AWS Secrets Manager ARNs during boot config loading.
  """

  @callback resolve_arn!(arn :: String.t()) :: String.t()
end
