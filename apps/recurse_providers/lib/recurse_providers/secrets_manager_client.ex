defmodule Recurse.Providers.SecretsManagerClient do
  @moduledoc """
  Narrow client seam for AWS Secrets Manager ref resolution.

  Production uses the ExAws-backed implementation under
  `Recurse.Providers.Impls`; tests can inject a small module that implements
  this callback without reaching AWS.
  """

  @callback get_secret_value(secret_id :: String.t(), opts :: keyword()) ::
              {:ok, map()} | {:error, term()}
end
