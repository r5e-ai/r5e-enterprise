defmodule Recurse.Shared.ConfigYaml do
  @moduledoc """
  Shared YAML parsing wrapper for boot-time configuration files.

  Gateway and broker config loaders use YAML as a deployment-file format; this
  wrapper keeps parser-module calls out of Gateway/Runtime business logic while
  preserving one parser dependency.
  """

  @spec read_from_string(binary()) :: {:ok, term()} | {:error, term()}
  def read_from_string(yaml) when is_binary(yaml), do: YamlElixir.read_from_string(yaml)
end
