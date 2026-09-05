defmodule Recurse.Gateway.Config.EnvFlags do
  @moduledoc """
  Strict boolean parsing for security-relevant runtime env switches
  (spec 012 S1 review).

  `config/runtime.exs`'s general `env_bool` helper treats anything other
  than the literal `"true"` as `false`. For switches whose `false` side
  is the *insecure* side — `R5E_DATABASE_SSL`, `R5E_SECURE_COOKIE` — a
  typo (`R5E_SECURE_COOKIE=ture`, `R5E_DATABASE_SSL=0`) silently failed
  open. `strict_bool!/2` accepts only the literals `true` / `false`
  (unset or empty → the default) and raises on anything else, so the
  misspelling is a boot failure that names the variable rather than a
  cookie without `Secure` or a database connection without TLS.

  Pure function; called from `config/runtime.exs`, where the gateway's
  modules are loaded before the file is evaluated (Mix evaluates
  `runtime.exs` after compilation; releases load the code path first).
  """

  @doc """
  Parse `System.get_env(name)` as a strict boolean.

    * unset or `""` → `default`
    * `"true"` → `true`; `"false"` → `false` (exact, lower-case literals)
    * anything else → `ArgumentError` naming the variable

      iex> System.delete_env("R5E_EXAMPLE_FLAG")
      iex> Recurse.Gateway.Config.EnvFlags.strict_bool!("R5E_EXAMPLE_FLAG", true)
      true
  """
  @spec strict_bool!(String.t(), boolean()) :: boolean()
  def strict_bool!(name, default) when is_binary(name) and is_boolean(default) do
    name |> System.get_env() |> parse!(name, default)
  end

  @doc "Same as `strict_bool!/2` for an already-read value."
  @spec parse!(String.t() | nil, String.t(), boolean()) :: boolean()
  def parse!(nil, _name, default), do: default
  def parse!("", _name, default), do: default
  def parse!("true", _name, _default), do: true
  def parse!("false", _name, _default), do: false

  def parse!(other, name, _default) do
    raise ArgumentError,
          ~s(#{name} must be exactly "true" or "false" \(got #{inspect(other)}\); ) <>
            "refusing to guess for a security switch"
  end
end
