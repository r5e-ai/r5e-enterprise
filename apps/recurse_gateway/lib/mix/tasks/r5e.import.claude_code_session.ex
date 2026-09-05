defmodule Mix.Tasks.R5e.Import.ClaudeCodeSession do
  @moduledoc """
  Imports a Claude Code JSONL session export into audit attestations.

  ## Tenant resolution

  The tenant_id used for the imported receipts is resolved with the
  following precedence (highest to lowest):

    1. `--tenant-id` / `-t` CLI flag (or `--tenant_id` long-form).
    2. `RECURSE_IMPORT_DEFAULT_TENANT_ID` environment variable.
    3. `Application.get_env(:recurse_gateway, :import)[:default_tenant_id]`
       — populated from the same env var by `config/runtime.exs` so a
       dogfood-deploy operator can set it once at the systemd
       EnvironmentFile / `.envrc` layer.
    4. A synthetic ULID-style fallback (`#{"01HZQ3R5E0DOGFOODAUDITDEVA1"}`)
       used only when nothing else is set. This fallback exists for
       legacy local-dev paths and intentionally does not match any real
       deployment — if you see receipts attributed to it, your
       resolution chain is misconfigured.

  Caught 2026-04-30: an orchestrator imported real session data with
  the synthetic fallback while the auth'd user lived in WorkOS org
  `org_01...`, so the imported receipts were invisible to the user.
  Layered resolution + a documented env-var override prevent that
  recurrence.
  """

  use Mix.Task

  alias Recurse.Gateway.Importers.ClaudeCodeSession

  @shortdoc "Import a Claude Code JSONL session export"

  # Last-resort tenant_id when neither the CLI flag, env var, nor
  # application config supplies one. Synthetic ULID-style; does not
  # exist in any real deployment.
  @ulid_fallback_tenant_id "01HZQ3R5E0DOGFOODAUDITDEVA1"

  @env_var "RECURSE_IMPORT_DEFAULT_TENANT_ID"

  @impl Mix.Task
  def run(argv) do
    Mix.Task.run("app.start")

    {opts, args, invalid} =
      OptionParser.parse(argv,
        strict: [
          principal: :string,
          tenant_id: :string,
          skip_thinking: :boolean
        ],
        aliases: [p: :principal, t: :tenant_id]
      )

    cond do
      invalid != [] ->
        Mix.raise("invalid options: #{inspect(invalid)}")

      length(args) != 1 ->
        Mix.raise("usage: mix r5e.import.claude_code_session [opts] PATH")

      true ->
        import_path(List.first(args), opts)
    end
  end

  defp import_path(path, opts) do
    importer_opts = [
      principal: Keyword.get(opts, :principal, default_principal()),
      tenant_id: Keyword.get(opts, :tenant_id, default_tenant_id()),
      skip_thinking?: Keyword.get(opts, :skip_thinking, true)
    ]

    case ClaudeCodeSession.import_session(path, importer_opts) do
      {:ok, %{receipts: receipts, session_id: session_id}} ->
        Mix.shell().info("imported #{receipts} Claude Code receipts")
        Mix.shell().info("session_id=#{session_id || "<none>"}")
        Mix.shell().info("verification=ledger_signed")

      {:error, reason} ->
        Mix.raise("Claude Code session import failed: #{inspect(reason)}")
    end
  end

  @doc false
  # Resolves the default tenant_id used when no CLI flag is provided.
  #
  # Resolution order: env → application config → ULID fallback.
  #
  # Public-but-undocumented (`@doc false`) so it's reachable from unit
  # tests without invoking the full Mix task.
  @spec default_tenant_id() :: String.t()
  def default_tenant_id do
    env_tenant_id() || config_tenant_id() || @ulid_fallback_tenant_id
  end

  defp env_tenant_id do
    case System.get_env(@env_var) do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp config_tenant_id do
    :recurse_gateway
    |> Application.get_env(:import, [])
    |> Keyword.get(:default_tenant_id)
    |> case do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp default_principal do
    username = System.get_env("USER") || "unknown"

    hostname =
      case :inet.gethostname() do
        {:ok, hostname} -> List.to_string(hostname)
        {:error, _reason} -> "localhost"
      end

    "#{username}@#{hostname}"
  end
end
