defmodule Recurse.Providers.Repo.Migrations.LlmProviderConfigsAuthModePassthrough do
  @moduledoc """
  Spec 012 (compose quickstart) S2 — widen `llm_provider_configs.auth_mode`
  CHECK to accept `passthrough`.

  `passthrough` is the auth mode of the Anthropic upstream row seeded by
  `Recurse.Gateway.LlmProxy.UpstreamSeed`: the gateway holds no credential
  for the upstream and forwards the client's own `Authorization` /
  `x-api-key` header verbatim. The Ecto enum in
  `Recurse.Providers.Schemas.LlmProviderConfig` is widened in lockstep.

  Same NOT VALID + VALIDATE pattern as `20260424900000_f004_widen_event_kind_check.exs`
  so the table is never locked for a scan (the table is tiny today, but the
  pattern is the house rule for every CHECK widening).
  """
  use Ecto.Migration

  @old_values ~w(bearer bearer_plus_chatgpt_account_id api_key aws_sigv4 internal_none)
  @new_values @old_values ++ ~w(passthrough)

  defp check_clause(values) do
    "auth_mode IN (" <> Enum.map_join(values, ", ", &"'#{&1}'") <> ")"
  end

  def up do
    execute(
      "ALTER TABLE llm_provider_configs DROP CONSTRAINT IF EXISTS llm_provider_configs_auth_mode_check"
    )

    execute("""
    ALTER TABLE llm_provider_configs
      ADD CONSTRAINT llm_provider_configs_auth_mode_check
      CHECK (#{check_clause(@new_values)}) NOT VALID
    """)

    execute(
      "ALTER TABLE llm_provider_configs VALIDATE CONSTRAINT llm_provider_configs_auth_mode_check"
    )
  end

  def down do
    execute("DELETE FROM llm_provider_configs WHERE auth_mode = 'passthrough'")

    execute(
      "ALTER TABLE llm_provider_configs DROP CONSTRAINT IF EXISTS llm_provider_configs_auth_mode_check"
    )

    execute("""
    ALTER TABLE llm_provider_configs
      ADD CONSTRAINT llm_provider_configs_auth_mode_check
      CHECK (#{check_clause(@old_values)})
    """)
  end
end
