defmodule Recurse.Providers.Repo.Migrations.LlmProviderConfigs do
  @moduledoc """
  Spec 009 (LLM API Proxy + Tool-Use Policy Gating) — Phase 2 migration #1 of 4.

  Creates `llm_provider_configs` — per-tenant + per-provider configuration
  determining which upstream LLM hosts a tenant's traffic forwards to.

  Source of truth: `specs/009-llm-api-proxy/data-model.md` §LlmProviderConfig.
  Consumed by `Recurse.Providers.LlmProviders.lookup/2` (Phase 2) and the
  `Recurse.Gateway.LlmProxy.UpstreamResolver` (Phase 3).

  Notes on shape:
    * `tenant_id` is the `:string` ULID, FK to `tenants.tenant_id` per the
      F002 convention shared across this Repo's schemas (see
      `20260423100000_f002_initial_schemas.exs` and the `Tenant` schema
      `@primary_key {:tenant_id, :string, autogenerate: false}`).
    * `transport_modes` is a string array ("wss", "https-sse"). The set
      of valid values is enforced via a CHECK using a Postgres array
      containment predicate.
    * `auth_mode` and `api_format` are strings with CHECK constraints
      naming the enums; the Ecto schema uses `Ecto.Enum` over the same
      atoms so the in-memory + on-disk shapes agree.
    * `metadata` is JSONB (Ecto `:map`) for forward-compat (Azure
      deployment_name, region, etc.) — Backlog A's "predicates as JSONB"
      future-shape (see `.specify/spec-backlog.md`) is naturally
      supported by this column.

  Indexes:
    * UNIQUE `(tenant_id, provider, upstream_host)` — primary lookup +
      idempotence on re-config.
    * `(tenant_id, enabled)` — hot path for "list active providers for
      this tenant" admin queries.
  """

  use Ecto.Migration

  def change do
    create table(:llm_provider_configs) do
      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :provider, :string, null: false
      add :upstream_host, :string, null: false
      add :upstream_port, :integer, null: false, default: 443
      add :transport_modes, {:array, :string}, null: false
      add :auth_mode, :string, null: false
      add :api_format, :string, null: false
      add :enabled, :boolean, null: false, default: true
      add :model_allowlist, {:array, :string}, null: false, default: []
      add :default_token_budget_per_call, :integer
      add :metadata, :map, null: false, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:llm_provider_configs, [:tenant_id, :provider, :upstream_host],
             name: :llm_provider_configs_tenant_provider_host_index
           )

    create index(:llm_provider_configs, [:tenant_id, :enabled],
             name: :llm_provider_configs_tenant_enabled_index
           )

    # Whitelist the API-format enum values per data-model.md.
    create constraint(
             :llm_provider_configs,
             :llm_provider_configs_api_format_check,
             check:
               "api_format IN ('openai_responses', 'openai_chat_completions', 'anthropic_messages', 'google_gemini', 'openai_compatible')"
           )

    # Whitelist the auth-mode enum values per data-model.md.
    create constraint(
             :llm_provider_configs,
             :llm_provider_configs_auth_mode_check,
             check:
               "auth_mode IN ('bearer', 'bearer_plus_chatgpt_account_id', 'api_key', 'aws_sigv4', 'internal_none')"
           )

    # transport_modes is a non-empty subset of {wss, https-sse}. Use
    # `cardinality(...)` rather than `array_length(..., 1)` because
    # `array_length` of an empty array returns NULL (not 0), and a CHECK
    # that evaluates to NULL is treated as PASS by Postgres — empty
    # arrays would slip through. `cardinality` returns 0 for empty,
    # which keeps the comparison well-typed.
    create constraint(
             :llm_provider_configs,
             :llm_provider_configs_transport_modes_check,
             check:
               "cardinality(transport_modes) >= 1 AND transport_modes <@ ARRAY['wss', 'https-sse']::varchar[]"
           )

    create constraint(
             :llm_provider_configs,
             :llm_provider_configs_upstream_port_check,
             check: "upstream_port > 0 AND upstream_port <= 65535"
           )

    create constraint(
             :llm_provider_configs,
             :llm_provider_configs_default_token_budget_check,
             check: "default_token_budget_per_call IS NULL OR default_token_budget_per_call > 0"
           )
  end
end
