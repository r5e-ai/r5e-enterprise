defmodule Recurse.Providers.LlmProvidersTest do
  @moduledoc """
  DB-layer tests for `Recurse.Providers.LlmProviders.lookup/2` and the
  `llm_provider_configs` schema's DB invariants (CHECK constraints +
  UNIQUE index).

  Uses the live Ecto SQL Sandbox (per the F002 T097 pattern in
  `postgres_merkle_ledger_schema_test.exs`). Requires
  `mix ecto.migrate` to have run against the test DB.
  """

  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL
  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.LlmProviders
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmProviderConfig
  alias Recurse.Shared.Ulid

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    tenant_id = Ulid.generate()

    %Tenant{}
    |> Tenant.changeset(%{
      tenant_id: tenant_id,
      display_name: "LlmProvidersTest tenant",
      tier: :standalone_gateway,
      created_at: DateTime.utc_now()
    })
    |> Repo.insert!()

    {:ok, tenant_id: tenant_id}
  end

  defp valid_attrs(tenant_id, opts \\ []) do
    %{
      tenant_id: tenant_id,
      provider: Keyword.get(opts, :provider, "openai_chatgpt"),
      upstream_host: Keyword.get(opts, :upstream_host, "chatgpt.com"),
      upstream_port: 443,
      transport_modes: ["wss", "https-sse"],
      auth_mode: :bearer_plus_chatgpt_account_id,
      api_format: :openai_responses,
      enabled: Keyword.get(opts, :enabled, true),
      model_allowlist: ["gpt-5-codex"],
      metadata: %{}
    }
  end

  describe "lookup/2" do
    test "returns {:ok, cfg} when row exists and enabled = true", %{tenant_id: tenant_id} do
      {:ok, _} =
        %LlmProviderConfig{}
        |> LlmProviderConfig.changeset(valid_attrs(tenant_id))
        |> Repo.insert()

      assert {:ok, %LlmProviderConfig{} = cfg} =
               LlmProviders.lookup(tenant_id, "chatgpt.com")

      assert cfg.tenant_id == tenant_id
      assert cfg.provider == "openai_chatgpt"
      assert cfg.upstream_host == "chatgpt.com"
      assert cfg.enabled == true
      assert cfg.api_format == :openai_responses
    end

    test "returns {:error, :not_allowed} when row exists but enabled = false", %{
      tenant_id: tenant_id
    } do
      {:ok, _} =
        %LlmProviderConfig{}
        |> LlmProviderConfig.changeset(valid_attrs(tenant_id, enabled: false))
        |> Repo.insert()

      assert {:error, :not_allowed} = LlmProviders.lookup(tenant_id, "chatgpt.com")
    end

    test "returns {:error, :not_configured} when no row matches", %{tenant_id: tenant_id} do
      assert {:error, :not_configured} =
               LlmProviders.lookup(tenant_id, "definitely-not-configured.example.com")
    end

    test "tenant scoping isolates rows across tenants", %{tenant_id: tenant_a} do
      tenant_b = Ulid.generate()

      %Tenant{}
      |> Tenant.changeset(%{
        tenant_id: tenant_b,
        display_name: "tenant B",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      })
      |> Repo.insert!()

      # tenant_a configures chatgpt.com; tenant_b does NOT.
      {:ok, _} =
        %LlmProviderConfig{}
        |> LlmProviderConfig.changeset(valid_attrs(tenant_a))
        |> Repo.insert()

      assert {:ok, %LlmProviderConfig{}} = LlmProviders.lookup(tenant_a, "chatgpt.com")
      assert {:error, :not_configured} = LlmProviders.lookup(tenant_b, "chatgpt.com")
    end
  end

  describe "DB-layer invariants" do
    test "UNIQUE (tenant_id, provider, upstream_host) blocks duplicates", %{
      tenant_id: tenant_id
    } do
      {:ok, _} =
        %LlmProviderConfig{}
        |> LlmProviderConfig.changeset(valid_attrs(tenant_id))
        |> Repo.insert()

      assert {:error, %Ecto.Changeset{errors: errors}} =
               %LlmProviderConfig{}
               |> LlmProviderConfig.changeset(valid_attrs(tenant_id))
               |> Repo.insert()

      assert Keyword.has_key?(errors, :tenant_id) or
               Enum.any?(errors, fn {_k, {msg, _}} -> msg =~ "already" end)
    end

    test "CHECK constraint rejects unknown api_format inserted via raw SQL", %{
      tenant_id: tenant_id
    } do
      assert_raise Postgrex.Error, ~r/api_format_check/, fn ->
        SQL.query!(
          Repo,
          """
          INSERT INTO llm_provider_configs
            (tenant_id, provider, upstream_host, upstream_port, transport_modes,
             auth_mode, api_format, enabled, model_allowlist, metadata,
             inserted_at, updated_at)
          VALUES
            ($1, 'openai_chatgpt', 'chatgpt.com', 443, ARRAY['wss']::varchar[],
             'bearer', 'fake_format', true, ARRAY[]::varchar[], '{}'::jsonb,
             NOW(), NOW())
          """,
          [tenant_id]
        )
      end
    end

    test "CHECK constraint rejects unknown transport_modes via raw SQL", %{tenant_id: tenant_id} do
      assert_raise Postgrex.Error, ~r/transport_modes_check/, fn ->
        SQL.query!(
          Repo,
          """
          INSERT INTO llm_provider_configs
            (tenant_id, provider, upstream_host, upstream_port, transport_modes,
             auth_mode, api_format, enabled, model_allowlist, metadata,
             inserted_at, updated_at)
          VALUES
            ($1, 'openai_chatgpt', 'chatgpt.com', 443, ARRAY['carrier-pigeon']::varchar[],
             'bearer', 'openai_responses', true, ARRAY[]::varchar[], '{}'::jsonb,
             NOW(), NOW())
          """,
          [tenant_id]
        )
      end
    end

    test "CHECK constraint rejects empty transport_modes via raw SQL", %{tenant_id: tenant_id} do
      assert_raise Postgrex.Error, ~r/transport_modes_check/, fn ->
        SQL.query!(
          Repo,
          """
          INSERT INTO llm_provider_configs
            (tenant_id, provider, upstream_host, upstream_port, transport_modes,
             auth_mode, api_format, enabled, model_allowlist, metadata,
             inserted_at, updated_at)
          VALUES
            ($1, 'openai_chatgpt', 'chatgpt.com', 443, ARRAY[]::varchar[],
             'bearer', 'openai_responses', true, ARRAY[]::varchar[], '{}'::jsonb,
             NOW(), NOW())
          """,
          [tenant_id]
        )
      end
    end

    test "schema_migrations contains the 20260507000001 row" do
      %{rows: rows} =
        SQL.query!(
          Repo,
          "SELECT version FROM schema_migrations WHERE version = $1",
          [20_260_507_000_001]
        )

      assert [[20_260_507_000_001]] = rows
    end

    test "expected indexes exist" do
      %{rows: rows} =
        SQL.query!(
          Repo,
          """
          SELECT indexname FROM pg_indexes
          WHERE tablename = 'llm_provider_configs'
          ORDER BY indexname
          """,
          []
        )

      names = Enum.map(rows, &List.first/1)
      assert "llm_provider_configs_tenant_provider_host_index" in names
      assert "llm_provider_configs_tenant_enabled_index" in names
    end
  end
end
