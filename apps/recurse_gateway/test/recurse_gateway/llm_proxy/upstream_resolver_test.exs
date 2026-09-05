defmodule Recurse.Gateway.LlmProxy.UpstreamResolverTest do
  @moduledoc """
  Unit tests for `Recurse.Gateway.LlmProxy.UpstreamResolver`.

  Spec source of truth:
  `specs/009-llm-api-proxy/contracts/streaming_proxy.md` §UpstreamResolver
  + `specs/009-llm-api-proxy/data-model.md` §LlmProviderConfig.

  This is the gateway-side seam over `Recurse.Providers.LlmProviders.lookup/2`.
  The Provider context's tests already cover SQL invariants exhaustively
  (`apps/recurse_providers/test/recurse_providers/llm_providers_test.exs`);
  these tests focus on:

    * the gateway-side argument-shape contract
    * graceful handling of nil / non-binary inputs (which would
      crash at the provider layer's `is_binary` guard)
    * pass-through of all three result tags (`:ok`, `:not_configured`,
      `:not_allowed`)

  Uses the live SQL Sandbox per the F002 pattern.
  """

  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.LlmProxy.UpstreamResolver
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
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
      display_name: "UpstreamResolverTest tenant",
      tier: :standalone_gateway,
      created_at: DateTime.utc_now()
    })
    |> Repo.insert!()

    {:ok, tenant_id: tenant_id}
  end

  defp insert_config(tenant_id, opts \\ [])

  defp insert_config(tenant_id, opts) when is_list(opts) do
    attrs = %{
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

    {:ok, cfg} =
      %LlmProviderConfig{}
      |> LlmProviderConfig.changeset(attrs)
      |> Repo.insert()

    cfg
  end

  describe "resolve/2" do
    test "returns {:ok, cfg} when (tenant_id, host_header) matches an enabled row",
         %{tenant_id: tenant_id} do
      _ = insert_config(tenant_id)

      assert {:ok, %LlmProviderConfig{} = cfg} =
               UpstreamResolver.resolve(tenant_id, "chatgpt.com")

      assert cfg.tenant_id == tenant_id
      assert cfg.upstream_host == "chatgpt.com"
      assert cfg.enabled == true
      assert cfg.api_format == :openai_responses
    end

    test "returns {:error, :not_allowed} when row exists but disabled",
         %{tenant_id: tenant_id} do
      _ = insert_config(tenant_id, enabled: false)
      assert {:error, :not_allowed} = UpstreamResolver.resolve(tenant_id, "chatgpt.com")
    end

    test "returns {:error, :not_configured} when no row matches",
         %{tenant_id: tenant_id} do
      assert {:error, :not_configured} =
               UpstreamResolver.resolve(tenant_id, "unknown.example.com")
    end

    test "tenant scoping: tenant A's row does not leak to tenant B",
         %{tenant_id: tenant_a} do
      tenant_b = Ulid.generate()

      %Tenant{}
      |> Tenant.changeset(%{
        tenant_id: tenant_b,
        display_name: "tenant B",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      })
      |> Repo.insert!()

      _ = insert_config(tenant_a, upstream_host: "chatgpt.com")

      assert {:ok, %LlmProviderConfig{}} = UpstreamResolver.resolve(tenant_a, "chatgpt.com")
      assert {:error, :not_configured} = UpstreamResolver.resolve(tenant_b, "chatgpt.com")
    end

    test "exact host match — different upstream_host does not collide",
         %{tenant_id: tenant_id} do
      _ = insert_config(tenant_id, upstream_host: "chatgpt.com", provider: "openai_chatgpt")

      _ =
        insert_config(tenant_id,
          upstream_host: "api.openai.com",
          provider: "openai_api_key"
        )

      assert {:ok, %{upstream_host: "chatgpt.com", provider: "openai_chatgpt"}} =
               UpstreamResolver.resolve(tenant_id, "chatgpt.com")

      assert {:ok, %{upstream_host: "api.openai.com", provider: "openai_api_key"}} =
               UpstreamResolver.resolve(tenant_id, "api.openai.com")
    end

    test "nil tenant_id degrades to {:error, :not_configured}" do
      assert {:error, :not_configured} = UpstreamResolver.resolve(nil, "chatgpt.com")
    end

    test "nil host_header degrades to {:error, :not_configured}",
         %{tenant_id: tenant_id} do
      assert {:error, :not_configured} = UpstreamResolver.resolve(tenant_id, nil)
    end

    test "non-binary inputs degrade gracefully (no FunctionClauseError raise)" do
      assert {:error, :not_configured} = UpstreamResolver.resolve(:atom, :other_atom)
      assert {:error, :not_configured} = UpstreamResolver.resolve(123, [])
    end
  end
end
