defmodule Recurse.Providers.Schemas.LlmProviderConfigTest do
  @moduledoc """
  Schema-layer (in-memory) unit tests for
  `Recurse.Providers.Schemas.LlmProviderConfig`.

  Exercises `changeset/2`: required fields, enum rejection,
  array-element subset validation, port range, token-budget range.
  Does NOT hit Postgres — the DB-layer CHECK constraints + UNIQUE
  index are exercised by the migration smoke test in
  `test/recurse_providers/llm_providers_test.exs`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Schemas.LlmProviderConfig

  @tenant_id "01ARZ3NDEKTSV4RRFFQ69G5FAV"

  @valid_attrs %{
    tenant_id: @tenant_id,
    provider: "openai_chatgpt",
    upstream_host: "chatgpt.com",
    upstream_port: 443,
    transport_modes: ["wss", "https-sse"],
    auth_mode: :bearer_plus_chatgpt_account_id,
    api_format: :openai_responses,
    enabled: true,
    model_allowlist: ["gpt-5-codex"],
    metadata: %{"region" => "us-east-1"}
  }

  describe "changeset/2 — happy path" do
    test "valid attrs produce a valid changeset" do
      cs = LlmProviderConfig.changeset(%LlmProviderConfig{}, @valid_attrs)
      assert cs.valid?, "expected valid; got errors: #{inspect(cs.errors)}"
    end

    test "default values applied for omitted fields" do
      attrs = Map.drop(@valid_attrs, [:upstream_port, :enabled, :model_allowlist, :metadata])
      cs = LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs)
      assert cs.valid?
      # `upstream_port` defaults to 443 at the schema layer; default surfaces
      # only after `Ecto.Changeset.apply_changes/1` since cast doesn't put
      # field defaults into changes when key is absent. Validate via apply.
      applied = Ecto.Changeset.apply_changes(cs)
      assert applied.upstream_port == 443
      assert applied.enabled == true
      assert applied.model_allowlist == []
      assert applied.metadata == %{}
    end
  end

  describe "changeset/2 — required fields" do
    test "missing all required fields surfaces all errors" do
      cs = LlmProviderConfig.changeset(%LlmProviderConfig{}, %{})
      refute cs.valid?

      keys = Keyword.keys(cs.errors)
      assert :tenant_id in keys
      assert :provider in keys
      assert :upstream_host in keys
      assert :transport_modes in keys
      assert :auth_mode in keys
      assert :api_format in keys
    end

    test "missing only one required field is enough to invalidate" do
      attrs = Map.delete(@valid_attrs, :upstream_host)
      cs = LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs)
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :upstream_host)
    end
  end

  describe "Ecto.Enum rejection" do
    test "auth_mode rejects unknown atoms" do
      attrs = Map.put(@valid_attrs, :auth_mode, :bogus_auth)
      cs = LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs)
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :auth_mode)
    end

    test "api_format rejects unknown atoms" do
      attrs = Map.put(@valid_attrs, :api_format, :totally_made_up)
      cs = LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs)
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :api_format)
    end

    test "auth_mode accepts every contracted value" do
      for v <- [
            :bearer,
            :bearer_plus_chatgpt_account_id,
            :api_key,
            :aws_sigv4,
            :internal_none,
            :passthrough
          ] do
        attrs = Map.put(@valid_attrs, :auth_mode, v)
        assert LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
      end
    end

    test "api_format accepts every contracted value" do
      for v <- [
            :openai_responses,
            :openai_chat_completions,
            :anthropic_messages,
            :google_gemini,
            :openai_compatible
          ] do
        attrs = Map.put(@valid_attrs, :api_format, v)
        assert LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
      end
    end
  end

  describe "transport_modes — array subset validation" do
    test "rejects empty list" do
      attrs = Map.put(@valid_attrs, :transport_modes, [])
      cs = LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs)
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :transport_modes)
    end

    test "rejects unknown transport mode" do
      attrs = Map.put(@valid_attrs, :transport_modes, ["wss", "carrier-pigeon"])
      cs = LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs)
      refute cs.valid?
      {_, msg, _} = cs.errors[:transport_modes] |> elem(0) |> then(&{nil, &1, []})
      assert msg =~ "carrier-pigeon"
    end

    test "accepts singleton wss" do
      attrs = Map.put(@valid_attrs, :transport_modes, ["wss"])
      assert LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
    end

    test "accepts singleton https-sse" do
      attrs = Map.put(@valid_attrs, :transport_modes, ["https-sse"])
      assert LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
    end

    test "accepts both" do
      attrs = Map.put(@valid_attrs, :transport_modes, ["wss", "https-sse"])
      assert LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
    end
  end

  describe "upstream_port range" do
    test "rejects 0" do
      attrs = Map.put(@valid_attrs, :upstream_port, 0)
      refute LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
    end

    test "rejects > 65535" do
      attrs = Map.put(@valid_attrs, :upstream_port, 70_000)
      refute LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
    end

    test "accepts 65535" do
      attrs = Map.put(@valid_attrs, :upstream_port, 65_535)
      assert LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
    end
  end

  describe "default_token_budget_per_call" do
    test "nil is valid (unlimited)" do
      attrs = Map.put(@valid_attrs, :default_token_budget_per_call, nil)
      assert LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
    end

    test "rejects non-positive values" do
      for bad <- [0, -1, -1000] do
        attrs = Map.put(@valid_attrs, :default_token_budget_per_call, bad)
        refute LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
      end
    end

    test "accepts positive values" do
      attrs = Map.put(@valid_attrs, :default_token_budget_per_call, 8000)
      assert LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs).valid?
    end
  end
end
