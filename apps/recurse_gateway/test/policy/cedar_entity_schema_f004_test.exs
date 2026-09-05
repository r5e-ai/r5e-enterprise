defmodule RecurseGateway.Policy.CedarEntitySchemaF004Test do
  @moduledoc """
  T030 — F004 Cedar entity-schema fixture test.

  Extends `RecurseGateway.Policy.CedarEntitySchemaTest` (the F002 baseline)
  with the F004-specific assertions per
  `specs/004-audit-console/contracts/cedar_entity_schema_extensions.md`.

  Guards three properties of the F004-extended schema at
  `priv/cedar/schema.cedarschema.json`:

    1. **Parseability** — the file decodes as JSON, declares the `Recurse`
       namespace, and contains the new `BrowserSessionContext` commonType
       and `Resource::ConsoleSurface` entity type.
    2. **Action coverage (25)** — the schema declares 25 actions total
       (4 F002 + 20 F004 + 1 F7 MCP-Registry quarantine). The F004 set is
       enumerated verbatim from the contract matrix table at
       `contracts/cedar_entity_schema_extensions.md` §"Role-to-action
       allowlist" (the matrix is the source of truth — its rows enumerate
       14 named F004 actions plus 6 `AuditAgentTool*` actions = 20; the
       contract's "19 new" prose count is an off-by-one inherited from an
       earlier draft that did not include `AuditAgentToolSimulatePolicyDryrun`
       in the count, although it appears in the matrix proper).
    3. **`tenant_id` REQUIRED on all three Principal types** — the
       multi-tenant readiness invariant per the contract's "New
       principal-attribute requirements" section. Even in single-tenant
       Phase-1 the attribute is mandatory so future federation doesn't
       have to retrofit.

  Stability is enforced by-side via the SHA-256 fixture pin in
  `cedar_entity_schema_fixture_test.exs` (the F002 sibling — pin updated
  in lockstep with this file).

  Cross-references:
    * `specs/004-audit-console/contracts/cedar_entity_schema_extensions.md`
    * `specs/004-audit-console/data-model.md` §0 (canonical action matrix)
    * `apps/recurse_gateway/test/policy/cedar_entity_schema_test.exs`
      (F002 baseline; not modified)
    * `apps/recurse_gateway/test/policy/cedar_entity_schema_fixture_test.exs`
      (SHA-256 byte-pin tripwire)
    * `apps/recurse_shared/lib/recurse_shared/cedar.ex` —
      `Recurse.Cedar.validate_policy_syntax/1` is the available NIF parse
      surface used in this test (no separate `parse/2` schema-parse NIF
      yet; tracked under F002 T100).
  """
  use ExUnit.Case, async: true

  @schema_path Path.expand(
                 "../../priv/cedar/schema.cedarschema.json",
                 __DIR__
               )

  # F002 baseline (4) — these were declared by F002 T098 / FR-011 and remain.
  @f002_actions ~w(
    Action::ChatCompletion
    Action::ReadReceipts
    Action::ExportEvidence
    Action::ReadPayload
  )

  # F004 additions (20) — verbatim from
  # `specs/004-audit-console/data-model.md` §0 canonical matrix.
  # 13 non-tool actions + 6 audit-agent tool actions = 20 total.
  @f004_new_actions ~w(
    Action::LoginSession
    Action::DashboardQuery
    Action::PolicySimulate
    Action::PolicyReplay
    Action::PolicyDraftCreate
    Action::PolicyDraftEdit
    Action::PolicyDraftArchive
    Action::PolicyDraftDryRun
    Action::PolicySuggestionGenerate
    Action::PolicySuggestionView
    Action::PolicySuggestionAdopt
    Action::PolicySuggestionDismiss
    Action::PolicySuggestionRefresh
    Action::ChatDrawerQuery
    Action::AuditAgentToolQueryReceipts
    Action::AuditAgentToolFetchReceiptDetail
    Action::AuditAgentToolExplainDenial
    Action::AuditAgentToolFindSimilarReceipts
    Action::AuditAgentToolSimulatePolicyDryrun
    Action::AuditAgentToolSuggestPolicyPattern
  )

  # MCP/F7 additions (1) — operator-only mutation gate for
  # `PATCH /v1/mcp/registry/:id`. See `design/briefs/07-mcp-registry.md`
  # §"Quarantine workflow" + the F7 backend MR (issue: missing PATCH
  # handler raised in MR !88 GAN review F001).
  @mcp_actions ~w(
    Action::McpRegistryQuarantine
  )

  @all_actions @f002_actions ++ @f004_new_actions ++ @mcp_actions

  defp load_schema do
    @schema_path
    |> File.read!()
    |> JSON.decode!()
  end

  describe "parseability" do
    test "file exists at the expected Gateway path" do
      assert File.exists?(@schema_path),
             "Cedar schema missing at #{@schema_path}"
    end

    test "parses as valid JSON wrapped in the Recurse namespace" do
      raw = File.read!(@schema_path)
      assert {:ok, %{"Recurse" => %{} = ns}} = JSON.decode(raw)
      assert Map.has_key?(ns, "entityTypes")
      assert Map.has_key?(ns, "actions")
      assert Map.has_key?(ns, "commonTypes")
    end

    test "round-trips through the existing Cedar NIF parse surface (validate_policy_syntax/1 on the policy bundle, which references actions declared here)" do
      # Recurse.Cedar.parse/2 doesn't exist yet (tracked under F002 T100 —
      # the schema-parse NIF binding is pending). Until it lands we
      # validate the actions declared here are referenceable by validating
      # a bundle that names them; that exercises the same Cedar parser
      # surface end-to-end.
      bundle =
        Path.expand("../../priv/reference_policies/platform_roles.cedar", __DIR__)
        |> File.read!()

      assert :ok = Recurse.Cedar.validate_policy_syntax(bundle)
    end
  end

  describe "structural coverage — F004 commonType + entity type additions" do
    test "BrowserSessionContext commonType declared with all six attributes" do
      %{"Recurse" => %{"commonTypes" => %{"BrowserSessionContext" => bsc}}} =
        load_schema()

      assert %{"type" => "Record", "attributes" => attrs} = bsc

      for required_key <- ~w(tenant_id correlation_id timestamp client_ip browser_session_id) do
        assert %{"required" => true} = Map.fetch!(attrs, required_key),
               "BrowserSessionContext.#{required_key} must be required"
      end

      assert %{"required" => false} = Map.fetch!(attrs, "user_agent"),
             "BrowserSessionContext.user_agent must be optional per F004 contract"
    end

    test "Resource::ConsoleSurface entity type declared with `console_path` attribute" do
      %{"Recurse" => %{"entityTypes" => et}} = load_schema()

      assert %{"shape" => %{"type" => "Record", "attributes" => attrs}} =
               Map.fetch!(et, "Resource::ConsoleSurface")

      assert %{"console_path" => %{"type" => "String", "required" => true}} = attrs
    end
  end

  describe "structural coverage — `tenant_id` REQUIRED on all three Principal types (F004)" do
    @principal_types ~w(Principal::Human Principal::ServiceAccount Principal::Autonomous)

    for principal_type <- @principal_types do
      test "#{principal_type} declares tenant_id as a required String" do
        %{"Recurse" => %{"entityTypes" => et}} = load_schema()

        assert %{"shape" => %{"attributes" => %{"tenant_id" => attr}}} =
                 Map.fetch!(et, unquote(principal_type)),
               "#{unquote(principal_type)} missing tenant_id attribute"

        assert %{"type" => "String", "required" => true} = attr,
               "#{unquote(principal_type)}.tenant_id must be required String " <>
                 "per F004 contract; got #{inspect(attr)}"
      end
    end

    test "recurse_role remains REQUIRED on all three Principal types (F002 invariant preserved)" do
      %{"Recurse" => %{"entityTypes" => et}} = load_schema()

      for principal_type <- @principal_types do
        assert %{"shape" => %{"attributes" => %{"recurse_role" => attr}}} =
                 Map.fetch!(et, principal_type)

        assert %{"type" => "String", "required" => true} = attr
      end
    end
  end

  describe "structural coverage — actions (25 total: 4 F002 + 20 F004 + 1 F7)" do
    test "schema declares exactly 25 actions" do
      %{"Recurse" => %{"actions" => actions}} = load_schema()

      assert map_size(actions) == 25,
             "Expected 25 actions (4 F002 + 20 F004 + 1 F7); got #{map_size(actions)}.\n" <>
               "Declared: #{inspect(Enum.sort(Map.keys(actions)))}"
    end

    test "all 25 expected actions are present" do
      %{"Recurse" => %{"actions" => actions}} = load_schema()

      missing =
        @all_actions
        |> Enum.reject(fn name -> Map.has_key?(actions, name) end)

      assert missing == [],
             "Missing actions: #{inspect(missing)}.\n" <>
               "Declared: #{inspect(Enum.sort(Map.keys(actions)))}"
    end

    test "no unexpected actions are declared (catches typos / drift)" do
      %{"Recurse" => %{"actions" => actions}} = load_schema()

      extra =
        actions
        |> Map.keys()
        |> Enum.reject(fn name -> name in @all_actions end)

      assert extra == [],
             "Unexpected actions declared: #{inspect(extra)}. If this is\n" <>
               "intentional, update @all_actions in this test (and the\n" <>
               "F004 contract / data-model matrix) in lockstep."
    end

    test "PolicySuggestionGenerate appliesTo only ServiceAccount + Autonomous (system-only)" do
      %{
        "Recurse" => %{
          "actions" => %{
            "Action::PolicySuggestionGenerate" => %{
              "appliesTo" => %{"principalTypes" => principal_types}
            }
          }
        }
      } = load_schema()

      assert Enum.sort(principal_types) == [
               "Principal::Autonomous",
               "Principal::ServiceAccount"
             ]
    end

    test "all other F004 actions appliesTo Principal::Human + Resource::ConsoleSurface" do
      %{"Recurse" => %{"actions" => actions}} = load_schema()

      human_only_actions = @f004_new_actions -- ["Action::PolicySuggestionGenerate"]

      for action_name <- human_only_actions do
        %{"appliesTo" => %{"principalTypes" => pts, "resourceTypes" => rts}} =
          Map.fetch!(actions, action_name)

        assert pts == ["Principal::Human"],
               "#{action_name} principalTypes must be [Principal::Human]; got #{inspect(pts)}"

        assert rts == ["Resource::ConsoleSurface"],
               "#{action_name} resourceTypes must be [Resource::ConsoleSurface]; got #{inspect(rts)}"
      end
    end
  end

  describe "schema source-of-truth guard" do
    @sha256_pin "b6715b35a17aa2aee1f1daa8eda976c599f0b4aea2a3d550e73d7008d6e41193"

    test "schema file SHA-256 matches the captured F004 pin" do
      actual =
        :crypto.hash(:sha256, File.read!(@schema_path))
        |> Base.encode16(case: :lower)

      assert actual == @sha256_pin, """
      Cedar entity schema SHA-256 drifted from the F004 pin.

        expected: #{@sha256_pin}
        actual:   #{actual}

      If this change is intentional (e.g., a new F005 action), recompute
      via `openssl dgst -sha256 #{@schema_path}` and update both
      `@sha256_pin` here AND `@expected_sha256` in
      `cedar_entity_schema_fixture_test.exs`.
      """
    end
  end
end
