defmodule RecurseGateway.Policy.CedarEntitySchemaTest do
  @moduledoc """
  T098 — Cedar entity schema fixture test.

  Guards three properties of the F002 Cedar Entity Schema
  (`priv/cedar/schema.cedarschema.json`):

    1. **Parseability** — the file is valid JSON in the Cedar schema
       shape expected by the evaluator at boot (`Recurse::*` namespace
       with `entityTypes`, `actions`, `commonTypes`).
    2. **Structural coverage** — the schema declares the entity types
       and actions required by F002 FR-011 (Principal::Human /
       ServiceAccount / Autonomous; Resource::LLMEndpoint /
       AuditEndpoint / PayloadBroker; Action::ChatCompletion /
       ReadReceipts / ExportEvidence / ReadPayload).
    3. **Schema source-of-truth guard** — the Gateway's on-disk copy is
       byte-identical to the contract copy under
       `specs/002-standalone-gateway-vertical-slice/contracts/`. Any
       drift fails CI, forcing a deliberate dual-update.

  Cross-reference:
    * `specs/002-standalone-gateway-vertical-slice/contracts/cedar_entity_schema.cedarschema.json`
      — canonical source of truth.
    * `apps/recurse_shared/lib/recurse_shared/cedar.ex` — `Recurse.Cedar`
      facade (no `schema_from_json/1` surface yet; see T100 for the
      forthcoming NIF schema-parse binding).
    * `apps/recurse_gateway/test/policy/cedar_entity_schema_fixture_test.exs`
      — SHA-256 pin tripwire. Complementary; this test is semantic, that
      one is byte-identity.
  """
  use ExUnit.Case, async: true

  @gateway_schema_path Path.expand(
                         "../../priv/cedar/schema.cedarschema.json",
                         __DIR__
                       )

  @contract_schema_path Path.expand(
                          "../../../../specs/002-standalone-gateway-vertical-slice/contracts/cedar_entity_schema.cedarschema.json",
                          __DIR__
                        )

  describe "parseability" do
    test "file exists at the expected Gateway path" do
      assert File.exists?(@gateway_schema_path),
             "Cedar schema missing at #{@gateway_schema_path}"
    end

    test "parses as valid JSON" do
      raw = File.read!(@gateway_schema_path)
      assert {:ok, %{} = parsed} = JSON.decode(raw)
      # Top-level is the `Recurse` namespace wrapper.
      assert Map.has_key?(parsed, "Recurse")
    end

    test "Recurse namespace has entityTypes + actions + commonTypes" do
      %{"Recurse" => ns} = load_gateway_schema()

      assert %{"entityTypes" => et} = ns
      assert is_map(et) and map_size(et) > 0

      assert %{"actions" => ac} = ns
      assert is_map(ac) and map_size(ac) > 0

      assert %{"commonTypes" => ct} = ns
      assert is_map(ct) and map_size(ct) > 0
    end
  end

  describe "structural coverage — entity types (F002 FR-011)" do
    @expected_entity_types ~w(
      Principal::Human
      Principal::ServiceAccount
      Principal::Autonomous
      Resource::LLMEndpoint
      Resource::AuditEndpoint
      Resource::PayloadBroker
    )

    test "all required entity types declared" do
      %{"Recurse" => %{"entityTypes" => et}} = load_gateway_schema()

      for expected <- @expected_entity_types do
        assert Map.has_key?(et, expected),
               "Missing entity type `Recurse::#{expected}` — required by F002 FR-011.\n" <>
                 "Declared: #{inspect(Map.keys(et))}"
      end
    end

    test "Principal::Human has `recurse_role` attribute (F001 FR-026)" do
      %{"Recurse" => %{"entityTypes" => %{"Principal::Human" => human}}} =
        load_gateway_schema()

      assert %{
               "shape" => %{
                 "attributes" => %{
                   "recurse_role" => %{"type" => "String", "required" => true}
                 }
               }
             } = human
    end
  end

  describe "structural coverage — actions (F002 FR-011)" do
    @expected_actions ~w(
      Action::ChatCompletion
      Action::ReadReceipts
      Action::ExportEvidence
      Action::ReadPayload
    )

    test "all required actions declared" do
      %{"Recurse" => %{"actions" => actions}} = load_gateway_schema()

      for expected <- @expected_actions do
        assert Map.has_key?(actions, expected),
               "Missing action `Recurse::#{expected}` — required by F002 FR-011.\n" <>
                 "Declared: #{inspect(Map.keys(actions))}"
      end
    end

    test "Action::ChatCompletion applies to all three Principal types" do
      %{"Recurse" => %{"actions" => %{"Action::ChatCompletion" => chat}}} =
        load_gateway_schema()

      assert %{"appliesTo" => %{"principalTypes" => principal_types}} = chat

      assert Enum.sort(principal_types) == [
               "Principal::Autonomous",
               "Principal::Human",
               "Principal::ServiceAccount"
             ]

      assert %{"appliesTo" => %{"resourceTypes" => ["Resource::LLMEndpoint"]}} = chat
    end

    test "Action::ChatCompletion context requires tenant_id + correlation_id + timestamp + client_ip + streaming + model" do
      %{
        "Recurse" => %{
          "actions" => %{
            "Action::ChatCompletion" => %{
              "appliesTo" => %{"context" => %{"attributes" => ctx}}
            }
          }
        }
      } = load_gateway_schema()

      for required_key <- ~w(tenant_id correlation_id timestamp client_ip streaming model) do
        assert %{"required" => true} = Map.fetch!(ctx, required_key),
               "Action::ChatCompletion context attribute `#{required_key}` must be required"
      end
    end

    test "ExportEvidence context carries the run_ids set" do
      %{
        "Recurse" => %{
          "actions" => %{
            "Action::ExportEvidence" => %{
              "appliesTo" => %{"context" => %{"attributes" => ctx}}
            }
          }
        }
      } = load_gateway_schema()

      assert %{
               "run_ids" => %{
                 "type" => "Set",
                 "element" => %{"type" => "String"},
                 "required" => true
               }
             } = ctx
    end
  end

  describe "common types" do
    test "CorrelationContext is declared with the four standard attributes" do
      %{"Recurse" => %{"commonTypes" => %{"CorrelationContext" => cc}}} =
        load_gateway_schema()

      assert %{
               "type" => "Record",
               "attributes" => %{
                 "tenant_id" => %{"type" => "String", "required" => true},
                 "correlation_id" => %{"type" => "String", "required" => true},
                 "timestamp" => %{"type" => "Long", "required" => true},
                 "client_ip" => %{"type" => "String", "required" => true}
               }
             } = cc
    end
  end

  describe "schema source-of-truth guard" do
    test "Gateway copy is byte-identical to the contract copy" do
      gateway_bytes = File.read!(@gateway_schema_path)
      contract_bytes = File.read!(@contract_schema_path)

      # Fail with a hex-digest diff so drift is immediately diagnosable.
      gateway_sha = :crypto.hash(:sha256, gateway_bytes) |> Base.encode16(case: :lower)
      contract_sha = :crypto.hash(:sha256, contract_bytes) |> Base.encode16(case: :lower)

      assert gateway_bytes == contract_bytes, """
      Cedar schema drift between contract and Gateway copy:

        contract: #{@contract_schema_path}
          sha256: #{contract_sha}
        gateway:  #{@gateway_schema_path}
          sha256: #{gateway_sha}

      Both files MUST be byte-identical. If the contract changed, copy it to
      the Gateway side (and update the SHA pin in
      `cedar_entity_schema_fixture_test.exs`). If the Gateway side changed,
      upstream the change to the contract first.
      """
    end
  end

  describe "NIF surface (T100 recheck)" do
    @tag :pending
    test "Cedar NIF exposes a schema_from_json/1 function" do
      # T100 will add a schema-parse NIF binding (currently the Rust NIF
      # only exposes `canonical_hash/1`, `validate_policy_syntax/1`,
      # `evaluate/2`, and `evaluate_with_entities/3` — grep
      # `native/recurse_cedar/src/lib.rs` for the current surface).
      #
      # When T100 lands, flip this tag off and assert:
      #   assert {:ok, _schema} =
      #            File.read!(@gateway_schema_path)
      #            |> Recurse.Cedar.schema_from_json()
      flunk("pending — T100 will add Recurse.Cedar.schema_from_json/1")
    end
  end

  # -- helpers ---------------------------------------------------------------

  defp load_gateway_schema do
    @gateway_schema_path
    |> File.read!()
    |> JSON.decode!()
  end
end
