defmodule Recurse.Gateway.Policy.EvaluatorTest do
  @moduledoc """
  Tests for `Recurse.Gateway.Policy.Evaluator` (F002 T047).

  Fixtures are the Wave 2-A reference policies at
  `apps/recurse_gateway/priv/reference_policies/`. The evaluator composes
  a Cedar entity set from an `IdentityContext` + request and invokes
  `Recurse.Cedar.evaluate_with_entities/3`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.Policy.Evaluator
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @permissive_path Path.expand(
                     "../../priv/reference_policies/permissive_all.cedar",
                     __DIR__
                   )
  @platform_roles_path Path.expand(
                         "../../priv/reference_policies/platform_roles.cedar",
                         __DIR__
                       )

  defp bundle_ref_for(path) do
    bytes = File.read!(path)
    canonical_hash = Recurse.Cedar.canonical_hash(bytes)

    %PolicyBundleRef{
      bundle_id: Base.encode16(canonical_hash, case: :lower),
      canonical_hash: canonical_hash,
      loaded_at: DateTime.utc_now(),
      evaluator_handle: bytes,
      bundle_bytes: bytes
    }
  end

  defp identity_context_with_role(role, opts \\ []) do
    kind = Keyword.get(opts, :kind, :obo_human)

    principal =
      case kind do
        :obo_human ->
          Principal.obo_human(%{
            issuer: "https://idp.test",
            subject: "alice",
            display_name: "Alice",
            groups: ["engineering"],
            recurse_role: role
          })

        :service_account ->
          Principal.service_account(%{
            issuer: "https://idp.test",
            account_id: "svc-1",
            scope: ["chat"],
            recurse_role: role
          })

        :autonomous ->
          Principal.autonomous(%{
            spiffe_id: "spiffe://recurse.test/workload/alice",
            recurse_role: role
          })
      end

    IdentityContext.new(%{
      machine_identity: "spiffe://recurse.test/workload/test",
      principal: principal,
      tenant_id: "tenant-test",
      correlation_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    })
  end

  defp chat_completion_request do
    %{
      action: ~s[Recurse::Action::"ChatCompletion"],
      resource: %{
        type: "Recurse::Resource::LLMEndpoint",
        id: "openai_chat_completions",
        attrs: %{"model" => "gpt-4o-mini", "provider" => "openai"}
      },
      context: %{
        "streaming" => true,
        "model" => "gpt-4o-mini",
        "client_ip" => "192.0.2.1"
      }
    }
  end

  defp read_receipts_request do
    %{
      action: ~s[Recurse::Action::"ReadReceipts"],
      resource: %{
        type: "Recurse::Resource::AuditEndpoint",
        id: "read_receipts",
        attrs: %{"endpoint" => "/v1/audit/receipts"}
      },
      context: %{
        "client_ip" => "192.0.2.1"
      }
    }
  end

  describe "permissive_all policy" do
    setup do
      %{bundle: bundle_ref_for(@permissive_path)}
    end

    test "allows any principal with any action on any resource", %{bundle: bundle} do
      ctx = identity_context_with_role("caller")

      assert {:allow, matched} = Evaluator.evaluate(bundle, ctx, chat_completion_request())
      assert matched != [:cedar_error]
      assert is_list(matched)
    end

    test "allows ServiceAccount principals", %{bundle: bundle} do
      ctx = identity_context_with_role("caller", kind: :service_account)

      assert {:allow, _} = Evaluator.evaluate(bundle, ctx, chat_completion_request())
    end

    test "allows Autonomous principals", %{bundle: bundle} do
      ctx = identity_context_with_role("caller", kind: :autonomous)

      assert {:allow, _} = Evaluator.evaluate(bundle, ctx, chat_completion_request())
    end
  end

  describe "platform_roles policy" do
    setup do
      %{bundle: bundle_ref_for(@platform_roles_path)}
    end

    test "caller + ChatCompletion => allow", %{bundle: bundle} do
      ctx = identity_context_with_role("caller")

      assert {:allow, _} = Evaluator.evaluate(bundle, ctx, chat_completion_request())
    end

    test "caller + ReadReceipts => deny", %{bundle: bundle} do
      ctx = identity_context_with_role("caller")

      assert {:deny, _} = Evaluator.evaluate(bundle, ctx, read_receipts_request())
    end

    test "tenant_auditor + ReadReceipts => allow", %{bundle: bundle} do
      ctx = identity_context_with_role("tenant_auditor")

      assert {:allow, _} = Evaluator.evaluate(bundle, ctx, read_receipts_request())
    end

    test "tenant_auditor + ChatCompletion => deny", %{bundle: bundle} do
      ctx = identity_context_with_role("tenant_auditor")

      assert {:deny, _} = Evaluator.evaluate(bundle, ctx, chat_completion_request())
    end

    test "platform_operator + ChatCompletion => deny (F004 narrowing — Data-Plane is caller-only)",
         %{bundle: bundle} do
      # F004 (cedar_entity_schema_extensions.md §"Role-to-action allowlist")
      # narrowed the prior unconditional `operator → all actions` rule. The
      # operator role is for audit-console / audit-plane access; LLM end-user
      # `ChatCompletion` requires the `caller` role.
      ctx = identity_context_with_role("platform_operator")

      assert {:deny, _} = Evaluator.evaluate(bundle, ctx, chat_completion_request())
    end

    test "platform_operator + ReadReceipts => allow (unrestricted)", %{bundle: bundle} do
      ctx = identity_context_with_role("platform_operator")

      assert {:allow, _} = Evaluator.evaluate(bundle, ctx, read_receipts_request())
    end

    test "unknown role => deny", %{bundle: bundle} do
      ctx = identity_context_with_role("rando")

      assert {:deny, _} = Evaluator.evaluate(bundle, ctx, chat_completion_request())
    end

    test "nil recurse_role => deny (defense-in-depth)", %{bundle: bundle} do
      # Principal built without a recurse_role; the evaluator supplies "" and
      # no `permit` clause's guard matches.
      principal = Principal.obo_human(%{issuer: "https://idp.test", subject: "bob"})

      ctx =
        IdentityContext.new(%{
          machine_identity: "spiffe://recurse.test/workload/bob",
          principal: principal,
          tenant_id: "tenant-test",
          correlation_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ"
        })

      assert {:deny, _} = Evaluator.evaluate(bundle, ctx, chat_completion_request())
    end
  end

  describe "fail-closed on evaluator errors" do
    test "malformed resource => deny with :cedar_error sentinel" do
      bundle = bundle_ref_for(@permissive_path)
      ctx = identity_context_with_role("caller")

      malformed_request = %{
        action: ~s[Recurse::Action::"ChatCompletion"],
        resource: :not_a_map,
        context: %{}
      }

      assert {:deny, [:cedar_error]} = Evaluator.evaluate(bundle, ctx, malformed_request)
    end
  end
end
