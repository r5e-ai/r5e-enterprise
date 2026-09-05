defmodule Recurse.Gateway.Policy.ComposeDefaultBundleTest do
  @moduledoc """
  Guards the quickstart's default Cedar bundle at `policy/bundle.cedar`
  (spec 012 D6). It must parse under the pinned Cedar NIF, canonical-hash
  cleanly, and make the decisions the README promises on two planes:

    * tool calls, in the `ToolUse::"<tool>"` shape the LLM proxy presents
      (see `Recurse.Gateway.LlmProxy.CedarToolUseGate.build_cedar_context/2`
      for the context, including the case where `tool_args` is NOT inlined
      because the input exceeded the size threshold);
    * the audit plane, through the same `Recurse.Gateway.Policy.Evaluator`
      path `Recurse.Gateway.AuditPlane.Authz.gate/4` uses, so the role model
      from `priv/reference_policies/platform_roles.cedar` survives in the
      single compose bundle.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.Policy.Evaluator
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @bundle_path Path.expand("../../../../policy/bundle.cedar", __DIR__)
  @schema_path Path.expand("../../priv/cedar/schema.cedarschema.json", __DIR__)

  # Every shell-shaped tool the bundle governs, with the argument key(s)
  # each shape carries its command under.
  @shell_shapes [
    {"Bash", "command"},
    {"shell", "command"},
    {"exec_command", "cmd"},
    {"local_shell", "cmd"},
    {"local_shell", "command"},
    {"unified_exec", "cmd"},
    {"unified_exec", "command"}
  ]

  @destructive [
    "rm -rf /tmp/scratch",
    "psql -c 'DROP DATABASE prod'",
    "git push --force origin main",
    "cat disk.img > /dev/sda"
  ]

  @ordinary ["ls -la", "git push origin feature", "cat README.md"]

  setup_all do
    {:ok, bundle: File.read!(@bundle_path)}
  end

  test "bundle exists at the path compose bind-mounts and parses", %{bundle: bundle} do
    assert File.regular?(@bundle_path)
    assert :ok = Recurse.Cedar.validate_policy_syntax(bundle)
    assert <<_::binary-size(32)>> = Recurse.Cedar.canonical_hash(bundle)
  end

  test "loads through the FilesystemPolicyProvider boot path with the baked entity schema" do
    # Exactly what the container does: RECURSE_POLICY_BUNDLE_PATH=/policy/bundle.cedar +
    # the schema baked at RECURSE_POLICY_SCHEMA_PATH.
    assert {:ok, state} =
             Recurse.Providers.Impls.FilesystemPolicyProvider.init(%{
               bundle_path: @bundle_path,
               entity_schema_path: @schema_path,
               reload_on_sighup: false
             })

    assert is_map(state)
  end

  describe "tool calls (D6)" do
    test "denies destructive Bash commands and allows ordinary ones", %{bundle: bundle} do
      for command <- @destructive do
        assert :deny = decide(bundle, "Bash", "command", command), command
      end

      for command <- @ordinary do
        assert :allow = decide(bundle, "Bash", "command", command), command
      end
    end

    test "covers every Codex shell shape with the same patterns", %{bundle: bundle} do
      for {tool, key} <- @shell_shapes, command <- @destructive do
        assert :deny = decide(bundle, tool, key, command), "#{tool}.#{key}: #{command}"
      end

      for {tool, key} <- @shell_shapes, command <- @ordinary do
        assert :allow = decide(bundle, tool, key, command), "#{tool}.#{key}: #{command}"
      end
    end

    test "fails closed: a shell tool whose tool_args were not inlined is denied",
         %{bundle: bundle} do
      # What CedarToolUseGate.build_cedar_context/2 emits when the input exceeds
      # `cedar_args_inline_threshold_bytes`: hash + size, no `tool_args`.
      oversized = %{
        "tool_args_hash" => String.duplicate("ab", 32),
        "tool_args_size_bytes" => 20_000
      }

      for {tool, _key} <- @shell_shapes do
        request = request_json(tool, oversized)

        assert {:ok, %{decision: :deny}} =
                 Recurse.Cedar.evaluate_with_entities(bundle, request, entities(tool)),
               "#{tool} without tool_args must be denied"
      end
    end

    test "non-shell tools without tool_args fall through to the baseline permit",
         %{bundle: bundle} do
      request = request_json("Read", %{})

      assert {:ok, %{decision: :allow}} =
               Recurse.Cedar.evaluate_with_entities(bundle, request, entities("Read"))
    end
  end

  describe "audit plane (platform_roles.cedar role model)" do
    setup %{bundle: bundle} do
      {:ok, ref: bundle_ref(bundle)}
    end

    test "a caller is denied ExportEvidence; a platform_operator is allowed", %{ref: ref} do
      assert {:deny, matched} =
               Evaluator.evaluate(ref, identity("caller"), audit_request("ExportEvidence"))

      refute matched == [:cedar_error]

      assert {:allow, matched} =
               Evaluator.evaluate(
                 ref,
                 identity("platform_operator"),
                 audit_request("ExportEvidence")
               )

      refute matched == [:cedar_error]
    end

    test "the baseline permit does not leak into the audit plane", %{ref: ref} do
      # A principal with no role at all: the old `permit (principal, action,
      # resource)` allowed this; the invoke_tool-scoped one must not.
      for action <- ~w(ReadReceipts ReadPayload ExportEvidence DashboardQuery PolicyDraftCreate) do
        assert {:deny, _} = Evaluator.evaluate(ref, identity(nil), audit_request(action)), action
      end
    end

    test "the dev login's default role (platform_operator) passes the console checks",
         %{ref: ref} do
      # `bin/r5e login` mints platform_operator; these are the actions the
      # dashboard exercises right after sign-in.
      for action <-
            ~w(LoginSession DashboardQuery ReadReceipts ReadPayload ExportEvidence PolicySimulate PolicyDraftCreate) do
        assert {:allow, _} =
                 Evaluator.evaluate(ref, identity("platform_operator"), audit_request(action)),
               action
      end
    end

    test "tenant_auditor keeps read-only scope", %{ref: ref} do
      assert {:allow, _} =
               Evaluator.evaluate(
                 ref,
                 identity("tenant_auditor"),
                 audit_request("DashboardQuery")
               )

      assert {:deny, _} =
               Evaluator.evaluate(
                 ref,
                 identity("tenant_auditor"),
                 audit_request("PolicyDraftCreate")
               )

      assert {:deny, _} =
               Evaluator.evaluate(
                 ref,
                 identity("tenant_auditor"),
                 audit_request("McpRegistryQuarantine")
               )
    end
  end

  # ---------------------------------------------------------------------------
  # Tool-call helpers (raw NIF request, same shape as CedarToolUseGate)
  # ---------------------------------------------------------------------------

  defp decide(bundle, tool, arg_key, value) do
    request = request_json(tool, %{"tool_args" => %{arg_key => value}})

    {:ok, %{decision: decision}} =
      Recurse.Cedar.evaluate_with_entities(bundle, request, entities(tool))

    decision
  end

  defp request_json(tool, context) do
    JSON.encode!(%{
      "principal" => ~s[User::"local-dev@r5e"],
      "action" => ~s[Action::"invoke_tool"],
      "resource" => ~s[ToolUse::"#{tool}"],
      "context" => context
    })
  end

  defp entities(tool) do
    JSON.encode!([
      %{"uid" => %{"type" => "User", "id" => "local-dev@r5e"}, "attrs" => %{}, "parents" => []},
      %{"uid" => %{"type" => "ToolUse", "id" => tool}, "attrs" => %{}, "parents" => []}
    ])
  end

  # ---------------------------------------------------------------------------
  # Audit-plane helpers (Evaluator path, same as AuditPlane.Authz)
  # ---------------------------------------------------------------------------

  defp bundle_ref(bytes) do
    canonical_hash = Recurse.Cedar.canonical_hash(bytes)

    %PolicyBundleRef{
      bundle_id: Base.encode16(canonical_hash, case: :lower),
      canonical_hash: canonical_hash,
      loaded_at: DateTime.utc_now(),
      evaluator_handle: bytes,
      bundle_bytes: bytes
    }
  end

  defp identity(role) do
    IdentityContext.new(%{
      machine_identity: "spiffe://recurse.test/workload/test",
      principal:
        Principal.obo_human(%{
          issuer: "http://localhost:4000",
          subject: "local-dev@r5e",
          display_name: "Local Dev",
          groups: [],
          recurse_role: role
        }),
      tenant_id: "01TEN_LOCAL",
      correlation_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    })
  end

  defp audit_request(action) do
    %{
      action: ~s[Recurse::Action::"#{action}"],
      resource: %{
        type: "Recurse::Resource::AuditEndpoint",
        id: "compose_bundle_test",
        attrs: %{"endpoint" => "/v1/audit/test"}
      },
      context: %{"client_ip" => "127.0.0.1"}
    }
  end
end
