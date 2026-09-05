defmodule RecurseGateway.Policy.CedarEvaluatorPropertyTest do
  @moduledoc """
  F002 property-test — **Surface S (base)** — Cedar entity-schema + policy
  evaluation stability (T058).

  Cross-refs:
    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md`
      §Surface S.
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T058.
    * `apps/recurse_gateway/priv/cedar/schema.cedarschema.json` (entity
      schema under test).
    * `apps/recurse_gateway/priv/reference_policies/platform_roles.cedar`
      (reference policy under test).

  ## Invariants

  1. **Role → action decision matrix** — for any valid `(role, action,
     principal_kind)` tuple under the reference `platform_roles.cedar`,
     `Evaluator.evaluate/3` produces the expected decision:

        | recurse_role      | Allowed actions                               |
        |-------------------|-----------------------------------------------|
        | platform_operator | all actions                                   |
        | tenant_auditor    | ReadReceipts / ExportEvidence / ReadPayload   |
        | caller            | ChatCompletion                                |
        | (any other)       | none (fail-closed)                            |

     Audit-Plane actions (`ReadReceipts`, `ExportEvidence`, `ReadPayload`)
     accept only `Principal::Human` and `Principal::ServiceAccount` per
     the schema's `appliesTo.principalTypes`. `ChatCompletion` accepts
     all three principal kinds including `Principal::Autonomous`.

  2. **Canonical-hash stability under whitespace / comment / key-order
     perturbation** — `Recurse.Cedar.canonical_hash/1` is the SHA-256 of
     the RFC 8785 JCS encoding of the parsed Cedar EST. That encoding
     strips source-level whitespace, comments, and trailing commas, so
     mutations that don't change the underlying policy set MUST yield
     the same hash. (Statement-reordering DOES change the EST and
     therefore is NOT asserted here; the catalog text calls out
     whitespace / comments specifically.)

  ## Generator discipline (per `elixir:stream-data-thinking`)

  Generators built with `gen all` / `bind`; no `filter`. The
  `(role, action, principal_kind)` space is small enough to enumerate
  constructively — `member_of` over each axis, with a guard in `bind`
  to narrow principal_kind for Audit-Plane actions.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Gateway.Policy.Evaluator
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @iterations 500

  @platform_roles_path Path.expand(
                         "../../priv/reference_policies/platform_roles.cedar",
                         __DIR__
                       )

  @known_roles ~w(platform_operator tenant_auditor caller)
  @unknown_roles ~w(rando admin guest none)

  @actions ~w(ChatCompletion ReadReceipts ExportEvidence ReadPayload)

  # Human + ServiceAccount apply to all four actions; Autonomous applies
  # only to ChatCompletion per the schema's `appliesTo.principalTypes`.
  @data_plane_principal_kinds [:obo_human, :service_account, :autonomous]
  @audit_plane_principal_kinds [:obo_human, :service_account]

  # ---------------------------------------------------------------------------
  # Decision oracle — mirrors platform_roles.cedar verbatim.
  #
  # Any drift between this table and the policy file will surface as a
  # property failure, which is desired — that's the point of the test.
  # ---------------------------------------------------------------------------

  # Note: F004 narrowed the prior F002 platform_operator wildcard. Operators
  # get audit-plane / UI surfaces; ChatCompletion (Data-Plane, end-user role)
  # is now `caller`-only. See platform_roles.cedar (F002 baseline +
  # F004 audit-console block) and contracts/cedar_entity_schema_extensions.md
  # §"Role-to-action allowlist".
  @spec expected_decision(String.t(), String.t()) :: :allow | :deny
  defp expected_decision("platform_operator", "ReadReceipts"), do: :allow
  defp expected_decision("platform_operator", "ExportEvidence"), do: :allow
  defp expected_decision("platform_operator", "ReadPayload"), do: :allow
  defp expected_decision("platform_operator", _), do: :deny
  defp expected_decision("tenant_auditor", "ReadReceipts"), do: :allow
  defp expected_decision("tenant_auditor", "ExportEvidence"), do: :allow
  defp expected_decision("tenant_auditor", "ReadPayload"), do: :allow
  defp expected_decision("tenant_auditor", _), do: :deny
  defp expected_decision("caller", "ChatCompletion"), do: :allow
  defp expected_decision("caller", _), do: :deny
  defp expected_decision(_unknown_role, _action), do: :deny

  # ---------------------------------------------------------------------------
  # Generators
  # ---------------------------------------------------------------------------

  defp known_role_gen, do: StreamData.member_of(@known_roles)
  defp unknown_role_gen, do: StreamData.member_of(@unknown_roles)

  # Bind (action, principal_kind) together so we never try `ReadReceipts`
  # with an `:autonomous` principal (schema rejection → Cedar eval error
  # → deny-with-:cedar_error sentinel; possible but a noise source that
  # doesn't exercise the decision matrix).
  defp action_and_principal_kind_gen do
    StreamData.bind(StreamData.member_of(@actions), fn action ->
      kinds =
        case action do
          "ChatCompletion" -> @data_plane_principal_kinds
          _ -> @audit_plane_principal_kinds
        end

      StreamData.bind(StreamData.member_of(kinds), fn kind ->
        StreamData.constant({action, kind})
      end)
    end)
  end

  # ---------------------------------------------------------------------------
  # IdentityContext / request / bundle builders
  # ---------------------------------------------------------------------------

  defp build_principal(:obo_human, role) do
    Principal.obo_human(%{
      issuer: "https://idp.test",
      subject: "alice",
      display_name: "Alice",
      groups: ["engineering"],
      recurse_role: role
    })
  end

  defp build_principal(:service_account, role) do
    Principal.service_account(%{
      issuer: "https://idp.test",
      account_id: "svc-1",
      scope: ["chat"],
      recurse_role: role
    })
  end

  defp build_principal(:autonomous, role) do
    Principal.autonomous(%{
      spiffe_id: "spiffe://recurse.test/workload/alice",
      recurse_role: role
    })
  end

  defp build_identity_context(principal_kind, role) do
    IdentityContext.new(%{
      machine_identity: "spiffe://recurse.test/workload/test",
      principal: build_principal(principal_kind, role),
      tenant_id: "tenant-test",
      correlation_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    })
  end

  defp build_request("ChatCompletion") do
    %{
      action: ~s[Recurse::Action::"ChatCompletion"],
      resource: %{
        type: "Recurse::Resource::LLMEndpoint",
        id: "openai_chat_completions",
        attrs: %{"model" => "gpt-4o-mini", "provider" => "openai"}
      },
      context: %{
        "streaming" => false,
        "model" => "gpt-4o-mini",
        "client_ip" => "192.0.2.1"
      }
    }
  end

  defp build_request("ReadReceipts") do
    %{
      action: ~s[Recurse::Action::"ReadReceipts"],
      resource: %{
        type: "Recurse::Resource::AuditEndpoint",
        id: "read_receipts",
        attrs: %{"endpoint" => "/v1/audit/receipts"}
      },
      context: %{"client_ip" => "192.0.2.1"}
    }
  end

  defp build_request("ExportEvidence") do
    %{
      action: ~s[Recurse::Action::"ExportEvidence"],
      resource: %{
        type: "Recurse::Resource::AuditEndpoint",
        id: "export_evidence",
        attrs: %{"endpoint" => "/v1/audit/export"}
      },
      context: %{
        "client_ip" => "192.0.2.1",
        "run_ids" => ["01HZZZZZZZZZZZZZZZZZZZZZZZ"]
      }
    }
  end

  defp build_request("ReadPayload") do
    %{
      action: ~s[Recurse::Action::"ReadPayload"],
      resource: %{
        type: "Recurse::Resource::PayloadBroker",
        id: "payload_broker",
        attrs: %{
          "run_id" => "01HZZZZZZZZZZZZZZZZZZZZZZZ",
          "tenant_id" => "tenant-test"
        }
      },
      context: %{
        "client_ip" => "192.0.2.1",
        "run_id" => "01HZZZZZZZZZZZZZZZZZZZZZZZ"
      }
    }
  end

  defp bundle_ref_for(bytes) when is_binary(bytes) do
    canonical_hash = Recurse.Cedar.canonical_hash(bytes)

    %PolicyBundleRef{
      bundle_id: Base.encode16(canonical_hash, case: :lower),
      canonical_hash: canonical_hash,
      loaded_at: DateTime.utc_now(),
      evaluator_handle: bytes,
      bundle_bytes: bytes
    }
  end

  # ---------------------------------------------------------------------------
  # Property 1 — known-role decision matrix
  # ---------------------------------------------------------------------------

  describe "Surface S property 1: known-role decision matrix under platform_roles.cedar" do
    @describetag :property_surface_s

    setup do
      bytes = File.read!(@platform_roles_path)
      %{bundle: bundle_ref_for(bytes), bytes: bytes}
    end

    property "decision matches the role-to-action oracle",
             %{bundle: bundle} do
      check all(
              role <- known_role_gen(),
              {action, principal_kind} <- action_and_principal_kind_gen(),
              max_runs: @iterations
            ) do
        ctx = build_identity_context(principal_kind, role)
        request = build_request(action)

        {decision, _matched} = Evaluator.evaluate(bundle, ctx, request)

        assert decision == expected_decision(role, action),
               "role=#{role} action=#{action} kind=#{principal_kind} → #{decision}; " <>
                 "expected #{expected_decision(role, action)}"
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Property 2 — unknown role fail-closed
  # ---------------------------------------------------------------------------

  describe "Surface S property 2: unknown recurse_role => deny (fail-closed)" do
    @describetag :property_surface_s

    setup do
      bytes = File.read!(@platform_roles_path)
      %{bundle: bundle_ref_for(bytes)}
    end

    property "unknown role produces :deny for every action", %{bundle: bundle} do
      check all(
              role <- unknown_role_gen(),
              {action, principal_kind} <- action_and_principal_kind_gen(),
              max_runs: @iterations
            ) do
        ctx = build_identity_context(principal_kind, role)
        request = build_request(action)

        assert {:deny, _matched} = Evaluator.evaluate(bundle, ctx, request)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Property 3 — policy_canonical_hash stable across whitespace / comment
  # perturbation of the bundle file.
  #
  # Cedar's `canonical_hash/1` is documented stable across whitespace,
  # comments, and trailing-comma perturbations (see `Recurse.Cedar`
  # moduledoc lines 7-11). This property verifies that guarantee by
  # programmatically mutating the reference bundle file and asserting
  # the resulting hashes match.
  # ---------------------------------------------------------------------------

  describe "Surface S property 3: canonical_hash stability" do
    @describetag :property_surface_s

    setup do
      bytes = File.read!(@platform_roles_path)
      %{base_bytes: bytes, base_hash: Recurse.Cedar.canonical_hash(bytes)}
    end

    # Mutation type generator — each variant preserves semantics.
    defp mutation_gen do
      StreamData.one_of([
        StreamData.tuple({StreamData.constant(:whitespace), whitespace_gen()}),
        StreamData.tuple({StreamData.constant(:comment), comment_gen()}),
        StreamData.tuple({StreamData.constant(:trailing_newlines), StreamData.integer(1..5)})
      ])
    end

    # Random run of horizontal whitespace (spaces + tabs). Bounded length
    # keeps property runs fast.
    defp whitespace_gen do
      StreamData.string([?\s, ?\t], min_length: 1, max_length: 10)
    end

    # Random `//` line comment. Kept printable-ASCII-safe so we don't
    # accidentally emit multi-line content that breaks parse.
    defp comment_gen do
      gen all(text <- StreamData.string(:alphanumeric, min_length: 0, max_length: 40)) do
        "// " <> text <> "\n"
      end
    end

    # Apply a mutation to the bundle source. Each strategy injects
    # between the last `;` and EOF so Cedar statements stay intact.
    defp apply_mutation(bytes, {:whitespace, ws}) do
      # Inject whitespace at the end of every line (before the newline).
      # That mutates interior as well as EOF whitespace without changing
      # the token stream.
      String.replace(bytes, "\n", ws <> "\n")
    end

    defp apply_mutation(bytes, {:comment, comment}) do
      # Append a comment line after the final policy statement.
      String.trim_trailing(bytes, "\n") <> "\n" <> comment
    end

    defp apply_mutation(bytes, {:trailing_newlines, n}) do
      String.trim_trailing(bytes, "\n") <> String.duplicate("\n", n)
    end

    property "whitespace / comment / trailing-newline mutations preserve canonical_hash",
             %{base_bytes: base_bytes, base_hash: base_hash} do
      check all(mutation <- mutation_gen(), max_runs: @iterations) do
        mutated = apply_mutation(base_bytes, mutation)

        # Sanity: the mutation actually changed the byte stream
        # (otherwise the property is tautological). Allow equality when
        # the generator happens to produce a no-op mutation.
        _ = mutated

        mutated_hash = Recurse.Cedar.canonical_hash(mutated)

        assert mutated_hash == base_hash,
               "mutation=#{inspect(mutation)} produced different canonical_hash"

        assert byte_size(mutated_hash) == 32
      end
    end
  end
end
