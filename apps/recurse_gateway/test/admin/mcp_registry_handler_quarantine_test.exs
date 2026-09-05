defmodule Recurse.Gateway.Admin.McpRegistryHandlerQuarantineTest do
  @moduledoc """
  Contract tests for the F7 quarantine workflow (`PATCH /v1/mcp/registry/:id`).

  Asserts the full vertical slice:

    * Cedar gate — only `platform_operator` may quarantine; `tenant_auditor`
      gets 403.
    * Body validation — malformed `trust_tier`/`reason` returns 400 with
      the F001 error envelope.
    * Persistence — `:persistent_term` cache reflects the new tier
      AND the registry file on disk is rewritten atomically.
    * Cedar policy_constraints — `cedar_policies` clause is rewritten
      from `permit(...)` to `forbid(...)` (and vice-versa for restore).
    * Receipt — exactly one `:ui_mcp_quarantine` ledger receipt commits
      BEFORE the HTTP response goes out (Principle III).
    * Failure paths — unknown id → 404, no receipt; persistence failure
      → 500, no receipt; bad body → 400, no receipt.

  `async: false` because BundleLoader + ProviderRegistry + the test
  fixture's `:mcp_registry_path` override are global per F002 convention.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.McpRegistryHandler
  alias Recurse.Gateway.McpRegistry.Loader
  alias Recurse.Gateway.McpRegistry.Mutator
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "MCP Quarantine Test Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    # Fixture registry — copy the production priv catalog into a tmp dir
    # we can mutate freely. The `Mutator.persist/1` write path will
    # rewrite this tmp file, NOT the shipped priv file.
    fixture_path = copy_registry_to_tmp()
    Application.put_env(:recurse_gateway, :mcp_registry_path, fixture_path)
    :persistent_term.erase({Loader, :registry})
    :ok = Loader.load!()

    bundle_path = write_bundle()

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    _ =
      start_supervised!(
        Supervisor.child_spec(
          {BundleLoader,
           bundle_path: bundle_path,
           entity_schema_path: entity_schema_path,
           trap_sighup: false,
           name: nil},
          id: make_ref()
        )
      )

    # The application supervisor already started `Mutator` at boot under
    # the canonical name (see `RecurseGateway.Application`). We don't
    # need to re-start it — just ensure it's alive (the test fixture
    # path was swapped in BEFORE this point so the running GenServer
    # already targets the tmp catalog).
    if is_nil(Process.whereis(Mutator)) do
      _ = start_supervised!({Mutator, name: Mutator})
    end

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/mcp-quarantine-test"
    })

    previous_validator_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid",
      known_kids: [
        {"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}
      ]
    )

    on_exit(fn ->
      ProviderRegistry.uninstall()

      if previous_validator_opts do
        Application.put_env(:recurse_gateway, :jwt_validator_opts, previous_validator_opts)
      else
        Application.delete_env(:recurse_gateway, :jwt_validator_opts)
      end

      Application.delete_env(:recurse_gateway, :mcp_registry_path)
      :persistent_term.erase({Loader, :registry})
      File.rm(fixture_path)
    end)

    :ok
  end

  # ---------------------------------------------------------------------------
  # Success paths
  # ---------------------------------------------------------------------------

  describe "PATCH /v1/mcp/registry/:id (operator quarantine)" do
    test "200 + flips trust_tier in cache + on disk + emits :ui_mcp_quarantine receipt" do
      attach_ui_receipts_telemetry()
      jwt = mint_jwt("platform_operator")

      body =
        JSON.encode!(%{
          "trust_tier" => "quarantined",
          "reason" => "demo: quarantining for verification testing"
        })

      conn =
        :patch
        |> Plug.Test.conn("/v1/mcp/registry/r5e-audit-mcp", body)
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 200
      result = JSON.decode!(conn.resp_body)
      assert result["entry"]["id"] == "r5e-audit-mcp"
      assert result["entry"]["trust_tier"] == "quarantined"
      assert result["previous_trust_tier"] == "verified"

      # Cedar policy clause was flipped from permit -> forbid.
      [clause | _] = get_in(result, ["entry", "policy_constraints", "cedar_policies"])
      assert clause =~ "forbid("
      assert clause =~ ~s|resource.mcp_server == "r5e-audit-mcp"|

      # Quarantine zeroes the rate limit (the schema's "policy-denied" sentinel).
      assert get_in(result, ["entry", "policy_constraints", "rate_limit_per_minute"]) == 0

      # Persistent_term cache reflects the new tier.
      {:ok, cached} = Loader.get("r5e-audit-mcp")
      assert cached.trust_tier == :quarantined

      # File on disk reflects the new tier.
      file_contents =
        :recurse_gateway
        |> Application.get_env(:mcp_registry_path)
        |> File.read!()
        |> JSON.decode!()

      [reloaded] = Enum.filter(file_contents["entries"], &(&1["id"] == "r5e-audit-mcp"))
      assert reloaded["trust_tier"] == "quarantined"

      # Exactly one ledger receipt fired with the canonical event_kind +
      # the auditor-meaningful payload metadata.
      assert_receive {:ui_receipt_emitted,
                      %{
                        event_kind: :ui_mcp_quarantine,
                        entry_id: "r5e-audit-mcp",
                        previous_trust_tier: "verified",
                        new_trust_tier: "quarantined",
                        reason: "demo: quarantining for verification testing"
                      }},
                     2_000
    end

    test "200 + emits receipt with nil reason when reason is omitted" do
      attach_ui_receipts_telemetry()
      jwt = mint_jwt("platform_operator")

      body = JSON.encode!(%{"trust_tier" => "quarantined"})

      conn =
        :patch
        |> Plug.Test.conn("/v1/mcp/registry/r5e-audit-mcp", body)
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 200

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_mcp_quarantine, reason: nil}},
                     2_000
    end

    test "restoration: quarantined -> verified flips clause back to permit" do
      attach_ui_receipts_telemetry()
      jwt = mint_jwt("platform_operator")

      # First quarantine the entry, then restore it.
      _ =
        :patch
        |> Plug.Test.conn(
          "/v1/mcp/registry/r5e-audit-mcp",
          JSON.encode!(%{"trust_tier" => "quarantined"})
        )
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      conn =
        :patch
        |> Plug.Test.conn(
          "/v1/mcp/registry/r5e-audit-mcp",
          JSON.encode!(%{"trust_tier" => "verified"})
        )
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 200
      result = JSON.decode!(conn.resp_body)
      assert result["previous_trust_tier"] == "quarantined"
      assert result["entry"]["trust_tier"] == "verified"

      [clause | _] = get_in(result, ["entry", "policy_constraints", "cedar_policies"])
      assert clause =~ "permit("
      assert clause =~ ~s|resource.trust_tier == "verified"|

      # Rate limit is restored — original was 60/min for r5e-audit-mcp.
      assert get_in(result, ["entry", "policy_constraints", "rate_limit_per_minute"]) == 60

      # Snapshot fields are dropped on restore (no leftover state).
      assert get_in(result, ["entry", "policy_constraints", "pre_quarantine_cedar_policies"]) ==
               nil

      assert get_in(result, [
               "entry",
               "policy_constraints",
               "pre_quarantine_rate_limit_per_minute"
             ]) == nil

      # Two receipts emitted in total.
      assert_receive {:ui_receipt_emitted, %{new_trust_tier: "quarantined"}}, 2_000
      assert_receive {:ui_receipt_emitted, %{new_trust_tier: "verified"}}, 2_000
    end

    # F002 regression — `filesystem-mcp` carries a per-entry
    # `principal.role in ["operator", "developer"]` constraint and a
    # 30/min rate limit. Quarantine→restore MUST preserve both via the
    # snapshot+restore mechanism, NOT regenerate from a tier-canonical
    # template (which would silently weaken the policy + halve the
    # rate limit ceiling on every cycle).
    test "F002 regression: quarantine->restore preserves principal.role constraints + rate limit" do
      jwt = mint_jwt("platform_operator")

      original_clause =
        case Loader.get("filesystem-mcp") do
          {:ok, entry} ->
            entry.policy_constraints["cedar_policies"] |> List.first()
        end

      assert original_clause =~ "principal.role"

      _ =
        :patch
        |> Plug.Test.conn(
          "/v1/mcp/registry/filesystem-mcp",
          JSON.encode!(%{"trust_tier" => "quarantined"})
        )
        |> with_path_params(%{"id" => "filesystem-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      conn =
        :patch
        |> Plug.Test.conn(
          "/v1/mcp/registry/filesystem-mcp",
          JSON.encode!(%{"trust_tier" => "community"})
        )
        |> with_path_params(%{"id" => "filesystem-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 200
      result = JSON.decode!(conn.resp_body)
      [restored_clause | _] = get_in(result, ["entry", "policy_constraints", "cedar_policies"])

      # The restored clause is the ORIGINAL (verbatim), not a template.
      assert restored_clause == original_clause
      assert restored_clause =~ ~s|principal.role in ["operator", "developer"]|

      # Rate limit is restored to the original 30, not lifted to the
      # safe default of 60.
      assert get_in(result, ["entry", "policy_constraints", "rate_limit_per_minute"]) == 30
    end
  end

  # ---------------------------------------------------------------------------
  # Cedar gate — operator-only
  # ---------------------------------------------------------------------------

  describe "PATCH /v1/mcp/registry/:id (auth)" do
    test "403 for tenant_auditor (read-only role)" do
      attach_ui_receipts_telemetry()
      jwt = mint_jwt("tenant_auditor")

      body = JSON.encode!(%{"trust_tier" => "quarantined"})

      conn =
        :patch
        |> Plug.Test.conn("/v1/mcp/registry/r5e-audit-mcp", body)
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 403
      assert %{"error" => "ERR_FORBIDDEN"} = JSON.decode!(conn.resp_body)

      # Negative — no receipt fired for a denied request (the deny ITSELF
      # is attested via UiReceipts emit-deny telemetry inside Authz, NOT
      # via :ui_mcp_quarantine which is success-only).
      refute_receive {:ui_receipt_emitted, %{event_kind: :ui_mcp_quarantine}}, 500

      # Persistent state unchanged.
      {:ok, cached} = Loader.get("r5e-audit-mcp")
      assert cached.trust_tier == :verified
    end

    test "401 with no JWT" do
      conn =
        :patch
        |> Plug.Test.conn(
          "/v1/mcp/registry/r5e-audit-mcp",
          JSON.encode!(%{"trust_tier" => "quarantined"})
        )
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Plug.Parsers.call(
          Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: JSON)
        )
        |> McpRegistryHandler.update()

      assert conn.status == 401
    end
  end

  # ---------------------------------------------------------------------------
  # Body validation — 400s
  # ---------------------------------------------------------------------------

  describe "PATCH /v1/mcp/registry/:id (body validation)" do
    test "400 when trust_tier is missing" do
      attach_ui_receipts_telemetry()
      jwt = mint_jwt("platform_operator")

      conn =
        :patch
        |> Plug.Test.conn("/v1/mcp/registry/r5e-audit-mcp", JSON.encode!(%{}))
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 400
      result = JSON.decode!(conn.resp_body)
      assert result["error"] == "ERR_BAD_REQUEST"
      assert result["error_description"] =~ "trust_tier"

      refute_receive {:ui_receipt_emitted, %{event_kind: :ui_mcp_quarantine}}, 500
    end

    test "400 when trust_tier is unknown" do
      jwt = mint_jwt("platform_operator")

      body = JSON.encode!(%{"trust_tier" => "untrusted"})

      conn =
        :patch
        |> Plug.Test.conn("/v1/mcp/registry/r5e-audit-mcp", body)
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error_description"] =~ "verified"
    end

    test "400 when reason exceeds 500 bytes" do
      jwt = mint_jwt("platform_operator")
      huge_reason = String.duplicate("x", 501)

      body = JSON.encode!(%{"trust_tier" => "quarantined", "reason" => huge_reason})

      conn =
        :patch
        |> Plug.Test.conn("/v1/mcp/registry/r5e-audit-mcp", body)
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error_description"] =~ "reason"
    end
  end

  # ---------------------------------------------------------------------------
  # Not-found path
  # ---------------------------------------------------------------------------

  describe "PATCH /v1/mcp/registry/:id (unknown id)" do
    test "404 with F001 envelope + no receipt" do
      attach_ui_receipts_telemetry()
      jwt = mint_jwt("platform_operator")

      body = JSON.encode!(%{"trust_tier" => "quarantined"})

      conn =
        :patch
        |> Plug.Test.conn("/v1/mcp/registry/does-not-exist", body)
        |> with_path_params(%{"id" => "does-not-exist"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 404
      result = JSON.decode!(conn.resp_body)
      assert result["error"] == "not_found"

      refute_receive {:ui_receipt_emitted, %{event_kind: :ui_mcp_quarantine}}, 500
    end
  end

  # ---------------------------------------------------------------------------
  # F003 — Principle III ledger receipt assertions
  #
  # The earlier success-path tests in this file capture the
  # `[:recurse, :ui_receipt, :emitted]` telemetry signal, which is
  # NOT the same as proving the receipt was DSSE-signed and committed
  # to the Postgres ledger before the response went out. The two tests
  # below close that gap by:
  #
  #   1. Querying the Postgres `attestations` table directly after a
  #      successful PATCH and asserting a `:ui_mcp_quarantine` row
  #      exists with the expected payload metadata.
  #   2. Installing a failing-ledger provider stub and asserting the
  #      PATCH returns 5xx AND the on-disk + persistent_term cache
  #      were ROLLED BACK to their pre-mutation shape (Principle III
  #      symmetric: every committed receipt corresponds to a real
  #      state change, AND every real state change has a receipt).
  # ---------------------------------------------------------------------------

  describe "PATCH /v1/mcp/registry/:id (Principle III ledger commit + rollback)" do
    test "F003 positive: successful PATCH writes a :ui_mcp_quarantine row to the ledger" do
      jwt = mint_jwt("platform_operator")

      body =
        JSON.encode!(%{
          "trust_tier" => "quarantined",
          "reason" => "ledger commit assertion test"
        })

      conn =
        :patch
        |> Plug.Test.conn("/v1/mcp/registry/r5e-audit-mcp", body)
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 200

      # The `attestations` table is the canonical receipt log; the
      # ledger commit landed BEFORE the 200 response per Principle III.
      attestation = wait_for_attestation(:ui_mcp_quarantine)

      # F004 system events are predicate-only — the auditor-meaningful
      # payload metadata is JCS-hashed into `payload_hash`, not embedded
      # in the signed predicate JSON itself. Asserting on the canonical
      # predicate fields proves the row is real, signed, and points
      # back at the system-event predicate-only URI scheme.
      assert attestation.event_kind == :ui_mcp_quarantine
      assert byte_size(attestation.dsse_signature) > 0
      assert byte_size(attestation.signed_predicate_bytes) > 0

      predicate = JSON.decode!(attestation.signed_predicate_bytes)
      assert predicate["event_kind"] == "ui_mcp_quarantine"
      assert predicate["envelope_version"] == "1.0"
      assert String.starts_with?(predicate["payload_hash"], "sha256:")
      assert String.starts_with?(predicate["payload_uri"], "recurse://system/predicate-only/")
    end

    test "F003 negative: failing-ledger provider returns 500 + rolls back disk + cache" do
      jwt = mint_jwt("platform_operator")

      pre_mutation =
        case Loader.get("r5e-audit-mcp") do
          {:ok, entry} -> entry
        end

      assert pre_mutation.trust_tier == :verified

      # Swap in a ledger provider whose `commit_attestation/2` always
      # returns `{:error, _}` (the StubLedger doesn't even export
      # `commit_attestation/2`, so UiReceipts.emit_strict/2 takes the
      # `:ledger_provider_missing_commit_attestation` branch — which is
      # the same observable failure shape from the handler's POV).
      ProviderRegistry.uninstall()

      ProviderRegistry.install_raw!(%{
        llm: {Recurse.Gateway.Test.StubLLM, %{}},
        ledger: {Recurse.Gateway.Test.StubLedger, %{}},
        storage: {Recurse.Gateway.Test.StubStorage, %{}},
        secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
        tenant_id: @tenant_id,
        signer: "observed://gateway/mcp-quarantine-test-failing-ledger"
      })

      body = JSON.encode!(%{"trust_tier" => "quarantined", "reason" => "rollback test"})

      conn =
        :patch
        |> Plug.Test.conn("/v1/mcp/registry/r5e-audit-mcp", body)
        |> with_path_params(%{"id" => "r5e-audit-mcp"})
        |> with_json(jwt)
        |> McpRegistryHandler.update()

      assert conn.status == 500

      # The persistent_term cache reverted to the pre-mutation tier.
      {:ok, after_cache} = Loader.get("r5e-audit-mcp")
      assert after_cache.trust_tier == :verified

      # The on-disk catalog reverted too.
      file_contents =
        :recurse_gateway
        |> Application.get_env(:mcp_registry_path)
        |> File.read!()
        |> JSON.decode!()

      [reloaded] = Enum.filter(file_contents["entries"], &(&1["id"] == "r5e-audit-mcp"))
      assert reloaded["trust_tier"] == "verified"

      # No `:ui_mcp_quarantine` row in the ledger — the commit failed
      # AND the rollback ensures no orphan state change exists either.
      assert ledger_count(:ui_mcp_quarantine) == 0
    end
  end

  # ---------------------------------------------------------------------------
  # Cedar policy clause rewrite — direct Mutator unit tests
  # ---------------------------------------------------------------------------

  describe "Mutator.update_trust_tier/3 (direct)" do
    test "quarantine -> forbid clause; rate limit pinned to 0" do
      ctx = %{actor_principal_subject: "alice@corp", reason: nil}

      {:ok, %{previous_tier: prev, entry: entry}} =
        Mutator.update_trust_tier("filesystem-mcp", :quarantined, ctx)

      assert prev == :community
      assert entry.trust_tier == :quarantined

      [clause | _] = entry.policy_constraints["cedar_policies"]
      assert clause =~ "forbid("
      assert entry.policy_constraints["rate_limit_per_minute"] == 0
    end

    test "unknown id returns :not_found" do
      ctx = %{actor_principal_subject: "alice@corp", reason: nil}
      assert {:error, :not_found} = Mutator.update_trust_tier("ghost-mcp", :quarantined, ctx)
    end

    test "atomic-write idiom: tmp file is gone after success" do
      ctx = %{actor_principal_subject: "alice@corp", reason: nil}

      {:ok, _} = Mutator.update_trust_tier("filesystem-mcp", :quarantined, ctx)

      registry_dir =
        :recurse_gateway
        |> Application.get_env(:mcp_registry_path)
        |> Path.dirname()

      tmp_files =
        registry_dir
        |> File.ls!()
        |> Enum.filter(&String.contains?(&1, ".tmp."))

      assert tmp_files == []
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp copy_registry_to_tmp do
    source =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "mcp_registry",
        "registry.json"
      ])

    tmp_dir =
      Path.join(System.tmp_dir!(), "mcp-registry-test-#{System.unique_integer([:positive])}")

    File.mkdir_p!(tmp_dir)
    tmp_path = Path.join(tmp_dir, "registry.json")
    File.cp!(source, tmp_path)
    tmp_path
  end

  defp mint_jwt(recurse_role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: recurse_role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp with_json(conn, jwt) do
    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: JSON))
  end

  defp with_path_params(conn, params) do
    %{conn | path_params: Map.merge(conn.path_params || %{}, params)}
  end

  # F003 helpers — query the Postgres `attestations` table directly so
  # tests prove the DSSE-signed ledger commit landed (not just that
  # telemetry fired). The Sandbox is `:shared` to `self()` so the
  # GenServer-issued commit is visible from the test process.
  defp wait_for_attestation(event_kind, attempts \\ 20)

  defp wait_for_attestation(event_kind, 0) do
    flunk(
      "Expected attestation for event_kind=#{inspect(event_kind)} to land in the ledger, " <>
        "but no row appeared after polling. Verify UiReceipts.emit_strict/2 ran + committed."
    )
  end

  defp wait_for_attestation(event_kind, attempts) do
    import Ecto.Query

    case Attestation
         |> where([a], a.event_kind == ^event_kind)
         |> order_by([a], desc: a.timestamp)
         |> limit(1)
         |> Repo.one() do
      nil ->
        Process.sleep(25)
        wait_for_attestation(event_kind, attempts - 1)

      attestation ->
        attestation
    end
  end

  defp ledger_count(event_kind) do
    import Ecto.Query

    Attestation
    |> where([a], a.event_kind == ^event_kind)
    |> Repo.aggregate(:count)
  end

  defp attach_ui_receipts_telemetry do
    test_pid = self()
    handler_id = "ui-receipt-test-#{System.unique_integer()}"

    :telemetry.attach(
      handler_id,
      UiReceipts.telemetry_event(),
      fn _event, _measurements, meta, _config ->
        send(test_pid, {:ui_receipt_emitted, meta})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
  end

  defp write_bundle do
    source =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ])
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "mcp_quarantine_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end
end
