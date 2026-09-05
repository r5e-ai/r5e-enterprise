defmodule Recurse.Gateway.Admin.AuditAgent.TestHelper do
  @moduledoc """
  Shared test setup for the F004 Phase-6 audit-agent contract tests
  (T099-T104). Centralizes the Cedar bundle + ProviderRegistry +
  IdentityContext fixture so each per-tool test stays focused on the
  tool-specific assertions.

  All tests using this helper run `async: false` because BundleLoader
  + ProviderRegistry are global per F002 convention.
  """

  alias Recurse.Gateway.Admin.AuditAgent.Runtime
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  def tenant_id, do: @tenant_id

  @doc """
  Boot the per-test fixture. Returns `:ok` for direct use in
  `setup do ... end` blocks.
  """
  def setup_fixture do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "Audit-Agent Test Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    bundle_path = write_bundle()

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    _ =
      ExUnit.Callbacks.start_supervised!(
        Supervisor.child_spec(
          {BundleLoader,
           bundle_path: bundle_path,
           entity_schema_path: entity_schema_path,
           trap_sighup: false,
           name: nil},
          id: make_ref()
        )
      )

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.AuditAgentStubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.AuditAgentStubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/audit-agent-test"
    })

    Runtime.reset_rate_limit_table_for_tests!()

    ExUnit.Callbacks.on_exit(fn ->
      ProviderRegistry.uninstall()
      Runtime.reset_rate_limit_table_for_tests!()
    end)

    :ok
  end

  @doc """
  Build an IdentityContext for the given role (one of
  `"tenant_auditor" | "platform_operator" | "caller"`).
  """
  def build_ctx(recurse_role, opts \\ []) do
    subject = Keyword.get(opts, :subject, "test-#{recurse_role}@corp")

    principal =
      Principal.obo_human(%{
        issuer: "https://test/",
        subject: subject,
        recurse_role: recurse_role
      })

    IdentityContext.new(%{
      machine_identity: "observed://gateway/audit-agent-test",
      principal: principal,
      tenant_id: @tenant_id,
      correlation_id: Ecto.UUID.generate()
    })
  end

  @doc """
  Per-test telemetry attach for capturing UiReceipt emissions. The pid
  passed in receives `{:ui_receipt_emitted, meta}` for every emit.
  """
  def attach_telemetry(test_pid \\ self()) do
    handler_id = "audit-agent-receipt-#{System.unique_integer()}"

    :telemetry.attach(
      handler_id,
      UiReceipts.telemetry_event(),
      fn _event, _measurements, meta, _config ->
        send(test_pid, {:ui_receipt_emitted, meta})
      end,
      nil
    )

    ExUnit.Callbacks.on_exit(fn -> :telemetry.detach(handler_id) end)
  end

  @doc """
  Insert a synthetic Attestation row + matching Session for tools that
  need a real receipt to consult. Returns the run_id.
  """
  def seed_attestation(opts \\ []) do
    alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
    alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session

    now = DateTime.utc_now()
    subject = Keyword.get(opts, :subject, "alice@corp")
    decision = Keyword.get(opts, :policy_decision, :deny)
    event_kind = Keyword.get(opts, :event_kind, :llm_call)

    {:ok, session} =
      %Session{}
      |> Session.changeset(%{
        tenant_id: @tenant_id,
        session_scope: :discovery_session,
        state: :active,
        session_start: now,
        principal_kind: :obo_human,
        principal_canonical: subject
      })
      |> Repo.insert()

    attestation =
      %Attestation{}
      |> Attestation.changeset(%{
        session_id: session.session_id,
        turn_id: Ecto.UUID.generate(),
        event_kind: event_kind,
        machine_identity: %{
          "observed_jwt_subject" => "agent",
          "observed_jwt_issuer" => "test"
        },
        principal: %{
          "kind" => "obo_human",
          "subject" => subject,
          "issuer" => "https://test/",
          "recurse_role" => "caller"
        },
        tenant_id: @tenant_id,
        policy_canonical_hash: :crypto.hash(:sha256, "policy"),
        payload_hash: :crypto.hash(:sha256, "payload"),
        payload_uri: "s3://bucket/p.json",
        correlation_id: "corr-test-#{System.unique_integer()}",
        signer_kms_key_id: "test-key",
        signer_key_version: "v1",
        timestamp: now,
        signed_predicate_bytes: <<0::64>>,
        dsse_signature: <<0::64>>,
        verification_level: :signed,
        tier_completeness_advisory: :partial,
        policy_decision: decision,
        outcome: :success
      })
      |> Repo.insert!()

    attestation.run_id
  end

  defp write_bundle do
    source =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ])
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "audit_agent_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    ExUnit.Callbacks.on_exit(fn -> File.rm(path) end)
    path
  end
end

defmodule Recurse.Gateway.Test.AuditAgentStubLLM do
  @moduledoc false
  @behaviour Recurse.Providers.LLMProvider
  @impl true
  def init(_), do: {:ok, %{}}

  @impl true
  def chat_complete(_state, _req, _ctx) do
    {:ok,
     %{
       "model" => "stub-model",
       "choices" => [
         %{
           "message" => %{
             "role" => "assistant",
             "content" => "Stubbed audit-agent explanation."
           }
         }
       ],
       "usage" => %{"prompt_tokens" => 100, "completion_tokens" => 50}
     }}
  end

  @impl true
  def chat_complete_stream(_state, _req, _ctx), do: {:ok, []}
  @impl true
  def capabilities(_state), do: [:sync]
  @impl true
  def healthcheck(_state), do: :ok
  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule Recurse.Gateway.Test.AuditAgentStubLLMOversize do
  @moduledoc """
  Stub LLM provider that returns >1K-token output. Used by token-budget
  property tests for `explain_denial` + `suggest_policy_pattern[source=llm]`
  to verify the per-call output cap is enforced.
  """
  @behaviour Recurse.Providers.LLMProvider
  @impl true
  def init(_), do: {:ok, %{}}

  @impl true
  def chat_complete(_state, _req, _ctx) do
    # ~5K characters → ~1.25K estimated tokens at the 4-char/token rate.
    big = String.duplicate("oversize ", 600)

    {:ok,
     %{
       "model" => "stub-model",
       "choices" => [%{"message" => %{"role" => "assistant", "content" => big}}],
       "usage" => %{"prompt_tokens" => 100, "completion_tokens" => 1500}
     }}
  end

  @impl true
  def chat_complete_stream(_state, _req, _ctx), do: {:ok, []}
  @impl true
  def capabilities(_state), do: [:sync]
  @impl true
  def healthcheck(_state), do: :ok
  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule Recurse.Gateway.Test.AuditAgentStubStorage do
  @moduledoc false
  @behaviour Recurse.Providers.StorageProvider
  @impl true
  def init(_), do: {:ok, %{}}
  @impl true
  def put_payload(_state, _payload, _ctx), do: {:ok, %{uri: "s3://stub/key", hash: <<0::256>>}}
  @impl true
  def get_payload(_state, _uri, _ctx), do: {:error, :permanent, :not_implemented}
  @impl true
  def delete_payload(_state, _uri, _ctx), do: {:error, :permanent, :not_implemented}
  @impl true
  def capabilities(_state), do: []
  @impl true
  def healthcheck(_state), do: :ok
  @impl true
  def terminate(_state, _reason), do: :ok
end
