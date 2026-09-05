defmodule RecurseGateway.Integration.F004Phase2AttestationWiringTest do
  @moduledoc """
  F004 T055a integration smoke — confirms the receipt-emission seams replaced
  in Phase 2 Wave 3A actually persist `attestations` rows in the Postgres
  ledger (not just emit telemetry).

  Per Constitution Principle III ("everything attestable, NON-NEGOTIABLE")
  the W2-A `UiReceipts` seam and W2-C retention purgers MUST commit real
  cryptographically-attested receipts. T055a unblocks Phase 3 since
  `T070`'s US1 integration test asserts `:ui_query` and `:ui_login` receipts
  appear in the audit log within SC-009's 2-second budget — telemetry-only
  emission would fail that test.

  ## What this test exercises

  Three distinct receipt-emission paths land one `attestations` row each:

    1. **OIDC failure path** (`:ui_login` outcome=`state_invalid`) — exercises
       the `LoginHandler` callback with no nonce row, which routes through
       `UiReceipts.emit/2` → `EnvelopeBuilder.build_system/4` →
       `PostgresMerkleLedger.commit_attestation/2`.
    2. **OIDC success path** (`:ui_login` outcome=`success`) — the
       happy-path principal materialization (the only path where the
       predicate carries an `:obo_human` principal kind).
    3. **Retention purge cycle** (`:ui_retention_purge` data_class=`chat_history`)
       — exercises the shared
       `Recurse.Gateway.SuggestionEngine.RetentionPurger.Receipt.emit/1`
       helper used by all three retention workers.

  Per the task spec ("you don't need 26 separate test cases"), per-event-kind
  Cedar-action coverage is owned by Phase 3+. This test asserts the seam
  shape: the right `event_kind` atom lands on a real Postgres row with the
  right verification level + DSSE signature.

  ## `async: false`

  Same reason as the F002 integration tests — shared `:persistent_term`
  slots (`ProviderRegistry`) and a single SQL-Sandbox connection. Every
  other test stays `async: true`.
  """

  use ExUnit.Case, async: false

  @moduletag :integration

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Admin.BrowserAuth.LoginHandler
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.SuggestionEngine.RetentionPurger.ChatHistory, as: ChatHistoryPurger
  alias Recurse.Gateway.Test.StubSecretsProvider
  alias Recurse.Gateway.Test.StubStorageProvider
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @gateway_origin "https://gateway.test"
  @authorize_url "https://idp.test/authorize"
  @client_id "broker-client"
  @redirect_uri "https://gateway.test/admin/login/callback"

  setup do
    # -- DB sandbox --
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    # -- Browser-session secret (LoginHandler.finalize_success encrypts the
    # cookie via this) --
    prior_browser_session = Application.get_env(:recurse_gateway, :browser_session)

    Application.put_env(:recurse_gateway, :browser_session,
      secret_key_base: :crypto.strong_rand_bytes(32),
      secure_cookie?: true
    )

    on_exit(fn ->
      if prior_browser_session do
        Application.put_env(:recurse_gateway, :browser_session, prior_browser_session)
      else
        Application.delete_env(:recurse_gateway, :browser_session)
      end
    end)

    # -- Provider Registry --
    on_exit(fn ->
      ProviderRegistry.uninstall()
      StubStorageProvider.reset()
    end)

    :ok = StubStorageProvider.reset()

    {:ok, ledger_state} = PostgresMerkleLedger.init(%{})
    {:ok, storage_state} = StubStorageProvider.init(%{bucket: "test-bucket"})
    {:ok, secrets_state} = StubSecretsProvider.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {__MODULE__.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, ledger_state},
      storage: {StubStorageProvider, storage_state},
      secrets: {StubSecretsProvider, secrets_state},
      tenant_id: @tenant_id,
      signer: "observed://gateway/test"
    })

    base_opts = [
      authorize_url: @authorize_url,
      idp_token_url: "https://idp.test/token",
      client_id: @client_id,
      redirect_uri: @redirect_uri,
      tenant_id: @tenant_id,
      gateway_origin: @gateway_origin,
      finch_pool: :openai_pool,
      id_token_validator: fn _token, _config -> {:ok, %{"sub" => "alice@corp"}} end,
      token_exchange: fn _id_token, _claims, _config ->
        {:ok,
         %{
           jwt: build_jwt_for_cookie(),
           principal_subject: "alice@corp",
           browser_session_id: "bsid-#{System.unique_integer([:positive])}"
         }}
      end
    ]

    %{base_opts: base_opts}
  end

  describe "UiReceipts ledger commit (T055a step c)" do
    test "OIDC failure path commits exactly one :ui_login attestation row",
         %{base_opts: opts} do
      pre_count = count_attestations(:ui_login)

      conn =
        :get
        |> Plug.Test.conn("/admin/login/callback?state=&code=AUTHCODE")

      out = LoginHandler.call(conn, opts)
      assert out.status == 400

      post_count = count_attestations(:ui_login)
      assert post_count == pre_count + 1, "expected one new :ui_login row"

      [row | _] = recent_attestations(:ui_login, 1)
      assert row.event_kind == :ui_login
      assert row.tenant_id == @tenant_id
      assert row.verification_level == :global_inclusion_verified
      assert row.policy_decision == :allow
      assert row.outcome == :success
      assert is_binary(row.dsse_signature)
      assert byte_size(row.payload_hash) == 32
      assert byte_size(row.policy_canonical_hash) == 32
    end

    test "OIDC success path commits :ui_login attestation with obo_human principal",
         %{base_opts: _opts} do
      pre_count = count_attestations(:ui_login)

      # Direct UiReceipts.emit call mirrors what `LoginHandler.finalize_success/5`
      # does on the happy path — the LoginHandler's full happy path requires
      # mocking the IdP Finch call which is exercised in the contract test.
      # Here we focus on the seam contract: a `:ui_login` `outcome: "success"`
      # with a known principal_subject persists an obo_human-keyed receipt.
      :ok =
        UiReceipts.emit(:ui_login, %{
          outcome: "success",
          principal_subject: "alice@corp",
          browser_session_id: "bsid-happy",
          tenant_id: @tenant_id
        })

      post_count = count_attestations(:ui_login)
      assert post_count == pre_count + 1

      [row | _] = recent_attestations(:ui_login, 1)
      assert row.event_kind == :ui_login
      assert row.principal["kind"] == "obo_human"
      assert row.principal["subject"] == "alice@corp"
    end
  end

  describe "Retention purger ledger commit (T055a step d)" do
    test "ChatHistory cycle commits exactly one :ui_retention_purge attestation row" do
      pre_count = count_attestations(:ui_retention_purge)

      # The ChatHistory worker's perform/1 runs the full cycle (no rows to
      # delete in this empty DB; the cycle still emits a receipt with
      # zero counts, matching the spec's "ONE receipt per cycle" rule).
      assert :ok = ChatHistoryPurger.perform(%Oban.Job{args: %{}})

      post_count = count_attestations(:ui_retention_purge)
      assert post_count == pre_count + 1, "expected one new :ui_retention_purge row"

      [row | _] = recent_attestations(:ui_retention_purge, 1)
      assert row.event_kind == :ui_retention_purge
      assert row.tenant_id == @tenant_id
      assert row.verification_level == :global_inclusion_verified
      assert row.principal["kind"] == "service_account"
      assert row.principal["account_id"] == "recurse-gateway-retention-purger"
    end
  end

  # -- Helpers --------------------------------------------------------------

  defp count_attestations(event_kind) when is_atom(event_kind) do
    import Ecto.Query

    from(a in Attestation, where: a.event_kind == ^event_kind, select: count(a.run_id))
    |> Repo.one()
  end

  defp recent_attestations(event_kind, limit) when is_atom(event_kind) do
    import Ecto.Query

    from(a in Attestation,
      where: a.event_kind == ^event_kind,
      order_by: [desc: a.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  # Build a JWT that the BrowserSessionPlug.peek_jwt_exp can decode to a
  # future `exp`. Signature is not checked at this layer — only `exp`. Used
  # for the success-path encrypt_payload call to pass the cookie writer's
  # validation. The integration test does NOT exercise downstream
  # JwtValidator, so an unsigned `exp`-bearing payload is sufficient.
  defp build_jwt_for_cookie do
    header = Base.url_encode64(JSON.encode!(%{"alg" => "none", "typ" => "JWT"}), padding: false)

    payload =
      Base.url_encode64(
        JSON.encode!(%{
          "exp" => System.system_time(:second) + 3600,
          "sub" => "alice@corp"
        }),
        padding: false
      )

    "#{header}.#{payload}.signature"
  end

  # ---------------------------------------------------------------------------
  # Local LLM stub — `ProviderRegistry.install_raw!/1` requires an `llm`
  # entry but this test never reaches `Recurse.Providers.LLMProvider`
  # callbacks. Defining the stub locally (rather than depending on
  # `Recurse.Gateway.Test.StubLLM` from `router_test.exs`) keeps test-file
  # load order from mattering.
  # ---------------------------------------------------------------------------

  defmodule StubLLM do
    @moduledoc false
    @behaviour Recurse.Providers.LLMProvider
    @impl true
    def init(_), do: {:ok, %{}}
    @impl true
    def chat_complete(_state, _req, _ctx), do: {:ok, %{}}
    @impl true
    def chat_complete_stream(_state, _req, _ctx), do: {:ok, []}
    @impl true
    def capabilities(_state), do: [:sync]
    @impl true
    def healthcheck(_state), do: :ok
    @impl true
    def terminate(_state, _reason), do: :ok
  end
end
