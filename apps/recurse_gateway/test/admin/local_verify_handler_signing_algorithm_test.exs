defmodule Recurse.Gateway.Admin.LocalVerifyHandlerSigningAlgorithmTest do
  @moduledoc """
  Spec 012 S1 review (finding E): `LocalVerifyHandler` step 1 must
  dispatch on the signing key's algorithm instead of assuming ES256.

  An Ed25519 signature is 64 bytes, the exact size of a raw ES256
  `r || s`, so `Dsse.verify_es256/4` accepts it as input and returns a
  well-formed but FALSE `:signature_mismatch`. The console then told the
  auditor a genuine receipt was forged. The fix reports
  `unsupported_algorithm` with a plain explanation and never claims a
  mismatch.

  Both key-resolution branches are exercised with the real
  `LocalPemSecretsProvider` (the compose quickstart's signer):

    * archive miss → `Resolvers.SigningKey.Fallback` (the `observed://`
      arm; every compose receipt lands here) → algorithm read off the PEM;
    * archive hit → `signing_keys.algorithm` column (what the
      `KmsRotationWatcher` pins at rotation time).

  Plus a control: the same path with an ES256 local key still passes,
  including the DER-encoded signature `:public_key.sign/3` emits.

  `async: false`: mutates ProviderRegistry + `:browser_session` config.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :integration

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Admin.LocalVerifyHandler
  alias Recurse.Gateway.Admin.LocalVerifyHandlerSigningAlgorithmTest.StubStorage
  alias Recurse.Gateway.Attestation.EnvelopeBuilder
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.LocalPemSecretsProvider
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5X"
  @signer "observed://gateway/signing-alg-test"

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "Signing-algorithm dispatch test tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    tmp_dir = Path.join(System.tmp_dir!(), "verify_alg_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    bundle_path = write_bundle(tmp_dir)

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

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

    previous_validator_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)
    previous_browser_session = Application.get_env(:recurse_gateway, :browser_session)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid",
      known_kids: [{"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}]
    )

    Application.put_env(:recurse_gateway, :browser_session,
      cookie_name: "r5e_session",
      secret_key_base: :crypto.strong_rand_bytes(64),
      secure_cookie?: false,
      absent_cookie_redirect: :always_401
    )

    on_exit(fn ->
      File.rm_rf!(tmp_dir)
      ProviderRegistry.uninstall()
      restore_env(:jwt_validator_opts, previous_validator_opts)
      restore_env(:browser_session, previous_browser_session)
    end)

    %{tmp_dir: tmp_dir}
  end

  describe "Ed25519-signed receipt" do
    test "archive miss: step 1 reports unsupported_algorithm, never signature_mismatch", ctx do
      install_local_pem!(ctx.tmp_dir, :ed25519)
      run_id = build_attestation!()

      sig_check = verify_step_1(run_id)

      assert sig_check["status"] == "fail"
      assert sig_check["explanation"] =~ "unsupported_algorithm"
      assert sig_check["explanation"] =~ "ed25519"
      assert sig_check["explanation"] =~ "source=provider"
      assert sig_check["explanation"] =~ "not evidence of tampering"
      refute sig_check["explanation"] =~ "signature_mismatch"
      refute sig_check["explanation"] =~ "verification failed"
    end

    test "archive hit: the signing_keys.algorithm column drives the verdict", ctx do
      {_mod, state} = install_local_pem!(ctx.tmp_dir, :ed25519)
      seed_archive!(state.public_pem, :ed25519)
      run_id = build_attestation!()

      sig_check = verify_step_1(run_id)

      assert sig_check["status"] == "fail"
      assert sig_check["explanation"] =~ "unsupported_algorithm"
      assert sig_check["explanation"] =~ "ed25519"
      assert sig_check["explanation"] =~ "source=archive"
      refute sig_check["explanation"] =~ "signature_mismatch"
    end
  end

  describe "ES256-signed receipt (control)" do
    test "the same local PEM path verifies, DER signature included", ctx do
      install_local_pem!(ctx.tmp_dir, :es256)
      run_id = build_attestation!()

      sig_check = verify_step_1(run_id)

      assert sig_check["status"] == "pass", sig_check["explanation"]
      assert sig_check["explanation"] =~ "ES256"
      assert sig_check["explanation"] =~ "source=provider"
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp install_local_pem!(tmp_dir, algorithm) do
    {:ok, secrets_state} =
      LocalPemSecretsProvider.init(%{
        key_path: Path.join(tmp_dir, "local-signing-key-#{algorithm}.pem"),
        algorithm: algorithm
      })

    {:ok, ledger_state} = PostgresMerkleLedger.init(%{})
    {:ok, storage_state} = StubStorage.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, ledger_state},
      storage: {StubStorage, storage_state},
      secrets: {LocalPemSecretsProvider, secrets_state},
      tenant_id: @tenant_id,
      signer: @signer
    })

    {LocalPemSecretsProvider, secrets_state}
  end

  # The ledger stamps `signer_kms_key_id = sp.signer` + `signer_key_version =
  # "v1"` on every row (PostgresMerkleLedger.attestation_changeset/5), so an
  # archive row keyed that way is what `fetch_record_from_archive/2` finds.
  defp seed_archive!(public_pem, algorithm) do
    now = DateTime.utc_now()

    %SigningKey{}
    |> SigningKey.insert_changeset(%{
      tenant_id: @tenant_id,
      kms_key_id: @signer,
      key_version: "v1",
      public_key_pem: public_pem,
      algorithm: algorithm,
      first_seen_at: now,
      last_seen_at: now,
      chain_hash: :crypto.hash(:sha256, "signing-alg-test"),
      inserted_at: now
    })
    |> Repo.insert!()
  end

  defp verify_step_1(run_id) do
    jwt =
      JwtTestHelper.mint_test_jwt(
        recurse_role: "tenant_auditor",
        audience: "recurse-gateway-test",
        issuer: "https://test-broker.example.invalid"
      )

    conn = Plug.Test.conn(:post, "/v1/audit/receipts/#{run_id}/verify", "")
    conn = %{conn | path_params: %{"run_id" => run_id}}
    conn = Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> jwt)
    conn = LocalVerifyHandler.handle(conn)

    assert conn.status == 200
    body = JSON.decode!(conn.resp_body)
    sig_check = Enum.find(body["checks"], &(&1["step"] == 1))
    assert sig_check["name"] == "signature"
    sig_check
  end

  defp build_attestation! do
    identity_ctx = %IdentityContext{
      tenant_id: @tenant_id,
      machine_identity:
        {:observed_jwt_subject,
         %{observed_jwt_subject: "alice@corp", issuer: "https://test-broker.example.invalid"}},
      principal:
        Principal.obo_human(%{
          issuer: "https://test-broker.example.invalid",
          subject: "alice@corp",
          recurse_role: "tenant_auditor"
        }),
      correlation_id: Recurse.Shared.Ulid.generate(),
      resolved_at_usec: System.os_time(:microsecond)
    }

    request_bytes = ~s|{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}|
    response_bytes = ~s|{"object":"chat.completion","id":"x"}|

    {:ok, %Active{bundle: bundle_ref}} = Active.current()
    policy_canonical_hash = :crypto.hash(:sha256, bundle_ref.bundle_bytes)

    run_id = Ecto.UUID.generate()
    payload_uri = "s3://signing-alg-test/#{run_id}.json"

    :ok =
      StubStorage.preload(
        payload_uri,
        Recurse.Shared.Jcs.encode(%{
          "request" => Jason.decode!(request_bytes),
          "response" => Jason.decode!(response_bytes)
        })
      )

    {:ok, envelope} =
      EnvelopeBuilder.build(
        identity_ctx,
        request_bytes,
        response_bytes,
        :allow,
        policy_canonical_hash,
        :success,
        run_id: run_id,
        session_id: run_id,
        turn_id: run_id,
        signer: @signer,
        payload_uri: payload_uri,
        secrets_provider: ProviderRegistry.secrets_provider()
      )

    {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)
    run_id
  end

  defp write_bundle(tmp_dir) do
    source =
      [
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ]
      |> Path.join()
      |> File.read!()

    path = Path.join(tmp_dir, "bundle.cedar")
    File.write!(path, source)
    path
  end

  defp restore_env(key, nil), do: Application.delete_env(:recurse_gateway, key)
  defp restore_env(key, value), do: Application.put_env(:recurse_gateway, key, value)
end

defmodule Recurse.Gateway.Admin.LocalVerifyHandlerSigningAlgorithmTest.StubStorage do
  @moduledoc false
  # ETS-backed StorageProvider stub; distinct table from the F7 suites.
  @behaviour Recurse.Providers.StorageProvider

  @table :signing_alg_test_stub_storage

  @impl true
  def init(_config) do
    ensure_table!()
    {:ok, %{}}
  end

  def preload(uri, bytes) when is_binary(uri) and is_binary(bytes) do
    ensure_table!()
    :ets.insert(@table, {uri, bytes})
    :ok
  end

  @impl true
  def put_payload(_state, bytes, _ctx) when is_binary(bytes) do
    ensure_table!()
    hash = :crypto.hash(:sha256, bytes)
    uri = "s3://signing-alg-stub/" <> Base.encode16(hash, case: :lower)
    :ets.insert(@table, {uri, bytes})
    {:ok, %{uri: uri, hash: hash}}
  end

  @impl true
  def get_payload(_state, uri, _ctx) do
    ensure_table!()

    case :ets.lookup(@table, uri) do
      [{^uri, bytes}] -> {:ok, bytes}
      [] -> {:error, :not_found}
    end
  end

  @impl true
  def delete_payload(_state, uri, _ctx) do
    ensure_table!()
    :ets.delete(@table, uri)
    :ok
  end

  @impl true
  def capabilities(_state), do: [:put, :get, :delete]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok

  defp ensure_table! do
    case :ets.info(@table) do
      :undefined -> :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
      _ -> :ok
    end
  end
end
