defmodule Recurse.Gateway.Admin.LocalVerifyHandlerObservedSignerTest do
  @moduledoc """
  F7 regression — `LocalVerifyHandler` signature check (step 1) must
  pass for observed-tier receipts even when the `signing_keys` archive
  is empty.

  Background (F7 trilogy):

    * Observed-tier receipts (predicate-only events; ledger DSSE; UI
      receipts; F002 audit-plane internal events) stamp
      `signer_kms_key_id = "observed://gateway/<deployment>"` on the
      attestation row. The marker is NOT a real KMS ARN — it's an
      opaque provenance tag stamped by the boot-time provider bootstrap
      (`Recurse.Gateway.Config.EnvProviderRegistry`).
    * The actual signer is whatever
      `SecretsProvider.active_signing_key/1` returns at envelope-build
      time. On audit-dev that's a real KMS ARN under
      `runr5e-core-beam-signing`; in tests it's the per-test stub
      provider's keypair.
    * Synthetic markers never appear in the `signing_keys` archive
      (keyed by KMS ARN + version). Until issue #24 lands the
      KmsRotationWatcher backfill for ARN-keyed receipts, EVERY
      observed-tier receipt arrives at `LocalVerifyHandler` with the
      archive empty for its signer.
    * MR !31's audit-pass refactor extracted the archive query into
      `Resolvers.SigningKey` but inadvertently dropped the
      `observed://` fallback (dangling commit c11a16c). The first F7
      attempt re-landed the fallback as a sibling extraction
      (MR !60) but resolved `observed://` against the broker JWT
      PEM (`:internal_jwt.signing_key_path`) — the WRONG key. The
      broker JWT PEM signs OIDC/login tokens, not attestations.
      Result: well-formed verify against wrong key →
      `:signature_mismatch`. This MR (the closing leg of the F7
      trilogy, after MR !60 + MR !62) corrects the
      `observed://` arm to compose `active_signing_key/1` +
      `public_key/2` on the SAME provider — the same compose pattern
      used at attestation-EMIT time in `EnvelopeBuilder` — so the
      verify resolves the byte sequence whose private half signed.

  This test directly exercises the F7 fix path: archive empty, signer
  is `observed://`, SecretsProvider's active key public PEM matches
  the test JWK → step 1 (`signature`) returns `:pass`.

  ## Async + global state

  `async: false` because the test mutates ProviderRegistry +
  `:browser_session` config slots used by US2's plugs.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :integration

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Admin.LocalVerifyHandler
  alias Recurse.Gateway.Admin.LocalVerifyHandlerObservedSignerTest.KmsArnSecretsProvider
  alias Recurse.Gateway.Admin.LocalVerifyHandlerObservedSignerTest.ObservedSignerSecretsProvider
  alias Recurse.Gateway.Admin.LocalVerifyHandlerObservedSignerTest.ObservedSignerStubStorage
  alias Recurse.Gateway.Attestation.EnvelopeBuilder
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5W"

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "F7 Observed Signer Test Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    # Mint a fresh ES256 keypair. The test SecretsProvider holds it as
    # both the signing key (private half via `sign/3`) and the public
    # key returned by `public_key/2` — so when the Fallback's
    # observed:// arm composes `active_signing_key/1` + `public_key/2`,
    # the PEM it returns is the same key whose private half signed the
    # envelope, and DSSE verification succeeds end-to-end.
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})

    tmp_dir = Path.join(System.tmp_dir!(), "f7_observed_signer_#{System.unique_integer()}")
    File.mkdir_p!(tmp_dir)

    bundle_path = write_bundle()

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    _bundle_pid =
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

    {:ok, ledger_state} = PostgresMerkleLedger.init(%{})
    {:ok, secrets_state} = ObservedSignerSecretsProvider.init(%{jwk: jwk})
    {:ok, storage_state} = ObservedSignerStubStorage.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, ledger_state},
      storage: {ObservedSignerStubStorage, storage_state},
      secrets: {ObservedSignerSecretsProvider, secrets_state},
      tenant_id: @tenant_id,
      signer: "observed://gateway/f7-test"
    })

    previous_validator_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)
    previous_browser_session = Application.get_env(:recurse_gateway, :browser_session)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid",
      known_kids: [
        {"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}
      ]
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

    %{jwk: jwk, tmp_dir: tmp_dir}
  end

  describe "F7 regression — observed:// signer + empty archive" do
    test "step 1 (signature) passes when signer is observed:// and broker PEM is configured",
         ctx do
      run_id = build_observed_attestation!(ctx)

      jwt = mint_jwt("tenant_auditor")
      conn = build_post_conn(jwt, "/v1/audit/receipts/#{run_id}/verify", run_id)
      conn = LocalVerifyHandler.handle(conn)

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)

      sig_check = Enum.find(body["checks"], &(&1["step"] == 1))

      assert sig_check["name"] == "signature"

      assert sig_check["status"] == "pass",
             """
             F7 regression: signature check failed.
               explanation: #{sig_check["explanation"]}

             Expected: archive miss → Resolvers.SigningKey.Fallback resolves
             the observed:// signer via SecretsProvider.active_signing_key/1
             + public_key/2 and DSSE verifies against the active provider key.

             If this test fails after a refactor, either the dangling-commit-
             c11a16c observed:// fallback has been dropped again, OR the
             observed:// arm has regressed to reading the broker JWT PEM
             (which signs OIDC tokens, NOT attestations — see F7 trilogy
             moduledoc on Resolvers.SigningKey.Fallback).
             """

      assert sig_check["explanation"] =~ "source=provider"
    end
  end

  describe "F7 regression — KMS-ARN signer falls back to SecretsProvider on archive miss" do
    test "step 1 (signature) passes via SecretsProvider when signer is a real KMS ARN", ctx do
      # Swap the test SecretsProvider implementation in ProviderRegistry so
      # `active_signing_key/1` returns a real KMS ARN instead of the
      # `observed://` synthetic kid. This exercises the OTHER fallback arm —
      # `Resolvers.SigningKey.Fallback.fetch/2` should dispatch to
      # `SecretsProvider.public_key/2` (the same module's :public_key impl)
      # and DSSE verifies against the returned PEM.
      previous_secrets = ProviderRegistry.secrets_provider()
      kept_llm = {Recurse.Gateway.Test.StubLLM, %{}}
      kept_ledger = ProviderRegistry.ledger_provider()
      kept_storage = ProviderRegistry.storage_provider()

      kms_arn = "arn:aws:kms:us-east-1:111122223333:key/f7-test-kms"
      {:ok, kms_state} = KmsArnSecretsProvider.init(%{jwk: ctx.jwk, key_id: kms_arn})

      ProviderRegistry.install_raw!(%{
        llm: kept_llm,
        ledger: kept_ledger,
        storage: kept_storage,
        secrets: {KmsArnSecretsProvider, kms_state},
        tenant_id: @tenant_id,
        signer: "observed://gateway/f7-test"
      })

      # Sanity-check that the swap actually took effect.
      assert {KmsArnSecretsProvider, _} = ProviderRegistry.secrets_provider()

      assert {:ok, %{key_id: ^kms_arn}} =
               KmsArnSecretsProvider.active_signing_key(kms_state)

      on_exit(fn ->
        ProviderRegistry.install_raw!(%{
          llm: kept_llm,
          ledger: kept_ledger,
          storage: kept_storage,
          secrets: previous_secrets,
          tenant_id: @tenant_id,
          signer: "observed://gateway/f7-test"
        })
      end)

      run_id = build_observed_attestation!(ctx, signer: kms_arn)

      # Verify the persisted attestation actually has the KMS ARN signer.
      att =
        Repo.get!(
          Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation,
          run_id
        )

      assert att.signer_kms_key_id == kms_arn,
             "expected attestation to be signed with KMS ARN, got #{inspect(att.signer_kms_key_id)}"

      jwt = mint_jwt("tenant_auditor")
      conn = build_post_conn(jwt, "/v1/audit/receipts/#{run_id}/verify", run_id)
      conn = LocalVerifyHandler.handle(conn)

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)

      sig_check = Enum.find(body["checks"], &(&1["step"] == 1))

      assert sig_check["status"] == "pass",
             """
             KMS-ARN fallback regression: signature check failed.
               explanation: #{sig_check["explanation"]}

             Expected: archive miss → Resolvers.SigningKey.Fallback dispatches
             to SecretsProvider.public_key/2 and DSSE verifies.
             """

      assert sig_check["explanation"] =~ "source=provider"
      assert sig_check["explanation"] =~ "f7-test-kms"
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp build_observed_attestation!(ctx, opts \\ []) do
    signer = Keyword.get(opts, :signer, "observed://gateway/f7-test")

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

    {:ok, bundle_ref} = BundleLoader.current_bundle()
    policy_canonical_hash = :crypto.hash(:sha256, bundle_ref.bundle_bytes)

    run_id = Ecto.UUID.generate()
    payload_uri = "s3://f7-observed-signer/#{run_id}.json"

    :ok =
      ObservedSignerStubStorage.preload(
        payload_uri,
        canonicalize_pair(request_bytes, response_bytes)
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
        signer: signer,
        payload_uri: payload_uri,
        secrets_provider: ProviderRegistry.secrets_provider()
      )

    {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

    seed_policy_bundle(policy_canonical_hash, bundle_ref.bundle_bytes)

    # NOTE: deliberately NOT seeding the signing_keys archive — F7 demo
    # path is "archive empty → fallback chain resolves the signer".
    _ctx = ctx

    run_id
  end

  defp canonicalize_pair(req, resp) do
    Recurse.Shared.Jcs.encode(%{
      "request" => Jason.decode!(req),
      "response" => Jason.decode!(resp)
    })
  end

  defp seed_policy_bundle(canonical_hash, bundle_bytes) do
    now = DateTime.utc_now()

    sql = """
    INSERT INTO policy_bundles
      (id, tenant_id, policy_canonical_hash, bundle_bytes, cedar_version, loaded_at, source)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT DO NOTHING
    """

    {:ok, _} =
      Ecto.Adapters.SQL.query(Repo, sql, [
        Ecto.UUID.bingenerate(),
        @tenant_id,
        canonical_hash,
        bundle_bytes,
        "4.9.1",
        now,
        "filesystem"
      ])
  end

  defp build_post_conn(jwt, path, run_id) do
    conn = Plug.Test.conn(:post, path, "")
    conn = %{conn | path_params: %{"run_id" => run_id}}
    Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> jwt)
  end

  defp mint_jwt(role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp write_bundle do
    source =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ])
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "f7_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp restore_env(key, nil), do: Application.delete_env(:recurse_gateway, key)
  defp restore_env(key, value), do: Application.put_env(:recurse_gateway, key, value)
end

defmodule Recurse.Gateway.Admin.LocalVerifyHandlerObservedSignerTest.ObservedSignerSecretsProvider do
  @moduledoc """
  Test-only `SecretsProvider` for the F7 regression test (observed
  signer arm). `active_signing_key/1` returns an
  `observed://gateway/f7-test` `kms_key_id` so the persisted
  attestation row's `signer_kms_key_id` is a synthetic observed
  marker, exactly like production observed-tier receipts.

  Public-key export is implemented to return the real public PEM
  derived from the test JWK, so DSSE verification against it actually
  succeeds end-to-end.
  """
  @behaviour Recurse.Providers.SecretsProvider

  @observed_kid "observed://gateway/f7-test"

  @impl true
  def init(config) when is_map(config), do: {:ok, config}

  @impl true
  def active_signing_key(_state) do
    {:ok, %{key_id: @observed_kid, key_version: "v1", algorithm: :ecdsa_p256}}
  end

  @impl true
  def sign(%{jwk: jwk}, _handle, pae_bytes) when is_binary(pae_bytes) do
    Recurse.Gateway.Admin.LocalVerifyHandlerObservedSignerTest.SignHelper.sign_es256!(
      jwk,
      pae_bytes
    )
  end

  @impl true
  def public_key(%{jwk: jwk}, _handle) do
    pub_jwk = JOSE.JWK.to_public(jwk)
    {_mod, pem} = JOSE.JWK.to_pem(pub_jwk)
    {:ok, pem}
  end

  @impl true
  def store_user_token(_state, _ctx, _tok, _ttl), do: :ok

  @impl true
  def exchange_for_downstream_token(_s, _c, _id, _scope),
    do: {:error, :not_implemented_in_test}

  @impl true
  def capabilities(_state), do: [:sign, :public_key_export]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule Recurse.Gateway.Admin.LocalVerifyHandlerObservedSignerTest.KmsArnSecretsProvider do
  @moduledoc """
  Sibling test SecretsProvider that returns a real-looking KMS ARN
  from `active_signing_key/1` instead of an `observed://` marker.
  Used by the F7 KMS-ARN regression test to exercise the `:provider`
  fallback arm.
  """
  @behaviour Recurse.Providers.SecretsProvider

  @impl true
  def init(config) when is_map(config), do: {:ok, config}

  @impl true
  def active_signing_key(%{key_id: key_id}) do
    {:ok, %{key_id: key_id, key_version: "v1", algorithm: :ecdsa_p256}}
  end

  @impl true
  def sign(%{jwk: jwk}, _handle, pae_bytes) when is_binary(pae_bytes) do
    Recurse.Gateway.Admin.LocalVerifyHandlerObservedSignerTest.SignHelper.sign_es256!(
      jwk,
      pae_bytes
    )
  end

  @impl true
  def public_key(%{jwk: jwk}, _handle) do
    pub_jwk = JOSE.JWK.to_public(jwk)
    {_mod, pem} = JOSE.JWK.to_pem(pub_jwk)
    {:ok, pem}
  end

  @impl true
  def store_user_token(_state, _ctx, _tok, _ttl), do: :ok

  @impl true
  def exchange_for_downstream_token(_s, _c, _id, _scope),
    do: {:error, :not_implemented_in_test}

  @impl true
  def capabilities(_state), do: [:sign, :public_key_export]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule Recurse.Gateway.Admin.LocalVerifyHandlerObservedSignerTest.SignHelper do
  @moduledoc false
  # Shared ECDSA signing helper for both test SecretsProvider impls.

  def sign_es256!(jwk, pae_bytes) do
    {_, otp_priv_key} = JOSE.JWK.to_key(jwk)
    der = :public_key.sign(pae_bytes, :sha256, otp_priv_key)
    {:ok, ecdsa_der_to_raw(der, 32)}
  end

  defp ecdsa_der_to_raw(<<0x30, _len, 0x02, r_len, rest::binary>>, size) do
    <<r::binary-size(r_len), 0x02, s_len, s_rest::binary>> = rest
    <<s::binary-size(s_len), _::binary>> = s_rest
    pad(strip_leading_zero(r), size) <> pad(strip_leading_zero(s), size)
  end

  defp strip_leading_zero(<<0x00, rest::binary>>) when byte_size(rest) > 0, do: rest
  defp strip_leading_zero(other), do: other

  defp pad(bin, size) when byte_size(bin) == size, do: bin

  defp pad(bin, size) when byte_size(bin) < size do
    :binary.copy(<<0>>, size - byte_size(bin)) <> bin
  end
end

defmodule Recurse.Gateway.Admin.LocalVerifyHandlerObservedSignerTest.ObservedSignerStubStorage do
  @moduledoc """
  ETS-backed stub StorageProvider for the F7 regression test. Distinct
  table name from the US2 + US3 stubs so the integration suites don't
  collide on shared state when run in sequence.
  """
  @behaviour Recurse.Providers.StorageProvider

  @table :f7_observed_signer_stub_storage

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
    uri = "s3://f7-stub/" <> (:crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower))
    :ets.insert(@table, {uri, bytes})
    {:ok, %{uri: uri, hash: :crypto.hash(:sha256, bytes)}}
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
      :undefined ->
        :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])

      _ ->
        :ok
    end
  end
end
