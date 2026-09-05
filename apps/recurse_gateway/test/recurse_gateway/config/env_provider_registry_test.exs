defmodule Recurse.Gateway.Config.EnvProviderRegistryTest do
  @moduledoc """
  Unit tests for `Recurse.Gateway.Config.EnvProviderRegistry`.

  Scope:
    * Happy path — all required env vars set → install_map matches the
      expected provider impl + per-impl config shape.
    * Missing required env var → raises `RuntimeError` with the variable
      name in the message.
    * Unknown impl shortname → raises `RuntimeError` with the unknown
      name + the known-shortnames list in the message.
    * Optional `R5E_PROVIDER_POLICY_IMPL` validation — accepts known
      shortnames (`oci`, `filesystem`); rejects typos.

  `async: false` because every test mutates `System.put_env/2` /
  `System.delete_env/1` and `:recurse_gateway` app env. The setup
  blocks save/restore prior values so concurrent unrelated tests aren't
  affected when this suite runs after them sequentially.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.Config.EnvProviderRegistry

  alias Recurse.Providers.Impls.{
    AwsKmsSecretsProvider,
    FilesystemPolicyProvider,
    FilesystemStorageProvider,
    LocalPemSecretsProvider,
    OciPolicyProvider,
    OpenAiLlmProvider,
    PostgresMerkleLedger,
    S3StorageProvider
  }

  @env_vars ~w(
    R5E_TENANT_ID
    R5E_PROVIDER_LEDGER_IMPL
    R5E_PROVIDER_PAYLOAD_BROKER_IMPL
    R5E_PROVIDER_SECRETS_IMPL
    R5E_PROVIDER_LLM_IMPL
    R5E_PROVIDER_POLICY_IMPL
    DATABASE_URL
    POSTGRES_USER
    POSTGRES_PASSWORD
    POSTGRES_HOST
    POSTGRES_PORT
    POSTGRES_DB
    OPENAI_API_KEY
    OPENAI_BASE_URL
    OPENAI_TIMEOUT_MS
    KMS_KEY_ID
    KMS_ALGORITHM
    AWS_REGION
    CAS_BUCKET
    CAS_KMS_ENCRYPTION
    CAS_OBJECT_LOCK_COMPLIANCE_DAYS
    R5E_INTERIM_COMMIT_EVENT_COUNT
    R5E_INTERIM_COMMIT_THRESHOLD_MINUTES
    R5E_CAS_ROOT
    R5E_LOCAL_SIGNING_KEY_PATH
    R5E_LOCAL_SIGNING_ALG
  )

  setup do
    saved =
      Map.new(@env_vars, fn name ->
        {name, System.get_env(name)}
      end)

    Enum.each(@env_vars, &System.delete_env/1)

    on_exit(fn ->
      Enum.each(saved, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)
    end)

    :ok
  end

  describe "build_install_map!/0 — happy path" do
    test "returns the expected install_map shape with all impls populated" do
      put_required_env()

      assert %{
               tenant_id: "01HXJQ7YZABCDEFGHJKMNPQRS",
               signer: "observed://gateway",
               llm: {OpenAiLlmProvider, llm_config},
               ledger: {PostgresMerkleLedger, ledger_config},
               storage: {S3StorageProvider, storage_config},
               secrets: {AwsKmsSecretsProvider, secrets_config}
             } = EnvProviderRegistry.build_install_map!()

      assert llm_config.base_url == "https://api.openai.com/v1"
      assert llm_config.resolved_api_key == "sk-test-env"
      assert llm_config.timeout_ms == 30_000
      assert llm_config.finch_pool == :openai_pool

      assert ledger_config.database_url ==
               "postgres://recurse:recurse@localhost:5432/recurse_test"

      assert ledger_config.interim_commit_event_count == 10_000
      assert ledger_config.interim_commit_threshold_minutes == 60

      assert storage_config.bucket == "test-cas-bucket"
      assert storage_config.region == "us-west-2"
      assert storage_config.finch_pool == :s3_pool
      assert storage_config.kms_encryption == true
      assert storage_config.object_lock_compliance_days == 2_555

      assert secrets_config.key_arn ==
               "arn:aws:kms:us-west-2:123456789012:key/00000000-0000-0000-0000-000000000000"

      assert secrets_config.algorithm == "ECDSA_SHA_256"
      assert secrets_config.region == "us-west-2"
      assert secrets_config.finch_pool == :kms_pool
      assert secrets_config.refs == %{}
    end

    test "synthesizes DATABASE_URL from POSTGRES_* env vars when DATABASE_URL unset" do
      put_required_env()
      System.delete_env("DATABASE_URL")
      System.put_env("POSTGRES_USER", "alice")
      System.put_env("POSTGRES_PASSWORD", "p@ss/word")
      System.put_env("POSTGRES_HOST", "db.internal")
      System.put_env("POSTGRES_PORT", "5433")
      System.put_env("POSTGRES_DB", "audit_console")

      assert %{ledger: {PostgresMerkleLedger, ledger_config}} =
               EnvProviderRegistry.build_install_map!()

      # `p@ss/word` is URL-encoded — `@` -> `%40`, `/` -> `%2F`.
      assert ledger_config.database_url ==
               "postgres://alice:p%40ss%2Fword@db.internal:5433/audit_console"
    end

    test "respects optional integer overrides via env" do
      put_required_env()
      System.put_env("R5E_INTERIM_COMMIT_EVENT_COUNT", "500")
      System.put_env("R5E_INTERIM_COMMIT_THRESHOLD_MINUTES", "5")
      System.put_env("CAS_OBJECT_LOCK_COMPLIANCE_DAYS", "30")
      System.put_env("OPENAI_TIMEOUT_MS", "5000")

      assert %{
               ledger: {PostgresMerkleLedger, ledger_config},
               storage: {S3StorageProvider, storage_config},
               llm: {OpenAiLlmProvider, llm_config}
             } = EnvProviderRegistry.build_install_map!()

      assert ledger_config.interim_commit_event_count == 500
      assert ledger_config.interim_commit_threshold_minutes == 5
      assert storage_config.object_lock_compliance_days == 30
      assert llm_config.timeout_ms == 5000
    end

    test "respects boolean override CAS_KMS_ENCRYPTION=false" do
      put_required_env()
      System.put_env("CAS_KMS_ENCRYPTION", "false")

      assert %{storage: {S3StorageProvider, storage_config}} =
               EnvProviderRegistry.build_install_map!()

      assert storage_config.kms_encryption == false
    end
  end

  describe "build_install_map!/0 — missing required env" do
    test "raises with R5E_TENANT_ID name when tenant id is unset" do
      put_required_env()
      System.delete_env("R5E_TENANT_ID")

      assert_raise RuntimeError,
                   ~r/R5E_TENANT_ID is unset or empty/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "raises with R5E_PROVIDER_LEDGER_IMPL when ledger impl is unset" do
      put_required_env()
      System.delete_env("R5E_PROVIDER_LEDGER_IMPL")

      assert_raise RuntimeError,
                   ~r/R5E_PROVIDER_LEDGER_IMPL is unset or empty/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "raises with OPENAI_API_KEY when LLM impl key is unset" do
      put_required_env()
      System.delete_env("OPENAI_API_KEY")

      assert_raise RuntimeError,
                   ~r/OPENAI_API_KEY is unset or empty/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "raises with CAS_BUCKET when payload broker bucket is unset" do
      put_required_env()
      System.delete_env("CAS_BUCKET")

      assert_raise RuntimeError,
                   ~r/CAS_BUCKET is unset or empty/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "raises with KMS_KEY_ID when secrets key is unset" do
      put_required_env()
      System.delete_env("KMS_KEY_ID")

      assert_raise RuntimeError,
                   ~r/KMS_KEY_ID is unset or empty/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "raises with AWS_REGION when region is unset" do
      put_required_env()
      System.delete_env("AWS_REGION")

      assert_raise RuntimeError,
                   ~r/AWS_REGION is unset or empty/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "raises with POSTGRES_HOST when synthesizing DATABASE_URL with missing pieces" do
      put_required_env()
      System.delete_env("DATABASE_URL")
      System.put_env("POSTGRES_USER", "alice")
      System.put_env("POSTGRES_PASSWORD", "secret")
      # POSTGRES_HOST intentionally missing
      System.put_env("POSTGRES_DB", "audit_console")

      assert_raise RuntimeError,
                   ~r/POSTGRES_HOST is unset or empty/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end
  end

  describe "build_install_map!/0 — unknown impl shortname" do
    test "raises with the offending name + known list when ledger impl is bogus" do
      put_required_env()
      System.put_env("R5E_PROVIDER_LEDGER_IMPL", "nonsense")

      assert_raise RuntimeError,
                   ~r/R5E_PROVIDER_LEDGER_IMPL: unknown impl shortname "nonsense".+postgres_merkle/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "raises when payload broker shortname is bogus" do
      put_required_env()
      System.put_env("R5E_PROVIDER_PAYLOAD_BROKER_IMPL", "gcs")

      assert_raise RuntimeError,
                   ~r/R5E_PROVIDER_PAYLOAD_BROKER_IMPL: unknown impl shortname "gcs".+s3/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "raises when LLM shortname is bogus" do
      put_required_env()
      System.put_env("R5E_PROVIDER_LLM_IMPL", "anthropic")

      assert_raise RuntimeError,
                   ~r/R5E_PROVIDER_LLM_IMPL: unknown impl shortname "anthropic".+openai/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "raises when secrets shortname is bogus" do
      put_required_env()
      System.put_env("R5E_PROVIDER_SECRETS_IMPL", "vault")

      assert_raise RuntimeError,
                   ~r/R5E_PROVIDER_SECRETS_IMPL: unknown impl shortname "vault".+aws_kms/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end
  end

  describe "build_install_map!/0 — invalid env value coercion" do
    test "raises when an integer-typed env var has non-integer content" do
      put_required_env()
      System.put_env("R5E_INTERIM_COMMIT_EVENT_COUNT", "lots")

      assert_raise RuntimeError,
                   ~r/R5E_INTERIM_COMMIT_EVENT_COUNT.+not a valid integer/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "raises when a boolean-typed env var has non-boolean content" do
      put_required_env()
      System.put_env("CAS_KMS_ENCRYPTION", "yesplease")

      assert_raise RuntimeError,
                   ~r/CAS_KMS_ENCRYPTION.+not a valid boolean/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end
  end

  describe "build_install_map!/0 — optional LLM slot" do
    test "omits the :llm key when R5E_PROVIDER_LLM_IMPL is unset" do
      put_required_env()
      System.delete_env("R5E_PROVIDER_LLM_IMPL")
      System.delete_env("OPENAI_API_KEY")

      install_map = EnvProviderRegistry.build_install_map!()

      refute Map.has_key?(install_map, :llm)
      assert %{ledger: {PostgresMerkleLedger, _}} = install_map
      assert %{storage: {S3StorageProvider, _}} = install_map
      assert %{secrets: {AwsKmsSecretsProvider, _}} = install_map
    end

    test "omits the :llm key when R5E_PROVIDER_LLM_IMPL is empty" do
      put_required_env()
      System.put_env("R5E_PROVIDER_LLM_IMPL", "")
      System.delete_env("OPENAI_API_KEY")

      install_map = EnvProviderRegistry.build_install_map!()

      refute Map.has_key?(install_map, :llm)
    end

    test "still raises on missing OPENAI_API_KEY when LLM impl IS set (no silent fallthrough)" do
      put_required_env()
      System.delete_env("OPENAI_API_KEY")
      # R5E_PROVIDER_LLM_IMPL=openai is in put_required_env — operator
      # opted into the LLM role, so per-impl config is fail-closed.

      assert_raise RuntimeError,
                   ~r/OPENAI_API_KEY is unset or empty/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end
  end

  describe "build_install_map!/0 — zero-cloud shortnames (spec 012)" do
    test "filesystem payload broker defaults R5E_CAS_ROOT to /data/cas" do
      put_required_env()
      System.put_env("R5E_PROVIDER_PAYLOAD_BROKER_IMPL", "filesystem")
      System.delete_env("CAS_BUCKET")

      assert %{storage: {FilesystemStorageProvider, %{root: "/data/cas"}}} =
               EnvProviderRegistry.build_install_map!()
    end

    test "filesystem payload broker honours R5E_CAS_ROOT" do
      put_required_env()
      System.put_env("R5E_PROVIDER_PAYLOAD_BROKER_IMPL", "filesystem")
      System.put_env("R5E_CAS_ROOT", "/var/lib/r5e/cas")

      assert %{storage: {FilesystemStorageProvider, %{root: "/var/lib/r5e/cas"}}} =
               EnvProviderRegistry.build_install_map!()
    end

    test "local_pem secrets defaults to the /secrets PEM path and ES256" do
      put_required_env()
      System.put_env("R5E_PROVIDER_SECRETS_IMPL", "local_pem")
      System.delete_env("KMS_KEY_ID")

      assert %{
               secrets:
                 {LocalPemSecretsProvider,
                  %{key_path: "/secrets/local-signing-key.pem", algorithm: :es256}}
             } = EnvProviderRegistry.build_install_map!()
    end

    test "local_pem secrets honours R5E_LOCAL_SIGNING_KEY_PATH + R5E_LOCAL_SIGNING_ALG" do
      put_required_env()
      System.put_env("R5E_PROVIDER_SECRETS_IMPL", "local_pem")
      System.put_env("R5E_LOCAL_SIGNING_KEY_PATH", "/keys/attest.pem")
      System.put_env("R5E_LOCAL_SIGNING_ALG", "Ed25519")

      assert %{
               secrets:
                 {LocalPemSecretsProvider, %{key_path: "/keys/attest.pem", algorithm: :ed25519}}
             } =
               EnvProviderRegistry.build_install_map!()
    end

    test "raises on an unknown R5E_LOCAL_SIGNING_ALG" do
      put_required_env()
      System.put_env("R5E_PROVIDER_SECRETS_IMPL", "local_pem")
      System.put_env("R5E_LOCAL_SIGNING_ALG", "rsa")

      assert_raise RuntimeError,
                   ~r/R5E_LOCAL_SIGNING_ALG: unknown algorithm "rsa".+es256, ed25519/,
                   fn -> EnvProviderRegistry.build_install_map!() end
    end

    test "zero-cloud shape needs no AWS env at all" do
      put_required_env()
      System.put_env("R5E_PROVIDER_PAYLOAD_BROKER_IMPL", "filesystem")
      System.put_env("R5E_PROVIDER_SECRETS_IMPL", "local_pem")

      Enum.each(
        ~w(CAS_BUCKET KMS_KEY_ID AWS_REGION R5E_PROVIDER_LLM_IMPL OPENAI_API_KEY),
        &System.delete_env/1
      )

      install_map = EnvProviderRegistry.build_install_map!()

      assert %{storage: {FilesystemStorageProvider, _}, secrets: {LocalPemSecretsProvider, _}} =
               install_map

      refute Map.has_key?(install_map, :llm)
    end
  end

  describe "validate_policy_impl!/0" do
    test "returns nil when R5E_PROVIDER_POLICY_IMPL is unset" do
      System.delete_env("R5E_PROVIDER_POLICY_IMPL")
      assert nil == EnvProviderRegistry.validate_policy_impl!()
    end

    test "returns nil when R5E_PROVIDER_POLICY_IMPL is empty" do
      System.put_env("R5E_PROVIDER_POLICY_IMPL", "")
      assert nil == EnvProviderRegistry.validate_policy_impl!()
    end

    test "returns OciPolicyProvider for shortname \"oci\"" do
      System.put_env("R5E_PROVIDER_POLICY_IMPL", "oci")
      assert OciPolicyProvider == EnvProviderRegistry.validate_policy_impl!()
    end

    test "returns FilesystemPolicyProvider for shortname \"filesystem\"" do
      System.put_env("R5E_PROVIDER_POLICY_IMPL", "filesystem")
      assert FilesystemPolicyProvider == EnvProviderRegistry.validate_policy_impl!()
    end

    test "raises on unknown policy shortname" do
      System.put_env("R5E_PROVIDER_POLICY_IMPL", "ocii")

      assert_raise RuntimeError,
                   ~r/R5E_PROVIDER_POLICY_IMPL: unknown impl shortname "ocii".+filesystem, oci/,
                   fn -> EnvProviderRegistry.validate_policy_impl!() end
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp put_required_env do
    System.put_env("R5E_TENANT_ID", "01HXJQ7YZABCDEFGHJKMNPQRS")
    System.put_env("R5E_PROVIDER_LEDGER_IMPL", "postgres_merkle")
    System.put_env("R5E_PROVIDER_PAYLOAD_BROKER_IMPL", "s3")
    System.put_env("R5E_PROVIDER_SECRETS_IMPL", "aws_kms")
    System.put_env("R5E_PROVIDER_LLM_IMPL", "openai")

    System.put_env("DATABASE_URL", "postgres://recurse:recurse@localhost:5432/recurse_test")
    System.put_env("OPENAI_API_KEY", "sk-test-env")

    System.put_env(
      "KMS_KEY_ID",
      "arn:aws:kms:us-west-2:123456789012:key/00000000-0000-0000-0000-000000000000"
    )

    System.put_env("AWS_REGION", "us-west-2")
    System.put_env("CAS_BUCKET", "test-cas-bucket")
  end
end
