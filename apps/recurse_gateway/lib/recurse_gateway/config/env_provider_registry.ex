defmodule Recurse.Gateway.Config.EnvProviderRegistry do
  @moduledoc """
  Boot-time provider bootstrap driven entirely by environment variables.

  Replaces the prior `Recurse.Gateway.Config.TierConfigLoader` (YAML +
  SHA-256 sidecar) with a flat env-var contract: each provider role
  selects an implementation by shorthand, and each impl's per-config is
  read from its own existing env vars (`POSTGRES_*`, `OPENAI_API_KEY`,
  `KMS_KEY_ID`, `CAS_BUCKET`, `R5E_CEDAR_*`, ...).

  The YAML's only unique contribution was choosing the impl module per
  role; now `R5E_PROVIDER_<ROLE>_IMPL` does that directly.

  ## Iron Law check (`elixir:elixir-thinking`)

    1. Mutable state across calls? No — a single boot-time read of the
       OS environment, then an idempotent
       `Recurse.Gateway.ProviderRegistry.install!/1` call.
    2. Concurrent execution? No — runs once during supervision-tree
       startup, before any children that read provider state.
    3. Fault isolation? No — a missing env var is a config bug; we raise
       and let the supervisor crash. Fail-closed per Constitution
       Principle III.

  All three NO → plain functions. Not a GenServer.

  ## Env var contract (`R5E_PROVIDER_*_IMPL`)

  | Role            | Env var                          | Required? | Shortname → module |
  |-----------------|----------------------------------|-----------|--------------------|
  | Ledger          | `R5E_PROVIDER_LEDGER_IMPL`         | yes | `postgres_merkle` → `Recurse.Providers.Impls.PostgresMerkleLedger` |
  | Payload broker  | `R5E_PROVIDER_PAYLOAD_BROKER_IMPL` | yes | `s3` → `Recurse.Providers.Impls.S3StorageProvider`<br/>`filesystem` → `Recurse.Providers.Impls.FilesystemStorageProvider` |
  | Secrets         | `R5E_PROVIDER_SECRETS_IMPL`        | yes | `aws_kms` → `Recurse.Providers.Impls.AwsKmsSecretsProvider`<br/>`local_pem` → `Recurse.Providers.Impls.LocalPemSecretsProvider` |
  | LLM             | `R5E_PROVIDER_LLM_IMPL`            | NO  | `openai` → `Recurse.Providers.Impls.OpenAiLlmProvider` |
  | Policy          | `R5E_PROVIDER_POLICY_IMPL`         | NO  | `oci` → `Recurse.Providers.Impls.OciPolicyProvider`<br/>`filesystem` → `Recurse.Providers.Impls.FilesystemPolicyProvider` |

  Plus impl-specific env vars consumed inside the per-role config builders.

  ### Zero-cloud shortnames (spec 012 Compose quickstart)

  `filesystem` (payload broker) and `local_pem` (secrets) are the
  providers the Docker Compose quickstart installs so the gateway boots
  with no AWS account:

  | Shortname    | Env var                       | Default                          |
  |--------------|-------------------------------|----------------------------------|
  | `filesystem` | `R5E_CAS_ROOT`                | `/data/cas`                      |
  | `local_pem`  | `R5E_LOCAL_SIGNING_KEY_PATH`  | `/secrets/local-signing-key.pem` |
  | `local_pem`  | `R5E_LOCAL_SIGNING_ALG`       | `es256` (or `ed25519`)           |

  Both are dev/local-appliance posture: the signing key is plain on disk
  and the CAS is a directory. Neither is a production shape.

  ### LLM is OPTIONAL

  When `R5E_PROVIDER_LLM_IMPL` is unset or empty the install_map omits
  the `:llm` key; `ProviderRegistry.llm_provider/0` then returns
  `:not_configured`. This matches the spec-009 LLM-proxy + audit-only
  deployment shape where the gateway forwards client-bearing traffic
  rather than synthesizing chat completions itself, so requiring an
  `OPENAI_API_KEY` at boot would force operators to provision an
  unused secret.

  When the var IS set, every per-impl env var (e.g. `OPENAI_API_KEY`
  for the `openai` shortname) is required and missing values raise.
  Setting the impl shortname commits the operator to its config
  surface — fail-closed per Constitution Principle III.

  ## Tenant identity

  The deployment-pinned `tenant_id` is read from `R5E_TENANT_ID`. In the
  managed-SaaS posture, this is the customer's WorkOS organization id
  (e.g. `org_01KQ5T2EH9NP3AWE54AB2APWNH`); other shapes are accepted as
  long as the value is non-empty.

  ## Boot-time fail-closed

  A missing required env var or an unknown impl shortname raises
  `RuntimeError` with the offending name in the message. The Gateway
  supervisor crashes, systemd / the container runtime surfaces the
  failure. This matches the prior tier-config loader's posture.

  ## NOT installed

  - The Policy provider role is wired into `ProviderRegistry` only when
    a future install_map adds a `:policy` key. Today the policy bundle
    is loaded by `Recurse.Gateway.Policy.BundleLoader`
    (filesystem) or `Recurse.Gateway.Policy.OciBundleManager` (OCI).
    Reading `R5E_PROVIDER_POLICY_IMPL` here is reserved for a
    follow-up MR that unifies the bootstrap; we still validate the
    shorthand at boot to surface typos early.
  """

  alias Recurse.Gateway.ProviderRegistry

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

  @ledger_impls %{
    "postgres_merkle" => PostgresMerkleLedger
  }

  @payload_broker_impls %{
    "s3" => S3StorageProvider,
    "filesystem" => FilesystemStorageProvider
  }

  @secrets_impls %{
    "aws_kms" => AwsKmsSecretsProvider,
    "local_pem" => LocalPemSecretsProvider
  }

  @llm_impls %{
    "openai" => OpenAiLlmProvider
  }

  @policy_impls %{
    "oci" => OciPolicyProvider,
    "filesystem" => FilesystemPolicyProvider
  }

  @doc """
  Read every required env var, build the install_map, hand it to
  `Recurse.Gateway.ProviderRegistry.install!/1`. Raises on any missing
  env var or unknown impl shortname.
  """
  @spec install!() :: :ok
  def install! do
    install_map = build_install_map!()
    ProviderRegistry.install!(install_map)
  end

  @doc """
  Build the install_map without installing it. Exposed for tests.

  The `:llm` slot is built ONLY when `R5E_PROVIDER_LLM_IMPL` is set
  to a non-empty value. Spec-009 proxy deployments + audit-only
  deployments don't synthesize chat completions from the gateway
  itself, so requiring `OPENAI_API_KEY` at boot would force operators
  to provision an unused secret. See `ProviderRegistry.install_map`
  for the consumer contract; consumers handle `:not_configured` from
  `ProviderRegistry.llm_provider/0`.
  """
  @spec build_install_map!() :: ProviderRegistry.install_map()
  def build_install_map! do
    tenant_id = require_env!("R5E_TENANT_ID")

    base = %{
      tenant_id: tenant_id,
      signer: "observed://gateway",
      ledger: build_ledger!(),
      storage: build_payload_broker!(),
      secrets: build_secrets!()
    }

    case maybe_build_llm!() do
      :not_configured -> base
      {_mod, _cfg} = entry -> Map.put(base, :llm, entry)
    end
  end

  # ---------------------------------------------------------------------------
  # Per-role builders
  # ---------------------------------------------------------------------------

  # Optional LLM builder. Returns `:not_configured` when
  # `R5E_PROVIDER_LLM_IMPL` is unset or empty (the proxy-only / audit-only
  # deployment shape); raises when the var IS set but per-impl env
  # (`OPENAI_API_KEY`) is missing — same fail-closed posture as the
  # other roles. Surfaces a setup typo (`R5E_PROVIDER_LLM_IMPL=opena`)
  # via `resolve_impl!`'s known-shortname error.
  @spec maybe_build_llm!() :: {module(), map()} | :not_configured
  defp maybe_build_llm! do
    case System.get_env("R5E_PROVIDER_LLM_IMPL") do
      nil -> :not_configured
      "" -> :not_configured
      _ -> build_llm!()
    end
  end

  @spec build_llm!() :: {module(), map()}
  defp build_llm! do
    case resolve_impl!("R5E_PROVIDER_LLM_IMPL", @llm_impls) do
      OpenAiLlmProvider ->
        config = %{
          base_url: env_default("OPENAI_BASE_URL", "https://api.openai.com/v1"),
          resolved_api_key: require_env!("OPENAI_API_KEY"),
          timeout_ms: env_integer("OPENAI_TIMEOUT_MS", 30_000),
          finch_pool: :openai_pool
        }

        {OpenAiLlmProvider, config}
    end
  end

  @spec build_ledger!() :: {module(), map()}
  defp build_ledger! do
    case resolve_impl!("R5E_PROVIDER_LEDGER_IMPL", @ledger_impls) do
      PostgresMerkleLedger ->
        config = %{
          database_url: resolve_database_url!(),
          interim_commit_event_count: env_integer("R5E_INTERIM_COMMIT_EVENT_COUNT", 10_000),
          interim_commit_threshold_minutes:
            env_integer("R5E_INTERIM_COMMIT_THRESHOLD_MINUTES", 60)
        }

        {PostgresMerkleLedger, config}
    end
  end

  @spec build_payload_broker!() :: {module(), map()}
  defp build_payload_broker! do
    case resolve_impl!("R5E_PROVIDER_PAYLOAD_BROKER_IMPL", @payload_broker_impls) do
      S3StorageProvider ->
        config = %{
          bucket: require_env!("CAS_BUCKET"),
          region: require_env!("AWS_REGION"),
          finch_pool: :s3_pool,
          kms_encryption: env_boolean("CAS_KMS_ENCRYPTION", true),
          object_lock_compliance_days: env_integer("CAS_OBJECT_LOCK_COMPLIANCE_DAYS", 2_555)
        }

        {S3StorageProvider, config}

      FilesystemStorageProvider ->
        {FilesystemStorageProvider, %{root: env_default("R5E_CAS_ROOT", "/data/cas")}}
    end
  end

  @spec build_secrets!() :: {module(), map()}
  defp build_secrets! do
    case resolve_impl!("R5E_PROVIDER_SECRETS_IMPL", @secrets_impls) do
      AwsKmsSecretsProvider ->
        config = %{
          key_arn: require_env!("KMS_KEY_ID"),
          algorithm: env_default("KMS_ALGORITHM", "ECDSA_SHA_256"),
          region: require_env!("AWS_REGION"),
          finch_pool: :kms_pool,
          refs: %{}
        }

        {AwsKmsSecretsProvider, config}

      LocalPemSecretsProvider ->
        config = %{
          key_path: env_default("R5E_LOCAL_SIGNING_KEY_PATH", "/secrets/local-signing-key.pem"),
          algorithm: local_signing_alg!()
        }

        {LocalPemSecretsProvider, config}
    end
  end

  # `R5E_LOCAL_SIGNING_ALG` — validated here (not just in the provider's
  # `init/1`) so a typo fails at boot with the env-var name in the
  # message, matching every other shortname/enum in this module. The
  # parsing itself is the provider's (`normalize_algorithm/1`), so the
  # two can't drift.
  @spec local_signing_alg!() :: LocalPemSecretsProvider.algorithm()
  defp local_signing_alg! do
    raw = env_default("R5E_LOCAL_SIGNING_ALG", "es256")

    case LocalPemSecretsProvider.normalize_algorithm(raw) do
      {:ok, algorithm} ->
        algorithm

      {:error, _reason} ->
        known = Enum.map_join(LocalPemSecretsProvider.algorithms(), ", ", &Atom.to_string/1)

        raise RuntimeError,
              "R5E_LOCAL_SIGNING_ALG: unknown algorithm #{inspect(raw)}. " <>
                "Known algorithms: #{known}."
    end
  end

  @doc """
  Validate `R5E_PROVIDER_POLICY_IMPL` (if set) without installing
  anything. Returns the resolved module so callers can pre-flight the
  shorthand at boot. Today the policy bundle is loaded outside
  `ProviderRegistry`; this hook surfaces typos early without coupling
  the two paths.

  Returns `nil` when the env var is unset (policy provider remains
  optional during the YAML-removal transition).
  """
  @spec validate_policy_impl!() :: module() | nil
  def validate_policy_impl! do
    case System.get_env("R5E_PROVIDER_POLICY_IMPL") do
      nil ->
        nil

      "" ->
        nil

      shortname ->
        resolve_shortname!("R5E_PROVIDER_POLICY_IMPL", shortname, @policy_impls)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  @spec resolve_impl!(String.t(), %{optional(String.t()) => module()}) :: module()
  defp resolve_impl!(env_var, registry) do
    shortname = require_env!(env_var)
    resolve_shortname!(env_var, shortname, registry)
  end

  @spec resolve_shortname!(
          String.t(),
          String.t(),
          %{optional(String.t()) => module()}
        ) :: module()
  defp resolve_shortname!(env_var, shortname, registry) do
    case Map.get(registry, shortname) do
      nil ->
        known = registry |> Map.keys() |> Enum.sort() |> Enum.join(", ")

        raise RuntimeError,
              "#{env_var}: unknown impl shortname #{inspect(shortname)}. " <>
                "Known shortnames: #{known}."

      module when is_atom(module) ->
        module
    end
  end

  # Synthesize DATABASE_URL from POSTGRES_* env vars when the operator
  # hasn't provided a URL directly. Mirrors the same compose-from-pieces
  # logic that lived in `runtime.exs`. We URL-encode user + password so
  # special characters in either don't malform the URI.
  @spec resolve_database_url!() :: String.t()
  defp resolve_database_url! do
    case System.get_env("DATABASE_URL") do
      url when is_binary(url) and url != "" ->
        url

      _ ->
        user = URI.encode_www_form(require_env!("POSTGRES_USER"))
        password = URI.encode_www_form(require_env!("POSTGRES_PASSWORD"))
        host = require_env!("POSTGRES_HOST")
        port = env_default("POSTGRES_PORT", "5432")
        database = require_env!("POSTGRES_DB")
        "postgres://#{user}:#{password}@#{host}:#{port}/#{database}"
    end
  end

  @spec require_env!(String.t()) :: String.t()
  defp require_env!(name) do
    case System.get_env(name) do
      value when is_binary(value) and value != "" ->
        value

      _ ->
        raise RuntimeError,
              "EnvProviderRegistry: required environment variable #{name} is unset or empty."
    end
  end

  @spec env_default(String.t(), String.t()) :: String.t()
  defp env_default(name, default) do
    case System.get_env(name) do
      value when is_binary(value) and value != "" -> value
      _ -> default
    end
  end

  @spec env_integer(String.t(), integer()) :: integer()
  defp env_integer(name, default) do
    case System.get_env(name) do
      nil ->
        default

      "" ->
        default

      raw when is_binary(raw) ->
        case Integer.parse(raw) do
          {value, ""} ->
            value

          _ ->
            raise RuntimeError,
                  "EnvProviderRegistry: env var #{name}=#{inspect(raw)} is not a valid integer."
        end
    end
  end

  @spec env_boolean(String.t(), boolean()) :: boolean()
  defp env_boolean(name, default) do
    case System.get_env(name) do
      nil ->
        default

      "" ->
        default

      "true" ->
        true

      "false" ->
        false

      "1" ->
        true

      "0" ->
        false

      other ->
        raise RuntimeError,
              "EnvProviderRegistry: env var #{name}=#{inspect(other)} is not a valid boolean " <>
                "(expected one of: true, false, 1, 0)."
    end
  end
end
