# Runtime config. Provider bootstrap is now driven directly by
# `R5E_PROVIDER_<ROLE>_IMPL` env vars (see
# `Recurse.Gateway.Config.EnvProviderRegistry`); the prior YAML
# `RECURSE_TIER_CONFIG` / `RECURSE_TIER_CONFIG_HASH_FILE` contract was
# retired in MR !119 prep work. Per-impl config (`POSTGRES_*`,
# `OPENAI_API_KEY`, `KMS_KEY_ID`, `CAS_BUCKET`, `R5E_CEDAR_*`, ...) stays
# in the operator's env file.

import Config

blank? = fn
  value when is_binary(value) -> String.trim(value) == ""
  _ -> true
end

env = fn name ->
  case System.get_env(name) do
    value when is_binary(value) and value != "" -> value
    _ -> nil
  end
end

env_bool = fn name, default ->
  case env.(name) do
    nil -> default
    value -> value == "true"
  end
end

env_int = fn name, default ->
  name
  |> env.()
  |> Kernel.||(default)
  |> String.to_integer()
end

origin_from_uri = fn uri ->
  case URI.parse(uri || "") do
    %URI{scheme: scheme, host: host, port: port} when is_binary(scheme) and is_binary(host) ->
      default_port? =
        is_nil(port) or (scheme == "https" and port == 443) or
          (scheme == "http" and port == 80)

      if default_port? do
        "#{scheme}://#{host}"
      else
        "#{scheme}://#{host}:#{port}"
      end

    _ ->
      nil
  end
end

require_envs! = fn label, envs ->
  missing = for {name, value} <- envs, blank?.(value), do: name

  if missing != [] do
    raise """
    #{label} missing.

    Required env vars: #{envs |> Enum.map(fn {name, _} -> name end) |> Enum.join(", ")}
    Currently missing: #{Enum.join(missing, ", ")}
    """
  end
end

port = env.("PORT") || "4000"
audit_console_enabled? = env_bool.("R5E_AUDIT_CONSOLE_ENABLED", true)
broker_mode = env.("R5E_BROKER_MODE") || "collapsed"
workos_redirect_uri = env.("WORKOS_REDIRECT_URI")

public_hostname =
  env.("R5E_PUBLIC_HOSTNAME") ||
    origin_from_uri.(workos_redirect_uri) ||
    if config_env() == :prod do
      raise """
      Production public hostname config missing.

      Set R5E_PUBLIC_HOSTNAME, OR set WORKOS_REDIRECT_URI to an absolute URI.
      """
    else
      "http://127.0.0.1:#{port}"
    end

broker_jwt_audience = public_hostname
internal_jwt_issuer = "#{public_hostname}/internal"

broker_jwks_url =
  env.("BROKER_JWKS_URL") ||
    case broker_mode do
      "collapsed" ->
        "http://127.0.0.1:#{port}/v1/auth/jwks"

      "split" ->
        if config_env() == :prod do
          raise """
          Production split-broker config missing.

          Set BROKER_JWKS_URL when R5E_BROKER_MODE=split.
          """
        else
          nil
        end

      other ->
        raise "R5E_BROKER_MODE must be collapsed or split, got #{inspect(other)}"
    end

browser_oidc_provider = env.("BROWSER_OIDC_PROVIDER") || "workos"

if config_env() == :prod and audit_console_enabled? do
  # WorkOS credentials are only meaningful on the WorkOS path. The
  # `oidc` / `broker` providers (spec 012 Compose quickstart runs
  # `BROWSER_OIDC_PROVIDER=oidc` with dev login and no IdP) must not be
  # forced to provision an unused WorkOS tenant.
  if browser_oidc_provider == "workos" do
    require_envs!.("Production WorkOS config", [
      {"WORKOS_API_KEY", env.("WORKOS_API_KEY")},
      {"WORKOS_CLIENT_ID", env.("WORKOS_CLIENT_ID")},
      {"WORKOS_REDIRECT_URI", workos_redirect_uri}
    ])
  end

  require_envs!.("Production broker JWT config", [
    {"BROKER_JWT_SIGNING_KEY_PATH", env.("BROKER_JWT_SIGNING_KEY_PATH")}
  ])
end

# Dev fallback for the broker JWT keyring: when no
# BROKER_JWT_SIGNING_KEY_PATH is configured AND we're not in prod,
# spin up an ephemeral in-memory keypair so `iex -S mix run` boots
# cleanly. Production already raises (require_envs!.) if the path is
# missing; this branch only fires for dev / test runs without an
# explicit key path. (Test config wires `keyring: [generate_ephemeral?: true]`
# in `config/test.exs`; this picks up the dev case symmetrically.)
if config_env() != :prod and is_nil(env.("BROKER_JWT_SIGNING_KEY_PATH")) do
  config :recurse_broker, keyring: [generate_ephemeral?: true]
end

# ---------------------------------------------------------------------------
# Import defaults — settings consumed by the `mix r5e.import.*` tasks.
#
# `:default_tenant_id` is the third resolution layer for the Claude Code
# session importer (`Mix.Tasks.R5e.Import.ClaudeCodeSession`). The task
# resolves tenant_id as: CLI flag → `RECURSE_IMPORT_DEFAULT_TENANT_ID`
# env var → this config key → synthetic ULID fallback. Setting this key
# from the env var here means operators can wire the env
# variable once in the runtime environment and every release
# that runs the importer picks up the right tenant without a CLI flag.
# ---------------------------------------------------------------------------
config :recurse_gateway, :import,
  default_tenant_id: System.get_env("RECURSE_IMPORT_DEFAULT_TENANT_ID")

# ---------------------------------------------------------------------------
# WorkOS AuthKit wiring for the Audit Console.
#
# Reads `WORKOS_*` env vars from the runtime environment. The Gateway's
# `BrowserAuth.Workos` adapter + the boot-time JwksCache child both pull
# from these app-env keys.
#
# `BROWSER_OIDC_PROVIDER` defaults to `"workos"` so a vanilla dogfood
# deploy that sets nothing extra still picks the WorkOS path. To switch
# back to the broker-mediated F002/F004 path, set
# `BROWSER_OIDC_PROVIDER=oidc`.
# ---------------------------------------------------------------------------

config :recurse_gateway, :workos,
  api_key: System.get_env("WORKOS_API_KEY"),
  client_id: System.get_env("WORKOS_CLIENT_ID"),
  redirect_uri: System.get_env("WORKOS_REDIRECT_URI"),
  default_organization_id: System.get_env("WORKOS_DEFAULT_ORGANIZATION_ID"),
  api_base: System.get_env("WORKOS_API_BASE", "https://api.workos.com"),
  # WORKOS_ROLE_MAP_JSON: optional JSON map from WorkOS role slug → Recurse
  # role slug. Consumed by `BrowserAuth.Workos.pick_role/2`; the post-mapping
  # value is allowlist-checked against `@canonical_console_roles`
  # (`tenant_auditor` | `platform_operator`) before a cookie is issued.
  # Empty default = secure-by-default; deploys that use canonical Recurse
  # slugs in WorkOS need not set this. Deploys that use WorkOS default
  # `member` / `admin` slugs (or any non-canonical naming) must set it.
  # Example: WORKOS_ROLE_MAP_JSON='{"member":"tenant_auditor","admin":"platform_operator"}'
  # Parens around the multi-line case are load-bearing — without them
  # Elixir's parser treats `case ... end` as ambiguous in a keyword-list
  # value position and reports `undefined function config/4` at boot
  # (it splits the call into 4 args around the case-end boundary).
  recurse_role_map:
    (case System.get_env("WORKOS_ROLE_MAP_JSON") do
       nil -> %{}
       "" -> %{}
       json -> JSON.decode!(json)
     end)

config :recurse_gateway, :browser_oidc_idp,
  provider: browser_oidc_provider,
  issuer_url:
    env.("BROWSER_OIDC_ISSUER_URL") || env.("WORKOS_API_BASE") || "https://api.workos.com",
  audience: System.get_env("WORKOS_CLIENT_ID")

# Non-WorkOS providers (`oidc` / `broker`) make the JwksCache demand an IdP
# `jwks_url` at boot. `BROWSER_OIDC_JWKS_URL` names the real IdP. The
# collapsed-broker fallback (the gateway's own `/v1/auth/jwks`, the same
# trick `config/dev.exs` uses) applies ONLY when dev login is on — that is
# the one configuration where cookies are minted with the broker's key and
# no IdP exists (the Compose quickstart). With dev login off, `jwks_url`
# stays unset so the boot-time raise in
# `Recurse.Gateway.Application.generic_oidc_jwks_entries/0` still names the
# missing `BROWSER_OIDC_JWKS_URL` instead of silently trusting a JWKS that
# nothing signs against (spec 012 S1 review).
# `config/dev.exs` already sets `jwks_url` for dev; leaving it alone there.
dev_login_enabled? = env.("R5E_DEV_LOGIN_ENABLED") == "true"

if browser_oidc_provider != "workos" and config_env() != :dev do
  case env.("BROWSER_OIDC_JWKS_URL") || (dev_login_enabled? and broker_jwks_url) do
    url when is_binary(url) ->
      config :recurse_gateway, :browser_oidc_idp, jwks_url: url

    _ ->
      :ok
  end
end

# Internal JWT signing config — the WorkOS path mints
# broker-shaped `X-Observed-Identity` JWTs in-process so Cedar-gated
# F004 endpoints work post-WorkOS-login (GAN-fix #1, 2026-04-26). The
# signing key is the SAME ES256 PEM the broker reads from
# `BROKER_JWT_SIGNING_KEY_PATH`; collapsed-broker deploys mount one PEM file
# into the gateway pod.
#
# `:audience` MUST match the gateway's `:jwt_validator_opts.audience`
# (i.e., the broker audience the F002 production wiring uses) so the
# downstream JwtValidator accepts the minted token.
#
# The deployment-specific hostname and audience placeholders that used to
# live here are gone: `:audience` and `:issuer` are derived once above from
# the public gateway origin, so the mint side and the validator side cannot
# drift independently.
config :recurse_gateway, :internal_jwt,
  signing_key_path: System.get_env("BROKER_JWT_SIGNING_KEY_PATH"),
  audience: broker_jwt_audience,
  issuer: internal_jwt_issuer,
  ttl_seconds: env_int.("INTERNAL_JWT_TTL_SECONDS", "900")

# JWKS endpoint URL for the BROKER's signing key (the one we mint with above).
# `Recurse.Gateway.Admin.BrokerJwksHandler` publishes to `/v1/auth/jwks` on
# this gateway; in collapsed-broker deploys the URL points back at this pod
# using the configured `PORT`. Split-broker mode must set `BROKER_JWKS_URL`
# explicitly.
config :recurse_gateway,
  broker_jwks_url: broker_jwks_url

# JwtValidator opts read by every cookie-authed audit-plane handler
# (`Authz.authenticate/1`) AND by the OIDC login path's broker-JWT
# verification. Without this block the validator falls into its
# catch-all `unknown_kid` rejection because no `:known_kids` resolver
# is configured — every audit-plane request 401s even with a valid
# cookie. (Issue #19.)
#
# `:audience` and `:issuer` MUST match what the WorkOS adapter's
# `mint_internal_jwt/6` stamps into the JWT (see `:internal_jwt`
# block above) — they're the audience/issuer the broker-shaped JWT
# carries.
#
# `:known_kids: {:cache, JwksCache}` routes kid lookups through the
# in-process JwksCache GenServer. The cache is configured at boot
# (`Recurse.Gateway.Application.jwks_cache_children/0`) with an
# entry for the broker-issuer + broker-jwks-url so its first lookup
# fetches the JWKS document and populates the kid → JWK map.
config :recurse_gateway, :jwt_validator_opts,
  audience: broker_jwt_audience,
  issuer: internal_jwt_issuer,
  known_kids: {:cache, Recurse.Gateway.Identity.JwksCache},
  clock_skew_seconds: 60

# Cedar policy bundle paths read by `Recurse.Gateway.Policy.BundleLoader`
# at boot. The loader synchronously parses the bundle and stashes the
# result in `:persistent_term`; every audit-plane handler reads from
# there via `Authz.gate` → `BundleLoader.current_bundle/0`.
#
# Defaults are empty (NOT a filesystem path that may not exist).
# `application.ex#policy_bundle_loader_children/0` skips starting the
# BundleLoader entirely when bundle_path or schema_path is empty/nil,
# so an unset config = no Cedar enforcement = BEAM boots clean. (See
# the matching no-op default for `R5E_PROVIDER_POLICY_IMPL` on the OCI
# path — chart `infra/helm/audit-console/values.yaml`.)
#
# Operators opt in by setting RECURSE_POLICY_BUNDLE_PATH +
# RECURSE_POLICY_SCHEMA_PATH to file paths that exist in the runtime
# container. The previous default (an absolute path under the EC2 host's etc dir)
# was specific to the legacy EC2 deploy where a deploy step copied the
# bundle there from the release tarball; EKS containers don't have
# that path provisioned, so the loader's fail-closed init/1 crashed
# every pod at boot. (Issue #23.)
#
# R5E_POLICY_BUNDLE_POLL_MS (spec 012 S5): 0 (default) = reload only on
# SIGHUP; > 0 = also stat the bundle file every N ms and reload when it
# changed (how the compose `policy-sync` sidecar hands over a new bundle
# from another container). compose sets 5000.
config :recurse_gateway, :policy_bundle,
  bundle_path: System.get_env("RECURSE_POLICY_BUNDLE_PATH", ""),
  entity_schema_path: System.get_env("RECURSE_POLICY_SCHEMA_PATH", ""),
  poll_ms: env_int.("R5E_POLICY_BUNDLE_POLL_MS", "0")

# ---------------------------------------------------------------------------
# ex_aws HTTP client — wires the S3 StorageProvider over the supervised
# `:s3_pool` Finch pool via `ExAws.Request.Req` (Req → Finch → :s3_pool).
#
# Without this, ex_aws falls back to its default HTTP client (`:hackney`),
# which we deliberately don't carry in the release — the umbrella standardizes
# on Finch (KMS uses a custom FinchHttpClient adapter; LLM upstream uses
# Req over its own Finch pool). The S3 provider's @moduledoc explicitly
# states "Production wires `ExAws.Request.Req`"; this is that wiring.
#
# Caught 2026-04-29 during MR !34 audit-dev triage — the @moduledoc
# documented the architectural intent but the runtime config didn't
# implement it, so dogfood `/healthz` reported `storage: down:function
# :hackney.request/5 is undefined`. Issue #30 / Task F follow-up:
# replace this with a per-tier `http_client` config knob if/when we need
# different backends per tier.
config :ex_aws, http_client: ExAws.Request.Req

# ---------------------------------------------------------------------------
# Postgres Repo runtime override.
#
# `config/config.exs` reads `POSTGRES_*` env vars at COMPILE time, baking the
# build-host defaults into the release. For a release deployed into a different
# runtime (Kubernetes pod, customer VPC, dedicated VM) those defaults are wrong.
#
# Re-evaluate the same env vars at runtime so the deployed Repo points at the
# real Postgres host. Defaults match config.exs to keep dev/test behavior
# identical when no env is set.
# ---------------------------------------------------------------------------

if config_env() == :prod do
  # Postgres config — fail-fast when neither DATABASE_URL nor the discrete
  # POSTGRES_* set is fully populated. The previous version silently fell
  # through to localhost:5432 + a "recurse" user, which masked config
  # mistakes until first query. EKS deploy 2026-05-06 caught this when a
  # POSTGRES_URL secret key didn't get renamed to DATABASE_URL: the BEAM
  # booted clean, took readiness traffic, and failed on the first /admin
  # request with `(DBConnection.ConnectionError) ... localhost:5432`.
  #
  # Resolution rules (in order):
  #   1. If DATABASE_URL is set + non-empty, use it as-is.
  #   2. Else, if all four discrete vars are present (POSTGRES_HOST,
  #      POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB), synthesize a URL
  #      from them. POSTGRES_PORT defaults to 5432; POSTGRES_POOL_SIZE
  #      defaults to "10" (both fine to default — they're not host-routable).
  #   3. Otherwise, raise with a clear error listing which vars were missing.
  #
  database_url_env = System.get_env("DATABASE_URL")

  resolved_database_url =
    cond do
      is_binary(database_url_env) and database_url_env != "" ->
        database_url_env

      true ->
        required = %{
          "POSTGRES_HOST" => System.get_env("POSTGRES_HOST"),
          "POSTGRES_USER" => System.get_env("POSTGRES_USER"),
          "POSTGRES_PASSWORD" => System.get_env("POSTGRES_PASSWORD"),
          "POSTGRES_DB" => System.get_env("POSTGRES_DB")
        }

        missing = for {k, v} <- required, v in [nil, ""], do: k

        if missing != [] do
          raise """
          Production database config missing.

          Set DATABASE_URL, OR set all of POSTGRES_HOST, POSTGRES_USER,
          POSTGRES_PASSWORD, POSTGRES_DB.

          Currently missing: #{Enum.join(missing, ", ")}
          DATABASE_URL: #{inspect(database_url_env)}
          POSTGRES_PORT: #{inspect(System.get_env("POSTGRES_PORT"))}

          (POSTGRES_PORT defaults to 5432, POSTGRES_POOL_SIZE to 10 — those
          are fine to default. Host/user/password/db are not.)
          """
        end

        pg_user = URI.encode_www_form(required["POSTGRES_USER"])
        pg_password = URI.encode_www_form(required["POSTGRES_PASSWORD"])
        pg_host = required["POSTGRES_HOST"]
        pg_port = System.get_env("POSTGRES_PORT", "5432")
        pg_db = required["POSTGRES_DB"]

        url = "postgres://#{pg_user}:#{pg_password}@#{pg_host}:#{pg_port}/#{pg_db}"
        # Mirror into the env so EnvProviderRegistry + any direct
        # `System.get_env("DATABASE_URL")` callers see a single value.
        System.put_env("DATABASE_URL", url)
        url
    end

  # Drive the Repo from the resolved URL so a single source of truth wins.
  #
  # SSL — RDS forces TLS. Postgrex doesn't honor `sslmode=require` in the URL
  # query string (that's a libpq convention; Postgrex's URL parser ignores it),
  # so the connection comes through unencrypted and pg_hba.conf rejects with
  # `no pg_hba.conf entry for host "<ip>", user "<u>", database "<db>", no
  # encryption`. Need explicit `:ssl, true` on the Repo config to make
  # Postgrex negotiate TLS during the startup handshake.
  #
  # `verify: :verify_none` skips CA chain validation. RDS uses Amazon root
  # CAs; we'd need to bundle the cert chain into the release (or
  # `:public_key.cacerts_load/0` from system trust) to flip this to
  # `:verify_peer`. Tracked as a separate hardening pass; for now we accept
  # transport encryption without server-identity pinning, which still beats
  # the current "fail with no encryption" state.
  #
  # Hardening followup: bundle the AWS RDS root cert chain (rds-ca-rsa2048-g1)
  # at `priv/certs/rds-ca-bundle.pem` and switch to:
  #   ssl_opts: [verify: :verify_peer, cacertfile: "/app/lib/recurse_providers-*/priv/certs/rds-ca-bundle.pem"]
  # See https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html.
  #
  # `R5E_DATABASE_SSL=false` turns TLS off for a Postgres that does not
  # speak it — the Compose quickstart's `postgres:16-alpine` on the
  # private compose network (spec 012). Default stays `true` (RDS).
  # Strict: only the literals true/false; anything else raises rather
  # than failing open to no-TLS (spec 012 S1 review).
  database_ssl? = Recurse.Gateway.Config.EnvFlags.strict_bool!("R5E_DATABASE_SSL", true)

  # Release log level (spec 012 S2 review). Elixir's Logger defaults to
  # :debug, and at :debug Ecto logs every INSERT with its parameters —
  # receipt tags, session ids — into `docker compose logs`. Default :info;
  # LOGGER_LEVEL=debug opts back in, and only then does Ecto query logging
  # come along (`log: false` otherwise). Anything else is a boot error
  # rather than a silent fallback.
  log_level =
    case env.("LOGGER_LEVEL") do
      nil ->
        :info

      level when level in ~w[debug info notice warning error critical alert emergency] ->
        String.to_atom(level)

      other ->
        raise """
        LOGGER_LEVEL must be one of debug|info|notice|warning|error|critical|alert|emergency, \
        got #{inspect(other)}.
        """
    end

  config :logger, level: log_level

  config :recurse_providers, Recurse.Providers.Repo,
    url: resolved_database_url,
    pool_size: String.to_integer(System.get_env("POSTGRES_POOL_SIZE", "10")),
    ssl: database_ssl?,
    ssl_opts: if(database_ssl?, do: [verify: :verify_none], else: []),
    log: if(log_level == :debug, do: :debug, else: false)

  # Gateway HTTP listener — start Bandit on :PORT for the audit_console
  # release. Default in `config.exs` is `start_http?: false` so `mix test`
  # doesn't bind a port; production releases must opt in. The
  # standalone_gateway compile-time config does this for the docker-compose
  # path; the audit_console release goes through runtime.exs instead.
  # NOTE: `application.ex:608` reads these as top-level keys, NOT nested
  # under `:gateway` (the moduledoc is wrong; the code is what counts).
  config :recurse_gateway,
    start_http?: env_bool.("R5E_START_HTTP", true),
    http_port: String.to_integer(port),
    http_scheme: :http,
    # `:audit_console_enabled?` gates the JwksCache + Task.Supervisor
    # children in `application.ex#jwks_cache_children/0`. Without
    # JwksCache running the LoginHandler callback crashes at
    # `JwtValidator.resolve_kid/3` with `(EXIT) no process` — every
    # WorkOS sign-in 500s. Default to true for the audit_console
    # release.
    audit_console_enabled?: audit_console_enabled?,
    # Telemetry poller drives gauge measurements (memory, process
    # count, Repo pool stats). Cheap; safe to enable in prod.
    # Default false in code (so `mix test` doesn't spawn a poller),
    # default true here so audit_console releases get observability
    # out of the box.
    telemetry_poller_enabled?: env_bool.("R5E_TELEMETRY_POLLER", true),
    telemetry_poller_period_ms: env_int.("R5E_TELEMETRY_POLLER_PERIOD_MS", "10000"),
    public_hostname: public_hostname

  # BrowserSessionPlug encrypts the OIDC-success cookie envelope with a
  # 32-byte key. SECRET_KEY_BASE is conventionally a high-entropy
  # string. Container deploys should source it from their secrets backend;
  # SHA-256 derives the 32-byte key used by the cookie envelope. Rotation
  # should happen via `:browser_session.secondary_keys` once supported.
  skb = env.("SECRET_KEY_BASE") || ""

  if byte_size(skb) < 32 do
    raise "SECRET_KEY_BASE must be at least 32 chars (got #{byte_size(skb)}). Generate with `openssl rand -hex 32`."
  end

  # `R5E_SECURE_COOKIE=false` drops the cookie's `Secure` attribute for a
  # plain-http origin (the quickstart serves http://localhost:4000; curl
  # and browsers will not send a Secure cookie over http). Default true.
  # Strict: only the literals true/false; a misspelling raises instead
  # of shipping a cookie without `Secure` (spec 012 S1 review).
  config :recurse_gateway, :browser_session,
    secret_key_base: :crypto.hash(:sha256, skb),
    secure_cookie?: Recurse.Gateway.Config.EnvFlags.strict_bool!("R5E_SECURE_COOKIE", true)
end

# ---------------------------------------------------------------------------
# Dev login (`POST /admin/test/login`) — spec 012 runtime switch.
#
# Compile-time default is `false` (config/config.exs); `config/dev.exs`
# sets it `true`. When `R5E_DEV_LOGIN_ENABLED` is set it wins for every
# env, so the Compose quickstart's prod release can mint a browser cookie
# without an IdP. Unset → compile-time value stands. The handler reads the
# Application env at request time, so this is the only switch.
# ---------------------------------------------------------------------------
case env.("R5E_DEV_LOGIN_ENABLED") do
  nil -> :ok
  value -> config :recurse_gateway, dev_login_enabled?: value == "true"
end

# ---------------------------------------------------------------------------
# 009 T028 / T073 — LLM API proxy runtime wiring.
#
# This block is evaluated for every config_env() (dev / test / prod) so an
# `iex -S mix` dev BEAM can flip the proxy on by exporting the env vars
# below. The compose stack is the supported way to run it.
#
# Default off in test (mix test relies on the legacy in-tree
# `:llm_proxy_enabled?` Application.put_env/4 stub in test_helper.exs).
# Default off in prod unless `R5E_LLM_PROXY_ENABLED=true` is set, since
# production tier configs activate the proxy explicitly per deployment.
#
# Env vars:
#   R5E_LLM_PROXY_ENABLED        — "true" to start the listener.
#   R5E_LLM_PROXY_PORT           — listener port (default 4443).
#   R5E_LLM_PROXY_SCHEME         — "http" or "https" (default "https"
#                                  whenever proxy is enabled).
#   RECURSE_GATEWAY_LLM_PROXY_CERT / RECURSE_GATEWAY_LLM_PROXY_KEY —
#       PEM paths for the TLS cert. Defaulted in `application.ex` to
#       `_build/dev/recurse-gateway-dev.{crt,key}`. Operators override
#       per deploy.
#   R5E_LLM_PROXY_DEFAULT_UPSTREAM_HOST — spec 012 D3. Upstream used when
#       the inbound Host is the gateway itself (ANTHROPIC_BASE_URL mode).
#       Default `api.anthropic.com`; `none` disables default-upstream mode
#       (pure Host-header routing).
#   R5E_LLM_PROXY_FALLBACK_UNKNOWN_HOSTS — spec 012 S2 review. "true" also
#       routes a Host with NO LlmProviderConfig row to the default upstream
#       (logged at warning per request). Default false: an unknown Host
#       answers ERR_NO_UPSTREAM_CONFIG, so a DNS-override client pointed at
#       the wrong provider cannot have its credential forwarded elsewhere.
#   R5E_LLM_PROXY_UPSTREAMS      — spec 012 S2. Comma list of preset names
#       (`anthropic`, `openai_api`) upserted as LlmProviderConfig rows
#       under R5E_TENANT_ID at boot by
#       `Recurse.Gateway.LlmProxy.UpstreamSeed`. Compose sets `anthropic`.
# ---------------------------------------------------------------------------
# Allow dev (`mix run --no-halt` / `iex -S mix`) to flip the audit-plane
# HTTP listener on too — useful for the real-Codex demo runbook
# (`curl http://localhost:4000/healthz` smoke). The :prod block above
# already wires `start_http?` from R5E_START_HTTP; this branch covers
# dev/test without polluting the prod config path.
if config_env() != :prod and env_bool.("R5E_START_HTTP", false) do
  config :recurse_gateway,
    start_http?: true,
    http_port: env_int.("PORT", "4000"),
    http_scheme: :http
end

llm_proxy_enabled? = env_bool.("R5E_LLM_PROXY_ENABLED", false)

if llm_proxy_enabled? do
  llm_proxy_port = env_int.("R5E_LLM_PROXY_PORT", "4443")

  llm_proxy_scheme =
    case env.("R5E_LLM_PROXY_SCHEME") do
      "http" -> :http
      "https" -> :https
      nil -> :https
      _ -> :https
    end

  # Spec 012 D3 — default-upstream mode. `none` opts out.
  llm_proxy_default_upstream_host =
    case env.("R5E_LLM_PROXY_DEFAULT_UPSTREAM_HOST") do
      nil -> "api.anthropic.com"
      "none" -> nil
      host -> host
    end

  # Spec 012 S2 — boot-time upstream seeding (see UpstreamSeed).
  llm_proxy_upstreams =
    (env.("R5E_LLM_PROXY_UPSTREAMS") || "")
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()

  config :recurse_gateway,
    llm_proxy_enabled?: true,
    llm_proxy_port: llm_proxy_port,
    llm_proxy_scheme: llm_proxy_scheme,
    # Falls back to the deployment tenant so proxied receipts land in the
    # same tenant the dashboard cookie is scoped to (spec 012).
    llm_proxy_default_tenant_id:
      env.("R5E_LLM_PROXY_DEFAULT_TENANT_ID") || env.("R5E_TENANT_ID") ||
        "01TEN_DEV_009_LLM_PROXY",
    llm_proxy_default_upstream_host: llm_proxy_default_upstream_host,
    llm_proxy_fallback_unknown_hosts: env_bool.("R5E_LLM_PROXY_FALLBACK_UNKNOWN_HOSTS", false),
    llm_proxy_upstreams: llm_proxy_upstreams
end

# ---------------------------------------------------------------------------
# Spec 012 S6b — detached payload retention for proxied LLM calls.
#
#   R5E_RETAIN_PAYLOADS           — "true" to keep the upstream request body
#       and the concatenated upstream response bytes (the bytes the
#       receipt's prompt_hash / response_hash cover) in the StorageProvider
#       and record their URIs on the LlmCallRecord, so an evidence export
#       can pack them and recurse-verify step 7 can check them. Default
#       false: these bytes contain prompt content and the StorageProvider
#       (S3 bucket, `cas` volume) is the operator's own store. compose sets
#       true for the quickstart.
#   R5E_RETAIN_PAYLOADS_MAX_BYTES — per-direction cap (default 8 MiB). A
#       direction that exceeds it is not stored at all and the record
#       carries payload_truncated=true (a prefix cannot be verified).
#
# The JCS predicate body behind every receipt's payload_hash is always
# retained (no prompt content; it is the receipt itself).
config :recurse_gateway,
  retain_payloads?: env_bool.("R5E_RETAIN_PAYLOADS", false),
  retain_payloads_max_bytes: env_int.("R5E_RETAIN_PAYLOADS_MAX_BYTES", "8388608")

# ---------------------------------------------------------------------------
# The fold (`apps/recurse_fold`) and its kernel (`:r5e`, a path dependency
# whose own config files are NOT loaded — every key it reads is set here or
# in config/config.exs). Spec 012 S9a. The `R5E_FOLD_*` names are the
# operator surface; each row is documented in apps/recurse_fold/README.md
# ("Configuration"), which is the one table Tally keeps for these keys.
#
#   R5E_FOLD_ENABLED            "true" starts the kernel and seeds the fold at
#                               boot (fold key, role Endorsement, eleven Kinds,
#                               default bundle, three shapes). Required in
#                               this release; unset is the same as "true", and
#                               any other value refuses startup rather than
#                               being ignored. Admission unavailability also
#                               makes readiness fail and requests refuse.
#   R5E_FOLD_DATA_DIR           the kernel's data dir: log, CAS, resource store
#                               and the node / retention / fold keys under
#                               keys/. Prod default /data/kernel (compose: the
#                               `kernel` named volume) — never a path inside
#                               a checkout, never r5e-kernel/.r5e.
#   R5E_FOLD_PORT               the kernel's own HTTP read surface (default 4546,
#                               never the kernel's 4545).
#   R5E_FOLD_START_SERVER       "true" binds that port. Prod default false: the
#                               container publishes nothing for it and the
#                               gateway's /readyz is the status surface; reads
#                               go through `bin/audit_console rpc`.
#   R5E_FOLD_CAS_MAX_BYTES      spec/05 §5 ceiling on a PUT /cas body (16 MiB).
#   R5E_FOLD_CAS_TTL_SECONDS    retention; unset = the sweeper removes nothing.
#   R5E_FOLD_COMMIT_RETRIES     spec/05 §7 re-runs of a contended admission (3).
#   R5E_FOLD_NATLANG_SPEC_PATH  the reviewed spec-010 document the nine
#                               KindDefinitions cite as derivedFrom. Prod
#                               default /app/etc/fold/spec-010.md (baked by
#                               the default Dockerfile).
#   R5E_FOLD_CARGO_LOCK_PATH    the Cargo.lock the engine build descriptor
#                               measures. Prod default /app/etc/fold/Cargo.lock
#                               (same Dockerfile).
#
# The fold key and the node key are NOT configurable: both are generated
# under R5E_FOLD_DATA_DIR/keys on first boot (`config :r5e, :signer` stays
# at its default, R5e.Signer.Local). Under mix the legacy R5E_DATA_DIR /
# R5E_PORT names are still honoured (scripts/fold-demo.sh sets them), the
# R5E_FOLD_* name winning when both are set.
fold_int = fn name, default ->
  case env.(name) do
    nil -> default
    value -> String.to_integer(value)
  end
end

# R4-F8 (RC review 2026-09-05): any value other than `true` is refused,
# case-insensitively. This used to match the literal string "false" alone,
# so `R5E_FOLD_ENABLED=0`, `no`, `off` or `FALSE` booted with admission
# **enabled** and said nothing — the operator believed they had turned the
# fold off and the release believed they had asked for it on. Only one of
# those two can be right, and a silent disagreement about the release's
# single most safety-relevant flag is the one outcome neither party wants.
# Unset stays the default (enabled); the refusal is about a value that was
# typed and not honoured.
case env.("R5E_FOLD_ENABLED") do
  nil ->
    :ok

  value ->
    unless String.downcase(String.trim(value)) == "true" do
      raise """
      R5E_FOLD_ENABLED=#{inspect(value)} is not a value this release accepts.

      Admission cannot be disabled in the governed enterprise release, so
      the only accepted value is "true" (any case). Unset the variable to
      get the same thing by default.
      """
    end
end

config :recurse_fold, enabled?: true

if config_env() == :prod do
  config :r5e,
    data_dir: env.("R5E_FOLD_DATA_DIR") || "/data/kernel",
    http_port: fold_int.("R5E_FOLD_PORT", 4546),
    start_server: env_bool.("R5E_FOLD_START_SERVER", false),
    cas_max_bytes: fold_int.("R5E_FOLD_CAS_MAX_BYTES", 16 * 1024 * 1024),
    cas_ttl_seconds: fold_int.("R5E_FOLD_CAS_TTL_SECONDS", nil),
    commit_retries: fold_int.("R5E_FOLD_COMMIT_RETRIES", 3),
    cedar_cargo_lock_path: env.("R5E_KERNEL_CARGO_LOCK_PATH") || "/app/etc/fold/kernel-Cargo.lock"

  config :recurse_fold,
    natlang_spec_path: env.("R5E_FOLD_NATLANG_SPEC_PATH") || "/app/etc/fold/spec-010.md",
    cargo_lock_path: env.("R5E_FOLD_CARGO_LOCK_PATH") || "/app/etc/fold/Cargo.lock"
else
  # Overrides apply only when set, so config/config.exs (and config/test.exs)
  # stay authoritative for an unconfigured run.
  if data_dir = env.("R5E_FOLD_DATA_DIR") || env.("R5E_DATA_DIR") do
    config :r5e, data_dir: data_dir
  end

  if r5e_port = env.("R5E_FOLD_PORT") || env.("R5E_PORT") do
    config :r5e, http_port: String.to_integer(r5e_port)
  end

  if start_server = env.("R5E_FOLD_START_SERVER") do
    config :r5e, start_server: start_server == "true"
  end

  if ttl = env.("R5E_FOLD_CAS_TTL_SECONDS") do
    config :r5e, cas_ttl_seconds: String.to_integer(ttl)
  end

  if spec_path = env.("R5E_FOLD_NATLANG_SPEC_PATH") do
    config :recurse_fold, natlang_spec_path: spec_path
  end

  if lock_path = env.("R5E_FOLD_CARGO_LOCK_PATH") do
    config :recurse_fold, cargo_lock_path: lock_path
  end
end
