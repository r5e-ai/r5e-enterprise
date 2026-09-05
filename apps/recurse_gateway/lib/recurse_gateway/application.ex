defmodule RecurseGateway.Application do
  @moduledoc """
  Gateway OTP application.

  ## Supervision tree (Phase-1 / F002 T016)

  The Gateway starts four named `Finch` HTTP-connection pools as children
  under a `:one_for_one` supervisor. Each pool is dedicated to a specific
  upstream so that slow/unhealthy peers on one pool cannot starve the
  others. Pool sizes + protocol selection are anchored in
  `specs/002-standalone-gateway-vertical-slice/research.md` D1 (KMS) and
  D3 (OpenAI SSE).

  Named pools (child id == `:name` per Finch's own supervisor spec):

    * `:openai_pool` — size 50, `protocols: [:http2, :http1]`,
      request 30s / connect 5s. OpenAI currently advertises HTTP/2 on
      `api.openai.com`; HTTP/1 is kept as a fallback for strict-proxy
      environments that downgrade. 30s request timeout covers a
      worst-case non-streaming chat completion; streaming SSE paths
      are naturally bounded by Bandit's `chunk/2` backpressure (D3).
    * `:kms_pool` — size 50, `protocols: [:http2]`,
      request 5s / connect 2s. AWS KMS speaks HTTP/2 exclusively on
      its public endpoints; per D1 we route `KMS:Sign` hot-path calls
      here to isolate from other AWS traffic. Tight timeouts — the
      Gateway's per-attestation signing budget (FR-034) is 2s total
      for 3 retries.
    * `:s3_pool` — size 25, `protocols: [:http1]`,
      request 30s / connect 5s. S3 over HTTP/1.1 avoids HTTP/2
      head-of-line-blocking on large PUTs and is the documented
      recommendation for AWS SDKs; 30s request covers typical detached
      payload uploads. Size is smaller since payload PUTs are
      fire-and-reconcile (FR-032 outbox pattern) and not on the hot
      completion path.
    * `:jwks_pool` — size 10, `protocols: [:http1]`,
      request 3s / connect 2s. JWKS documents are tiny and fetched
      rarely (cached with TTL); HTTP/1 is universal across IdP
      JWKS endpoints and the size reflects the coalesced-single-flight
      pattern in `Recurse.Gateway.Identity.JwksCache` (per T042).
    * `:imds_pool` — size 5, `protocols: [:http1]`,
      request 5s / connect 2s. EC2 IMDS and ECS task-role metadata
      endpoints only speak HTTP/1.1; this pool keeps ExAws credential
      refreshes off the HTTP/2-only KMS pool.

  ### Why Finch pools are supervised GenServers (Iron Law check)

  Finch pools wrap `NimblePool` — they hold live TCP/TLS connections
  and must fault-isolate per-pool (a crashed `:kms_pool` shouldn't
  tear down `:openai_pool`). This is a legitimate use of
  supervision: each pool has runtime state, owns OS-level resources
  (sockets), and must be restarted independently. Not a "GenServer
  for organization" anti-pattern.

  ### Why :one_for_one

  The four pools are independent: OpenAI's availability has no
  causal link to KMS or S3, and vice-versa. Using `:one_for_all`
  would unnecessarily restart healthy pools when one crashes.

  ## SIEM Forwarder (F002 T053)

  `Recurse.Gateway.Siem.Forwarder` is supervised alongside the Finch
  pools. It's a GenServer that subscribes to the
  `recurse:attestation_first_committed` PubSub topic (published by the
  `PostgresMerkleLedger` in `:recurse_providers`) and emits one NDJSON
  line per attestation to stdout, per FR-024/FR-025. `:recurse_providers`
  starts before `:recurse_gateway` in the umbrella, so `Recurse.PubSub`
  is guaranteed to be running when the forwarder subscribes.

  ## Attestation FirstCommitter (F002 T049)

  `Recurse.Gateway.Attestation.FirstCommitter` is the Gateway's
  architectural seam for first-commit events. It subscribes to the
  same `recurse:attestation_first_committed` topic independently of
  the SIEM forwarder — the two observers are orthogonal so neither can
  starve or accidentally couple to the other. Today it emits a
  `[:recurse, :attestation, :first_committed]` telemetry event + keeps
  an observed counter; future first-commit hooks (audit-broker cache
  invalidation, metrics, webhooks) land here without touching the
  SIEM path.

  ## HTTP surface (F002 T050)

  `Recurse.Gateway.Router` is wrapped in a Bandit child when
  `config :recurse_gateway, :gateway, start_http?: true`. Mirrors the
  pattern in `RecurseBroker.Application`: the umbrella default in
  `config/config.exs` is `false`, so `mix test` doesn't bind the port.
  `config/standalone_gateway.exs` flips it on for the production
  tier.

  `port` and `scheme` are overridable via the same key
  (`config :recurse_gateway, :gateway, port: 4000, scheme: :http`).

  ## Oban supervisor (F004 T044)

  `Oban` is added as the LAST child so every dependency it touches —
  the `Recurse.Providers.Repo` (in the sibling `:recurse_providers` app
  which boots before this app per the umbrella ordering) and the
  `Recurse.PubSub` registry it uses for inter-process notification — is
  already alive. Oban itself is gated behind
  `:oban_enabled?` so the test suite can opt out (we don't want the
  cron sweeps firing during `mix test`; the dedicated Oban tests for
  T045-T047 use `Oban.Testing` inline mode instead).

  Queue config lives in `config/config.exs` under
  `config :recurse_gateway, Oban, ...` per F002 convention (queue
  topology is a deployment knob, not a runtime decision). The Cron
  schedule, however, is assembled at boot in `oban_cron_crontab/0`
  rather than statically in config — Oban's Cron plugin resolves every
  worker module at supervisor init and entries pointing to modules
  that haven't compiled yet (Phase-7 suggestion runners; W2-A
  NoncePurger) would refuse the spec. The boot-time filter via
  `Code.ensure_loaded?` lets Phase 2 boot cleanly with just the three
  retention purgers, with later phases picking up their entries
  automatically as worker modules land.
  """

  use Application

  @impl true
  def start(_type, _args) do
    # Dogfood-deploy GAN-fix #6 — fail loudly at boot when the browser
    # OIDC provider is misconfigured. Silent fall-through to the broker
    # path on an unknown provider value is worse than a hard early
    # signal: the operator who set `BROWSER_OIDC_PROVIDER=worksos`
    # (typo) would have a working broker-path login screen until the
    # auditor failed to recognize it. Crash here instead.
    :ok = validate_browser_oidc_provider!()

    # MR !119 prep: pre-flight the (optional) policy-provider env-var
    # shorthand so a typo (e.g. `R5E_PROVIDER_POLICY_IMPL=ocii`) crashes
    # at boot instead of silently falling through to whichever bundle
    # loader is wired in the supervision tree. Returns nil when the env
    # var is unset; raises on unknown shorthand.
    _ = Recurse.Gateway.Config.EnvProviderRegistry.validate_policy_impl!()

    # Env-driven provider bootstrap. Each provider role's impl is
    # selected by `R5E_PROVIDER_<ROLE>_IMPL`; per-impl config still
    # comes from impl-specific env vars (`POSTGRES_*`, `OPENAI_API_KEY`,
    # `KMS_KEY_ID`, `CAS_BUCKET`, ...).
    #
    # Install runs as a supervised GenServer child positioned AFTER
    # `finch_pool_children()` and BEFORE provider-consuming workers (see
    # `env_provider_installer_children/0` + the children-list assembly
    # below). The supervisor blocks on the installer's `init/1` until
    # install completes, preserving the "install before workers"
    # contract this MUST be sync-against. The pre-supervisor inline call
    # didn't work once provider impls started doing eager Finch I/O at
    # init (e.g. `AwsKmsSecretsProvider` IMDS+KMS validation): Finch
    # pools are themselves children of the same supervisor, so the
    # inline call couldn't satisfy that dep and crashed the pod with
    # `ArgumentError: unknown registry: :imds_pool`. See
    # `Recurse.Gateway.Boot.EnvProviderInstaller` @moduledoc for the
    # full rationale.
    #
    # Gated on `:audit_console_enabled?` AND a presence check for
    # `R5E_PROVIDER_LEDGER_IMPL` so the test suite + integration suites
    # that build `ProviderRegistry` directly via `install_raw!/1` are
    # not forced through the env path.

    # MCP Trusted Registry vertical slice — load + cache the static
    # registry catalog at boot. Pure persistent_term cache (no GenServer),
    # raises if the priv file is missing or malformed (the file ships in
    # the artifact, so absence is a build problem). Same boot-load pattern
    # as `WellKnownManifest` + `SchemaPublication`.
    :ok = Recurse.Gateway.McpRegistry.Loader.assert_event_kind_registered!()
    :ok = Recurse.Gateway.McpRegistry.Loader.load!()

    children =
      finch_pool_children() ++
        rate_limit_children() ++
        env_provider_installer_children() ++
        [
          # Prometheus metrics registry (F002 T091). Must boot BEFORE the
          # HTTP endpoint so `/metrics` never serves an empty registry.
          # See `Recurse.Gateway.Observability.MetricsRegistry` for why
          # we embed the `Core` reporter rather than the full
          # `telemetry_metrics_prometheus` exporter.
          Recurse.Gateway.Observability.MetricsRegistry,
          Recurse.Gateway.Siem.Forwarder,
          Recurse.Gateway.Attestation.FirstCommitter,
          # F7 MCP Registry mutator — serializes operator-driven trust_tier
          # mutations (`PATCH /v1/mcp/registry/:id`). Reads still go through
          # `Loader` against `:persistent_term`; only the write side is
          # serialized through this GenServer. Same shape as
          # `Recurse.Gateway.Policy.BundleLoader` (write-side singleton +
          # lock-free reads).
          Recurse.Gateway.McpRegistry.Mutator
        ] ++
        jwks_cache_children() ++
        policy_bundle_loader_children() ++
        oci_bundle_manager_children() ++
        telemetry_poller_children() ++
        outbox_reconciler_children() ++
        http_endpoint_children() ++
        llm_proxy_endpoint_children() ++
        oban_children()

    opts = [strategy: :one_for_one, name: RecurseGateway.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Dogfood-deploy GAN-fix #6 — validate the browser-OIDC provider
  # config at boot. Two failure modes both crash the supervisor before
  # any child starts (silent later failures are worse than a hard
  # early signal):
  #
  #   * Unknown provider value (anything other than `"workos"` |
  #     `"broker"` | `"oidc"`). Silent fall-through to broker defaults
  #     would mask typos like `BROWSER_OIDC_PROVIDER=worksos`.
  #   * `provider == "workos"` AND any required WorkOS env var
  #     (`WORKOS_CLIENT_ID` / `WORKOS_API_KEY`) is unset. Without these
  #     the WorkOS adapter cannot complete a sign-in and the gateway
  #     would 500 on the first auditor login.
  #
  # Audit-console-gated: only enforced when `:audit_console_enabled?`
  # is on; tests + non-console deployments pass through.
  @spec validate_browser_oidc_provider!() :: :ok
  def validate_browser_oidc_provider! do
    if Application.get_env(:recurse_gateway, :audit_console_enabled?, false) do
      do_validate_browser_oidc_provider!()
    else
      :ok
    end
  end

  defp do_validate_browser_oidc_provider! do
    idp_config = Application.get_env(:recurse_gateway, :browser_oidc_idp, [])
    provider = Keyword.get(idp_config, :provider, "workos")

    cond do
      provider not in ["workos", "broker", "oidc"] ->
        raise """
        Audit console is enabled with an unknown browser-OIDC provider.
        BROWSER_OIDC_PROVIDER=#{inspect(provider)} (acceptable values: "workos" | "broker" | "oidc").

        Silent fall-through to broker defaults would mask a typo —
        fix the env var or disable the audit console.
        """

      provider == "workos" ->
        validate_workos_required_env!()
        validate_internal_jwt_required_env!()

      true ->
        :ok
    end
  end

  defp validate_workos_required_env! do
    workos_config = Application.get_env(:recurse_gateway, :workos, [])

    missing =
      Enum.filter([:client_id, :api_key], fn key ->
        v = Keyword.get(workos_config, key)
        is_nil(v) or v == ""
      end)

    if missing == [] do
      :ok
    else
      raise """
      Audit console is enabled and configured for WorkOS browser-OIDC,
      but required env var(s) are unset: #{inspect(missing)}
      (`WORKOS_CLIENT_ID` / `WORKOS_API_KEY`).

      Without these the WorkOS adapter cannot complete a sign-in.
      Set them in the environment, or disable the audit console with
      `config :recurse_gateway, :audit_console_enabled?, false`.
      """
    end
  end

  # GAN round-2 finding #3: WorkOS path mints a broker-shaped internal
  # JWT to satisfy F002's IdentityContextBuilder contract. Minting needs
  # an ES256 signing key (typically the broker's, mounted via
  # `BROKER_JWT_SIGNING_KEY_PATH`) + an audience.
  #
  # Without these, every WorkOS sign-in attempt 403s with `jwt_mint_failed`
  # AT REQUEST TIME — which is exactly the silent-fail class round-1
  # finding #6 was meant to prevent. Crash at boot instead.
  defp validate_internal_jwt_required_env! do
    internal_jwt_config = Application.get_env(:recurse_gateway, :internal_jwt, [])

    signing_key_path = Keyword.get(internal_jwt_config, :signing_key_path)

    validate_internal_jwt_signing_key_path!(signing_key_path)
    validate_internal_jwt_audience!(Keyword.get(internal_jwt_config, :audience))
    validate_internal_jwt_issuer!(Keyword.get(internal_jwt_config, :issuer))
    validate_internal_jwt_ttl!(Keyword.get(internal_jwt_config, :ttl_seconds))
  end

  defp validate_internal_jwt_signing_key_path!(signing_key_path) do
    cond do
      is_nil(signing_key_path) or signing_key_path == "" ->
        raise """
        Audit console is enabled and configured for WorkOS browser-OIDC,
        but `:internal_jwt.signing_key_path` is unset
        (`BROKER_JWT_SIGNING_KEY_PATH` env).

        The WorkOS adapter mints a broker-shaped internal JWT for the
        cookie envelope so F002's IdentityContextBuilder accepts the
        session. Without the signing key, every WorkOS sign-in 403s
        with `jwt_mint_failed`.

        Mount the broker's ES256 PEM at the path the env var points at.
        """

      not File.regular?(signing_key_path) ->
        raise """
        Audit console is enabled and configured for WorkOS browser-OIDC,
        but `:internal_jwt.signing_key_path` (#{inspect(signing_key_path)})
        is NOT a regular file (does not exist or is a special device).

        Verify the file exists and is mounted into the container.
        """

      # GAN round-3 finding #1 (codex blocker, gemini corroborated):
      # `File.regular?/1` doesn't check read permission. A `chmod 000`
      # PEM passes the file-type check, then `load_signing_key/1`
      # raises at first sign-in. Catch the readability gap at boot
      # so misconfigurations fail loud + early.
      match?({:error, _}, File.read(signing_key_path)) ->
        {:error, reason} = File.read(signing_key_path)

        raise """
        Audit console is enabled and configured for WorkOS browser-OIDC,
        but `:internal_jwt.signing_key_path` (#{inspect(signing_key_path)})
        is NOT readable (File.read/1 returned #{inspect(reason)}).

        The gateway runtime user needs read permission on this file.
        Check ownership/mode (`chmod 0400 path && chown gateway-user path`)
        or the volume-mount config in the deploy spec.
        """

      true ->
        :ok
    end
  end

  defp validate_internal_jwt_audience!(audience) do
    if is_nil(audience) or audience == "" do
      raise """
      Audit console is enabled and configured for WorkOS browser-OIDC,
      but `:internal_jwt.audience` is unset (`BROKER_JWT_AUDIENCE` env).

      The minted internal JWT's `aud` claim must match what F002's
      `JwtValidator` expects. In runtime.exs this is derived from
      `R5E_PUBLIC_HOSTNAME` or `WORKOS_REDIRECT_URI`; set one of those.
      """
    end
  end

  # GAN round-3 finding #3 (claude+gemini convergent):
  # `:internal_jwt.issuer` was checked at request time only —
  # asymmetric with the other prerequisites. Catch at boot.
  defp validate_internal_jwt_issuer!(issuer) do
    if is_nil(issuer) or issuer == "" do
      raise """
      Audit console is enabled and configured for WorkOS browser-OIDC,
      but `:internal_jwt.issuer` is unset (`INTERNAL_JWT_ISSUER` env).

      The minted internal JWT's `iss` claim identifies this Recurse
      gateway as the JWT-mint authority. Set `INTERNAL_JWT_ISSUER`
      (typically `https://gateway.<your-domain>/internal`).
      """
    end
  end

  defp validate_internal_jwt_ttl!(nil), do: :ok

  # GAN round-3 finding #3: TTL clamp was enforced lazily at
  # request time via `Workos.parse_ttl/1`. Run it at boot too so
  # an out-of-range `INTERNAL_JWT_TTL_SECONDS` crashes the
  # supervisor instead of every sign-in attempt.
  defp validate_internal_jwt_ttl!(ttl_seconds) do
    Recurse.Gateway.Admin.BrowserAuth.Workos.parse_ttl(ttl_seconds)
    :ok
  rescue
    e in ArgumentError ->
      reraise RuntimeError.exception("""
              Audit console is enabled and configured for WorkOS browser-OIDC,
              but `:internal_jwt.ttl_seconds` is out of bounds.

              #{Exception.message(e)}

              Set `INTERNAL_JWT_TTL_SECONDS` to an integer in the documented range.
              """),
              __STACKTRACE__
  end

  # Env-driven provider bootstrap. Reads the OS environment, builds the
  # ProviderRegistry install_map, calls `install!/1`. Plain function
  # call, NOT a supervised child — this is one-shot config wiring at
  # boot, not runtime state.
  #
  # Gated on `:audit_console_enabled?` AND a presence check for
  # `R5E_PROVIDER_LEDGER_IMPL` so the test suite + integration suites
  # that build `ProviderRegistry` directly via `install_raw!/1` are not
  # forced through the env path. Once every deploy path has flipped
  # over, this gate can be tightened to "always when
  # audit_console_enabled?".
  # Returns the EnvProviderInstaller child spec when both gates pass,
  # otherwise an empty list. Called from the children-list assembly in
  # `start/2` so the installer is positioned AFTER `finch_pool_children()`
  # (so Finch pools are up before any provider impl's `init/1` does
  # eager I/O via Finch — see `Recurse.Gateway.Boot.EnvProviderInstaller`
  # @moduledoc) and BEFORE provider-consuming workers (so the supervisor
  # blocks on the installer's `init/1` returning before later workers
  # start).
  @spec env_provider_installer_children() :: [Supervisor.child_spec() | module()]
  defp env_provider_installer_children do
    audit_console_enabled? = Application.get_env(:recurse_gateway, :audit_console_enabled?, false)

    if audit_console_enabled? and provider_env_present?() do
      [Recurse.Gateway.Boot.EnvProviderInstaller]
    else
      []
    end
  end

  # Cheap presence check used by the gate above. Operators flip over to
  # the env-driven path by setting `R5E_PROVIDER_LEDGER_IMPL` (the
  # canonical sentinel — every audit-console deploy needs a ledger).
  @spec provider_env_present?() :: boolean()
  defp provider_env_present? do
    case System.get_env("R5E_PROVIDER_LEDGER_IMPL") do
      value when is_binary(value) and value != "" -> true
      _ -> false
    end
  end

  # F002 T091 — `:telemetry_poller` drives gauge-shaped measurements
  # (e.g. `recurse.outbox.depth`) that aren't event-emitted by the hot
  # path. Default period is 10s; overridable via
  # `:telemetry_poller_period_ms`. Gated behind `:telemetry_poller_enabled?`
  # (off in tests by default — the poller calls into Ecto which the
  # sandbox can't service from a non-test process).
  @spec telemetry_poller_children() :: [Supervisor.child_spec() | {module(), keyword()}]
  defp telemetry_poller_children do
    if Application.get_env(:recurse_gateway, :telemetry_poller_enabled?, false) do
      period = Application.get_env(:recurse_gateway, :telemetry_poller_period_ms, 10_000)

      [
        {:telemetry_poller,
         measurements: Recurse.Gateway.Observability.Metrics.poller_measurements(),
         period: period,
         name: Recurse.Gateway.Observability.Poller}
      ]
    else
      []
    end
  end

  # F002 T092 — Hammer 7 ETS-backed rate-limit backend. Gated by
  # `:rate_limit_enabled?` so the test suite doesn't pay for the child.
  # Prod + the integration suites that exercise the limiter opt in via
  # config.
  @spec rate_limit_children() :: [Supervisor.child_spec() | {module(), keyword()}]
  defp rate_limit_children do
    if Application.get_env(:recurse_gateway, :rate_limit_enabled?, false) do
      [Recurse.Gateway.RateLimit.Backend]
    else
      []
    end
  end

  # F002 T090 — Outbox Reconciler. Gated because the hot-path does not
  # enqueue outbox rows yet and most tests don't need a polling process.
  @spec outbox_reconciler_children() :: [Supervisor.child_spec() | {module(), keyword()}]
  defp outbox_reconciler_children do
    if Application.get_env(:recurse_gateway, :outbox_reconciler_enabled?, false) do
      opts = Application.get_env(:recurse_gateway, :outbox_reconciler, [])
      [{Recurse.Gateway.Storage.OutboxReconciler, opts}]
    else
      []
    end
  end

  defp finch_pool_children do
    [
      {Finch,
       name: :openai_pool,
       pools: %{
         :default => [
           size: 50,
           protocols: [:http2, :http1],
           conn_opts: [transport_opts: [timeout: 5_000]]
         ]
       }},
      {Finch,
       name: :kms_pool,
       pools: %{
         :default => [
           size: 50,
           # AWS KMS does NOT advertise HTTP/2 via ALPN — verified
           # 2026-04-27 with `openssl s_client -alpn h2 -connect
           # kms.us-west-2.amazonaws.com:443` returning "No ALPN
           # negotiated". The original `[:http2]`-only pool caused
           # `Finch.Error{reason: :disconnected}` on every KMS call,
           # which crashed `AwsKmsSecretsProvider.init/1` at boot.
           # `[:http1, :http2]` ALSO failed — Finch sends ALPN with
           # both h2+http/1.1 advertised; KMS doesn't pick anything
           # ("No ALPN negotiated") and Mint disconnects. Only
           # `[:http1]` (matching `:s3_pool`) consistently works,
           # because it sends no ALPN at all.
           protocols: [:http1],
           conn_opts: [transport_opts: [timeout: 2_000]]
         ]
       }},
      {Finch,
       name: :s3_pool,
       pools: %{
         :default => [
           size: 25,
           protocols: [:http1],
           conn_opts: [transport_opts: [timeout: 5_000]]
         ]
       }},
      {Finch,
       name: :jwks_pool,
       pools: %{
         :default => [
           size: 10,
           protocols: [:http1],
           conn_opts: [transport_opts: [timeout: 2_000]]
         ]
       }},
      {Finch,
       name: :imds_pool,
       pools: %{
         :default => [
           size: 5,
           protocols: [:http1],
           conn_opts: [transport_opts: [timeout: 2_000]]
         ]
       }}
    ]
  end

  # JwksCache + Task.Supervisor for the audit-console browser-flow IdP
  # (dogfood deploy: WorkOS). Gated by `:audit_console_enabled?` AND a
  # configured WorkOS provider. The cache holds RS256 verification keys
  # for the IdP's access_tokens; without it the
  # `LoginHandler.default_id_token_validator/2` (or the WorkOS adapter's
  # `default_validator/2`) cannot resolve `kid` → JWK and every browser
  # sign-in fails closed at the validator step.
  #
  # **Fail-closed behaviour**: when audit console is enabled AND
  # `:browser_oidc_idp.provider == "workos"` AND `WORKOS_CLIENT_ID` is
  # unset, `start/2` raises at boot rather than silently skipping the
  # cache child. The misconfigured deploy never accepts a sign-in.
  #
  # The Task.Supervisor child (`Recurse.Gateway.Identity.JwksCache.TaskSupervisor`)
  # is started UNCONDITIONALLY alongside the cache because
  # `JwksCache.async_nolink/2` calls would otherwise crash with
  # `:noproc`. We pin its name so the cache's `:task_supervisor` opt
  # resolves to a stable atom.
  @spec jwks_cache_children() :: [Supervisor.child_spec() | {module(), keyword()}]
  defp jwks_cache_children do
    if Application.get_env(:recurse_gateway, :audit_console_enabled?, false) do
      idp_config = Application.get_env(:recurse_gateway, :browser_oidc_idp, [])
      provider = Keyword.get(idp_config, :provider, "workos")

      idp_issuers = build_jwks_cache_issuers(provider, idp_config)
      broker_issuers = broker_jwks_cache_issuer()
      issuers = idp_issuers ++ broker_issuers

      [
        {Task.Supervisor, name: Recurse.Gateway.Identity.JwksCache.TaskSupervisor},
        {Recurse.Gateway.Identity.JwksCache,
         issuers: issuers,
         finch_pool: :jwks_pool,
         task_supervisor: Recurse.Gateway.Identity.JwksCache.TaskSupervisor,
         name: Recurse.Gateway.Identity.JwksCache}
      ]
    else
      []
    end
  end

  # Cedar policy BundleLoader (filesystem source) — gated on
  # `:audit_console_enabled?` (every audit-plane handler reads via
  # `Recurse.Gateway.Policy.Active.current/0` which the BundleLoader
  # populates on successful boot; reads return `:not_loaded` until
  # this child has finished its boot-time bundle parse).
  # Skipped when bundle paths are unset so non-audit-console deploys
  # don't crash on a missing bundle. (Issue #23.)
  @spec policy_bundle_loader_children() :: [Supervisor.child_spec() | {module(), keyword()}]
  defp policy_bundle_loader_children do
    if Application.get_env(:recurse_gateway, :audit_console_enabled?, false) do
      cfg = Application.get_env(:recurse_gateway, :policy_bundle, [])
      bundle_path = Keyword.get(cfg, :bundle_path)
      schema_path = Keyword.get(cfg, :entity_schema_path)

      cond do
        is_nil(bundle_path) or bundle_path == "" ->
          []

        is_nil(schema_path) or schema_path == "" ->
          []

        true ->
          [
            {Recurse.Gateway.Policy.BundleLoader,
             bundle_path: bundle_path,
             entity_schema_path: schema_path,
             trap_sighup: true,
             poll_ms: Keyword.get(cfg, :poll_ms, 0),
             name: Recurse.Gateway.Policy.BundleLoader}
          ]
      end
    else
      []
    end
  end

  # OCI-backed Cedar bundle manager — alternative to the BundleLoader
  # filesystem path above. Started ONLY when the env-driven provider
  # registry resolved policy provider impl to OciPolicyProvider AND the
  # required env vars (R5E_CEDAR_BUNDLE_REGISTRY/REPOSITORY/REF +
  # R5E_CEDAR_COSIGN_KEY_ARN + R5E_CEDAR_BUNDLE_AUTH) are present.
  # Boot is fail-closed: if config_from_env! raises, the supervisor
  # crash propagates and the BEAM exits before serving traffic.
  # Cedar bundles for the audit-dev / audit-demo / customer
  # deployment shapes flow through this manager exclusively post-cutover;
  # BundleLoader stays for tests + the air-gapped tier.
  @spec oci_bundle_manager_children() :: [Supervisor.child_spec() | {module(), keyword()}]
  defp oci_bundle_manager_children do
    if Application.get_env(:recurse_gateway, :audit_console_enabled?, false) and
         oci_policy_provider_selected?() do
      case System.get_env("R5E_CEDAR_BUNDLE_REGISTRY") do
        nil ->
          []

        "" ->
          []

        _ ->
          [
            {Recurse.Gateway.Policy.OciBundleManager,
             Recurse.Gateway.Policy.OciBundleManager.config_from_env!()}
          ]
      end
    else
      []
    end
  end

  defp oci_policy_provider_selected? do
    System.get_env("R5E_PROVIDER_POLICY_IMPL") == "oci"
  end

  # Register the BROKER's own issuer + JWKS URL in the cache so JWTs we
  # mint in-process (WorkOS path) validate on subsequent requests. Without
  # this, `JwksCache.fetch_jwk(broker_issuer, _)` returns
  # `{:error, :unknown_issuer}` and `JwtValidator` reports `unknown_kid`
  # for every cookie-authed audit-plane request. (Issue #19.)
  #
  # Skipped when either the broker-issuer or broker-jwks-url is unset.
  # That's the F002-only / no-internal-mint posture; no JWTs are minted
  # in-process so no broker issuer needs registering.
  @spec broker_jwks_cache_issuer() :: [map()]
  defp broker_jwks_cache_issuer do
    internal = Application.get_env(:recurse_gateway, :internal_jwt, [])
    issuer_url = Keyword.get(internal, :issuer)
    jwks_url = Application.get_env(:recurse_gateway, :broker_jwks_url)

    cond do
      is_nil(issuer_url) or issuer_url == "" -> []
      is_nil(jwks_url) or jwks_url == "" -> []
      true -> [%{issuer_url: issuer_url, jwks_url: jwks_url, ttl_seconds: 300}]
    end
  end

  # Build the JwksCache `:issuers` list for the configured browser-OIDC
  # provider. WorkOS = single issuer (the WorkOS API base) with
  # client-scoped JWKS URL. Other providers (Okta / generic OIDC) read
  # `:issuer_url` + `:jwks_url` directly from `:browser_oidc_idp` config.
  defp build_jwks_cache_issuers("workos", _idp_config) do
    workos_config = Application.get_env(:recurse_gateway, :workos, [])
    client_id = Keyword.get(workos_config, :client_id)
    api_base = Keyword.get(workos_config, :api_base, "https://api.workos.com")

    if is_nil(client_id) or client_id == "" do
      raise """
      Audit console is enabled and configured for WorkOS browser-OIDC,
      but `WORKOS_CLIENT_ID` is unset. The JwksCache cannot resolve the
      WorkOS access_token signing keys without the client ID
      (`https://api.workos.com/sso/jwks/{WORKOS_CLIENT_ID}` returns 404
      without the path segment).

      Set `WORKOS_CLIENT_ID` in the environment, or disable the audit
      console with `config :recurse_gateway, :audit_console_enabled?, false`.
      """
    end

    base = String.trim_trailing(api_base, "/")
    jwks_url = base <> "/sso/jwks/" <> client_id

    # WorkOS uses TWO different `iss` claims depending on token type:
    #   * access_token issuer = api_base (e.g., `https://api.workos.com`)
    #   * id_token issuer     = api_base + "/user_management/" + client_id
    # Both share the same JWKS URL. Register both so JwtValidator can
    # resolve the id_token's `iss` claim during the OIDC callback.
    [
      %{issuer_url: base, jwks_url: jwks_url, ttl_seconds: 300},
      %{
        issuer_url: base <> "/user_management/" <> client_id,
        jwks_url: jwks_url,
        ttl_seconds: 300
      }
    ]
  end

  # Generic OIDC provider — read `:issuer_url` + `:jwks_url` from
  # `:browser_oidc_idp` config. Used by deployments that wire Okta /
  # Auth0 / Keycloak directly (no WorkOS-specific discovery).
  defp build_jwks_cache_issuers(_other_provider, idp_config) do
    issuer_url = Keyword.get(idp_config, :issuer_url)
    jwks_url = Keyword.get(idp_config, :jwks_url)

    if is_nil(issuer_url) or is_nil(jwks_url) do
      raise """
      Audit console is enabled with a non-WorkOS browser-OIDC provider
      but `:browser_oidc_idp.issuer_url` or `:browser_oidc_idp.jwks_url`
      is unset. Cannot start the JwksCache.
      """
    end

    [
      %{
        issuer_url: issuer_url,
        jwks_url: jwks_url,
        ttl_seconds: Keyword.get(idp_config, :ttl_seconds, 300)
      }
    ]
  end

  # F004 T044 — Oban supervisor child spec. Gated behind `:oban_enabled?`
  # so `mix test` doesn't spin up the cron sweeps (the dedicated worker
  # tests use `Oban.Testing` inline mode).
  #
  # Iron-Law check (`elixir:otp-thinking`): Oban itself is a supervisor
  # owning queue producers + a cron plugin process — it MUST be a
  # supervised child to fault-isolate from sibling processes (a runaway
  # job should not topple the Gateway router). Not the "GenServer for
  # organization" anti-pattern. `:one_for_one` (the parent strategy) is
  # correct: Oban's failure should not cascade to Finch pools or the
  # SIEM forwarder.
  #
  # Cron-table assembly happens here at boot (not in `config/config.exs`)
  # because Oban's Cron plugin resolves every worker module at init time —
  # entries with worker modules that haven't compiled yet (Phase 7
  # heuristic/LLM runners; W2-A NoncePurger) would refuse the supervisor
  # spec. We include each entry conditionally via `Code.ensure_loaded?`
  # so Phase-2 boots cleanly with just the three retention purgers, and
  # later phases pick up their entries automatically as the worker
  # modules land.
  @spec oban_children() :: [Supervisor.child_spec() | {module(), keyword()}]
  defp oban_children do
    if Application.get_env(:recurse_gateway, :oban_enabled?, false) do
      base = Application.fetch_env!(:recurse_gateway, Oban)
      cron_plugin = {Oban.Plugins.Cron, crontab: oban_cron_crontab()}
      plugins = Keyword.get(base, :plugins, []) ++ [cron_plugin]
      [{Oban, Keyword.put(base, :plugins, plugins)}]
    else
      []
    end
  end

  # Cron schedule — the F004 T044 + T048 reservation table. Each entry is
  # included only when its worker module is callable in the running BEAM
  # (the `perform/1` Oban.Worker callback exists on the module). Entries:
  #
  #   * `*/5 * * * *` — `Recurse.Gateway.Admin.BrowserAuth.NoncePurger` (W2-A T038).
  #     5-minute OIDC-nonce TTL sweep; matches the 1-hour post-`expires_at`
  #     retention in `oidc_login_nonces`.
  #   * `0 3 * * *` — `RetentionPurger.PolicyDrafts` (T045). Daily 03:00 UTC;
  #     overridable via the `console.retention.purge_schedule_cron` tier-config
  #     key per `contracts/retention_lifecycle.md`.
  #   * `0 3 * * *` — `RetentionPurger.PolicySuggestions` (T046). Daily 03:00 UTC;
  #     interleaves with PolicyDrafts on the single-concurrency `:retention`
  #     queue.
  #   * `0 3 * * *` — `RetentionPurger.ChatHistory` (T047). Daily 03:00 UTC;
  #     same queue.
  #   * `0 * * * *` — `Recurse.Gateway.SuggestionEngine.HeuristicRunner` (T048
  #     reservation; impl in T131). Hourly per FR-030.
  #   * `0 2 * * *` — `Recurse.Gateway.SuggestionEngine.LlmRunner` (T048
  #     reservation; impl in T133). Daily 02:00 UTC so it finishes before
  #     the 03:00 retention sweeps.
  #
  # `Code.ensure_loaded?/1` attempts to load the module and returns
  # `false` if the `.beam` file doesn't exist on the code path — perfect
  # for filtering cron entries whose worker module hasn't compiled yet
  # (Phase-7 / W2-A forward references). Unlike `function_exported?/3`,
  # which would silently miss not-yet-loaded modules even when their
  # `.beam` files ARE present, `Code.ensure_loaded?` actively triggers
  # the loader.
  @spec oban_cron_crontab() :: [{String.t(), module()}]
  defp oban_cron_crontab do
    candidates = [
      {"*/5 * * * *", Recurse.Gateway.Admin.BrowserAuth.NoncePurger},
      {"0 3 * * *", Recurse.Gateway.SuggestionEngine.RetentionPurger.PolicyDrafts},
      {"0 3 * * *", Recurse.Gateway.SuggestionEngine.RetentionPurger.PolicySuggestions},
      {"0 3 * * *", Recurse.Gateway.SuggestionEngine.RetentionPurger.ChatHistory},
      {"0 * * * *", Recurse.Gateway.SuggestionEngine.HeuristicRunner}
    ]

    Enum.filter(candidates, fn {_cron, worker} -> Code.ensure_loaded?(worker) end)
  end

  defp http_endpoint_children do
    if Application.get_env(:recurse_gateway, :start_http?, false) do
      port = Application.get_env(:recurse_gateway, :http_port, 4000)
      scheme = Application.get_env(:recurse_gateway, :http_scheme, :http)

      [
        Supervisor.child_spec(
          {Bandit, plug: Recurse.Gateway.Router, port: port, scheme: scheme},
          id: Recurse.Gateway.Router
        )
      ]
    else
      []
    end
  end

  # 009 T028 — LLM API proxy endpoint. Sibling Bandit child on a
  # separate port so the public-facing audit-plane router (4000) is
  # untouched. The customer's DNS override routes the LLM hostnames
  # (chatgpt.com, auth.openai.com, api.openai.com, ...) to the
  # gateway's IP; this listener owns those connections. Default port
  # 4443 (operator overridable). Disabled by default — flip on per
  # deployment via `:llm_proxy_enabled?`.
  #
  # The two-endpoint shape rather than a forward-merged single router
  # is intentional: the LLM proxy MUST NOT plug Plug.Parsers (it
  # forwards request bodies verbatim), but the audit-plane router
  # depends on Plug.Parsers having pre-decoded JSON. Mixing them in
  # one router would either break the audit plane (skipping parsers)
  # or break the proxy (consuming the body before forwarding).
  @spec llm_proxy_endpoint_children() :: [Supervisor.child_spec() | {module(), keyword()}]
  defp llm_proxy_endpoint_children do
    if Application.get_env(:recurse_gateway, :llm_proxy_enabled?, false) do
      port = Application.get_env(:recurse_gateway, :llm_proxy_port, 4443)
      scheme = Application.get_env(:recurse_gateway, :llm_proxy_scheme, :http)

      bandit_opts =
        [plug: Recurse.Gateway.LlmProxy.ProxyRouter, port: port, scheme: scheme]
        |> Keyword.merge(llm_proxy_tls_opts(scheme))

      # Spec 012 S2 — seed the upstream rows named in
      # `R5E_LLM_PROXY_UPSTREAMS` BEFORE the listener accepts its first
      # request. `UpstreamSeed.start_link/1` runs synchronously and returns
      # `:ignore`, so the supervisor blocks on it and leaves no process.
      upstream_seed_children() ++
        [
          # The Cedar tool-use decision cache (009 T042) is gone with the
          # evaluator it cached: there is one Cedar answer per act and it
          # is the kernel's, recorded, never cached (RC review 2026-09-05).
          Supervisor.child_spec(
            {Bandit, bandit_opts},
            id: Recurse.Gateway.LlmProxy.ProxyRouter
          )
        ]
    else
      []
    end
  end

  @spec upstream_seed_children() :: [Supervisor.child_spec() | module()]
  defp upstream_seed_children do
    case Application.get_env(:recurse_gateway, :llm_proxy_upstreams, []) do
      [_ | _] -> [Recurse.Gateway.LlmProxy.UpstreamSeed]
      _ -> []
    end
  end

  # 009 T073 — TLS termination for the LLM-proxy listener. When the
  # operator flips scheme=:https, Bandit needs `certfile` + `keyfile`
  # paths. Resolved in this priority order:
  #
  #   1. `:llm_proxy_certfile` / `:llm_proxy_keyfile` Application config
  #      (compile-time `config/*.exs` or runtime.exs).
  #   2. `RECURSE_GATEWAY_LLM_PROXY_CERT` / `RECURSE_GATEWAY_LLM_PROXY_KEY`
  #      env vars (operator overrides).
  #   3. Defaults: `_build/dev/recurse-gateway-dev.{crt,key}` — a
  #      self-signed cert for chatgpt.com / auth.openai.com /
  #      api.openai.com, which the dev loop generates. Nothing generates
  #      it for you here; the compose stack terminates TLS itself.
  #
  # If scheme=:http we return [] (plain HTTP listener; tests + non-TLS
  # mock-upstream rigs).
  @spec llm_proxy_tls_opts(:http | :https) :: keyword()
  defp llm_proxy_tls_opts(:https) do
    cert =
      Application.get_env(:recurse_gateway, :llm_proxy_certfile) ||
        System.get_env("RECURSE_GATEWAY_LLM_PROXY_CERT") ||
        Path.expand("_build/dev/recurse-gateway-dev.crt", File.cwd!())

    key =
      Application.get_env(:recurse_gateway, :llm_proxy_keyfile) ||
        System.get_env("RECURSE_GATEWAY_LLM_PROXY_KEY") ||
        Path.expand("_build/dev/recurse-gateway-dev.key", File.cwd!())

    [
      certfile: cert,
      keyfile: key,
      # Permissive cipher list for dev — Bandit defaults are fine for
      # production. ALPN advertised so Codex's reqwest+rustls picks
      # http/1.1 cleanly when the proxy doesn't negotiate h2.
      otp_app: :recurse_gateway,
      thousand_island_options: [
        transport_options: [
          alpn_preferred_protocols: ["h2", "http/1.1"]
        ]
      ]
    ]
  end

  defp llm_proxy_tls_opts(_), do: []
end
