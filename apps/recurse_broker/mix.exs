defmodule RecurseBroker.MixProject do
  @moduledoc """
  F002 Standalone Identity Broker OTP app (:recurse_broker).

  Implements RFC 8693 OAuth 2.0 Token Exchange per F002 FR-008 (which rewrites
  F001 FR-053 mechanics): customer OIDC `id_token` in → minted
  `X-Observed-Identity` JWT out, consumed by the Gateway's `PrincipalProvider`
  implementation. Packaged as a separate `mix release` and shipped as a sibling
  Docker container alongside `recurse-gateway` in the F002 `docker-compose.yaml`.

  The broker is intentionally narrow: three HTTP endpoints
  (`POST /token/exchange`, `GET /oidc/jwks`, `GET /healthz`) served by Bandit +
  `Plug.Router`, with a small supervision tree holding legitimate runtime state
  (remote customer-IdP JWKS cache + broker-side signing KeyRing). Per research
  D2, state-bearing components are GenServers; validator / role-mapper / JWT
  signer are pure modules.

  See `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
  for the authoritative wire-level API contract, `research.md` D2 for the
  implementation rationale, and `plan.md` for how this app fits in the umbrella.
  """
  use Mix.Project

  def project do
    [
      app: :recurse_broker,
      version: "0.1.0",
      package: package(),
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps()
    ]
  end

  # The licence, stated where a scanner looks for it. AGPL-3.0-only is the
  # decision recorded in `LICENSE.md`: `-only`, not `-or-later`.
  defp package do
    [
      licenses: ["AGPL-3.0-only"],
      links: %{"Source" => "https://gitlab.com/r5e-group/r5e-enterprise"}
    ]
  end

  # Test-support modules (MockOidcIssuer helper shared across T079 + T081 +
  # T089) live under `test/support/`. Compile them only in :test env so
  # production releases stay lean. Mirrors the pattern in
  # `apps/recurse_gateway/mix.exs`.
  #
  # NOTE: apps/recurse_broker/test/support/ modules (MockOidcIssuer +
  # SupervisorHelper) are consumed cross-app by Gateway integration tests.
  # Keep `elixirc_paths(:test)` including test/support so compile doesn't
  # strip them in umbrella test runs.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [
      extra_applications: [:logger],
      mod: {RecurseBroker.Application, []}
    ]
  end

  defp deps do
    [
      # Umbrella sibling — shared attestation structs, Principal struct,
      # JCS canonicalization, DSSE primitives (Principle V: the broker does
      # NOT import vendor SDKs; it composes on top of recurse_shared).
      {:recurse_shared, in_umbrella: true},
      # HTTP server for the broker endpoint (POST /token/exchange,
      # GET /oidc/jwks, GET /healthz).
      {:bandit, "~> 1.12.5"},
      {:plug, "~> 1.20.3"},
      # JWT sign + verify — customer id_token verification and
      # X-Observed-Identity minting. Alg allowlist enforced per FR-007 / D2.
      {:jose, "~> 1.11"},
      # OIDC discovery + JWKS fetch (HTTP client over Finch under the hood).
      {:req, "~> 0.6.3"},
      # Optional Finch pool (`:broker_jwks_pool`) started by
      # `RecurseBroker.Application` only when `:jwks_finch_pool` app env is
      # truthy. Req requires `:finch` as a runtime dep (transitively), so
      # this is a no-op addition in practice — listed explicitly so the
      # broker can name its own pool without relying on Req's default.
      {:finch, "~> 0.23.0"},
      # JSON encoding. Elixir 1.19 ships a built-in `JSON` module; Jason
      # retained for now until the JCS / JOSE / Plug stack all converge on
      # the built-in. Revisit in a dedicated cleanup pass.
      {:jason, "~> 1.4"},
      # YAML parser for `broker-role-mapping.yaml` (see
      # `RecurseBroker.RoleMapper` + `contracts/recurse_broker_api.md`
      # "broker-role-mapping.yaml schema"). yaml_elixir is the active
      # modern wrapper — yamerl directly is avoided for its
      # charlist-vs-binary ergonomics.
      {:yaml_elixir, "~> 2.11"},
      # Test-only.
      {:stream_data, "~> 1.3", only: :test},
      {:mox, "~> 1.2", only: :test}
    ]
  end
end
