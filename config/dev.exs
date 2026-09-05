# Dev-tier compile-time config. Loaded by config.exs's conditional
# `import_config "#{config_env()}.exs"`, so it applies to `MIX_ENV=dev`
# only — never test, never a prod release.
#
# Originally written for the 2026-07-27 local demo bring-up
# (see scripts/fable_demo/README.md); everything here is what dev
# otherwise leaves off:
#
#   * audit_console_enabled? — boots JwksCache + EnvProviderInstaller gate +
#     BundleLoader children so the audit-plane endpoints authenticate.
#   * dev_login_enabled? — POST /admin/test/login (server-side cookie mint,
#     no IdP round-trip). See Recurse.Gateway.Admin.BrowserAuth.DevLoginHandler;
#     config.exs pins it to `false` for every other env; runtime.exs honours
#     `R5E_DEV_LOGIN_ENABLED` when set (spec 012), so a prod release can opt
#     in for the local quickstart.
#   * :browser_session secret — BrowserSessionPlug needs a 32-byte key to
#     mint/verify the r5e_session cookie. Derived from a constant public
#     string below: it is deliberately NOT a secret, and dev cookies are
#     therefore forgeable by anyone with this file. That is fine for
#     http://localhost and unacceptable anywhere else, which is why this
#     value lives in dev.exs and nowhere near runtime.exs.
#   * secure_cookie? false — we serve plain http://localhost.

import Config

config :recurse_gateway,
  audit_console_enabled?: true,
  dev_login_enabled?: true

config :recurse_gateway, :browser_session,
  secret_key_base: :crypto.hash(:sha256, "r5e-local-dev-only-not-a-secret"),
  secure_cookie?: false

# JwksCache boot requirement for non-WorkOS providers (BROWSER_OIDC_PROVIDER=oidc):
# it demands an IdP jwks_url. A local dev run does no real IdP round-trip
# (cookies are minted in-BEAM / via DevLoginHandler), so point the IdP entry at
# the gateway's own collapsed-broker JWKS. runtime.exs merges :provider and
# :issuer_url on top of this at boot; :jwks_url survives the merge.
config :recurse_gateway, :browser_oidc_idp, jwks_url: "http://127.0.0.1:4000/v1/auth/jwks"
