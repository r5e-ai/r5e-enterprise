# Mix env config — Managed SaaS tier.
# Phase-1 scaffolding only. Provider selection is driven by
# `R5E_PROVIDER_<ROLE>_IMPL` env vars consumed by
# `Recurse.Gateway.Config.EnvProviderRegistry` at boot, NOT this file.

import Config

config :recurse_runtime, start?: true
config :recurse_gateway, start_http?: true
