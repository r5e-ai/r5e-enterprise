# Mix env config — Standalone AI Gateway tier (FR-050).
# Phase-1 scaffolding only. Provider selection is driven by
# `R5E_PROVIDER_<ROLE>_IMPL` env vars consumed by
# `Recurse.Gateway.Config.EnvProviderRegistry` at boot, NOT this file.

import Config

config :recurse_runtime, start?: false
config :recurse_gateway, start_http?: true
