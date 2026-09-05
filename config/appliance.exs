# Mix env config — Air-Gapped Appliance tier (FR-013: Phase-2 deferred).
# Phase-1 scaffolding only. Reference YAML: config/appliance.reference.yml (T055).

import Config

config :recurse_runtime, start?: true
config :recurse_gateway, start_http?: true
