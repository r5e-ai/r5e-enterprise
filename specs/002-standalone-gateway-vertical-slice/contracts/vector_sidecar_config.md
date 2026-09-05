# Contract: Vector Sidecar Configuration

**Feature**: F002 | **Spec**: FR-024 / FR-026 | **Research**: D6 | **Key Entity**: Vector sidecar

Vector (vector.dev, Apache-licensed, Rust) is the default log shipper for the Gateway's stdout NDJSON. Ships as a sibling container in `docker-compose.yaml`. Customers MAY substitute Fluent Bit / Fluentd / Promtail / Logstash — the contract is "NDJSON on Gateway stdout," shipper choice is `docker-compose.override.yaml`.

## Shipped files

- `docker-compose.yaml` — declares the `vector` service with `image: timberio/vector:0.44.0-alpine`, `volumes: [/var/run/docker.sock:/var/run/docker.sock:ro, ./docker-compose/vector.toml:/etc/vector/vector.toml:ro]`.
- `docker-compose/vector.toml` — reference config.

## Reference `docker-compose/vector.toml`

```toml
# Vector reference config for Recurse Standalone AI Gateway
# F002 FR-024 + FR-026. Splunk HEC sink is commented out by default;
# uncomment + fill `endpoint` and `default_token` to enable.

data_dir = "/var/lib/vector"

[api]
enabled = true
address = "0.0.0.0:8686"

# Source: tail the recurse-gateway container's stdout
[sources.gateway_stdout]
type = "docker_logs"
include_containers = ["recurse-gateway"]
docker_host = "unix:///var/run/docker.sock"

# Optional transform example (disabled by default).
# Uncomment to add deployment tags or redact fields.
# [transforms.tag_env]
# type = "remap"
# inputs = ["gateway_stdout"]
# source = '''
#   .env = "prod"
# '''

# Sink 1: console (always on, useful for local dev).
[sinks.console]
type = "console"
inputs = ["gateway_stdout"]
encoding.codec = "json"

# Sink 2: Splunk HEC — UNCOMMENT + FILL to enable.
# [sinks.splunk]
# type = "splunk_hec_logs"
# inputs = ["gateway_stdout"]
# endpoint = "https://http-inputs-<tenant>.splunkcloud.com:443"
# default_token = "<your-hec-token>"
# source = "recurse:gateway"
# sourcetype = "recurse:attestation:v1"
# index = "recurse_audit"
# indexed_fields = ["tenant_id", "run_id", "principal.recurse_role", "policy_decision", "verification_level", "tier_completeness_advisory"]
# compression = "gzip"
# tls.verify_certificate = true
# # tls.ca_file = "/etc/vector/tls/ca.pem"   # for self-signed on-prem
#
# buffer.type = "disk"
# buffer.max_size = 268435456              # 256 MiB
# buffer.when_full = "block"                # backpressure to Gateway stdout; visible condition
#
# request.retry_max_duration_secs = 3600    # retry up to an hour
# request.retry_initial_backoff_secs = 1
# request.retry_max_backoff_secs = 30

# Sink 3 (optional): Datadog, Fluent-forward, generic HTTP — see vector.dev/docs/reference/configuration/sinks/
```

## Deployment contract

- **Multi-arch image**: `timberio/vector:0.44.0-alpine` manifest includes `linux/amd64` + `linux/arm64` — verified via `docker buildx imagetools inspect` during integration test.
- **Docker socket access**: `:ro` mount is sufficient (Vector only reads logs, never modifies containers). No privileged mode.
- **Observability**: Vector's `:8686` API + internal-metrics endpoint SHOULD be scraped by the deployment's Prometheus (alongside Gateway's `:4000/metrics`).

## Customer substitution

The contract is **Gateway stdout = NDJSON conforming to F001 FR-048 surface 1**. Customers swap Vector for another shipper by editing `docker-compose.override.yaml`:

```yaml
# Example: Fluent Bit substitution
services:
  vector:
    profiles: [do-not-start]    # disable default Vector
  fluentbit:
    image: fluent/fluent-bit:3.0
    volumes:
      - ./fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on: [recurse-gateway]
```

Recurse does NOT test Fluent Bit / Fluentd / Promtail / Logstash in F002 CI — the NDJSON emit is tested (SC-008); downstream shipper integration is the customer's responsibility.

## Failure modes

| Condition | Vector behavior | Recurse surface |
|---|---|---|
| Splunk HEC returns 429 | Exponential backoff per `request.retry_*` config | Vector's internal `component_received_events_total` lags; scraping catches it |
| Splunk HEC unreachable > 1h | Buffer fills; if `when_full = "block"`, Gateway stdout blocks; if `"drop_newest"`, events drop + Vector increments `component_discarded_events_total` | If `"block"`: Gateway's `recurse_siem_forwarder_emit_errors_total` increments when stdout-write blocks (detectable). If `"drop"`: lost events are Vector's responsibility — operator alert via Vector metrics |
| Vector process crashes | Docker Compose restarts (healthcheck-gated); buffer on-disk survives restart | Gateway emission continues regardless; events queue in kernel stdio buffer briefly |
| Vector config invalid | Vector fails to start; docker-compose shows failed health | Operator catches at deploy time; Gateway operates with no shipper (logs still on stdout, visible via `docker compose logs gateway`) |

## Out of scope for F002

- Vector Remap Language (VRL) transforms beyond the commented example — customer-specific.
- Secondary sinks (Datadog, Loki, Sentinel) — reference provides Splunk HEC; others are copy-paste from vector.dev docs.
- Multi-sink fanout semantics (e.g., same event to Splunk AND S3 archive) — customer config.
