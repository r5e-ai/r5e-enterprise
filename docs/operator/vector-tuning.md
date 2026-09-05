# Vector Sidecar Tuning — Recurse Standalone AI Gateway

**Audience**: platform operators responsible for the Recurse Standalone Gateway deployment.
**Scope**: tuning the Vector log-shipper sidecar that tails the Gateway container's stdout and forwards NDJSON attestation events to the customer's SIEM.
**Related specs**: F002 FR-024, FR-025, FR-026; `specs/002-standalone-gateway-vertical-slice/contracts/vector_sidecar_config.md`.

---

## Why Vector

The Recurse Gateway emits one NDJSON line per attestation to its container stdout (F002 FR-024 + FR-025). **Reliable delivery to the SIEM is a deployment-time concern**, not a Gateway concern — the Gateway ships no HTTP push code and no on-disk spool.

The reference `docker-compose.yaml` includes Vector (`timberio/vector:0.44.0-alpine`) as a sibling container behind the `logs` profile: `docker compose --profile logs up -d` starts it, plain `docker compose up -d` does not. Vector:

- Tails `recurse-gateway`'s stdout via the Docker Engine API (`docker_logs` source).
- Optionally transforms events (add deployment tags, redact fields — see VRL examples below).
- Ships the NDJSON to one or more configured sinks (console for local dev, Splunk HEC for production, others per customer choice).
- Handles bounded retry + on-disk spool on target outage.

**Customers MAY substitute** Fluent Bit, Fluentd, Promtail, Logstash, or any other NDJSON-capable shipper. The contract is "NDJSON on Gateway stdout conforming to F001 FR-048 surface 1." See [Switching shippers](#switching-shippers) below.

---

## File layout

```
<repo-root>/
  docker-compose.yaml                # declares the `vector` service (profile `logs`)
  docker-compose/
    vector.toml                      # reference Vector config (ships to customers)
    vector.test.toml                 # test-only config used by docker-compose.test.yaml
```

The operator edits `docker-compose/vector.toml` in place. It's mounted read-only into the container at `/etc/vector/vector.toml`.

---

## Step 1 — Enable the Splunk HEC sink

The reference `docker-compose/vector.toml` ships with Sink 1 (console) enabled and Sink 2 (Splunk HEC) **commented out**. To enable HEC:

1. Obtain a Splunk HEC token from your Splunk admin (scope: `sourcetype=recurse:attestation:v1`, `index=recurse_audit`).

2. Open `docker-compose/vector.toml` and uncomment the `[sinks.splunk]` block plus each `# buffer.*` and `# request.*` line underneath it.

3. Fill in:

   ```toml
   endpoint      = "https://http-inputs-<your-tenant>.splunkcloud.com:443"
   default_token = "<your-hec-token>"
   ```

   (If you're on self-signed-cert on-prem Splunk, uncomment `tls.ca_file` and point it at your CA bundle mounted into the container.)

4. Restart Vector only (no Gateway bounce needed):

   ```bash
   docker compose --profile logs restart vector
   ```

5. Verify events are flowing:

   ```bash
   docker compose --profile logs logs --tail=20 vector
   # Expected: "component_sent_events_total" increments; no HEC 4xx/5xx errors.
   ```

   In Splunk, run a search: `index=recurse_audit sourcetype=recurse:attestation:v1 | head 10`.

---

## Step 2 — Buffer tuning

Vector buffers events in memory OR on disk between the source and each sink. Tune for your SIEM's availability and the customer's acceptable data-loss window.

### Key knobs (per-sink, under `[sinks.splunk]`)

| Knob | Default shipped | Recommended for prod | Behavior |
|---|---|---|---|
| `buffer.type` | `"disk"` (commented) | `"disk"` | Disk buffer survives Vector process restarts. Memory buffer is lost on restart. |
| `buffer.max_size` | `268435456` (256 MiB) | 512 MiB – 2 GiB | Max on-disk buffer size before `when_full` kicks in. |
| `buffer.when_full` | `"block"` | `"block"` (GRC) or `"drop_newest"` (non-GRC) | **`block`** backpressures Gateway stdout writes — if HEC is down for long enough, the Gateway eventually stalls writing receipts, which surfaces as `recurse_siem_forwarder_emit_errors_total` > 0. Detectable. **`drop_newest`** silently discards events when full; Vector increments `component_discarded_events_total`. Lost events are Vector's failure mode. |
| `request.retry_max_duration_secs` | `3600` (1 h) | `3600` – `14400` | How long Vector retries against HEC before giving up on an in-flight request. |
| `request.retry_initial_backoff_secs` | `1` | `1` | First retry after 1 s. |
| `request.retry_max_backoff_secs` | `30` | `30`–`60` | Cap on exponential backoff. |

### Choosing `when_full`

**For GRC / audit deployments**: use `when_full = "block"`. Losing attestation events silently breaks the Principle-III guarantee (every LLM call has a receipt; the receipt is observable). `block` converts a shipper outage into a visible Gateway signal — `recurse_siem_forwarder_emit_errors_total` increments when stdout-write blocks.

**For non-GRC / observability-grade deployments**: `when_full = "drop_newest"` is acceptable. The ledger still holds every receipt (SIEM forwarding is a derivative stream); the risk is that the SIEM misses rows while Vector's buffer recovers. Monitor Vector's `component_discarded_events_total`.

### Disk sizing rule of thumb

```
buffer.max_size_bytes >=
  peak_events_per_second
  × avg_event_bytes
  × acceptable_outage_secs
```

For a workload averaging 200 attestations/sec at ~1 KiB/event, buffering 2 hours of outage needs **~1.4 GiB**. Size the `vector_data` Docker volume accordingly.

---

## Step 3 — Transforms (optional)

The reference config includes a commented VRL example for tagging events with deployment metadata:

```toml
[transforms.tag_env]
type = "remap"
inputs = ["gateway_stdout"]
source = '''
  .env = "prod"
  .cluster = "us-east-1"
'''
```

To route transformed events to HEC, change the sink's `inputs` from `["gateway_stdout"]` to `["tag_env"]`.

Common customer transforms:

- **Redact email-like `principal.display_name`** before HEC:
  ```
  if exists(.principal.display_name) {
    .principal.display_name = redact(.principal.display_name, filters: ["email"])
  }
  ```
- **Drop noisy allow events** (keep denies + upstream errors only):
  ```
  if .policy_decision == "allow" && !exists(.outcome) {
    abort
  }
  ```
  (`abort` in VRL drops the event from the pipeline.)

Keep transforms minimal — every field-level mutation risks breaking the F001 FR-048 surface 1 schema shape that customer SIEM dashboards depend on.

---

## Switching shippers

The contract is **NDJSON on Gateway stdout = F001 FR-048 surface 1**. Any shipper that can tail a container's stdout and forward to the downstream SIEM works.

Create `docker-compose.override.yaml` at repo root:

### Example: Fluent Bit

```yaml
services:
  vector:
    profiles: [do-not-start]    # disable default Vector
  fluentbit:
    image: fluent/fluent-bit:3.0
    volumes:
      - ./fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on: [gateway]
    networks:
      - egress
    restart: unless-stopped
```

### Example: Fluentd

```yaml
services:
  vector:
    profiles: [do-not-start]
  fluentd:
    image: fluent/fluentd:v1.17-1
    volumes:
      - ./fluent.conf:/fluentd/etc/fluent.conf:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on: [gateway]
    networks:
      - egress
```

### Example: Promtail → Loki

```yaml
services:
  vector:
    profiles: [do-not-start]
  promtail:
    image: grafana/promtail:3.1.0
    volumes:
      - ./promtail.yaml:/etc/promtail/config.yml:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on: [gateway]
    networks:
      - egress
```

### Example: Logstash

```yaml
services:
  vector:
    profiles: [do-not-start]
  logstash:
    image: docker.elastic.co/logstash/logstash:8.14.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on: [gateway]
    networks:
      - egress
```

**Recurse does NOT test Fluent Bit / Fluentd / Promtail / Logstash in F002 CI.** The NDJSON emit is tested (SC-008); downstream shipper correctness is the customer's responsibility. Verify with a canary event round-trip before declaring production-ready.

---

## Troubleshooting

### Check Vector is tailing the Gateway

```bash
docker compose --profile logs logs --tail=50 vector
```

Look for `component_received_events_total` climbing as you exercise the Gateway.

### Check Vector's Prometheus metrics

Vector exposes `:8686` with an internal-metrics API. The compose file does not publish that port on the host, so read it from inside the container (or add a `ports:` entry for your Prometheus):

```bash
docker compose --profile logs exec vector wget -q -O - http://localhost:8686/metrics | grep -E 'component_(received|sent|discarded|errors)'
```

Key metrics:

- `component_received_events_total{component_id="gateway_stdout"}` — events Vector pulled off Gateway stdout.
- `component_sent_events_total{component_id="splunk"}` — events delivered to HEC successfully.
- `component_discarded_events_total{component_id="splunk"}` — events dropped (only relevant if `when_full = "drop_newest"`).
- `component_errors_total{component_id="splunk"}` — HEC sink errors (4xx/5xx/timeout).

If `component_received_events_total` > 0 but `component_sent_events_total` stays flat: HEC endpoint or auth is wrong. Check `docker compose logs vector` for the error body.

### Vector health endpoint

The reference `docker-compose.yaml` healthchecks Vector's `/health` on `:8686`. A failing healthcheck surfaces in `docker compose ps`:

```bash
docker compose --profile logs ps
# NAME             STATUS
# r5e-vector-1     Up (unhealthy)   <-- investigate
```

### Vector fails to start

Usually a config syntax error. Vector prints the exact line number on stderr:

```bash
docker compose --profile logs logs vector
# ERROR Unable to load config: expected table key at line 42 column 3
```

Fix the config, then:

```bash
docker compose --profile logs restart vector
```

Gateway continues emitting NDJSON to its own stdout during Vector downtime — nothing is lost until the Docker daemon rotates the container log, which the default `json-file` driver does not do unless `max-size` is set in `daemon.json`.

### HEC returning 403 / 401

Either the token is wrong or the token lacks permission on the configured `index` / `sourcetype`. Validate with:

```bash
curl -kv -H "Authorization: Splunk <token>" \
  -d '{"event":"test"}' \
  https://http-inputs-<tenant>.splunkcloud.com:443/services/collector
```

### HEC returning 400 ("No data")

Vector is sending events with an empty `event` field. Usually means the `docker_logs` source isn't parsing the JSON stdout correctly. The test overlay (`docker-compose/vector.test.toml`) shows the correct pattern: a `parse_siem` `remap` transform that runs `parse_json(.message)` before the sink.

---

## Out of scope for this runbook

- **TLS termination details** — use your organization's standard Splunk / SIEM TLS config. Recurse ships `tls.verify_certificate = true` as the default and recommends leaving it on.
- **Multi-sink fanout** (same event to Splunk AND S3 archive) — copy the `[sinks.splunk]` block, rename, change the type. See vector.dev/docs.
- **VRL recipe library** — Vector's own docs are the canonical reference; the examples above are the minimum we test.
- **Cluster-mode Vector** (multiple Vector instances behind a load balancer) — F002 ships a single-instance Gateway per deployment, so single-instance Vector is sufficient. Multi-instance patterns are a Phase-1.5 concern.
