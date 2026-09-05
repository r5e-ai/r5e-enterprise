#!/usr/bin/env bash
# F002 US4 — Vector sidecar integration test (T069).
#
# Boots the reference stack (docker-compose.yaml) + test overlay
# (docker-compose.test.yaml), emits two attestations via the Gateway
# (one ALLOW, one DENY), and asserts that Vector forwards exactly two
# NDJSON events to the mock HEC container, each conforming to the F001
# FR-048 surface 1 schema.
#
# ## Why bash, not ExUnit
#
# The test spins up a full docker-compose stack including a Python
# mock-HEC sidecar. Wiring that into ExUnit would require either
# `docker compose` shellouts from Elixir (same bash under a thicker
# wrapper) or a bespoke Elixir HEC mock (lots of code, zero Elixir
# value over a 30-line Python HTTP server). Per
# specs/002-standalone-gateway-vertical-slice/tasks.md T069 + the
# scoping note in the T069 prompt, bash is the less-complex option.
#
# ## CI integration
#
# This script is invoked from CI by a stanza in `.github/workflows`
# (TODO when F002 CI lands). Locally run via:
#
#   ./test/integration/us4_vector_forwarder_test.sh
#
# Requires: docker, docker compose, jq. Exits 0 on pass, non-zero with
# a diagnostic message on fail.
#
# ## What this test does NOT do
#
# It does not exercise the real OpenAI API. The Gateway is configured
# (via docker-compose.test.yaml's env overrides) to use a stub LLM
# provider that returns a canned `chat.completion` response. The goal
# is to validate the **SIEM forwarder → stdout → Vector → HEC** path,
# not the upstream LLM.
#
# ## Prerequisites (CI side)
#
# The test overlay references test-only stub modules
# (`Recurse.Providers.Support.MockLLMProvider`,
# `Recurse.Gateway.Test.StubSecretsProvider`) that are only compiled
# with MIX_ENV=test. The shipped `Dockerfile` builds a MIX_ENV=prod
# release and does NOT include these stubs. Running this script
# end-to-end therefore requires a separate test-image build (MIX_ENV=test
# Dockerfile stanza) that F002 CI is expected to provide. Until that
# lands, this script is a skeleton that validates the compose+Vector
# wiring (phase 0 + healthcheck waits succeed) but the LLM request
# phase will 500 because the stub module isn't present in the image.
#
# Mark the script successful once CI image work lands and phase 2+3
# observe the two HEC events.

set -euo pipefail

# ---------- configuration ----------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILES=(-f docker-compose.yaml -f docker-compose.test.yaml)
HEC_EVENTS_FILE="$REPO_ROOT/test/integration/hec_events/events.ndjson"
GATEWAY_URL="http://localhost:4000"
WAIT_AFTER_REQUESTS_SECS=5
BOOT_TIMEOUT_SECS=90

ALLOW_JWT="${ALLOW_JWT:-__TEST_ALLOW_JWT_REPLACE_ME__}"
DENY_JWT="${DENY_JWT:-__TEST_DENY_JWT_REPLACE_ME__}"

# ---------- helpers ----------------------------------------------------------

log() { echo "[us4-test] $*" >&2; }
die() { log "FAIL: $*"; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

cleanup() {
  log "tearing down compose stack"
  docker compose "${COMPOSE_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}

wait_for_healthy() {
  local service="$1"
  local deadline=$((SECONDS + BOOT_TIMEOUT_SECS))
  while (( SECONDS < deadline )); do
    local status
    status="$(docker compose "${COMPOSE_FILES[@]}" ps --format json "$service" 2>/dev/null \
      | jq -r '.Health // .State // "unknown"' | head -n1)"
    if [[ "$status" == "healthy" || "$status" == "running" ]]; then
      return 0
    fi
    sleep 2
  done
  die "$service did not become healthy within ${BOOT_TIMEOUT_SECS}s"
}

# ---------- preconditions ----------------------------------------------------

require_cmd docker
require_cmd jq
require_cmd curl
docker compose version >/dev/null 2>&1 || die "docker compose v2 required"

log "preconditions OK"

# ---------- phase 0: env + config validation --------------------------------

# The shipped compose file references `.env.gateway` / `.env.broker` which
# are git-ignored (real customer secrets). For the test we seed them from
# the `.example` templates so `docker compose config` validates and the
# containers boot with harmless placeholders. The test overlay then
# overrides the handful of env vars that actually matter (stub LLM, stub
# secrets provider) via `environment:` keys.
if [[ ! -f .env.gateway ]]; then
  log "seeding .env.gateway from docker-compose/gateway.env.example"
  cp docker-compose/gateway.env.example .env.gateway
fi
if [[ ! -f .env.broker ]]; then
  log "seeding .env.broker from docker-compose/broker.env.example"
  cp docker-compose/broker.env.example .env.broker
fi

log "validating compose config"
docker compose "${COMPOSE_FILES[@]}" config >/dev/null \
  || die "docker compose config failed — overlay is malformed"

# ---------- phase 1: boot ---------------------------------------------------

trap cleanup EXIT

log "bringing up compose stack"
docker compose "${COMPOSE_FILES[@]}" up -d --remove-orphans

log "waiting for postgres to become healthy"
wait_for_healthy postgres

log "waiting for recurse-gateway to become healthy"
wait_for_healthy recurse-gateway

log "waiting for recurse-broker to become healthy"
wait_for_healthy recurse-broker

log "waiting for vector to become healthy"
wait_for_healthy vector

log "waiting for mock-hec to become healthy"
wait_for_healthy mock-hec

# ---------- phase 2: emit 2 attestations -------------------------------------

log "issuing ALLOW request"
curl -sS -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $ALLOW_JWT" \
  -H "Content-Type: application/json" \
  -X POST "$GATEWAY_URL/v1/chat/completions" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"test allow"}]}' \
  > /tmp/us4_allow_status.txt || true

log "issuing DENY request"
curl -sS -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $DENY_JWT" \
  -H "Content-Type: application/json" \
  -X POST "$GATEWAY_URL/v1/chat/completions" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"test deny"}]}' \
  > /tmp/us4_deny_status.txt || true

log "waiting ${WAIT_AFTER_REQUESTS_SECS}s for Vector → HEC forwarding"
sleep "$WAIT_AFTER_REQUESTS_SECS"

# ---------- phase 3: assert HEC received events -----------------------------

[[ -f "$HEC_EVENTS_FILE" ]] \
  || die "HEC events file missing at $HEC_EVENTS_FILE — did mock-hec mount correctly?"

log "HEC events file contents:"
cat "$HEC_EVENTS_FILE" >&2

event_count=$(grep -c '^.' "$HEC_EVENTS_FILE" || true)
if [[ "$event_count" != "2" ]]; then
  die "expected exactly 2 HEC events, got $event_count"
fi

log "asserting each event is valid JSON + matches F001 FR-048 surface 1 schema"

required_keys=(run_id session_id principal machine_identity \
  policy_decision policy_canonical_hash verification_level \
  tier_completeness_advisory correlation_id timestamp)

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  # Assert valid JSON
  echo "$line" | jq -e . >/dev/null || die "HEC event is not valid JSON: $line"

  for key in "${required_keys[@]}"; do
    echo "$line" | jq -e "has(\"$key\")" >/dev/null \
      || die "HEC event missing required key '$key': $line"
  done

  advisory=$(echo "$line" | jq -r '.tier_completeness_advisory')
  [[ "$advisory" == "partial" ]] \
    || die "tier_completeness_advisory must be 'partial' in Standalone; got '$advisory'"

  decision=$(echo "$line" | jq -r '.policy_decision')
  [[ "$decision" == "allow" || "$decision" == "deny" ]] \
    || die "policy_decision must be 'allow' or 'deny'; got '$decision'"
done < "$HEC_EVENTS_FILE"

# Assert we got one allow + one deny.
allow_count=$(jq -r 'select(.policy_decision == "allow") | .run_id' "$HEC_EVENTS_FILE" | wc -l | tr -d ' ')
deny_count=$(jq -r 'select(.policy_decision == "deny") | .run_id'  "$HEC_EVENTS_FILE" | wc -l | tr -d ' ')

[[ "$allow_count" == "1" ]] || die "expected 1 allow event, got $allow_count"
[[ "$deny_count"  == "1" ]] || die "expected 1 deny event, got $deny_count"

log "PASS: 2 HEC events received, both valid, one allow + one deny"
exit 0
