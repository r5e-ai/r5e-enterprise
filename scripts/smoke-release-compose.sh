#!/usr/bin/env bash
# Exercise a prebuilt release image with a local mock provider. This script
# creates and removes only its uniquely named Compose project and volumes.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${R5E_GATEWAY_IMAGE:-}"

if [ -z "$IMAGE" ]; then
  echo "usage: R5E_GATEWAY_IMAGE=r5e/gateway:<candidate> scripts/smoke-release-compose.sh" >&2
  exit 3
fi

if ! command -v cargo >/dev/null 2>&1 && [ -x "${CARGO_HOME:-${HOME}/.cargo}/bin/cargo" ]; then
  export PATH="${CARGO_HOME:-${HOME}/.cargo}/bin:${PATH}"
fi

for command in docker curl jq openssl python3 unzip xxd cargo; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "release smoke: '$command' is required" >&2
    exit 3
  }
done

docker image inspect "$IMAGE" >/dev/null

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
stamp_lower="$(printf '%s' "$STAMP" | tr '[:upper:]' '[:lower:]')"
PROJECT="r5e-smoke-${stamp_lower}-$$"
PROJECT="${PROJECT//:/-}"
OUTPUT_DIR="${R5E_SMOKE_OUTPUT_DIR:-${TMPDIR:-/tmp}/r5e-release-smoke-${STAMP}-$$}"
mkdir -p "$OUTPUT_DIR"

export R5E_SMOKE_GATEWAY_PORT="$(free_port)"
export R5E_SMOKE_PROXY_PORT="$(free_port)"
export R5E_SMOKE_PROVIDER_PORT="$(free_port)"
export R5E_SMOKE_GATEWAY_CONTAINER="${PROJECT}-gateway"
export R5E_SMOKE_POSTGRES_CONTAINER="${PROJECT}-postgres"
export R5E_SMOKE_ENV_FILE="${OUTPUT_DIR}/smoke.env"
# Docker Desktop shares the repository checkout with its VM. Host-private
# temporary directories are not portable bind-mount sources across engines,
# so stage the copied public policy under the checkout's ignored tmp/ tree.
export R5E_SMOKE_POLICY_DIR="${ROOT}/tmp/${PROJECT}-policy"
export R5E_GATEWAY_IMAGE="$IMAGE"
export R5E_STATE_DIR="${OUTPUT_DIR}/state"
export R5E_GATEWAY_URL="http://127.0.0.1:${R5E_SMOKE_GATEWAY_PORT}"
export R5E_GATEWAY_PORT="$R5E_SMOKE_GATEWAY_PORT"
export R5E_PROXY_PORT="$R5E_SMOKE_PROXY_PORT"
export R5E_FOLD_PROJECT="$PROJECT"

mkdir -p "$R5E_SMOKE_POLICY_DIR"
cp "$ROOT/policy/bundle.cedar" "$R5E_SMOKE_POLICY_DIR/bundle.cedar"
# The output root is private, but Docker Desktop presents this bind mount to
# the image's uid 1000. The policy is public source, so make only this copied
# directory and file traversable/readable by the non-root container user.
chmod 755 "$R5E_SMOKE_POLICY_DIR"
chmod 644 "$R5E_SMOKE_POLICY_DIR/bundle.cedar"

cat > "$R5E_SMOKE_ENV_FILE" <<EOF
SECRET_KEY_BASE=$(openssl rand -hex 32)
GATEWAY_ADMIN_SESSION_SECRET_KEY_BASE=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
R5E_TENANT_ID=01TEN_RELEASE_SMOKE
R5E_DEV_LOGIN_ENABLED=true
R5E_LOCAL_SIGNING_ALG=es256
R5E_LLM_PROXY_UPSTREAMS=anthropic
R5E_LLM_PROXY_DEFAULT_UPSTREAM_HOST=host.docker.internal
R5E_RETAIN_PAYLOADS=true
EOF

COMPOSE=(docker compose --env-file "$R5E_SMOKE_ENV_FILE" -p "$PROJECT" \
  -f "$ROOT/docker-compose.yaml" -f "$ROOT/docker-compose.smoke.yaml")
MOCK_PID=""

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  set +e
  "${COMPOSE[@]}" logs --no-color >"${OUTPUT_DIR}/compose.log" 2>&1
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  python3 - "$ROOT" "$R5E_SMOKE_POLICY_DIR" <<'PY'
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1]).resolve()
policy = Path(sys.argv[2]).resolve()
if policy.parent == root / "tmp" and policy.name.startswith("r5e-smoke-"):
    shutil.rmtree(policy, ignore_errors=True)
PY
  if [ -n "$MOCK_PID" ]; then
    kill "$MOCK_PID" >/dev/null 2>&1
    wait "$MOCK_PID" >/dev/null 2>&1
  fi
  echo "release smoke: artifacts ${OUTPUT_DIR}"
  exit "$rc"
}
trap cleanup EXIT INT TERM

"${COMPOSE[@]}" config --quiet
python3 "$ROOT/scripts/mock-anthropic-provider.py" \
  --port "$R5E_SMOKE_PROVIDER_PORT" --log "${OUTPUT_DIR}/mock-requests.jsonl" &
MOCK_PID=$!

for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:${R5E_SMOKE_PROVIDER_PORT}/healthz" >/dev/null && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:${R5E_SMOKE_PROVIDER_PORT}/healthz" >/dev/null

"${COMPOSE[@]}" up -d --no-build postgres gateway

wait_for_gateway() {
  for _ in $(seq 1 120); do
    curl -fsS "${R5E_GATEWAY_URL}/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

wait_for_gateway

PROVIDER_RPC='import Ecto.Query; alias Recurse.Providers.Repo; alias Recurse.Providers.Schemas.LlmProviderConfig; tenant = System.fetch_env!("R5E_TENANT_ID"); row = Repo.one!(from c in LlmProviderConfig, where: c.tenant_id == ^tenant and c.provider == "anthropic"); metadata = row.metadata |> Map.drop(["seed", "preset"]) |> Map.put("scheme", "http"); row |> LlmProviderConfig.changeset(%{upstream_host: System.fetch_env!("R5E_SMOKE_PROVIDER_HOST"), upstream_port: String.to_integer(System.fetch_env!("R5E_SMOKE_PROVIDER_PORT")), metadata: metadata}) |> Repo.update!(); IO.puts("r5e-smoke-provider-ready")'
"${COMPOSE[@]}" exec -T gateway /app/bin/audit_console rpc "$PROVIDER_RPC" \
  | tee "${OUTPUT_DIR}/provider-rpc.log"
grep -q 'r5e-smoke-provider-ready' "${OUTPUT_DIR}/provider-rpc.log"

"$ROOT/bin/r5e" login release-smoke@r5e | tee "${OUTPUT_DIR}/login-before-restart.log"
"$ROOT/bin/r5e" status | tee "${OUTPUT_DIR}/status-before-restart.log"

request() {
  marker="$1"
  output="$2"
  curl -fsS -N --max-time 20 \
    -H 'content-type: application/json' \
    -H 'anthropic-version: 2023-06-01' \
    -H 'authorization: Bearer r5e-release-smoke-no-external-provider' \
    -d "{\"model\":\"claude-haiku-4-5-20251001\",\"max_tokens\":64,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"${marker}\"}]}" \
    "http://127.0.0.1:${R5E_SMOKE_PROXY_PORT}/v1/messages" > "$output"
}

request SMOKE_ALLOW "${OUTPUT_DIR}/allow-before-restart.sse"
grep -q 'ls -la' "${OUTPUT_DIR}/allow-before-restart.sse"
grep -q 'message_stop' "${OUTPUT_DIR}/allow-before-restart.sse"

request SMOKE_DENY "${OUTPUT_DIR}/deny.sse"
grep -q 'blocked by org policy' "${OUTPUT_DIR}/deny.sse"
grep -q 'message_stop' "${OUTPUT_DIR}/deny.sse"
if grep -q 'rm -rf /tmp/r5e-release-smoke-forbidden' "${OUTPUT_DIR}/deny.sse"; then
  echo "release smoke: forbidden command bytes reached the client" >&2
  exit 1
fi

"$ROOT/bin/r5e" evidence export --out "${OUTPUT_DIR}/enterprise-denial.zip"
"$ROOT/bin/r5e" evidence verify "${OUTPUT_DIR}/enterprise-denial.zip" \
  | tee "${OUTPUT_DIR}/enterprise-verify.log"
unzip -t "${OUTPUT_DIR}/enterprise-denial.zip" >/dev/null

"$ROOT/bin/r5e" evidence export --fold --out "${OUTPUT_DIR}/fold-before"
"$ROOT/bin/r5e" evidence verify --fold "${OUTPUT_DIR}/fold-before" \
  | tee "${OUTPUT_DIR}/fold-verify-before.log"

before_events="$(jq -r '.events' "${OUTPUT_DIR}/fold-before/manifest.json")"
before_signer="$(jq -r '.signer.keyId' "${OUTPUT_DIR}/fold-before/manifest.json")"

"${COMPOSE[@]}" restart gateway
wait_for_gateway
"$ROOT/bin/r5e" login release-smoke-after-restart@r5e \
  | tee "${OUTPUT_DIR}/login-after-restart.log"
"$ROOT/bin/r5e" status | tee "${OUTPUT_DIR}/status-after-restart.log"

request SMOKE_ALLOW "${OUTPUT_DIR}/allow-after-restart.sse"
grep -q 'ls -la' "${OUTPUT_DIR}/allow-after-restart.sse"
grep -q 'message_stop' "${OUTPUT_DIR}/allow-after-restart.sse"

"$ROOT/bin/r5e" evidence export --fold --out "${OUTPUT_DIR}/fold-after"
"$ROOT/bin/r5e" evidence verify --fold "${OUTPUT_DIR}/fold-after" \
  | tee "${OUTPUT_DIR}/fold-verify-after.log"

after_events="$(jq -r '.events' "${OUTPUT_DIR}/fold-after/manifest.json")"
after_signer="$(jq -r '.signer.keyId' "${OUTPUT_DIR}/fold-after/manifest.json")"
test "$before_signer" = "$after_signer"
test "$after_events" -gt "$before_events"
test "$(jq -s 'length' "${OUTPUT_DIR}/mock-requests.jsonl")" -eq 3

cat > "${OUTPUT_DIR}/summary.txt" <<EOF
image=${IMAGE}
compose_project=${PROJECT}
gateway_port=${R5E_SMOKE_GATEWAY_PORT}
proxy_port=${R5E_SMOKE_PROXY_PORT}
mock_provider_port=${R5E_SMOKE_PROVIDER_PORT}
fold_signer=${after_signer}
fold_events_before=${before_events}
fold_events_after=${after_events}
provider_requests=3
result=PASS
EOF
cat "${OUTPUT_DIR}/summary.txt"
