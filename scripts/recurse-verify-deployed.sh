#!/usr/bin/env bash
# recurse-verify-deployed.sh — post-deploy verification of an audit-dev
# BEAM. Implements the "runtime MUST verify the digest post-deploy"
# half of the deploy invariant from `.specify/cicd-hardening.md`.
#
# Usage:
#   ./scripts/recurse-verify-deployed.sh <instance-id> <expected-sha256>
#
# Args:
#   instance-id     — EC2 instance running the BEAM, e.g. i-046b34d4015648a20
#   expected-sha256 — SHA-256 of the release tarball CI built and pushed
#
# What it checks (all must pass; any failure exits non-zero):
#
#   1. Service is active. If `systemctl is-active r5e-audit-audit.service`
#      returns anything other than `active`, the deploy didn't take.
#
#   2. The audit-console release manifest on disk matches the expected
#      SHA. The deploy job records the SHA into a file at deploy time;
#      this re-reads it and compares.
#
#   3. HTTP probe: GET /admin/login returns 200. Cheap smoke test — if
#      Bandit isn't listening, nothing else matters.
#
#   4. The compiled Router.beam references the dispatch modules we
#      expect for this build. Post-MR-!31 the router uses macros that
#      expand to calls into `CookieOrBearerPlug` and `BrowserSessionPipe`;
#      Router.beam carries baked-in module references for both. If
#      either is missing (e.g., the router compiled but those modules
#      didn't make it into the release), dispatch is broken — rollback.
#      Use `strings <beam-file>`; the BEAM file format embeds atom
#      names in clear text.
#
#   5. (TODO) A future check: hit a `/v1/_meta/version` endpoint that
#      returns the deployed SHA, compare to expected. The endpoint
#      doesn't exist yet — would land alongside this script's first
#      iteration. Current proxy is the disk-based release manifest.
#
# Required env / args (validated up-front so failures are loud):
#   AWS_REGION  default us-west-2
#   AWS_PROFILE optional; CI inherits assumed-role creds via env
#
# Exits:
#   0 — all checks passed
#   1 — any check failed (caller should trigger rollback)
#   2 — usage error / missing args

set -euo pipefail

INSTANCE_ID="${1:-}"
EXPECTED_SHA="${2:-}"
AWS_REGION="${AWS_REGION:-us-west-2}"

if [ -z "${INSTANCE_ID}" ] || [ -z "${EXPECTED_SHA}" ]; then
  echo "usage: $0 <instance-id> <expected-sha256>" >&2
  exit 2
fi

echo "[verify] instance=${INSTANCE_ID} expected_sha=${EXPECTED_SHA}"

# Helper: run a command on the BEAM via SSM and return its stdout.
# Polls for completion; fails if the SSM command itself fails.
ssm_run() {
  local desc="$1"
  local cmd="$2"
  local cmd_id
  cmd_id=$(aws ssm send-command \
    --region "${AWS_REGION}" \
    --instance-ids "${INSTANCE_ID}" \
    --document-name "AWS-RunShellScript" \
    --comment "verify: ${desc}" \
    --parameters "commands=[\"${cmd//\"/\\\"}\"]" \
    --output text --query 'Command.CommandId')
  for i in $(seq 1 30); do
    local status
    status=$(aws ssm get-command-invocation \
      --region "${AWS_REGION}" \
      --command-id "${cmd_id}" --instance-id "${INSTANCE_ID}" \
      --query 'Status' --output text 2>/dev/null || echo "Pending")
    if [ "${status}" = "Success" ]; then
      aws ssm get-command-invocation \
        --region "${AWS_REGION}" \
        --command-id "${cmd_id}" --instance-id "${INSTANCE_ID}" \
        --query 'StandardOutputContent' --output text
      return 0
    fi
    if [ "${status}" = "Failed" ] || [ "${status}" = "Cancelled" ] || [ "${status}" = "TimedOut" ]; then
      echo "[verify] ssm command failed for: ${desc}" >&2
      aws ssm get-command-invocation \
        --region "${AWS_REGION}" \
        --command-id "${cmd_id}" --instance-id "${INSTANCE_ID}" \
        --query 'StandardErrorContent' --output text >&2
      return 1
    fi
    sleep 2
  done
  echo "[verify] ssm command timed out: ${desc}" >&2
  return 1
}

# ----------------------------------------------------------------------- #
# Check 1: service active
# ----------------------------------------------------------------------- #

echo "[verify] (1/4) systemctl is-active r5e-audit-audit.service"
ACTIVE=$(ssm_run "is-active" "sudo systemctl is-active r5e-audit-audit.service")
ACTIVE=$(echo "${ACTIVE}" | tr -d '[:space:]')
if [ "${ACTIVE}" != "active" ]; then
  echo "[verify] FAIL (1): service status is '${ACTIVE}', expected 'active'" >&2
  exit 1
fi
echo "[verify] OK (1): service active"

# ----------------------------------------------------------------------- #
# Check 2: deployed release SHA matches expected
# ----------------------------------------------------------------------- #

echo "[verify] (2/4) deployed release SHA == ${EXPECTED_SHA}"
DEPLOYED_SHA=$(ssm_run "release-sha" "cat /opt/r5e/audit/current/RELEASE_SHA 2>/dev/null || sha256sum /tmp/release.tar.gz | awk '{print \$1}'")
DEPLOYED_SHA=$(echo "${DEPLOYED_SHA}" | tr -d '[:space:]')
if [ "${DEPLOYED_SHA}" != "${EXPECTED_SHA}" ]; then
  echo "[verify] FAIL (2): deployed SHA '${DEPLOYED_SHA}' != expected '${EXPECTED_SHA}'" >&2
  exit 1
fi
echo "[verify] OK (2): SHA match"

# ----------------------------------------------------------------------- #
# Check 3: HTTP probe — /admin/login returns 200
# ----------------------------------------------------------------------- #

echo "[verify] (3/4) curl http://127.0.0.1:4002/admin/login"
HTTP_CODE=$(ssm_run "http-probe" "curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:4002/admin/login")
HTTP_CODE=$(echo "${HTTP_CODE}" | tr -d '[:space:]')
if [ "${HTTP_CODE}" != "200" ]; then
  echo "[verify] FAIL (3): /admin/login returned ${HTTP_CODE}, expected 200" >&2
  exit 1
fi
echo "[verify] OK (3): /admin/login → 200"

# ----------------------------------------------------------------------- #
# Check 4: bytecode symbol set — Router.beam contains expected symbols
#
# This is the structural catch for the "deployed bytecode missing symbol"
# class of regression. Add a symbol here when:
#   - You ship a new public function in the router
#   - You want to assert it survived the build pipeline
# Remove a symbol when:
#   - The function is genuinely deleted (don't suppress check failures
#     by deleting the symbol — that defeats the point)
# ----------------------------------------------------------------------- #

# Post-MR-!31: the router no longer carries inline auth-dispatch helpers
# (`cookie_or_bearer_then` + `has_authorization_header?` were retired
# during the audit-pass consolidation). Auth dispatch now flows through
# `Recurse.Gateway.Auth.CookieOrBearerPlug.dispatch/2` and
# `Recurse.Gateway.Admin.BrowserSessionPipe.dispatch/2`, with the
# router's `dual_auth_*` / `cookie_only_*` macros (in
# `Recurse.Gateway.Auth.RouteMacros`) expanding to those calls.
#
# The structural-catch this check exists for is "compile-time
# elimination of dispatch wiring from Router.beam." After the macro
# expansion, Router.beam contains baked-in module references for the
# two dispatch modules — so we assert THOSE survived the build. If
# either is missing from the BEAM, dispatch is broken; rollback.
#
# DO NOT add `cookie_or_bearer_then` or `has_authorization_header?`
# back here — they are genuinely deleted (see Issue #29 / MR !31).
REQUIRED_ROUTER_SYMBOLS=(
  "Elixir.Recurse.Gateway.Auth.CookieOrBearerPlug"
  "Elixir.Recurse.Gateway.Admin.BrowserSessionPipe"
)

echo "[verify] (4/4) Router.beam contains required symbols"
SYMBOLS_FOUND=$(ssm_run "router-symbols" \
  "sudo strings /opt/r5e/audit/current/lib/recurse_gateway-0.1.0/ebin/Elixir.Recurse.Gateway.Router.beam | grep -E '$(IFS='|'; echo "${REQUIRED_ROUTER_SYMBOLS[*]}")' | sort -u")

MISSING=()
for sym in "${REQUIRED_ROUTER_SYMBOLS[@]}"; do
  if ! grep -q "${sym}" <<<"${SYMBOLS_FOUND}"; then
    MISSING+=("${sym}")
  fi
done

if [ "${#MISSING[@]}" -gt 0 ]; then
  echo "[verify] FAIL (4): missing required symbols in Router.beam:" >&2
  printf '  - %s\n' "${MISSING[@]}" >&2
  echo "[verify]   found in beam:" >&2
  echo "${SYMBOLS_FOUND}" | sed 's/^/    /' >&2
  exit 1
fi
echo "[verify] OK (4): all required Router.beam symbols present"

# ----------------------------------------------------------------------- #

echo "[verify] all checks passed"
