#!/usr/bin/env bash
# scripts/verify-ad001-behaviour-surfaces.sh
#
# AD-001 c' — Provider Interface behaviour-file content guard.
#
# Recomputes SHA-256 over each of the seven F001-landed Provider Interface
# behaviour files (`apps/recurse_providers/lib/recurse_providers/*_provider.ex`)
# and compares against `scripts/ad001-pinned-hashes.txt`. Any drift is a
# constitutional-amendment-required event — see
# `specs/002-standalone-gateway-vertical-slice/plan.md` AD-001 for rationale.
#
# Exit codes:
#   0  all pinned SHAs match — behaviour surfaces unchanged from F002-MVP.
#   1  at least one pinned file's SHA differs from the pinned value.
#   2  the pinned file is missing on disk, or a malformed hash line is
#      encountered.
#
# Usage:
#   ./scripts/verify-ad001-behaviour-surfaces.sh
#
# CI invocation (example — adapt to the project's CI conventions):
#   - name: Verify AD-001 c' behaviour surfaces unchanged
#     run: ./scripts/verify-ad001-behaviour-surfaces.sh
#
# Pre-commit invocation (example, not wired automatically here):
#   Add to .git/hooks/pre-commit or a pre-commit-framework config:
#     ./scripts/verify-ad001-behaviour-surfaces.sh
#
# Updating pinned hashes:
#   A genuine change to a Provider Interface behaviour file is — by
#   AD-001 c' — a constitutional event, not a routine refactor. When
#   that change lands (after the amendment is approved and recorded in
#   `.specify/memory/constitution.md`), regenerate the pinned file with:
#     for f in $(cut -d' ' -f3- scripts/ad001-pinned-hashes.txt); do
#       shasum -a 256 "$f"
#     done > scripts/ad001-pinned-hashes.txt.new
#     mv scripts/ad001-pinned-hashes.txt.new scripts/ad001-pinned-hashes.txt
#   and cite the amendment in the commit message.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
PINNED_FILE="${SCRIPT_DIR}/ad001-pinned-hashes.txt"

if [[ ! -f "${PINNED_FILE}" ]]; then
  echo "error: pinned hashes file not found: ${PINNED_FILE}" >&2
  exit 2
fi

# Pick the right sha256 binary. macOS (and some *BSDs) ship `shasum`,
# Linux distros ship `sha256sum`. Fall back to `openssl` if neither is
# present (e.g. minimal containers). All three emit the hash in the
# first whitespace-separated field.
if command -v sha256sum > /dev/null 2>&1; then
  sha_cmd=(sha256sum)
elif command -v shasum > /dev/null 2>&1; then
  sha_cmd=(shasum -a 256)
elif command -v openssl > /dev/null 2>&1; then
  # Wrap openssl in a function so we can still pipe a filename in.
  sha_cmd=(__openssl_sha256)
  __openssl_sha256() {
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  }
else
  echo "error: none of sha256sum, shasum, or openssl is available" >&2
  exit 2
fi

drift=0
checked=0

while IFS= read -r line || [[ -n "${line}" ]]; do
  # Skip comment lines and blank lines — keep the pinned file
  # human-editable without breaking this loop.
  [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue

  # Expected line format: "<sha256>  <repo-relative-path>"
  # (two-space separator, matches `shasum` + `sha256sum` output).
  expected_sha="$(echo "${line}" | awk '{print $1}')"
  path="$(echo "${line}" | awk '{print $2}')"

  if [[ -z "${expected_sha}" || -z "${path}" ]]; then
    echo "error: malformed line in ${PINNED_FILE}: ${line}" >&2
    exit 2
  fi

  target="${REPO_ROOT}/${path}"

  if [[ ! -f "${target}" ]]; then
    echo "AD-001 c' violation: ${path} is missing on disk." >&2
    echo "  Constitutional amendment required. See specs/002-standalone-gateway-vertical-slice/plan.md AD-001." >&2
    drift=1
    continue
  fi

  if [[ "${sha_cmd[0]}" == "__openssl_sha256" ]]; then
    actual_sha="$(__openssl_sha256 "${target}")"
  else
    actual_sha="$("${sha_cmd[@]}" "${target}" | awk '{print $1}')"
  fi

  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "AD-001 c' violation: ${path} SHA drift." >&2
    echo "  expected: ${expected_sha}" >&2
    echo "  actual:   ${actual_sha}" >&2
    echo "  Constitutional amendment required. See specs/002-standalone-gateway-vertical-slice/plan.md AD-001." >&2
    drift=1
  fi

  checked=$((checked + 1))
done < "${PINNED_FILE}"

if [[ "${drift}" -eq 0 ]]; then
  echo "AD-001 c' verification passed — ${checked} pinned behaviour surface(s) unchanged."
  exit 0
else
  echo "" >&2
  echo "AD-001 c' verification FAILED. See messages above." >&2
  exit 1
fi
