#!/usr/bin/env bash
# compute-tier-config-hash.sh — write the SHA-256 of a tier-config YAML to a
# sibling `.sha256` file. F002 T012 + FR-027 / FR-033 out-of-band integrity.
#
# Usage:
#   ./scripts/compute-tier-config-hash.sh path/to/tier-config.yaml
#
# Writes `path/to/tier-config.sha256` containing a single lowercase hex digest
# (no trailing filename, no newline) so the Gateway can byte-compare at boot.

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <path-to-yaml>" >&2
  exit 2
fi

SRC="$1"

if [ ! -f "${SRC}" ]; then
  echo "compute-tier-config-hash.sh: file not found: ${SRC}" >&2
  exit 1
fi

# Pick whichever sha256 tool the host has. macOS ships `shasum`; Linux ships
# `sha256sum`. Both produce the same `<hex>  <filename>` format.
if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD="shasum -a 256"
else
  echo "compute-tier-config-hash.sh: need sha256sum or shasum in PATH" >&2
  exit 1
fi

HASH=$(${HASH_CMD} "${SRC}" | awk '{print $1}')

DEST="${SRC%.yaml}.sha256"
# Strip trailing newline — byte-for-byte match at the Gateway integrity check.
printf '%s' "${HASH}" > "${DEST}"

echo "wrote ${DEST}: ${HASH}"
