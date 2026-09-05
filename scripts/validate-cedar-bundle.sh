#!/usr/bin/env bash
# validate-cedar-bundle.sh — parse + stability-check a Cedar policy bundle
# via the F001-shipped `mix recurse.cedar.stability_check` task. F002 T012.
#
# Usage:
#   ./scripts/validate-cedar-bundle.sh path/to/bundle.cedar
#
# Exits 0 on pass, non-zero on parse/stability failure.

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <path-to-bundle.cedar>" >&2
  exit 2
fi

BUNDLE="$1"

if [ ! -f "${BUNDLE}" ]; then
  echo "validate-cedar-bundle.sh: file not found: ${BUNDLE}" >&2
  exit 1
fi

if ! command -v mix >/dev/null 2>&1; then
  echo "validate-cedar-bundle.sh: mix not found in PATH (Elixir toolchain required)" >&2
  exit 1
fi

# The task is shipped by F001 at apps/recurse_shared/lib/mix/tasks/recurse.cedar.stability_check.ex.
exec mix recurse.cedar.stability_check "${BUNDLE}"
