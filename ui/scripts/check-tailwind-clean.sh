#!/usr/bin/env bash
set -euo pipefail

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git diff --quiet -- tailwind.config.ts
else
  jj diff --quiet -- tailwind.config.ts
fi
