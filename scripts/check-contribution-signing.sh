#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Contribution signing check — first job of every merge-request pipeline.
#   DCO: every commit in the MR range carries "Signed-off-by:" for its author email.
#   CLA (AGPL repos only, R5E_REQUIRE_CLA=1): the MR author's account appears in
#   CLA-SIGNERS.md with the sha256 of the current CLA.md, or is listed in MAINTAINERS.
# Prints the failing rule and the one command that fixes it. Never touches the repo.
set -euo pipefail
# coreutils on Linux images, perl shasum on macOS; either gives the same digest.
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
base="${CI_MERGE_REQUEST_DIFF_BASE_SHA:-${1:-}}"; head="${CI_COMMIT_SHA:-HEAD}"
author="${GITLAB_USER_LOGIN:-${2:-}}"
[[ -n "$base" ]] || { echo "usage: $0 <base-sha> [author-account]"; exit 2; }
fail=0
while read -r sha; do
  email=$(git show -s --format=%ae "$sha")
  if ! git show -s --format=%B "$sha" | grep -qi "^Signed-off-by: .*<${email}>"; then
    echo "DCO: commit ${sha:0:12} lacks 'Signed-off-by:' for ${email}  -> fix: git rebase --exec 'git commit --amend --no-edit -s' ${base}"; fail=1
  fi
done < <(git rev-list --no-merges "${base}..${head}")
if [[ "${R5E_REQUIRE_CLA:-0}" == "1" && -n "$author" ]]; then
  if grep -qx "$author" MAINTAINERS 2>/dev/null; then :; else
    want="cla:sha256:$(sha256_of CLA.md)"
    if ! grep -E "^[^ ]*${author}[^ ]* +v[0-9.]+ +${want} " CLA-SIGNERS.md >/dev/null 2>&1; then
      echo "CLA: ${author} has not agreed to the current CLA.md (${want})  -> fix: read CLA.md, submit the private signature form, then open a merge request adding your line to CLA-SIGNERS.md"; fail=1
    fi
  fi
fi
[[ $fail -eq 0 ]] && echo "contribution signing: ok"
exit $fail
