#!/bin/sh
# policy-sync (spec 012 S5): keep one file from a git repo equal to the
# Cedar bundle the gateway evaluates.
#
# Runs in `alpine/git` (busybox sh, no bash). Loop:
#
#   1. Shallow-fetch R5E_POLICY_GIT_REF from R5E_POLICY_GIT_URL into
#      $WORK and reset the checkout to it (branch, tag, or full sha).
#   2. sha256 R5E_POLICY_GIT_PATH in the checkout. If it differs from the
#      bundle currently in $DEST (or $DEST is still the entrypoint's
#      symlink to the checkout default), write a temp file next to $DEST
#      and `mv` it into place. rename(2) is atomic and replaces a symlink
#      rather than following it, so the gateway's poller sees a new inode
#      with complete contents, never a half-written file.
#   3. Log the commit sha + bundle sha256 on every change. Sleep
#      R5E_POLICY_GIT_INTERVAL seconds. Repeat.
#
# Nothing here validates Cedar: the gateway parses the bundle on reload
# and keeps the previous one if the new one fails (see /readyz "policy").
# Nothing here ever deletes $DEST: a fetch error, a missing file, or a
# bad URL leaves the current bundle in place and is retried next tick.
#
# Auth: R5E_POLICY_GIT_TOKEN (https only) is handed to git through a
# credential helper that reads it from the environment, so it never
# appears on a command line, in `ps`, or in this log. Keep it in .env.
set -u

URL="${R5E_POLICY_GIT_URL:-}"
REF="${R5E_POLICY_GIT_REF:-main}"
FILE="${R5E_POLICY_GIT_PATH:-policy/bundle.cedar}"
INTERVAL="${R5E_POLICY_GIT_INTERVAL:-30}"
DEST="${R5E_POLICY_DEST:-/policy/bundle.cedar}"
WORK="${R5E_POLICY_WORK:-/work}"
TOKEN="${R5E_POLICY_GIT_TOKEN:-}"
USERNAME="${R5E_POLICY_GIT_USERNAME:-oauth2}"

log() { printf '[policy-sync] %s\n' "$*"; }

# Log the URL with any userinfo removed, in case someone put the token in
# the URL despite the note above.
redacted_url() { printf '%s' "$1" | sed -E 's#(://)[^/@]+@#\1<redacted>@#'; }

if [ -z "$URL" ]; then
  log "R5E_POLICY_GIT_URL is unset; nothing to sync. The gateway keeps serving ./policy/bundle.cedar."
  log "Set R5E_POLICY_GIT_URL in .env (see .env.example) and start again with: docker compose --profile git-policy up -d"
  exit 0
fi

case "$INTERVAL" in
  ''|*[!0-9]*) log "R5E_POLICY_GIT_INTERVAL must be a whole number of seconds (got '$INTERVAL')"; exit 78 ;;
esac

export GIT_TERMINAL_PROMPT=0
# The checkout is ours, but a file:// source bind-mounted from the host is
# usually owned by another uid; git >= 2.35.2 refuses such repos unless
# they are marked safe. This sidecar reads repositories only.
git config --global --add safe.directory '*'

if [ -n "$TOKEN" ]; then
  case "$URL" in
    https://*) ;;
    *) log "R5E_POLICY_GIT_TOKEN is set but the URL is not https://; the token applies to https only" ;;
  esac
  # A helper that answers with the credentials from the environment. git
  # invokes it as `sh -c '<helper> get'`; the env is inherited, the token
  # is never interpolated into the string.
  git config --global credential.helper \
    '!f() { printf "username=%s\npassword=%s\n" "$R5E_POLICY_GIT_USERNAME" "$R5E_POLICY_GIT_TOKEN"; }; f'
  export R5E_POLICY_GIT_USERNAME="$USERNAME" R5E_POLICY_GIT_TOKEN="$TOKEN"
fi

sha256_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

if [ ! -d "$WORK/.git" ]; then
  git init -q "$WORK" && git -C "$WORK" remote add origin "$URL" \
    || { log "cannot initialise $WORK"; exit 1; }
fi

# What the gateway is serving right now (follows the entrypoint's symlink
# so an unchanged default is recognised as already in place).
current="$(sha256_of "$DEST")"
log "watching $(redacted_url "$URL") ref=$REF path=$FILE every ${INTERVAL}s -> $DEST (current sha256=${current:-none})"

# Run git, prefixing anything it prints; return git's own status (a
# pipeline's status would be sed's, so the output is captured first).
git_step() {
  out="$(git -C "$WORK" "$@" 2>&1)"
  rc=$?
  [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/[policy-sync] git: /'
  return $rc
}

while :; do
  if git_step fetch -q --depth 1 origin "$REF" && git_step reset -q --hard FETCH_HEAD; then
    commit="$(git -C "$WORK" rev-parse HEAD)"
    src="$WORK/$FILE"
    if [ -f "$src" ]; then
      new="$(sha256_of "$src")"
      if [ "$new" != "$current" ] || [ -L "$DEST" ]; then
        tmp="$DEST.tmp.$$"
        if cp "$src" "$tmp" && mv -f "$tmp" "$DEST"; then
          current="$new"
          log "updated $DEST from commit=$commit bundle_sha256=$new"
        else
          rm -f "$tmp"
          log "could not write $DEST (commit=$commit); keeping the current bundle"
        fi
      fi
    else
      log "commit=$commit has no $FILE; keeping the current bundle"
    fi
  else
    log "fetch of $REF from $(redacted_url "$URL") failed; keeping the current bundle, retrying in ${INTERVAL}s"
  fi
  sleep "$INTERVAL"
done
