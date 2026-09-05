#!/usr/bin/env bash
# r5e claude-code setup — point Claude Code at the gateway's proxy listener
# (spec 012 S2). Sourced by bin/r5e; also runnable standalone for tests:
#
#   R5E_PROXY_PORT=4443 bash bin/lib/claude-code-setup.sh [--write-settings]
#
# Prints the two exports Claude Code needs. With --write-settings, merges
# {"env": {"ANTHROPIC_BASE_URL": ..., "NO_PROXY": ...}} into
# $HOME/.claude/settings.json (created if absent; a symlink is written
# through to its target; other keys untouched; a timestamped backup is
# written first; the diff is printed). This is what the Claude desktop
# app's Code tab reads, per plan §10.
#
# Only stock tools plus python3 (preferred) or jq for the JSON merge.

claude_code_setup() {
  local write=0 arg
  for arg in "$@"; do
    case "$arg" in
      --write-settings) write=1 ;;
      -h|--help)
        echo "usage: r5e claude-code setup [--write-settings]"
        echo "  prints ANTHROPIC_BASE_URL / NO_PROXY exports; --write-settings merges them"
        echo "  into \$HOME/.claude/settings.json (backup + diff, never clobbers other keys)"
        return 0 ;;
      *) echo "r5e claude-code setup: unknown option '$arg'" >&2; return 3 ;;
    esac
  done

  local port="${R5E_PROXY_PORT:-4443}"
  local base_url="${R5E_CLAUDE_CODE_BASE_URL:-http://localhost:${port}}"
  local no_proxy="localhost,127.0.0.1"

  echo "# Claude Code -> r5e gateway (proxy listener on ${base_url})"
  echo "export ANTHROPIC_BASE_URL=${base_url}"
  echo "export NO_PROXY=${no_proxy}"
  echo "# Then: claude -p \"reply with the single word ok\"   (existing claude.ai login or API key is forwarded as-is)"
  echo "# Persist for the Claude desktop app's Code tab: bin/r5e claude-code setup --write-settings"

  [ "$write" -eq 1 ] || return 0

  local dir="${HOME}/.claude" file="${HOME}/.claude/settings.json"

  # Pick the merge tool BEFORE touching the filesystem, so a machine with
  # neither leaves no backup/created file behind.
  local merger=""
  if command -v python3 >/dev/null 2>&1; then
    merger=python3
  elif command -v jq >/dev/null 2>&1; then
    merger=jq
  else
    echo "r5e claude-code setup: need python3 or jq to merge ${file}" >&2
    return 3
  fi

  mkdir -p "$dir"

  # A symlinked settings.json (dotfiles repo) is written through to its
  # target; replacing the link itself would silently detach the dotfile.
  if [ -L "$file" ]; then
    local target
    target="$(readlink -f "$file")" || target=""
    if [ -z "$target" ]; then
      echo "r5e claude-code setup: ${file} is a symlink that cannot be resolved; left untouched" >&2
      return 1
    fi
    echo "# symlink: ${file} -> ${target}"
    file="$target"
  fi

  if [ -f "$file" ]; then
    local backup="${file}.bak.$(date +%Y%m%d%H%M%S)"
    cp -p "$file" "$backup"
    echo "# backup: ${backup}"
  else
    printf '{}\n' > "$file"
    echo "# created: ${file}"
  fi

  # bin/r5e runs under `set -euo pipefail`: a plain failing command here
  # would abort the script before any cleanup. `|| rc=$?` keeps the failure
  # in-band so the message prints and the temp file is removed.
  local tmp="${file}.tmp.$$" rc=0
  if [ "$merger" = python3 ]; then
    python3 - "$file" "$base_url" "$no_proxy" > "$tmp" <<'PY' || rc=$?
import json, sys
path, base_url, no_proxy = sys.argv[1:4]
with open(path, encoding="utf-8") as f:
    raw = f.read()
data = json.loads(raw) if raw.strip() else {}
if not isinstance(data, dict):
    sys.exit("settings.json top level is not an object; refusing to modify")
env = data.get("env")
if env is None:
    env = {}
if not isinstance(env, dict):
    sys.exit("settings.json 'env' is not an object; refusing to modify")
env["ANTHROPIC_BASE_URL"] = base_url
env["NO_PROXY"] = no_proxy
data["env"] = env
json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
PY
  else
    jq --arg b "$base_url" --arg n "$no_proxy" \
      '(.env //= {}) | .env.ANTHROPIC_BASE_URL = $b | .env.NO_PROXY = $n' "$file" > "$tmp" || rc=$?
  fi

  if [ "$rc" -ne 0 ] || [ ! -s "$tmp" ]; then
    rm -f "$tmp"
    echo "r5e claude-code setup: merge failed (${merger} exit ${rc}); ${file} left untouched" >&2
    return 1
  fi

  echo "# diff (${file}):"
  diff -u "$file" "$tmp" | sed 's/^/  /' || true
  mv "$tmp" "$file"
  echo "# wrote ${file} (env.ANTHROPIC_BASE_URL, env.NO_PROXY)"
}

# Standalone invocation (tests): run when executed, not when sourced.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  claude_code_setup "$@"
fi
