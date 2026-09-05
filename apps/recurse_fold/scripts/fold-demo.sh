#!/usr/bin/env bash
# fold-demo.sh — Story 1 of spec 010, under **signed** admission (spec 011).
#
# Usage (from apps/recurse_fold):
#   ./scripts/fold-demo.sh
#
# Throwaway state, throwaway port, safe to repeat. It never commits, pushes,
# or touches r5e-kernel/.r5e.
#
# The canonical sequence for one turn of agent work, in chain order:
#   0. the fold's own authority: a key under the data dir, endorsed by the
#      node key for kinds ["*"] with the right to issue (spec 011 §10)
#   1. PUT /cas the prompt bytes                      (an act, not an upload)
#   2. admit Prompt{contentRef}                       (artifact, content-named)
#   3. admit LlmCall{model, prompt}                   (event; shape: cedar.…/LlmCall)
#   4. admit ToolCall `rm -rf`             → DENIED   (shape: cedar.…/ToolCall)
#   5. admit ToolCall `ls -la`             → ADMITTED (the deny is selective)
#   6. PUT /cas the completion bytes
#   7. admit Completion{contentRef}
#   8. admit LlmResponse{toolCalls: [denied, admitted]}
#   9. admit ToolResult for the call that ran
#  10. export
#  11. RESTART the node over the same data dir (replay), export again, and
#      verify that offline with r5e-core's escript, --posture house
#
# Why the acts run in Elixir and not in curl: since spec 011 every admission
# carries an ed25519 signature over the canonical request object, and the
# key is the fold's own, held under the data directory. A shell cannot build
# that envelope, and giving it one would mean handing a private key to a
# script. So the acts go through `Recurse.Fold.admit/3` — the same function
# spec 012's LLM proxy calls — inside the node that holds the key, and this
# script orchestrates: boot, act, restart, export, verify, and check the
# verifier's own output line by line.
#
# What is being shown: the policy text, the presentation (PolicyShape), the
# engine build, the exact bytes handed to Cedar **and the authority the
# actor was acting under** are all on the chain, and the denial's receipt
# cites every one of them by address. The 2026-07-27 enterprise demo policy
# runs unchanged — conformance, not rewrite.

set -euo pipefail

# Erlang's stdout defaults to latin1 when the locale says nothing; the
# verifier's prose is full of em dashes. Ask for UTF-8 so the output you read
# is the output the verifier wrote.
export LC_ALL="${LC_ALL:-en_US.UTF-8}"

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_DIR="$(cd "$APP_DIR/../../../r5e-core" 2>/dev/null && pwd)" || {
  echo "ABORT: ../../../r5e-core not found next to r5e-enterprise." >&2; exit 1; }

DATA_DIR="$APP_DIR/.r5e-demo"
PORT="${R5E_PORT:-4546}"
VERIFY_OUT="$APP_DIR/fold-demo-verification.txt"
ACTS_JSON="$DATA_DIR/demo-acts.json"
RESTART_JSON="$DATA_DIR/demo-restart.json"

for bin in elixir mix curl jq; do
  command -v "$bin" >/dev/null || { echo "ABORT: missing dependency: $bin" >&2; exit 1; }
done
[[ -f "$APP_DIR/mix.exs" ]] || { echo "ABORT: $APP_DIR is not the recurse_fold app." >&2; exit 1; }

# Throwaway by construction. This is NOT r5e-kernel/.r5e.
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
echo "== fold demo == throwaway state in $DATA_DIR, port $PORT. Repeat freely."

cd "$APP_DIR"
echo "-- mix deps.get (quiet) --"
mix deps.get >/dev/null

FAILURES=0
expect() { # expect LABEL EXPECTED ACTUAL
  if [[ "$3" != "$2" ]]; then
    echo "FAIL: $1 — expected '$2', got '$3'" >&2
    FAILURES=$((FAILURES + 1))
  else
    echo "-- $1: $3 (as expected) --"
  fi
}

assert_address() { # assert_address LABEL VALUE PREFIX
  case "$2" in
    "$3"*) echo "-- $1: $2 --" ;;
    *) echo "FAIL: $1 — expected an address starting '$3', got '$2'" >&2
       FAILURES=$((FAILURES + 1)) ;;
  esac
}

run_phase() { # run_phase PHASE SUMMARY_PATH
  R5E_DATA_DIR="$DATA_DIR" R5E_PORT="$PORT" mix run scripts/fold_demo.exs "$1" "$2"
}

# ---------- steps 0-10: boot, act, export ----------
run_phase acts "$ACTS_JSON"

FOLD_KEY="$(jq -r '.foldKey' "$ACTS_JSON")"
NODE_KEY="$(jq -r '.nodeKey' "$ACTS_JSON")"
ENDORSEMENT="$(jq -r '.endorsement' "$ACTS_JSON")"
BUNDLE_ADDR="$(jq -r '.bundle' "$ACTS_JSON")"
SOURCE_ADDR="$(jq -r '.source' "$ACTS_JSON")"
EVAL_ADDR="$(jq -r '.evaluation' "$ACTS_JSON")"
BUNDLE_BEFORE="$(jq -r '.bundlePath' "$ACTS_JSON")"
EVENTS_BEFORE="$(jq -r '.events' "$ACTS_JSON")"

assert_address "the fold signs under a key id"      "$FOLD_KEY"    "key:ed25519:sha256:"
assert_address "endorsed by the node key"           "$ENDORSEMENT" "event:sha256:"
assert_address "the denial cites an evaluation record" "$EVAL_ADDR" "bytes:sha256:"
expect "the destructive ToolCall"  denied   "$(jq -r '.deniedOutcome' "$ACTS_JSON")"
expect "the harmless ToolCall"     admitted "$(jq -r '.allowedOutcome' "$ACTS_JSON")"
expect "the evaluation record carries resolvedAuthority (§11)" 1 \
  "$(jq -r '.resolvedAuthority' "$ACTS_JSON")"

if [[ "$FOLD_KEY" == "$NODE_KEY" ]]; then
  echo "FAIL: the fold is signing with the node key rather than its own." >&2
  FAILURES=$((FAILURES + 1))
fi

# ---------- 11. restart, replay, export again ----------
echo
echo "===== step 11: RESTART the node over the same data dir, then export again ====="
run_phase restart "$RESTART_JSON"

BUNDLE="$(jq -r '.bundlePath' "$RESTART_JSON")"
EVENTS_AFTER="$(jq -r '.events' "$RESTART_JSON")"

expect "the restart added no events" "$EVENTS_BEFORE" "$EVENTS_AFTER"
expect "the endorsement was found, not re-admitted" \
  "$ENDORSEMENT" "$(jq -r '.endorsement' "$RESTART_JSON")"

DERIVED_BEFORE="$(jq -c '.derivedObjects | sort' "$BUNDLE_BEFORE/manifest.json")"
DERIVED_AFTER="$(jq -c '.derivedObjects | sort' "$BUNDLE/manifest.json")"
expect "derivedObjects is a function of the log, not of uptime" \
  "$DERIVED_BEFORE" "$DERIVED_AFTER"

# ---------- verify the POST-RESTART bundle offline ----------
echo
echo "===== verify the POST-RESTART bundle offline, with --posture house ====="

STANDALONE="$CORE_DIR/verifier/recurse_verify"
if [[ ! -x "$STANDALONE" ]]; then
  echo "-- building the standalone verifier escript (one time) --"
  (cd "$CORE_DIR/verifier" && mix deps.get >/dev/null && mix escript.build >/dev/null) || true
fi

if [[ -x "$STANDALONE" ]]; then
  echo "-- verifying with r5e-core's standalone escript, unchanged --"
  "$STANDALONE" --posture house "$BUNDLE" | tee "$VERIFY_OUT"
else
  echo "-- escript unavailable; verifying in-process with the same RecurseVerify library --"
  mix run --no-start -e \
    '{:ok, r} = RecurseVerify.run(List.first(System.argv()), posture: "house"); IO.puts(RecurseVerify.format(r))' \
    "$BUNDLE" | tee "$VERIFY_OUT"
fi

# ---------- the verifier's verdict is part of the exit code ----------
check_output() { # check_output LABEL PATTERN
  if ! grep -qE "$2" "$VERIFY_OUT"; then
    echo "FAIL: $1. Read $VERIFY_OUT." >&2
    FAILURES=$((FAILURES + 1))
  fi
}

check_output "the verifier reported findings" '^\s+none -- every check above passed'
check_output "the claims line does not show exactly one denial" '^\s+claims: [0-9]+ admissions, 1 denials'
check_output "the signatures line does not show every admission signed" \
  '^\s+signatures: ([0-9]+) of \1 admissions signed and verified'
check_output "the endorsements line reports no cited chains" \
  '^\s+endorsements: [1-9][0-9]* chains cited across'
check_output "the reader posture was not stated" 'reader posture: house'
check_output "the policy line does not report the §8 evaluation records" 'cite a policy evaluation record'
check_output "the cas line does not report the kernel-derived objects as cited" 'kernel-derived \(each cited by'
check_output "the cas line does not report the derivedObjects union check" \
  "the export's list is exactly the union of the payloads' own derivedObjects"

echo
echo "================= fold demo complete ================="
echo "  fold key         : $FOLD_KEY"
echo "  node key         : $NODE_KEY  (endorsed the fold at $ENDORSEMENT)"
echo "  policy bundle    : $BUNDLE_ADDR"
echo "  policy text      : $SOURCE_ADDR"
echo "  evaluation record: $EVAL_ADDR  (the denial's exact input to Cedar)"
echo "  export bundle    : $BUNDLE  (taken AFTER the restart)"
echo "  export before    : $BUNDLE_BEFORE  (same derivedObjects, same event count)"
echo "  verifier output  : $VERIFY_OUT  (read it end to end — the not-checked block is part of the truth)"
echo "  throwaway state  : $DATA_DIR (rm -rf when done)"

if (( FAILURES > 0 )); then
  echo "  RESULT           : $FAILURES expectation(s) FAILED" >&2
  exit 1
fi
echo "  RESULT           : every expectation held"
