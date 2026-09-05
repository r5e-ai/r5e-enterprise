# Session Lifecycle & Attestation Chain (Deliverable L)

**Status**: Phase-1 contract. **Binding for Feature 002+
Gateway/Runtime session-management implementation.**

**Requirements**: FR-036 (sessions are atomic commit units), FR-037
(session epochs + interim commits), FR-038 (two-axis completeness),
FR-040 (bounded commit retry), FR-041 (turn_id parent for parallel tool
calls), FR-044 (explicit session state machine), FR-029 (cancellation).
**Canonical code source**:
`apps/recurse_shared/lib/recurse_shared/session/state_machine.ex`
(transitions encoded as the authoritative allow-table; this document
diagrams and narrates what that module defines).

## The seven session states

| State                     | Meaning                                                                                    | Terminal |
|---------------------------|--------------------------------------------------------------------------------------------|:--------:|
| `active`                  | Session in progress; events being emitted; per-event `verification_level` starts `signed`, advances to `local_inclusion_verified` as the current epoch fills | no |
| `interim_committed`       | An interim epoch root just landed in the global ledger; events in that epoch advance to `global_inclusion_verified`; session is still open | no |
| `commit_retry`            | A commit attempt (final or interim) failed; bounded backoff in progress per FR-040; affected events remain at `local_inclusion_verified` | no |
| `commit_retry_exhausted`  | Retries hit the configured bound; `recurse_ledger_commit_backoff_exhausted_total` alert fires; events frozen at `local_inclusion_verified` awaiting operator action | no |
| `aborted`                 | Explicit abort by operator or Runtime (unrecoverable error, forced tear-down); no further events written | **yes** |
| `cancelled`               | Caller-initiated graceful cancellation per FR-029 (client DELETEs operation OR closes SSE); server emits terminal cancellation frame | **yes** |
| `committed`               | Final epoch committed; ALL events at `global_inclusion_verified`; session closed successfully | **yes** |

Terminal states have no outgoing transitions.

## State transition diagram

```
                ┌──────────────────────────────────────────────────┐
                │                                                  │
                │                                                  ▼
                │                                          ┌───────────────┐
                │                                          │  cancelled    │◀─── FR-029
                │                                          │  (terminal)   │     client DELETEs op or closes SSE
                │                                          └───────────────┘
                │                                                  ▲
                │                                                  │
                │                                          ┌───────────────┐
                │                                          │  aborted      │◀─── operator / Runtime unrecoverable
                │                                          │  (terminal)   │
                │                                          └───────────────┘
                │                                                  ▲
                │          ┌──────────┐                            │
                │          │          │◀──── interim commit lands  │
                │          │          │      (FR-037)              │
                │          ▼          │                            │
  (boot)─────▶ ┌──────────────┐    ┌──────────────────┐            │
              │              │───▶│                   │─── commit ─┤
              │   active     │    │ interim_committed │   landed   │
              │              │◀───│                   │   at end   │
              └──────────────┘    └──────────────────┘   of sess.  │
                 │     ▲                 │                         │
                 │     │                 │                         ▼
                 │     │                 │                  ┌───────────────┐
      commit     │     │ retry       commit final           │  committed    │
      attempt    │     │ succeeded   (session-end)          │  (terminal)   │
      fails      │     │ as interim                         └───────────────┘
      (FR-040)   │     │
                 ▼     │
              ┌──────────────┐     retry
              │ commit_retry │─── exhausted ─────▶ ┌──────────────────────────┐
              │              │     (FR-040          │ commit_retry_exhausted   │
              └──────────────┘     bound hit)       │ (alert fires;            │
                                                    │ operator intervention)   │
                                                    └──────────────────────────┘
                                                              │
                                                              ▼ (operator DELETE / abort)
                                                      aborted | cancelled
```

## Full transition table

Every pair below is **present** in
`Recurse.Shared.Session.StateMachine`'s `@transitions` allow-table.
Any pair NOT in this table returns `{:error, :invalid_transition}`.

| From                       | To                           | Trigger                                                             |
|----------------------------|------------------------------|---------------------------------------------------------------------|
| `active`                   | `interim_committed`          | Interim epoch root committed per FR-037 threshold (10k events or 60m) |
| `interim_committed`        | `active`                     | New events arriving; next epoch's events begin accumulating         |
| `active`                   | `commit_retry`               | Ledger commit attempt failed per FR-040                             |
| `commit_retry`             | `commit_retry_exhausted`     | Retry backoff bound reached                                         |
| `commit_retry`             | `interim_committed`          | Retry succeeded (either interim or final commit)                    |
| `interim_committed`        | `committed`                  | Final epoch committed at session end (terminal)                     |
| `active`                   | `cancelled`                  | FR-029 client cancellation                                          |
| `active`                   | `aborted`                    | Operator / Runtime abort                                            |
| `interim_committed`        | `cancelled`                  | FR-029 cancellation during `interim_committed`                      |
| `interim_committed`        | `aborted`                    | Abort during `interim_committed`                                    |
| `commit_retry`             | `cancelled`                  | FR-029 cancellation during `commit_retry`                           |
| `commit_retry`             | `aborted`                    | Abort during `commit_retry`                                         |
| `commit_retry_exhausted`   | `cancelled`                  | FR-029 cancellation after operator alert                            |
| `commit_retry_exhausted`   | `aborted`                    | Operator-driven abort after retry exhaustion                        |

No other transitions are allowed. In particular:

- NO transition out of `committed` / `cancelled` / `aborted` (terminal).
- NO direct `active → committed`; commit at session-end goes
  `active → interim_committed → committed`. The interim step ensures
  the epoch-root Merkle proof exists before the session is marked
  final.
- NO `commit_retry_exhausted → active` or `→ interim_committed`.
  Exhaustion is a **one-way gate** requiring operator intervention;
  the operator either tears down (`aborted`) or the client cancels.

## Relationship to `verification_level` (FR-038 axis 1)

`session_state` (FR-044) governs session-lifecycle; `verification_level`
(FR-038) governs per-event proof strength. They interact like so:

| Session state              | Events emitted in THIS state start at | Events written in PRIOR states are now at                          |
|----------------------------|---------------------------------------|---------------------------------------------------------------------|
| `active`                   | `signed`                              | `signed` or `local_inclusion_verified` as Merkle tree accumulates  |
| `interim_committed`        | `signed` (new epoch starts)           | Prior-epoch events advance to `global_inclusion_verified`           |
| `commit_retry`             | `signed`                              | No change (pending commit is what the retry is for)                 |
| `commit_retry_exhausted`   | BLOCKED — no new events accepted      | Frozen at `local_inclusion_verified`                                |
| `cancelled`                | (terminal; no new events)             | Frozen at whatever level they had at cancellation                    |
| `aborted`                  | (terminal; no new events)             | Frozen at whatever level they had at abort                           |
| `committed`                | (terminal; no new events)             | All events at `global_inclusion_verified`                            |

The monotonic progression `signed → local_inclusion_verified →
global_inclusion_verified` is preserved through every transition.

## Interim epochs (FR-037)

Sessions are partitioned into epochs at:

- **Event-count threshold**: default `interim_commit_event_count = 10000`.
- **Wall-clock threshold**: default `interim_commit_threshold_minutes = 60`.
- **Session end**: the final epoch always closes.

At each epoch boundary the Runtime:

1. Computes the epoch's Merkle root (hash of all attestation envelope
   hashes in epoch order).
2. Writes an epoch-close entry to the WAL-backed CAS.
3. Submits the root to the `LedgerProvider` for global commit.
4. On success → `interim_committed`; prior-epoch events advance to
   `global_inclusion_verified`.
5. On failure → `commit_retry`; events frozen at
   `local_inclusion_verified`.

Session chain position (FR-021 `session_chain_position`) is monotonic
across epochs — it does NOT reset at an epoch boundary. Epoch boundary
is metadata only; event indexing is continuous.

## Ledger-down path (FR-040)

Bounded retry per FR-040 with exponential backoff:

```
attempt 1   t=0      backoff 1s
attempt 2   t=1s     backoff 2s
attempt 3   t=3s     backoff 5s
attempt 4   t=8s     backoff 15s
attempt 5   t=23s    backoff 60s
attempt 6   t=83s    backoff 300s (5m)
attempt 7   t=383s   backoff 900s (15m)
attempt 8   t=1283s (~21m) backoff 1800s (30m)
attempt 9   → commit_retry_exhausted @ ~51m
```

(Exact numbers configurable per tier; `tier_config.schema.json` holds
the `ledger_commit_retry_bound_seconds` field.)

On exhaustion:

- `session_state := commit_retry_exhausted`.
- `commit_retry_exhausted: true` surfaces in the outer container of
  every receipt in this session (FR-021 / SC-015).
- `recurse_ledger_commit_backoff_exhausted_total` counter increments.
- Alert routes per tier-config `alerting_sinks`.
- Affected events are **not lost** — they persist in the WAL-backed
  CAS at `local_inclusion_verified`. An operator must:
  - (a) restore ledger connectivity, then manually re-trigger commit
    (Feature 002+ operator API), which transitions the state to
    `interim_committed`; **NOT** automatically — the exhaustion is a
    hard gate; or
  - (b) `abort` the session (state → `aborted`) after deciding the
    events are not retainable.

## Cancellation path (FR-029)

The cancellation contract:

- **Sync ops**: client issues `DELETE /v1/operations/{operation_id}`.
- **SSE streams**: client closes the TCP connection.

Server behavior:

1. Mark the session `cancelled` via state machine.
2. Emit a terminal SSE frame (if applicable) with
   `event: cancellation` and correlation ID.
3. Flush an in-flight epoch if partially accumulated (same
   `interim_committed` → `committed` path would run, but from
   `cancelled` state this is **not** allowed — the cancellation is
   terminal even if some events weren't globally-committed).
4. Events remain in the WAL CAS at whatever `verification_level` they
   had at cancellation time. They will NEVER advance further (the
   session is closed).

This is the deliberate contract: a cancelled session MAY have events
at `local_inclusion_verified` that never reach
`global_inclusion_verified`. The outer container surfaces this as
`session_state: cancelled` + `verification_level: local_inclusion_verified`.
Auditors interpret per `cli_verifier_procedure.md` Step 6.

## Worked example — 10000-event session with 2 interim commits and 1 ledger outage

Scenario: an agent runs a 3-hour batch job that produces ~10000
attestation events. Default thresholds mean one interim commit per
hour. Midway through the final commit, the `LedgerProvider` goes
offline for 8 minutes.

```
t=0h00m   session opens                                              state: active
                                                                     epoch 0 accumulating
                                                                     session_chain_position: 0

t=0h58m   event #4000 emitted                                        state: active
                                                                     epoch 0, position 3999

t=1h00m   event #4200 triggers interim commit threshold
          (time-based, minutes=60)
          Runtime seals epoch 0 root                                 epoch 0 root = sha256:R0
          LedgerProvider.commit(R0) → OK                             state: interim_committed
          events 0..4199 advance to global_inclusion_verified
          next event starts epoch 1                                  state: active (epoch 1)

t=2h00m   event #7900 triggers next interim commit
          epoch 1 root = sha256:R1
          LedgerProvider.commit(R1) → OK                             state: interim_committed
          events 4200..7899 advance to global_inclusion_verified
          next event starts epoch 2                                  state: active (epoch 2)

t=2h57m   event #9800 emitted                                        state: active
                                                                     epoch 2, position 9799

t=3h00m   session-end commit requested
          epoch 2 root = sha256:R2
          LedgerProvider.commit(R2) → TIMEOUT (ledger offline)       state: commit_retry
                                                                     attempt 1, backoff 1s
          attempt 2 (+1s)  → TIMEOUT                                 attempt 2, backoff 2s
          attempt 3 (+3s)  → TIMEOUT                                 attempt 3, backoff 5s
          attempt 4 (+8s)  → TIMEOUT                                 attempt 4, backoff 15s
          attempt 5 (+23s) → TIMEOUT                                 attempt 5, backoff 60s
          attempt 6 (+83s, ~1m23s) → TIMEOUT                         attempt 6, backoff 300s
          attempt 7 (+383s, ~6m23s) → TIMEOUT                        attempt 7, backoff 900s
          attempt 8 (+1283s, ~21m) → OK  (ledger restored @ ~8m real-time;
                                          this attempt fires inside the 15m backoff window)
          LedgerProvider.commit(R2) → OK                             state: interim_committed
          events 7900..9999 advance to global_inclusion_verified
          final-commit path:                                         state: committed (terminal)
                                                                     all 10000 events now at
                                                                     global_inclusion_verified

Final receipt state:
  session_id: 01HQXZ9RXKSESS...
  session_state: committed
  all events: verification_level=global_inclusion_verified
  commit_retry_exhausted: false  (retry succeeded before bound)
```

Alternative ending — if the ledger outage had lasted past attempt 9
(~51m):

```
...
attempt 9 @ t=~3h51m → TIMEOUT                                       state: commit_retry_exhausted
                                                                     alert fires
                                                                     events 7900..9999 frozen
                                                                     at local_inclusion_verified
                                                                     commit_retry_exhausted: true
                                                                     in outer container
operator action required — see cli_verifier_procedure.md §Step 6
```

Events from epochs 0 and 1 remain at `global_inclusion_verified`
regardless — the outage affected only the final commit. FR-037's
epoch partitioning is precisely what gives this property.

## Programmatic check

The state machine is property-tested in
`apps/recurse_shared/test/session/state_machine_property_test.exs`
against the invariant: "for every `(from, to)` pair not in the
`@transitions` allow-table, `transition/2` returns
`{:error, :invalid_transition}`." Any implementation of session
handling in Feature 002+ MUST route through
`Recurse.Shared.Session.StateMachine.transition/2` and surface its
errors to the caller; direct state mutation bypassing the validator
is a review-blocker.

## Cross-references

- `apps/recurse_shared/lib/recurse_shared/session/state_machine.ex` —
  canonical implementation.
- `apps/recurse_shared/lib/recurse_shared/session/session.ex` —
  `Session` struct carrying `:state`.
- `apps/recurse_shared/lib/recurse_shared/session/epoch.ex` —
  `Epoch` struct (FR-037 partitioning unit).
- `attestation.schema.json` — `outer.session_state` enum matches
  this document's seven states.
- `cli_verifier_procedure.md` §Step 6 — auditor-side interpretation
  of `session_state` + `verification_level`.
- `tier_config.schema.json` — `interim_commit_event_count`,
  `interim_commit_threshold_minutes`, `ledger_commit_retry_bound_seconds`.
- FR-040 specifies backoff bounds; exact schedule per tier.
