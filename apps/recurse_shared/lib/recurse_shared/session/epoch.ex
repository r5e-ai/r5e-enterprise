defmodule Recurse.Shared.Session.Epoch do
  @moduledoc """
  Session Epoch struct per FR-037.

  Long-running sessions are partitioned into epochs for bounded commit
  latency. Epoch boundaries occur at:

    * interim commit — configurable event-count or time threshold
      (default `interim_commit_event_count: 10_000` or
      `interim_commit_threshold_minutes: 60`, whichever first)
    * session end — final epoch closes on termination

  Each epoch produces an `epoch_root` (Merkle root bytes) committed to
  the global ledger.

  ## Fields

    * `session_chain_epoch` — monotonic per-session integer starting at 0
    * `epoch_start` — RFC 3339 UTC string; first event's timestamp
    * `epoch_end` — RFC 3339 UTC string or `nil` while epoch is open
    * `epoch_root` — SHA-256 Merkle root bytes of the in-session chain;
      `nil` until the epoch closes
    * `event_count` — bounded by Tier Configuration
    * `committed?` — true after the global-ledger commit lands
  """

  @type t :: %__MODULE__{
          session_chain_epoch: non_neg_integer(),
          epoch_start: String.t(),
          epoch_end: String.t() | nil,
          epoch_root: binary() | nil,
          event_count: non_neg_integer(),
          committed?: boolean()
        }

  @enforce_keys [:session_chain_epoch, :epoch_start]
  defstruct session_chain_epoch: 0,
            epoch_start: nil,
            epoch_end: nil,
            epoch_root: nil,
            event_count: 0,
            committed?: false
end
