defmodule Recurse.Gateway.PolicyBundleRef do
  @moduledoc """
  Immutable reference to a loaded Cedar policy bundle.

  Per F002 data-model.md §`Recurse.Gateway.PolicyBundleRef`, every request
  captures a `%PolicyBundleRef{}` at ingress and evaluates against THAT
  reference for its full lifetime (FR-010 per-request snapshot). If the
  bundle reloads mid-request, in-flight traffic keeps its captured
  reference and never sees a torn state.

  The struct is write-once: the `BundleLoader` GenServer (T046) owns the
  write side; readers use `:persistent_term` to fetch the current
  reference with zero locking. There are no `put_*` / `update_*` helpers
  by design.

  ## Fields

    * `:bundle_id` — opaque identifier (currently the hex-encoded canonical hash).
    * `:canonical_hash` — 32-byte SHA-256 of `JCS(PolicySet::to_json())` per FR-039.
    * `:loaded_at` — `DateTime.t()` stamped at load time (UTC).
    * `:evaluator_handle` — opaque handle the Evaluator uses (currently the
      Cedar source bytes; future impls may substitute a pre-compiled
      handle without changing the public shape).
    * `:bundle_bytes` — Cedar policy source as read from disk.
  """

  @enforce_keys [:bundle_id, :canonical_hash, :loaded_at, :evaluator_handle, :bundle_bytes]
  defstruct [:bundle_id, :canonical_hash, :loaded_at, :evaluator_handle, :bundle_bytes]

  @type t :: %__MODULE__{
          bundle_id: binary(),
          canonical_hash: <<_::256>>,
          loaded_at: DateTime.t(),
          evaluator_handle: term(),
          bundle_bytes: binary()
        }
end
