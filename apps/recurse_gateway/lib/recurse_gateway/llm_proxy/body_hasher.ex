defmodule Recurse.Gateway.LlmProxy.BodyHasher do
  @moduledoc """
  Stateful streaming SHA-256 hasher for the LLM proxy's request +
  response body bytes.

  Spec source of truth:
    * Constitution Principle III (Cryptographic Provenance) — every
      LLM call produces a real `prompt_hash` + `response_hash`. These
      are the foundation of the per-traversal verifiability guarantee:
      an offline auditor reassembles the canonical bytes that crossed
      the wire and computes SHA-256 to verify the hash recorded in the
      attestation predicate.
    * Constitution Principle IV (Detached Payloads) — only the hash
      ends up in the predicate body. The raw bytes never persist to
      the ledger; storage is the existing payload-broker path (S3 +
      content-addressed). This module computes the hash WHILE the
      bytes flow past — it does NOT buffer the body.

  ## Why a thin wrapper

  `:crypto.hash_init(:sha256)` + `:crypto.hash_update/2` +
  `:crypto.hash_final/1` already implement streaming SHA-256
  correctly. The wrapper exists so:

    * The proxy code reads as `BodyHasher.update(state, bytes)`
      rather than `:crypto.hash_update(state, bytes)`. The intent is
      "incrementally hash this body chunk" — naming makes the
      audit-row provenance obvious.
    * Future implementations (e.g., a SHA-256-on-the-NIF-side
      optimisation, or a multi-algorithm wrapper if Constitution
      v2 ever moves off SHA-256) have one place to land.
    * Tests can mock this module via `Mox` if a future implementation
      needs to stub the algorithm.

  ## Iron Law (`elixir:elixir-thinking`)

    1. Mutable state across calls? No — `state` is threaded through
       function calls; each call returns the next state.
    2. Concurrent execution? No — pure transform on the caller process.
    3. Fault isolation? No — `:crypto.hash_*` functions don't fail on
       binary input; they return new state.

  All three NO → plain functions. The "state" here is opaque OTP-side
  digest context; we don't own a process to hold it.

  ## Usage

      hasher = BodyHasher.init()
      hasher = BodyHasher.update(hasher, "prompt bytes")
      hasher = BodyHasher.update(hasher, "more bytes")
      hash = BodyHasher.final(hasher)  # 32 raw bytes

  The proxy initialises ONE hasher per direction (`request_body_hasher`
  + `response_body_hasher`) at call open, threads them through the
  receive loop, and computes `final/1` at close to populate the
  attestation `prompt_hash` / `response_hash`.
  """

  @typedoc """
  Opaque hasher state. Implementation detail: an `:crypto` digest
  context; callers MUST NOT inspect or modify it directly.
  """
  @opaque t :: :crypto.hash_state()

  @doc """
  Initialise a new SHA-256 streaming hasher.
  """
  @spec init() :: t()
  def init, do: :crypto.hash_init(:sha256)

  @doc """
  Append `bytes` to the hasher's running digest.

  Returns the new hasher state. `bytes` may be any binary, including
  the empty binary (no-op).
  """
  @spec update(t(), binary()) :: t()
  def update(state, bytes) when is_binary(bytes) do
    :crypto.hash_update(state, bytes)
  end

  @doc """
  Finalise the hasher and return the SHA-256 digest as 32 raw bytes.

  After `final/1` the state is consumed and MUST NOT be used for
  further `update/2` calls.
  """
  @spec final(t()) :: <<_::256>>
  def final(state) do
    :crypto.hash_final(state)
  end
end
