defmodule Recurse.Cedar.Nif do
  @moduledoc """
  Rustler NIF bindings for the `recurse_cedar` Rust crate.

  This module is an implementation detail — application code should call
  `Recurse.Cedar` instead. Exposed here only because Rustler requires the
  `use Rustler` module to match the Rust-side `rustler::init!` target
  (`Elixir.Recurse.Cedar.Nif`).

  See `native/recurse_cedar/src/lib.rs` for the Rust surface and the
  content-addressed Cedar pin (research D2 / FR-039).
  """

  use Rustler,
    otp_app: :recurse_shared,
    crate: :recurse_cedar,
    path: "../../native/recurse_cedar"

  @doc """
  Compute `policy_canonical_hash` for a Cedar policy source string.

  Returns `{:ok, <<_::256>>}` on success or `{:error, reason}` when the
  Cedar crate's `PolicySet::from_str` / `to_json` / the JCS encoder
  rejects the input. See `native/recurse_cedar/src/lib.rs`.
  """
  @spec canonical_hash(binary()) :: {:ok, binary()} | {:error, binary()}
  def canonical_hash(_policy_source), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Parse-only validation for the Cedar Playground live-feedback surface.

  The Rust NIF signature is `fn validate_policy_syntax(source: String) ->
  Result<(), String>`. Rustler encodes `Ok(())` as `{:ok, {}}` on the
  BEAM side, not as the bare atom `:ok` — the @spec below reflects the
  actual runtime return shape. The `Recurse.Cedar.validate_policy_syntax/1`
  facade unwraps to bare `:ok` for ergonomic callers.
  """
  @spec validate_policy_syntax(binary()) :: {:ok, {}} | {:error, binary()}
  def validate_policy_syntax(_source), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Scaffold request evaluation — returns "allow" or "deny". Feature 002+ wires
  the production entity store + schema.
  """
  @spec evaluate(binary(), binary()) :: {:ok, binary()} | {:error, binary()}
  def evaluate(_policy_source, _request_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Evaluate a Cedar request against a policy set + explicit entity store.

  Returns a JSON string (binary) of shape
  `{"decision": "allow" | "deny", "matched_policies": [policy_id, ...]}`
  on success, or `{:error, reason}` on any parse / evaluation failure.

  `entities_json` is a Cedar-entity-JSON-format array (per `Entities::from_json_value`).
  """
  @spec evaluate_with_entities(binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, binary()}
  def evaluate_with_entities(_policy_source, _request_json, _entities_json),
    do: :erlang.nif_error(:nif_not_loaded)
end
