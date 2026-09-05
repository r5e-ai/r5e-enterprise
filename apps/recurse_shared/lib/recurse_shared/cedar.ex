defmodule Recurse.Cedar do
  @moduledoc """
  Friendly facade over the Cedar Rustler NIF (`Recurse.Cedar.Nif`).

  This module is the canonical entry point for Cedar operations in
  Phase-1. It owns three surfaces:

    * `canonical_hash/1` — FR-039's `policy_canonical_hash`. SHA-256 of the
      RFC 8785 JCS canonicalization of the Cedar crate's EST JSON
      representation of the parsed policy set. Stable across whitespace,
      comments, and trailing-comma perturbations of the source.

    * `validate_policy_syntax/1` — parse-only validation used by the Cedar
      Playground (Deliverable P, FR-049).

  Policy evaluation is NOT exposed on this facade in Phase 1. A scaffold
  implementation lives at `Recurse.Cedar.Scaffold.evaluate/2` (different
  module name on purpose — calling it requires typing "Scaffold", which
  is the affordance that prevents Feature 002+ from accidentally wiring
  the scaffold into the real policy-enforcement path). The production
  `Recurse.Cedar.evaluate/2` will land in Feature 002+ once the entity
  store + schema-typed context are wired.

  ## Content-addressed Cedar pin (research D2)

  The policy canonical hash is only meaningful under a pinned Cedar engine.
  Three components advance lockstep:

    1. `cedar_version` — `"4.9.1"`, pinned in `native/recurse_cedar/Cargo.toml`
       and mirrored in `priv/test_fixtures/cedar_stability/cedar_version.txt`.
    2. `cedar_crate_digest` — SHA-256 of the `cedar-policy` crate tarball,
       sourced from `Cargo.lock`; mirrored in
       `priv/test_fixtures/cedar_stability/cedar_crate_digest.txt`.
    3. `cedar_fixture_hash` — `canonical_hash/1` of the representative
       policy set committed under `priv/test_fixtures/cedar_stability/`;
       asserted in CI by `mix recurse.cedar.stability_check`.

  Any drift between the three fails the build. Upgrading Cedar requires a
  fresh fixture bake and a documented dual-hash transition window in
  `specs/001-api-jido-foundations/contracts/cedar_pin.md` (T091).
  """

  alias Recurse.Cedar.Nif

  @typedoc """
  32-byte SHA-256 digest of the canonical JCS-encoded policy set.
  """
  @type canonical_hash :: <<_::256>>

  @doc """
  Compute the `policy_canonical_hash` for a Cedar policy source string.

  Returns the 32-byte binary on success, or raises `ArgumentError` with the
  underlying Cedar/JCS parse error on failure. Developers who want to
  handle syntax errors gracefully (e.g., the Cedar Playground) should use
  `validate_policy_syntax/1` first, or `canonical_hash_result/1` which
  returns a tagged tuple.
  """
  @spec canonical_hash(binary()) :: canonical_hash()
  def canonical_hash(policy_source) when is_binary(policy_source) do
    case Nif.canonical_hash(policy_source) do
      {:ok, hash} ->
        hash

      {:error, reason} ->
        raise ArgumentError, "canonical_hash failed: #{reason}"
    end
  end

  @doc """
  Tagged-tuple variant of `canonical_hash/1` for flows that want to handle
  parse errors without catching exceptions (e.g., Cedar Playground server-side).
  """
  @spec canonical_hash_result(binary()) :: {:ok, canonical_hash()} | {:error, binary()}
  def canonical_hash_result(policy_source) when is_binary(policy_source) do
    Nif.canonical_hash(policy_source)
  end

  @doc """
  Same as `canonical_hash/1` but returns the hex-encoded lowercase form.
  """
  @spec canonical_hash_hex(binary()) :: binary()
  def canonical_hash_hex(policy_source) when is_binary(policy_source) do
    policy_source
    |> canonical_hash()
    |> Base.encode16(case: :lower)
  end

  @doc """
  Validate that a Cedar source string parses as a policy set.

  Returns `:ok` on success; `{:error, reason}` with a human-readable
  diagnostic on failure. The NIF itself returns `{:ok, {}}` — the
  facade unwraps to bare `:ok` so the typespec holds and callers can
  pattern-match cleanly at a `case` head.
  """
  @spec validate_policy_syntax(binary()) :: :ok | {:error, binary()}
  def validate_policy_syntax(source) when is_binary(source) do
    case Nif.validate_policy_syntax(source) do
      :ok -> :ok
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  @doc """
  Evaluate a Cedar request against a policy set + an explicit entity store.

  Unlike `Recurse.Cedar.Scaffold.evaluate/2` (which authorizes against an
  empty entity set and therefore cannot resolve attribute references like
  `principal.recurse_role`), this function accepts a Cedar-entity-JSON
  payload so that policies conditioned on entity attributes can evaluate
  correctly. This is the production seat F002's
  `Recurse.Gateway.Policy.Evaluator` calls into for FR-039 evaluation.

  Parameters:

    * `policy_source` — Cedar policy source text (e.g. the contents of
      `permissive_all.cedar`).
    * `request_json` — JSON string of shape
      `{"principal": "Type::\"id\"", "action": "Type::\"id\"",
         "resource": "Type::\"id\"", "context": {...}}`.
    * `entities_json` — Cedar entity-JSON array; each element is
      `{"uid": {"type": "...", "id": "..."}, "attrs": {...}, "parents": []}`.

  Returns `{:ok, %{decision: :allow | :deny, matched_policies: [String.t()]}}`
  on success, or `{:error, reason}` if parsing or evaluation fails.
  `matched_policies` is sorted ascending (deduped) so equal authorizations
  hash equal.
  """
  @spec evaluate_with_entities(binary(), binary(), binary()) ::
          {:ok, %{decision: :allow | :deny, matched_policies: [String.t()]}}
          | {:error, binary()}
  def evaluate_with_entities(policy_source, request_json, entities_json)
      when is_binary(policy_source) and is_binary(request_json) and is_binary(entities_json) do
    with {:ok, json} <-
           Nif.evaluate_with_entities(policy_source, request_json, entities_json),
         {:ok, parsed} <- decode_evaluation(json) do
      {:ok, parsed}
    end
  end

  defp decode_evaluation(json) do
    case JSON.decode(json) do
      {:ok, %{"decision" => "allow", "matched_policies" => matched}} when is_list(matched) ->
        {:ok, %{decision: :allow, matched_policies: matched}}

      {:ok, %{"decision" => "deny", "matched_policies" => matched}} when is_list(matched) ->
        {:ok, %{decision: :deny, matched_policies: matched}}

      {:ok, other} ->
        {:error, "unexpected evaluation response shape: #{inspect(other)}"}

      {:error, reason} ->
        {:error, "evaluation response decode error: #{inspect(reason)}"}
    end
  end
end

defmodule Recurse.Cedar.Scaffold do
  @moduledoc """
  Phase-1 scaffold for Cedar policy evaluation. **NOT the production
  evaluator.** Authorizes against an empty entity store (no schema, no
  entity hierarchy), so any policy referencing entities —
  `principal in Group::"admins"` — silently evaluates to `deny` because
  the group literally does not exist.

  This module exists to smoke-test the Rustler NIF wiring (the NIF's
  `canonical_hash/1` is the FR-039 production surface; its `evaluate/2`
  is a scaffold). Feature 002+ will ship the real evaluator at
  `Recurse.Cedar.evaluate/2` once `SchemaProvider` + `EntityProvider`
  interfaces land.

  Calling this function is always a scaffold-level operation; if you
  need real policy decisions, wait for Feature 002+ or wire the
  PolicyProvider reference impl.
  """

  alias Recurse.Cedar.Nif

  @doc """
  Scaffold Cedar evaluation. See module moduledoc for why you probably
  don't want this in production code.
  """
  @spec evaluate(binary(), binary()) :: {:ok, binary()} | {:error, binary()}
  def evaluate(policy_source, request_json)
      when is_binary(policy_source) and is_binary(request_json) do
    case Nif.evaluate(policy_source, request_json) do
      {:ok, decision} -> {:ok, decision}
      {:error, reason} -> {:error, reason}
      # Rustler encodes Ok(String) as the bare string for
      # Result<String, String> return types.
      decision when is_binary(decision) -> {:ok, decision}
    end
  end
end
