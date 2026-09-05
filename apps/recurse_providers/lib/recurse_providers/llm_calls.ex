defmodule Recurse.Providers.LlmCalls do
  @moduledoc """
  Context-style helper for the `llm_call_records` + `tool_use_intent_records`
  audit tables.

  Spec source of truth:
    * `specs/009-llm-api-proxy/data-model.md` §LlmCallRecord +
      §ToolUseIntentRecord
    * `specs/009-llm-api-proxy/contracts/llm_call_attestation.md` for
      the canonical signed-predicate shape this row mirrors

  This module is the seam Phase-5's attestation emitter (Sub-3.7) uses
  to denormalize an `:llm_call_attested` predicate into queryable rows.
  Phase-4's audit-plane endpoint (Sub-4.1) reads through these rows for
  the CISO "LLM Calls" view.

  ## Cross-context FK by ID, not association

  `LlmCallRecord.signed_predicate_run_id` is an FK to `attestations.run_id`
  (a UUID `:binary_id`). Per Ecto-thinking ("cross-context references:
  IDs, not associations"), the audit row knows the predicate by id only
  and we don't model an Ecto association across that boundary.
  """

  alias Ecto.Multi
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmCallRecord
  alias Recurse.Providers.Schemas.ToolUseIntentRecord

  @typedoc """
  The successful return of `write_call_with_intents/2`. The intents
  list is in the same order as the input attrs list.
  """
  @type write_result :: %{
          call: LlmCallRecord.t(),
          intents: [ToolUseIntentRecord.t()]
        }

  @typedoc """
  An invariant violation surfaced before the DB transaction begins.
  See `write_call_with_intents/2`.
  """
  @type invariant_error ::
          :tool_use_intent_count_mismatch
          | :tool_use_denied_count_mismatch

  @typedoc """
  Failure modes:
    * `{:error, :call, %Ecto.Changeset{}}` — call changeset invalid
    * `{:error, {:intent, index}, %Ecto.Changeset{}}` — intent at
      position `index` had an invalid changeset
    * `{:error, invariant_error()}` — pre-DB invariant rejected
  """
  @type write_error ::
          {:error, :call, Ecto.Changeset.t()}
          | {:error, {:intent, non_neg_integer()}, Ecto.Changeset.t()}
          | {:error, invariant_error()}

  @doc """
  Insert one `LlmCallRecord` plus N `ToolUseIntentRecord`s atomically.

  All inserts execute inside a single Postgres transaction via
  `Ecto.Multi` — either every row lands or nothing does. The intents'
  `:llm_call_record_id` column is wired up to the call's freshly-minted
  `id` by the Multi step ordering (the call insert step runs first;
  each intent step closes over `call.id`).

  ## Pre-DB invariants

  Before opening the transaction we check that the intent counts in the
  provided `call_attrs` agree with the actual list of intents. The
  call-row's `:tool_use_intent_count` and `:tool_use_denied_count`
  fields are written by the Phase-5 emitter as a separate concern from
  the per-intent rows; if they disagree, the audit row is internally
  inconsistent. Surface this as a structured error rather than papering
  over it.

  ## Examples

      iex> {:ok, %{call: call, intents: [intent]}} =
      ...>   Recurse.Providers.LlmCalls.write_call_with_intents(call_attrs, [intent_attrs])
      ...> call.tool_use_intent_count
      1
  """
  @spec write_call_with_intents(map(), [map()]) ::
          {:ok, write_result()} | write_error()
  def write_call_with_intents(call_attrs, intent_attrs_list)
      when is_map(call_attrs) and is_list(intent_attrs_list) do
    with :ok <- check_intent_counts(call_attrs, intent_attrs_list) do
      do_write(call_attrs, intent_attrs_list)
    end
  end

  defp check_intent_counts(call_attrs, intent_attrs_list) do
    declared_intent =
      Map.get(call_attrs, :tool_use_intent_count) ||
        Map.get(call_attrs, "tool_use_intent_count")

    declared_denied =
      Map.get(call_attrs, :tool_use_denied_count) ||
        Map.get(call_attrs, "tool_use_denied_count")

    actual_intent = length(intent_attrs_list)

    actual_denied =
      Enum.count(intent_attrs_list, fn attrs ->
        decision = Map.get(attrs, :decision) || Map.get(attrs, "decision")
        decision == "deny"
      end)

    cond do
      is_integer(declared_intent) and declared_intent != actual_intent ->
        {:error, :tool_use_intent_count_mismatch}

      is_integer(declared_denied) and declared_denied != actual_denied ->
        {:error, :tool_use_denied_count_mismatch}

      true ->
        :ok
    end
  end

  defp do_write(call_attrs, intent_attrs_list) do
    multi =
      Multi.insert(
        Multi.new(),
        :call,
        LlmCallRecord.changeset(%LlmCallRecord{}, call_attrs)
      )

    multi =
      intent_attrs_list
      |> Enum.with_index()
      |> Enum.reduce(multi, fn {attrs, idx}, acc ->
        Multi.insert(acc, {:intent, idx}, fn %{call: %LlmCallRecord{id: id}} ->
          attrs_with_call = Map.put(coerce_attrs(attrs), :llm_call_record_id, id)
          ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, attrs_with_call)
        end)
      end)

    case Repo.transaction(multi) do
      {:ok, results} ->
        intents =
          intent_attrs_list
          |> Enum.with_index()
          |> Enum.map(fn {_attrs, idx} -> Map.fetch!(results, {:intent, idx}) end)

        {:ok, %{call: results.call, intents: intents}}

      {:error, :call, changeset, _changes} ->
        {:error, :call, changeset}

      {:error, {:intent, idx}, changeset, _changes} ->
        {:error, {:intent, idx}, changeset}
    end
  end

  # Allow callers to pass either string-keyed or atom-keyed attrs maps.
  # Internally we normalize to atom keys when injecting the FK so the
  # changeset cast doesn't trip on a mixed key shape.
  defp coerce_attrs(attrs) when is_map(attrs) do
    if Enum.any?(attrs, fn {k, _} -> is_binary(k) end) do
      for {k, v} <- attrs, into: %{} do
        {existing_atom_key(k), v}
      end
    else
      attrs
    end
  rescue
    # Unknown atom key — preserve original map; cast/3 will reject the
    # unknown field naturally.
    ArgumentError -> attrs
  end

  defp existing_atom_key(key) when is_binary(key), do: String.to_existing_atom(key)
  defp existing_atom_key(key), do: key
end
