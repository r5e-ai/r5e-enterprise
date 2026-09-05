defmodule Recurse.Gateway.Admin.AuditAgent.ToolCall do
  @moduledoc """
  Per-tool attestation emitter (F004 T108).

  Builds the canonical signed-predicate map for a single agent tool call
  and routes it through the existing `UiReceipts.emit/2` seam — every
  tool invocation produces exactly one attested receipt with the
  per-tool `event_kind` from `data-model.md` §0.

  ## Signed-predicate shape

  Per `audit_agent_tools.md` §"Per-call lifecycle" step 5:

      %{
        tool_name: "<one of six Day-1 vocabulary entries>",
        input_hash: <sha256-hex of canonical JSON of input>,
        output_hash: <sha256-hex of canonical JSON of output, OR nil on error>,
        attested_run_ids: [<run_id strings the tool referenced>],
        outcome: "success" | "upstream_error" | "budget_exceeded" | "crash",
        conversation_id: <UUID, denormalized for auditor convenience>,
        # Plus standard meta the UiReceipts seam threads through:
        principal_subject: ...,
        tenant_id: ...,
        correlation_id: ...
      }

  Hashes (NOT raw input/output) are what land in the ledger — the
  full input/output text lives only in `chat_messages.tool_calls`
  JSONB, subject to the 30-day chat-history retention. This split is
  the load-bearing PII boundary documented in `audit_agent_tools.md`
  §"Retention note" (Tool 3) and `data-model.md` §1.4 PII-handling.

  ## Iron Law check (`elixir:elixir-thinking`)

    1. Mutable state across calls? No — every emit is a pure function
       of (event_kind, predicate map). UiReceipts handles the ledger
       commit synchronously on the caller process.
    2. Concurrent execution? No — runs on the SSE-handler process.
    3. Fault isolation? No — UiReceipts.emit/2 already isolates ledger
       failures (returns :ok always; logs gaps to SIEM).

  All three NO → plain functions.

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_agent_tools.md` §"Per-call lifecycle"
    * `specs/004-audit-console/data-model.md` §0 (canonical event_kind matrix)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/ui_receipts.ex`
      (the receipt-emission seam)
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Shared.IdentityContext

  @type outcome :: :success | :upstream_error | :budget_exceeded | :crash

  @typedoc """
  Per-call emission inputs.

    * `:tool_name` — string, one of the six Day-1 vocabulary entries.
    * `:event_kind` — atom, the canonical `:ui_chat_skill_invoked_<name>`.
    * `:input` — the validated input map passed into `Tool.call/2`.
    * `:output` — the result map (or `nil` on error).
    * `:attested_run_ids` — list of run_id strings the tool consulted
      (e.g. the `run_id` argument for `fetch_receipt_detail`).
    * `:outcome` — see `t:outcome/0`.
    * `:identity_ctx` — the F001 IdentityContext for this request.
    * `:conversation_id` — for auditor cross-link convenience.
  """
  @type emit_args :: %{
          required(:tool_name) => String.t(),
          required(:event_kind) => atom(),
          required(:input) => map(),
          required(:output) => map() | nil,
          required(:attested_run_ids) => [String.t()],
          required(:outcome) => outcome(),
          required(:identity_ctx) => IdentityContext.t(),
          required(:conversation_id) => String.t(),
          optional(:tokens_in) => non_neg_integer(),
          optional(:tokens_out) => non_neg_integer(),
          optional(:error) => String.t() | nil
        }

  @doc """
  Emit one per-tool attested receipt. Returns `:ok` always — never
  raises (mirrors `UiReceipts.emit/2`'s fault-isolation contract).
  """
  @spec emit(emit_args()) :: :ok
  def emit(%{
        tool_name: tool_name,
        event_kind: event_kind,
        input: input,
        output: output,
        attested_run_ids: run_ids,
        outcome: outcome,
        identity_ctx: %IdentityContext{} = ctx,
        conversation_id: conversation_id
      } = args)
      when is_binary(tool_name) and is_atom(event_kind) and is_map(input) and
             is_list(run_ids) and is_binary(conversation_id) do
    predicate = %{
      tool_name: tool_name,
      input_hash: canonical_hash(input),
      output_hash: canonical_hash(output),
      attested_run_ids: run_ids,
      outcome: Atom.to_string(outcome),
      conversation_id: conversation_id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id,
      tokens_in: Map.get(args, :tokens_in, 0),
      tokens_out: Map.get(args, :tokens_out, 0),
      error: Map.get(args, :error)
    }

    UiReceipts.emit(event_kind, predicate)
  end

  @doc """
  SHA-256 hex digest of the JCS-style canonical JSON encoding of
  `term`. Returns `nil` for nil inputs (used when a tool errored
  before producing an output).

  Uses `JSON.encode!/1` rather than full RFC 8785 JCS — the contract's
  invariant is "hash is reproducible for byte-identical inputs"; the
  built-in encoder is deterministic for the closed set of map shapes
  the tools emit (no nested floats, no escape ambiguities).

  Public so contract tests can recompute and compare.
  """
  @spec canonical_hash(map() | nil) :: String.t() | nil
  def canonical_hash(nil), do: nil

  def canonical_hash(term) when is_map(term) or is_list(term) do
    bytes = canonical_encode(term)
    :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)
  end

  # Deterministic JSON encoding — sort map keys before encoding so two
  # logically-equal terms hash identically regardless of insert order.
  defp canonical_encode(term) when is_map(term) do
    term
    |> Enum.sort_by(fn {k, _} -> to_string(k) end)
    |> Enum.map(fn {k, v} -> {to_string(k), canonical_value(v)} end)
    |> Enum.into(%{})
    |> JSON.encode!()
  end

  defp canonical_encode(term) when is_list(term) do
    term
    |> Enum.map(&canonical_value/1)
    |> JSON.encode!()
  end

  defp canonical_value(v) when is_map(v) do
    v
    |> Enum.sort_by(fn {k, _} -> to_string(k) end)
    |> Enum.map(fn {k, v2} -> {to_string(k), canonical_value(v2)} end)
    |> Enum.into(%{})
  end

  defp canonical_value(v) when is_list(v), do: Enum.map(v, &canonical_value/1)
  defp canonical_value(v) when is_atom(v) and not is_boolean(v) and not is_nil(v),
    do: Atom.to_string(v)

  defp canonical_value(v), do: v

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}})
       when is_binary(sub),
       do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}})
       when is_binary(id),
       do: id

  defp principal_subject_from_ctx(_), do: "unknown"
end
