defmodule Recurse.Gateway.Admin.ChatHistory.ChatMessage do
  @moduledoc """
  Ecto schema for the `chat_messages` table — individual message within a
  ChatConversation.

  Cross-references:
    * `specs/004-audit-console/data-model.md` §1.4 (column rationale, indices,
      lifecycle, PII handling).
    * Migration — `apps/recurse_providers/priv/repo/migrations/20260424_f004_chat_messages.exs`
      (Wave 1A, sibling task).
    * Glossary cluster — **Audit Agent** (entries: *Chat Message*, *Tool
      Vocabulary*).
    * Six-tool wall — `specs/004-audit-console/plan.md` "Six-tool wall" + the
      audit-agent tools contract `contracts/audit_agent_tools.md`.

  AD-001 c' note: lives under the Gateway admin context. Talks to
  `Recurse.Providers.Repo` via the parent context module
  `Recurse.Gateway.Admin.ChatHistory` (T108, separate phase).

  **Append-only**: messages are not edited once written. Soft-delete via
  `deleted_at` is the only mutation post-insert (retention purge / D7).

  **Sequence concurrency guard**: `unique_constraint([:conversation_id,
  :sequence])` is the database-level invariant that backs the
  `ChatHistory.create_message/2` retry loop — two writers racing to insert
  `sequence = N` fail the second; the create path catches the conflict and
  retries with `sequence = N+1`.

  **Postgres null-byte sharp edge**: `content` is sanitized via
  `sanitize_null_bytes/2` because Postgres rejects `\\x00` in `text` columns
  even though it is a valid UTF-8 byte (project Ecto-thinking skill: "Null
  Bytes Crash Postgres"). Sanitizing here means callers can shovel raw user
  input through without worrying about boundary-strip discipline.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @role_values [:user, :agent, :tool_call, :tool_result]

  # Day-1 closed Tool Vocabulary — the "six-tool wall" from plan.md. The
  # `tool_calls` JSONB shape MUST cite one of these exact strings; anything
  # else is rejected by `validate_tool_calls_shape/1`. New tools require a
  # spec amendment, not a runtime addition.
  @tool_vocabulary ~w(
    query_receipts
    fetch_receipt_detail
    explain_denial
    find_similar_receipts
    simulate_policy_dryrun
    suggest_policy_pattern
  )

  # Closed status atoms for individual tool-call records inside `tool_calls`.
  @tool_status_values ~w(ok error)

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :id,
             :conversation_id,
             :role,
             :content,
             :tool_calls,
             :attested_run_id,
             :sequence,
             :deleted_at,
             :inserted_at,
             :updated_at
           ]}

  schema "chat_messages" do
    field(:conversation_id, :binary_id)
    field(:role, Ecto.Enum, values: @role_values)
    field(:content, :string)
    field(:tool_calls, {:array, :map}, default: [])
    field(:attested_run_id, :binary_id)
    field(:sequence, :integer)
    field(:deleted_at, :utc_datetime_usec)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required_fields [:conversation_id, :role, :content, :sequence]
  @optional_fields [:tool_calls, :attested_run_id, :deleted_at]

  @doc """
  Cast + validate a ChatMessage row per data-model §1.4.

  Validations:
    * `content` ≤ 64 KB.
    * `role` ∈ #{inspect(@role_values)}.
    * `sequence` > 0.
    * `tool_calls` is a list of maps each citing a tool from the closed Day-1
      vocabulary (see `@tool_vocabulary` above) — enforced by
      `validate_tool_calls_shape/1`.
    * `unique_constraint([:conversation_id, :sequence])` for the concurrency
      guard documented in the moduledoc.
    * Conversation FK constraint (DB-enforced).
    * `content` null bytes stripped via `sanitize_null_bytes/2` AFTER cast,
      BEFORE length validation — Postgres rejects `\\x00` in text columns.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(message, attrs) do
    message
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> sanitize_null_bytes(:content)
    |> validate_required(@required_fields)
    |> validate_length(:content, max: 65_536)
    |> validate_inclusion(:role, @role_values)
    |> validate_number(:sequence, greater_than: 0)
    |> validate_tool_calls_shape()
    |> foreign_key_constraint(:conversation_id)
    |> unique_constraint([:conversation_id, :sequence],
      name: :chat_messages_conversation_id_sequence_index
    )
  end

  @doc """
  Strip Postgres-incompatible null bytes (`\\x00`) from a string-typed change
  on `field`. This is the canonical Ecto sharp-edge fix called out in the
  project Ecto-thinking skill.

  Made public so other admin contexts can reuse the helper.
  """
  @spec sanitize_null_bytes(Ecto.Changeset.t(), atom()) :: Ecto.Changeset.t()
  def sanitize_null_bytes(changeset, field) do
    case get_change(changeset, field) do
      value when is_binary(value) ->
        sanitized = String.replace(value, "\x00", "")

        if sanitized == value do
          changeset
        else
          put_change(changeset, field, sanitized)
        end

      _other ->
        changeset
    end
  end

  # Each entry in `tool_calls` MUST be a map shaped like:
  #   %{tool: "<one of @tool_vocabulary>",
  #     args: %{...},
  #     result_run_id: nil | binary,
  #     status: :ok | :error,
  #     error: nil | binary}
  #
  # Atom or string keys are accepted (Ecto/Jason both round-trip atom keys to
  # strings on JSONB read). Empty list (the default for `:user` rows) passes
  # trivially.
  defp validate_tool_calls_shape(changeset) do
    case get_field(changeset, :tool_calls) do
      nil ->
        changeset

      [] ->
        changeset

      calls when is_list(calls) ->
        if Enum.all?(calls, &valid_tool_call?/1) do
          changeset
        else
          add_error(
            changeset,
            :tool_calls,
            "every entry must cite a tool from the Day-1 vocabulary " <>
              "(#{Enum.join(@tool_vocabulary, ", ")}) and supply :args and :status"
          )
        end

      _other ->
        add_error(changeset, :tool_calls, "must be a list of maps")
    end
  end

  defp valid_tool_call?(call) when is_map(call) do
    tool = call[:tool] || call["tool"]
    args = call[:args] || call["args"]
    status = call[:status] || call["status"]

    is_binary(tool) and tool in @tool_vocabulary and
      is_map(args) and
      valid_tool_status?(status)
  end

  defp valid_tool_call?(_other), do: false

  defp valid_tool_status?(status) when is_atom(status),
    do: Atom.to_string(status) in @tool_status_values

  defp valid_tool_status?(status) when is_binary(status),
    do: status in @tool_status_values

  defp valid_tool_status?(_other), do: false
end
