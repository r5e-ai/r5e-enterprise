defmodule Recurse.Gateway.Admin.ChatHistory.ChatConversation do
  @moduledoc """
  Ecto schema for the `chat_conversations` table — audit-agent transcript root.

  Cross-references:
    * `specs/004-audit-console/data-model.md` §1.3 (column rationale, indices,
      lifecycle, PII handling).
    * Migration — `apps/recurse_providers/priv/repo/migrations/20260424_f004_chat_conversations.exs`
      (Wave 1A, sibling task).
    * Glossary cluster — **Audit Agent** (entry: *Chat Conversation*).

  AD-001 c' note: lives under the Gateway admin context. Talks to
  `Recurse.Providers.Repo` via the parent context module
  `Recurse.Gateway.Admin.ChatHistory` (T108, separate phase).

  **Lifecycle is implicit** — no `status` enum (per data-model §1.3):
    * Active while `archived_at IS NULL`.
    * Archived when `archived_at IS NOT NULL` (operator or retention-auto).
    * Hard-deleted 90 days after archive (D7).

  Transcript retention (30-day default `console.retention.chat_history_days`)
  is **separate** from the receipt retention for each emitted message. That
  separation is the load-bearing invariant that keeps F002's 7-year audit
  retention from being contaminated by 30-day chat retention.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :id,
             :tenant_id,
             :principal_subject,
             :started_at,
             :last_message_at,
             :archived_at,
             :deleted_at,
             :inserted_at,
             :updated_at
           ]}

  schema "chat_conversations" do
    field(:tenant_id, :string)
    field(:principal_subject, :string)
    field(:started_at, :utc_datetime_usec)
    field(:last_message_at, :utc_datetime_usec)
    field(:archived_at, :utc_datetime_usec)
    field(:deleted_at, :utc_datetime_usec)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required_fields [:tenant_id, :principal_subject, :started_at, :last_message_at]
  @optional_fields [:archived_at, :deleted_at]

  @doc """
  Cast + validate a ChatConversation row per data-model §1.3.

  Validations:
    * `principal_subject` ≤ 255 chars (PII).
    * Tenant FK constraint (DB-enforced).
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(conversation, attrs) do
    conversation
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:principal_subject, max: 255)
    |> foreign_key_constraint(:tenant_id)
  end
end
