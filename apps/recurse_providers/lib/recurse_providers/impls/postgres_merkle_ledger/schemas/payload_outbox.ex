defmodule Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.PayloadOutbox do
  @moduledoc """
  Ecto schema for the `payload_outbox` table — durable retry queue for S3
  payload PUT reconciliation per F002 FR-032.

  Cross-references:

    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-032
      ("S3 outbox reconciliation").
    * `specs/002-standalone-gateway-vertical-slice/data-model.md` §payload_outbox.
    * Migration: `priv/repo/migrations/20260423100001_f002_merkle_ledger_tables.exs`.

  ## Row lifecycle

  A Gateway call that attempts to commit an attestation whose detached
  payload failed to reach S3 enqueues a row here with
  `status = "pending"` and `next_attempt_at = now()`. The
  `Recurse.Gateway.Storage.OutboxReconciler` (F002 T090) polls rows where
  `status = "pending" AND next_attempt_at <= now()`, retries the S3 PUT
  via `StorageProvider.put_payload/3`, and on success commits to the
  ledger and flips the row to `"committed"`. After 10 failed attempts the
  row transitions to `"dead_letter"` and surfaces via
  `recurse_outbox_depth` for operator alerting.

  The append-semantics ledger never commits a payload whose S3 object
  hasn't been observed to exist (FR-032 monotonic ordering), so this
  table is the ONLY way a payload-committed attestation lands in the
  ledger when S3 was transiently unavailable at call time.

  ## Columns

  Mirrors the `F002MerkleLedgerTables` migration exactly (including
  `timestamps(type: :utc_datetime_usec)` giving `inserted_at` +
  `updated_at`).

  ## Iron Law (`elixir:elixir-thinking`)

  This module is a pure Ecto schema + changeset. No GenServer, no process
  state — the reconciler process owns the polling/retry state, this
  module only shapes rows.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type status :: :pending | :committed | :dead_letter

  @type t :: %__MODULE__{
          id: Ecto.UUID.t() | nil,
          run_id: Ecto.UUID.t() | nil,
          attestation_bytes: binary() | nil,
          payload_bytes: binary() | nil,
          target_uri: String.t() | nil,
          attempts: non_neg_integer(),
          last_attempt_at: DateTime.t() | nil,
          next_attempt_at: DateTime.t() | nil,
          status: String.t() | nil,
          last_error: String.t() | nil,
          inserted_at: DateTime.t() | nil,
          updated_at: DateTime.t() | nil
        }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "payload_outbox" do
    field(:run_id, :binary_id)
    field(:attestation_bytes, :binary)
    field(:payload_bytes, :binary)
    field(:target_uri, :string)
    field(:attempts, :integer, default: 0)
    field(:last_attempt_at, :utc_datetime_usec)
    field(:next_attempt_at, :utc_datetime_usec)
    field(:status, :string, default: "pending")
    field(:last_error, :string)

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(run_id attestation_bytes payload_bytes target_uri next_attempt_at status)a
  @optional_fields ~w(attempts last_attempt_at last_error)a
  @valid_statuses ~w(pending committed dead_letter)

  @doc """
  Changeset for inserting a fresh `pending` outbox row after a transient
  S3 PUT failure.
  """
  @spec insert_changeset(map()) :: Ecto.Changeset.t()
  def insert_changeset(attrs) do
    %__MODULE__{}
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_number(:attempts, greater_than_or_equal_to: 0)
  end

  @doc """
  Changeset for advancing the row — updates `attempts`, `last_attempt_at`,
  `next_attempt_at`, `status`, and `last_error` only.
  """
  @spec retry_changeset(t(), map()) :: Ecto.Changeset.t()
  def retry_changeset(%__MODULE__{} = row, attrs) do
    row
    |> cast(attrs, ~w(attempts last_attempt_at next_attempt_at status last_error)a)
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_number(:attempts, greater_than_or_equal_to: 0)
  end
end
