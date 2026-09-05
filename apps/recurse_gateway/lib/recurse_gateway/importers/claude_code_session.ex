defmodule Recurse.Gateway.Importers.ClaudeCodeSession do
  @moduledoc """
  Imports Claude Code JSONL session exports into audit attestations.

  Phase 2 routes imported receipt specs through the same DSSE signing and
  Postgres-Merkle commit path used by native Gateway receipts. Imported source
  metadata is predicate-only evidence: it is hashed into the receipt payload
  and identified by a `recurse://import/...` URI.
  """

  alias Recurse.Gateway.Importers.ClaudeCodeSession.EntryClassifier
  alias Recurse.Gateway.Importers.JsonlSessionImporter

  @type opts :: [
          principal: String.t(),
          tenant_id: String.t(),
          skip_thinking?: boolean()
        ]

  @spec import_session(Path.t(), opts()) ::
          {:ok, %{receipts: non_neg_integer(), session_id: String.t() | nil}} | {:error, term()}
  def import_session(path, opts \\ []) do
    JsonlSessionImporter.import_session(path, EntryClassifier, opts)
  end
end
