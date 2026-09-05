defmodule Recurse.Providers.Repo.Migrations.AddAttestationTags do
  @moduledoc """
  Adds a `tags` JSONB column to the `attestations` table for the
  schema-on-read tool-call extractor pipeline.

  ## What this column stores

  The full output of `Recurse.Gateway.Extractors.ClaudeCodeJsonl.extract/1`
  for tool_call attestations. Top-level keys are stable
  (`category`, `display_summary`, `scope_kind`, `scope_value`,
  `target_resources`, `semantic_args`); the `semantic_args` sub-map is
  schema-on-read, varying per category. See the extractor's @moduledoc
  for the full per-category shape.

  ## NOT signed (NOT part of DSSE bytes)

  Same band as `tool_name` / `tool_summary` (B7): `tags` is a
  derived/mutable field on the outer container. The signed predicate
  bytes do NOT change — `signed_predicate.event_kind`,
  `signed_predicate_bytes`, and `dsse_signature` continue to authenticate
  the original receipt-spec exactly as before.

  Auditors can rely on:

    * `event_kind` (signed) — the canonical wire-shape kind.
    * `tags.category` (NOT signed) — the schema-on-read derived classification
      at extract time. Re-extracting against a newer extractor version may
      produce a different category for the same row; that's the point of
      a derived-mutable field.

  ## Migration safety

  Pure additive change — adds one nullable JSONB column. AccessExclusiveLock
  on `attestations` is held only for the catalog update (milliseconds);
  no row-rewriting because the column defaults to NULL. Safe against the
  projected-1B-row attestations table.

  Existing rows (pre-extractor) remain NULL; the row renderer falls back
  to the legacy `tool_summary` column when `tags` is NULL.

  Cross-references:

    * `apps/recurse_gateway/lib/recurse_gateway/extractors/claude_code_jsonl.ex`
    * `apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger/schemas/attestation.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/audit_plane/receipt_serializers.ex`
    * `20260429000000_b7_add_tool_summary_columns.exs` — sibling outer-container
      column-add migration; same band, same shape.
  """

  use Ecto.Migration

  def up do
    alter table(:attestations) do
      add(:tags, :jsonb)
    end
  end

  def down do
    alter table(:attestations) do
      remove(:tags)
    end
  end
end
