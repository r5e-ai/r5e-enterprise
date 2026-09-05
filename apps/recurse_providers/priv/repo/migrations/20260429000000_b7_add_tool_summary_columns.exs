defmodule Recurse.Providers.Repo.Migrations.B7AddToolSummaryColumns do
  @moduledoc """
  Demo punch-list B7 — surface tool-call detail on audit-log rows.

  The Audit Log dashboard's `tool_call` rows currently render only
  `event_kind · principal` because no row-level tool detail is
  persisted: the importer encodes `tool_name` + a 1-line summary into
  the predicate_map → JCS-hashed payload, but those bytes are not
  retained as queryable columns. The forward stub at
  `live_tail_socket.ex:579` (`Map.get(att, :tool_name)`) and
  `receipts_handler.ex:461` already presume `tool_name` is a row
  attribute, so this migration lights the existing wiring up.

  Both columns are non-signed UI metadata. They are NOT part of the
  signed_predicate, NOT hashed, NOT included in DSSE verification.
  Adding them does not affect `verification_level` or the proof
  envelope. They exist purely to feed the dashboard row renderer +
  the audit-agent's row-summary tooling.

  ## Field semantics

    * `tool_name` (text, nullable) — short tool identifier (e.g.,
      `"Bash"`, `"Edit"`, `"Read"`). Populated by the importer from
      the source-session entry's tool_use block.

    * `tool_summary` (text, nullable) — 1-line human-readable
      description, with PII-aware redaction applied at write time
      (see `SessionReceiptBuilder.tool_summary_from/1`). Examples:
        * `"Bash: ls /etc"`
        * `"Edit: apps/foo/bar.ex"`
        * `"Read: /tmp/payload.json"`
        * `"WebFetch: (args redacted)"`

  Both are NULL for non-`:tool_call` rows. Existing rows (pre-import)
  remain NULL; the row renderer falls back to a generic event_kind
  summary in that case.

  ## Migration safety

  Pure additive change — adds two NULLable columns. AccessExclusiveLock
  on attestations is held only for the catalog update (milliseconds);
  no row-rewriting or default-fill scan because both columns default
  to NULL. Safe against the projected-1B-row attestations table.
  """

  use Ecto.Migration

  def up do
    alter table(:attestations) do
      add(:tool_name, :text)
      add(:tool_summary, :text)
    end
  end

  def down do
    alter table(:attestations) do
      remove(:tool_name)
      remove(:tool_summary)
    end
  end
end
