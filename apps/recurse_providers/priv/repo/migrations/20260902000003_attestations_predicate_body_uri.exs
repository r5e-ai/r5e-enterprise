defmodule Recurse.Providers.Repo.Migrations.AttestationsPredicateBodyUri do
  @moduledoc """
  Spec 012 S6b (plan §16) — retain what the signature commits to.

  Predicate-only receipts (`payload_uri = recurse://system/predicate-only/<run_id>`,
  every `:llm_call_attested` / `:tool_use_denied` / `:ui_*` event) carry
  `payload_hash = SHA-256(JCS(predicate_map))`, but until S6b the JCS
  bytes were never written anywhere, so no verifier could recompute the
  hash. The emitter now puts those exact bytes into the StorageProvider
  (content-addressed) and records the returned URI here.

  Nullable, NOT part of the signed predicate (same band as `tags`): the
  signature already binds `payload_hash`; this column only says where a
  copy of the hashed bytes lives. NULL = not retained (receipts older
  than S6b, or a CAS put that failed — the receipt is committed anyway).

  `payload_uri` is left as the predicate-only sentinel on purpose: the
  URI scheme is what `PredicateOnlyUri.kind/1` and the offline verifier
  branch on, and changing it would re-shape every verify path.
  """

  use Ecto.Migration

  def up do
    alter table(:attestations) do
      add(:predicate_body_uri, :string)
    end
  end

  def down do
    alter table(:attestations) do
      remove(:predicate_body_uri)
    end
  end
end
