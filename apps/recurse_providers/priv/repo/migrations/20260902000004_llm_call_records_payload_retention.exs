defmodule Recurse.Providers.Repo.Migrations.LlmCallRecordsPayloadRetention do
  @moduledoc """
  Spec 012 S6b (plan §16) — detached payload retention for proxied LLM
  calls (spec 009 `streaming_proxy.md` "detached payloads", Constitution
  Principle IV).

  `prompt_hash` / `response_hash` on the signed predicate cover the
  upstream request body and the concatenated upstream response bytes.
  With `R5E_RETAIN_PAYLOADS=true` the proxy keeps those bytes and the
  emitter puts them into the StorageProvider; the URIs land here so the
  evidence export can pack `payloads/<sha256>` next to the receipt.

    * `prompt_payload_uri` / `response_payload_uri` — nullable; NULL when
      retention is off, the capture exceeded `R5E_RETAIN_PAYLOADS_MAX_BYTES`,
      or the CAS put failed (the receipt is written regardless).
    * `payload_truncated` — true when a direction exceeded the cap. A
      partial payload cannot be checked against the hash, so nothing is
      stored for that direction and the flag records why.
  """

  use Ecto.Migration

  def up do
    alter table(:llm_call_records) do
      add(:prompt_payload_uri, :string)
      add(:response_payload_uri, :string)
      add(:payload_truncated, :boolean, null: false, default: false)
    end
  end

  def down do
    alter table(:llm_call_records) do
      remove(:payload_truncated)
      remove(:response_payload_uri)
      remove(:prompt_payload_uri)
    end
  end
end
