defmodule Recurse.Gateway.AuditPlane.ReceiptSerializers do
  @moduledoc """
  Single source for the JSON shape of an attestation's
  `signed_predicate` and `outer_container` blocks.

  ## Why this module exists (Issue #29 / Constitution Principle VII)

  Two consumers had drifting renderers:

    * `EvidenceZipBuilder.signed_predicate_json/1`,
      `outer_container_json/1`, `manifest_json/1` (lines 340-392) —
      the export-zip artifacts. Includes
      `signed_predicate_bytes_b64`, `dsse_signature_b64`,
      `global_inclusion_proof_b64`, `local_inclusion_proof_b64` so
      offline `recurse-verify` can run.

    * `ReceiptsHandler.render_signed_predicate/1`,
      `render_outer_container/1` (lines 250-280) — the Receipt
      Detail JSON the SPA renders. EXCLUDES the heavy bytes
      fields (the SPA's detail tab doesn't decode them; the
      Verify Locally button fetches them on demand).

  Same field names, divergent field sets. The s3 + s4 surveys
  flagged this as drift bait — the moment one consumer adds a new
  field to its renderer (e.g., a per-receipt "verification level
  advisory"), the other one rots and the SPA's detail view
  silently disagrees with the export zip.

  This module is the canonical renderer. The two consumers
  delegate; the heavy-bytes inclusion is a per-call option, not a
  per-implementation divergence.

  ## Field-set contract

  The default (no opts) shape matches `ReceiptsHandler`'s detail
  view — the lightest shape, suitable for Receipt Detail JSON.
  Pass `include_proof_bytes: true` and/or
  `include_signature_bytes: true` to add the offline-verifiable
  fields that the export-zip needs.

  ## B7 row metadata (2026-04-29)

  The `signed_predicate` shape carries two additional fields,
  `tool_name` and `tool_summary`, which are NOT part of the DSSE
  signed bytes. They live as denormalized columns on the
  `attestations` row purely so the audit-log table renderer can
  display tool detail without a separate payload fetch. Both are
  string-or-nil; they are NULL for non-`:tool_call` rows. The
  `signed_predicate.json` artifact in the export zip carries the same
  shape — auditors comparing the export to the live wire receipt
  see byte-identical fields. The DSSE PAE payload (the actual
  signed bytes) is unchanged from F002; verification continues to
  authenticate `signed_predicate_bytes_b64` only.

  ## Iron Law

  Pure module. No process. Maps in, maps out.
  """

  @typedoc """
  Render options:

    * `:include_signature_bytes` — when `true`, include
      `signed_predicate_bytes_b64` and `dsse_signature_b64` (raw
      bytes Base64-encoded). Used by the export-zip
      `signed_predicate.json` artifact. Default `false`.

    * `:include_proof_bytes` — when `true`, include
      `global_inclusion_proof_b64` and `local_inclusion_proof_b64`.
      Used by the export-zip `outer_container.json` artifact.
      Default `false`.
  """
  @type render_opts :: [
          {:include_signature_bytes, boolean()}
          | {:include_proof_bytes, boolean()}
        ]

  @doc """
  Render the `signed_predicate` block. The map shape is identical
  to what existed inline in `ReceiptsHandler.render_signed_predicate/1`
  (default) and `EvidenceZipBuilder.signed_predicate_json/1`
  (with `include_signature_bytes: true`).
  """
  @spec signed_predicate(att :: map(), render_opts()) :: map()
  def signed_predicate(att, opts \\ []) when is_map(att) do
    base = %{
      "run_id" => att.run_id,
      "session_id" => att.session_id,
      "turn_id" => att.turn_id,
      "event_kind" => to_string_or_nil(att.event_kind),
      "machine_identity" => att.machine_identity,
      "principal" => att.principal,
      "tenant_id" => att.tenant_id,
      "policy_canonical_hash" => hex_or_nil(att.policy_canonical_hash),
      "payload_hash" => hex_or_nil(att.payload_hash),
      "payload_uri" => att.payload_uri,
      "correlation_id" => att.correlation_id,
      "signer_kms_key_id" => att.signer_kms_key_id,
      "signer_key_version" => att.signer_key_version,
      "timestamp" => dt_or_nil(att.timestamp),
      # B7 — non-signed UI metadata. Shape-stable string-or-nil so SPA
      # row renderer can branch on presence without backend round-trip.
      # NOT part of the DSSE-signed bytes; safe to absent under
      # `include_signature_bytes: true` since callers (export-zip)
      # don't consume these fields.
      "tool_name" => Map.get(att, :tool_name),
      "tool_summary" => Map.get(att, :tool_summary)
    }

    if Keyword.get(opts, :include_signature_bytes, false) do
      Map.merge(base, %{
        "signed_predicate_bytes_b64" =>
          Base.encode64(Map.get(att, :signed_predicate_bytes) || <<>>),
        "dsse_signature_b64" =>
          Base.encode64(Map.get(att, :dsse_signature) || <<>>)
      })
    else
      base
    end
  end

  @doc """
  Render the `outer_container` block. Default shape matches the
  Receipt Detail JSON; `include_proof_bytes: true` adds the
  Base64-encoded inclusion proofs for the export zip.

  ## Tool-call extractor `tags` (2026-04-30)

  When the row carries a populated `tags` JSONB column (see
  `Recurse.Gateway.Extractors.ClaudeCodeJsonl`), it surfaces
  unchanged on the wire under the `tags` key. NULL tags map to
  `nil` (omitted client-side per JSON conventions). NOT part of
  the signed predicate; auditors comparing the export-zip's
  `outer_container.json` to the live wire receipt see byte-
  identical fields.
  """
  @spec outer_container(att :: map(), render_opts()) :: map()
  def outer_container(att, opts \\ []) when is_map(att) do
    base = %{
      "verification_level" => to_string_or_nil(att.verification_level),
      "tier_completeness_advisory" => to_string_or_nil(att.tier_completeness_advisory),
      "session_chain_epoch" => att.session_chain_epoch,
      "session_chain_root" => hex_or_nil(att.session_chain_root),
      "policy_decision" => to_string_or_nil(att.policy_decision),
      "outcome" => to_string_or_nil(att.outcome),
      "upstream_status_code" => att.upstream_status_code,
      "commit_retry_exhausted" => att.commit_retry_exhausted,
      "tags" => Map.get(att, :tags)
    }

    if Keyword.get(opts, :include_proof_bytes, false) do
      Map.merge(base, %{
        "global_inclusion_proof_b64" =>
          Base.encode64(Map.get(att, :global_inclusion_proof) || <<>>),
        "local_inclusion_proof_b64" =>
          Base.encode64(Map.get(att, :local_inclusion_proof) || <<>>)
      })
    else
      base
    end
  end

  @doc """
  Render a full receipt (signed_predicate + outer_container). The
  `run_id` is hoisted to the top level for convenience matching
  ReceiptsHandler's existing detail-view shape.
  """
  @spec receipt(att :: map(), render_opts()) :: map()
  def receipt(att, opts \\ []) when is_map(att) do
    %{
      "run_id" => att.run_id,
      "signed_predicate" => signed_predicate(att, opts),
      "outer_container" => outer_container(att, opts)
    }
  end

  defp to_string_or_nil(nil), do: nil
  defp to_string_or_nil(v) when is_atom(v), do: Atom.to_string(v)
  defp to_string_or_nil(v) when is_binary(v), do: v
  defp to_string_or_nil(v), do: to_string(v)

  defp hex_or_nil(nil), do: nil
  defp hex_or_nil(v) when is_binary(v), do: Base.encode16(v, case: :lower)

  defp dt_or_nil(nil), do: nil
  defp dt_or_nil(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
end
