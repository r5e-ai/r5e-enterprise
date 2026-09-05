defmodule Recurse.Gateway.AuditPlane.PredicateOnlyUri do
  @moduledoc """
  Single source of truth for the predicate-only URI schemes used when an
  attestation's `signed_predicate` IS the audit content (no separate S3
  payload to fetch). Two such schemes exist:

    * `recurse://system/predicate-only/<run_id>` — Gateway-internal
      system events (login outcomes, session lifecycle, retention purge,
      bundle promote, etc.). Plus the synthetic no-policy SHA-256
      sentinel used for `policy_canonical_hash` on these events.

    * `recurse://import/<source_kind>/<run_id>` — receipts emitted by
      the JSONL importer for source-session artifacts (Claude Code,
      Codex, future adapters). Predicate-only inside the Gateway, but
      not Gateway-internal — they represent EXTERNAL source artifacts
      whose payload bytes were not CAS-stashed by this Gateway.

  ## Why this module exists (Issue #29 / AD-1 Option A)

  Before this module landed:

    * The scheme prefix was duplicated as a STRING LITERAL in
      `EvidenceZipBuilder:140` and `PayloadBroker:97` (Grade-1
      duplication).

    * The canonical definitions lived inside `EnvelopeBuilder` (the
      sign-side, the most security-critical module — it mints DSSE
      signatures), exposed via two public accessors:
      `system_event_payload_uri_scheme/0` (line 562) and
      `system_event_no_policy_hash/0` (line 555).

    * Verify-side modules (`PayloadBroker`, `LocalVerifyHandler`,
      `EvidenceZipBuilder`) imported FROM `EnvelopeBuilder` to
      consume those constants — an asymmetric coupling: sign-side
      and verify-side are sibling concerns operating on the same
      domain object, but the import direction implied a parent-child
      relationship that doesn't exist in the domain.

  Per AD-1 Option A (issue #29 architectural model), this module
  becomes the canonical owner. `EnvelopeBuilder` reuses
  `PredicateOnlyUri.uri_scheme_prefix/0` and
  `PredicateOnlyUri.system_event_no_policy_hash/0` internally for
  sign-side build, and removes its public accessors. Verify-side
  modules also delegate here. The asymmetric coupling is retired.

  When the JSONL importer ([!7]) added a second predicate-only scheme
  (`recurse://import/`), the same induction applied: extract the
  recognition + accessor here rather than reintroduce a sibling
  scheme constant inside `EnvelopeBuilder`. Constitution Principle VII
  (NON-NEGOTIABLE) — second consumer triggers extraction.

  ## What "predicate-only" means

  Some event_kinds carry their full audit content in the
  `signed_predicate` itself, with no separate request/response
  payload to put in S3:

    * `:ui_login` — auth outcome metadata
    * `:ui_session` — session lifecycle markers
    * `:ui_query` — UI-internal query records (read-only audit-trail
       events)
    * `:retention_purge`, `:bundle_promote`, etc.
    * `:tool_call`, `:llm_call` (when imported from a source session) —
       imported source-session events whose payload was not CAS-stashed
       by this Gateway. Recognized by the `recurse://import/` prefix.

  For these, `payload_uri` is set to a predicate-only scheme URI and
  `payload_hash` is `SHA-256(JCS(predicate_metadata))`. The
  PayloadBroker, the export zip builder, and the verify-checklist's
  payload-hash check ALL recognize the scheme and short-circuit to
  inline rendering instead of attempting an S3 fetch.

  ## Iron Law

  Pure module. No process. Constants + helpers.
  """

  @uri_scheme_prefix "recurse://system/predicate-only/"
  @imported_uri_scheme_prefix "recurse://import/"

  # Synthetic 32-byte sentinel for system events when no Cedar evaluation
  # occurred. Identical across every system event so verifiers can
  # short-circuit policy-bundle lookup. Computed at compile time from a
  # stable string seed.
  @system_event_no_policy_hash :crypto.hash(:sha256, "recurse.system.no-policy.v1")

  @typedoc """
  Discriminator for the two predicate-only families. `:other` is
  returned for any URI that is NOT predicate-only (s3://, https://,
  nil, junk).
  """
  @type kind :: :system | :imported | :other

  @doc """
  Returns the system-event URI scheme prefix as a string. Use
  `match?/1` for recognition; this accessor is for tests and for
  callers that need to construct URIs (use `build/1` for that).
  """
  @spec uri_scheme_prefix() :: String.t()
  def uri_scheme_prefix, do: @uri_scheme_prefix

  @doc """
  Returns the imported-event URI scheme prefix as a string.
  Use `match_imported?/1` for recognition; this accessor is for tests
  and for callers (e.g., the JSONL importer) that need to construct
  imported URIs (use `build_imported/2` for that).
  """
  @spec imported_uri_scheme_prefix() :: String.t()
  def imported_uri_scheme_prefix, do: @imported_uri_scheme_prefix

  @doc """
  Returns the synthetic 32-byte SHA-256 sentinel used as
  `policy_canonical_hash` on system events that did not go through
  Cedar evaluation. Stable across the codebase + across time. Imported
  events also use this sentinel — they were not Cedar-gated by this
  Gateway, so the same "no-policy" semantic applies.
  """
  @spec system_event_no_policy_hash() :: <<_::256>>
  def system_event_no_policy_hash, do: @system_event_no_policy_hash

  @doc """
  True when the given URI is in the system-event predicate-only scheme.
  False for anything else (including nil, non-binary, imported URIs,
  and `s3://`/`https://` payload URIs).

  Use this BEFORE calling `Recurse.Gateway.AuditPlane.Resolvers.Payload.fetch/2`
  in any handler that needs to short-circuit storage fetches for
  system events.
  """
  @spec match?(payload_uri :: term()) :: boolean()
  def match?(uri) when is_binary(uri), do: String.starts_with?(uri, @uri_scheme_prefix)
  def match?(_), do: false

  @doc """
  True when the given URI is in the imported-event predicate-only
  scheme. False for anything else (including nil, non-binary, system
  event URIs, and `s3://`/`https://` payload URIs).
  """
  @spec match_imported?(payload_uri :: term()) :: boolean()
  def match_imported?(uri) when is_binary(uri),
    do: String.starts_with?(uri, @imported_uri_scheme_prefix)

  def match_imported?(_), do: false

  @doc """
  Discriminate which predicate-only family a URI belongs to. Returns
  `:system`, `:imported`, or `:other`. Use this in branches where the
  message / behavior differs between the two families (e.g., the
  payload-hash check's `explanation` text in `LocalVerifyHandler`).
  """
  @spec kind(payload_uri :: term()) :: kind()
  def kind(uri) when is_binary(uri) do
    cond do
      String.starts_with?(uri, @uri_scheme_prefix) -> :system
      String.starts_with?(uri, @imported_uri_scheme_prefix) -> :imported
      true -> :other
    end
  end

  def kind(_), do: :other

  @doc """
  Build a system-event predicate-only URI for the given `run_id`. Used
  by `EnvelopeBuilder.build_system/4` (sign-side) and any future system
  event constructor.
  """
  @spec build(run_id :: String.t()) :: String.t()
  def build(run_id) when is_binary(run_id), do: @uri_scheme_prefix <> run_id

  @doc """
  Build an imported-event predicate-only URI for the given `source_kind`
  + `run_id`. Used by `EnvelopeBuilder.build_imported/4` (sign-side) and
  the JSONL session importer.

  `source_kind` is the source-session adapter family (e.g.,
  `"claude-code"`, `"codex"`); the importer encodes it into the URI so
  verifiers can identify provenance without parsing the predicate.
  """
  @spec build_imported(source_kind :: String.t(), run_id :: String.t()) :: String.t()
  def build_imported(source_kind, run_id)
      when is_binary(source_kind) and is_binary(run_id),
      do: @imported_uri_scheme_prefix <> source_kind <> "/" <> run_id

  @doc """
  Build the structured response body that `PayloadBroker.handle/1`
  returns when the SPA's PayloadTab fetches a predicate-only run_id.
  Returns the JSON-serialized envelope; the caller wraps it in a
  `{:predicate_only, body}` tuple for its `with` chain.

  Centralizes the SPA contract: any change to the response shape
  (e.g., adding a `tenant_id` echo) lands here, not in three places.
  """
  @spec predicate_only_response_body(attestation_map :: map()) :: binary()
  def predicate_only_response_body(attestation_map) when is_map(attestation_map) do
    JSON.encode!(%{
      "predicate_only" => true,
      "run_id" => Map.get(attestation_map, :run_id),
      "event_kind" => stringify_event_kind(Map.get(attestation_map, :event_kind)),
      "payload_uri" => Map.get(attestation_map, :payload_uri),
      "explanation" =>
        "This event has no separate payload. The signed_predicate IS " <>
          "the audit content; see the Predicate tab."
    })
  end

  @doc """
  The export-zip's payload-file marker for a predicate-only event.
  EvidenceZipBuilder writes this string into the zip's
  `payload.json` slot for predicate-only receipts so the offline
  recurse-verify CLI sees a stable, recognizable token instead of
  an empty file or an S3-error message.
  """
  @spec evidence_zip_payload_marker() :: binary()
  def evidence_zip_payload_marker do
    JSON.encode!(%{
      "predicate_only" => true,
      "explanation" =>
        "This event has no separate payload. The signed_predicate IS " <>
          "the audit content."
    })
  end

  defp stringify_event_kind(kind) when is_atom(kind) and not is_nil(kind), do: Atom.to_string(kind)
  defp stringify_event_kind(kind) when is_binary(kind), do: kind
  defp stringify_event_kind(_), do: nil
end
