defmodule Recurse.Gateway.Importers.SessionReceiptBuilder do
  @moduledoc false

  alias Recurse.Gateway.Attestation.EnvelopeBuilder
  alias Recurse.Gateway.AuditPlane.PredicateOnlyUri
  alias Recurse.Shared.{IdentityContext, Principal}

  @schema_version "phase2"
  @uuid_v5_namespace "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

  @type receipt_spec :: %{
          required(:event_kind) => atom(),
          required(:source_event_kind) => atom(),
          required(:natural_key) => String.t(),
          required(:summary) => String.t(),
          required(:timestamp) => DateTime.t() | nil,
          optional(:turn_key) => String.t(),
          optional(:session_chain_position) => non_neg_integer(),
          optional(:source_metadata) => map(),
          optional(:content_metadata) => map(),
          optional(:policy_decision) => :allow | :deny,
          optional(:outcome) => :success | :upstream_error | :cancelled,
          optional(:upstream_status_code) => integer() | nil,
          # B7 — non-signed UI metadata derived at classify time.
          optional(:tool_name) => String.t() | nil,
          optional(:tool_summary) => String.t() | nil,
          # Tool-call extractor — schema-on-read enriched tags.
          optional(:tags) => map() | nil
        }

  @type build_context :: %{
          required(:tenant_id) => String.t(),
          required(:principal) => String.t(),
          required(:source) => String.t(),
          required(:source_session_id) => String.t(),
          required(:signer) => String.t(),
          required(:secrets_provider) => {module(), term()}
        }

  @type commit :: %{
          required(:envelope) => Recurse.Shared.Attestation.Envelope.t(),
          required(:ledger_opts) => keyword(),
          required(:run_id) => String.t()
        }

  @spec build_commit(receipt_spec(), build_context()) :: {:ok, commit()} | {:error, term()}
  def build_commit(spec, context) when is_map(spec) and is_map(context) do
    run_id = run_id_for(spec, context)
    session_id = session_id_for(context)
    turn_id = turn_id_for(spec, context)
    session_chain_position = Map.get(spec, :session_chain_position, 0)
    timestamp = spec.timestamp || DateTime.utc_now()
    predicate_map = predicate_map(spec, context, run_id)

    envelope_opts = [
      run_id: run_id,
      session_id: session_id,
      turn_id: turn_id,
      session_chain_position: session_chain_position,
      signer: context.signer,
      secrets_provider: context.secrets_provider,
      timestamp: timestamp,
      payload_uri: payload_uri(context, session_id, run_id)
    ]

    with {:ok, envelope} <-
           EnvelopeBuilder.build_imported(
             spec.event_kind,
             identity_context(context, run_id),
             predicate_map,
             envelope_opts
           ) do
      {:ok,
       %{
         envelope: envelope,
         ledger_opts: ledger_opts(spec),
         run_id: run_id
       }}
    end
  end

  @spec run_id_for(receipt_spec(), build_context()) :: Ecto.UUID.t()
  def run_id_for(spec, context) do
    deterministic_uuid("#{context.tenant_id}:#{context.source}:receipt", spec.natural_key)
  end

  @spec session_id_for(build_context()) :: Ecto.UUID.t()
  def session_id_for(context) do
    deterministic_uuid(
      "#{context.tenant_id}:#{context.source}:session",
      context.source_session_id
    )
  end

  @spec deterministic_uuid(String.t(), String.t()) :: Ecto.UUID.t()
  def deterministic_uuid(namespace, key) do
    name = namespace <> ":" <> key
    hash = :crypto.hash(:sha, uuid_bytes!(@uuid_v5_namespace) <> name)

    <<part1::binary-size(4), part2::binary-size(2), version_bytes::binary-size(2),
      variant_bytes::binary-size(2), part5::binary-size(6), _rest::binary>> = hash

    <<_old_version::4, version_rest::4, version_tail>> = version_bytes
    <<_old_variant::2, variant_rest::6, variant_tail>> = variant_bytes

    part3 = <<5::4, version_rest::4, version_tail>>
    part4 = <<2::2, variant_rest::6, variant_tail>>

    [part1, part2, part3, part4, part5]
    |> Enum.map_join("-", &Base.encode16(&1, case: :lower))
  end

  defp uuid_bytes!(uuid) do
    uuid
    |> String.replace("-", "")
    |> Base.decode16!(case: :mixed)
  end

  defp identity_context(context, run_id) do
    IdentityContext.new(%{
      machine_identity: context.signer,
      principal:
        Principal.obo_human(%{
          issuer: context.signer,
          subject: context.principal
        }),
      tenant_id: context.tenant_id,
      correlation_id: run_id
    })
  end

  defp predicate_map(spec, context, run_id) do
    %{
      "schema_version" => @schema_version,
      "source" => context.source,
      "source_event_kind" => Atom.to_string(spec.source_event_kind),
      "source_session_id_sha256" => sha256_hex(context.source_session_id),
      "run_id" => run_id,
      "summary" => spec.summary,
      "metadata" => Map.get(spec, :source_metadata, %{}),
      "content" => Map.get(spec, :content_metadata, %{}),
      "attestation_sources" => [context.source]
    }
  end

  defp payload_uri(context, session_id, run_id) do
    PredicateOnlyUri.imported_uri_scheme_prefix() <>
      "#{context.source}/#{session_id}/#{run_id}"
  end

  defp ledger_opts(spec) do
    [
      session_mode: :source_session_epochs,
      policy_decision: Map.get(spec, :policy_decision, :allow),
      outcome: Map.get(spec, :outcome, :success),
      upstream_status_code: Map.get(spec, :upstream_status_code),
      # B7 — non-signed UI metadata; nil for non-tool_call specs.
      tool_name: Map.get(spec, :tool_name),
      tool_summary: Map.get(spec, :tool_summary),
      # Tool-call extractor — schema-on-read tags; nil for non-tool_call specs.
      tags: Map.get(spec, :tags)
    ]
  end

  defp turn_id_for(spec, context) do
    turn_key = Map.get(spec, :turn_key, spec.natural_key)
    deterministic_uuid("#{context.tenant_id}:#{context.source}:turn", turn_key)
  end

  defp sha256_hex(value) do
    :crypto.hash(:sha256, value)
    |> Base.encode16(case: :lower)
  end
end
