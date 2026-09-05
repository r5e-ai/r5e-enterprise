defmodule Recurse.Gateway.AuditPlane.EvidenceZipBuilder do
  @moduledoc """
  Build an Export Evidence zip for a single `run_id` (F002 T063, FR-022,
  F001 FR-048 surface 2).

  Pure module. Takes a `run_id` + the identity context (needed for S3
  StorageProvider calls) and returns `{:ok, zip_bytes}` on success.

  ## Zip contents (per `contracts/recurse_verify_spec.md` §Output format)

    * `signed_predicate.json` — JSON-encoded signed predicate.
    * `outer_container.json` — JSON-encoded outer container state.
    * `payload.json` — detached request/response pair bytes from S3.
    * `inclusion_proof.transitem` — concatenated RFC 9162 TransItem bytes:
      `<session_chain_len:uint32><session_chain_bytes>
       <global_len:uint32><global_bytes>`.
    * `signing_key.pem` — PEM-encoded public key for the signer KMS key
      version used for this attestation. Sourced from the `signing_keys`
      archive (F001 signing_key_archive contract + US5 T074).
    * `policy_bundle.cedar` — Cedar policy bundle bytes matching the
      attestation's `policy_canonical_hash`. Resolved from the
      `policy_bundles` archive first (spec 012 S6b: every activated
      bundle is archived by `Recurse.Gateway.Policy.BundleArchive`), so
      an export after a policy change still packs the bundle that decided.
    * `predicate/<run_id>.json` — spec 012 S6b. For predicate-only
      receipts, the JCS-encoded predicate body — the exact bytes the
      signed `payload_hash` is the SHA-256 of — fetched from the
      StorageProvider via `attestations.predicate_body_uri`. Absent when
      the receipt predates retention or the body could not be fetched
      (the manifest says so); `recurse-verify` step 5 hashes it.
    * `payloads/<sha256-hex>` — spec 012 S6b. The retained upstream
      request and response bytes (`R5E_RETAIN_PAYLOADS`) behind the
      predicate's `prompt_hash` / `response_hash`, looked up through the
      `LlmCallRecord` of the receipt (or, for a `:tool_use_denied` child,
      of its parent via `turn_id`). `recurse-verify` step 7 hashes them.
    * `manifest.json` — index of files + run_id + timestamps + provenance
      tags (`signing_key_source`, `policy_bundle_source`) so the auditor
      can see which fallback tier produced each artifact (issue #29
      "Ramifications" — manifest provenance), plus `predicate_body`,
      `payloads` and `payload_retention` (S6b).

  ## Iron Law check

  Pure function. No process. No state. Runs on the request process.

  ## Multi-run exports

  For N > 1 run_ids `build_many/3` builds one inner zip per run_id and
  nests them in a wrapping zip (zip-of-zips). Each inner zip is
  self-verifiable via `recurse-verify` without unpacking the outer.
  """

  alias Recurse.Gateway.AuditPlane.PredicateOnlyUri
  alias Recurse.Gateway.AuditPlane.ReceiptSerializers
  alias Recurse.Gateway.AuditPlane.Resolvers.{Payload, PolicyBundle, SigningKey}
  alias Recurse.Gateway.AuditPlane.Resolvers.SigningKey.Fallback, as: SigningKeyFallback
  alias Recurse.Gateway.AuditPlane.TenantGuard
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmCallRecord
  alias Recurse.Shared.IdentityContext

  import Ecto.Query, only: [from: 2]

  require Logger

  @type build_result ::
          {:ok, binary()}
          | {:error,
             :not_found
             | :tenant_mismatch
             | :payload_fetch_failed
             | :signing_key_not_found
             | :policy_bundle_not_found
             | :inclusion_proof_failed
             | term()}

  @doc """
  Build an Export Evidence zip for a single `run_id`. Returns
  `{:ok, zip_bytes}` or `{:error, reason}`.

  `opts` accepts:

    * `:repo` — Ecto repo override (tests). Defaults to
      `Recurse.Providers.Repo`.
  """
  @spec build(String.t(), IdentityContext.t(), keyword()) :: build_result()
  def build(run_id, %IdentityContext{} = identity_ctx, opts \\ []) when is_binary(run_id) do
    repo = Keyword.get(opts, :repo, Repo)

    with {:ok, att} <- fetch_attestation(repo, run_id),
         :ok <- TenantGuard.validate(identity_ctx, att),
         {:ok, payload_bytes} <- fetch_payload(att.payload_uri, identity_ctx),
         {:ok, signing_key_pem, signing_key_source} <- fetch_signing_key(repo, att),
         {:ok, policy_bundle_bytes, policy_bundle_source, resolved_policy_hash} <-
           fetch_policy_bundle(repo, att.policy_canonical_hash),
         {:ok, inclusion_proof_bytes} <- fetch_inclusion_proof(run_id) do
      # Spec 012 S6b — both best-effort: an export never fails because a
      # retained artifact is missing; the manifest + verifier say so.
      predicate_body = fetch_predicate_body(att, identity_ctx)
      {payloads, payload_retention} = fetch_payloads(repo, att, identity_ctx)

      manifest =
        manifest_json(att,
          signing_key_source: signing_key_source,
          policy_bundle_source: policy_bundle_source,
          resolved_policy_hash: resolved_policy_hash,
          predicate_body: predicate_body,
          payloads: payloads,
          payload_retention: payload_retention
        )

      files =
        [
          {~c"signed_predicate.json", signed_predicate_json(att)},
          {~c"outer_container.json", outer_container_json(att)},
          {~c"payload.json", payload_bytes},
          {~c"inclusion_proof.transitem", inclusion_proof_bytes},
          {~c"signing_key.pem", signing_key_pem},
          {~c"policy_bundle.cedar", policy_bundle_bytes}
        ] ++
          predicate_body_entries(att, predicate_body) ++
          Enum.map(payloads, fn %{file: file, bytes: bytes} -> {to_charlist(file), bytes} end) ++
          [{~c"manifest.json", manifest}]

      case :zip.create(~c"evidence-#{run_id}.zip", files, [:memory]) do
        {:ok, {_name, zip_bytes}} -> {:ok, zip_bytes}
        {:error, reason} -> {:error, {:zip_failed, reason}}
      end
    end
  end

  @doc """
  Build a zip-of-zips for multiple run_ids. Each inner zip is produced
  by `build/3`. Returns `{:ok, outer_zip_bytes}` on full success or
  `{:error, {run_id, reason}}` on the first failure.
  """
  @spec build_many([String.t()], IdentityContext.t(), keyword()) ::
          {:ok, binary()} | {:error, {String.t(), term()}}
  def build_many(run_ids, %IdentityContext{} = identity_ctx, opts \\ []) when is_list(run_ids) do
    result =
      Enum.reduce_while(run_ids, {:ok, []}, fn run_id, {:ok, acc} ->
        case build(run_id, identity_ctx, opts) do
          {:ok, inner} ->
            entry = {~c"evidence-#{run_id}.zip", inner}
            {:cont, {:ok, [entry | acc]}}

          {:error, reason} ->
            {:halt, {:error, {run_id, reason}}}
        end
      end)

    with {:ok, entries} <- result do
      case :zip.create(~c"evidence-export.zip", Enum.reverse(entries), [:memory]) do
        {:ok, {_name, outer_bytes}} -> {:ok, outer_bytes}
        {:error, reason} -> {:error, {:zip_failed, reason}}
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Internals
  # ---------------------------------------------------------------------------

  defp fetch_attestation(repo, run_id) do
    case repo.get(Attestation, run_id) do
      nil -> {:error, :not_found}
      %Attestation{} = att -> {:ok, att}
    end
  end

  # Predicate-only URI short-circuit delegates to
  # `Recurse.Gateway.AuditPlane.PredicateOnlyUri.kind/1` (issue #29 /
  # AD-1 Option A; extended for imported scheme in issue #60). Both
  # families (`:system` Gateway-internal events and `:imported`
  # source-session artifacts from MR !80's JSONL importer) are
  # predicate-only by design — the signed_predicate IS the audit
  # content, no separate payload bytes were stored. The zip gets the
  # same placeholder marker for both, documenting that the offline
  # recurse-verify CLI sees a stable token instead of a failed-fetch
  # message. Real-payload URIs route through `Resolvers.Payload.fetch/2`.
  defp fetch_payload(payload_uri, identity_ctx) when is_binary(payload_uri) do
    case PredicateOnlyUri.kind(payload_uri) do
      :system ->
        {:ok, PredicateOnlyUri.evidence_zip_payload_marker()}

      :imported ->
        {:ok, PredicateOnlyUri.evidence_zip_payload_marker()}

      :other ->
        case Payload.fetch(payload_uri, identity_ctx) do
          {:ok, bytes} ->
            {:ok, bytes}

          {:error, {:fetch_failed, reason}} ->
            Logger.error("evidence_zip_builder payload fetch failed: #{inspect(reason)}")

            {:error, :payload_fetch_failed}
        end
    end
  end

  defp fetch_payload(_payload_uri, _identity_ctx),
    do: {:error, :payload_fetch_failed}

  # Spec 012 S6b — the retained JCS predicate body (predicate-only
  # receipts). `:absent` when never retained or unfetchable; the bytes
  # are packed as stored, hash checked by the verifier, not here.
  defp fetch_predicate_body(%Attestation{predicate_body_uri: uri} = att, identity_ctx)
       when is_binary(uri) and uri != "" do
    case Payload.fetch(uri, identity_ctx) do
      {:ok, bytes} ->
        {:ok, bytes}

      {:error, {:fetch_failed, reason}} ->
        Logger.warning(
          "evidence_zip_builder: predicate body fetch failed for run_id=#{att.run_id} " <>
            "uri=#{uri}: #{inspect(reason)} — exporting without predicate/<run_id>.json"
        )

        :absent
    end
  end

  defp fetch_predicate_body(_att, _identity_ctx), do: :absent

  defp predicate_body_entries(%Attestation{run_id: run_id}, {:ok, bytes}),
    do: [{to_charlist(predicate_body_file(run_id)), bytes}]

  defp predicate_body_entries(_att, :absent), do: []

  defp predicate_body_file(run_id), do: "predicate/#{run_id}.json"

  # Spec 012 S6b — retained request/response bytes. The LlmCallRecord
  # belongs to the parent `:llm_call_attested`; a `:tool_use_denied`
  # child points at its parent through `turn_id`.
  defp fetch_payloads(repo, %Attestation{} = att, identity_ctx) do
    case llm_call_record(repo, att) do
      nil ->
        {[], "no_llm_call_record"}

      %LlmCallRecord{} = record ->
        entries =
          [
            {"request", record.prompt_payload_uri, record.prompt_hash},
            {"response", record.response_payload_uri, record.response_hash}
          ]
          |> Enum.flat_map(fn {role, uri, hash} ->
            fetch_payload_entry(role, uri, hash, identity_ctx)
          end)

        {entries, retention_status(record)}
    end
  end

  defp llm_call_record(repo, %Attestation{run_id: run_id, turn_id: turn_id}) do
    candidates = Enum.reject(Enum.uniq([run_id, turn_id]), &is_nil/1)

    repo.one(
      from(c in LlmCallRecord,
        where: c.signed_predicate_run_id in ^candidates,
        order_by: [asc: c.inserted_at],
        limit: 1
      )
    )
  rescue
    error ->
      Logger.warning("evidence_zip_builder: llm_call_record lookup raised #{inspect(error)}")

      nil
  end

  defp fetch_payload_entry(role, uri, <<_::binary-size(32)>> = hash, identity_ctx)
       when is_binary(uri) and uri != "" do
    case Payload.fetch(uri, identity_ctx) do
      {:ok, bytes} ->
        hex = Base.encode16(hash, case: :lower)
        [%{role: role, file: "payloads/#{hex}", sha256: hex, bytes: bytes}]

      {:error, {:fetch_failed, reason}} ->
        Logger.warning(
          "evidence_zip_builder: #{role} payload fetch failed uri=#{uri}: #{inspect(reason)}"
        )

        []
    end
  end

  defp fetch_payload_entry(_role, _uri, _hash, _identity_ctx), do: []

  defp retention_status(%LlmCallRecord{payload_truncated: true}), do: "truncated"

  defp retention_status(%LlmCallRecord{prompt_payload_uri: nil, response_payload_uri: nil}),
    do: "not_retained"

  defp retention_status(%LlmCallRecord{}), do: "retained"

  # Signing-key resolution: archive lookup via the shared resolver, with
  # an export-specific 2-tier fallback (live KMS provider, broker PEM)
  # so evidence export succeeds even when the archive is empty
  # (operator UX). The returned source discriminator threads through to
  # `manifest_json/1` so auditors see which tier produced the PEM.
  #
  # The fallback chain itself (KMS provider + broker-local PEM dispatch)
  # lives in `Resolvers.SigningKey.Fallback` — extracted in F7 fix when
  # `LocalVerifyHandler` re-acquired the same fallback shape (Constitution
  # Principle VII; the second consumer triggers extraction). See that
  # module's `@moduledoc` for the dispatch contract.
  defp fetch_signing_key(_repo, %Attestation{
         signer_kms_key_id: kms_key_id,
         signer_key_version: key_version
       })
       when is_binary(kms_key_id) and is_binary(key_version) do
    case SigningKey.fetch_from_archive(kms_key_id, key_version) do
      {:ok, pem, :archive} ->
        {:ok, pem, :archive}

      {:error, :not_found} ->
        Logger.warning(
          "signing_keys archive empty for kms_key_id=#{inspect(kms_key_id)} key_version=#{inspect(key_version)}; " <>
            "falling back via Resolvers.SigningKey.Fallback (issue #24)."
        )

        case SigningKeyFallback.fetch(kms_key_id, key_version) do
          {:ok, pem, source} -> {:ok, pem, source}
          {:error, :not_found} -> {:error, :signing_key_not_found}
        end
    end
  end

  defp fetch_signing_key(_repo, _att), do: {:error, :signing_key_not_found}

  # Policy-bundle resolution delegates to the shared resolver. The
  # resolver carries source discrimination (`:archive | :loader_match |
  # :loader_drift`) which we thread through to manifest provenance,
  # plus the resolved hash — for `:loader_drift` the resolver hands
  # back the LOADER's hash, NOT the receipt's. Auditors need both
  # recorded so the drift is provable from the artifact alone (GAN
  # review fix on !31, gemini_cli finding).
  defp fetch_policy_bundle(_repo, policy_canonical_hash) when is_binary(policy_canonical_hash) do
    case PolicyBundle.resolve(policy_canonical_hash) do
      {:ok, bytes, source, resolved_hash} ->
        {:ok, bytes, source, resolved_hash}

      {:error, :not_found} ->
        {:error, :policy_bundle_not_found}
    end
  end

  defp fetch_policy_bundle(_repo, _hash), do: {:error, :policy_bundle_not_found}

  defp fetch_inclusion_proof(run_id) do
    case PostgresMerkleLedger.generate_inclusion_proof(run_id) do
      {:ok, %{session_chain: sc, global: g}} ->
        {:ok, encode_inclusion_proof(sc, g)}

      {:error, reason} ->
        {:error, {:inclusion_proof_failed, reason}}
    end
  end

  # Concatenate two TransItem bytes with length prefixes so the auditor
  # verifier can split them into local + global proofs.
  defp encode_inclusion_proof(session_chain_bytes, global_bytes) do
    <<byte_size(session_chain_bytes)::unsigned-integer-size(32), session_chain_bytes::binary,
      byte_size(global_bytes)::unsigned-integer-size(32), global_bytes::binary>>
  end

  # JSON shapes — delegate to ReceiptSerializers for canonical rendering.
  # The export zip needs the heavy bytes (signature + proofs) so the
  # offline recurse-verify CLI can run; pass the include-bytes opts.
  defp signed_predicate_json(att) do
    att
    |> ReceiptSerializers.signed_predicate(include_signature_bytes: true)
    |> JSON.encode!()
  end

  defp outer_container_json(att) do
    att
    |> ReceiptSerializers.outer_container(include_proof_bytes: true)
    |> JSON.encode!()
  end

  defp manifest_json(att, opts) do
    signing_key_source = Keyword.fetch!(opts, :signing_key_source)
    policy_bundle_source = Keyword.fetch!(opts, :policy_bundle_source)
    resolved_policy_hash = Keyword.fetch!(opts, :resolved_policy_hash)
    predicate_body = Keyword.get(opts, :predicate_body, :absent)
    payloads = Keyword.get(opts, :payloads, [])
    payload_retention = Keyword.get(opts, :payload_retention, "not_retained")

    predicate_body_file =
      case predicate_body do
        {:ok, _bytes} -> predicate_body_file(att.run_id)
        :absent -> nil
      end

    JSON.encode!(%{
      "run_id" => att.run_id,
      "exported_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "files" =>
        [
          "signed_predicate.json",
          "outer_container.json",
          "payload.json",
          "inclusion_proof.transitem",
          "signing_key.pem",
          "policy_bundle.cedar"
        ] ++
          List.wrap(predicate_body_file) ++
          Enum.map(payloads, & &1.file) ++
          ["manifest.json"],
      # Spec 012 S6b — where the bytes behind the signed hashes are. nil /
      # "not_retained" is a statement, not an error: the verifier reports
      # those checks as skipped / not included rather than failed.
      "predicate_body" => predicate_body_file,
      "payloads" =>
        Enum.map(payloads, fn %{role: role, file: file, sha256: sha} ->
          %{"role" => role, "file" => file, "sha256" => sha}
        end),
      "payload_retention" => payload_retention,
      "format_version" => "1.1",
      "verification_level_at_export" => atom_to_string(att.verification_level),
      "signing_key_source" => Atom.to_string(signing_key_source),
      "policy_bundle_source" => Atom.to_string(policy_bundle_source),
      # Resolved hash lets the auditor diagnose `:loader_drift` from the
      # exported artifact alone — when this differs from the receipt's
      # `policy_canonical_hash` (rendered in `signed_predicate.json`),
      # the drift is provable without re-hashing `policy_bundle.cedar`.
      # GAN review fix on !31 (gemini_cli finding).
      "resolved_policy_hash" => Base.encode16(resolved_policy_hash, case: :lower)
    })
  end

  defp atom_to_string(nil), do: nil
  defp atom_to_string(v) when is_atom(v), do: Atom.to_string(v)
  defp atom_to_string(v) when is_binary(v), do: v
end
