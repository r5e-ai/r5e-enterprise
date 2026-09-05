defmodule Recurse.Gateway.Admin.LocalVerifyHandler do
  @moduledoc """
  `POST /v1/audit/receipts/{run_id}/verify` (F004 T075, FR-018).

  Runs the 5 distinct cryptographic verification checks per FR-018
  server-side against a pre-loaded receipt + the F002-existing Cedar
  policy bundle + the F002-existing `merkle_nodes` / `global_ledger_entries`
  rows. Returns a JSON checklist with each step's `status: "pass" | "fail"`
  and `explanation` text.

  The 5 checks (per FR-018):

    1. **Signature**: DSSE signature over the predicate envelope verifies
       against the trust-anchor pubkey loaded from `signing_keys` archive
       for the receipt's `(signer_kms_key_id, signer_key_version)` pair.
    2. **Local Merkle inclusion**: receipt's per-session Merkle inclusion
       proof verifies up to the session epoch root. Under 1-run-1-session
       the session tree has a single leaf, so the proof is empty and the
       verification reduces to `MerkleTree.hash_leaf(predicate_bytes) ==
       session_chain_root`.
    3. **Global Merkle inclusion**: session epoch root's RFC 9162 inclusion
       proof verifies up to the global ledger root. Decoded from
       `attestations.global_inclusion_proof` (TransItem bytes).
    4. **Policy hash match**: `policy_canonical_hash` in the predicate
       names a bundle in the `policy_bundles` archive (spec 012 S6b: every
       activation is archived), else matches the currently-loaded bundle's
       `canonical_hash`. Mismatch is recorded as a fail with the diff hashes
       in the explanation.
    5. **Payload hash match**: predicate's `payload_hash` matches the
       SHA-256 of the S3-stored payload bytes. For system events
       (predicate-only — `payload_uri` starts with the system sentinel
       scheme) the retained JCS predicate body (`predicate_body_uri`,
       spec 012 S6b) is fetched and hashed — MATCH / FAIL, the same check
       `recurse-verify` step 5 runs offline. When no body was retained
       (pre-S6b receipts) and for imported events (`recurse://import/...`)
       the hash is bound by the DSSE signature and the check reports that.

  ## Cedar action + emission

  Reuses F002's `Recurse::Action::ReadReceipts` (no new gate). Emits a
  single `:ui_query` (`query_kind: "verify_locally"`) UI-receipt per
  invocation regardless of pass/fail, per `data-model.md` §0.

  ## Response shape

      %{
        "run_id" => "uuid",
        "overall_status" => "pass" | "fail",
        "checks" => [
          %{"step" => 1, "name" => "signature",
            "status" => "pass", "explanation" => "..."},
          %{"step" => 2, "name" => "local_merkle_inclusion",
            "status" => "pass", "explanation" => "..."},
          %{"step" => 3, "name" => "global_merkle_inclusion",
            "status" => "pass", "explanation" => "..."},
          %{"step" => 4, "name" => "policy_hash_match",
            "status" => "pass", "explanation" => "..."},
          %{"step" => 5, "name" => "payload_hash_match",
            "status" => "pass", "explanation" => "..."}
        ],
        "verified_at" => "2026-04-24T...",
        "tier_completeness_advisory" => "partial"
      }

  Each check's `explanation` carries enough detail for an auditor to
  reproduce the result without server access (e.g., a hex hash mismatch
  shows both expected + actual; a successful signature check names the
  algorithm + key id).

  ## Iron Law check (`elixir:phoenix-thinking`, `elixir:elixir-thinking`)

  Pure module — no GenServer. Runs on the Bandit-spawned request process.
  All five checks are pure functions of the loaded receipt + the storage
  fetch + the bundle ref; no inter-check state besides the accumulator.

  ## SC-002 budget (≤3s)

  The hot operations are: (a) one Repo.get for the attestation, (b) one
  Repo.one for the signing-key PEM, (c) one StorageProvider.get_payload
  call, (d) one Active.current/0 (pre-loaded, ETS-fast),
  (e) one MerkleTree.verify_inclusion_proof. The Receipt Detail
  pre-fetches global Merkle siblings into the response (T074), so the
  SPA's Verify Locally completes well within budget.

  ## Cross-references

    * `specs/004-audit-console/spec.md` FR-018, SC-002
    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"Receipt Detail" (verify endpoint contract)
    * `specs/004-audit-console/data-model.md` §0
      (`:ui_query` `query_kind: "verify_locally"`)
    * `apps/recurse_gateway/lib/recurse_gateway/audit_plane/receipts_handler.ex`
      (T074 — pre-fetches proof envelope into Receipt Detail response)
    * `apps/recurse_shared/lib/recurse_shared/attestation/dsse.ex`
      (DSSE PAE primitive reused here for signature verification input)
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.AuditPlane.PredicateOnlyUri
  alias Recurse.Gateway.AuditPlane.Resolvers.{Payload, PolicyBundle, SigningKey}
  alias Recurse.Gateway.AuditPlane.Resolvers.SigningKey.Fallback, as: SigningKeyFallback
  alias Recurse.Gateway.AuditPlane.TenantGuard
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Providers.Impls.PostgresMerkleLedger.MerkleTree
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.GlobalLedgerEntry
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Attestation.Dsse
  alias Recurse.Shared.Attestation.Rfc9162
  alias Recurse.Shared.IdentityContext

  import Ecto.Query, only: [from: 2]

  require Logger

  @action "Recurse::Action::ReadReceipts"
  @dsse_payload_type "application/vnd.in-toto+json"

  @doc """
  Entry point. Returns the responded `Plug.Conn`.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{path_params: %{"run_id" => run_id}} = conn)
      when is_binary(run_id) do
    resource = %{
      type: "Recurse::Resource::AuditEndpoint",
      id: "v1_audit_receipts_verify",
      attrs: %{"endpoint" => "/v1/audit/receipts/#{run_id}/verify"}
    }

    case Authz.gate(conn, @action, resource, %{"run_id" => run_id}) do
      {:ok, conn_with_ctx, ctx, _bundle_ref} ->
        do_handle(conn_with_ctx, ctx, run_id)

      error ->
        Authz.dispatch_gate_error(conn, error)
    end
  end

  def handle(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "run_id path parameter is required")
  end

  # ---------------------------------------------------------------------------
  # Verification pipeline
  # ---------------------------------------------------------------------------

  defp do_handle(conn, ctx, run_id) do
    with {:ok, %Attestation{} = att} <- fetch_attestation(run_id),
         :ok <- TenantGuard.validate(ctx, att) do
      run_checks_and_respond(conn, ctx, att)
    else
      {:error, :not_found} ->
        Authz.send_not_found(conn, "no attestation for run_id #{run_id}")

      {:error, :tenant_mismatch} ->
        Authz.send_forbidden(conn, :tenant_mismatch)
    end
  end

  defp run_checks_and_respond(conn, ctx, %Attestation{} = att) do
    checks = run_checks(att, ctx)
    overall_status = if Enum.all?(checks, &(&1.status == :pass)), do: :pass, else: :fail

    body =
      JSON.encode!(%{
        "run_id" => att.run_id,
        "overall_status" => Atom.to_string(overall_status),
        "checks" => Enum.map(checks, &check_to_json/1),
        "verified_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
        "tier_completeness_advisory" => to_string_or_nil(att.tier_completeness_advisory)
      })

    emit_verify_query(ctx, att.run_id, overall_status)

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(200, body)
  end

  defp run_checks(%Attestation{} = att, ctx) do
    # The signature check is computed first so its outcome can be threaded
    # into the system-event payload-hash short-circuit (GAN-review fix #6,
    # 2026-04-25): for system events the persisted attestation does NOT
    # carry the JCS-encoded predicate map (EnvelopeBuilder.build_system/4
    # hashes a caller-supplied map we don't store), so the payload-hash
    # check must rely on the signature check to bind `payload_hash` to
    # the predicate. If the signature failed, that binding is gone — we
    # cannot honestly report the payload hash as "implied-pass".
    sig_check = check_signature(att)

    [
      sig_check,
      check_local_merkle_inclusion(att),
      check_global_merkle_inclusion(att),
      check_policy_hash_match(att),
      check_payload_hash_match(att, ctx, sig_check)
    ]
  end

  # ---------------------------------------------------------------------------
  # Check 1 — DSSE signature over the predicate envelope.
  # ---------------------------------------------------------------------------

  defp check_signature(%Attestation{
         signed_predicate_bytes: predicate_bytes,
         dsse_signature: signature,
         signer_kms_key_id: kms_key_id,
         signer_key_version: key_version
       })
       when is_binary(predicate_bytes) and is_binary(signature) and
              is_binary(kms_key_id) and is_binary(key_version) do
    case resolve_signing_key(kms_key_id, key_version) do
      {:ok, pem, archived_algorithm, source} ->
        key = %{pem: pem, source: source, kms_key_id: kms_key_id, key_version: key_version}

        verify_signature(
          signing_algorithm(archived_algorithm, pem),
          predicate_bytes,
          signature,
          key
        )

      {:error, :not_found} ->
        check(
          :fail,
          1,
          "signature",
          "signing-key not resolvable for " <>
            "(kms_key_id=#{redact(kms_key_id)}, key_version=#{key_version}); " <>
            "tried archive, secrets-provider, broker-local PEM"
        )
    end
  end

  defp check_signature(_att) do
    check(
      :fail,
      1,
      "signature",
      "missing signed_predicate_bytes / dsse_signature / signer key reference"
    )
  end

  # Only ES256 (`:ecdsa_p256`) has a verifier in the console today. Anything
  # else is reported as `unsupported_algorithm`, NOT run through
  # `Dsse.verify_es256/4`: an Ed25519 signature is 64 bytes, the exact size
  # of a raw ES256 `r || s`, so the ES256 path would return a well-formed
  # but FALSE `:signature_mismatch` verdict (spec 012 S1 review). The
  # local PEM signer (`R5E_LOCAL_SIGNING_ALG=ed25519`) is the source of
  # such receipts; the Ed25519 verifier lives in r5e-core's
  # `recurse_verify` (plan §11), not here yet.
  defp verify_signature(:ecdsa_p256, predicate_bytes, signature, key) do
    case Dsse.verify_es256(@dsse_payload_type, predicate_bytes, signature, key.pem) do
      :ok ->
        check(
          :pass,
          1,
          "signature",
          "DSSE ES256 signature verified against signing-key " <>
            "(source=#{key.source}, kms_key_id=#{redact(key.kms_key_id)}, " <>
            "key_version=#{key.key_version})"
        )

      {:error, reason} ->
        check(:fail, 1, "signature", "DSSE signature verification failed: #{inspect(reason)}")
    end
  end

  defp verify_signature(algorithm, _predicate_bytes, _signature, key) do
    check(
      :fail,
      1,
      "signature",
      "unsupported_algorithm: receipt is signed with #{algorithm_label(algorithm)} " <>
        "(source=#{key.source}, kms_key_id=#{redact(key.kms_key_id)}, " <>
        "key_version=#{key.key_version}); the console verifies ES256 (ecdsa_p256) " <>
        "signatures only, so this signature was NOT checked and this result is not " <>
        "evidence of tampering. Ed25519 receipts cannot be verified here or offline " <>
        "by recurse-verify yet; set R5E_LOCAL_SIGNING_ALG=es256 for verifiable receipts."
    )
  end

  # Prefer the archived `signing_keys.algorithm` (pinned at rotation time);
  # when the key came through the provider fallback (no archive row, e.g.
  # every `observed://` receipt), read the algorithm off the PEM itself.
  defp signing_algorithm(archived, _pem) when archived in [:ecdsa_p256, :ed25519, :rsa_pss_2048],
    do: archived

  defp signing_algorithm(_missing, pem) do
    case Dsse.public_key_algorithm(pem) do
      {:ok, algorithm} -> algorithm
      {:error, reason} -> {:unknown, reason}
    end
  end

  defp algorithm_label({:unknown, reason}), do: "an unrecognised key (#{inspect(reason)})"
  defp algorithm_label(algorithm) when is_atom(algorithm), do: Atom.to_string(algorithm)

  # Resolve the signing-key PEM for the receipt's `(kms_key_id, key_version)`.
  #
  # Layered chain (issue #24 / F7):
  #   1. `signing_keys` archive (immutable per-rotation snapshot — preferred
  #      because it pins the key WAS active at receipt commit time).
  #   2. On miss, fall back via `Resolvers.SigningKey.Fallback`:
  #        * `observed://...` synthetic signers — broker's local PEM at
  #          `:internal_jwt.signing_key_path` (predicate-only events were
  #          signed via the broker's internal JWT key, NOT via KMS).
  #        * real KMS ARN — `SecretsProvider.public_key/2`.
  #
  # Until the KmsRotationWatcher (issue #24) backfills the archive,
  # observed-tier receipts ALWAYS arrive here on the fallback path; the
  # cherry-pick of dangling commit c11a16c restored that path after the
  # MR !31 audit-pass refactor moved the archive query into
  # `Resolvers.SigningKey` and inadvertently dropped the fallback (F7).
  #
  # Returns `{:ok, pem, archived_algorithm | nil, source}`; the algorithm is
  # only known from the archive row (the fallback returns a bare PEM).
  defp resolve_signing_key(kms_key_id, key_version) do
    case SigningKey.fetch_record_from_archive(kms_key_id, key_version) do
      {:ok, %{public_key_pem: pem, algorithm: algorithm}, :archive} ->
        {:ok, pem, algorithm, :archive}

      {:error, :not_found} ->
        Logger.warning(fn ->
          "local_verify signing_keys archive empty for " <>
            "kms_key_id=#{inspect(kms_key_id)} key_version=#{inspect(key_version)}; " <>
            "falling back via Resolvers.SigningKey.Fallback (issue #24, F7)."
        end)

        case SigningKeyFallback.fetch(kms_key_id, key_version) do
          {:ok, pem, source} -> {:ok, pem, nil, source}
          {:error, :not_found} = miss -> miss
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Check 2 — Local Merkle inclusion (session chain).
  # ---------------------------------------------------------------------------

  defp check_local_merkle_inclusion(%Attestation{
         signed_predicate_bytes: predicate_bytes,
         session_chain_root: session_root
       })
       when is_binary(predicate_bytes) and is_binary(session_root) and
              byte_size(session_root) == 32 do
    leaf_hash = MerkleTree.hash_leaf(predicate_bytes)

    if leaf_hash == session_root do
      check(
        :pass,
        2,
        "local_merkle_inclusion",
        "predicate hash leaf matches session_chain_root " <>
          "(1-run-1-session: empty audit path; root=#{hex(session_root)})"
      )
    else
      check(
        :fail,
        2,
        "local_merkle_inclusion",
        "leaf hash #{hex(leaf_hash)} does not match session_chain_root #{hex(session_root)}"
      )
    end
  end

  defp check_local_merkle_inclusion(_att) do
    check(
      :fail,
      2,
      "local_merkle_inclusion",
      "missing signed_predicate_bytes or session_chain_root"
    )
  end

  # ---------------------------------------------------------------------------
  # Check 3 — Global Merkle inclusion (RFC 9162).
  # ---------------------------------------------------------------------------

  defp check_global_merkle_inclusion(%Attestation{
         session_chain_root: session_root,
         global_inclusion_proof: proof_bytes,
         verification_level: vl
       })
       when is_binary(session_root) and is_binary(proof_bytes) and
              byte_size(proof_bytes) > 0 do
    case Rfc9162.decode(proof_bytes) do
      {:ok, %{leaf_index: index, tree_size: tree_size, inclusion_path: path}} ->
        verify_global_against_root(session_root, index, tree_size, path, vl)

      {:error, reason} ->
        check(
          :fail,
          3,
          "global_merkle_inclusion",
          "global inclusion proof bytes did not decode as RFC 9162 TransItem: #{inspect(reason)}"
        )
    end
  end

  defp check_global_merkle_inclusion(%Attestation{verification_level: :signed}) do
    check(
      :fail,
      3,
      "global_merkle_inclusion",
      "receipt has not yet reached :global_inclusion_verified " <>
        "(commit pipeline still in :signed state)"
    )
  end

  defp check_global_merkle_inclusion(_att) do
    check(
      :fail,
      3,
      "global_merkle_inclusion",
      "missing session_chain_root or global_inclusion_proof bytes"
    )
  end

  defp verify_global_against_root(session_root, index, tree_size, path, vl) do
    case load_global_root(tree_size) do
      {:ok, root} ->
        if MerkleTree.verify_inclusion_proof(session_root, index, tree_size, path, root) do
          check(
            :pass,
            3,
            "global_merkle_inclusion",
            "session_chain_root included at index=#{index} in tree_size=#{tree_size}; " <>
              "global root=#{hex(root)}; verification_level=#{vl}"
          )
        else
          check(
            :fail,
            3,
            "global_merkle_inclusion",
            "RFC 9162 inclusion proof did not reconstruct the global root " <>
              "(index=#{index}, tree_size=#{tree_size})"
          )
        end

      {:error, reason} ->
        check(
          :fail,
          3,
          "global_merkle_inclusion",
          "global root rebuild failed: #{inspect(reason)}"
        )
    end
  end

  defp load_global_root(tree_size) when is_integer(tree_size) and tree_size >= 1 do
    leaves =
      Repo.all(
        from(g in GlobalLedgerEntry,
          order_by: [asc: g.sequence],
          select: g.session_epoch_root,
          limit: ^tree_size
        )
      )

    cond do
      length(leaves) < tree_size ->
        {:error, {:tree_size_exceeds_visible_leaves, tree_size, length(leaves)}}

      leaves == [] ->
        {:error, :empty_global_tree}

      true ->
        {:ok, MerkleTree.build_root(leaves)}
    end
  end

  defp load_global_root(_), do: {:error, :invalid_tree_size}

  # ---------------------------------------------------------------------------
  # Check 4 — Policy hash match.
  # ---------------------------------------------------------------------------

  defp check_policy_hash_match(%Attestation{policy_canonical_hash: receipt_hash})
       when is_binary(receipt_hash) do
    if receipt_hash == PredicateOnlyUri.system_event_no_policy_hash() do
      check(
        :pass,
        4,
        "policy_hash_match",
        "system event — predicate carries the synthetic no-policy hash sentinel " <>
          "(receipt was not Cedar-gated; e.g., a UI session lifecycle event)"
      )
    else
      check_policy_against_bundle(receipt_hash)
    end
  end

  defp check_policy_hash_match(_att) do
    check(:fail, 4, "policy_hash_match", "missing policy_canonical_hash on receipt")
  end

  defp check_policy_against_bundle(receipt_hash) do
    # Spec 012 S6b — every activated bundle is archived by canonical hash
    # (`Policy.BundleArchive`), so a receipt evaluated under a bundle that
    # has since been replaced still verifies: consult the archive first,
    # the live bundle only when the archive has no row (pre-S6b receipts).
    case PolicyBundle.resolve(receipt_hash) do
      {:ok, _bytes, :archive, _hash} ->
        check(
          :pass,
          4,
          "policy_hash_match",
          "receipt's policy_canonical_hash #{hex(receipt_hash)} matches an archived " <>
            "Cedar bundle (policy_bundles row written when that bundle was activated)"
        )

      _ ->
        check_policy_against_live_bundle(receipt_hash)
    end
  end

  defp check_policy_against_live_bundle(receipt_hash) do
    # F004 Phase-1 verifier path. The receipt's `policy_canonical_hash`
    # may have been stamped using EITHER of two canonicalization rules
    # (JCS PolicySet::to_json OR SHA-256 of bundle bytes — F002 compat).
    # `PolicyBundle.match_against_bundle/2` runs both rules and reports
    # which (if any) matched. See its `@spec` for return shape.
    with {:ok, %Active{bundle: bundle_ref}} <- Active.current(),
         {:ok, match_kind} <- PolicyBundle.match_against_bundle(receipt_hash, bundle_ref) do
      check(
        :pass,
        4,
        "policy_hash_match",
        "receipt's policy_canonical_hash #{hex(receipt_hash)} matches the " <>
          "currently-loaded Cedar bundle (#{match_kind})"
      )
    else
      {:error, :no_match, %{loader_canonical: loader_hash, bytes_sha: bytes_hash}} ->
        check(
          :fail,
          4,
          "policy_hash_match",
          "receipt's policy_canonical_hash #{hex(receipt_hash)} matches neither " <>
            "the currently-loaded bundle's canonical_hash (#{hex(loader_hash)}) " <>
            "nor SHA-256(bundle_bytes) (#{hex(bytes_hash)}), and the `policy_bundles` " <>
            "archive has no row for it (receipt predates the archive, or its bundle was " <>
            "never activated by this Gateway)"
        )

      {:error, reason} ->
        check(
          :fail,
          4,
          "policy_hash_match",
          "active Cedar bundle unavailable: #{inspect(reason)}"
        )
    end
  end

  # ---------------------------------------------------------------------------
  # Check 5 — Payload hash match.
  # ---------------------------------------------------------------------------

  defp check_payload_hash_match(
         %Attestation{
           payload_uri: payload_uri,
           payload_hash: receipt_hash
         } = att,
         ctx,
         sig_check
       )
       when is_binary(payload_uri) and is_binary(receipt_hash) do
    case PredicateOnlyUri.kind(payload_uri) do
      :system -> check_system_event_payload_hash(att, ctx, sig_check)
      :imported -> check_imported_event_payload_hash(att, sig_check)
      :other -> check_storage_payload_hash(payload_uri, receipt_hash, ctx)
    end
  end

  defp check_payload_hash_match(_att, _ctx, _sig_check) do
    check(:fail, 5, "payload_hash_match", "missing payload_uri or payload_hash on receipt")
  end

  # Spec 012 S6b — the emitter retains the JCS predicate body (the exact
  # bytes `payload_hash` was computed over) and records where. Fetch it
  # and recompute: this is the check the offline verifier runs, and it
  # no longer depends on the signature to vouch for the hash.
  defp check_system_event_payload_hash(
         %Attestation{predicate_body_uri: uri, payload_hash: receipt_hash} = att,
         ctx,
         sig_check
       )
       when is_binary(uri) and uri != "" do
    case Payload.fetch(uri, ctx) do
      {:ok, bytes} ->
        actual = :crypto.hash(:sha256, bytes)

        if actual == receipt_hash do
          check(
            :pass,
            5,
            "payload_hash_match",
            "retained predicate body (#{byte_size(bytes)} bytes, #{uri}) hashes to " <>
              "payload_hash #{hex(actual)} — the bytes the signature commits to are present " <>
              "and unchanged"
          )
        else
          check(
            :fail,
            5,
            "payload_hash_match",
            "retained predicate body at #{uri} hashes to #{hex(actual)} but the receipt's " <>
              "payload_hash is #{hex(receipt_hash)} — the stored body is not the one signed"
          )
        end

      {:error, {:fetch_failed, reason}} ->
        # Recorded but unreadable (deleted per GDPR Art. 17, CAS volume
        # gone): deletion must not invalidate the receipt (StorageProvider
        # contract), so fall back to the signature-bound rationale and say
        # why the bytes themselves were not compared.
        check_system_event_payload_hash(
          %{att | predicate_body_uri: nil},
          ctx,
          sig_check,
          "retained predicate body at #{uri} could not be fetched (#{inspect(reason)}); "
        )
    end
  end

  defp check_system_event_payload_hash(att, ctx, sig_check),
    do: check_system_event_payload_hash(att, ctx, sig_check, "")

  # System events: the payload "bytes" are the JCS-encoded predicate. The
  # commit pipeline already wrote `payload_hash = SHA-256(JCS(predicate_map))`;
  # we re-derive it from `signed_predicate_bytes` for self-verification.
  # NOTE: in F002 the JCS input is the SignedPredicate.to_map result; F004
  # system events go through `EnvelopeBuilder.build_system/4` which hashes
  # the caller-supplied `predicate_map` directly. We can't reconstruct that
  # input from the persisted attestation, so we trust the receipt's own
  # `payload_hash` for system events as long as the signature passed in
  # check 1 (the signature attests that the hash WAS the right one at
  # commit time). This short-circuit is documented as :pass with an
  # "implied by signature" rationale.
  defp check_system_event_payload_hash(
         %Attestation{payload_hash: hash},
         _ctx,
         %{status: :pass},
         prefix
       ) do
    check(
      :pass,
      5,
      "payload_hash_match",
      prefix <>
        "system event — payload is predicate-only and no retained body was compared; " <>
        "hash #{hex(hash)} is bound by the DSSE signature verified at step 1"
    )
  end

  # GAN-review fix (PR-readiness #6, 2026-04-25): the implied-pass for
  # system events relied on the DSSE signature binding `payload_hash` to
  # the predicate. If check 1 (signature) failed, that binding is gone —
  # we cannot honestly report payload_hash as `:pass` with the "bound by
  # signature" rationale. Surface the dependency explicitly: when the
  # signature failed, the payload-hash check fails too with a rationale
  # that points the auditor at the upstream failure.
  defp check_system_event_payload_hash(
         %Attestation{payload_hash: hash},
         _ctx,
         %{status: :fail},
         prefix
       ) do
    check(
      :fail,
      5,
      "payload_hash_match",
      prefix <>
        "system event — payload-hash binding depends on the DSSE signature, but " <>
        "step 1 (signature) failed; cannot assert hash #{hex(hash)} is the right one. " <>
        "Resolve the signature failure first."
    )
  end

  defp check_imported_event_payload_hash(%Attestation{payload_hash: hash}, %{status: :pass}) do
    check(
      :pass,
      5,
      "payload_hash_match",
      "imported event — source payload was not CAS-stashed by this Gateway; " <>
        "hash #{hex(hash)} is bound by the DSSE signature verified at step 1"
    )
  end

  defp check_imported_event_payload_hash(%Attestation{payload_hash: hash}, %{status: :fail}) do
    check(
      :fail,
      5,
      "payload_hash_match",
      "imported event — payload-hash binding depends on the DSSE signature, but " <>
        "step 1 (signature) failed; cannot assert hash #{hex(hash)} is the right one. " <>
        "Resolve the signature failure first."
    )
  end

  defp check_storage_payload_hash(payload_uri, receipt_hash, ctx) do
    case Payload.fetch(payload_uri, ctx) do
      {:ok, bytes} ->
        actual = :crypto.hash(:sha256, bytes)

        if actual == receipt_hash do
          check(
            :pass,
            5,
            "payload_hash_match",
            "fetched payload's SHA-256 #{hex(actual)} matches receipt payload_hash"
          )
        else
          check(
            :fail,
            5,
            "payload_hash_match",
            "payload SHA-256 mismatch — fetched=#{hex(actual)} receipt=#{hex(receipt_hash)}"
          )
        end

      {:error, {:fetch_failed, reason}} ->
        check(
          :fail,
          5,
          "payload_hash_match",
          "payload fetch failed for #{payload_uri}: #{inspect(reason)}"
        )
    end
  end

  # ---------------------------------------------------------------------------
  # Lookups
  # ---------------------------------------------------------------------------

  defp fetch_attestation(run_id) do
    case Repo.get(Attestation, run_id) do
      nil -> {:error, :not_found}
      %Attestation{} = att -> {:ok, att}
    end
  rescue
    Ecto.Query.CastError -> {:error, :not_found}
  end

  # ---------------------------------------------------------------------------
  # Receipt emission + helpers
  # ---------------------------------------------------------------------------

  defp emit_verify_query(%IdentityContext{} = ctx, run_id, overall_status) do
    UiReceipts.emit(:ui_query, %{
      query_kind: "verify_locally",
      run_id: run_id,
      overall_status: Atom.to_string(overall_status),
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}})
       when is_binary(sub),
       do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}})
       when is_binary(id),
       do: id

  defp principal_subject_from_ctx(_), do: nil

  defp check(status, step, name, explanation) do
    %{status: status, step: step, name: name, explanation: explanation}
  end

  defp check_to_json(%{status: status, step: step, name: name, explanation: explanation}) do
    %{
      "step" => step,
      "name" => name,
      "status" => Atom.to_string(status),
      "explanation" => explanation
    }
  end

  defp hex(nil), do: nil
  defp hex(bin) when is_binary(bin), do: Base.encode16(bin, case: :lower)

  # Redact the middle of a long ARN-style key id so audit logs / API
  # responses don't expose full KMS key URNs unnecessarily. Keeps prefix
  # + suffix for human recognition.
  defp redact(s) when is_binary(s) and byte_size(s) > 24 do
    prefix = binary_part(s, 0, 12)
    suffix = binary_part(s, byte_size(s) - 12, 12)
    prefix <> "..." <> suffix
  end

  defp redact(s) when is_binary(s), do: s

  defp to_string_or_nil(nil), do: nil
  defp to_string_or_nil(v) when is_atom(v), do: Atom.to_string(v)
  defp to_string_or_nil(v) when is_binary(v), do: v
  defp to_string_or_nil(v), do: to_string(v)
end
