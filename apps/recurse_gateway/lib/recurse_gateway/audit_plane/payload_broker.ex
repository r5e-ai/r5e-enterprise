defmodule Recurse.Gateway.AuditPlane.PayloadBroker do
  @moduledoc """
  `GET /v1/audit/payload?run_id=...` (F002 T062, FR-020).

  Brokers access to the detached payload stored in S3 via the configured
  StorageProvider. Cedar-gated via `Recurse::Action::ReadPayload` with a
  `Resource::PayloadBroker` carrying the `run_id` + `tenant_id` attributes
  per the Cedar entity schema.

  ## Flow

    1. `AuditPlane.Authz.gate/4` — JWT + Cedar.
    2. Look up the receipt's `payload_uri` from the ledger.
    3. Ensure the receipt's `tenant_id` matches the caller's deployment tenant
       (Standalone is single-tenant, but defence-in-depth).
    4. Stream the S3 object via `StorageProvider.get_payload/3`.
       (Phase-1 buffers then sends; ranged-GET streaming lands later per
       FR-020. Under the 1-run-1-session heuristic payloads are small
       enough for buffered delivery.)
    5. Respond with `Content-Type: application/json` and the bytes.

  ## F004 reuse (T076 — documentation only)

  F004's Receipt Detail "Payload" tab routes to this exact endpoint with
  no behavioural change. Browser-flow callers hit it through the same
  Bandit port; the `Recurse.Gateway.Admin.BrowserSessionPlug` lifts the
  session cookie's embedded JWT into `Authorization: Bearer <jwt>` BEFORE
  the request reaches `AuditPlane.Authz.gate/4`, so this handler sees the
  identical request shape regardless of whether the caller is a
  direct-API tenant_auditor or a SPA-driven browser session. The Cedar
  action remains `ReadPayload` (F002 reuse — no new gate).

  Per `data-model.md` §0 the F004 emission for this path is
  `:ui_payload_access`. F002's emission contract (the data-plane receipt
  for the broker access itself) is preserved as-is. The new
  `:ui_payload_access` UI-receipt emission lands in T077-adjacent code
  if/when we choose to discriminate browser-vs-API callers; today the
  F002 emission carries `event_kind: :llm_call` for the broker access
  metadata via the existing pipeline. The `:ui_payload_access` overlay
  is integration-tested in `test/integration/us2_receipt_detail_test.exs`
  (T072+T080).

  ## Iron Law check

  Pure module. No process. Runs on the request process.
  """

  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.AuditPlane.ErrorEnvelope
  alias Recurse.Gateway.AuditPlane.PredicateOnlyUri
  alias Recurse.Gateway.AuditPlane.Resolvers.Payload, as: PayloadResolver
  alias Recurse.Gateway.AuditPlane.TenantGuard
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger

  require Logger

  @action "Recurse::Action::ReadPayload"

  @doc """
  Entry point. Returns the responded `Plug.Conn`.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{} = conn) do
    conn_with_params = Plug.Conn.fetch_query_params(conn)
    run_id = Map.get(conn_with_params.query_params, "run_id")

    if is_nil(run_id) or run_id == "" do
      Authz.send_bad_request(conn_with_params, "run_id query parameter is required")
    else
      gate_and_serve(conn_with_params, run_id)
    end
  end

  defp gate_and_serve(conn, run_id) do
    resource = %{
      type: "Recurse::Resource::PayloadBroker",
      id: "payload:#{run_id}",
      attrs: %{
        "run_id" => run_id,
        "tenant_id" => ProviderRegistry.tenant_id()
      }
    }

    extra_ctx = %{"run_id" => run_id}

    case Authz.gate(conn, @action, resource, extra_ctx) do
      {:ok, conn_with_ctx, ctx, _bundle_ref} -> do_handle(conn_with_ctx, ctx, run_id)
      error -> Authz.dispatch_gate_error(conn, error)
    end
  end

  # Predicate-only URI dispatch delegates to
  # `Recurse.Gateway.AuditPlane.PredicateOnlyUri.kind/1` (issue #29 /
  # AD-1 Option A; extended for imported scheme in issue #60). Two
  # families:
  #
  #   * `:system` — `recurse://system/predicate-only/<run_id>`. Gateway-
  #     internal events (`:ui_login`, `:ui_session`, `:ui_query`, etc.)
  #     whose audit content IS the signed_predicate. Returns 200 with
  #     the structured `predicate_only:true` body the SPA's
  #     `isPredicateOnlyMarker` recognizes (existing behavior; do not
  #     change — would break the deployed SPA).
  #
  #   * `:imported` — `recurse://import/<source_kind>/<run_id>`.
  #     Predicate-only-by-design from MR !80's JSONL importer. Returns
  #     422 `ERR_PREDICATE_ONLY` so the SPA's API error path renders a
  #     friendly explanation instead of "Internal error processing
  #     Audit Plane request" (issue #60). 422 is the right semantic
  #     code: request was understood, resource exists, but is
  #     predicate-only by design (NOT 404 "missing", NOT 400
  #     "malformed").
  #
  # Without the short-circuit, either family's URI gets handed to the
  # StorageProvider, which only recognizes `s3://...` and rejects
  # everything else as `{:malformed_uri, ...}` → 500.

  defp do_handle(conn, ctx, run_id) do
    with {:ok, attestation_map} <- PostgresMerkleLedger.query_by_run_id(run_id),
         :ok <- TenantGuard.validate(ctx, attestation_map),
         {:ok, payload_uri} <- require_payload_uri(attestation_map),
         :continue <- predicate_only_short_circuit(payload_uri, attestation_map),
         {:ok, bytes} <- PayloadResolver.fetch(payload_uri, ctx) do
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, bytes)
    else
      {:predicate_only_system, body} ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, body)

      {:predicate_only_imported, payload_uri} ->
        ErrorEnvelope.send_unprocessable_entity(
          conn,
          "ERR_PREDICATE_ONLY",
          "Receipt is predicate-only (imported source artifact). The signed_predicate IS the full audit content; no separate payload bytes were stored. payload_uri=#{payload_uri}",
          []
        )

      {:error, :not_found} ->
        Authz.send_not_found(conn, "no attestation for run_id #{run_id}")

      {:error, :tenant_mismatch} ->
        Authz.send_forbidden(conn, :tenant_mismatch)

      {:error, :missing_payload_uri} ->
        Authz.send_not_found(conn, "attestation has no payload URI")

      {:error, {:fetch_failed, reason}} ->
        Logger.error(fn -> "payload_broker fetch failed: #{inspect(reason)}" end)
        Authz.send_internal_error(conn, reason)

      {:error, reason} ->
        Logger.error(fn -> "payload_broker unexpected error: #{inspect(reason)}" end)
        Authz.send_internal_error(conn, reason)
    end
  end

  # Dispatch on the predicate-only family. Returns:
  #
  #   * `{:predicate_only_system, body}` — system event; serialize the
  #     structured 200 marker (the SPA's existing path renders this
  #     via `isPredicateOnlyMarker`).
  #   * `{:predicate_only_imported, payload_uri}` — imported event;
  #     422 `ERR_PREDICATE_ONLY`. Echoes the URI in the error
  #     description so SIEM forwarders + auditor diagnostics can
  #     confirm provenance without a second roundtrip.
  #   * `:continue` — real S3-backed payload; fall through to fetch.
  defp predicate_only_short_circuit(payload_uri, attestation_map) do
    case PredicateOnlyUri.kind(payload_uri) do
      :system ->
        body =
          PredicateOnlyUri.predicate_only_response_body(
            Map.put(attestation_map, :payload_uri, payload_uri)
          )

        {:predicate_only_system, body}

      :imported ->
        {:predicate_only_imported, payload_uri}

      :other ->
        :continue
    end
  end

  defp require_payload_uri(%{payload_uri: uri}) when is_binary(uri) and uri != "",
    do: {:ok, uri}

  defp require_payload_uri(_), do: {:error, :missing_payload_uri}
end
