defmodule Recurse.Gateway.AuditPlane.ExportHandler do
  @moduledoc """
  `POST /v1/audit/export` (F002 T061, FR-022).

  Accepts a list of `run_id`s (max 100 per call), advances any that are not
  yet `:global_inclusion_verified` via `PostgresMerkleLedger.force_commit_for_run_ids/2`
  (FR-017, AD-001 c'), then builds an Export Evidence zip per F001 FR-048
  surface 2. Cedar-gated via `Recurse::Action::ExportEvidence`.

  ## Response

    * `Content-Type: application/zip`
    * `Content-Disposition: attachment; filename="evidence-<timestamp>.zip"`
    * Zip bytes. For N=1 the body is the single inner zip. For N>1 it's a
      zip-of-zips containing one inner zip per run_id.

  ## F004 reuse (T077 — documentation + browser-scoped emission)

  F004's Receipt Detail "Download Export Evidence" CTA POSTs the single
  `run_id` here through the SAME Bandit port. Browser-flow callers come
  through `Recurse.Gateway.Admin.BrowserSessionPlug`, which lifts the
  cookie envelope into `Authorization: Bearer <jwt>` upstream — so this
  handler runs the IDENTICAL Cedar gate (`ExportEvidence`) and zip
  pipeline regardless of caller class.

  Per `data-model.md` §0 the F004 emission for browser-scoped exports is
  `:ui_evidence_export`, mapped to F002's existing `ExportEvidence` Cedar
  action. We emit it via `UiReceipts.emit/2` AFTER the F002 receipt
  pipeline (which is owned by `EvidenceZipBuilder` + `commit_attestation`)
  and ONLY when the caller arrived via the BrowserSessionPlug (detected
  by the `:browser_session` assign on the conn). API-bearer callers get
  zero F004 overlay.

  ## Iron Law check

  Pure module. No process. Runs on the request process.
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.AuditPlane.EvidenceZipBuilder
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Shared.IdentityContext

  require Logger

  @action "Recurse::Action::ExportEvidence"
  @max_run_ids 100

  @doc """
  Entry point. Returns the responded `Plug.Conn`.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{} = conn) do
    case parse_run_ids(conn) do
      {:ok, run_ids} ->
        gate_and_build(conn, run_ids)

      {:error, message} ->
        Authz.send_bad_request(conn, message)
    end
  end

  # ---------------------------------------------------------------------------
  # Request parsing
  # ---------------------------------------------------------------------------

  defp parse_run_ids(%Plug.Conn{body_params: %Plug.Conn.Unfetched{}}),
    do: {:error, "request body was not parsed as JSON"}

  defp parse_run_ids(%Plug.Conn{body_params: body}) when is_map(body) do
    case Map.get(body, "run_ids") do
      list when is_list(list) and list != [] ->
        cond do
          length(list) > @max_run_ids ->
            {:error, "max #{@max_run_ids} run_ids per call"}

          not Enum.all?(list, &is_binary/1) ->
            {:error, "run_ids must be a list of strings"}

          true ->
            {:ok, list}
        end

      _ ->
        {:error, "run_ids must be a non-empty JSON array"}
    end
  end

  defp parse_run_ids(_), do: {:error, "request body must be a JSON object"}

  # ---------------------------------------------------------------------------
  # Auth + build
  # ---------------------------------------------------------------------------

  defp gate_and_build(conn, run_ids) do
    resource = %{
      type: "Recurse::Resource::AuditEndpoint",
      id: "v1_audit_export",
      attrs: %{"endpoint" => "/v1/audit/export"}
    }

    extra_ctx = %{"run_ids" => run_ids}

    case Authz.gate(conn, @action, resource, extra_ctx) do
      {:ok, conn_with_ctx, ctx, _bundle_ref} -> do_handle(conn_with_ctx, ctx, run_ids)
      error -> Authz.dispatch_gate_error(conn, error)
    end
  end

  defp do_handle(conn, ctx, run_ids) do
    with :ok <- force_commit(run_ids),
         {:ok, zip_bytes} <- build_zip(run_ids, ctx) do
      filename = export_filename()

      # F004 T077 — emit `:ui_evidence_export` UI-receipt overlay scoped
      # to browser-session callers. Detect via the `:browser_session`
      # assign that BrowserSessionPlug stamps. API-bearer callers get
      # the F002 receipt only.
      maybe_emit_ui_evidence_export(conn, ctx, run_ids)

      conn
      |> Plug.Conn.put_resp_content_type("application/zip")
      |> Plug.Conn.put_resp_header(
        "content-disposition",
        ~s|attachment; filename="#{filename}"|
      )
      |> Plug.Conn.send_resp(200, zip_bytes)
    else
      {:error, {run_id, :not_found}} ->
        Authz.send_not_found(conn, "no attestation for run_id #{run_id}")

      {:error, {run_id, reason}} when is_binary(run_id) ->
        Logger.error(fn ->
          "export_handler failed for run_id=#{run_id}: #{inspect(reason)}"
        end)

        Authz.send_internal_error(conn, {run_id, reason})

      {:error, reason} ->
        Logger.error(fn -> "export_handler failed: #{inspect(reason)}" end)
        Authz.send_internal_error(conn, reason)
    end
  end

  # ---------------------------------------------------------------------------
  # Ledger-provider dispatch — FR-017 force-commit on Postgres-Merkle.
  #
  # Detect the configured ledger provider. Postgres-Merkle → invoke the
  # rich `force_commit_for_run_ids/2` public method so exported receipts
  # are guaranteed `:global_inclusion_verified` at export time. Any other
  # provider (none today, future Trillian etc.) reflects current commit
  # state with an advisory — skip the force-commit hop.
  # ---------------------------------------------------------------------------

  defp force_commit(run_ids) do
    case ProviderRegistry.ledger_provider() do
      {PostgresMerkleLedger, state} ->
        case PostgresMerkleLedger.force_commit_for_run_ids(state, run_ids) do
          {:ok, _outcomes} -> :ok
          {:error, reason} -> {:error, reason}
        end

      {_other_mod, _state} ->
        # Non-Postgres-Merkle provider: skip force-commit, rely on the
        # receipt's existing verification_level with advisory.
        :ok
    end
  end

  defp build_zip([single_run_id], ctx) do
    EvidenceZipBuilder.build(single_run_id, ctx)
  end

  defp build_zip(run_ids, ctx) do
    EvidenceZipBuilder.build_many(run_ids, ctx)
  end

  defp export_filename do
    ts =
      DateTime.utc_now()
      |> DateTime.to_iso8601(:basic)
      |> String.replace(~r/[^0-9TZ]/, "")

    "evidence-#{ts}.zip"
  end

  # ---------------------------------------------------------------------------
  # F004 T077 — `:ui_evidence_export` overlay emission
  # ---------------------------------------------------------------------------

  # Browser-session detection: BrowserSessionPlug puts a `:browser_session`
  # assign on the conn after lifting the cookie envelope into the auth
  # header. API-bearer callers never have this assign. We do not emit if
  # the assign is missing — the F002 receipt is the source of truth for
  # API-bearer flows.
  defp maybe_emit_ui_evidence_export(%Plug.Conn{assigns: %{browser_session: _}} = _conn, ctx, run_ids) do
    UiReceipts.emit(:ui_evidence_export, %{
      run_ids: run_ids,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp maybe_emit_ui_evidence_export(_conn, _ctx, _run_ids), do: :ok

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}}) when is_binary(sub),
    do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}}) when is_binary(id),
    do: id

  defp principal_subject_from_ctx(_), do: nil
end
