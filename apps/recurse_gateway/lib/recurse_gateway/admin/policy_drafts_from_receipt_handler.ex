defmodule Recurse.Gateway.Admin.PolicyDraftsFromReceiptHandler do
  @moduledoc """
  `POST /v1/policy/drafts/from-receipt` (F004 T090).

  Generates a Cedar skeleton matching the source receipt's
  `(principal, action, resource)` shape. Used by the Receipt Detail UI's
  "Create policy rule from this receipt" button — the Wiz-pattern
  differentiated wedge entry point per US3 acceptance scenario 1.

  ## Skeleton derivation

  Given a `source_receipt_run_id`, this handler:

    1. Loads the receipt via `Repo.get(Attestation, run_id)`.
    2. Maps the receipt's `event_kind` to a Cedar action UID via
       `BlastRadius.action_uid_from_event_kind/1` (single-source-of-truth
       per `data-model.md` §0).
    3. Derives the principal entity-type from the JSONB `principal.kind`
       claim.
    4. Composes a `forbid (principal, action, resource);`-shaped Cedar
       skeleton (operator can flip to `permit` in the editor).
    5. Calls `PolicyDrafts.create/2` with the skeleton + back-link to
       the source receipt.

  ## Cedar action + receipt

  Cedar action `PolicyDraftCreate` (same as `POST /v1/policy/drafts`);
  emits `:ui_policy_draft_created`. The fact that the draft has a
  `source_receipt_run_id` is carried through to the receipt's predicate
  for downstream "show me drafts seeded by this receipt" queries
  (FR-016 back-link).

  ## Iron Law check (`elixir:phoenix-thinking` + `elixir:elixir-thinking`)

  Pure module — no GenServer. Skeleton synthesis is a 4-line string
  builder; principal-kind and action-uid mapping are total functions
  with safe defaults.

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"Policy drafts" — `POST /v1/policy/drafts/from-receipt`
    * `specs/004-audit-console/spec.md` US3 acceptance scenario 1
    * `specs/004-audit-console/data-model.md` §0
    * `apps/recurse_gateway/lib/recurse_gateway/admin/blast_radius.ex` (T086)
  """

  alias Recurse.Gateway.Admin.BlastRadius
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicyDrafts
  alias Recurse.Gateway.Admin.PolicyDrafts.PolicyDraft
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext

  require Logger

  @action "Recurse::Action::\"PolicyDraftCreate\""

  @doc """
  Plug-shaped entry point.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_drafts_from_receipt",
      attrs: %{"endpoint" => "/v1/policy/drafts/from-receipt"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_handle(conn_after, ctx)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  defp do_handle(conn, %IdentityContext{} = ctx) do
    body = conn.body_params || %{}

    case Map.get(body, "source_receipt_run_id") do
      run_id when is_binary(run_id) and run_id != "" ->
        do_handle_with_run_id(conn, ctx, run_id)

      _ ->
        Authz.send_bad_request(conn, "source_receipt_run_id is required (UUID)")
    end
  end

  defp do_handle_with_run_id(conn, ctx, run_id) do
    case fetch_receipt(run_id) do
      {:ok, %Attestation{} = receipt} ->
        # Tenant-scope check: receipts from another tenant cannot seed a
        # draft scoped to ours. Phase-1 single-tenant makes this a tautology
        # but Phase-2 federation will exercise it.
        if receipt.tenant_id == ctx.tenant_id do
          create_draft_from_receipt(conn, ctx, receipt)
        else
          Authz.send_not_found(conn, "source receipt not found in this tenant")
        end

      {:error, :not_found} ->
        Authz.send_not_found(conn, "source receipt not found")
    end
  end

  defp create_draft_from_receipt(conn, %IdentityContext{} = ctx, %Attestation{} = receipt) do
    skeleton = build_cedar_skeleton(receipt)
    scope_metadata = build_scope_metadata(receipt)
    condition_metadata = []

    attrs = %{
      "cedar_source" => skeleton,
      "scope_metadata" => scope_metadata,
      "condition_metadata" => condition_metadata,
      "source_receipt_run_id" => receipt.run_id,
      "author_principal_subject" => principal_subject_from_ctx(ctx),
      "status" => :draft
    }

    case PolicyDrafts.create(ctx.tenant_id, attrs) do
      {:ok, %PolicyDraft{} = draft} ->
        emit_draft_created(ctx, draft)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(201, JSON.encode!(render_full(draft)))

      {:error, %Ecto.Changeset{} = changeset} ->
        Authz.send_bad_request(conn, format_changeset_errors(changeset))
    end
  end

  # ---------------------------------------------------------------------------
  # Cedar skeleton synthesis
  # ---------------------------------------------------------------------------

  # The skeleton starts as a `forbid` (the safer default for the operator —
  # they're typically defending against a deny-worthy pattern they just
  # observed). The operator can flip to `permit` in the Monaco editor before
  # saving.
  defp build_cedar_skeleton(%Attestation{} = receipt) do
    principal_type = principal_type_from(receipt.principal)
    principal_id = principal_id_from(receipt.principal)

    action_uid =
      BlastRadius.action_uid_from_event_kind(receipt.event_kind) ||
        ~s(Recurse::Action::"DashboardQuery")

    """
    // Skeleton generated from receipt #{receipt.run_id} on #{DateTime.to_iso8601(DateTime.utc_now())}.
    // Edit principal/action/resource as needed; flip `forbid` to `permit` to allow.
    forbid (
      principal == #{principal_type}::"#{principal_id}",
      action == #{action_uid},
      resource
    )
    when {
      principal.tenant_id == context.tenant_id
    };
    """
  end

  defp build_scope_metadata(%Attestation{} = receipt) do
    %{
      "scope_kind" => "principal",
      "scope_value" => principal_id_from(receipt.principal)
    }
  end

  defp principal_type_from(%{"kind" => "obo_human"}), do: "Recurse::Principal::Human"

  defp principal_type_from(%{"kind" => "service_account"}),
    do: "Recurse::Principal::ServiceAccount"

  defp principal_type_from(%{"kind" => "autonomous"}), do: "Recurse::Principal::Autonomous"
  defp principal_type_from(_), do: "Recurse::Principal::Human"

  defp principal_id_from(%{"subject" => sub}) when is_binary(sub) and sub != "", do: sub
  defp principal_id_from(%{"account_id" => id}) when is_binary(id) and id != "", do: id
  defp principal_id_from(_), do: "unknown"

  # ---------------------------------------------------------------------------
  # Receipt fetch
  # ---------------------------------------------------------------------------

  defp fetch_receipt(run_id) do
    case Repo.get(Attestation, run_id) do
      nil -> {:error, :not_found}
      %Attestation{} = receipt -> {:ok, receipt}
    end
  rescue
    Ecto.Query.CastError -> {:error, :not_found}
  end

  # ---------------------------------------------------------------------------
  # Receipt emission
  # ---------------------------------------------------------------------------

  defp emit_draft_created(%IdentityContext{} = ctx, %PolicyDraft{} = draft) do
    UiReceipts.emit(:ui_policy_draft_created, %{
      draft_id: draft.id,
      source_receipt_run_id: draft.source_receipt_run_id,
      seeded_from_receipt: true,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  defp render_full(%PolicyDraft{} = draft) do
    %{
      "id" => draft.id,
      "tenant_id" => draft.tenant_id,
      "author_principal_subject" => draft.author_principal_subject,
      "source_receipt_run_id" => draft.source_receipt_run_id,
      "cedar_source" => draft.cedar_source,
      "scope_metadata" => draft.scope_metadata,
      "condition_metadata" => draft.condition_metadata,
      "status" => Atom.to_string(draft.status || :draft),
      "created_at" => dt_or_nil(draft.inserted_at),
      "updated_at" => dt_or_nil(draft.updated_at)
    }
  end

  defp dt_or_nil(nil), do: nil
  defp dt_or_nil(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp dt_or_nil(s) when is_binary(s), do: s

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}})
       when is_binary(sub),
       do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}})
       when is_binary(id),
       do: id

  defp principal_subject_from_ctx(_), do: "unknown"

  defp format_changeset_errors(%Ecto.Changeset{} = changeset) do
    errors =
      Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
        Enum.reduce(opts, msg, fn {key, value}, acc ->
          String.replace(acc, "%{#{key}}", to_string(value))
        end)
      end)

    "validation failed: #{inspect(errors)}"
  end
end
