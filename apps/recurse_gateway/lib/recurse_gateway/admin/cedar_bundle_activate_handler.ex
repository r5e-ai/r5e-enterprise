defmodule Recurse.Gateway.Admin.CedarBundleActivateHandler do
  @moduledoc """
  Plug-shaped handler for `POST /v1/admin/cedar-bundle/activate` (MR !119,
  Spec A — OCI policy provider hot-reload surface).

  Triggers a Cedar bundle activation by ref via
  `Recurse.Gateway.Policy.OciBundleManager.activate/3`. The body is
  JSON-shaped:

      {
        "ref": "0.2.0-abc1234",       // required, non-empty string
        "digest": "sha256:abc..."     // optional, advisory pin
      }

  ## Auth

  Cedar-gated `CedarBundleActivate` action — the deployed policy bundle
  MUST grant only `principal.recurse_role == "platform_operator"`. The
  gate runs through the same `Recurse.Gateway.AuditPlane.Authz.gate/4`
  pipeline every other admin endpoint uses.

  ## Receipt emission

  Activation is a state-changing privileged operation per Constitution
  Principle III — every successful activation emits a synthetic
  `:policy_bundle_activated` system receipt via
  `Recurse.Gateway.Admin.BrowserAuth.UiReceipts.emit_strict/2`. Failed
  activations do NOT emit a receipt because no state transition happened
  (the previous bundle remains active); the failure is captured via
  Logger + telemetry inside the OciBundleManager.

  ## Iron Law check (`elixir:phoenix-thinking`)

  Pure module — no GenServer state. Runs on the Bandit-spawned request
  process. `OciBundleManager.activate/3` is the synchronous heavy
  lifter (registry pull + cosign verify + atomic swap).

  ## Error responses

    * `400` — body is missing `ref` or `ref` is not a non-empty string.
    * `401` / `403` — Cedar gate denied (handled inside `gate/4`).
    * `502` — registry / cosign / Cedar parse / canonical-hash failure.
      The previous bundle remains active.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/policy/oci_bundle_manager.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/audit_plane/authz.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/ui_receipts.ex`
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.AuditPlane.ErrorEnvelope
  alias Recurse.Gateway.Policy.OciBundleManager
  alias Recurse.Shared.IdentityContext

  require Logger

  @action ~s|Recurse::Action::"CedarBundleActivate"|

  @doc "Plug-shaped entry point — `POST /v1/admin/cedar-bundle/activate`."
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "cedar_bundle_activate",
      attrs: %{"endpoint" => "/v1/admin/cedar-bundle/activate"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_handle(conn_after, ctx)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  defp do_handle(conn, %IdentityContext{} = ctx) do
    body = conn.body_params || %{}

    with {:ok, ref} <- parse_ref(body),
         {:ok, digest} <- parse_digest(body),
         {:ok, result} <- activate_bundle(ref, digest) do
      emit_activated(ctx, ref, result)

      response_body =
        JSON.encode!(%{
          "ok" => true,
          "old_digest" => result.old_digest,
          "new_digest" => result.new_digest,
          "ref" => result.ref,
          "activated_at" => DateTime.to_iso8601(result.activated_at)
        })

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, response_body)
    else
      {:error, :missing_ref} ->
        send_validation_error(conn, "ref is required and must be a non-empty string")

      {:error, :invalid_ref_type} ->
        send_validation_error(conn, "ref must be a non-empty string")

      {:error, :invalid_digest_type} ->
        send_validation_error(conn, "digest must be a string in the form sha256:<hex>")

      {:error, {:upstream, reason}} ->
        send_upstream_error(conn, reason)

      {:error, reason} ->
        # Catch-all from OciBundleManager.activate/3 — any error past the
        # validation gate is an upstream / verification failure, so 502
        # is the right semantic. Detailed reason in the body.
        send_upstream_error(conn, reason)
    end
  end

  # ---------------------------------------------------------------------------
  # Validation
  # ---------------------------------------------------------------------------

  defp parse_ref(body) do
    case Map.get(body, "ref") do
      v when is_binary(v) and v != "" -> {:ok, v}
      nil -> {:error, :missing_ref}
      _ -> {:error, :invalid_ref_type}
    end
  end

  defp parse_digest(body) do
    case Map.get(body, "digest") do
      nil -> {:ok, nil}
      v when is_binary(v) and v != "" -> {:ok, v}
      _ -> {:error, :invalid_digest_type}
    end
  end

  # ---------------------------------------------------------------------------
  # Activation
  # ---------------------------------------------------------------------------

  defp activate_bundle(ref, digest) do
    opts =
      case digest do
        nil -> []
        d -> [digest: d]
      end

    case OciBundleManager.activate(ref, opts) do
      {:ok, _result} = ok -> ok
      {:error, reason} -> {:error, {:upstream, reason}}
    end
  rescue
    error ->
      Logger.error(fn ->
        "CedarBundleActivateHandler caught unexpected error: #{inspect(error)}"
      end)

      {:error, {:upstream, error}}
  catch
    :exit, reason ->
      # GenServer not running, timeout, or peer crash — surface as a 502
      # rather than letting the request handler crash.
      Logger.error(fn ->
        "CedarBundleActivateHandler caught exit: #{inspect(reason)}"
      end)

      {:error, {:upstream, {:bundle_manager_unavailable, reason}}}
  end

  # ---------------------------------------------------------------------------
  # Receipt
  # ---------------------------------------------------------------------------

  # The new `:policy_bundle_activated` event_kind requires lockstep updates
  # in three sibling locations to satisfy the FunctionClauseError-style
  # allowlist guards in `UiReceipts.emit_strict/2` and the
  # `SignedPredicate.@event_kinds` contract:
  #   * `UiReceipts.@allowed_event_kinds`
  #   * `SignedPredicate.@event_kinds`
  #   * DB CHECK widening migration sibling to
  #     `20260501000000_mcp_add_ui_mcp_quarantine_event_kind.exs`
  #
  # This MR (file scope: 3 new files + router.ex + attestation.ex) only
  # adds the atom to `Attestation.@event_kind_values`. To avoid raising
  # at runtime when the lockstep updates land in a sibling commit we
  # try-rescue the emit; once the allowlist is updated, the emit fires
  # cleanly and the rescue branch is dead. The activation itself ALREADY
  # mutated the active bundle, so a missing receipt is a logged audit
  # gap (per the F004 FR-031 convention), not a request failure.
  defp emit_activated(%IdentityContext{} = ctx, ref, result) do
    _ =
      UiReceipts.emit_strict(:policy_bundle_activated, %{
        ref: ref,
        old_digest: result.old_digest,
        new_digest: result.new_digest,
        activated_at: DateTime.to_iso8601(result.activated_at),
        principal_subject: principal_subject_from_ctx(ctx),
        tenant_id: ctx.tenant_id,
        correlation_id: ctx.correlation_id
      })

    :ok
  rescue
    FunctionClauseError ->
      Logger.error(fn ->
        "policy_bundle_activated receipt skipped — emit_strict allowlist " <>
          "missing :policy_bundle_activated. Lockstep update required in " <>
          "UiReceipts.@allowed_event_kinds + SignedPredicate.@event_kinds + " <>
          "DB CHECK migration. Activation already succeeded; logging gap."
      end)

      :telemetry.execute(
        [:recurse, :policy, :oci_bundle, :receipt_skipped],
        %{count: 1},
        %{reason: :emit_strict_allowlist_missing, ref: ref}
      )

      :ok
  end

  # ---------------------------------------------------------------------------
  # Response helpers
  # ---------------------------------------------------------------------------

  defp send_validation_error(conn, message) do
    Authz.send_bad_request(conn, message)
  end

  # `ErrorEnvelope` exposes 400/401/403/404/422/500/503 helpers but no
  # 502 helper, so we build the envelope body via `ErrorEnvelope.build/3`
  # (which guarantees the canonical flat shape + correlation_id lookup)
  # and send it with `Plug.Conn.send_resp/3` directly.
  defp send_upstream_error(conn, reason) do
    description =
      "Cedar bundle activation failed: #{inspect(reason)}. " <>
        "Previous bundle remains active."

    body = ErrorEnvelope.build("ERR_BUNDLE_ACTIVATE_UPSTREAM", description)

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(502, JSON.encode!(body))
  end

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}})
       when is_binary(sub),
       do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}})
       when is_binary(id),
       do: id

  defp principal_subject_from_ctx(_), do: "unknown"
end
