defmodule Recurse.Gateway.Admin.PolicyReplayHandler do
  @moduledoc """
  `POST /v1/policy/replay/{run_id}` (F004 T140 / US6).

  Replays a historical receipt against the currently-deployed Cedar
  bundle (default) OR an operator-supplied override Cedar source. Used
  by the Policy Simulator's "Replay" mode (FR-022).

  Per `contracts/audit_api_extensions.md` §"POST /v1/policy/replay/{run_id}":

    * **Path**: `run_id` of the target receipt.
    * **Body** (optional): `{"override_cedar_source": "..."}`.
    * **Response 200**: `{run_id, original_decision, replayed_decision,
      decision_changed, matched_policies, reasoning, cedar_source_hash,
      attested_run_id}`.
    * **Cedar action**: `PolicyReplay`.
    * **`event_kind` emitted**: `:ui_policy_replay`.

  ## Reuses Phase 5 Blast Radius helpers (no duplication)

    * `BlastRadius.synthesize_entity_store/1` — builds the Cedar entity
      store from the receipt's signed predicate.
    * `BlastRadius.action_uid_from_event_kind/1` — maps `event_kind` →
      Cedar action UID per data-model.md §0.
    * `BlastRadius.classify_pair/2` — only used to derive
      `decision_changed` (we don't return the 4-cell classification here;
      replay is single-receipt).

  ## Default vs override

  Without `override_cedar_source`, we evaluate against the deployed
  bundle via `Recurse.Gateway.Policy.Active.current/0` (F002 contract;
  the canonical reader populated by both filesystem and OCI loaders).
  With override, we evaluate against the supplied source — used by
  operators testing a candidate edit before promoting to a draft.

  ## Iron Law check (`elixir:phoenix-thinking` + `elixir:elixir-thinking`)

  Pure module — no GenServer. Cedar evaluation is a stateless NIF call.
  Single-receipt evaluation is much cheaper than full Blast Radius
  (no streaming, no batching).

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"POST /v1/policy/replay/{run_id}"
    * `specs/004-audit-console/data-model.md` §0
    * `apps/recurse_gateway/lib/recurse_gateway/admin/blast_radius.ex`
      (T086 — helpers reused here)
  """

  import Ecto.Query

  alias Recurse.Gateway.Admin.BlastRadius
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext

  require Logger

  @action "Recurse::Action::\"PolicyReplay\""

  @doc "Plug-shaped entry point — `POST /v1/policy/replay/{run_id}`."
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{path_params: %{"run_id" => run_id}} = conn) when is_binary(run_id) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_replay",
      attrs: %{"endpoint" => "/v1/policy/replay/#{run_id}"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_handle(conn_after, ctx, run_id)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  def handle(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "run_id path parameter is required")
  end

  defp do_handle(conn, %IdentityContext{} = ctx, run_id) do
    body = conn.body_params || %{}
    override = parse_override(body)

    with {:ok, attestation} <- fetch_attestation(run_id, ctx.tenant_id),
         {:ok, cedar_source, cedar_source_hash} <- resolve_cedar_source(override),
         {:ok, action_uid} <- resolve_action_uid(attestation),
         {:ok, evaluation} <- evaluate(attestation, cedar_source, action_uid, ctx) do
      attested_run_id = Ecto.UUID.generate()
      original = attestation.policy_decision || :allow
      decision_changed = original != evaluation.decision

      emit_replay(
        ctx,
        run_id,
        attested_run_id,
        cedar_source_hash,
        decision_changed,
        evaluation.decision
      )

      response_body =
        JSON.encode!(%{
          "run_id" => run_id,
          "original_decision" => Atom.to_string(original),
          "replayed_decision" => Atom.to_string(evaluation.decision),
          "decision_changed" => decision_changed,
          "matched_policies" =>
            Enum.map(evaluation.matched_policies, &normalize_matched_policy/1),
          "reasoning" => build_reasoning(evaluation.decision, evaluation.matched_policies),
          "cedar_source_hash" => "sha256:" <> cedar_source_hash,
          "attested_run_id" => attested_run_id
        })

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, response_body)
    else
      {:error, :not_found} ->
        Authz.send_not_found(conn, "receipt not found")

      {:error, {:cedar_parse_error, message}} ->
        Authz.send_bad_request(conn, "cedar parse error: #{message}")

      {:error, :no_action_uid} ->
        Authz.send_bad_request(conn, "receipt event_kind is not Cedar-gated; cannot replay")

      {:error, :bundle_not_loaded} ->
        Authz.send_service_unavailable(conn, "policy bundle not loaded")

      {:error, {:eval_error, message}} ->
        Authz.send_bad_request(conn, "cedar eval error: #{inspect(message)}")
    end
  end

  # ---------------------------------------------------------------------------
  # Private — receipt + cedar resolution
  # ---------------------------------------------------------------------------

  defp fetch_attestation(run_id, tenant_id) do
    query =
      from(a in Attestation,
        where: a.run_id == ^run_id and a.tenant_id == ^tenant_id,
        limit: 1
      )

    case safe_one(query) do
      nil -> {:error, :not_found}
      attestation -> {:ok, attestation}
    end
  end

  defp safe_one(query) do
    Repo.one(query)
  rescue
    Ecto.Query.CastError -> nil
  end

  defp parse_override(body) do
    case Map.get(body, "override_cedar_source") do
      s when is_binary(s) and s != "" -> s
      _ -> nil
    end
  end

  defp resolve_cedar_source(nil) do
    case Active.current() do
      {:ok, %Active{bundle: %PolicyBundleRef{bundle_bytes: bytes, canonical_hash: hash}}} ->
        {:ok, bytes, Base.encode16(hash, case: :lower)}

      {:error, _reason} ->
        {:error, :bundle_not_loaded}
    end
  end

  defp resolve_cedar_source(override) when is_binary(override) do
    case Recurse.Cedar.validate_policy_syntax(override) do
      :ok ->
        hash = Recurse.Cedar.canonical_hash_hex(override)
        {:ok, override, hash}

      {:error, message} ->
        {:error, {:cedar_parse_error, message}}
    end
  end

  defp resolve_action_uid(%Attestation{event_kind: kind}) do
    case BlastRadius.action_uid_from_event_kind(kind) do
      nil -> {:error, :no_action_uid}
      uid -> {:ok, uid}
    end
  end

  # ---------------------------------------------------------------------------
  # Private — Cedar evaluation
  # ---------------------------------------------------------------------------

  defp evaluate(%Attestation{} = attestation, cedar_source, action_uid, %IdentityContext{} = ctx) do
    predicate = attestation_to_predicate(attestation)
    entities = BlastRadius.synthesize_entity_store(predicate)
    entities_json = JSON.encode!(entities)

    [principal_entity, resource_entity | _] = entities

    request_json =
      JSON.encode!(%{
        "principal" => ~s[#{principal_entity["uid"]["type"]}::"#{principal_entity["uid"]["id"]}"],
        "action" => action_uid,
        "resource" => ~s[#{resource_entity["uid"]["type"]}::"#{resource_entity["uid"]["id"]}"],
        "context" => %{
          "tenant_id" => attestation.tenant_id || ctx.tenant_id || "",
          "correlation_id" => ctx.correlation_id || "policy-replay",
          "timestamp" => System.system_time(:second)
        }
      })

    case Recurse.Cedar.evaluate_with_entities(cedar_source, request_json, entities_json) do
      {:ok, %{decision: decision} = result} ->
        {:ok,
         %{
           decision: decision,
           matched_policies: Map.get(result, :matched_policies, [])
         }}

      {:error, message} ->
        {:error, {:eval_error, message}}
    end
  end

  defp attestation_to_predicate(%Attestation{} = a) do
    %{
      "principal" => a.principal || %{},
      "tenant_id" => a.tenant_id,
      "resource_kind" => "Recurse::Resource::ConsoleSurface",
      "resource_attributes" => %{}
    }
  end

  # ---------------------------------------------------------------------------
  # Private — receipt emission + helpers
  # ---------------------------------------------------------------------------

  defp emit_replay(
         %IdentityContext{} = ctx,
         source_run_id,
         attested_run_id,
         cedar_hash,
         decision_changed,
         replayed_decision
       ) do
    UiReceipts.emit(:ui_policy_replay, %{
      source_run_id: source_run_id,
      replay_run_id: attested_run_id,
      cedar_source_hash: cedar_hash,
      decision_changed: decision_changed,
      replayed_decision: Atom.to_string(replayed_decision),
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp normalize_matched_policy(p) when is_binary(p),
    do: %{"id" => p, "effect" => nil, "line_start" => nil, "line_end" => nil}

  defp normalize_matched_policy(p) when is_map(p), do: p
  defp normalize_matched_policy(other), do: %{"id" => to_string(other)}

  defp build_reasoning(:allow, []),
    do: "no policy matched but Cedar default-allow returned :allow"

  defp build_reasoning(:allow, matched),
    do: "permit policies matched: #{Enum.join(matched, ", ")}"

  defp build_reasoning(:deny, []),
    do: "no policy matched; default deny applied"

  defp build_reasoning(:deny, matched),
    do: "forbid or unmatched: #{Enum.join(matched, ", ")}"

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}})
       when is_binary(sub),
       do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}})
       when is_binary(id),
       do: id

  defp principal_subject_from_ctx(_), do: "unknown"
end
