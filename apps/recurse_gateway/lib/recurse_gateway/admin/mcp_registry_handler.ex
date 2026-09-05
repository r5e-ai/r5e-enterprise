defmodule Recurse.Gateway.Admin.McpRegistryHandler do
  @moduledoc """
  Cookie-only admin endpoints for the Trusted MCP Registry:

    * `GET /v1/mcp/registry` — list all entries (the catalog page).
    * `GET /v1/mcp/registry/:id` — single entry detail (SBOM + CVE view).
    * `PATCH /v1/mcp/registry/:id` — operator-only trust_tier mutation
      (F7 quarantine workflow). Cedar action `McpRegistryQuarantine`,
      `platform_operator` role only; emits `:ui_mcp_quarantine`.

  Read paths are open to any authenticated console user
  (`tenant_auditor` | `platform_operator`) — the registry catalog is
  per-deployment static, so a viewer-level grant is sufficient for
  Phase-1. The PATCH path adds a Cedar gate that scopes to
  `platform_operator` exclusively per `design/briefs/07-mcp-registry.md`
  §"Quarantine workflow (operator action)" (brief lives on
  `chore/design-briefs-pencil-handoff`, MR !86 — this MR ships
  independently and merges in tandem so the citation resolves
  post-merge; runtime + tests do not depend on the brief file).

  ## Iron Law check (`elixir:phoenix-thinking`)

    1. Mutable state? No — reads from `McpRegistry.Loader`'s
       persistent_term cache; mutations serialize through
       `McpRegistry.Mutator` (a separate GenServer that owns the write
       side). The handler itself is stateless.
    2. Concurrent execution? No — runs on the request process. The
       Mutator GenServer is the serialization seam for concurrent
       PATCH requests.
    3. Fault isolation? No — errors send F001 envelope responses, never
       raise. Persistence failures (read-only filesystem) become 500s
       so the receipt is NOT committed for a state change about to be
       lost on BEAM restart (fail-closed).

  All three NO → plain functions.

  ## Wire contracts

    * Response: `apps/recurse_gateway/priv/schemas/mcp_registry_list_response.json`
    * Entry shape: `apps/recurse_gateway/priv/schemas/mcp_registry_entry.json`
    * 404 on unknown id uses the F001 error envelope shape.

  ## Receipt emission (Constitution Principle III) — strict ordering + rollback

  Every successful PATCH emits exactly one DSSE-signed
  `:ui_mcp_quarantine` ledger receipt BEFORE the HTTP response is
  sent. The receipt's payload carries the entry id, the previous +
  new trust_tier, the operator's principal_subject, and (when
  quarantining) the auditor-supplied `reason`.

  The ordering is: persist (disk + cache) → DSSE-sign + ledger-commit
  via `UiReceipts.emit_strict/2` → respond. If the ledger commit
  fails (transient signing service / DB outage), the handler ROLLS
  BACK the persistence by calling `Mutator.restore_entry/2` with the
  pre-mutation entry shape and returns 500. This preserves the
  invariant that every committed receipt corresponds to a real
  state change AND every real state change has a receipt — neither
  half can drift without the other.

  Failed mutations (schema reject, persistence error, unknown id) do
  NOT emit a receipt — there is no state change to attest, and a
  phantom receipt for a non-event would corrupt the audit log.

  ## Cross-references

    * `Recurse.Gateway.McpRegistry.Loader` — the cached catalog source.
    * `Recurse.Gateway.McpRegistry.Mutator` — write-side singleton.
    * `Recurse.Gateway.Admin.SchemaPublication` — the established
       priv-loaded admin-endpoint pattern this module mirrors.
    * `design/briefs/07-mcp-registry.md` §"Quarantine workflow".
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.McpRegistry.Loader
  alias Recurse.Gateway.McpRegistry.Mutator
  alias Recurse.Shared.IdentityContext

  require Logger

  @action_quarantine ~s|Recurse::Action::"McpRegistryQuarantine"|
  @valid_target_tiers ~w(verified community quarantined)
  @max_reason_bytes 500

  @doc """
  Handle `GET /v1/mcp/registry`.

  Returns the full catalog payload. The BrowserSessionPipe established
  the cookie envelope before this handler runs; the principal lives on
  `conn.assigns.identity_ctx`.
  """
  @spec list(Plug.Conn.t()) :: Plug.Conn.t()
  def list(%Plug.Conn{} = conn) do
    catalog = Loader.catalog()

    body =
      JSON.encode!(%{
        "version" => catalog.version,
        "generated_at" => catalog.generated_at,
        "description" => catalog.description,
        "entries" => Enum.map(catalog.entries, &Loader.entry_to_json/1)
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(200, body)
  end

  @doc """
  Handle `GET /v1/mcp/registry/:id`.

  Returns the single registry entry by id, or a 404 F001 error envelope.
  """
  @spec get_one(Plug.Conn.t()) :: Plug.Conn.t()
  def get_one(%Plug.Conn{path_params: %{"id" => id}} = conn) when is_binary(id) do
    case Loader.get(id) do
      {:ok, entry} ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(Loader.entry_to_json(entry)))

      :error ->
        send_not_found(conn, id)
    end
  end

  def get_one(%Plug.Conn{} = conn), do: send_not_found(conn, "")

  @doc """
  Handle `PATCH /v1/mcp/registry/:id`.

  Operator-only mutation that flips an entry's `trust_tier` (and the
  documented Cedar policy clause) per the F7 quarantine workflow.

  Request body:

      { "trust_tier": "quarantined" | "verified" | "community",
        "reason": "<optional auditor-facing free text, ≤500 bytes>" }

  Responses:

    * `200` — `{"entry": <full updated entry>, "previous_trust_tier": "<tier>"}`
    * `400` — malformed body / unknown trust_tier
    * `401` — auth missing/invalid (handled inside `Authz.gate/4`)
    * `403` — caller is not `platform_operator`
    * `404` — unknown entry id
    * `500` — persistence failure (read-only filesystem); receipt NOT
      emitted

  Side effects (only on the 200 path):

    1. The entry's `trust_tier` flips in `:persistent_term` AND on
       disk (atomic tmp+rename in `Mutator`).
    2. The entry's `policy_constraints.cedar_policies` is rewritten
       from `permit(...)` to `forbid(...)` (or vice-versa for restore)
       so the auditor-facing documentation matches runtime gate state.
    3. A `:ui_mcp_quarantine` DSSE-signed ledger receipt is committed
       before the HTTP response goes out (Principle III).
  """
  @spec update(Plug.Conn.t()) :: Plug.Conn.t()
  def update(%Plug.Conn{path_params: %{"id" => entry_id}} = conn) when is_binary(entry_id) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "mcp_registry_quarantine",
      attrs: %{"endpoint" => "/v1/mcp/registry/#{entry_id}"}
    }

    case Authz.gate(conn, @action_quarantine, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_update(conn_after, ctx, entry_id)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  def update(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "id path parameter is required")
  end

  defp do_update(conn, %IdentityContext{} = ctx, entry_id) do
    body = conn.body_params || %{}

    with {:ok, target_tier} <- parse_target_tier(Map.get(body, "trust_tier")),
         {:ok, reason} <- parse_reason(Map.get(body, "reason")) do
      mutation_ctx = %{
        actor_principal_subject: principal_subject_from_ctx(ctx),
        reason: reason
      }

      case Mutator.update_trust_tier(entry_id, target_tier, mutation_ctx) do
        {:ok, %{previous_tier: previous_tier, previous_entry: previous_entry, entry: entry}} ->
          finish_update(
            conn,
            ctx,
            {entry, previous_tier, previous_entry},
            reason,
            entry_id,
            target_tier
          )

        {:error, :not_found} ->
          send_not_found(conn, entry_id)

        {:error, {:write_failed, reason}} ->
          Logger.error(
            "mcp_registry: PATCH #{entry_id} -> #{target_tier} write_failed: " <>
              inspect(reason)
          )

          Authz.send_internal_error(conn, {:registry_write_failed, reason})

        {:error, {:invalid_tier, _}} ->
          Authz.send_bad_request(
            conn,
            "trust_tier must be one of: " <> Enum.join(@valid_target_tiers, ", ")
          )
      end
    else
      {:error, :invalid_trust_tier} ->
        Authz.send_bad_request(
          conn,
          "trust_tier is required and must be one of: " <> Enum.join(@valid_target_tiers, ", ")
        )

      {:error, :invalid_reason} ->
        Authz.send_bad_request(
          conn,
          "reason must be a string ≤#{@max_reason_bytes} bytes"
        )
    end
  end

  # ---------------------------------------------------------------------------
  # Private — body parsing
  # ---------------------------------------------------------------------------

  defp finish_update(
         conn,
         ctx,
         {entry, previous_tier, previous_entry},
         reason,
         entry_id,
         target_tier
       ) do
    # Receipt commits SYNCHRONOUSLY before the HTTP response, per
    # Principle III. We use `emit_strict/2` (NOT `emit/2`) so a
    # ledger-commit failure surfaces as `{:error, _}` instead of
    # being swallowed. On failure we ROLL BACK the disk + cache
    # mutation via `Mutator.restore_entry/2` and return 500, so
    # the audit log invariant — every receipt corresponds to a
    # real state change AND vice versa — is preserved.
    case emit_quarantine_receipt(ctx, entry, previous_tier, reason) do
      {:ok, _run_id} ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(
          200,
          JSON.encode!(%{
            "entry" => Loader.entry_to_json(entry),
            "previous_trust_tier" => Atom.to_string(previous_tier)
          })
        )

      {:error, commit_reason} ->
        rollback_outcome = Mutator.restore_entry(previous_entry)

        Logger.error(
          "mcp_registry: PATCH #{entry_id} -> #{target_tier} ledger commit " <>
            "FAILED: #{inspect(commit_reason)}; rollback=#{inspect(rollback_outcome)}"
        )

        Authz.send_internal_error(
          conn,
          {:ledger_commit_failed, commit_reason, rollback_outcome}
        )
    end
  end

  defp parse_target_tier(tier) when tier in @valid_target_tiers,
    do: {:ok, String.to_existing_atom(tier)}

  defp parse_target_tier(_), do: {:error, :invalid_trust_tier}

  defp parse_reason(nil), do: {:ok, nil}
  defp parse_reason(""), do: {:ok, nil}

  defp parse_reason(reason) when is_binary(reason) and byte_size(reason) <= @max_reason_bytes,
    do: {:ok, reason}

  defp parse_reason(_), do: {:error, :invalid_reason}

  # ---------------------------------------------------------------------------
  # Private — receipt emission
  # ---------------------------------------------------------------------------

  defp emit_quarantine_receipt(%IdentityContext{} = ctx, entry, previous_tier, reason) do
    UiReceipts.emit_strict(:ui_mcp_quarantine, %{
      entry_id: entry.id,
      entry_name: entry.name,
      previous_trust_tier: Atom.to_string(previous_tier),
      new_trust_tier: Atom.to_string(entry.trust_tier),
      reason: reason,
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

  defp principal_subject_from_ctx(_), do: "unknown"

  # ---------------------------------------------------------------------------
  # Private — F001 error envelope
  # ---------------------------------------------------------------------------

  defp send_not_found(conn, id) do
    body =
      JSON.encode!(%{
        "error" => "not_found",
        "error_description" => "No MCP registry entry with id #{inspect(id)}",
        "correlation_id" => correlation_id_or_new(conn),
        "attested_run_id" => nil
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(404, body)
  end

  defp correlation_id_or_new(conn) do
    case Plug.Conn.get_req_header(conn, "x-correlation-id") do
      [id | _] when is_binary(id) and id != "" -> id
      _ -> "no-correlation-id"
    end
  end
end
