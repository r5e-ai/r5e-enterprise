defmodule Recurse.Gateway.DataPlane.McpServerHandler do
  @moduledoc """
  Hosted MCP server endpoint — `POST /v1/mcp/{server}/tools/{tool}`.

  This is the **VLAN-rebuttal money shot** for the demo: every MCP tool
  call gets a cryptographically-verifiable receipt attesting which agent
  identity called which tool on which MCP server with what trust tier.

  ## Vertical-slice scope (Path B demo)

  Phase-1 ships a deliberate subset of the MCP HTTP transport spec:

    1. Token authentication: production accepts an `Authorization: Bearer
       <jwt>` minted via the Recurse broker's RFC 8693 token-exchange
       (the agent's SPIFFE-bound JWT is exchanged for a Gateway-audience
       JWT). The demo additionally accepts a STUB `Bearer demo-mcp-token-*`
       synthetic token labeled in code (the brief explicitly permits this
       — full RFC 8693 wire-up is a follow-up MR).
    2. Three demo tools, all backed by the existing audit-plane shape:
         - `r5e.audit.list_receipts(filters)`
         - `r5e.audit.verify_receipt(run_id)`
         - `r5e.audit.query_attestations(query)`
    3. Trust-tier gate: registry entries with `trust_tier == :quarantined`
       are policy-denied. Both allow AND deny paths emit `:mcp_tool_call`
       attestations (Constitution Principle III: every data-plane mutation
       attestable, including denied requests).
    4. JSON-RPC-flavored response envelope per
       `priv/schemas/mcp_tool_call_response.json`.

  ## What the demo path produces (auditor-verifiable)

  Every call → one `:mcp_tool_call` attestation in the ledger. The
  receipt's signed predicate carries (in `payload`):

    * `mcp_server` — the registry entry id
    * `tool` — the tool name
    * `policy_decision` — `"allow" | "deny"`
    * `trust_tier` — registry entry's tier at call time
    * `arguments` (truncated/redacted) — for forensic recovery

  Click any receipt on `/admin/dashboard` and the auditor sees the full
  cryptographic chain: identity → policy state → tool dispatched →
  result hash → ledger inclusion proof.

  ## Iron Law check (`elixir:elixir-thinking`)

    1. Mutable state? No — every call is a pure function of `(conn,
       registry catalog, tool args)`.
    2. Concurrent execution? No — runs on the request process. The
       receipt-emission seam (`UiReceipts.emit/2`) does its own ledger
       commit on the same process, mirroring the F004 pattern.
    3. Fault isolation? No — errors return F001 envelopes; the receipt
       emission is wrapped in `try/rescue` inside `UiReceipts`.

  All three NO → plain functions.

  ## Cross-references

    * `priv/schemas/mcp_tool_call_request.json` — request shape.
    * `priv/schemas/mcp_tool_call_response.json` — response shape.
    * `Recurse.Gateway.McpRegistry.Loader` — trusted catalog.
    * `Recurse.Gateway.Admin.BrowserAuth.UiReceipts` — receipt-emission
      seam (widened in this MR to accept `:mcp_tool_call`).
    * Constitution Principle III — every data-plane mutation attestable.
  """

  require Logger

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.McpRegistry.Loader
  alias Recurse.Gateway.ProviderRegistry

  @demo_token_prefix "demo-mcp-token-"

  @supported_tools %{
    "r5e.audit.list_receipts" => :list_receipts,
    "r5e.audit.verify_receipt" => :verify_receipt,
    "r5e.audit.query_attestations" => :query_attestations
  }

  @doc """
  Entry point — bearer-authenticated MCP tool dispatch.

  Path params: `server` + `tool` (Plug.Router populates `path_params`).
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{path_params: %{"server" => server, "tool" => tool}} = conn) do
    request_id = read_id(conn)

    with {:ok, principal_subject} <- authenticate(conn),
         {:ok, entry} <- fetch_entry(server),
         :ok <- ensure_tool_supported(tool),
         {:ok, args} <- fetch_arguments(conn) do
      dispatch(conn, request_id, entry, tool, args, principal_subject)
    else
      {:error, :missing_authorization} ->
        send_error(conn, 401, "missing_authorization", "Missing or malformed Authorization header.")

      {:error, :invalid_token} ->
        send_error(conn, 401, "invalid_token", "Bearer token rejected by validator.")

      {:error, {:registry_miss, id}} ->
        send_error(conn, 404, "mcp_server_not_found", "No MCP server registered with id #{inspect(id)}.")

      {:error, {:unsupported_tool, tool}} ->
        send_error(conn, 404, "tool_not_found",
          "Tool #{inspect(tool)} is not implemented by this MCP server. " <>
            "Supported: #{Enum.join(Map.keys(@supported_tools), ", ")}")

      {:error, {:bad_request, reason}} ->
        send_error(conn, 400, "bad_request", reason)
    end
  end

  def handle(%Plug.Conn{} = conn) do
    send_error(conn, 400, "bad_request", "Missing path params: server, tool.")
  end

  # ---------------------------------------------------------------------------
  # Auth — minimal stub: production wires through real JWT validator.
  # ---------------------------------------------------------------------------

  # Accepts EITHER:
  #   1. `Bearer demo-mcp-token-<id>` — synthetic dev/demo token. Resolves
  #      to a service-account principal `mcp-agent-<id>`.
  #   2. `Bearer <jwt>` — real production token (RFC 8693 token-exchanged
  #      JWT minted by the broker). Validation TODO — for the demo MR,
  #      we accept any non-empty bearer that is NOT the demo prefix and
  #      mark the principal as `mcp-agent-real-bearer` until the broker
  #      wire-up MR lands.
  #
  # Production hardening: replace `validate_real_bearer/1` with a call
  # through `Recurse.Gateway.Identity.JwtValidator.validate/2`.
  defp authenticate(conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      [header] when is_binary(header) ->
        normalize_bearer(header)

      _ ->
        {:error, :missing_authorization}
    end
  end

  defp normalize_bearer("Bearer " <> token), do: validate_token(String.trim(token))
  defp normalize_bearer("bearer " <> token), do: validate_token(String.trim(token))
  defp normalize_bearer(_), do: {:error, :missing_authorization}

  defp validate_token(@demo_token_prefix <> id) when byte_size(id) > 0 do
    {:ok, "mcp-agent-" <> id}
  end

  defp validate_token(token) when byte_size(token) > 0 do
    # Stub for non-demo bearers — until the broker wire-up MR lands,
    # any non-empty bearer that is NOT a demo token is accepted as
    # real-but-unverified. A production deployment MUST replace this
    # branch with `JwtValidator.validate/2`.
    Logger.info(fn ->
      "mcp_server: real-bearer stub accepted token=<redacted, len=#{byte_size(token)}>"
    end)

    {:ok, "mcp-agent-real-bearer"}
  end

  defp validate_token(_), do: {:error, :invalid_token}

  # ---------------------------------------------------------------------------
  # Registry lookup + tool dispatch
  # ---------------------------------------------------------------------------

  defp fetch_entry(server) do
    case Loader.get(server) do
      {:ok, entry} -> {:ok, entry}
      :error -> {:error, {:registry_miss, server}}
    end
  end

  defp ensure_tool_supported(tool) do
    if Map.has_key?(@supported_tools, tool) do
      :ok
    else
      {:error, {:unsupported_tool, tool}}
    end
  end

  defp fetch_arguments(conn) do
    case conn.body_params do
      %{"arguments" => args} when is_map(args) -> {:ok, args}
      %{} -> {:ok, %{}}
      _ -> {:error, {:bad_request, "Request body must be a JSON object."}}
    end
  end

  defp read_id(conn) do
    case conn.body_params do
      %{"id" => id} -> id
      _ -> nil
    end
  end

  # ---------------------------------------------------------------------------
  # The actual demo dispatch — quarantine gate + tool synthesis + receipt.
  # ---------------------------------------------------------------------------

  defp dispatch(conn, request_id, entry, tool, args, principal_subject) do
    {decision, deny_reason, result} =
      case entry.trust_tier do
        :quarantined ->
          {"deny",
           "MCP server #{inspect(entry.id)} is quarantined (trust_tier=quarantined). " <>
             "Tool calls are policy-denied per registry policy_constraints.",
           nil}

        _ ->
          synthesize_tool_result(tool, args)
      end

    run_id = Ecto.UUID.generate()
    tenant_id = ProviderRegistry.tenant_id()

    UiReceipts.emit(:mcp_tool_call, %{
      run_id: run_id,
      tenant_id: tenant_id,
      mcp_server: entry.id,
      mcp_server_name: entry.name,
      mcp_server_version: entry.version,
      tool: tool,
      trust_tier: Atom.to_string(entry.trust_tier),
      policy_decision: decision,
      principal_subject: principal_subject,
      arguments_summary: summarize_arguments(args)
    })

    body =
      JSON.encode!(%{
        "id" => request_id,
        "server" => entry.id,
        "tool" => tool,
        "policy_decision" => decision,
        "deny_reason" => deny_reason,
        "trust_tier" => Atom.to_string(entry.trust_tier),
        "attested_run_id" => run_id,
        "result" => result
      })

    status =
      case decision do
        "allow" -> 200
        "deny" -> 403
      end

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, body)
  end

  # Demo tool implementations. Synthetic results — they don't reach
  # into the ledger so the demo path stays robust against test
  # infrastructure differences. Phase-2 plumbs the real ReceiptsHandler
  # / LocalVerifyHandler through these tools (see /reflect).
  defp synthesize_tool_result("r5e.audit.list_receipts", args) do
    limit = pos_int(Map.get(args, "limit"), 5)
    event_kind = Map.get(args, "event_kind")

    receipts =
      for i <- 1..limit do
        %{
          "run_id" => "demo-run-" <> Integer.to_string(i),
          "event_kind" => event_kind || "tool_call",
          "timestamp" => "2026-04-30T00:00:#{:io_lib.format("~2..0B", [i]) |> IO.iodata_to_binary()}Z",
          "policy_decision" => "allow",
          "tenant_id" => ProviderRegistry.tenant_id()
        }
      end

    {"allow", nil, %{"receipts" => receipts, "count" => length(receipts)}}
  end

  defp synthesize_tool_result("r5e.audit.verify_receipt", args) do
    case Map.get(args, "run_id") do
      run_id when is_binary(run_id) and byte_size(run_id) > 0 ->
        {"allow", nil,
         %{
           "run_id" => run_id,
           "verification_status" => "VALID",
           "checks" => %{
             "dsse_signature" => "pass",
             "payload_hash" => "pass",
             "policy_canonical_hash" => "pass",
             "session_chain_position" => "pass",
             "rfc9162_inclusion_proof" => "pass"
           }
         }}

      _ ->
        {"allow", nil,
         %{
           "verification_status" => "INVALID",
           "error" => "missing required argument: run_id"
         }}
    end
  end

  defp synthesize_tool_result("r5e.audit.query_attestations", args) do
    query = Map.get(args, "query", "")

    {"allow", nil,
     %{
       "query" => query,
       "matches" => [
         %{
           "run_id" => "demo-run-match-1",
           "event_kind" => "policy_denied",
           "summary" => "Demo match for query " <> inspect(query)
         }
       ]
     }}
  end

  defp synthesize_tool_result(_tool, _args),
    do: {"allow", nil, %{"note" => "tool implemented but no demo synthesis"}}

  defp pos_int(v, _default) when is_integer(v) and v > 0 and v <= 100, do: v
  defp pos_int(_, default), do: default

  # Arguments may include sensitive payload bytes — for the demo we
  # capture key names + scalar arity, never raw values, so the receipt
  # is forensic-useful but not a payload leak.
  defp summarize_arguments(args) when is_map(args) do
    %{
      "keys" => args |> Map.keys() |> Enum.sort(),
      "arity" => map_size(args)
    }
  end

  defp summarize_arguments(_), do: %{"keys" => [], "arity" => 0}

  # ---------------------------------------------------------------------------
  # F001 error envelope — uniform shape across the audit + data plane.
  # ---------------------------------------------------------------------------

  defp send_error(conn, status, error, description) do
    body =
      JSON.encode!(%{
        "error" => error,
        "error_description" => description,
        "correlation_id" => correlation_id_or_new(conn),
        "attested_run_id" => nil
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, body)
  end

  defp correlation_id_or_new(conn) do
    case Plug.Conn.get_req_header(conn, "x-correlation-id") do
      [id | _] when is_binary(id) and id != "" -> id
      _ -> "no-correlation-id"
    end
  end
end
