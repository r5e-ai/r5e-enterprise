defmodule Recurse.Gateway.Admin.AuditAgent.Tools.FetchReceiptDetail do
  @moduledoc """
  Audit Agent Tool 2 — `fetch_receipt_detail` (F004 T110).

  Returns the full receipt detail for a single `run_id`. Output shape
  mirrors F002's `GET /v1/audit/receipts/{run_id}` response — see
  `apps/recurse_gateway/lib/recurse_gateway/audit_plane/receipts_handler.ex`
  `render_detail/3`.

  Cost: zero LLM tokens. Cedar action:
  `Recurse::Action::"AuditAgentToolFetchReceiptDetail"`. Required roles:
  `tenant_auditor` or `platform_operator`.

  Cross-references:
    * `specs/004-audit-console/contracts/audit_agent_tools.md` §"Tool 2"
  """

  @behaviour Recurse.Gateway.Admin.AuditAgent.Tool

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo

  @input_schema %{
    "type" => "object",
    "additionalProperties" => false,
    "required" => ["run_id"],
    "properties" => %{
      "run_id" => %{"type" => "string", "format" => "uuid"}
    }
  }

  @output_schema %{
    "type" => "object",
    "required" => ["run_id", "event_kind", "policy_decision"],
    "properties" => %{
      "run_id" => %{"type" => "string"},
      "event_kind" => %{"type" => "string"},
      "policy_decision" => %{"type" => "string"},
      "principal_subject" => %{"type" => "string"},
      "tenant_id" => %{"type" => "string"},
      "timestamp" => %{"type" => "string"},
      "tier_completeness_advisory" => %{"type" => ["string", "null"]},
      "verification_level" => %{"type" => ["string", "null"]},
      "outcome" => %{"type" => ["string", "null"]},
      "payload_uri" => %{"type" => ["string", "null"]}
    }
  }

  @impl true
  def name, do: "fetch_receipt_detail"

  @impl true
  def cedar_action, do: ~s|Recurse::Action::"AuditAgentToolFetchReceiptDetail"|

  @impl true
  def event_kind, do: :ui_chat_skill_invoked_fetch_receipt_detail

  @impl true
  def input_schema, do: @input_schema

  @impl true
  def output_schema, do: @output_schema

  @impl true
  def call(%{"run_id" => run_id}, %{tenant_id: tenant_id})
      when is_binary(run_id) and is_binary(tenant_id) do
    case safe_get(run_id) do
      nil ->
        {:error, :not_found}

      %Attestation{tenant_id: ^tenant_id} = att ->
        {:ok, render(att)}

      %Attestation{} ->
        # Cross-tenant — present as :not_found so we don't leak existence.
        {:error, :not_found}
    end
  end

  defp safe_get(run_id) do
    Repo.get(Attestation, run_id)
  rescue
    Ecto.Query.CastError -> nil
  end

  defp render(%Attestation{} = att) do
    %{
      "run_id" => att.run_id,
      "event_kind" => att.event_kind |> to_string(),
      "policy_decision" => att.policy_decision |> to_string(),
      "principal_subject" => principal_subject(att.principal),
      "tenant_id" => att.tenant_id,
      "timestamp" => att.timestamp |> DateTime.to_iso8601(),
      "tier_completeness_advisory" => to_string_or_nil(att.tier_completeness_advisory),
      "verification_level" => to_string_or_nil(att.verification_level),
      "outcome" => to_string_or_nil(att.outcome),
      "payload_uri" => att.payload_uri,
      "correlation_id" => att.correlation_id,
      "session_id" => att.session_id,
      "principal" => att.principal,
      "machine_identity" => att.machine_identity,
      "attested_run_ids" => [att.run_id]
    }
  end

  defp principal_subject(%{"subject" => s}) when is_binary(s), do: s
  defp principal_subject(%{"account_id" => s}) when is_binary(s), do: s
  defp principal_subject(_), do: "unknown"

  defp to_string_or_nil(nil), do: nil
  defp to_string_or_nil(v) when is_atom(v), do: Atom.to_string(v)
  defp to_string_or_nil(v) when is_binary(v), do: v
  defp to_string_or_nil(_), do: nil
end
