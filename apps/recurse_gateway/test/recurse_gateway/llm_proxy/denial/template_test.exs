defmodule Recurse.Gateway.LlmProxy.DenialInjector.TemplateTest do
  @moduledoc """
  The default denial template (R5E-102) and its appeal line (spec 012 S7):
  the line names whatever the tenant configured to appeal to, and is
  absent — not a generic "contact your administrator" — when nothing is.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.LlmProxy.DenialInjector.Template
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @deny %{rule_id: "policy6", reason: "denied_by_cedar_policy", suggested_alternative: nil}

  defp intent do
    {:ok, intent} =
      ToolUseIntent.new(%{
        call_id: "toolu_01",
        tool_name: "Bash",
        tool_args: %{"command" => "rm -rf scratch"},
        provider_event_span: %{start_byte_offset: 0, end_byte_offset: 1, event_indices: [1]}
      })

    intent
  end

  defp render(audit_context) do
    Template.render(intent(), @deny, Template.default(), audit_context: audit_context)
  end

  @base %{
    tenant_id: "01TEN_LOCAL",
    principal_id: "claude-code:abc",
    principal_kind: "obo_human",
    session_id: "sess-1",
    cedar_bundle_hash: :binary.copy(<<0x0C>>, 32)
  }

  test "no appeal pointer configured: no appeal line, no blank tail" do
    text = render(@base)
    refute text =~ "appeal"
    refute text =~ "administrator"
    assert String.ends_with?(text, "- Session: sess-1")
    assert text =~ "- Policy bundle: 0c0c0c0c0c0c"
  end

  test "empty strings count as unconfigured" do
    text = render(Map.merge(@base, %{appeal_uri: "", appeal_contact: ""}))
    refute text =~ "appeal"
  end

  test "appeal_uri alone" do
    text = render(Map.put(@base, :appeal_uri, "https://appeal.example/r5e"))

    assert text =~
             "- To appeal: https://appeal.example/r5e and cite the rule_id + bundle hash above."
  end

  test "appeal_contact alone" do
    text = render(Map.put(@base, :appeal_contact, "#sec-ops"))
    assert text =~ "- To appeal: ping #sec-ops and cite the rule_id + bundle hash above."
  end

  test "both: contact then uri, on the line after the session" do
    text =
      render(Map.merge(@base, %{appeal_uri: "https://appeal.example/r5e", appeal_contact: "#sec-ops"}))

    assert text =~
             "- Session: sess-1\n- To appeal: ping #sec-ops (https://appeal.example/r5e) and cite the rule_id + bundle hash above."
  end

  test "suggested alternative slots in between without blank lines" do
    text =
      Template.render(
        intent(),
        %{@deny | suggested_alternative: "rm -ri scratch"},
        Template.default(),
        audit_context: Map.put(@base, :appeal_contact, "#sec-ops")
      )

    assert text =~ "- Session: sess-1\n- Try alternative: rm -ri scratch\n- To appeal: ping #sec-ops"
  end
end
