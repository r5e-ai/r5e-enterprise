defmodule Recurse.Gateway.Importers.ClaudeCodeSessionTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.AuditPlane.PredicateOnlyUri
  alias Recurse.Gateway.Importers.ClaudeCodeSession
  alias Recurse.Gateway.Importers.ClaudeCodeSession.EntryClassifier
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.{StubSecretsProvider, StubStorageProvider}
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo

  @fixture "test/fixtures/claude_code_sessions/sample.jsonl"

  setup do
    :ok = Sandbox.checkout(Repo)
    tenant_id = "tenant-#{System.unique_integer([:positive])}"
    :ok = StubStorageProvider.reset()

    {:ok, ledger_state} = PostgresMerkleLedger.init(%{})
    {:ok, storage_state} = StubStorageProvider.init(%{bucket: "test-bucket"})
    {:ok, secrets_state} = StubSecretsProvider.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {__MODULE__.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, ledger_state},
      storage: {StubStorageProvider, storage_state},
      secrets: {StubSecretsProvider, secrets_state},
      tenant_id: tenant_id,
      signer: "observed://gateway/importer-test"
    })

    on_exit(fn ->
      ProviderRegistry.uninstall()
      StubStorageProvider.reset()
    end)

    {:ok,
     %{
       fixture: Path.expand(@fixture, File.cwd!()),
       tenant_id: tenant_id,
       principal: "auditor@example.test"
     }}
  end

  test "imports a fixture JSONL session into receipt-shaped attestation rows", context do
    assert {:ok, %{receipts: 3, session_id: "claude-session-1"}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    attestations = attestations_for(context.tenant_id)

    assert length(attestations) == 3

    assert attestations |> Enum.map(& &1.event_kind) |> Enum.sort() == [
             :llm_call,
             :llm_call,
             :tool_call
           ]

    assert Enum.all?(attestations, &(&1.verification_level == :global_inclusion_verified))
    assert Enum.all?(attestations, &(byte_size(&1.dsse_signature) > 0))
    assert Enum.all?(attestations, &String.starts_with?(&1.payload_uri, import_payload_prefix()))

    assert attestations |> Enum.map(& &1.session_id) |> Enum.uniq() |> length() == 1
    refute Enum.any?(attestations, &(&1.session_id == &1.run_id))
    assert attestations |> Enum.map(& &1.session_chain_epoch) |> Enum.sort() == [0, 1, 2]

    signed_event_kinds = attestations |> Enum.map(&predicate/1) |> Enum.map(& &1["event_kind"])
    assert Enum.sort(signed_event_kinds) == ["llm_call", "llm_call", "tool_call"]

    signed_positions =
      attestations |> Enum.map(&predicate/1) |> Enum.map(& &1["session_chain_position"])

    assert Enum.sort(signed_positions) == [0, 1, 2]
  end

  test "pairs a tool_use block with its later tool_result outcome", context do
    assert {:ok, %{receipts: 3}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    tool_receipt =
      context.tenant_id
      |> attestations_for()
      |> Enum.find(&(&1.event_kind == :tool_call))

    assert tool_receipt.outcome == :success
    assert String.starts_with?(tool_receipt.payload_uri, import_payload_prefix())
    assert predicate(tool_receipt)["payload_uri"] == tool_receipt.payload_uri
  end

  test "B7 — surfaces tool_name + tool_summary on tool_call rows", context do
    assert {:ok, %{receipts: 3}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    tool_receipt =
      context.tenant_id
      |> attestations_for()
      |> Enum.find(&(&1.event_kind == :tool_call))

    # The fixture's tool_use block must populate tool_name on the
    # persisted row so the audit-log dashboard can display detail
    # without a payload fetch. tool_summary is a 1-line, PII-aware
    # human-readable string (e.g., "Bash: ls /tmp").
    assert is_binary(tool_receipt.tool_name)
    assert tool_receipt.tool_name != ""
    assert is_binary(tool_receipt.tool_summary)
    assert tool_receipt.tool_summary =~ tool_receipt.tool_name
  end

  test "B7 — non-tool_call rows leave tool_name + tool_summary nil", context do
    assert {:ok, %{receipts: 3}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    llm_rows =
      context.tenant_id
      |> attestations_for()
      |> Enum.filter(&(&1.event_kind == :llm_call))

    assert Enum.all?(llm_rows, &is_nil(&1.tool_name))
    assert Enum.all?(llm_rows, &is_nil(&1.tool_summary))
  end

  test "tool-call extractor — populates tags JSONB on tool_call rows", context do
    assert {:ok, %{receipts: 3}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    tool_receipt =
      context.tenant_id
      |> attestations_for()
      |> Enum.find(&(&1.event_kind == :tool_call))

    # The extractor pipeline (Recurse.Gateway.Extractors.ClaudeCodeJsonl)
    # must populate `tags` on every imported tool_call row. Top-level keys
    # are stable; semantic_args is schema-on-read.
    assert is_map(tool_receipt.tags)
    assert is_binary(tool_receipt.tags["category"])
    assert tool_receipt.tags["category"] in ~w(subprocess_exec file_read file_write
                                                 file_search network_egress mcp_tool_call
                                                 agent_dispatch todo_management
                                                 notebook_edit unknown malformed)

    assert is_binary(tool_receipt.tags["display_summary"])
    assert is_map(tool_receipt.tags["semantic_args"])
    assert is_list(tool_receipt.tags["target_resources"])
  end

  test "tool-call extractor — non-tool_call rows leave tags nil", context do
    assert {:ok, %{receipts: 3}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    llm_rows =
      context.tenant_id
      |> attestations_for()
      |> Enum.filter(&(&1.event_kind == :llm_call))

    assert Enum.all?(llm_rows, &is_nil(&1.tags))
  end

  describe "EntryClassifier.tool_summary/2 — B7 strategy" do
    test "Bash truncates the command at 60 chars and prefixes 'Bash:'" do
      cmd = String.duplicate("a", 80)
      out = EntryClassifier.tool_summary("Bash", %{"command" => cmd})

      assert String.starts_with?(out, "Bash: ")
      assert String.ends_with?(out, "...")
      # 'Bash: ' + 60 chars of `a` + '...'
      assert String.length(out) <= 80
    end

    test "Edit / Write / MultiEdit show the file path only (no diff body)" do
      assert EntryClassifier.tool_summary("Edit", %{"file_path" => "apps/foo.ex"}) ==
               "Edit: apps/foo.ex"

      assert EntryClassifier.tool_summary("Write", %{"file_path" => "/tmp/x"}) ==
               "Write: /tmp/x"

      assert EntryClassifier.tool_summary("MultiEdit", %{"file_path" => "lib/y.ex"}) ==
               "MultiEdit: lib/y.ex"
    end

    test "Read shows the file path" do
      assert EntryClassifier.tool_summary("Read", %{"file_path" => "/etc/hosts"}) ==
               "Read: /etc/hosts"
    end

    test "Glob / Grep show the pattern" do
      assert EntryClassifier.tool_summary("Glob", %{"pattern" => "**/*.ex"}) =~ "Glob: "
      assert EntryClassifier.tool_summary("Grep", %{"pattern" => "TODO"}) =~ "Grep: "
    end

    test "WebFetch shows the url (truncated)" do
      assert EntryClassifier.tool_summary("WebFetch", %{"url" => "https://example.com/x"}) =~
               "WebFetch: "
    end

    test "everything else redacts args" do
      assert EntryClassifier.tool_summary("MysteryTool", %{"secret" => "shhh"}) ==
               "MysteryTool (args redacted)"
    end

    test "non-map input falls back to redaction message" do
      assert EntryClassifier.tool_summary("Bash", "not-a-map") == "Bash (args redacted)"
    end
  end

  test "skips thinking-only assistant entries by default", context do
    assert {:ok, %{receipts: 3}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    refute context.tenant_id
           |> attestations_for()
           |> Enum.map(&predicate/1)
           |> Enum.any?(fn payload -> inspect(payload) =~ "private reasoning" end)
  end

  test "does not sign raw assistant text, tool output, cwd, or branch metadata", context do
    assert {:ok, %{receipts: 3}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    signed =
      context.tenant_id
      |> attestations_for()
      |> Enum.map(&predicate/1)
      |> inspect()

    refute signed =~ "I inspected the audit console"
    refute signed =~ "18 tests, 0 failures"
    refute signed =~ "/Users/thomasjones/Documents/repos/r5e-enterprise"
    refute signed =~ "codex/importer"
    classified = classified_specs(context.fixture) |> inspect()

    refute classified =~ "I inspected the audit console"
    refute classified =~ "18 tests, 0 failures"
    refute classified =~ "/Users/thomasjones/Documents/repos/r5e-enterprise"
    refute classified =~ "codex/importer"
    assert classified =~ "redacted"
    assert classified =~ "sha256"
    assert classified =~ "length"
    assert classified =~ "truncated_preview?"
    refute classified =~ "text_sha256"
    refute classified =~ "content_sha256"
  end

  test "is idempotent for the same Claude Code session and source entries", context do
    assert {:ok, %{receipts: 3}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    assert {:ok, %{receipts: 0}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    assert context.tenant_id |> attestations_for() |> length() == 3
  end

  test "imports the same source file into separate tenants without run_id collisions", context do
    other_tenant_id = "#{context.tenant_id}-other"

    assert {:ok, %{receipts: 3}} =
             ClaudeCodeSession.import_session(context.fixture, importer_opts(context))

    assert {:ok, %{receipts: 3}} =
             ClaudeCodeSession.import_session(
               context.fixture,
               Keyword.put(importer_opts(context), :tenant_id, other_tenant_id)
             )

    first_run_ids =
      context.tenant_id
      |> attestations_for()
      |> Enum.map(& &1.run_id)
      |> MapSet.new()

    second_run_ids =
      other_tenant_id
      |> attestations_for()
      |> Enum.map(& &1.run_id)
      |> MapSet.new()

    assert MapSet.size(first_run_ids) == 3
    assert MapSet.size(second_run_ids) == 3
    assert MapSet.disjoint?(first_run_ids, second_run_ids)
  end

  test "skips malformed JSONL lines and imports the remaining entries", context do
    path =
      temp_jsonl("malformed", [
        ~s({"type":"assistant","sessionId":"malformed-session","uuid":"ok-entry","timestamp":"2026-04-26T10:00:00Z","message":{"content":[{"type":"text","text":"valid row"}]}}),
        "{not-json"
      ])

    log =
      capture_log(fn ->
        assert {:ok, %{receipts: 1, session_id: "malformed-session"}} =
                 ClaudeCodeSession.import_session(path, importer_opts(context))
      end)

    assert log =~ "skipping malformed Claude Code JSONL line"
    assert context.tenant_id |> attestations_for() |> length() == 1
  end

  test "returns an empty result for an empty JSONL file", context do
    path = temp_jsonl("empty", [])

    assert {:ok, %{receipts: 0, session_id: nil}} =
             ClaudeCodeSession.import_session(path, importer_opts(context))

    assert context.tenant_id |> attestations_for() |> length() == 0
  end

  defp importer_opts(context) do
    [
      tenant_id: context.tenant_id,
      principal: context.principal
    ]
  end

  defp attestations_for(tenant_id) do
    import Ecto.Query

    Attestation
    |> where([a], a.tenant_id == ^tenant_id)
    |> order_by([a], asc: a.timestamp, asc: a.run_id)
    |> Repo.all()
  end

  defp predicate(attestation) do
    Jason.decode!(attestation.signed_predicate_bytes)
  end

  defp classified_specs(path) do
    entries =
      path
      |> File.stream!()
      |> Enum.map(&Jason.decode!/1)

    tool_results =
      Enum.reduce(entries, %{}, fn entry, acc ->
        Map.merge(acc, EntryClassifier.tool_results(entry))
      end)

    Enum.flat_map(entries, &EntryClassifier.receipt_specs(&1, tool_results, skip_thinking?: true))
  end

  defp import_payload_prefix do
    PredicateOnlyUri.imported_uri_scheme_prefix() <> "claude_code_session_jsonl/"
  end

  defp temp_jsonl(name, lines) do
    path =
      Path.join([
        System.tmp_dir!(),
        "r5e-claude-code-session-#{name}-#{System.unique_integer([:positive])}.jsonl"
      ])

    File.write!(path, Enum.join(lines, "\n"))
    path
  end

  defmodule StubLLM do
  end
end
