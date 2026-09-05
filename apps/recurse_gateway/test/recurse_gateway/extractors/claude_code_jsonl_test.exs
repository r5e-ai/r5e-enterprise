defmodule Recurse.Gateway.Extractors.ClaudeCodeJsonlTest do
  use ExUnit.Case, async: true

  alias Recurse.Gateway.Extractors.ClaudeCodeJsonl

  doctest ClaudeCodeJsonl

  describe "Bash" do
    test "git status — read-only verb" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => "git status"}
        })

      assert tags["category"] == "subprocess_exec"
      assert tags["tool_kind"] == "bash"
      assert tags["verb"] == "git"
      assert tags["argument_body"] == "status"
      assert tags["display_summary"] == "Bash: git status"
      assert tags["scope_kind"] == "git_readonly"
      assert tags["scope_value"] == "git status"

      assert tags["semantic_args"] == %{
               "verb" => "git",
               "subverb" => "status",
               "writes" => false
             }
    end

    test "rm -rf /tmp/foo — recursive write with target_paths" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => "rm -rf /tmp/foo"}
        })

      assert tags["category"] == "subprocess_exec"
      assert tags["scope_kind"] == "subprocess_write"
      assert tags["semantic_args"]["verb"] == "rm"
      assert tags["semantic_args"]["writes"] == true
      assert tags["semantic_args"]["recursive"] == true
      assert tags["semantic_args"]["target_paths"] == ["/tmp/foo"]
      assert tags["target_resources"] == ["file:/tmp/foo"]
    end

    test "git push — git_write scope" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => "git push origin main"}
        })

      assert tags["scope_kind"] == "git_write"
      assert tags["semantic_args"]["writes"] == true
      assert tags["semantic_args"]["subverb"] == "push"
    end

    test "absolute-path verb — /usr/bin/git status normalizes to git" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => "/usr/bin/git status"}
        })

      assert tags["scope_kind"] == "git_readonly"
      assert tags["semantic_args"]["verb"] == "git"
      assert tags["semantic_args"]["subverb"] == "status"
    end

    test "empty command — graceful nil verb" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => ""}
        })

      assert tags["category"] == "subprocess_exec"
      assert tags["display_summary"] == "Bash: (empty)"
      refute Map.has_key?(tags["semantic_args"], "verb")
    end

    test "writes flag false for read-only verbs" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => "ls -la"}
        })

      # Default fallthrough — `ls` is not in @writing_verbs so writes=false.
      assert tags["semantic_args"]["writes"] == false
      assert tags["scope_kind"] == "subprocess_read"
    end
  end

  describe "Edit / Write / Read" do
    test "Edit inside-workdir relative path" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Edit",
          "input" => %{"file_path" => "lib/foo.ex"}
        })

      assert tags["category"] == "file_write"
      assert tags["display_summary"] == "Edit: lib/foo.ex"
      assert tags["scope_kind"] == "file_inside_workdir"
      assert tags["semantic_args"]["file_path"] == "lib/foo.ex"
      assert tags["semantic_args"]["outside_workdir"] == false
      assert tags["target_resources"] == ["file:lib/foo.ex"]
    end

    test "Read outside-workdir path — file_outside_workdir scope" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Read",
          "input" => %{"file_path" => "/etc/secrets/key.pem"}
        })

      assert tags["category"] == "file_read"
      assert tags["scope_kind"] == "file_outside_workdir"
      assert tags["semantic_args"]["file_path"] == "/etc/secrets/key.pem"
      assert tags["semantic_args"]["outside_workdir"] == true
    end

    test "Write missing file_path — graceful empty path" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Write",
          "input" => %{}
        })

      assert tags["category"] == "file_write"
      assert tags["display_summary"] == "Write: (no path)"
      assert tags["scope_kind"] == "file_inside_workdir"
    end
  end

  describe "WebFetch / WebSearch" do
    test "WebFetch — host, scheme, network_external" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "WebFetch",
          "input" => %{"url" => "https://api.example.com/v1/foo"}
        })

      assert tags["category"] == "network_egress"
      assert tags["scope_kind"] == "network_external"
      assert tags["semantic_args"]["host"] == "api.example.com"
      assert tags["semantic_args"]["scheme"] == "https"
      assert tags["target_resources"] == ["host:api.example.com"]
    end

    test "WebFetch malformed URL — graceful unknown scope" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "WebFetch",
          "input" => %{"url" => "::not-a-url::"}
        })

      assert tags["category"] == "network_egress"
      assert tags["scope_kind"] in ["network_external", "network_unknown"]
    end

    test "WebSearch — network_search scope, query in semantic_args" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "WebSearch",
          "input" => %{"query" => "elixir genserver tutorial"}
        })

      assert tags["category"] == "network_egress"
      assert tags["scope_kind"] == "network_search"
      assert tags["semantic_args"]["query"] == "elixir genserver tutorial"
    end
  end

  describe "MCP — mcp__server__tool" do
    test "datadog query_metrics with time-window — span computed in days" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "mcp__datadog__query_metrics",
          "input" => %{
            "metric" => "cpu_load",
            "since" => "2026-04-01",
            "until" => "2026-04-15"
          }
        })

      assert tags["category"] == "mcp_tool_call"
      assert tags["display_summary"] == "MCP[datadog]: query_metrics"
      assert tags["scope_kind"] == "metrics_query"
      assert tags["semantic_args"]["server"] == "datadog"
      assert tags["semantic_args"]["tool"] == "query_metrics"
      assert tags["semantic_args"]["metric"] == "cpu_load"
      assert tags["semantic_args"]["time_window_start"] == "2026-04-01"
      assert tags["semantic_args"]["time_window_end"] == "2026-04-15"
      assert tags["semantic_args"]["time_window_span_days"] == 14
      assert tags["target_resources"] == ["mcp:datadog/query_metrics", "metric:cpu_load"]
    end

    test "MCP without time-window — mcp_call scope" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "mcp__github__list_issues",
          "input" => %{"repo" => "acme/widgets"}
        })

      assert tags["category"] == "mcp_tool_call"
      assert tags["scope_kind"] == "mcp_call"
      assert tags["semantic_args"]["server"] == "github"
      assert tags["semantic_args"]["tool"] == "list_issues"
      refute Map.has_key?(tags["semantic_args"], "time_window_span_days")
    end

    test "MCP with datetime time-window — datetime parses, span in days" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "mcp__datadog__query_metrics",
          "input" => %{
            "from" => "2026-04-29T00:00:00Z",
            "to" => "2026-04-30T00:00:00Z"
          }
        })

      assert tags["semantic_args"]["time_window_span_days"] == 1
    end

    test "MCP malformed mcp__-prefixed name — unknown category" do
      tags = ClaudeCodeJsonl.extract(%{"name" => "mcp__incomplete", "input" => %{}})
      assert tags["category"] == "unknown"
    end
  end

  describe "Agent dispatch" do
    test "Task with subagent_type — agent: target resource" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Task",
          "input" => %{
            "subagent_type" => "general-purpose",
            "description" => "Investigate the build failure on origin/main",
            "prompt" => "..."
          }
        })

      assert tags["category"] == "agent_dispatch"
      assert tags["scope_kind"] == "agent_dispatch"
      assert tags["semantic_args"]["subagent_type"] == "general-purpose"

      assert tags["semantic_args"]["description_summary"] ==
               "Investigate the build failure on origin/main"

      assert tags["target_resources"] == ["agent:general-purpose"]
    end
  end

  describe "TodoWrite + NotebookEdit" do
    test "TodoWrite — todo count" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "TodoWrite",
          "input" => %{"todos" => [%{"content" => "a"}, %{"content" => "b"}]}
        })

      assert tags["category"] == "todo_management"
      assert tags["semantic_args"]["todo_count"] == 2
    end

    test "NotebookEdit — outside_workdir respected" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "NotebookEdit",
          "input" => %{"notebook_path" => "/var/tmp/foo.ipynb", "cell_type" => "code"}
        })

      assert tags["category"] == "notebook_edit"
      assert tags["scope_kind"] == "file_outside_workdir"
      assert tags["semantic_args"]["cell_type"] == "code"
    end
  end

  describe "Unknown + malformed" do
    test "unknown tool name — best-effort summary, sorted arg-keys captured" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "BrandNewTool",
          "input" => %{"foo" => 1, "bar" => 2}
        })

      assert tags["category"] == "unknown"
      assert tags["display_summary"] == "BrandNewTool (unrecognized tool)"
      assert tags["semantic_args"]["arg_keys"] == ["bar", "foo"]
    end

    test "non-map input — malformed category, never raises" do
      tags = ClaudeCodeJsonl.extract(%{"name" => "Bash", "input" => "not-a-map"})
      assert tags["category"] == "malformed"
      assert tags["display_summary"] == "Bash (malformed args)"
      assert tags["semantic_args"]["input_type"] == "string"
    end

    test "missing tool name — malformed" do
      tags = ClaudeCodeJsonl.extract(%{"input" => %{}})
      assert tags["category"] == "malformed"
    end

    test "non-map block entirely — malformed" do
      tags = ClaudeCodeJsonl.extract("garbage")
      assert tags["category"] == "malformed"
    end
  end

  describe "extractor v2 — top-level tool_kind / verb / argument_body (issue #62)" do
    test "Bash echo — verb is first token, argument_body is the rest verbatim" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => ~s(echo "hello world")}
        })

      assert tags["tool_kind"] == "bash"
      assert tags["verb"] == "echo"
      assert tags["argument_body"] == ~s("hello world")
    end

    test "Bash rm -rf — argument_body preserves flags + targets" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => "rm -rf /tmp/foo"}
        })

      assert tags["tool_kind"] == "bash"
      assert tags["verb"] == "rm"
      assert tags["argument_body"] == "-rf /tmp/foo"
    end

    test "Bash empty command — verb nil, argument_body nil" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => ""}
        })

      assert tags["tool_kind"] == "bash"
      assert tags["verb"] == nil
      assert tags["argument_body"] == nil
    end

    test "Bash single-token command — verb set, argument_body nil" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => "ls"}
        })

      assert tags["verb"] == "ls"
      assert tags["argument_body"] == nil
    end

    test "Edit — tool_kind=edit, verb=patch, argument_body=file_path" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Edit",
          "input" => %{"file_path" => "lib/foo.ex", "old_string" => "x", "new_string" => "y"}
        })

      assert tags["tool_kind"] == "edit"
      assert tags["verb"] == "patch"
      assert tags["argument_body"] == "lib/foo.ex"
    end

    test "MultiEdit — same edit/patch shape as Edit" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "MultiEdit",
          "input" => %{"file_path" => "lib/multi.ex"}
        })

      assert tags["tool_kind"] == "edit"
      assert tags["verb"] == "patch"
      assert tags["argument_body"] == "lib/multi.ex"
    end

    test "Read /etc/secrets — tool_kind=read, verb=cat, argument_body=path" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Read",
          "input" => %{"file_path" => "/etc/secrets/x"}
        })

      assert tags["tool_kind"] == "read"
      assert tags["verb"] == "cat"
      assert tags["argument_body"] == "/etc/secrets/x"
    end

    test "WebFetch — tool_kind=webfetch, verb=get, argument_body=url" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "WebFetch",
          "input" => %{"url" => "https://example.com/path"}
        })

      assert tags["tool_kind"] == "webfetch"
      assert tags["verb"] == "get"
      assert tags["argument_body"] == "https://example.com/path"
    end

    test "WebSearch — tool_kind=webfetch, verb=search, argument_body=query" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "WebSearch",
          "input" => %{"query" => "elixir genserver"}
        })

      assert tags["tool_kind"] == "webfetch"
      assert tags["verb"] == "search"
      assert tags["argument_body"] == "elixir genserver"
    end

    test "MCP query_metrics — tool_kind=mcp, verb=tool name, argument_body=JSON-encoded input" do
      input = %{"metric" => "cpu_load", "since" => "2026-04-01"}

      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "mcp__datadog__query_metrics",
          "input" => input
        })

      assert tags["tool_kind"] == "mcp"
      assert tags["verb"] == "query_metrics"
      assert is_binary(tags["argument_body"])
      # Round-trip the JSON-encoded body back to a map and compare structurally
      # — guards against hidden ordering coupling.
      assert Jason.decode!(tags["argument_body"]) == input
    end

    test "MCP empty input — argument_body nil (compacted)" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "mcp__github__list_repos",
          "input" => %{}
        })

      assert tags["tool_kind"] == "mcp"
      assert tags["verb"] == "list_repos"
      assert tags["argument_body"] == nil
    end

    test "Agent dispatch — tool_kind=agent, verb=dispatch, argument_body=subagent_type" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Agent",
          "input" => %{"subagent_type" => "extractor-v2", "description" => "ship #62"}
        })

      assert tags["tool_kind"] == "agent"
      assert tags["verb"] == "dispatch"
      assert tags["argument_body"] == "subagent_type: extractor-v2"
    end

    test "Task dispatch — same agent/dispatch shape" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Task",
          "input" => %{"subagent_type" => "general-purpose", "description" => "..."}
        })

      assert tags["tool_kind"] == "agent"
      assert tags["verb"] == "dispatch"
      assert tags["argument_body"] == "subagent_type: general-purpose"
    end

    test "TodoWrite — tool_kind=todo, verb=todo, argument_body=count" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "TodoWrite",
          "input" => %{"todos" => [%{"content" => "a"}, %{"content" => "b"}, %{"content" => "c"}]}
        })

      assert tags["tool_kind"] == "todo"
      assert tags["verb"] == "todo"
      assert tags["argument_body"] == "3 todos"
    end

    test "Glob — tool_kind=search, verb=glob, argument_body=pattern" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Glob",
          "input" => %{"pattern" => "**/*.ex"}
        })

      assert tags["tool_kind"] == "search"
      assert tags["verb"] == "glob"
      assert tags["argument_body"] == "**/*.ex"
    end

    test "Grep — tool_kind=search, verb=grep, argument_body=pattern" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Grep",
          "input" => %{"pattern" => "defmodule\\s+\\w+"}
        })

      assert tags["tool_kind"] == "search"
      assert tags["verb"] == "grep"
      assert tags["argument_body"] == "defmodule\\s+\\w+"
    end

    test "NotebookEdit — tool_kind=notebook_edit, verb=patch, argument_body=path" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "NotebookEdit",
          "input" => %{"notebook_path" => "/tmp/x.ipynb", "cell_type" => "code"}
        })

      assert tags["tool_kind"] == "notebook_edit"
      assert tags["verb"] == "patch"
      assert tags["argument_body"] == "/tmp/x.ipynb"
    end

    test "unknown tool — tool_kind=unknown, verb nil, argument_body nil (graceful)" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "BrandNewSurface",
          "input" => %{"x" => 1}
        })

      assert tags["tool_kind"] == "unknown"
      assert tags["verb"] == nil
      assert tags["argument_body"] == nil
    end

    test "malformed (non-map input) — tool_kind=unknown, verb nil, argument_body nil" do
      tags = ClaudeCodeJsonl.extract(%{"name" => "Bash", "input" => "not-a-map"})

      assert tags["tool_kind"] == "unknown"
      assert tags["verb"] == nil
      assert tags["argument_body"] == nil
    end

    test "all stable top-level keys present on every category (no missing keys)" do
      shapes = [
        %{"name" => "Bash", "input" => %{"command" => "git status"}},
        %{"name" => "Edit", "input" => %{"file_path" => "lib/foo.ex"}},
        %{"name" => "Read", "input" => %{"file_path" => "lib/bar.ex"}},
        %{"name" => "Glob", "input" => %{"pattern" => "*.ex"}},
        %{"name" => "WebFetch", "input" => %{"url" => "https://x.test"}},
        %{"name" => "mcp__github__list_repos", "input" => %{"org" => "x"}},
        %{"name" => "Agent", "input" => %{"subagent_type" => "x"}},
        %{"name" => "TodoWrite", "input" => %{"todos" => []}},
        %{"name" => "NotebookEdit", "input" => %{"notebook_path" => "/x.ipynb"}},
        %{"name" => "BrandNewTool", "input" => %{}}
      ]

      Enum.each(shapes, fn block ->
        tags = ClaudeCodeJsonl.extract(block)
        # Every extractor v2 row MUST have the three new keys present
        # (value may be nil, but the key must be there).
        assert Map.has_key?(tags, "tool_kind"), "missing tool_kind for #{inspect(block)}"
        assert Map.has_key?(tags, "verb"), "missing verb for #{inspect(block)}"
        assert Map.has_key?(tags, "argument_body"), "missing argument_body for #{inspect(block)}"
        assert is_binary(tags["tool_kind"]), "tool_kind must be string for #{inspect(block)}"
      end)
    end
  end

  describe "schema-on-read JSONB invariants" do
    test "all top-level keys are strings (no atoms — survives JSONB round-trip)" do
      tags =
        ClaudeCodeJsonl.extract(%{
          "name" => "Bash",
          "input" => %{"command" => "git status"}
        })

      Enum.each(Map.keys(tags), fn k ->
        assert is_binary(k), "top-level key #{inspect(k)} must be a string"
      end)

      Enum.each(Map.keys(tags["semantic_args"]), fn k ->
        assert is_binary(k), "semantic_args key #{inspect(k)} must be a string"
      end)
    end

    test "Jason round-trip is lossless for representative shapes" do
      shapes = [
        %{"name" => "Bash", "input" => %{"command" => "git status"}},
        %{"name" => "Edit", "input" => %{"file_path" => "lib/foo.ex"}},
        %{
          "name" => "mcp__datadog__query_metrics",
          "input" => %{"metric" => "cpu", "since" => "2026-04-01", "until" => "2026-04-02"}
        },
        %{"name" => "Task", "input" => %{"subagent_type" => "x", "description" => "y"}}
      ]

      Enum.each(shapes, fn block ->
        tags = ClaudeCodeJsonl.extract(block)
        decoded = tags |> Jason.encode!() |> Jason.decode!()
        # Top-level shape must round-trip exactly. Atoms anywhere would break this.
        assert decoded == tags
      end)
    end
  end
end
