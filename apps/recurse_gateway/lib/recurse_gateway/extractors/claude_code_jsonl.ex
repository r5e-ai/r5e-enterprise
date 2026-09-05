defmodule Recurse.Gateway.Extractors.ClaudeCodeJsonl do
  @moduledoc """
  Schema-on-read extractor for Claude Code `tool_use` blocks.

  Given a single tool_use block (the inner `%{"type" => "tool_use", ...}`
  map produced by Claude Code's JSONL session export), returns a map of
  enriched, queryable fields suitable for stamping onto an attestation's
  `tags` JSONB column.

  ## Why this is NOT a Provider Interface yet (Constitution Principle V)

  We have ONE concrete tool-call source today (Claude Code JSONL).
  Per Constitution Principle V the behaviour is defined when a SECOND
  consumer arrives — most likely a Codex session importer or a
  live-Gateway capture. Until then, this is a single concrete module
  with a stable public API; the interface gets carved out at the
  point we have two concrete patterns to abstract over (NOT before —
  the F002 Provider Interface set was defined post-second-impl for
  exactly this reason).

  Calling code uses `extract/1` directly today. When the second
  extractor lands we extract `Recurse.Gateway.Extractors.ToolCallExtractor`
  as a behaviour, this module renames `extract/1` to the callback,
  and the importer dispatches via the behaviour module. Until then,
  YAGNI.

  ## Output shape (`extract/1`)

  Returns a map with fixed top-level keys; `semantic_args` is the
  schema-on-read flex space:

      %{
        "category" => "subprocess_exec" | "file_write" | "file_read" |
                      "file_search" | "network_egress" | "mcp_tool_call" |
                      "agent_dispatch" | "todo_management" | "notebook_edit" |
                      "unknown" | "malformed",
        "tool_kind" => "bash" | "edit" | "read" | "search" | "webfetch" |
                       "mcp" | "agent" | "todo" | "notebook_edit" | "unknown",
        "verb" => String.t() | nil,            # action verb — see "verb / argument_body" below
        "argument_body" => String.t() | nil,   # structured action subject — see below
        "display_summary" => String.t(),       # 1-line, e.g. "Bash: git status"
        "scope_kind" => String.t() | nil,      # e.g. "git_readonly", "file_outside_workdir"
        "scope_value" => String.t() | nil,     # e.g. "git status", "/etc/secrets/key.pem"
        "target_resources" => [String.t()],    # e.g. ["file:lib/foo.ex"], ["mcp:datadog/query_metrics"]
        "semantic_args" => %{                  # schema-on-read; varies per category
          "verb" => "git",                     # subprocess
          "subverb" => "status",               # subprocess
          "writes" => true | false,            # subprocess
          "recursive" => true,                 # subprocess (rm -rf etc)
          "target_paths" => [String.t()],      # subprocess (rm/cp/mv targets)
          "file_path" => String.t(),           # file ops
          "outside_workdir" => true | false,   # file ops
          "url" => String.t(),                 # web ops
          "host" => String.t(),                # web ops
          "scheme" => String.t(),              # web ops
          "server" => String.t(),              # mcp
          "tool" => String.t(),                # mcp
          "time_window_start" => String.t(),   # mcp (ISO 8601 date or datetime)
          "time_window_end" => String.t(),     # mcp
          "time_window_span_days" => integer(),# mcp
          "metric" => String.t(),              # mcp
          "subagent_type" => String.t(),       # agent dispatch
          "description_summary" => String.t(), # agent dispatch
          ...
        }
      }

  Keys are STRINGS (not atoms) because the map round-trips through
  Postgres JSONB and unknown-atom risk on read-back is unacceptable for
  an audit-log path.

  ## verb / argument_body — extractor v2 (issue #62, 2026-04-30)

  `verb` and `argument_body` are top-level promotions of the most
  Cedar-policy-relevant fields out of the per-tool dispatch tables.
  Cedar attribute lookups address top-level keys natively; nested
  dotted access into `semantic_args` works but is harder to facet in
  the dashboard. The shape per tool is:

  | tool_kind     | verb              | argument_body                          |
  |---------------|-------------------|----------------------------------------|
  | bash          | first command tok | rest of command line                   |
  | edit          | "patch"           | file_path                              |
  | read          | "cat"             | file_path                              |
  | search        | "glob" / "grep"   | pattern                                |
  | webfetch      | "get" / "search"  | URL or query                           |
  | mcp           | tool (e.g. `query_metrics`) | `Jason.encode!(input)` (compact JSON) |
  | agent         | "dispatch"        | "subagent_type: <kind>"                |
  | todo          | "todo"            | "<count> todos"                        |
  | notebook_edit | "patch"           | notebook_path                          |
  | unknown       | nil               | nil                                    |

  `semantic_args.verb` is preserved for subprocess_exec only (where it
  predates the top-level promotion); existing Cedar policies addressing
  `semantic_args.verb` continue to work unchanged.

  ## Robustness contract

  * Unknown tool names → `category: "unknown"`, best-effort summary.
  * Malformed args (non-map input, missing required field) → `category: "malformed"`,
    `display_summary` includes the tool name; never raises.
  * Missing/empty inputs are valid; the extractor returns nil/empty
    fields rather than raising.

  This is the audit-log row-renderer's data source — IT MUST NOT CRASH.

  ## Cross-references

  * `Recurse.Gateway.Importers.ClaudeCodeSession.EntryClassifier.tool_summary/2` —
    pre-extractor B7 single-line summary; this module SUPERSEDES it for tool_call
    rows. The classifier still computes `tool_summary` for backwards-compat with
    pre-tags receipts and for column-only renderers; new code should consume
    `tags["display_summary"]` instead.
  * `Recurse.Gateway.AuditPlane.ReceiptSerializers.outer_container/2` — renders
    `tags` on the wire. NOT signed (mutable derived field).
  * `apps/recurse_providers/priv/repo/migrations/20260430100000_add_attestation_tags.exs` —
    DB migration adding the `tags` JSONB column.
  """

  @typedoc """
  Output map from `extract/1`. Top-level keys are stable; `semantic_args`
  is schema-on-read and varies per category.
  """
  @type tags :: %{required(String.t()) => term()}

  @type tool_use_block :: %{optional(String.t()) => term()}

  # MCP servers use the `mcp__<server>__<tool>` naming convention in Claude
  # Code. Splitting on the double-underscore preserves single-underscore tool
  # names like `query_metrics` or `get_dashboard`.
  @mcp_prefix "mcp__"
  @mcp_separator "__"

  # ISO 8601 date/datetime regex — strict-ish; we accept both date-only
  # ("2026-04-30") and date-time ("2026-04-30T12:34:56Z" or with offset).
  @iso8601_pattern ~r/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$/

  # Workdir markers used to classify file_path operations as inside vs.
  # outside the agent's working tree. The agent's cwd is conventionally
  # `/Users/<user>/Documents/repos/<repo>` or similar; anything starting
  # with `/etc/`, `/var/`, `/usr/`, `/private/`, etc. is "outside".
  @workdir_outside_prefixes [
    "/etc/",
    "/var/",
    "/usr/",
    "/private/",
    "/System/",
    "/Library/",
    "/bin/",
    "/sbin/",
    "/dev/",
    "/proc/",
    "/sys/",
    "/root/"
  ]

  # Subprocess verbs that mutate state vs. read-only. Drives the
  # `semantic_args.writes` flag and the `category` (subprocess_exec
  # always; the writes flag refines it).
  @writing_verbs ~w(rm mv cp mkdir rmdir touch chmod chown ln dd
                     git-commit git-push git-merge git-rebase git-reset
                     npm yarn pnpm pip apt apt-get brew docker kubectl
                     systemctl service launchctl curl-PUT wget-O)

  # Read-only git subverbs — when verb=git AND subverb in this list,
  # `scope_kind = "git_readonly"`. Anything else under git is treated as
  # write-or-unknown.
  @git_readonly_subverbs ~w(status log diff show blame branch
                              describe rev-parse rev-list ls-files
                              ls-tree config tag config remote
                              stash worktree)

  @doc """
  Extract enriched tags from a single Claude Code `tool_use` block.

  Accepts the inner block map (with `"name"` and `"input"` keys), NOT the
  outer JSONL line. The importer's `EntryClassifier` is responsible for
  walking the line → message → content[type=tool_use] tree and passing
  individual blocks here.

  ## Examples

      iex> tags = ClaudeCodeJsonl.extract(%{"name" => "Bash", "input" => %{"command" => "git status"}})
      iex> Map.take(tags, ["category", "display_summary"])
      %{"category" => "subprocess_exec", "display_summary" => "Bash: git status"}

      iex> tags = ClaudeCodeJsonl.extract(%{"name" => "Read", "input" => %{"file_path" => "/etc/secrets/key.pem"}})
      iex> Map.take(tags, ["category", "scope_kind"])
      %{"category" => "file_read", "scope_kind" => "file_outside_workdir"}

      iex> tags = ClaudeCodeJsonl.extract(%{"name" => "totally-made-up", "input" => %{}})
      iex> Map.get(tags, "category")
      "unknown"

      iex> tags = ClaudeCodeJsonl.extract(%{"name" => "Bash", "input" => "not-a-map"})
      iex> Map.get(tags, "category")
      "malformed"
  """
  @spec extract(tool_use_block()) :: tags()
  def extract(block) when is_map(block) do
    name = string_or_nil(Map.get(block, "name"))
    input = Map.get(block, "input")

    cond do
      not is_binary(name) or name == "" ->
        malformed_tags("(missing tool name)", input)

      not is_map(input) ->
        malformed_tags(name, input)

      true ->
        do_extract(name, input)
    end
  end

  def extract(_other), do: malformed_tags("(non-map block)", nil)

  # ---------------------------------------------------------------------------
  # Per-tool extraction
  # ---------------------------------------------------------------------------

  # MCP tools: `mcp__<server>__<tool>` — branched first so the rest of the
  # dispatch table doesn't need to special-case the prefix.
  defp do_extract(@mcp_prefix <> rest = name, input) do
    case String.split(rest, @mcp_separator, parts: 2) do
      [server, tool] when server != "" and tool != "" ->
        mcp_tags(name, server, tool, input)

      _ ->
        # Malformed `mcp__` shape — `mcp__foo` (no tool) or `mcp__` alone.
        unknown_tags(name, input)
    end
  end

  defp do_extract("Bash", input), do: bash_tags(input)
  defp do_extract("Edit", input), do: file_op_tags("Edit", input, :write)
  defp do_extract("Write", input), do: file_op_tags("Write", input, :write)
  defp do_extract("MultiEdit", input), do: file_op_tags("MultiEdit", input, :write)
  defp do_extract("NotebookEdit", input), do: notebook_edit_tags(input)
  defp do_extract("Read", input), do: file_op_tags("Read", input, :read)
  defp do_extract("Glob", input), do: file_search_tags("Glob", "pattern", input)
  defp do_extract("Grep", input), do: file_search_tags("Grep", "pattern", input)
  defp do_extract("WebFetch", input), do: web_tags("WebFetch", input)
  defp do_extract("WebSearch", input), do: web_search_tags(input)
  defp do_extract("Task", input), do: agent_dispatch_tags("Task", input)
  defp do_extract("Agent", input), do: agent_dispatch_tags("Agent", input)
  defp do_extract("TodoWrite", input), do: todo_write_tags(input)

  defp do_extract(other_name, input), do: unknown_tags(other_name, input)

  # ---------------------------------------------------------------------------
  # Bash — verb / subverb / writes / target_paths
  # ---------------------------------------------------------------------------

  defp bash_tags(input) do
    command = string_or_nil(Map.get(input, "command")) || ""
    {verb, subverb, target_paths, recursive?, writes?} = parse_bash_command(command)
    scope_kind = bash_scope_kind(verb, subverb, writes?)
    argument_body = bash_argument_body(command, verb)

    semantic_args =
      compact(%{
        "verb" => verb,
        "subverb" => subverb,
        "writes" => writes?,
        "recursive" => recursive? || nil,
        "target_paths" => target_paths
      })

    %{
      "category" => "subprocess_exec",
      "tool_kind" => "bash",
      "verb" => verb,
      "argument_body" => argument_body,
      "display_summary" => "Bash: " <> truncate(command, 80, fallback: "(empty)"),
      "scope_kind" => scope_kind,
      "scope_value" => command,
      "target_resources" => Enum.map(target_paths, &("file:" <> &1)),
      "semantic_args" => semantic_args
    }
  end

  # Strip the verb token off the front of the command to recover the
  # argument body — what `rm` was applied to, what `echo` will print,
  # what URL `curl` is hitting. Preserves the verb's surrounding context
  # (everything after the first whitespace chunk) so Cedar policies can
  # match on substrings like "/etc/" or ".env".
  #
  # Returns nil for empty commands (matches verb=nil contract).
  defp bash_argument_body("", _verb), do: nil
  defp bash_argument_body(_command, nil), do: nil

  defp bash_argument_body(command, _verb) when is_binary(command) do
    case String.split(command, ~r/\s+/, parts: 2) do
      [_first, rest] when rest != "" -> rest
      _ -> nil
    end
  end

  # bash scope-kind classification — extracted from `bash_tags/1` to satisfy
  # credo's cyclomatic-complexity threshold and to keep the cond bash-specific.
  defp bash_scope_kind("git", subverb, _writes?) when subverb in @git_readonly_subverbs,
    do: "git_readonly"

  defp bash_scope_kind("git", _subverb, true), do: "git_write"
  defp bash_scope_kind(_verb, _subverb, true), do: "subprocess_write"
  defp bash_scope_kind(_verb, _subverb, _writes?), do: "subprocess_read"

  # Tokenize a shell command lightly. Not a real shell parser — enough
  # to lift the verb (first token) and a useful subverb / target paths.
  # Returns {verb | nil, subverb | nil, target_paths, recursive?, writes?}.
  defp parse_bash_command(""), do: {nil, nil, [], false, false}

  defp parse_bash_command(command) when is_binary(command) do
    tokens = tokenize_command(command)

    case tokens do
      [] ->
        {nil, nil, [], false, false}

      [verb | rest] ->
        normalized_verb = normalize_verb(verb)
        subverb = lift_subverb(normalized_verb, rest)
        recursive? = recursive_flag?(rest)
        target_paths = lift_target_paths(normalized_verb, rest)
        writes? = writing_verb?(normalized_verb, subverb)

        {normalized_verb, subverb, target_paths, recursive?, writes?}
    end
  end

  defp tokenize_command(command) do
    # Strip leading env-vars (FOO=bar baz) and pipes/&&; take the first
    # command on the line for verb classification.
    command
    |> String.split([" && ", " || ", " | ", ";"], parts: 2)
    |> List.first()
    |> String.split(" ", trim: true)
    |> Enum.drop_while(&String.contains?(&1, "="))
  end

  # Strip `./` and absolute path prefix off the verb token so `./foo.sh`
  # and `/usr/bin/git` and `git` all classify as the underlying tool.
  defp normalize_verb(token) when is_binary(token) do
    cond do
      String.starts_with?(token, "./") -> "(script)"
      String.contains?(token, "/") -> token |> Path.basename() |> normalize_verb()
      true -> token
    end
  end

  # `git status`, `npm install` — second token is the subverb.
  defp lift_subverb("git", [sub | _]), do: sub
  defp lift_subverb("npm", [sub | _]), do: sub
  defp lift_subverb("yarn", [sub | _]), do: sub
  defp lift_subverb("pnpm", [sub | _]), do: sub
  defp lift_subverb("docker", [sub | _]), do: sub
  defp lift_subverb("kubectl", [sub | _]), do: sub
  defp lift_subverb("systemctl", [sub | _]), do: sub
  defp lift_subverb("brew", [sub | _]), do: sub
  defp lift_subverb("apt", [sub | _]), do: sub
  defp lift_subverb("apt-get", [sub | _]), do: sub
  defp lift_subverb("cargo", [sub | _]), do: sub
  defp lift_subverb("mix", [sub | _]), do: sub
  defp lift_subverb("aws", [sub | _]), do: sub
  defp lift_subverb(_, _), do: nil

  defp recursive_flag?(args),
    do: Enum.any?(args, &(&1 in ["-r", "-R", "-rf", "-fr", "--recursive"]))

  # rm/cp/mv non-flag args are typically file targets; pluck them.
  defp lift_target_paths(verb, args) when verb in ["rm", "cp", "mv", "ln", "touch", "mkdir"] do
    args
    |> Enum.reject(&String.starts_with?(&1, "-"))
    |> Enum.reject(&(&1 == ""))
  end

  defp lift_target_paths(_, _), do: []

  defp writing_verb?(verb, _subverb) when verb in @writing_verbs, do: true
  defp writing_verb?("git", subverb) when subverb in @git_readonly_subverbs, do: false
  defp writing_verb?("git", subverb) when is_binary(subverb), do: true
  defp writing_verb?(_, _), do: false

  # ---------------------------------------------------------------------------
  # Edit / Write / Read — file_path + outside-workdir classification
  # ---------------------------------------------------------------------------

  defp file_op_tags(tool, input, mode) do
    file_path = string_or_nil(Map.get(input, "file_path"))
    outside? = outside_workdir?(file_path)

    {category, scope_kind} =
      case {mode, outside?} do
        {:read, true} -> {"file_read", "file_outside_workdir"}
        {:read, false} -> {"file_read", "file_inside_workdir"}
        {:write, true} -> {"file_write", "file_outside_workdir"}
        {:write, false} -> {"file_write", "file_inside_workdir"}
      end

    semantic_args =
      compact(%{
        "file_path" => file_path,
        "outside_workdir" => outside?
      })

    %{
      "category" => category,
      "tool_kind" => file_op_tool_kind(mode),
      "verb" => file_op_verb(mode),
      "argument_body" => file_path,
      "display_summary" => "#{tool}: " <> (file_path || "(no path)"),
      "scope_kind" => scope_kind,
      "scope_value" => file_path,
      "target_resources" => target_resources_for_path(file_path),
      "semantic_args" => semantic_args
    }
  end

  defp file_op_tool_kind(:read), do: "read"
  defp file_op_tool_kind(:write), do: "edit"

  defp file_op_verb(:read), do: "cat"
  defp file_op_verb(:write), do: "patch"

  defp notebook_edit_tags(input) do
    notebook_path = string_or_nil(Map.get(input, "notebook_path"))
    cell_type = string_or_nil(Map.get(input, "cell_type"))

    semantic_args =
      compact(%{
        "notebook_path" => notebook_path,
        "cell_type" => cell_type,
        "outside_workdir" => outside_workdir?(notebook_path)
      })

    %{
      "category" => "notebook_edit",
      "tool_kind" => "notebook_edit",
      "verb" => "patch",
      "argument_body" => notebook_path,
      "display_summary" => "NotebookEdit: " <> (notebook_path || "(no path)"),
      "scope_kind" =>
        if(outside_workdir?(notebook_path),
          do: "file_outside_workdir",
          else: "file_inside_workdir"
        ),
      "scope_value" => notebook_path,
      "target_resources" => target_resources_for_path(notebook_path),
      "semantic_args" => semantic_args
    }
  end

  defp file_search_tags(tool, field, input) do
    pattern = string_or_nil(Map.get(input, field)) || ""
    path = string_or_nil(Map.get(input, "path"))

    semantic_args =
      compact(%{
        field => pattern,
        "path" => path
      })

    %{
      "category" => "file_search",
      "tool_kind" => "search",
      "verb" => file_search_verb(tool),
      "argument_body" => string_or_nil(pattern),
      "display_summary" => "#{tool}: " <> truncate(pattern, 80, fallback: "(empty)"),
      "scope_kind" => "file_search",
      "scope_value" => pattern,
      "target_resources" => target_resources_for_path(path),
      "semantic_args" => semantic_args
    }
  end

  defp file_search_verb("Glob"), do: "glob"
  defp file_search_verb("Grep"), do: "grep"
  defp file_search_verb(_), do: "search"

  defp outside_workdir?(nil), do: false
  defp outside_workdir?(""), do: false

  defp outside_workdir?(path) when is_binary(path) do
    Enum.any?(@workdir_outside_prefixes, &String.starts_with?(path, &1))
  end

  defp outside_workdir?(_), do: false

  defp target_resources_for_path(nil), do: []
  defp target_resources_for_path(""), do: []
  defp target_resources_for_path(path) when is_binary(path), do: ["file:" <> path]
  defp target_resources_for_path(_), do: []

  # ---------------------------------------------------------------------------
  # Web — URL / host / scheme
  # ---------------------------------------------------------------------------

  defp web_tags(tool, input) do
    url = string_or_nil(Map.get(input, "url")) || ""
    parsed = URI.parse(url)
    host = parsed.host
    scheme = parsed.scheme

    external? = scheme in ["http", "https"] and is_binary(host) and host != ""

    semantic_args =
      compact(%{
        "url" => url,
        "host" => host,
        "scheme" => scheme
      })

    %{
      "category" => "network_egress",
      "tool_kind" => "webfetch",
      "verb" => "get",
      "argument_body" => string_or_nil(url),
      "display_summary" => "#{tool}: " <> truncate(url, 100, fallback: "(empty)"),
      "scope_kind" => if(external?, do: "network_external", else: "network_unknown"),
      "scope_value" => url,
      "target_resources" => if(is_binary(host) and host != "", do: ["host:" <> host], else: []),
      "semantic_args" => semantic_args
    }
  end

  defp web_search_tags(input) do
    query = string_or_nil(Map.get(input, "query")) || ""

    %{
      "category" => "network_egress",
      "tool_kind" => "webfetch",
      "verb" => "search",
      "argument_body" => string_or_nil(query),
      "display_summary" => "WebSearch: " <> truncate(query, 100, fallback: "(empty)"),
      "scope_kind" => "network_search",
      "scope_value" => query,
      "target_resources" => [],
      "semantic_args" => compact(%{"query" => query})
    }
  end

  # ---------------------------------------------------------------------------
  # MCP — server / tool / time-window / metric
  # ---------------------------------------------------------------------------

  defp mcp_tags(name, server, tool, input) do
    time_window = extract_time_window(input)

    metric =
      string_or_nil(Map.get(input, "metric")) || string_or_nil(Map.get(input, "metric_name"))

    extra_resources =
      if is_binary(metric) and metric != "", do: ["metric:" <> metric], else: []

    base_semantic = %{
      "server" => server,
      "tool" => tool
    }

    base_semantic =
      if is_binary(metric) and metric != "" do
        Map.put(base_semantic, "metric", metric)
      else
        base_semantic
      end

    semantic_args = Map.merge(base_semantic, time_window)

    %{
      "category" => "mcp_tool_call",
      "tool_kind" => "mcp",
      "verb" => tool,
      "argument_body" => mcp_argument_body(input),
      "display_summary" => "MCP[#{server}]: #{tool}",
      "scope_kind" => mcp_scope_kind(time_window, metric),
      "scope_value" => name,
      "target_resources" => ["mcp:#{server}/#{tool}"] ++ extra_resources,
      "semantic_args" => semantic_args
    }
  end

  # Encode the MCP tool's args as compact JSON for `argument_body`. Keys
  # are sorted to make the resulting string stable across runs (matters
  # for any policy/dashboard that string-matches on the body).
  #
  # Returns nil for empty arg maps so the field compacts cleanly.
  defp mcp_argument_body(input) when is_map(input) and map_size(input) == 0, do: nil

  defp mcp_argument_body(input) when is_map(input) do
    case Jason.encode(input) do
      {:ok, json} -> json
      {:error, _} -> nil
    end
  end

  defp mcp_argument_body(_), do: nil

  defp mcp_scope_kind(time_window, _metric) when map_size(time_window) > 0, do: "metrics_query"
  defp mcp_scope_kind(_, metric) when is_binary(metric) and metric != "", do: "metrics_query"
  defp mcp_scope_kind(_, _), do: "mcp_call"

  # Look for any of {since, until, from, to, start, end, time_window_start,
  # time_window_end} in MCP args; parse as ISO 8601 (date OR datetime). If
  # both bounds parse successfully, also compute the span in days. The
  # resulting fields key into `semantic_args` as
  # `time_window_start`, `time_window_end`, `time_window_span_days`.
  defp extract_time_window(input) when is_map(input) do
    start_value =
      first_present(input, ["time_window_start", "since", "from", "start_time", "start", "begin"])

    end_value =
      first_present(input, ["time_window_end", "until", "to", "end_time", "end", "stop"])

    parsed_start = parse_iso8601(start_value)
    parsed_end = parse_iso8601(end_value)

    base =
      compact(%{
        "time_window_start" => parsed_start && to_string(parsed_start),
        "time_window_end" => parsed_end && to_string(parsed_end)
      })

    case time_span_days(parsed_start, parsed_end) do
      nil -> base
      n -> Map.put(base, "time_window_span_days", n)
    end
  end

  defp extract_time_window(_), do: %{}

  defp first_present(input, keys) do
    Enum.find_value(keys, fn key ->
      case Map.get(input, key) do
        v when is_binary(v) and v != "" -> v
        _ -> nil
      end
    end)
  end

  defp parse_iso8601(nil), do: nil

  defp parse_iso8601(value) when is_binary(value) do
    if Regex.match?(@iso8601_pattern, value) do
      if String.contains?(value, "T"),
        do: parse_iso8601_datetime(value),
        else: parse_iso8601_date(value)
    end
  end

  defp parse_iso8601_date(value) do
    case Date.from_iso8601(value) do
      {:ok, date} -> date
      _ -> nil
    end
  end

  defp parse_iso8601_datetime(value) do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _offset} -> dt
      _ -> nil
    end
  end

  defp time_span_days(%Date{} = a, %Date{} = b), do: Date.diff(b, a)

  defp time_span_days(%DateTime{} = a, %DateTime{} = b),
    do: div(DateTime.diff(b, a, :second), 86_400)

  defp time_span_days(%Date{} = a, %DateTime{} = b),
    do: time_span_days(a, DateTime.to_date(b))

  defp time_span_days(%DateTime{} = a, %Date{} = b),
    do: time_span_days(DateTime.to_date(a), b)

  defp time_span_days(_, _), do: nil

  # ---------------------------------------------------------------------------
  # Agent dispatch — Task / Agent
  # ---------------------------------------------------------------------------

  defp agent_dispatch_tags(tool, input) do
    subagent_type = string_or_nil(Map.get(input, "subagent_type"))
    description = string_or_nil(Map.get(input, "description")) || ""
    prompt = string_or_nil(Map.get(input, "prompt"))

    semantic_args =
      compact(%{
        "subagent_type" => subagent_type,
        "description_summary" => truncate(description, 80, fallback: nil),
        "prompt_length" => prompt && byte_size(prompt)
      })

    %{
      "category" => "agent_dispatch",
      "tool_kind" => "agent",
      "verb" => "dispatch",
      "argument_body" => agent_argument_body(subagent_type),
      "display_summary" => agent_summary(tool, subagent_type, description),
      "scope_kind" => "agent_dispatch",
      "scope_value" => subagent_type,
      "target_resources" => agent_resources(subagent_type),
      "semantic_args" => semantic_args
    }
  end

  defp agent_argument_body(nil), do: nil
  defp agent_argument_body(""), do: nil
  defp agent_argument_body(kind) when is_binary(kind), do: "subagent_type: " <> kind

  defp agent_summary(tool, nil, ""), do: "#{tool}: (subagent)"
  defp agent_summary(tool, nil, desc), do: "#{tool}: #{truncate(desc, 60, fallback: "")}"
  defp agent_summary(tool, kind, ""), do: "#{tool}[#{kind}]"

  defp agent_summary(tool, kind, desc),
    do: "#{tool}[#{kind}]: #{truncate(desc, 60, fallback: "")}"

  defp agent_resources(nil), do: []
  defp agent_resources(""), do: []
  defp agent_resources(kind), do: ["agent:" <> kind]

  # ---------------------------------------------------------------------------
  # TodoWrite — captured but low-information; mark the category cleanly
  # ---------------------------------------------------------------------------

  defp todo_write_tags(input) do
    todos = Map.get(input, "todos") || []
    count = if is_list(todos), do: length(todos), else: 0

    %{
      "category" => "todo_management",
      "tool_kind" => "todo",
      "verb" => "todo",
      "argument_body" => "#{count} todos",
      "display_summary" => "TodoWrite: #{count} todo(s)",
      "scope_kind" => "todo_management",
      "scope_value" => nil,
      "target_resources" => [],
      "semantic_args" => %{"todo_count" => count}
    }
  end

  # ---------------------------------------------------------------------------
  # Unknown / malformed
  # ---------------------------------------------------------------------------

  defp unknown_tags(name, input) do
    arg_keys = if is_map(input), do: Map.keys(input) |> Enum.sort() |> Enum.take(5), else: []

    %{
      "category" => "unknown",
      "tool_kind" => "unknown",
      "verb" => nil,
      "argument_body" => nil,
      "display_summary" => "#{name} (unrecognized tool)",
      "scope_kind" => nil,
      "scope_value" => nil,
      "target_resources" => [],
      "semantic_args" => compact(%{"tool_name" => name, "arg_keys" => arg_keys})
    }
  end

  defp malformed_tags(name, input) do
    %{
      "category" => "malformed",
      "tool_kind" => "unknown",
      "verb" => nil,
      "argument_body" => nil,
      "display_summary" => "#{name} (malformed args)",
      "scope_kind" => nil,
      "scope_value" => nil,
      "target_resources" => [],
      "semantic_args" =>
        compact(%{
          "tool_name" => name,
          "input_type" => input_type_label(input)
        })
    }
  end

  defp input_type_label(nil), do: "nil"
  defp input_type_label(v) when is_binary(v), do: "string"
  defp input_type_label(v) when is_list(v), do: "list"
  defp input_type_label(v) when is_map(v), do: "map"
  defp input_type_label(v) when is_number(v), do: "number"
  defp input_type_label(_), do: "other"

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp string_or_nil(v) when is_binary(v) and v != "", do: v
  defp string_or_nil(_), do: nil

  defp truncate(s, max, opts) when is_binary(s) and is_integer(max) and max > 0 do
    fallback = Keyword.get(opts, :fallback, "")

    cond do
      s == "" -> fallback
      String.length(s) <= max -> s
      true -> String.slice(s, 0, max) <> "..."
    end
  end

  defp truncate(_other, _max, opts) do
    Keyword.get(opts, :fallback, "")
  end

  defp compact(map) when is_map(map) do
    map
    |> Enum.reject(fn {_k, v} -> v in [nil, "", []] end)
    |> Map.new()
  end
end
