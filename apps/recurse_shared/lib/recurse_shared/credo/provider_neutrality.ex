if Code.ensure_loaded?(Credo.Check) do
  defmodule Recurse.Credo.ProviderNeutrality do
    @moduledoc """
    Custom Credo check enforcing Constitution Principle V / FR-004:
    vendor-SDK imports are only permitted inside the provider implementation
    tree (`apps/recurse_providers/lib/recurse_providers/impls/`).

    Any `alias`, `import`, or `use` of a known vendor SDK module in Gateway
    or Runtime business-logic code is flagged with a line-numbered issue
    pointing at the offending statement. The Provider Interface contract
    (Deliverable B) is the only supported path between Recurse core and a
    vendor — direct imports break the abstraction and lock Recurse to one
    vendor.

    See `specs/001-api-jido-foundations/research.md` D16 for the decision
    context.

    ## Allowlist, not denylist

    Previous iteration was a hardcoded list of 12 vendor SDK prefixes (ExAws,
    HTTPoison, etc.). Reviewer flagged (F7/F5 on speckit-pr-review) that any
    SDK not in the list — `Anthropic`, `OpenAI.*` as a hex package, vendor-
    specific OpenTelemetry exporters, `Stripe`, `Oban.Pro` vendor modules —
    slipped past silently. That was the wrong direction: FR-004 says
    "business logic MUST NOT import vendor SDKs directly," which is denylist-
    shaped semantically but allowlist-shaped operationally.

    The current implementation is an allowlist: any `alias`/`import`/`use` of
    a module whose top-level name is NOT in `@approved_prefixes` gets flagged
    in Gateway/Runtime business-logic files. The list covers only what Gateway
    and Runtime legitimately need: Recurse internal modules, the BEAM stdlib
    (which is called unqualified and so doesn't trigger alias/import/use),
    and the Phase-1-committed engines the spec explicitly permits. Vendor
    SDKs for external systems (AWS, OpenAI, Anthropic, Jira, etc.) MUST live
    in `apps/recurse_providers/lib/recurse_providers/impls/` behind a
    Provider Interface — the whole point of Principle V.

    ## Scope

      * Files under `apps/recurse_gateway/lib/` — checked.
      * Files under `apps/recurse_runtime/lib/` — checked.
      * Files under `apps/recurse_providers/lib/recurse_providers/impls/` — exempt.
      * Everything else (shared types, test support, specs) — not checked.

    ## Approved prefixes

    See `@approved_prefixes`. When a new library legitimately belongs in the
    Gateway/Runtime business-logic layer (e.g., a new BEAM primitive), add it
    here with a code-review sign-off citing the Constitution principle it
    doesn't violate.

    ## Alias resolution (resolved in Phase-10 refactor pass 2026-04-24)

    The check performs a two-pass AST walk to resolve short aliased names
    against the full module path before checking the approved-prefix
    allowlist. Scope is tracked as an explicit **stack** of per-module
    alias tables, keyed by the enclosing `defmodule` AST; nested modules
    inherit outer aliases AND may shadow them without leaking rebindings
    back out.

    Pass 1 (`collect_scopes/1`) walks the AST depth-first, pushes a new
    scope on each `defmodule` enter, captures every `alias` / `require`
    directive (simple, `:as`-rebound, and multi-alias `Base.{A, B}`
    forms) into the current scope's table, and emits a map
    `%{defmodule_line => flattened_alias_table}` where the flattened
    table is the stack merged outer-to-inner (inner shadows outer).

    Pass 2 (`traverse/3`) uses that table to resolve bare short names at
    each `__aliases__` call site and each `alias`/`import`/`use`
    directive, consulting the innermost scope whose defmodule encloses
    the node's line. If the short name resolves to an approved
    full-path prefix, no issue is raised; otherwise the issue's trigger
    is the **resolved** full path (so a forbidden `alias ExAws.S3, as:
    S3` followed by `S3.get_object/2` flags against `ExAws.S3`, not
    `S3`).

    `require Logger` + `Logger.info/1` is treated identically to alias
    for bare-name resolution (Elixir's scoping for `require` expands
    short names the same way). `import Enum` + `map(...)` is not a
    `__aliases__` call site at all — it compiles to a bare local
    function call — so no resolution is needed and no issue fires.

    Enumerated coverage at
    `apps/recurse_shared/test/recurse_shared/credo/provider_neutrality_test.exs`.

    ## Current scope note

    The check is scoped to Gateway (`apps/recurse_gateway/lib/`) and
    Runtime (`apps/recurse_runtime/lib/`) as of F002 Phase 10. The
    F002-introduced broker (`apps/recurse_broker/lib/`) is intentionally
    NOT in scope here — adding it is a deliberate extension recorded in
    `specs/002-standalone-gateway-vertical-slice/parked-tests.md` (see
    "Broker scope for ProviderNeutrality check") so the allowlist can
    be audited against broker's legitimate `JOSE` / `Req` / `Finch`
    needs before widening the filter. Do not broaden the scope without
    that review.
    """

    use Credo.Check,
      base_priority: :high,
      category: :design,
      explanations: [
        check: """
        Gateway and Runtime business logic must call every external system
        through a Provider Interface (Constitution Principle V / FR-004).
        Direct imports of vendor SDK modules — for example `ExAws.S3`,
        `HTTPoison`, or `Tesla` — reach past the abstraction and bind the
        core to one vendor's wire format.

        Move the vendor call into a module under
        `apps/recurse_providers/lib/recurse_providers/impls/` that implements
        the appropriate Provider Interface behaviour, and have the Gateway or
        Runtime code call that behaviour via the application's configured
        provider tuple.
        """
      ]

    # Allowlist of top-level prefixes permitted in Gateway/Runtime business
    # logic. Anything else gets flagged. To extend: add the prefix + a comment
    # explaining why this library belongs in business logic and not behind a
    # Provider Interface.
    @approved_prefixes [
      # Recurse internal — always OK
      "Recurse",
      # OSS admission release review: these are the required local kernel
      # and core verifier, not remote vendor SDKs (FR-004). Gateway policy
      # and evidence cross this boundary before releasing model/tool bytes.
      "R5e",
      "RecurseVerify",
      # HTTP server stack (Gateway)
      "Plug",
      "Bandit",
      # WebSocket adapter — bridges Plug.Conn upgrade requests to the
      # `WebSock` behaviour for Bandit (or Cowboy). Used by F004 T063's
      # LiveTailSocket. Vendor-neutral BEAM-ecosystem WebSocket plumbing,
      # not a vendor SDK — same trust class as Bandit/Plug.
      "WebSockAdapter",
      # Intra-node messaging (FR-034)
      "Phoenix.PubSub",
      "Registry",
      "GenServer",
      "Supervisor",
      "DynamicSupervisor",
      "Task",
      "Agent",
      # Async pipelines (Runtime)
      "Broadway",
      "Oban",
      # Query layer — specific drivers (Postgrex, MyXQL, ...) are blocked by
      # NOT being in this list and must live in providers/impls/
      "Ecto",
      # Constitution Principle III primitives (JWT/JWS/JWE) — allowed in
      # business logic because signing is structural, not vendor-specific
      "JOSE",
      # Framework-level HTTP primitives used by Gateway identity-side paths
      # (JWKS fetch over the named `:jwks_pool`) per F002 research D2 +
      # contracts/provider_impls.md §"approved framework primitives". These
      # are BEAM-ecosystem transports, not vendor SDKs — Req + Finch speak
      # the same HTTP a Provider Interface would, but the JWKS endpoint is
      # a Gateway-native identity primitive (FR-007), not a vendor service.
      "Req",
      "Finch",
      # OSS transport review: Mint HTTP/HTTP2/WebSocket implement the
      # transparent proxy's vendor-neutral wire transport, like Finch.
      "Mint",
      # Erlang atom-module callables. Keep this list tight — these are
      # approved stdlib/observability primitives, not vendor libs. Any
      # Erlang-atom call on a module NOT in this list is flagged as a
      # "erlang remote call" violation.
      ":telemetry",
      ":crypto",
      ":public_key",
      ":ssl",
      ":ets",
      ":inet",
      ":os",
      ":code",
      ":erlang",
      ":binary",
      ":lists",
      ":maps",
      ":rand",
      ":persistent_term",
      ":timer",
      ":calendar",
      ":json",
      ":math",
      ":zip",
      ":sys",
      # Local coordination, metrics storage and formatting; no vendor IO.
      ":global",
      ":counters",
      ":io_lib",
      # Logger and other Elixir stdlib that we might alias for typespecs
      "Logger",
      "Application",
      "Enum",
      "Map",
      "List",
      "Keyword",
      "String",
      "Stream",
      "File",
      "Path",
      "IO",
      "Integer",
      "Float",
      "Process",
      "Module",
      # `Code` is Elixir stdlib peer of `Module` — used for compile-time /
      # boot-time module-existence checks (e.g. F004 T044's
      # `oban_cron_crontab/0` filters cron entries whose worker module
      # hasn't compiled yet via `Code.ensure_loaded?/1`). Vendor-neutral.
      "Code",
      "Kernel",
      "System",
      "DateTime",
      "NaiveDateTime",
      "Date",
      "Time",
      "URI",
      "Base",
      "Regex",
      "Access",
      "OptionParser",
      # Elixir 1.18+ built-in JSON module. Elixir stdlib, not a vendor
      # SDK; project migrating away from Jason per user memory.
      "JSON",
      # Legacy JSON codec still used by Gateway modules until the
      # repository-wide stdlib `JSON` migration is complete. JSON encoding is
      # structural serialization here, not a vendor transport SDK.
      "Jason",
      # Elixir stdlib runtime primitives.
      "Atom",
      "Exception",
      "RuntimeError",
      "MapSet",
      # BEAM observability primitives (hex `:telemetry_metrics`).
      # Peer of `:telemetry` above — reporters are vendor-neutral BEAM
      # constructs, not vendor SDKs.
      "Telemetry.Metrics",
      # Prometheus reporter backing the Gateway `/metrics` endpoint. This is
      # observability plumbing, not an external provider integration.
      "TelemetryMetricsPrometheus",
      # Rate-limit policy enforcement primitive used behind Gateway's local
      # backend abstraction. It does not call an external vendor service.
      "Hammer",
      # Custom-macro-support callables that show up in `use` directives
      "Mix"
    ]

    @gateway_scope "apps/recurse_gateway/lib/"
    @runtime_scope "apps/recurse_runtime/lib/"
    @providers_exempt "apps/recurse_providers/lib/recurse_providers/impls/"

    @impl Credo.Check
    def run(%SourceFile{} = source_file, params) do
      if in_scope?(source_file.filename) do
        issue_meta = IssueMeta.for(source_file, params)
        ast = SourceFile.ast(source_file)

        # Pass 1: collect per-defmodule alias table, flattened with
        # outer→inner shadowing. Produces a sorted list of
        # `{start_line, end_line, alias_table}` ranges.
        scope_ranges = collect_scopes(ast)

        # Pass 2: walk the AST and emit issues. The `line_to_aliases/2`
        # lookup binds each AST node's line to the innermost enclosing
        # defmodule's alias table (or `%{}` if outside any defmodule,
        # e.g. top-level forms in a test fixture).
        {_ast, issues} =
          Macro.prewalk(ast, [], fn node, acc ->
            aliases = aliases_for(scope_ranges, line_of(node))
            traverse(node, acc, issue_meta, aliases)
          end)

        issues
      else
        []
      end
    end

    defp in_scope?(filename) do
      relative = relative_path(filename)

      cond do
        String.starts_with?(relative, @providers_exempt) -> false
        String.starts_with?(relative, @gateway_scope) -> true
        String.starts_with?(relative, @runtime_scope) -> true
        true -> false
      end
    end

    # Path normalization — Credo may hand us either absolute or repo-relative
    # paths depending on invocation mode.
    defp relative_path(filename) do
      cwd = File.cwd!()

      cond do
        String.starts_with?(filename, cwd <> "/") ->
          String.replace_prefix(filename, cwd <> "/", "")

        String.starts_with?(filename, "/") ->
          # Absolute path outside the repo — try the tail.
          filename

        true ->
          filename
      end
    end

    # ----------------------------------------------------------------
    # Pass 1 — scope collection
    # ----------------------------------------------------------------

    # Walks the AST via an explicit DFS that pushes/pops a per-module
    # scope stack. Each `defmodule` enter prepends an empty alias
    # table; alias/require directives mutate the innermost table; the
    # flattened (merged) table is recorded at exit with the module's
    # line range. Returns a list of
    # `{start_line, end_line, alias_table}` triples in discovery order.
    #
    # Using `Macro.prewalk/3` would be wrong here: prewalk has no
    # post-visit hook, so we couldn't cleanly pop the scope stack when
    # control leaves a nested `defmodule`, and aliases declared in a
    # sibling `defmodule` above a second `defmodule` would leak via
    # accumulator ordering. Explicit recursion is simpler and correct.
    defp collect_scopes(ast) do
      {_stack, ranges} = walk_scopes(ast, [], [])
      Enum.reverse(ranges)
    end

    # `defmodule ModuleName do ... end` — push a scope, walk the body,
    # record the flattened table, then pop.
    defp walk_scopes(
           {:defmodule, meta, [_name_ast, [{:do, body} | _]]} = _node,
           stack,
           ranges
         ) do
      inner_stack = [%{} | stack]

      {final_inner_stack, ranges_from_body} =
        walk_body(body, inner_stack, ranges)

      start_line = Keyword.get(meta, :line, 0)
      end_line = end_line_of(meta) || infer_end_line(body, start_line)

      [innermost | _rest] = final_inner_stack
      flattened = flatten_stack([innermost | stack])

      # Pop the scope before returning control to the caller.
      {stack, [{start_line, end_line, flattened} | ranges_from_body]}
    end

    # Three-tuple AST node with a list of args → recurse into args
    # without touching the scope stack.
    defp walk_scopes({_tag, _meta, args} = _node, stack, ranges)
         when is_list(args) do
      Enum.reduce(args, {stack, ranges}, fn child, {st, rs} ->
        walk_scopes(child, st, rs)
      end)
    end

    # Bare list of AST nodes (e.g. block body).
    defp walk_scopes(list, stack, ranges) when is_list(list) do
      Enum.reduce(list, {stack, ranges}, fn child, {st, rs} ->
        walk_scopes(child, st, rs)
      end)
    end

    # `{key, value}` keyword tuple — walk both sides.
    defp walk_scopes({a, b}, stack, ranges) do
      {stack1, ranges1} = walk_scopes(a, stack, ranges)
      walk_scopes(b, stack1, ranges1)
    end

    defp walk_scopes(_leaf, stack, ranges), do: {stack, ranges}

    # Walk a `defmodule` body: alias/require directives at this level
    # mutate the innermost scope; nested `defmodule`s recurse (which
    # pushes/pops their own scope); everything else recurses without
    # touching the scope stack.
    defp walk_body(body, stack, ranges) do
      stmts =
        case body do
          {:__block__, _, list} -> list
          single -> [single]
        end

      Enum.reduce(stmts, {stack, ranges}, fn stmt, {st, rs} ->
        case stmt do
          {:alias, _meta, args} ->
            {update_innermost(st, &record_alias(&1, args)), rs}

          {:require, _meta, args} ->
            # `require` binds short names the same way as `alias` for
            # our call-site resolution purposes. (`require Logger` +
            # `Logger.info/1` at the call site looks identical to the
            # alias form to this check.)
            {update_innermost(st, &record_alias(&1, args)), rs}

          {:defmodule, _, _} = nested ->
            walk_scopes(nested, st, rs)

          other ->
            walk_scopes(other, st, rs)
        end
      end)
    end

    defp update_innermost([head | rest], fun), do: [fun.(head) | rest]
    defp update_innermost([], _fun), do: []

    # `alias Foo.Bar.Baz` — short `Baz` binds to `"Foo.Bar.Baz"`.
    defp record_alias(table, [{:__aliases__, _, parts}]) when is_list(parts) do
      full = join_parts(parts)
      short = parts |> List.last() |> to_string()
      Map.put(table, short, full)
    end

    # `alias Foo.Bar.Baz, as: Qux` — short `Qux` binds to
    # `"Foo.Bar.Baz"`. When `:as` is absent, fall back to the last
    # segment.
    defp record_alias(table, [{:__aliases__, _, parts}, opts])
         when is_list(parts) and is_list(opts) do
      full = join_parts(parts)

      short =
        case Keyword.get(opts, :as) do
          {:__aliases__, _, as_parts} when is_list(as_parts) ->
            as_parts |> List.last() |> to_string()

          _ ->
            parts |> List.last() |> to_string()
        end

      Map.put(table, short, full)
    end

    # `alias Foo.Bar.{Baz, Qux}` — multi-alias; binds both.
    defp record_alias(
           table,
           [{{:., _, [{:__aliases__, _, base}, :{}]}, _, aliases}]
         )
         when is_list(base) and is_list(aliases) do
      base_name = join_parts(base)

      Enum.reduce(aliases, table, fn
        {:__aliases__, _, parts}, acc when is_list(parts) ->
          tail = join_parts(parts)
          full = base_name <> "." <> tail
          short = parts |> List.last() |> to_string()
          Map.put(acc, short, full)

        _, acc ->
          acc
      end)
    end

    defp record_alias(table, _other), do: table

    defp join_parts(parts), do: Enum.map_join(parts, ".", &to_string/1)

    # Stack layout: innermost at head, outermost at tail. Merge
    # outer-first so that inner bindings win on conflicts (shadowing).
    defp flatten_stack(stack) do
      stack
      |> Enum.reverse()
      |> Enum.reduce(%{}, fn table, acc -> Map.merge(acc, table) end)
    end

    defp end_line_of(meta) do
      case Keyword.get(meta, :end) do
        [line: line] -> line
        [{:line, line} | _] -> line
        _ -> nil
      end
    end

    # Fallback when the AST metadata lacks `:end` (older AST formatter
    # outputs, macro-expanded nodes, etc.). Scan the body for the max
    # line number among descendants.
    defp infer_end_line(body, start_line) do
      body
      |> collect_lines()
      |> Enum.max(fn -> start_line end)
    end

    defp collect_lines(ast) do
      {_, lines} =
        Macro.prewalk(ast, [], fn
          {_, meta, _} = node, acc when is_list(meta) ->
            case Keyword.get(meta, :line) do
              nil -> {node, acc}
              line -> {node, [line | acc]}
            end

          node, acc ->
            {node, acc}
        end)

      lines
    end

    defp line_of({_, meta, _}) when is_list(meta), do: Keyword.get(meta, :line)
    defp line_of(_), do: nil

    # Given the ranges list and a line number, return the alias table
    # of the innermost range that contains the line. When no defmodule
    # contains the line — e.g. top-level AST before any defmodule —
    # return `%{}`.
    defp aliases_for(_ranges, nil), do: %{}

    defp aliases_for(ranges, line) do
      containing =
        Enum.filter(ranges, fn {s, e, _t} -> s <= line and line <= e end)

      case containing do
        [] ->
          %{}

        _ ->
          # Innermost = deepest nesting = largest start line.
          {_s, _e, table} =
            Enum.max_by(containing, fn {s, _e, _t} -> s end)

          table
      end
    end

    # ----------------------------------------------------------------
    # Pass 2 — checking (alias-aware)
    # ----------------------------------------------------------------

    defp traverse({:alias, meta, args} = ast, issues, issue_meta, aliases) do
      {ast, collect(args, meta, issues, issue_meta, "alias", aliases)}
    end

    defp traverse({:import, meta, args} = ast, issues, issue_meta, aliases) do
      {ast, collect(args, meta, issues, issue_meta, "import", aliases)}
    end

    defp traverse({:use, meta, args} = ast, issues, issue_meta, aliases) do
      {ast, collect(args, meta, issues, issue_meta, "use", aliases)}
    end

    # Remote function call on an Elixir module: `Foo.Bar.baz(args)`.
    # AST shape for `ExAws.S3.get_object(bucket, key)`:
    #   {{:., _, [{:__aliases__, _, [:ExAws, :S3]}, :get_object]}, _meta, [...]}
    # Short names like `[:Jcs]` are resolved against the in-scope
    # alias table before the allowlist check. Closes iteration-2 F004.
    defp traverse(
           {{:., _, [{:__aliases__, _, parts}, _fun]}, meta, _args} = ast,
           issues,
           issue_meta,
           aliases
         )
         when is_list(parts) do
      module_path = resolve_module_path(parts, aliases)

      if allowed?(module_path) do
        {ast, issues}
      else
        {ast, [issue(issue_meta, meta, module_path, "remote call") | issues]}
      end
    end

    # Remote function call on an Erlang atom module: `:telemetry.execute(a, b)`,
    # `:gen_tcp.connect(...)`, `:httpc.request(...)`, etc. AST shape:
    #   {{:., _, [:atom_mod, :fun]}, _meta, [...]}
    # Closes iteration-4 F003 — the `__aliases__` pattern above doesn't
    # match Erlang-atom module calls, so a developer doing
    # `:httpc.request(...)` in Gateway code would slip past.
    #
    # IMPORTANT: Elixir modules ARE atoms under the hood (`Kernel` ==
    # the atom `:"Elixir.Kernel"`), so a naive `is_atom/1` guard would
    # also match the Elixir-module remote-call shape the `__aliases__`
    # clause above is meant to catch, causing every string-interpolation
    # call to `Kernel.to_string/1` in error messages to fire. We filter
    # out Elixir-prefixed atoms here; those are already handled above
    # via the `__aliases__` AST shape when the call site uses an alias,
    # and are not interesting when the call site uses the fully-
    # qualified `:"Elixir.Whatever"` form (which no human writes).
    defp traverse(
           {{:., _, [atom_mod, _fun]}, meta, _args} = ast,
           issues,
           issue_meta,
           _aliases
         )
         when is_atom(atom_mod) do
      atom_str = Atom.to_string(atom_mod)

      cond do
        # Elixir module atom — handled by the __aliases__ clause. Skip.
        String.starts_with?(atom_str, "Elixir.") ->
          {ast, issues}

        # Nil / true / false / reserved runtime atoms — not module calls.
        atom_mod in [nil, true, false] ->
          {ast, issues}

        true ->
          module_path = ":" <> atom_str

          if allowed?(module_path) do
            {ast, issues}
          else
            {ast, [issue(issue_meta, meta, module_path, "erlang remote call") | issues]}
          end
      end
    end

    defp traverse(ast, issues, _issue_meta, _aliases), do: {ast, issues}

    # Resolve a `__aliases__` parts list (e.g. `[:Jcs]` or
    # `[:PostgresMerkleLedger, :Query]`) against the current scope's
    # alias table. When the head maps to a known alias, substitute the
    # full path and append the remaining parts.
    defp resolve_module_path([head | rest], aliases) when is_atom(head) do
      head_str = to_string(head)

      case Map.get(aliases, head_str) do
        nil ->
          join_parts([head | rest])

        full ->
          case rest do
            [] -> full
            _ -> full <> "." <> join_parts(rest)
          end
      end
    end

    defp resolve_module_path(parts, _aliases) when is_list(parts) do
      join_parts(parts)
    end

    defp collect(args, meta, issues, issue_meta, directive, aliases) when is_list(args) do
      modules = extract_modules(args, aliases)

      Enum.reduce(modules, issues, fn module_path, acc ->
        if allowed?(module_path) do
          acc
        else
          [issue(issue_meta, meta, module_path, directive) | acc]
        end
      end)
    end

    defp collect(_args, _meta, issues, _issue_meta, _directive, _aliases), do: issues

    # Normalize AST args into a list of dotted module names, resolving
    # against the in-scope alias table. The `alias Foo.Bar` form may
    # itself reference an earlier alias (chained `alias`es), so we
    # chain the resolution through `resolve_module_path/2`.
    defp extract_modules([{:__aliases__, _, parts} | _], aliases)
         when is_list(parts) do
      [resolve_module_path(parts, aliases)]
    end

    defp extract_modules(
           [{{:., _, [{:__aliases__, _, base}, :{}]}, _, aliases_list}],
           aliases
         )
         when is_list(base) and is_list(aliases_list) do
      base_name = resolve_module_path(base, aliases)

      Enum.map(aliases_list, fn
        {:__aliases__, _, parts} when is_list(parts) ->
          tail = join_parts(parts)
          base_name <> "." <> tail

        _ ->
          base_name
      end)
    end

    defp extract_modules(_, _aliases), do: []

    defp allowed?(module_path) do
      Enum.any?(@approved_prefixes, fn prefix ->
        module_path == prefix or String.starts_with?(module_path, prefix <> ".")
      end)
    end

    defp issue(issue_meta, meta, module_path, directive) do
      format_issue(
        issue_meta,
        message:
          "FR-004 / Constitution Principle V — #{directive} of `#{module_path}` " <>
            "is not in the Gateway/Runtime approved-prefix allowlist. If this is a " <>
            "vendor SDK, move the call into apps/recurse_providers/lib/recurse_providers/impls/ " <>
            "behind a Provider Interface. If this is a legitimate Gateway/Runtime primitive, " <>
            "add the prefix to @approved_prefixes in provider_neutrality.ex with a " <>
            "code-review sign-off.",
        trigger: module_path,
        line_no: meta[:line],
        column: meta[:column]
      )
    end
  end
end
