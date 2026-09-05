defmodule Recurse.Gateway.AuditPlane.ReceiptsHandler do
  @moduledoc """
  `GET /v1/audit/receipts` (F002 T059, FR-021; F004 T061 extensions).

  Returns paginated attestations for an authenticated + Cedar-gated caller.

  ## Flow

    1. `AuditPlane.Authz.gate/4` — JWT validation + Cedar evaluation
       against `Recurse::Action::ReadReceipts`. Deny returns 403 in the
       F001 error envelope.
    2. Parse query params (`run_id`, `session_id`, `turn_id`, `limit`,
       `cursor`, `verification_level`, `tier_completeness_advisory`,
       `policy_decision`).
    3. Invoke `PostgresMerkleLedger.query_paginated/1` (public method
       on the impl per AD-001 c').
    4. Render `{receipts: [...], cursor: "..." | null}` — each receipt
       exposes the F001 split-envelope shape (`signed_predicate` +
       `outer_container`).

  ## F004 detail extension boundary (T074)

  When the router dispatches `GET /v1/audit/receipts/:run_id` (singular
  detail) the handler routes through `handle_detail/2` instead of the
  list pipeline. The detail response extends the F002 list-shape per
  `audit_api_extensions.md` cross-references:

    * `tier_completeness_advisory: "partial"` (FR-017) — surfaced at the
      top level for the SPA's amber-callout banner.
    * `payload_metadata` — full `{payload_uri, payload_hash, payload_bytes_size}`
      with `payload_bytes_size` `nil` when the StorageProvider can't
      cheaply compute it (F004 doesn't pre-fetch the payload to cost it).
    * `proof_envelope` — the full RFC 9162 `{session_chain_inclusion, global_inclusion,
      session_chain_root, signing_key_pem}` so the SPA's Verify Locally
      can run the 5-check pipeline within SC-002's 3s budget without
      additional round-trips.
    * `matched_policy.line_range` — `nil` until F005+ wires Cedar
      source-line resolution; the field is reserved per the contract so
      SPA TypeScript types stay forward-stable.

  Detail emits the SAME `:ui_query` (`query_kind: "audit_log"`) receipt
  the list path emits — single-receipt fetch is part of the audit-log
  read flow per FR-031. Cedar action remains `ReadReceipts` (F002 reuse).

  ## F004 list extension boundary (T061)

  F004 widens the surface with **additive-only** filter params + an
  alternate response shape for the audit-console structured-query bar:

    * `event_kind` — comma-separated list of canonical event_kind atoms
      (`?event_kind=ui_query,policy_denied`). When present, results are
      filtered post-fetch to the union of listed kinds.
    * `tool_name` — string filter matching `signed_predicate.tool_name`
      (currently a no-op for F004 receipts that don't carry a `tool_name`
      field; reserved for FR-010 boolean-AST attribute equality).
    * `q` — base64-encoded JSON structured-query AST (FR-010 boolean
      operators `AND`/`OR`/`NOT` over leaf predicates). Forward-stub:
      F004 ships a strict-subset evaluator (single leaf or two-leaf AND);
      the full AST evaluator lands in F005+. Bad/unknown shapes return
      400 with the F001 envelope.
    * `facets=true` — switches the response shape to
      `{receipts, facets, cursor}` per FR-012 (faceted counts grouped
      by `event_kind`, `policy_decision`, `verification_level` over the
      FULL filtered universe — server-side SQL `GROUP BY` via
      `PostgresMerkleLedger.query_facets/1`, NOT the paginated page;
      issue #44 fix 2026-04-30 so the SPA's left-rail picker shows
      every kind that exists in the table even when it's off the
      LIMIT-50 most-recent window).

  When NONE of the F004 params is present, the response shape is byte-
  identical to F002's existing surface; the F002 contract test suite
  continues to pass without modification. Cedar action remains
  `Recurse::Action::ReadReceipts` (F004 does not introduce a new
  authorization gate for the receipts endpoint — same role allowlist
  per data-model.md §0). On every successful query an additional
  `:ui_query` (`query_kind: "audit_log"`) attestation is emitted via
  `UiReceipts.emit/2` so audit-console queries are themselves attestable
  per Principle III.

  ## Iron Law check (`elixir:phoenix-thinking` / `otp-thinking`)

  Pure module. No GenServer. Runs on the Bandit-spawned request process.
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.AuditPlane.ReceiptSerializers
  alias Recurse.Gateway.AuditPlane.Resolvers.SigningKey, as: SigningKeyResolver
  alias Recurse.Gateway.AuditPlane.TenantGuard
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext

  require Logger

  @action "Recurse::Action::ReadReceipts"

  @valid_verification_levels ~w(signed local_inclusion_verified global_inclusion_verified)
  @valid_tier_completeness ~w(partial full)
  @valid_policy_decisions ~w(allow deny)

  # F004 T061 — canonical event_kind atoms accepted by the `event_kind`
  # filter param. Mirrors `Recurse.Shared.Attestation.SignedPredicate.@event_kinds`
  # but kept as a string allowlist here so we never `String.to_existing_atom/1`
  # untrusted client input on the request path. The Ecto `:event_kind`
  # column accepts only atoms in this set; the query layer stringifies on
  # the way down. See data-model.md §0 for the canonical matrix.
  @f004_event_kinds ~w(
    llm_call tool_call egress_denied policy_denied session_abort
    ui_login ui_session ui_query
    ui_policy_simulate ui_policy_replay
    ui_policy_draft_created ui_policy_draft_edited ui_policy_draft_archived ui_policy_draft_dry_run
    ui_policy_suggestion_generated ui_policy_suggestion_viewed ui_policy_suggestion_adopted
    ui_policy_suggestion_dismissed ui_policy_suggestion_refresh_requested
    ui_chat
    ui_chat_skill_invoked_query_receipts ui_chat_skill_invoked_fetch_receipt_detail
    ui_chat_skill_invoked_explain_denial ui_chat_skill_invoked_find_similar_receipts
    ui_chat_skill_invoked_simulate_policy_dryrun ui_chat_skill_invoked_suggest_policy_pattern
    ui_payload_access ui_evidence_export ui_retention_purge
    mcp_tool_call ui_mcp_quarantine
    policy_bundle_activated
    llm_call_attested tool_use_denied
  )

  @doc """
  Entry point. Returns a responded `Plug.Conn` after sending the response.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::AuditEndpoint",
      id: "v1_audit_receipts",
      attrs: %{"endpoint" => "/v1/audit/receipts"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_with_ctx, _ctx, _bundle_ref} -> do_handle(conn_with_ctx)
      error -> Authz.dispatch_gate_error(conn, error)
    end
  end

  @doc """
  F004 T074 — singular receipt-detail entry point. Routed from
  `GET /v1/audit/receipts/:run_id`. Reuses the same Cedar action
  (`ReadReceipts`) and JWT pipeline as `handle/1`, then renders the
  F004 detail-extension shape (`tier_completeness_advisory` at the
  top level + `payload_metadata` + `proof_envelope` + `matched_policy`
  with `line_range`). Emits the same `:ui_query` audit receipt as the
  list path.
  """
  @spec handle_detail(Plug.Conn.t()) :: Plug.Conn.t()
  def handle_detail(%Plug.Conn{path_params: %{"run_id" => run_id}} = conn)
      when is_binary(run_id) do
    resource = %{
      type: "Recurse::Resource::AuditEndpoint",
      id: "v1_audit_receipts_detail",
      attrs: %{"endpoint" => "/v1/audit/receipts/#{run_id}"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_with_ctx, ctx, _bundle_ref} ->
        do_detail(conn_with_ctx, ctx, run_id)

      error ->
        Authz.dispatch_gate_error(conn, error)
    end
  end

  def handle_detail(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "run_id path parameter is required")
  end

  defp do_handle(conn) do
    conn_with_params = Plug.Conn.fetch_query_params(conn)

    case parse_params(conn_with_params.query_params) do
      {:ok, params} ->
        # F004 T061 — additive F004 query-param parsing layered AFTER the
        # F002 parser. Returns either an augmented params map (with
        # `:f004_filters` + `:f004_facets?` keys ignored by F002's query
        # layer) or a 400 error. F002 query keys are unchanged by this
        # step so the F002 contract test suite is unaffected.
        case parse_f004_params(conn_with_params.query_params, params) do
          {:ok, augmented_params} -> run_query(conn_with_params, augmented_params)
          {:error, message} -> Authz.send_bad_request(conn_with_params, message)
        end

      {:error, message} ->
        Authz.send_bad_request(conn_with_params, message)
    end
  end

  defp run_query(conn, params) do
    # F004 T061 — split F004-only sentinel keys from the F002 query
    # surface. The `:event_kinds` filter is pushed down to SQL by the
    # ledger query layer (FR-009: `event_kind IN (...)` predicate);
    # the remaining `:tool_name` / `:structured_query` predicates stay
    # as in-memory post-filters (no DB columns + FR-010 forward-stub
    # AST evaluator).
    #
    # Pushing `event_kind` to SQL is the F16 demo-blocker fix
    # (2026-04-30): without it the LIMIT-50 page is dominated by the
    # high-volume `:ui_query` self-emission rows and `?event_kind=tool_call`
    # returns 0 rows even when `:tool_call` receipts exist. See
    # `Attestation` schema + `query_paginated/1` moduledoc.
    {f004_filters, f004_facets?, ledger_params} = build_ledger_params(params)

    case PostgresMerkleLedger.query_paginated(ledger_params) do
      {:ok, %{rows: rows, next_cursor: next_cursor}} ->
        # In-memory post-filter for the predicates that DON'T have a DB
        # column (`tool_name`) or are AST-shaped (`structured_query`).
        # `event_kind` is already gone from `f004_filters` here — the
        # ledger layer applied it as SQL `IN`.
        filtered_rows = apply_f004_filters(rows, f004_filters)

        body = render_response(filtered_rows, next_cursor, f004_facets?, ledger_params)

        emit_audit_log_query(conn, length(filtered_rows))

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, body)

      {:error, :invalid_cursor} ->
        Authz.send_bad_request(conn, "cursor is malformed or not from a prior response")

      {:error, reason} ->
        Logger.error(fn -> "receipts_handler query failed: #{inspect(reason)}" end)
        Authz.send_internal_error(conn, reason)
    end
  end

  # Split the augmented params map into:
  #   1. `f004_filters` (in-memory post-filter map: only the predicates
  #      that have NO SQL push-down — `tool_name`, `structured_query`).
  #   2. `f004_facets?` (boolean — switches the response shape).
  #   3. `ledger_params` (F002 keys + the SQL-push-down `:event_kinds`
  #      list). This is what `query_paginated/1` accepts.
  #
  # Promotes `:event_kinds` from the F004-only post-filter sentinels into
  # the canonical ledger-query surface so the LIMIT applies after the
  # filter (F16 fix). String-to-atom conversion is safe here: the parser
  # at `parse_event_kind_list/1` already restricted the strings to the
  # `@f004_event_kinds` allowlist, all of which are bound atoms in the
  # Attestation schema's `Ecto.Enum` — `String.to_existing_atom/1` will
  # always resolve successfully for validated inputs.
  defp build_ledger_params(params) do
    {f004_filters, f004_facets?, f002_params} = pop_f004_keys(params)
    {event_kinds_strings, post_filters} = Map.pop(f004_filters, :event_kinds)

    ledger_params =
      case event_kinds_strings do
        nil ->
          f002_params

        [] ->
          f002_params

        kinds when is_list(kinds) ->
          Map.put(f002_params, :event_kinds, to_event_kind_atoms(kinds))
      end

    {post_filters, f004_facets?, ledger_params}
  end

  defp to_event_kind_atoms(kinds) when is_list(kinds) do
    Enum.map(kinds, &String.to_existing_atom/1)
  end

  # F002-shape response when no `facets=true` flag is set; otherwise the
  # F004 faceted shape per FR-012. Wire-level discriminator is a top-level
  # `facets` key — its absence means "F002 client".
  defp render_response(rows, next_cursor, false, _ledger_params) do
    JSON.encode!(%{
      "receipts" => Enum.map(rows, &render_receipt/1),
      "cursor" => next_cursor
    })
  end

  defp render_response(rows, next_cursor, true, ledger_params) do
    JSON.encode!(%{
      "receipts" => Enum.map(rows, &render_receipt/1),
      "facets" => compute_facets(ledger_params),
      "cursor" => next_cursor
    })
  end

  # ---------------------------------------------------------------------------
  # Receipt rendering — F001 split-envelope shape
  # ---------------------------------------------------------------------------

  defp render_receipt(att) do
    %{
      "run_id" => att.run_id,
      "signed_predicate" => render_signed_predicate(att),
      "outer_container" => render_outer_container(att)
    }
  end

  defp render_signed_predicate(att), do: ReceiptSerializers.signed_predicate(att)

  defp render_outer_container(att), do: ReceiptSerializers.outer_container(att)

  # `to_string_or_nil`, `hex_or_nil` retained — still used by detail-only
  # renderers below (`render_payload_metadata`, `render_proof_envelope`,
  # `render_matched_policy`, the top-level `tier_completeness_advisory`
  # field in `render_detail`). `dt_or_nil` was only used by the inline
  # signed-predicate renderer above and has moved into ReceiptSerializers.
  defp to_string_or_nil(nil), do: nil
  defp to_string_or_nil(v) when is_atom(v), do: Atom.to_string(v)
  defp to_string_or_nil(v) when is_binary(v), do: v
  defp to_string_or_nil(v), do: to_string(v)

  defp hex_or_nil(nil), do: nil
  defp hex_or_nil(v) when is_binary(v), do: Base.encode16(v, case: :lower)

  # ---------------------------------------------------------------------------
  # Query-param parsing
  # ---------------------------------------------------------------------------

  defp parse_params(query_params) do
    with {:ok, limit} <- parse_limit(Map.get(query_params, "limit")),
         {:ok, verification_level} <-
           parse_enum(Map.get(query_params, "verification_level"), @valid_verification_levels,
             field: "verification_level"
           ),
         {:ok, tier_completeness_advisory} <-
           parse_enum(
             Map.get(query_params, "tier_completeness_advisory"),
             @valid_tier_completeness,
             field: "tier_completeness_advisory"
           ),
         {:ok, policy_decision} <-
           parse_enum(Map.get(query_params, "policy_decision"), @valid_policy_decisions,
             field: "policy_decision"
           ) do
      params =
        %{}
        |> maybe_put(:run_id, Map.get(query_params, "run_id"))
        |> maybe_put(:session_id, Map.get(query_params, "session_id"))
        |> maybe_put(:turn_id, Map.get(query_params, "turn_id"))
        |> maybe_put(:verification_level, verification_level)
        |> maybe_put(:tier_completeness_advisory, tier_completeness_advisory)
        |> maybe_put(:policy_decision, policy_decision)
        |> maybe_put(:limit, limit)
        |> maybe_put(:cursor, Map.get(query_params, "cursor"))

      {:ok, params}
    end
  end

  defp parse_limit(nil), do: {:ok, nil}

  defp parse_limit(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, ""} when n >= 1 -> {:ok, n}
      _ -> {:error, "limit must be a positive integer"}
    end
  end

  defp parse_enum(nil, _values, _opts), do: {:ok, nil}

  defp parse_enum(value, allowed, opts) when is_binary(value) do
    if value in allowed do
      {:ok, String.to_existing_atom(value)}
    else
      field = Keyword.fetch!(opts, :field)
      {:error, "#{field} must be one of #{Enum.join(allowed, ", ")}"}
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, ""), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  # ---------------------------------------------------------------------------
  # F004 T061 — additive query-param parsing + post-filter pipeline.
  # All F004-only logic is in functions BELOW this line; F002 surfaces
  # call into none of them. See moduledoc "F004 extension boundary".
  # ---------------------------------------------------------------------------

  defp parse_f004_params(query_params, f002_params) do
    with {:ok, event_kinds} <-
           parse_event_kind_list(Map.get(query_params, "event_kind")),
         {:ok, tool_name} <- parse_tool_name(Map.get(query_params, "tool_name")),
         {:ok, structured_query} <-
           parse_structured_query(Map.get(query_params, "q")),
         {:ok, facets?} <- parse_facets_flag(Map.get(query_params, "facets")) do
      f004_filters =
        %{}
        |> maybe_put(:event_kinds, event_kinds)
        |> maybe_put(:tool_name, tool_name)
        |> maybe_put(:structured_query, structured_query)

      augmented =
        f002_params
        |> Map.put(:f004_filters, f004_filters)
        |> Map.put(:f004_facets?, facets?)

      {:ok, augmented}
    end
  end

  defp parse_event_kind_list(nil), do: {:ok, nil}
  defp parse_event_kind_list(""), do: {:ok, nil}

  defp parse_event_kind_list(value) when is_binary(value) do
    kinds =
      value
      |> String.split(",", trim: true)
      |> Enum.map(&String.trim/1)

    case Enum.find(kinds, &(&1 not in @f004_event_kinds)) do
      nil -> {:ok, kinds}
      bad -> {:error, "event_kind contains unknown value: #{inspect(bad)}"}
    end
  end

  defp parse_tool_name(nil), do: {:ok, nil}
  defp parse_tool_name(""), do: {:ok, nil}
  defp parse_tool_name(value) when is_binary(value), do: {:ok, value}

  # Structured-query AST is base64-encoded JSON. F004 ships a strict-subset
  # evaluator: a single leaf (`%{"field" => f, "op" => "eq", "value" => v}`)
  # OR a single boolean op of two leaves (`%{"and" => [leaf, leaf]}` /
  # `%{"or" => [leaf, leaf]}` / `%{"not" => leaf}`). Anything more complex
  # returns 400 with a clear error pointing the caller at FR-010 evolution
  # in F005+. The forward-stub posture mirrors the project memory rule
  # "Don't build self-describing APIs prematurely" — concrete shapes
  # first, generalize when there's a real second consumer.
  defp parse_structured_query(nil), do: {:ok, nil}
  defp parse_structured_query(""), do: {:ok, nil}

  defp parse_structured_query(value) when is_binary(value) do
    with {:ok, json_bytes} <- safe_base64_decode(value),
         {:ok, ast} <- safe_json_decode(json_bytes),
         :ok <- validate_ast_shape(ast) do
      {:ok, ast}
    else
      _ -> {:error, "q must be base64-encoded JSON of a supported AST shape"}
    end
  end

  defp safe_base64_decode(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> Base.decode64(value)
    end
  end

  defp safe_json_decode(bytes) when is_binary(bytes) do
    case JSON.decode(bytes) do
      {:ok, decoded} -> {:ok, decoded}
      _ -> :error
    end
  end

  defp validate_ast_shape(%{"field" => f, "op" => op, "value" => _})
       when is_binary(f) and op in ["eq", "in"],
       do: :ok

  defp validate_ast_shape(%{"and" => [_l, _r]}), do: :ok
  defp validate_ast_shape(%{"or" => [_l, _r]}), do: :ok
  defp validate_ast_shape(%{"not" => _}), do: :ok
  defp validate_ast_shape(_), do: :error

  defp parse_facets_flag(nil), do: {:ok, false}
  defp parse_facets_flag("true"), do: {:ok, true}
  defp parse_facets_flag("1"), do: {:ok, true}
  defp parse_facets_flag("false"), do: {:ok, false}
  defp parse_facets_flag("0"), do: {:ok, false}
  defp parse_facets_flag(_), do: {:error, "facets must be 'true' or 'false'"}

  # Strip F004-only sentinel keys so PostgresMerkleLedger.query_paginated/1
  # never sees them (the F002 surface raises on unknown shape via Map
  # pattern; defensive cleanup here keeps that surface untouched).
  defp pop_f004_keys(params) do
    {f004_filters, params_1} = Map.pop(params, :f004_filters, %{})
    {f004_facets?, params_2} = Map.pop(params_1, :f004_facets?, false)
    {f004_filters, f004_facets?, params_2}
  end

  defp apply_f004_filters(rows, filters) when map_size(filters) == 0, do: rows

  defp apply_f004_filters(rows, filters) do
    # `:event_kinds` is NOT consulted here — `build_ledger_params/1`
    # promoted it onto the ledger query surface (SQL `event_kind IN (...)`
    # push-down per F16 fix). Any `:event_kind` predicate inside an
    # `:structured_query` AST leaf still evaluates in-memory (forward-stub
    # AST evaluator boundary; FR-010 evolves in F005+).
    Enum.filter(rows, fn row ->
      matches_tool_name?(row, Map.get(filters, :tool_name)) and
        matches_structured_query?(row, Map.get(filters, :structured_query))
    end)
  end

  defp matches_tool_name?(_row, nil), do: true

  defp matches_tool_name?(row, tool_name) when is_binary(tool_name) do
    # F004 receipts that DON'T carry a tool_name field never match a
    # tool_name filter. FR-010 evolution: when the audit-agent
    # `:ui_chat_skill_invoked_*` rows land tool_name as a top-level
    # signed_predicate field, this clause grows a Map.get-on-predicate
    # branch. Today, the row map exposes `event_kind` only.
    case row[:tool_name] do
      ^tool_name -> true
      _ -> false
    end
  end

  defp matches_structured_query?(_row, nil), do: true

  defp matches_structured_query?(row, ast) do
    eval_ast(row, ast)
  end

  defp eval_ast(row, %{"field" => f, "op" => "eq", "value" => v}) do
    field_value(row, f) == v
  end

  defp eval_ast(row, %{"field" => f, "op" => "in", "value" => values})
       when is_list(values) do
    field_value(row, f) in values
  end

  defp eval_ast(row, %{"and" => [l, r]}), do: eval_ast(row, l) and eval_ast(row, r)
  defp eval_ast(row, %{"or" => [l, r]}), do: eval_ast(row, l) or eval_ast(row, r)
  defp eval_ast(row, %{"not" => inner}), do: not eval_ast(row, inner)
  defp eval_ast(_row, _), do: false

  # Map AST `field` strings to attestation map keys. Atom values from
  # the Ecto enum are stringified for comparison so the AST author writes
  # JSON-friendly strings (`"deny"`) not Elixir atoms.
  defp field_value(row, "event_kind") do
    case row[:event_kind] do
      atom when is_atom(atom) -> Atom.to_string(atom)
      other -> other
    end
  end

  defp field_value(row, "policy_decision") do
    case row[:policy_decision] do
      atom when is_atom(atom) -> Atom.to_string(atom)
      other -> other
    end
  end

  defp field_value(row, "verification_level") do
    case row[:verification_level] do
      atom when is_atom(atom) -> Atom.to_string(atom)
      other -> other
    end
  end

  defp field_value(row, "tenant_id"), do: row[:tenant_id]
  defp field_value(row, "session_id"), do: row[:session_id]
  defp field_value(row, "principal_subject"), do: principal_subject_of(row)
  defp field_value(_row, _other), do: nil

  defp principal_subject_of(row) do
    case row[:principal] do
      %{"subject" => sub} -> sub
      %{"account_id" => id} -> id
      _ -> nil
    end
  end

  # ---------------------------------------------------------------------------
  # FR-012 facets — counts per (event_kind, policy_decision, verification_level)
  # over the FULL filtered result set, NOT the paginated page.
  #
  # Issue #44 (2026-04-30): the picker chip in the left rail relies on these
  # counts to (a) decide which kinds to render and (b) display the per-kind
  # row total. When facets were page-scoped, kinds outside the LIMIT-50
  # most-recent window had count 0 — the operator could not tell which kinds
  # exist in the universe and which they had filtered to zero. Same recency
  # trap shape as the F16 fix (MR !66) where SQL pushdown made the ROWS
  # complete; this is the same shape applied to the COUNTS.
  #
  # Implementation: a separate `query_facets/1` call against the same WHERE
  # predicates the paginated query uses (cursor + limit excluded). See
  # `PostgresMerkleLedger.query_facets/1` moduledoc for the rationale on
  # three single-axis `GROUP BY` queries vs one multi-dimensional aggregate.
  # ---------------------------------------------------------------------------

  defp compute_facets(ledger_params) do
    case PostgresMerkleLedger.query_facets(ledger_params) do
      {:ok, %{event_kind: ek, policy_decision: pd, verification_level: vl}} ->
        %{
          "event_kind" => ek,
          "policy_decision" => pd,
          "verification_level" => vl
        }
    end
  end

  # ---------------------------------------------------------------------------
  # `:ui_query` (`query_kind: "audit_log"`) emission per data-model.md §0.
  # Fire-and-forget through UiReceipts.emit/2; failures are logged at the
  # seam (T055a) and never raise to the caller per FR-031.
  # ---------------------------------------------------------------------------

  defp emit_audit_log_query(conn, row_count) do
    case Map.get(conn.assigns, :identity_ctx) do
      %IdentityContext{} = ctx ->
        UiReceipts.emit(:ui_query, %{
          query_kind: "audit_log",
          row_count: row_count,
          principal_subject: principal_subject_from_ctx(ctx),
          tenant_id: ctx.tenant_id,
          correlation_id: ctx.correlation_id
        })

      _ ->
        :ok
    end
  end

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}})
       when is_binary(sub),
       do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}})
       when is_binary(id),
       do: id

  defp principal_subject_from_ctx(_), do: nil

  # ---------------------------------------------------------------------------
  # F004 T074 — singular receipt-detail rendering pipeline.
  # ---------------------------------------------------------------------------

  defp do_detail(conn, ctx, run_id) do
    case Repo.get(Attestation, run_id) do
      nil ->
        Authz.send_not_found(conn, "no attestation for run_id #{run_id}")

      %Attestation{} = att ->
        case TenantGuard.validate(ctx, att) do
          :ok -> render_detail(conn, ctx, att)
          {:error, :tenant_mismatch} -> Authz.send_forbidden(conn, :tenant_mismatch)
        end
    end
  rescue
    Ecto.Query.CastError -> Authz.send_not_found(conn, "no attestation for run_id #{run_id}")
  end

  defp render_detail(conn, ctx, %Attestation{} = att) do
    body =
      JSON.encode!(%{
        "run_id" => att.run_id,
        # FR-017 — top-level so the SPA's amber callout reads it without
        # digging into outer_container. Discovery-tier Standalone is
        # always "partial".
        "tier_completeness_advisory" => to_string_or_nil(att.tier_completeness_advisory),
        "signed_predicate" => render_signed_predicate(Map.from_struct(att)),
        "outer_container" => render_outer_container(Map.from_struct(att)),
        "payload_metadata" => render_payload_metadata(att),
        "proof_envelope" => render_proof_envelope(att),
        "matched_policy" => render_matched_policy(att)
      })

    emit_audit_log_query_for_detail(ctx, att.run_id)

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(200, body)
  end

  # Full payload metadata per the F004 contract. `payload_bytes_size` is
  # `nil` when the StorageProvider hasn't recorded the size — Phase-1's
  # S3 + filesystem stubs don't pre-stamp size on commit so the SPA
  # treats `nil` as "fetch to know."
  defp render_payload_metadata(%Attestation{} = att) do
    %{
      "payload_uri" => att.payload_uri,
      "payload_hash" => hex_or_nil(att.payload_hash),
      "payload_bytes_size" => nil,
      # Spec 012 S6b — where the JCS predicate body behind `payload_hash`
      # was retained (predicate-only receipts); nil when not retained.
      "predicate_body_uri" => Map.get(att, :predicate_body_uri)
    }
  end

  # Pre-fetch the global Merkle siblings + signing-key PEM into the response
  # so the SPA's Verify Locally completes within SC-002's 3s budget without
  # an extra round-trip per check. The proof envelope mirrors what
  # `LocalVerifyHandler` consumes server-side; shipping the same bytes
  # client-side enables the SPA's progress UI to show "siblings loaded"
  # before the verify POST returns.
  defp render_proof_envelope(%Attestation{} = att) do
    %{
      "session_chain_root" => hex_or_nil(att.session_chain_root),
      "session_chain_epoch" => att.session_chain_epoch,
      "local_inclusion_proof_b64" => Base.encode64(att.local_inclusion_proof || <<>>),
      "global_inclusion_proof_b64" => Base.encode64(att.global_inclusion_proof || <<>>),
      "dsse_signature_b64" => Base.encode64(att.dsse_signature || <<>>),
      "signing_key_pem" => fetch_signing_key_pem(att),
      "verification_level" => to_string_or_nil(att.verification_level)
    }
  end

  # Decoration-only policy (per s4 finding): the detail/list views don't
  # fail-hard on archive miss — the SPA's Verify Locally button surfaces
  # the missing key as a verify-step failure. Wrap the resolver's
  # explicit `{:error, :not_found}` back into the historical nil return.
  defp fetch_signing_key_pem(%Attestation{
         signer_kms_key_id: kms_key_id,
         signer_key_version: key_version
       })
       when is_binary(kms_key_id) and is_binary(key_version) do
    case SigningKeyResolver.fetch_from_archive(kms_key_id, key_version) do
      {:ok, pem, :archive} -> pem
      {:error, :not_found} -> nil
    end
  end

  defp fetch_signing_key_pem(_att), do: nil

  # Matched-policy line range — `nil` until F005+ ships Cedar source-line
  # resolution (the parser doesn't expose per-policy spans through Rust
  # NIF yet). The field is reserved per the contract so SPA TypeScript
  # types stay forward-stable.
  defp render_matched_policy(%Attestation{} = att) do
    %{
      "policy_canonical_hash" => hex_or_nil(att.policy_canonical_hash),
      "matched_policy_id" => nil,
      "line_range" => nil
    }
  end

  defp emit_audit_log_query_for_detail(%IdentityContext{} = ctx, run_id) do
    UiReceipts.emit(:ui_query, %{
      query_kind: "audit_log",
      query_target: "receipt_detail",
      run_id: run_id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end
end
