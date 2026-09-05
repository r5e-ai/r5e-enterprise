defmodule Recurse.Gateway.Fold.Submitter do
  @moduledoc """
  Gateway Kind spec builders and admitted policy activation.

  The live proxy uses `Recurse.Gateway.Fold.Admission`: request admission
  precedes sending model bytes, tool admission precedes releasing executable
  bytes, and completion links to those actual receipts. Kernel evidence
  retention is mandatory and independent of the legacy audit ledger.

  This module supplies the pure spec builders used by that boundary.
  `submit_bundle/1` admits source bytes and the active PolicyBundle before
  a loader publishes its local projection. Kernel-owned policy governs
  management operations; workload policy governs model and tool admissions.

  `submit_call/2` is the historical after-the-fact importer, retained for
  compatibility tests. The live attestation emitter does not call it. Its
  counters and optional-build checks describe that importer, not readiness
  or enforcement on the governed proxy path.

  Specs are float-free: timestamps are strings, durations and token counts
  are integers. Gateway-observed client claims remain distinct from the
  fold key that signs each admission.
  """

  alias Recurse.Gateway.Policy.Active
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  require Logger

  @group "gateway.r5e.io"
  @version "v1alpha1"

  @fold Module.concat([Recurse, Fold])
  @fold_app Module.concat([Recurse, Fold, Application])
  @resource_store Module.concat([R5e, ResourceStore])
  @ref_index Module.concat([R5e, RefIndex])
  @canonical Module.concat([R5e, Canonical])

  # :counters slots (see `stats/0`).
  @c_calls 1
  @c_admitted 2
  @c_denied 3
  @c_refused 4
  @c_mismatches 5
  @c_no_bytes 6
  @c_errors 7
  @counter_size 7

  @counters_key {__MODULE__, :counters}
  @bundle_key {__MODULE__, :active_bundle_object}

  @typedoc "What `submit_call/2` put on the chain for one call."
  @type summary :: %{
          session: String.t() | nil,
          prompt: String.t() | nil,
          llm_call: String.t() | nil,
          tool_calls: [{ToolUseIntent.t(), :allow | :deny | :error, :allow | :deny, String.t()}],
          completion: String.t() | nil,
          response: String.t() | nil,
          mismatches: non_neg_integer()
        }

  # ---------------------------------------------------------------------------
  # Availability
  # ---------------------------------------------------------------------------

  @doc """
  True when the fold module is loaded in this build. Says nothing about
  whether it is enabled: a loaded, disabled fold refuses every act, and
  the refusal is the honest answer (`last_refusal` on `/readyz`), so the
  submitter calls it rather than deciding for it.
  """
  @spec available?() :: boolean()
  def available? do
    Code.ensure_loaded?(@fold) and function_exported?(@fold, :admit, 3) and
      function_exported?(@fold, :put_cas, 2)
  end

  @doc "True when the fold is loaded and switched on (`R5E_FOLD_ENABLED`)."
  @spec enabled?() :: boolean()
  def enabled? do
    available?() and Code.ensure_loaded?(@fold_app) and
      function_exported?(@fold_app, :enabled?, 0) and apply(@fold_app, :enabled?, []) == true
  end

  # Availability guard for the historical submit_call importer. The released
  # gateway depends on the fold application; live policy activation must be
  # admitted before the loader publishes its projection.
  defp kernel_running?, do: Process.whereis(R5e.Supervisor) != nil

  # ---------------------------------------------------------------------------
  # Pure spec builders — one per Kind, unit-tested against the Kind schemas
  # ---------------------------------------------------------------------------

  @doc """
  `AgentSession` — a span of work named by the client's own session id.
  `server`-named by the kernel; the client id lives in `sourceIds.session`.
  """
  @spec spec_for_agent_session(map()) :: map()
  def spec_for_agent_session(call_state) do
    compact(%{
      "harness" => harness(call_state),
      "startedAt" => iso(Map.get(call_state, :started_at)),
      "sourceIds" => optional(%{"session" => nonempty(Map.get(call_state, :client_session_id))})
    })
  end

  @doc "`Prompt` — the request bytes at `content_ref`, as sent to the proxy."
  @spec spec_for_prompt(map(), String.t(), String.t() | nil) :: map()
  def spec_for_prompt(call_state, content_ref, session_ref \\ nil) do
    compact(%{
      "contentRef" => %{"$ref" => content_ref},
      "mediaType" => "application/json",
      "session" => kind_ref(session_ref),
      "observedAt" => iso(Map.get(call_state, :started_at))
    })
  end

  @doc """
  `LlmCall` — model, prompt and the call's coordinates. `sourceIds.run`
  carries the caller-supplied run/trace identifier (the opening trace ID on
  the live proxy; a legacy receipt ID in the importer). The live aggregate
  links back to admission through its receipt references. `sourceIds.session`
  is the client's observed session id.
  Only the fields the Kind schema admits (`additionalProperties: false`):
  the gateway-side facts with no slot here (`principal_source`,
  `upstream_org_id`, `parser`, `parse`, the request kind) stay on the
  enterprise predicate, where they are.
  """
  @spec spec_for_llm_call(map(), String.t(), String.t() | nil, String.t() | nil) :: map()
  def spec_for_llm_call(call_state, prompt_name, session_ref, run_id) do
    compact(%{
      "model" => nonempty(Map.get(call_state, :model)) || "unknown",
      "prompt" => %{"$ref" => "#{@group}/#{@version}/Prompt/#{prompt_name}"},
      "provider" => nonempty(Map.get(call_state, :provider)),
      "upstreamHost" => nonempty(Map.get(call_state, :upstream_host)),
      "transport" => transport(Map.get(call_state, :transport)),
      "apiFormat" => api_format(Map.get(call_state, :api_format)),
      "requestPath" => nonempty(Map.get(call_state, :request_path)),
      "session" => kind_ref(session_ref),
      "sourceIds" =>
        optional(%{
          "session" => nonempty(Map.get(call_state, :client_session_id)),
          "run" => nonempty(run_id)
        }),
      "startedAt" => iso(Map.get(call_state, :started_at))
    })
  end

  @doc """
  `ToolCall` — one per intent, allowed or denied by the gateway alike.
  The arguments are inlined when the parser decoded them (the same map
  the enterprise mirror row keeps in `tool_args_inlined`), so the fold's
  own policy can read `context.tool_args` and decide for itself. When
  the parser kept only a hash (`:too_large`), `args` carries that hash
  and size under names that say what they are — the Kind requires one of
  `args` / `argsRef`, and an `argsRef` must be backed by bytes nobody
  retained. `index` is the intent's position in the model's order.
  """
  @spec spec_for_tool_call(
          ToolUseIntent.t(),
          String.t() | nil,
          non_neg_integer(),
          String.t() | nil
        ) ::
          map()
  def spec_for_tool_call(%ToolUseIntent{} = intent, llm_call_ref, index, session_ref \\ nil) do
    compact(%{
      "tool" => intent.tool_name,
      "args" => args(intent),
      "llmCall" => event_ref(llm_call_ref),
      "index" => index,
      "callId" => nonempty(intent.call_id),
      "session" => kind_ref(session_ref),
      "extractedAt" => iso(intent.extracted_at)
    })
  end

  @doc "`Completion` — the response bytes at `content_ref`, with the upstream's content type."
  @spec spec_for_completion(map(), String.t()) :: map()
  def spec_for_completion(call_state, content_ref) do
    compact(%{
      "contentRef" => %{"$ref" => content_ref},
      "mediaType" => response_media_type(call_state),
      "observedAt" => iso(Map.get(call_state, :completed_at))
    })
  end

  @doc """
  `LlmResponse` — how the call ended, binding the `LlmCall`, the
  `Completion` (required on `outcome: "ok"`) and every `ToolCall` in
  order. `usage`/`latency` are integers; `upstreamStatus` only when it is
  an HTTP status (a connection failure records 0 on the ledger and
  nothing here).
  """
  @spec spec_for_llm_response(map(), String.t(), String.t() | nil, [String.t()]) :: map()
  def spec_for_llm_response(call_state, llm_call_ref, completion_name, tool_call_refs) do
    error_kind = Map.get(call_state, :error_kind)

    compact(%{
      "llmCall" => %{"$ref" => llm_call_ref},
      "outcome" => if(is_nil(error_kind), do: "ok", else: "error"),
      "toolCalls" => Enum.map(tool_call_refs, &%{"$ref" => &1}),
      "completion" =>
        completion_name && %{"$ref" => "#{@group}/#{@version}/Completion/#{completion_name}"},
      "upstreamStatus" => http_status(Map.get(call_state, :upstream_status_code)),
      "errorKind" => error_kind,
      # B3 (RC review 2026-09-05): the gateway read the whole response and
      # released none of it, because nothing in it could be classified.
      # Recorded rather than inferred: `errorKind` says the parser failed
      # and `upstreamStatus` says what the upstream answered, but neither
      # says whether the client got the bytes.
      "responseWithheld" => if(Map.get(call_state, :response_withheld?), do: true),
      "usage" =>
        optional(%{
          "inputTokens" => non_neg(Map.get(call_state, :prompt_token_count)),
          "outputTokens" => non_neg(Map.get(call_state, :completion_token_count)),
          "reasoningTokens" => non_neg(Map.get(call_state, :reasoning_token_count))
        }),
      "latency" =>
        optional(%{
          "upstreamMs" => non_neg(Map.get(call_state, :latency_ms)),
          "addedMs" => non_neg(Map.get(call_state, :added_latency_ms))
        }),
      "completedAt" => iso(Map.get(call_state, :completed_at))
    })
  end

  # ---------------------------------------------------------------------------
  # Effects — the dual-write
  # ---------------------------------------------------------------------------

  @doc """
  Submit one finalized call to the fold. Called by the emitter after the
  ledger receipt and the audit rows are committed. Returns
  `{:ok, summary}`, `:skipped` (no fold in this build), or
  `{:refused, reason}` — never raises, never fails the caller.
  """
  @spec submit_call(map(), String.t() | nil) ::
          {:ok, summary()} | :skipped | {:refused, String.t()}
  def submit_call(call_state, run_id) when is_map(call_state) do
    if available?() do
      bump(@c_calls)
      do_submit_call(call_state, run_id)
    else
      :skipped
    end
  rescue
    error ->
      bump(@c_errors)

      Logger.error(fn ->
        "fold submitter: raised while submitting run_id=#{inspect(run_id)}: #{Exception.message(error)}"
      end)

      {:refused, "submitter raised: " <> Exception.message(error)}
  catch
    :exit, reason ->
      bump(@c_errors)
      Logger.error(fn -> "fold submitter: exit while submitting: #{inspect(reason)}" end)
      {:refused, "submitter exited: " <> inspect(reason)}
  end

  defp do_submit_call(call_state, run_id) do
    ensure_active_bundle()

    with {:ok, session_ref} <- session(call_state),
         {:ok, prompt_name} <- prompt(call_state, session_ref),
         {:ok, llm_call_ref} <- llm_call(call_state, prompt_name, session_ref, run_id),
         {:ok, tool_calls} <- tool_calls(call_state, llm_call_ref, session_ref),
         {:ok, completion_name} <- completion(call_state),
         {:ok, response_ref} <-
           llm_response(call_state, llm_call_ref, completion_name, tool_calls) do
      mismatches = Enum.count(tool_calls, fn {_intent, gw, fold, _ref} -> mismatch?(gw, fold) end)

      {:ok,
       %{
         session: session_ref,
         prompt: prompt_name,
         llm_call: llm_call_ref,
         tool_calls: tool_calls,
         completion: completion_name,
         response: response_ref,
         mismatches: mismatches
       }}
    else
      {:refused, reason} ->
        bump(@c_refused)

        Logger.warning(fn ->
          "fold submitter: refused for run_id=#{inspect(run_id)} — nothing recorded on the " <>
            "chain for the rest of this call; the ledger receipt stands: #{reason}"
        end)

        {:refused, reason}
    end
  end

  # -- AgentSession ------------------------------------------------------

  # One per first-seen client session id, remembered in `:persistent_term`
  # for the life of the node and looked up on the chain after a restart —
  # the Kind is `server`-named, so "already exists" is a question the
  # resource store answers by `sourceIds.session`, not a collision.
  defp session(call_state) do
    case nonempty(Map.get(call_state, :client_session_id)) do
      nil ->
        {:ok, nil}

      id ->
        cached_session(call_state, id)
    end
  end

  defp cached_session(call_state, id) do
    key = {__MODULE__, :session, id}

    case :persistent_term.get(key, nil) do
      ref when is_binary(ref) ->
        {:ok, ref}

      nil ->
        with {:ok, ref} <- find_or_admit_session(call_state, id) do
          :persistent_term.put(key, ref)
          {:ok, ref}
        end
    end
  end

  defp find_or_admit_session(call_state, id) do
    case find_session(id) do
      {:ok, ref} ->
        {:ok, ref}

      :none ->
        admit_session(call_state, id)
    end
  end

  defp admit_session(call_state, id) do
    case admit("AgentSession", spec_for_agent_session(call_state)) do
      {:ok, receipt} ->
        {:ok, "#{@group}/#{@version}/AgentSession/#{receipt["name"]}"}

      {:denied, receipt} ->
        Logger.warning(fn ->
          "fold submitter: AgentSession for client session #{redact(id)} denied by the " <>
            "fold's policy (#{receipt["reason"]}); acts will not cite a session"
        end)

        {:ok, nil}

      {:refused, _} = refused ->
        refused
    end
  end

  # After a restart the `:persistent_term` cache is empty; the chain is
  # not. Reads the resource store by name (kernel API, no compile-time
  # dep) — a linear scan over AgentSessions, once per first-seen id per
  # boot.
  defp find_session(id) do
    if Code.ensure_loaded?(@resource_store) and function_exported?(@resource_store, :list, 3) do
      @resource_store
      |> apply(:list, [@group, @version, "AgentSession"])
      |> Enum.find(fn entry -> get_in(entry, ["spec", "sourceIds", "session"]) == id end)
      |> case do
        %{"name" => name} when is_binary(name) ->
          {:ok, "#{@group}/#{@version}/AgentSession/#{name}"}

        _ ->
          :none
      end
    else
      :none
    end
  catch
    :exit, _ -> :none
  end

  # -- Prompt (bytes + artifact) -----------------------------------------

  defp prompt(call_state, session_ref) do
    case retained(Map.get(call_state, :request_payload), Map.get(call_state, :prompt_hash)) do
      {:ok, bytes} ->
        case put(bytes, "application/json") do
          {:ok, address} ->
            admit_optional("Prompt", spec_for_prompt(call_state, address, session_ref))

          {:denied, receipt} ->
            denied_optional("CasObject (request bytes)", receipt)

          {:refused, _} = refused ->
            refused
        end

      :none ->
        bump(@c_no_bytes)

        Logger.info(fn ->
          "fold submitter: request bytes not retained (R5E_RETAIN_PAYLOADS); no Prompt, so no " <>
            "LlmCall/LlmResponse for this call — its ToolCalls and session are still recorded"
        end)

        {:ok, nil}
    end
  end

  # -- LlmCall -------------------------------------------------------------

  defp llm_call(_call_state, nil, _session_ref, _run_id), do: {:ok, nil}

  defp llm_call(call_state, prompt_name, session_ref, run_id) do
    case admit("LlmCall", spec_for_llm_call(call_state, prompt_name, session_ref, run_id)) do
      {:ok, receipt} -> {:ok, receipt["eventRef"]}
      {:denied, receipt} -> denied_optional("LlmCall", receipt)
      {:refused, _} = refused -> refused
    end
  end

  # -- ToolCall × N ----------------------------------------------------------

  # Every intent, in the model's order, denied or not. The gateway's
  # decision and the fold's are compared per intent; the pair is logged
  # when they differ and counted on /readyz.
  defp tool_calls(call_state, llm_call_ref, session_ref) do
    call_state
    |> Map.get(:intents, [])
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, []}, fn {{%ToolUseIntent{} = intent, decision}, index},
                                       {:ok, acc} ->
      spec = spec_for_tool_call(intent, llm_call_ref, index, session_ref)
      gateway = gateway_decision(decision)

      case admit("ToolCall", spec) do
        {:ok, receipt} ->
          record_pair(intent, gateway, :allow, decision, receipt)
          {:cont, {:ok, [{intent, gateway, :allow, receipt["eventRef"]} | acc]}}

        {:denied, receipt} ->
          record_pair(intent, gateway, :deny, decision, receipt)
          {:cont, {:ok, [{intent, gateway, :deny, receipt["eventRef"]} | acc]}}

        {:refused, _} = refused ->
          {:halt, refused}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      other -> other
    end
  end

  defp record_pair(intent, gateway, fold, decision, receipt) do
    if fold == :deny, do: bump(@c_denied), else: bump(@c_admitted)

    if mismatch?(gateway, fold) do
      bump(@c_mismatches)

      Logger.warning(fn ->
        "fold decision mismatch: tool=#{inspect(intent.tool_name)} call_id=#{inspect(intent.call_id)} " <>
          "gateway=#{gateway}#{gateway_rule(decision)} fold=#{fold} " <>
          "fold_bundle=#{inspect(get_in(receipt, ["policy", "bundle"]))} " <>
          "fold_matched=#{inspect(get_in(receipt, ["policy", "matched"]))} " <>
          "fold_event=#{receipt["eventRef"]} — both decisions are recorded (the gateway's on " <>
          "the ledger receipt, the fold's on the kernel receipt); the two bundles differ"
      end)
    end
  end

  defp gateway_rule({:deny, %{rule_id: rule}}), do: "(rule #{rule})"
  defp gateway_rule({:error, reason}), do: "(#{inspect(reason)})"
  defp gateway_rule(_), do: ""

  @doc "The gateway gate decision as one of `:allow | :deny | :error`."
  @spec gateway_decision(term()) :: :allow | :deny | :error
  def gateway_decision({:allow}), do: :allow
  def gateway_decision({:deny, _}), do: :deny
  def gateway_decision(_), do: :error

  @doc """
  True when the gateway's decision and the fold's outcome disagree: the
  gateway let it through and the fold denied it, or the gateway
  suppressed it (deny or fail-closed error) and the fold admitted it.
  """
  @spec mismatch?(:allow | :deny | :error, :allow | :deny) :: boolean()
  def mismatch?(:allow, :allow), do: false
  def mismatch?(:allow, :deny), do: true
  def mismatch?(_suppressed, :allow), do: true
  def mismatch?(_suppressed, :deny), do: false

  # -- Completion (bytes + artifact) -------------------------------------

  defp completion(call_state) do
    case retained(Map.get(call_state, :response_payload), Map.get(call_state, :response_hash)) do
      {:ok, bytes} ->
        case put(bytes, response_media_type(call_state)) do
          {:ok, address} ->
            admit_optional("Completion", spec_for_completion(call_state, address))

          {:denied, receipt} ->
            denied_optional("CasObject (response bytes)", receipt)

          {:refused, _} = refused ->
            refused
        end

      :none ->
        {:ok, nil}
    end
  end

  defp admit_optional(kind, spec) do
    case admit(kind, spec) do
      {:ok, receipt} -> {:ok, receipt["name"]}
      {:denied, receipt} -> denied_optional(kind, receipt)
      {:refused, _} = refused -> refused
    end
  end

  # -- LlmResponse -------------------------------------------------------

  defp llm_response(_call_state, nil, _completion, _tool_calls), do: {:ok, nil}

  defp llm_response(call_state, llm_call_ref, completion_name, tool_calls) do
    refs = Enum.map(tool_calls, fn {_intent, _gateway, _fold, ref} -> ref end)
    spec = spec_for_llm_response(call_state, llm_call_ref, completion_name, refs)

    if spec["outcome"] == "ok" and is_nil(completion_name) do
      # The Kind requires a Completion on `ok`, and there are no bytes to
      # make one from. Say so rather than record an outcome the schema
      # would reject or a Completion nobody retained.
      Logger.info(fn ->
        "fold submitter: response bytes not retained; LlmResponse (outcome ok) needs a " <>
          "Completion and is not recorded for #{llm_call_ref}"
      end)

      {:ok, nil}
    else
      case admit("LlmResponse", spec) do
        {:ok, receipt} -> {:ok, receipt["eventRef"]}
        {:denied, receipt} -> denied_optional("LlmResponse", receipt)
        {:refused, _} = refused -> refused
      end
    end
  end

  # -- the gateway's bundle ------------------------------------------------

  @doc """
  Activate a just-loaded gateway bundle in the fold: put its bytes on the
  record as a `CasObject`, then re-admit `PolicyBundle/active` citing that
  object, so the chain says which bundle governed from that seq on.

  Both halves are idempotent. The bytes are put once per address; the
  re-admission is skipped while `PolicyBundle/active` already cites this
  address, so polling the same file every five seconds is not a
  supersession every five seconds. Refusal prevents the loader activation.

  Returns `{:ok, address}` when the bundle governs the fold — whether this
  call activated it or found it already active.
  """
  @spec submit_bundle(Active.t()) ::
          {:ok, String.t()} | {:denied, map()} | {:refused, String.t()}
  def submit_bundle(%Active{bundle: %{bundle_bytes: bytes, bundle_id: hex}} = active)
      when is_binary(bytes) do
    cond do
      not available?() ->
        {:refused, "required fold module is unavailable"}

      not enabled?() or not kernel_running?() ->
        # A disabled or not-yet-booted fold would refuse and note it as
        # `last_refusal`; a bundle activation is not a call and should not
        # leave that mark. The first call catches up (`ensure_active_bundle/0`).
        {:refused, "required kernel admission is unavailable"}

      true ->
        address = "bytes:" <> apply(@canonical, :hash_bytes, [bytes])

        result =
          with {:ok, addr} <- bundle_object(address, bytes),
               {:ok, activation} <- activate_bundle(addr, hex, active) do
            {:ok, addr, activation}
          end

        record_bundle_result(result, hex, active)
    end
  rescue
    error ->
      bump(@c_errors)
      Logger.error(fn -> "fold submitter: bundle submit raised: #{Exception.message(error)}" end)
      {:refused, "submitter raised: " <> Exception.message(error)}
  catch
    :exit, reason ->
      bump(@c_errors)
      {:refused, "submitter exited: " <> inspect(reason)}
  end

  def submit_bundle(_), do: {:refused, "invalid policy bundle"}

  @doc """
  Activate the currently loaded gateway bundle in the fold if this node has
  not done so yet. One `:persistent_term` read per call when nothing is to do.

  **Defensive code that should never fire.** It exists for the boot-order
  race S9b hit: the gateway's `BundleLoader` activates at its own
  application start, and if `recurse_gateway` starts before `recurse_fold`
  there is no kernel yet to write to. `mix.exs` lists `recurse_fold`
  before `recurse_gateway` in the `audit_console` release's `applications`
  (the fold does not depend on the gateway, so the order is free) —
  plan §20 correction 3 — so the boot activation lands and the first call
  finds nothing to do. Kept because the order is a release-assembly fact
  that a future edit could silently reverse, and because a bundle
  activated while the kernel is restarting would otherwise never reach the
  chain. If `/readyz` ever shows `active_bundle_object` appearing only
  after the first call, that order has been broken.
  """
  @spec ensure_active_bundle() :: :ok
  def ensure_active_bundle do
    with {:ok, %Active{bundle: %{bundle_id: hex}} = active} <- Active.current(),
         false <- match?(%{"canonical_hash" => ^hex}, :persistent_term.get(@bundle_key, nil)) do
      _ = submit_bundle(active)
      :ok
    else
      _ -> :ok
    end
  end

  # The bytes, put once per address. `{:ok, address}` either way.
  defp bundle_object(address, bytes) do
    if object_on_record?(address) do
      {:ok, address}
    else
      case put(bytes, "text/plain") do
        {:ok, addr} -> {:ok, addr}
        other -> other
      end
    end
  end

  # The activation itself: `PolicyBundle/active` citing those bytes.
  # Skipped while the admitted bundle already cites this address — a
  # re-admission of identical bytes is a supersession, not a no-op, and
  # the bundle loader polls the file every five seconds.
  defp activate_bundle(address, hex, active) do
    case admitted_bundle_identity() do
      {^address, scope} when is_list(scope) ->
        if Enum.sort(scope) == Enum.sort(Recurse.Fold.Policy.Cedar.governed_kinds()) do
          {:ok, :already_active}
        else
          admit_bundle(address, hex, active)
        end

      _ ->
        admit_bundle(address, hex, active)
    end
  end

  defp admit_bundle(address, hex, active) do
    case admit("PolicyBundle", bundle_spec(address, hex, active), name: "active") do
      {:ok, receipt} -> {:ok, receipt["eventRef"]}
      other -> other
    end
  end

  # `sourceRef` of the admitted `PolicyBundle/active`, or `nil`.
  defp admitted_bundle_identity do
    if Code.ensure_loaded?(@resource_store) and function_exported?(@resource_store, :get, 4) do
      case apply(@resource_store, :get, [@group, @version, "PolicyBundle", "active"]) do
        {:ok, entry, _lineage} ->
          {get_in(entry, ["spec", "sourceRef", "$ref"]), get_in(entry, ["spec", "governs"])}

        _ ->
          nil
      end
    end
  catch
    :exit, _ -> nil
  end

  # Float-free, and stable across activations of the same bytes: no
  # timestamp, no counter. `description` is the operator-facing sentence
  # the fold's own default bundle also carries.
  defp bundle_spec(address, hex, %Active{} = active) do
    compact(%{
      "engine" => "cedar",
      "governs" => Recurse.Fold.Policy.Cedar.governed_kinds(),
      "sourceRef" => %{"$ref" => address},
      "description" =>
        "The r5e-enterprise gateway's active Cedar bundle, loaded from #{active.source} " <>
          "(#{nonempty(active.source_ref) || "no source ref"}) and activated in the fold by " <>
          "required admission path before gateway activation. Cedar canonical hash #{hex}; " <>
          "the CasObject's address is the " <>
          "SHA-256 of the same bytes."
    })
  end

  # Counters, log line and the `/readyz` surface, for either half's outcome.
  defp record_bundle_result({:ok, addr, activation}, hex, active) do
    :persistent_term.put(@bundle_key, %{
      "canonical_hash" => hex,
      "object" => addr,
      "activation" => activation_ref(activation)
    })

    Logger.info(fn ->
      "fold submitter: gateway policy bundle canonical_hash=#{hex} (#{active.source}) " <>
        "is on the record as #{addr} and #{activation_note(activation)} — the CasObject's " <>
        "address is the SHA-256 of the bytes; the canonical hash re-derives from them with " <>
        "Recurse.Cedar.canonical_hash/1"
    end)

    {:ok, addr}
  end

  defp record_bundle_result({:denied, receipt}, hex, _active) do
    bump(@c_denied)

    Logger.warning(fn ->
      "fold submitter: activating the gateway bundle #{hex} in the fold was denied: " <>
        inspect(receipt["reason"])
    end)

    {:denied, receipt}
  end

  defp record_bundle_result({:refused, reason}, hex, _active) do
    bump(@c_refused)
    Logger.warning(fn -> "fold submitter: gateway bundle #{hex} not activated: #{reason}" end)
    {:refused, reason}
  end

  defp activation_ref(:already_active), do: admitted_bundle_activation()
  defp activation_ref(ref) when is_binary(ref), do: ref
  defp activation_ref(_), do: nil

  defp activation_note(:already_active),
    do: "was already the fold's PolicyBundle/active"

  defp activation_note(ref) when is_binary(ref),
    do: "is the fold's PolicyBundle/active from #{ref} on"

  defp activation_note(_), do: "is the fold's PolicyBundle/active"

  # The admission event of the `PolicyBundle/active` in force, for the
  # readiness surface when this node found the bundle already active.
  defp admitted_bundle_activation do
    if Code.ensure_loaded?(@resource_store) and function_exported?(@resource_store, :get, 4) do
      case apply(@resource_store, :get, [@group, @version, "PolicyBundle", "active"]) do
        {:ok, entry, _lineage} -> entry["admissionEvent"]
        _ -> nil
      end
    end
  catch
    :exit, _ -> nil
  end

  defp object_on_record?(address) do
    Code.ensure_loaded?(@ref_index) and function_exported?(@ref_index, :cas_object, 1) and
      match?({:ok, _}, apply(@ref_index, :cas_object, [address]))
  catch
    :exit, _ -> false
  end

  # ---------------------------------------------------------------------------
  # Readiness surface
  # ---------------------------------------------------------------------------

  @doc """
  Counters since boot, merged into the `/readyz` `fold` block:

    * `calls_submitted` — finalized calls handed to the fold;
    * `acts_admitted` / `acts_denied` — `ToolCall` outcomes on the chain
      (a denial is a receipt);
    * `refusals` — `{:refused, _}` returns (the reason is `last_refusal`);
    * `decision_mismatches` — intents where the gateway and the fold
      disagreed;
    * `calls_without_bytes` — calls with no retained request bytes, so no
      `LlmCall` on the chain;
    * `submitter_errors` — exceptions rescued here;
    * `active_bundle_object` — the CAS address of the active gateway
      bundle's bytes, its canonical hash, and the `event:` ref of the
      `PolicyBundle/active` admission that made those bytes govern the
      fold, or `nil` when no activation has reached the chain.
  """
  @spec stats() :: map()
  def stats do
    c = counters()

    %{
      "calls_submitted" => :counters.get(c, @c_calls),
      "acts_admitted" => :counters.get(c, @c_admitted),
      "acts_denied" => :counters.get(c, @c_denied),
      "refusals" => :counters.get(c, @c_refused),
      "decision_mismatches" => :counters.get(c, @c_mismatches),
      "calls_without_bytes" => :counters.get(c, @c_no_bytes),
      "submitter_errors" => :counters.get(c, @c_errors),
      "active_bundle_object" => :persistent_term.get(@bundle_key, nil)
    }
  end

  @doc "Zero the counters and forget cached sessions/bundle. Tests only."
  @spec reset() :: :ok
  def reset do
    c = counters()
    for i <- 1..@counter_size, do: :counters.put(c, i, 0)
    _ = :persistent_term.erase(@bundle_key)

    for {key, _} <- :persistent_term.get(),
        match?({__MODULE__, :session, _}, key),
        do: :persistent_term.erase(key)

    :ok
  end

  defp counters do
    case :persistent_term.get(@counters_key, nil) do
      nil ->
        c = :counters.new(@counter_size, [:write_concurrency])
        :persistent_term.put(@counters_key, c)
        c

      c ->
        c
    end
  end

  defp bump(slot), do: :counters.add(counters(), slot, 1)

  # ---------------------------------------------------------------------------
  # The two fold calls, by name
  # ---------------------------------------------------------------------------

  defp admit(kind, spec, opts \\ []),
    do: apply(@fold, :admit, ["#{@group}/#{@version}/#{kind}", spec, opts])

  defp put(bytes, media_type) do
    case apply(@fold, :put_cas, [bytes, [media_type: media_type]]) do
      {:ok, _receipt, address} -> {:ok, address}
      {:denied, _receipt} = denied -> denied
      {:refused, _} = refused -> refused
    end
  end

  # A denied artifact/event that later acts would cite: log it (the
  # receipt is on the chain) and carry on without the reference.
  defp denied_optional(kind, receipt) do
    bump(@c_denied)

    Logger.warning(fn ->
      "fold submitter: #{kind} denied by the fold's policy (#{inspect(receipt["reason"])}); " <>
        "recorded as a denial at #{receipt["eventRef"]}, not cited by later acts"
    end)

    {:ok, nil}
  end

  # ---------------------------------------------------------------------------
  # Field helpers
  # ---------------------------------------------------------------------------

  # Bytes the emitter captured and that hash to what the predicate says
  # they are; anything else is not evidence of this call.
  defp retained({:ok, bytes}, expected) when is_binary(bytes) and is_binary(expected) do
    if :crypto.hash(:sha256, bytes) == expected, do: {:ok, bytes}, else: :none
  end

  defp retained(_, _), do: :none

  defp args(%ToolUseIntent{tool_args: args}) when is_map(args), do: args

  defp args(%ToolUseIntent{tool_args_hash: hash, tool_args_size_bytes: size}) do
    compact(%{
      "argsHash" => hash && "sha256:" <> Base.encode16(hash, case: :lower),
      "argsSizeBytes" => non_neg(size),
      "argsOmitted" => true
    })
  end

  defp harness(call_state) do
    case Map.get(call_state, :principal_id) do
      "claude-code:" <> _ -> "claude-code"
      _ -> nil
    end
  end

  defp transport(:https_sse), do: "https-sse"
  defp transport(:wss), do: "wss"
  defp transport(:https), do: "https"
  defp transport("https-sse"), do: "https-sse"
  defp transport("wss"), do: "wss"
  defp transport("https"), do: "https"
  defp transport(_), do: nil

  defp api_format(nil), do: nil
  defp api_format(f) when is_atom(f), do: Atom.to_string(f)
  defp api_format(f) when is_binary(f), do: nonempty(f)

  defp content_type_header({key, value}) when is_binary(key) and is_binary(value) do
    if String.downcase(key, :ascii) == "content-type", do: value
  end

  defp content_type_header(_), do: nil

  defp response_media_type(call_state) do
    headers = Map.get(call_state, :upstream_response_headers)

    ct =
      if is_list(headers) do
        Enum.find_value(headers, &content_type_header/1)
      end

    case ct do
      nil -> nil
      v -> v |> String.split(";", parts: 2) |> hd() |> String.trim() |> nonempty()
    end
  end

  defp http_status(n) when is_integer(n) and n >= 100 and n <= 599, do: n
  defp http_status(_), do: nil

  defp non_neg(n) when is_integer(n) and n >= 0, do: n
  defp non_neg(_), do: nil

  defp iso(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp iso(_), do: nil

  defp kind_ref(nil), do: nil
  defp kind_ref(ref) when is_binary(ref), do: %{"$ref" => ref}

  defp event_ref(nil), do: nil
  defp event_ref(ref) when is_binary(ref), do: %{"$ref" => ref}

  defp nonempty(s) when is_binary(s) and s != "", do: s
  defp nonempty(_), do: nil

  # Drop nil values: "no value" is an absent key on a spec, never a null
  # (the schemas have no nullable slots). Empty objects are kept — an
  # empty `args` is a legitimate ToolCall (the Kind says "possibly empty",
  # and `exactlyOne` needs it present); optional nested objects that
  # would be empty are thinned by `optional/1` at their own sites.
  defp compact(map) when is_map(map) do
    map
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  # An optional nested object with nothing in it is absent, not `{}`.
  defp optional(map) when is_map(map) do
    case compact(map) do
      m when map_size(m) == 0 -> nil
      m -> m
    end
  end

  # Session ids are client-controlled; keep logs to a prefix.
  defp redact(id) when is_binary(id) and byte_size(id) > 8, do: binary_part(id, 0, 8) <> "…"
  defp redact(id), do: inspect(id)
end
