defmodule Recurse.Gateway.LlmProxy.CedarToolUseGate do
  @moduledoc """
  Shared gateway context helpers for the LLM proxies.

  **There is no evaluator here.** Authorization for a tool runs through
  `Recurse.Gateway.Fold.Admission` and the kernel, and there is exactly
  one Cedar answer per act — the kernel's. What is left in this module is
  the plumbing both proxies share: the per-call gate context, the
  argument-inlining threshold, the tool-name charset, Cedar string
  escaping, and the completion-token estimate.

  Until this release the module also carried `evaluate/2`, a second Cedar
  decision over the loader projection, plus a supervised ETS
  `DecisionCache` keyed on it. Neither had a live caller — every prior
  review confirmed that — and the release contract says passing
  transitional tests are not acceptance evidence, so both are removed
  rather than kept as a compatibility surface nobody compiles against
  (RC review 2026-09-05). `snapshot_bundle/1` stays: it reads the loader
  projection for tests and for the audit console, and establishes
  authority for nothing.

  Each live admission evaluates the chain's current policy. A policy
  activation can therefore affect later tools on an existing stream.
  The recorded kernel receipt binds the policy used for each decision.
  An admission error interrupts the stream; it is not a policy denial.
  """

  alias Recurse.Gateway.LlmProxy.TokenEstimator
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @typedoc """
  Per-call gate context. Built once at call-open by the proxy and
  threaded into every per-intent evaluation. Per the contract:

    * `:principal` — actor identity + claims for the Cedar User entity.
    * `:model` — the LLM model id (used both as Cedar context and as the
      per-model selector for the TokenEstimator).
    * `:tenant`, `:session_id` — call-scoping for Cedar policies.
    * `:prompt_hash` / `:response_so_far_hash` — content-derived audit
      anchors so policies can key on "this exact prompt".
    * `:estimated_completion_tokens` — populated from `TokenEstimator`
      (FR-011); Cedar policies enforce per-principal token budgets.
    * `:parallel_tool_call_index` — `nil` for sequential calls;
      otherwise the position in the upstream parallel-tool-calls array
      (per `ToolUseIntent.parallel_index`).
    * `:cedar_bundle_hash` — hex-encoded SHA-256 of the call-start
      bundle (matches `PolicyBundleRef.bundle_id`); included in the
      Cedar context so policies can audit-trail-key on bundle versions
      AND used as the cache key fourth component.
    * `:upstream_domain`, `:transport` — provider/transport
      identification for policies that want to allow/deny per upstream.
    * `:started_at` — call-start `DateTime.t()`; lets time-of-day
      policies exist.
    * `:bundle` — the `%PolicyBundleRef{}` snapshot from call-start.
      The cedar_bundle_hash MUST match this bundle's canonical_hash.
  """
  @type gate_context :: %{
          required(:principal) => principal_context(),
          required(:model) => String.t(),
          required(:tenant) => String.t(),
          required(:session_id) => String.t(),
          required(:prompt_hash) => binary(),
          required(:response_so_far_hash) => binary(),
          required(:estimated_completion_tokens) => non_neg_integer(),
          required(:cedar_bundle_hash) => binary(),
          required(:upstream_domain) => String.t(),
          required(:transport) => :wss | :https_sse,
          required(:started_at) => DateTime.t(),
          required(:bundle) => PolicyBundleRef.t(),
          optional(:parallel_tool_call_index) => non_neg_integer() | nil,
          optional(:args_inline_threshold_bytes) => pos_integer()
        }

  @type principal_context :: %{
          required(:id) => String.t(),
          required(:kind) => :obo_human | :service_account | :autonomous,
          optional(:chatgpt_account_id) => String.t() | nil,
          optional(:claims) => map()
        }

  @type deny_reason :: %{
          rule_id: String.t(),
          reason: String.t(),
          suggested_alternative: String.t() | nil
        }

  @typedoc """
  The three answers the tool path carries. Produced by
  `Recurse.Gateway.Fold.Admission.admit_tool/3` from the kernel's receipt
  and consumed by `Recurse.Gateway.LlmProxy.DenialInjector`; the shape is
  declared here because both proxies already speak this module's context
  vocabulary.
  """
  @type decision :: {:allow} | {:deny, deny_reason()} | {:error, atom()}

  @default_args_inline_threshold_bytes 10_000

  # `\A`/`\z`, not `^`/`$`: `$` also matches before a trailing newline.
  @tool_name_re ~r/\A[A-Za-z0-9_.:-]{1,128}\z/
  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  `true` when `name` matches `#{inspect(@tool_name_re)}` — the charset the
  gate will put inside `ToolUse::"…"`. Everything else is denied with
  `reason: "invalid_tool_name"` (see the module doc).
  """
  @spec valid_tool_name?(term()) :: boolean()
  def valid_tool_name?(name) when is_binary(name), do: Regex.match?(@tool_name_re, name)
  def valid_tool_name?(_), do: false

  @doc """
  Escape a string for use inside a Cedar string literal / entity id:
  `\\`, `"` and `'` are backslash-escaped, `\\n` `\\r` `\\t` use their
  short forms, other control bytes become `\\u{h+}` (minimal lowercase
  hex, Cedar's normalized form). Bytes ≥ 0x80 (UTF-8 continuation + lead
  bytes) pass through unchanged. Total over any binary; never raises.
  Non-printable Unicode above U+007F (zero-width characters and the
  like) is not escaped; Cedar rejects such an id as un-normalized, which
  surfaces as `{:error, :cedar_eval_error}` — still fail-closed, and
  unreachable for the validated `claude-code:` principals and tool names.
  """
  @spec cedar_escape(binary()) :: binary()
  def cedar_escape(s) when is_binary(s) do
    s
    |> :binary.bin_to_list()
    |> Enum.map(&escape_byte/1)
    |> IO.iodata_to_binary()
  end

  # Cedar accepts an entity id only in its NORMALIZED form (the string
  # must round-trip through its own printer, Rust's `str::escape_debug`):
  # short escapes for `\t \r \n \\ \' \"`, control bytes as `\u{h+}` with
  # minimal lowercase hex, printable text untouched.
  defp escape_byte(?\\), do: "\\\\"
  defp escape_byte(?"), do: "\\\""
  defp escape_byte(?'), do: "\\'"
  defp escape_byte(?\n), do: "\\n"
  defp escape_byte(?\r), do: "\\r"
  defp escape_byte(?\t), do: "\\t"

  defp escape_byte(b) when b < 0x20 or b == 0x7F,
    do: "\\u{" <> String.downcase(Integer.to_string(b, 16)) <> "}"

  defp escape_byte(b), do: <<b>>

  @doc """
  Build the Cedar context map a Cedar policy sees as `context`. Extracted
  per Principle VII so `StreamingProxy` and `WebSocketBridge` share the
  same construction (and tests can introspect it without invoking
  Cedar). Threshold logic + hash inlining live here.
  """
  @spec build_cedar_context(ToolUseIntent.t(), gate_context()) :: map()
  def build_cedar_context(%ToolUseIntent{} = intent, %{} = context) do
    threshold =
      Map.get(context, :args_inline_threshold_bytes, @default_args_inline_threshold_bytes)

    inline? = should_inline_args?(intent, threshold)

    base = %{
      "tool_args_hash" => Base.encode16(intent.tool_args_hash, case: :lower),
      "tool_args_size_bytes" => intent.tool_args_size_bytes,
      "model" => context.model,
      "tenant" => context.tenant,
      "session_id" => context.session_id,
      "prompt_hash" => Base.encode16(context.prompt_hash, case: :lower),
      "response_so_far_hash" => Base.encode16(context.response_so_far_hash, case: :lower),
      "estimated_completion_tokens" => context.estimated_completion_tokens,
      "cedar_bundle_hash" => Base.encode16(context.cedar_bundle_hash, case: :lower),
      "upstream_domain" => context.upstream_domain,
      "transport" => Atom.to_string(context.transport),
      "started_at" => DateTime.to_iso8601(context.started_at),
      "principal_kind" => Atom.to_string(context.principal.kind),
      "chatgpt_account_id" => Map.get(context.principal, :chatgpt_account_id) || "",
      "principal_groups" => extract_groups(context.principal),
      "parallel_tool_call_index" => parallel_index_or(-1, context, intent)
    }

    if inline? do
      Map.put(base, "tool_args", intent.tool_args)
    else
      base
    end
  end

  @doc """
  Capture the current Cedar bundle snapshot. Returns
  `{:ok, %PolicyBundleRef{}}` or `{:error, :not_loaded}`. Called by the
  proxy at call-open; the returned ref is threaded into every per-intent
  `evaluate/2` for the lifetime of the call.

  Thin wrapper over `Recurse.Gateway.Policy.Active.current/0` that
  unwraps the `%Active{}` envelope to return the inner
  `%PolicyBundleRef{}` (the gate context only needs bundle bytes +
  canonical_hash, not provenance). Tests can inject a fake via the
  `:active_module` opt to simulate alternate bundle states.
  """
  @spec snapshot_bundle(keyword()) :: {:ok, PolicyBundleRef.t()} | {:error, :not_loaded}
  def snapshot_bundle(opts \\ []) do
    active_mod = Keyword.get(opts, :active_module, Recurse.Gateway.Policy.Active)

    case active_mod.current() do
      {:ok, %Recurse.Gateway.Policy.Active{bundle: %PolicyBundleRef{} = ref}} -> {:ok, ref}
      {:error, :not_loaded} -> {:error, :not_loaded}
    end
  end

  @doc """
  Resolve the per-tenant args-inline threshold. Defaults to 10KB; tenants
  override via `LlmProviderConfig.metadata["cedar_args_inline_threshold_bytes"]`.
  """
  @spec resolve_args_inline_threshold(map() | nil) :: pos_integer()
  def resolve_args_inline_threshold(metadata) when is_map(metadata) do
    case Map.get(metadata, "cedar_args_inline_threshold_bytes") do
      n when is_integer(n) and n > 0 -> n
      _ -> @default_args_inline_threshold_bytes
    end
  end

  def resolve_args_inline_threshold(_), do: @default_args_inline_threshold_bytes

  @doc """
  Default args-inline threshold. Documented for tests + callers that
  want to hard-code it.
  """
  @spec default_args_inline_threshold_bytes() :: pos_integer()
  def default_args_inline_threshold_bytes, do: @default_args_inline_threshold_bytes

  @doc """
  Convenience builder used by `StreamingProxy` + `WebSocketBridge` at
  call-open to assemble the gate-context base (everything except the
  per-intent `:parallel_tool_call_index`). Returns a map shaped per
  `gate_context()` minus that one field.
  """
  @spec build_gate_context_base(map()) :: map()
  def build_gate_context_base(%{} = inputs) do
    Map.merge(
      %{
        estimated_completion_tokens: 0,
        prompt_hash: <<>>,
        response_so_far_hash: <<>>,
        parallel_tool_call_index: nil
      },
      inputs
    )
  end

  @doc """
  Wire-friendly: assemble the per-intent `gate_context` from a base and
  the intent's `parallel_index`. Used by the proxy dispatch loop.
  """
  @spec gate_context_for_intent(map(), ToolUseIntent.t()) :: gate_context()
  def gate_context_for_intent(base, %ToolUseIntent{parallel_index: idx}) do
    Map.put(base, :parallel_tool_call_index, idx)
  end

  @doc """
  Estimator wiring helper — populates `:estimated_completion_tokens` on
  the gate-context base from a prompt body + request params at
  call-open. Wraps `TokenEstimator.estimate_completion_tokens/3`.
  """
  @spec populate_estimated_tokens(map(), %{
          prompt_byte_size: non_neg_integer(),
          request_params: map()
        }) ::
          map()
  def populate_estimated_tokens(%{model: model} = base, %{
        prompt_byte_size: pbs,
        request_params: rp
      }) do
    estimate = TokenEstimator.estimate_completion_tokens(pbs, rp, model: model)
    Map.put(base, :estimated_completion_tokens, estimate)
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp extract_groups(%{claims: %{"groups" => groups}}) when is_list(groups),
    do: Enum.map(groups, &to_string/1)

  defp extract_groups(%{claims: %{groups: groups}}) when is_list(groups),
    do: Enum.map(groups, &to_string/1)

  defp extract_groups(_), do: []

  # `:too_large` sentinel intents NEVER inline (regardless of threshold).
  defp should_inline_args?(%ToolUseIntent{tool_args: :too_large}, _threshold), do: false

  defp should_inline_args?(%ToolUseIntent{tool_args_size_bytes: size}, threshold)
       when is_integer(size),
       do: size <= threshold

  defp should_inline_args?(_intent, _threshold), do: false

  # Per-intent override beats per-context default when both present.
  defp parallel_index_or(default, context, intent) do
    case Map.get(context, :parallel_tool_call_index) do
      nil ->
        case intent.parallel_index do
          nil -> default
          n when is_integer(n) -> n
        end

      n when is_integer(n) ->
        n
    end
  end
end
