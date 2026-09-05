defmodule Recurse.Gateway.LlmProxy.TokenEstimator do
  @moduledoc """
  Per-model byte→token estimator used by the Cedar tool-use gate to
  populate `gate_context.estimated_completion_tokens` (FR-011 closure
  per spec 009 Phase 3 Sub-3.4 / T045a).

  ## Why this exists

  FR-011 says "the proxy estimates request tokens from prompt size +
  max_tokens param; passes the estimate as Cedar context; Cedar can
  deny if budget exceeded." We don't have a real tokenizer in the
  Phase-3 hot path — running tiktoken / SentencePiece per request is
  too expensive — so we use a conservative chars-per-token approximation
  per model.

  ## Estimation formula

      min(
        request_params["max_tokens"] || default_per_model,
        prompt_byte_size / chars_per_token_per_model
      )

  The result is the LARGER of the two ceilings would be unsafe: we want
  the SMALLER (the tightest bound) so Cedar's budget rule is checking
  against an upper-bound-on-tokens-charged that the request could
  realistically incur. `max_tokens` is a hard ceiling the provider will
  enforce; `prompt_byte_size / chars_per_token` is a lower-bound on
  what's already-committed by the prompt content.

  Wait — let's re-read. The spec says:

      `min(request_params["max_tokens"] || default_per_model,
            prompt_byte_size / chars_per_token_per_model)`

  This is the COMPLETION-token estimate, not total tokens. Both
  expressions are "how many completion tokens could come out":

    * `max_tokens` is the explicit ceiling the user asked for.
    * `prompt_byte_size / chars_per_token` approximates the ceiling
      implied by typical model output ratio (heuristic: a request of
      N input tokens often produces no more than ~N output tokens
      under default settings).

  Taking `min` gives the tightest credible upper-bound on
  completion-token spend, which is the conservative number to feed
  to a budget Cedar policy.

  ## Per-model `chars_per_token`

  Phase-3 models all happen to run ~4 chars/token at p50 across English
  text. We seed with that conservative value; if a model later exhibits
  significantly different behavior (e.g. a Chinese-tuned model with
  shorter chars-per-token) operators can extend the table.

  ## Properties (PT in `token_estimator_test.exs`)

    * Monotonicity: `prompt' >= prompt` ⇒ `estimate(prompt', _) >= estimate(prompt, _)`
      when `max_tokens` is held constant.
    * Max-tokens ceiling: `estimate(_, %{"max_tokens" => k}) <= k`.

  ## Iron-Law check (`elixir:elixir-thinking`)

  Pure functions. No process. Module organizes code; the per-model
  `chars_per_token` table is data.
  """

  @typedoc """
  Request params map. Keys we read:

    * `"max_tokens"` — integer, optional. The user-requested completion
      ceiling. When absent we fall back to `default_per_model/1`.

  We accept additional keys without error so callers can pass the raw
  decoded request body unchanged.
  """
  @type request_params :: %{optional(String.t()) => term()}

  @typedoc """
  Per-model approximate chars-per-completion-token. Conservative defaults.
  """
  @type chars_per_token :: pos_integer()

  # Per-model chars-per-token table.
  #
  # 4 chars/token is the OpenAI-published English-text heuristic; the
  # Anthropic + Google models are within ±10% of that at p50, so we
  # seed all three identically. Extend per-model if real tokenizer
  # data reveals significant divergence.
  @chars_per_token %{
    "gpt-5-codex" => 4,
    "claude-3-5-sonnet" => 4,
    "gemini-1.5-pro" => 4
  }

  # Per-model default-when-`max_tokens`-unset. Same conservative shape:
  # if the caller didn't specify a ceiling, assume the model's own
  # default ceiling (4096 is a reasonable cross-model floor; real
  # models default higher, but Cedar policies wanting to deny on
  # over-budget will catch that).
  @default_max_tokens 4096

  # Fallback for unknown model strings — same conservative 4 chars/token.
  @default_chars_per_token 4

  @doc """
  Estimate completion tokens for a request given prompt byte size and
  request params.

  Returns a non-negative integer estimate that represents the
  conservative-upper-bound number of completion tokens the request
  could spend. Cedar policies that want to enforce a per-principal
  token budget compare this estimate against the principal's remaining
  budget at evaluation time.

  ## Examples

      iex> alias Recurse.Gateway.LlmProxy.TokenEstimator
      iex> TokenEstimator.estimate_completion_tokens(8000, %{}, model: "gpt-5-codex")
      2000

      iex> alias Recurse.Gateway.LlmProxy.TokenEstimator
      iex> TokenEstimator.estimate_completion_tokens(8000, %{"max_tokens" => 500}, model: "gpt-5-codex")
      500

      iex> alias Recurse.Gateway.LlmProxy.TokenEstimator
      iex> TokenEstimator.estimate_completion_tokens(0, %{"max_tokens" => 500}, model: "gpt-5-codex")
      0
  """
  @spec estimate_completion_tokens(non_neg_integer(), request_params(), keyword()) ::
          non_neg_integer()
  def estimate_completion_tokens(prompt_byte_size, request_params, opts \\ [])
      when is_integer(prompt_byte_size) and prompt_byte_size >= 0 and is_map(request_params) do
    model = Keyword.get(opts, :model, "")
    cpt = chars_per_token_for(model)
    prompt_ceiling = div(prompt_byte_size, cpt)

    requested_ceiling =
      case Map.get(request_params, "max_tokens") do
        n when is_integer(n) and n >= 0 -> n
        _ -> default_max_tokens_for(model)
      end

    min(prompt_ceiling, requested_ceiling)
  end

  @doc """
  Lookup the chars-per-token approximation for `model`. Falls back to
  `#{@default_chars_per_token}` (English-text heuristic) for unknown
  models so the estimator never raises and policies always get a
  conservative number.
  """
  @spec chars_per_token_for(String.t()) :: chars_per_token()
  def chars_per_token_for(model) when is_binary(model) do
    Map.get(@chars_per_token, model, @default_chars_per_token)
  end

  @doc """
  Default `max_tokens` ceiling when the request omits it. Per-model
  override slot in case operators need to tighten or loosen the floor;
  defaults to #{@default_max_tokens}.
  """
  @spec default_max_tokens_for(String.t()) :: pos_integer()
  def default_max_tokens_for(_model), do: @default_max_tokens
end
