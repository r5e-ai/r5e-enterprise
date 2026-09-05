defmodule Recurse.Gateway.LlmProxy.TokenEstimatorTest do
  @moduledoc """
  Tests for `Recurse.Gateway.LlmProxy.TokenEstimator` (Spec 009 Phase 3
  Sub-3.4 / T045a — FR-011 token-budget closure).

  Examples cover the formula. Properties cover monotonicity (PT-001) and
  the max_tokens ceiling (PT-002).
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Gateway.LlmProxy.TokenEstimator

  describe "estimate_completion_tokens/3" do
    test "returns 0 when prompt is empty" do
      assert TokenEstimator.estimate_completion_tokens(0, %{}, model: "gpt-5-codex") == 0
    end

    test "uses prompt_byte_size / chars_per_token when no max_tokens" do
      # 8000 bytes / 4 cpt = 2000; default_max_tokens (4096) is larger,
      # so prompt-derived ceiling wins.
      assert TokenEstimator.estimate_completion_tokens(8000, %{}, model: "gpt-5-codex") == 2000
    end

    test "respects explicit max_tokens ceiling" do
      assert TokenEstimator.estimate_completion_tokens(
               8000,
               %{"max_tokens" => 500},
               model: "gpt-5-codex"
             ) == 500
    end

    test "max_tokens ceiling honored even when prompt is huge" do
      assert TokenEstimator.estimate_completion_tokens(
               1_000_000,
               %{"max_tokens" => 50},
               model: "gpt-5-codex"
             ) == 50
    end

    test "unknown model falls back to default 4 chars/token + default ceiling" do
      # 16 bytes / 4 cpt = 4; below default_max_tokens.
      assert TokenEstimator.estimate_completion_tokens(16, %{}, model: "totally-made-up") == 4
    end

    test "non-integer max_tokens is ignored (falls back to default)" do
      # max_tokens missing-or-junk → default_max_tokens; 4000/4 = 1000 wins.
      assert TokenEstimator.estimate_completion_tokens(
               4000,
               %{"max_tokens" => "not-an-int"},
               model: "gpt-5-codex"
             ) == 1000
    end
  end

  describe "model coverage" do
    for model <- ["gpt-5-codex", "claude-3-5-sonnet", "gemini-1.5-pro"] do
      test "model #{model} has a chars_per_token entry" do
        assert TokenEstimator.chars_per_token_for(unquote(model)) >= 1
      end
    end
  end

  describe "PT-001 monotonicity in prompt size" do
    property "estimate is monotonically non-decreasing in prompt_byte_size" do
      check all p1 <- integer(0..100_000),
                p2 <- integer(0..100_000),
                max_tokens <- one_of([constant(nil), integer(1..100_000)]),
                model <- member_of(["gpt-5-codex", "claude-3-5-sonnet", "gemini-1.5-pro"]) do
        params = if max_tokens, do: %{"max_tokens" => max_tokens}, else: %{}
        e1 = TokenEstimator.estimate_completion_tokens(p1, params, model: model)
        e2 = TokenEstimator.estimate_completion_tokens(p2, params, model: model)

        if p1 <= p2 do
          assert e1 <= e2,
                 "expected estimate(#{p1}) <= estimate(#{p2}) for params=#{inspect(params)}, model=#{model}; got #{e1} > #{e2}"
        end
      end
    end
  end

  describe "PT-002 max_tokens ceiling" do
    property "estimate is always <= max_tokens when set" do
      check all prompt <- integer(0..1_000_000),
                max_tokens <- integer(0..100_000),
                model <- member_of(["gpt-5-codex", "claude-3-5-sonnet", "gemini-1.5-pro"]) do
        e =
          TokenEstimator.estimate_completion_tokens(
            prompt,
            %{"max_tokens" => max_tokens},
            model: model
          )

        assert e <= max_tokens
        assert e >= 0
      end
    end
  end
end
