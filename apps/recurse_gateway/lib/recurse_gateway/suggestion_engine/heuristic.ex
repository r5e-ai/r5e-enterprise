defmodule Recurse.Gateway.SuggestionEngine.Heuristic do
  @moduledoc """
  Shared types + helpers for the five F004 heuristic suggestion patterns
  (research D3). Every pattern module under
  `Recurse.Gateway.SuggestionEngine.Heuristic.*` exposes a single public
  `detect/1` function returning a list of suggestion records of this
  shape.

  ## Suggestion record

  Each pattern emits a map with the following keys:

      %{
        pattern_name: atom(),                   # e.g. :recurring_allow
        principal_subject_hash: binary(),        # 16-byte SHA-256 prefix
        action_hash: binary(),                   # 16-byte SHA-256 prefix
        principal_subject_excerpt: String.t(),   # for pattern_summary text
        action_label: String.t(),                # for pattern_summary text
        confidence_score: 0..100,                # pattern-specific
        pattern_summary: String.t(),             # ≤200 chars (D4 contract)
        proposed_cedar: String.t()               # ≤500 chars (D4 contract)
      }

  ## Determinism

  Pattern modules are pure functions. Surface U property test
  (`apps/recurse_gateway/test/suggestion_engine/heuristic_property_test.exs`)
  asserts byte-equality across two invocations against the same window;
  reordering invariance under chronological re-sort; per-pattern
  triggering against crafted fixtures; and the deduplication-key
  invariant. The five property test cases share the helpers below.

  ## Receipt-window shape

  The detect/1 functions take a list of receipt maps with at minimum:

      %{
        principal_subject: String.t(),
        action_label: String.t(),
        resource_kind: String.t(),
        policy_decision: :allow | :deny,
        committed_at: DateTime.t(),
        principal_kind: :obo_human | :service_account | :autonomous,
        matched_policy: String.t() | nil,
        tenant_attribute: String.t() | nil
      }

  Pattern modules accept that shape directly so callers (HeuristicRunner,
  property tests, the SuggestPolicyPattern audit-agent tool) can construct
  windows from receipts OR synthetic fixtures uniformly.

  ## Iron-Law check (`elixir:elixir-thinking`)

  No process. Every detect/1 call is a pure function. The HeuristicRunner
  Oban worker (T131) hands the window in; the worker holds whatever
  lifecycle state belongs to the run.
  """

  @type pattern_name ::
          :recurring_allow
          | :recurring_deny
          | :anomalous_burst
          | :cross_tenant_access
          | :stale_role_creep

  @type receipt :: %{
          required(:principal_subject) => String.t(),
          required(:action_label) => String.t(),
          required(:resource_kind) => String.t(),
          required(:policy_decision) => :allow | :deny,
          required(:committed_at) => DateTime.t(),
          optional(:principal_kind) => :obo_human | :service_account | :autonomous,
          optional(:matched_policy) => String.t() | nil,
          optional(:tenant_attribute) => String.t() | nil
        }

  @type suggestion :: %{
          required(:pattern_name) => pattern_name(),
          required(:principal_subject_hash) => binary(),
          required(:action_hash) => binary(),
          required(:principal_subject_excerpt) => String.t(),
          required(:action_label) => String.t(),
          required(:confidence_score) => non_neg_integer(),
          required(:pattern_summary) => String.t(),
          required(:proposed_cedar) => String.t()
        }

  @doc """
  Compute the deterministic dedup-key components for a suggestion. SHA-256
  prefixed to 16 bytes (128 bits) — collision-resistant in practice while
  staying short for index sizing.
  """
  @spec subject_hash(String.t()) :: binary()
  def subject_hash(subject) when is_binary(subject) do
    :crypto.hash(:sha256, subject) |> binary_part(0, 16)
  end

  @spec action_hash(String.t()) :: binary()
  def action_hash(action_label) when is_binary(action_label) do
    :crypto.hash(:sha256, action_label) |> binary_part(0, 16)
  end

  @doc """
  Truncate a principal subject for display in pattern_summary text.
  Keeps the local-part of email-shaped subjects; otherwise truncates.
  """
  @spec subject_excerpt(String.t()) :: String.t()
  def subject_excerpt(subject) when is_binary(subject) do
    if byte_size(subject) <= 64, do: subject, else: binary_part(subject, 0, 61) <> "..."
  end

  @doc """
  Trim a string to `max_bytes`. Used to honor the ≤200 / ≤500 char
  contract on pattern_summary / proposed_cedar.
  """
  @spec trim(String.t(), pos_integer()) :: String.t()
  def trim(s, max_bytes) when is_binary(s) and is_integer(max_bytes) do
    if byte_size(s) <= max_bytes do
      s
    else
      binary_part(s, 0, max_bytes - 3) <> "..."
    end
  end

  @doc """
  Sort suggestions deterministically by `(pattern_name, principal_subject_hash,
  action_hash)` so two engine invocations yield byte-identical lists. The
  Surface U byte-equality property test depends on this.
  """
  @spec sort([suggestion()]) :: [suggestion()]
  def sort(suggestions) when is_list(suggestions) do
    Enum.sort_by(suggestions, fn s ->
      {Atom.to_string(s.pattern_name), s.principal_subject_hash, s.action_hash}
    end)
  end

  @doc """
  Group a receipt list into chronological order (ascending by committed_at).
  Pattern modules use this to make iteration reordering-invariant.
  """
  @spec chronological([receipt()]) :: [receipt()]
  def chronological(receipts) when is_list(receipts) do
    Enum.sort_by(receipts, & &1.committed_at, DateTime)
  end
end
