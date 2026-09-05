defmodule Recurse.Gateway.LlmProxy.RequestKind do
  @moduledoc """
  Classifies one proxied LLM request by what the client was doing when it
  made it (spec 012 `plan.md` §9 "D2 receipt classification" + §10
  "session is the wrap").

  One Claude Code prompt produces three `POST /v1/messages` calls that
  share the endpoint and the credential: the session-title generator, the
  real agent turn, and a non-streaming side query. All three are attested
  (they carried the same prompt content), tagged by kind so the dashboard
  can default to `agent_turn` without inventing an "evidence of absence"
  mechanism.

  ## Rule (binding, from plan §9)

    1. `tools` present (non-empty list) → `:agent_turn`
    2. `output_config` present → `:session_title`
    3. `stream` absent (or `false`) → `:side_query`
    4. otherwise → `:agent_turn`

  The order matters: the captured `session_title.request.json` fixture
  carries `tools: []` *and* `output_config`, and `error_not_found` (a
  real turn against a bogus model) carries 29 tools *and*
  `output_config: {effort: high}`. An empty `tools` list is "no tools".

  The rule is shape-based (keys of the JSON body), not provider-specific,
  so it applies unchanged to any `https-sse` request; Codex Responses
  bodies (`tools` + `stream: true`) classify as `:agent_turn`.

  Pure functions; no state.
  """

  @type kind :: :agent_turn | :session_title | :side_query

  @kinds [:agent_turn, :session_title, :side_query]

  @doc "Every kind the classifier can return."
  @spec kinds() :: [kind()]
  def kinds, do: @kinds

  @doc """
  Classify a decoded request body (string-keyed map). Any non-map input
  (unparseable body, empty body) classifies as `:agent_turn` — the
  conservative default for the dashboard's default filter.
  """
  @spec classify(term()) :: kind()
  def classify(%{"tools" => tools}) when is_list(tools) and tools != [], do: :agent_turn
  def classify(%{"output_config" => oc}) when is_map(oc), do: :session_title
  def classify(%{"stream" => true}), do: :agent_turn
  def classify(params) when is_map(params), do: :side_query
  def classify(_), do: :agent_turn

  @doc """
  Classify a raw request body. Decodes JSON once; falls back to
  `:agent_turn` when the body is not a JSON object.
  """
  @spec classify_body(binary() | nil) :: kind()
  def classify_body(body) when is_binary(body) and body != "" do
    case JSON.decode(body) do
      {:ok, params} when is_map(params) -> classify(params)
      _ -> :agent_turn
    end
  end

  def classify_body(_), do: :agent_turn

  @doc "String form used in the predicate body and the receipt `tags`."
  @spec to_string(kind() | nil) :: String.t() | nil
  def to_string(nil), do: nil
  def to_string(kind) when kind in @kinds, do: Atom.to_string(kind)
end
