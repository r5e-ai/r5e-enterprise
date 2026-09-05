// LLM-calls-only — Standalone AI Gateway default policy.
//
// Smallest-viable policy set for the Standalone-Gateway deployment shape
// (per product decision 2). Permits LLM completion traffic through the
// Gateway; forbids everything else by default (no matching permit == deny).
//
// Shipped as the out-of-the-box starting point so customers get a working
// Gateway minute-one. Customers layer in RBAC / ABAC templates incrementally.

// Permit OpenAI-compat chat completion calls for any authenticated principal.
// The Standalone-Gateway's `X-Observed-Identity` JWT (FR-017 / FR-053) is
// asserted upstream of Cedar — by the time Cedar runs, principal is bound.
permit (
  principal,
  action == Action::"chat_completion",
  resource == Resource::"llm://openai/chat/completions"
);

// Permit embeddings endpoints — low risk, commonly needed for RAG pipelines.
permit (
  principal,
  action == Action::"embeddings",
  resource == Resource::"llm://openai/embeddings"
);

// Permit model-listing calls (the OpenAI SDK's client.models.list() path).
permit (
  principal,
  action == Action::"list_models",
  resource == Resource::"llm://openai/models"
);

// Permit streaming-mode completions (same action kind, SSE transport).
// Streaming policy matrix (Deliverable G) confirms SSE is the committed
// transport for LLM stream:true traffic.
permit (
  principal,
  action == Action::"chat_completion_stream",
  resource == Resource::"llm://openai/chat/completions"
);

// Denylist rail — block completions that attempt tool-use without explicit
// human-OBO context. Standalone-Gateway's default posture is "LLM text only";
// tool execution requires a Governance-tier deployment with an operator-reviewed
// allowlist (see standard_mcp_tools_allowlist.cedar).
forbid (
  principal,
  action == Action::"chat_completion",
  resource
)
when {
  context has tools_requested &&
  context.tools_requested == true &&
  (!(context has acting_for_human) || context.acting_for_human == false)
};
