# Starter Cedar Policy Templates

Phase-1 starter library for Recurse Enterprise customers who prefer a
reviewed baseline over writing Cedar from scratch. Maps to **Phase-1 product
decision 7** (policy authoring = templates + Cedar power-user + AI-generated)
and backs **FR-049**'s policy-author surfaces.

Each template is valid Cedar 4.9.1 under Recurse's pinned engine
(`apps/recurse_shared/priv/test_fixtures/cedar_stability/`). To customize,
copy the file into your own policy bundle, edit the placeholders, and push
via `PolicyProvider` (see `contracts/policy_bundle_contract.md`).

## Templates

| File                                  | Pattern                                        | Starting deployment shape                 |
|---------------------------------------|------------------------------------------------|-------------------------------------------|
| `rbac_starter.cedar`                  | Role-based access control (roles → actions)    | Managed SaaS / VPC Runner / Appliance     |
| `abac_starter.cedar`                  | Attribute-based access control (tenant, owner) | Any Governance shape                      |
| `denylist_pattern.cedar`              | Explicit forbids layered over broad permits    | Compose with any permit-based template    |
| `llm_calls_only.cedar`                | LLM-only completion traffic, no tool execution | Standalone AI Gateway default             |
| `standard_mcp_tools_allowlist.cedar`  | Curated MCP tool allowlist (Jira, Slack, etc.) | Any Governance shape with tool-calling    |

## How to customize

Common edits per template:

### `rbac_starter.cedar`
- Rename the `Role::"admin"`, `Role::"operator"`, `Role::"reader"`, `Role::"agent"`
  groups to match your org's taxonomy.
- Adjust the action allowlists per role (`Action::"read"`, `Action::"write"`, etc.).
- Add resource-kind guards (`resource is Dataset`, `resource is Document`) to
  narrow role scope.

### `abac_starter.cedar`
- Decide which resource attributes govern access (`owner`, `tenant`,
  `classification`) and wire them through Recurse's `IdentityContext`.
- Decide which context attributes the Gateway MUST inject to allow
  (`business_justification`, `ticket_id`, `acting_for_human`).
- Tune the clearance-level comparison if your org uses a different ladder.

### `denylist_pattern.cedar`
- Tag sensitive resources upstream (resource attribute `tags` includes `"sensitive"`)
  and carve out break-glass exceptions via the `context.break_glass` flag.
- Add tenant-specific forbids for regulated data (`legal_hold`, `pii`, `pci`).
- Extend the non-human-OBO block with additional allow-list roles.

### `llm_calls_only.cedar`
- Add additional LLM provider resources (`llm://anthropic/...`, `llm://azure/...`)
  if your Gateway proxies multiple model vendors.
- Tighten the action set if you don't want streaming or embeddings traffic.
- Layer `denylist_pattern.cedar` on top for defense-in-depth.

### `standard_mcp_tools_allowlist.cedar`
- Add or remove MCP tool resources per your approved integration list.
- For write-capable tools, supplement the `context.business_justification`
  guard with a role check (e.g., `principal in Role::"engineer"`).
- Use Recurse's Discovery-to-Policy flow (FR-049 surface 2) to surface new
  tool-call patterns your agents actually need and promote them here.

## Composing templates

Cedar evaluates all matching policies; any `forbid` wins over any `permit`.
Recommended starting composition for a Governance shape:

```
llm_calls_only.cedar
+ rbac_starter.cedar         (or abac_starter.cedar)
+ standard_mcp_tools_allowlist.cedar
+ denylist_pattern.cedar      (always — trap door for legal hold / sensitive)
```

Run the combined set through the Cedar Playground (`POST /v1/governance/policy/simulate`,
FR-049 surface 1) and the Blast-Radius simulator (`POST /v1/governance/policy/blast-radius`,
FR-049 surface 3) before publishing.

## Validating locally

From the repo root:

```sh
mix run --no-start -e '
  base = Path.join(:code.priv_dir(:recurse_shared), "policy_templates")
  Path.wildcard(Path.join(base, "*.cedar"))
  |> Enum.each(fn path ->
    src = File.read!(path)
    IO.inspect({Path.basename(path), Recurse.Cedar.validate_policy_syntax(src)})
  end)
'
```

Each template should return `{:ok, {}}` (the NIF's Ok-with-unit shape).

## Why not a visual builder?

Visual dropdown-based Cedar authoring (à la AWS IAM Visual Editor) is an
**explicit Phase-2 deferral** per FR-049. Phase-1 ships three surfaces:
split-pane Playground, Discovery-to-Policy generator, and Blast-Radius
simulation. Starter templates fill the "I don't want to start from a blank
editor" slot until visual building arrives.

## References

- `specs/001-api-jido-foundations/spec.md` FR-049 (three policy-author surfaces)
- `specs/001-api-jido-foundations/contracts/policy_author_ux.md` (Deliverable P)
- `specs/001-api-jido-foundations/contracts/policy_bundle_contract.md` (Deliverable K)
- `.specify/memory/product_decisions_phase1.md` §7 (policy authoring decision)
