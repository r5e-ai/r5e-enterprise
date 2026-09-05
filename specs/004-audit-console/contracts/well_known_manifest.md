# Contract: Well-Known Manifest + Schema Index

**Feature**: F004 | **Spec**: FR-045, FR-046 | **Research**: D10 | **Glossary**: Well-Known Manifest

This contract defines the discoverable JSON manifest the F004 audit console publishes at `/.well-known/r5e-audit.json`, the schema index at `/v1/schemas/index.json`, and the per-entity JSON Schema documents at `/v1/schemas/{name}.json`.

---

## CRITICAL distinction: stable manifest, NOT a self-describing API

Per project memory `feedback_no_premature_metaapi.md`: the Well-Known Manifest is a **stable forward-compatible description** of a typed versioned API — NOT a runtime reflective protocol. The distinction matters for tests, tooling, and PR review:

| Quality | Stable manifest (what F004 ships) | Reflective API (NOT what F004 ships) |
|---|---|---|
| Schema source | Hand-authored JSON Schemas under `apps/recurse_gateway/priv/schemas/*.json`, served verbatim. | Generated from runtime introspection of Ecto schemas + Plug routes. |
| Update cadence | New schema version = new file = new git commit + PR review. | Schemas mutate with each deployment, possibly silently. |
| Client behavior | Clients fetch schemas at **build time**, generate types via `json-schema-to-typescript` (D10), embed types in their build, and treat the runtime endpoint as a lookup convenience — clients work fine without it. | Clients depend on runtime fetching to know what fields exist. |
| Evolution policy | Additive changes only; breaking changes require a new schema URI (`v2`-suffixed). The manifest's `version` field signals breaking changes. | Schema can change shape on any deployment. |
| Test discipline | Contract tests assert the served schema bytes match the on-disk file byte-for-byte. | Contract tests can't catch drift. |
| F005 a2ui readiness | Forward-stub: an autonomous agent can parse the manifest at build-time. | Would be the wrong abstraction for a a2ui agent contract. |

**Implication**: `/.well-known/r5e-audit.json` is essentially an OpenAPI-shaped table of contents. Future endpoints are added by editing the manifest source-of-truth file (`apps/recurse_gateway/priv/schemas/manifest.json`) in a PR; the runtime serves the file from disk.

---

## `/.well-known/r5e-audit.json` — manifest shape

**HTTP**: `GET /.well-known/r5e-audit.json` — public, no auth required (CORS allowed via `corsica` per plan.md), `Content-Type: application/json`.

**Schema** (JSON Schema Draft 2020-12; the manifest is itself schema-validated):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.recurse.dev/r5e-audit-manifest/v1",
  "type": "object",
  "required": ["version", "endpoints", "schemas", "updated_at"],
  "properties": {
    "version": {
      "type": "string",
      "description": "Manifest version (semver). Major bump = breaking change.",
      "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"
    },
    "endpoints": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["path", "method", "schema_uri", "requires_role"],
        "properties": {
          "path": {"type": "string", "description": "URL path template, e.g., /v1/policy/drafts/{id}"},
          "method": {"type": "string", "enum": ["GET", "POST", "PATCH", "DELETE"]},
          "schema_uri": {"type": "string", "format": "uri", "description": "Pointer into /v1/schemas/* describing the response body envelope."},
          "request_schema_uri": {"type": "string", "format": "uri", "description": "Optional; for POST/PATCH/PUT bodies."},
          "requires_role": {
            "type": "array",
            "items": {"type": "string", "enum": ["tenant_auditor", "platform_operator"]},
            "description": "Any-of role allowlist. Empty array = public (manifest itself, schemas)."
          },
          "cedar_action": {"type": "string", "description": "The Cedar action gating this endpoint."},
          "event_kind": {"type": "string", "description": "The attested event_kind emitted on success."}
        }
      }
    },
    "schemas": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "uri", "version"],
        "properties": {
          "name": {"type": "string", "description": "Bareword name, e.g., 'attestation', 'policy_draft'."},
          "uri": {"type": "string", "format": "uri", "description": "Absolute URL to the schema JSON document."},
          "version": {"type": "string", "description": "Semver of the schema itself, independent of manifest version."}
        }
      }
    },
    "updated_at": {"type": "string", "format": "date-time"}
  }
}
```

**Example response**:

```json
{
  "version": "1.0.0",
  "endpoints": [
    {
      "path": "/v1/audit/sessions/{session_id}",
      "method": "GET",
      "schema_uri": "https://gateway.example.com/v1/schemas/session_timeline.json",
      "requires_role": ["tenant_auditor", "platform_operator"],
      "cedar_action": "Recurse::Action::\"DashboardQuery\"",
      "event_kind": "ui_query"
    },
    {
      "path": "/v1/policy/drafts",
      "method": "POST",
      "schema_uri": "https://gateway.example.com/v1/schemas/policy_draft.json",
      "request_schema_uri": "https://gateway.example.com/v1/schemas/policy_draft_create_request.json",
      "requires_role": ["platform_operator"],
      "cedar_action": "Recurse::Action::\"PolicyDraftCreate\"",
      "event_kind": "ui_policy_draft_created"
    }
  ],
  "schemas": [
    {"name": "attestation", "uri": "https://gateway.example.com/v1/schemas/attestation.json", "version": "1.0.0"},
    {"name": "policy_draft", "uri": "https://gateway.example.com/v1/schemas/policy_draft.json", "version": "1.0.0"},
    {"name": "policy_suggestion", "uri": "https://gateway.example.com/v1/schemas/policy_suggestion.json", "version": "1.0.0"},
    {"name": "chat_conversation", "uri": "https://gateway.example.com/v1/schemas/chat_conversation.json", "version": "1.0.0"},
    {"name": "session_timeline", "uri": "https://gateway.example.com/v1/schemas/session_timeline.json", "version": "1.0.0"}
  ],
  "updated_at": "2026-04-24T16:00:00Z"
}
```

**Cache headers**: `Cache-Control: public, max-age=300` (5 min). Manifest changes are operator-driven (PR + redeploy), so a 5-min cache is comfortable.

---

## `/v1/schemas/index.json` — schema index

**HTTP**: `GET /v1/schemas/index.json` — public, no auth, `Content-Type: application/json`.

**Schema**:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["schemas", "updated_at"],
  "properties": {
    "schemas": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "uri", "version"],
        "properties": {
          "name": {"type": "string"},
          "uri": {"type": "string", "format": "uri"},
          "version": {"type": "string"}
        }
      }
    },
    "updated_at": {"type": "string", "format": "date-time"}
  }
}
```

**Why both manifest AND index?** The manifest answers "what endpoints exist, with role + Cedar info"; the index answers "what schemas exist." Build-time codegen tooling (`ui/scripts/generate-types.ts` per D10) consumes the index to drive `json-schema-to-typescript`; the manifest is for richer discovery (e.g., generating an OpenAPI doc, building an autonomous agent client).

---

## Per-schema URIs — `/v1/schemas/{name}.json`

**HTTP**: `GET /v1/schemas/{name}.json` — public, no auth, `Content-Type: application/schema+json`.

**Format**: standard JSON Schema Draft 2020-12 documents. Each document MUST include:

- `$schema: "https://json-schema.org/draft/2020-12/schema"`
- `$id: "https://gateway.example.com/v1/schemas/{name}.json"` (canonical absolute URL)
- A top-level `type` (typically `"object"`)
- Versioning via a top-level `x-version` extension (e.g., `"x-version": "1.0.0"`)

**Day-1 schema set** (under `apps/recurse_gateway/priv/schemas/*.json`):

| Name | Purpose |
|---|---|
| `attestation` | F002 attestation envelope shape |
| `principal` | F002 principal claim shape |
| `session` | F002 session row shape |
| `session_timeline` | F004 `/v1/audit/sessions/{session_id}` response shape |
| `policy_draft` | F004 policy draft envelope |
| `policy_draft_create_request` | POST /v1/policy/drafts request body |
| `policy_suggestion` | F004 policy suggestion envelope |
| `policy_simulate_request` | POST /v1/policy/simulate request body |
| `policy_simulate_response` | POST /v1/policy/simulate response body |
| `policy_replay_response` | POST /v1/policy/replay/{run_id} response body |
| `blast_radius_summary` | The Blast Radius result shape (cached on drafts; returned by dry-run) |
| `chat_conversation` | F004 chat conversation envelope |
| `chat_message` | F004 chat message + tool_calls shape |
| `error_envelope` | The canonical flat error envelope shape (referenced by all 4xx/5xx responses; F001-nested retired in MR !31 / issue #30 Task L; built by `Recurse.Gateway.AuditPlane.ErrorEnvelope.build/3`) |

**Schema authoring discipline**:
- All schemas go through PR review.
- Adding a field: bump `x-version` patch version.
- Renaming or removing a field: bump `x-version` major version + create a new schema file (`policy_draft_v2.json`) + update the manifest to point at the new file. Old schema URI MUST keep returning the old shape for one minor manifest version (deprecation window).
- Schemas reference each other via absolute `$ref` URIs (e.g., `"$ref": "https://gateway.example.com/v1/schemas/principal.json"`). The Gateway's schema-publication module rewrites the `gateway.example.com` placeholder to the deployment's actual hostname at serve time.

---

## Build-time integration with the SPA (D10)

Per Phase 0 D10 (revised post-GAN — was originally a runtime-fetch pipeline; corrected to file-based codegen because the original was incoherent: types.ts was simultaneously gitignored AND CI-diffed):

1. The Gateway compiles its JSON Schemas to disk at `apps/recurse_gateway/priv/schemas/*.json` during `mix compile` (one file per published schema). The runtime `GET /v1/schemas/{name}.json` endpoint just serves these files via `Plug.Static`.
2. SPA build script (`ui/scripts/generate-types.ts`) reads the schema files **directly from disk** via the relative path `../apps/recurse_gateway/priv/schemas/`. **No running Gateway required at SPA build time.**
3. For each schema, runs `json-schema-to-typescript@^14`.
4. Writes the union type set to `ui/src/lib/types.ts`.
5. Computes a checksum of all schemas; embeds in `types.ts` as a constant.
6. **`types.ts` is COMMITTED** (NOT gitignored). CI runs `pnpm gen:types && git diff --exit-code ui/src/lib/types.ts` — drift between schemas and committed types fails CI.

This guarantees the SPA's TypeScript types and the Gateway's published schemas are byte-aligned at build time. Drift between published schema and SPA types is impossible without CI failure. The pipeline is fully offline (relevant for Air-Gapped Appliance forward-compat per Constitution Principle I).

---

## Property-test surfaces

Tested via Surface (F004 catalog) "Manifest stability":

- Round-trip: serialized manifest is byte-identical across serializations of the same source-of-truth file (deterministic key ordering — `Jason.encode!/2` with sorted keys).
- Version monotonicity: a manifest with major version N MUST contain only schemas with major version ≤ N.
- Reference integrity: every `schema_uri` and `request_schema_uri` referenced by an endpoint MUST resolve to a valid entry in the `schemas` array.
- Role allowlist correctness: every endpoint's `requires_role` array MUST be a subset of the Cedar entity schema's role allowlist for `cedar_action`.

---

## Out of scope

- Schemas for any F002 endpoint not also exposed in F004 (the F004 manifest documents what F004 adds + key F002 endpoints needed by the SPA; F002's full surface is not re-published).
- Auto-generated schemas from Ecto. Hand-authored only — Ecto schemas are an implementation detail; the wire format is the contract.
- OpenAPI 3.1 publication (the `version` field reserves the option; not shipped Day 1).
- HATEOAS-style `_links` collections in responses. Forward stub via the manifest, not embedded.
