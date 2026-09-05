//! Rustler NIF for Cedar policy evaluation.
//!
//! Phase-1 scope per tasks.md T042-T045 + research D2/D3:
//!   - `canonical_hash(policy_source)` — FR-039 `policy_canonical_hash`. Parses
//!     a Cedar policy set in its native source form, serializes to the crate's
//!     EST JSON, canonicalizes via RFC 8785 JCS, then SHA-256s the canonical
//!     byte stream. Output is a 32-byte binary.
//!   - `evaluate(policy_source, request_json)` — scaffold only; Feature 002+
//!     wires this into the Gateway policy-enforcement path. Returns `"allow"`
//!     or `"deny"` based on a minimal request-shape sanity check.
//!   - `validate_policy_syntax(source)` — parse-only path for the Cedar
//!     Playground live-feedback endpoint (T081). Returns `:ok` or
//!     `{:error, reason}`.
//!
//! The content-addressed Cedar pin (research D2) is enforced three ways:
//!   1. Cargo.toml pins `cedar-policy = "=4.9.1"`.
//!   2. Cargo.lock records the SHA-256 of the published crate tarball.
//!   3. `mix recurse.cedar.stability_check` replays the fixture through this
//!      NIF and asserts the resulting `canonical_hash` matches the committed
//!      `expected_hash.txt`.
//!
//! Do not add shared NIF state. Every call is stateless; Cedar contexts are
//! cheap to construct per invocation (research D3).

use cedar_policy::{Context, Entities, EntityUid, PolicySet, Request};
use rustler::{Binary, Env, OwnedBinary};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::str::FromStr;

/// Compute the `policy_canonical_hash` for a Cedar policy set source string.
///
/// Steps:
///   1. Parse the source into a [`PolicySet`] (AST validation).
///   2. Serialize to the crate's canonical EST JSON representation.
///   3. Canonicalize via RFC 8785 JCS (stable key ordering + number form).
///   4. SHA-256 the canonical UTF-8 bytes.
///
/// Returns a 32-byte binary. On parse or serialization failure the NIF raises
/// a Rustler error back into Elixir; callers should treat this as a developer
/// error (policy authors see syntax errors via `validate_policy_syntax/1`).
/// Compute the canonical hash. Returns a tagged `Result` so callers can
/// pattern-match on specific failure modes without needing to catch raised
/// Erlang exceptions. On the Elixir side this maps to
/// `{:ok, binary()} | {:error, binary()}`.
#[rustler::nif(schedule = "DirtyCpu")]
fn canonical_hash<'a>(env: Env<'a>, policy_source: String) -> Result<Binary<'a>, String> {
    let policy_set = PolicySet::from_str(&policy_source)
        .map_err(|e| format!("cedar parse error: {e}"))?;
    let json = policy_set
        .to_json()
        .map_err(|e| format!("cedar to_json error: {e}"))?;
    let canonical =
        serde_jcs::to_string(&json).map_err(|e| format!("jcs encode error: {e}"))?;
    let digest = Sha256::digest(canonical.as_bytes());

    let mut owned =
        OwnedBinary::new(32).ok_or_else(|| "cannot allocate output binary".to_string())?;
    owned.as_mut_slice().copy_from_slice(&digest);
    Ok(Binary::from_owned(owned, env))
}

/// Validate a Cedar policy source string.
///
/// Returns `Ok(())` if the policy set parses. On failure returns a
/// human-readable error string suitable for surfacing in the Cedar Playground
/// (Deliverable P, FR-049). Does not perform schema validation — that is
/// Feature 002+ work.
#[rustler::nif(schedule = "DirtyCpu")]
fn validate_policy_syntax(source: String) -> Result<(), String> {
    PolicySet::from_str(&source)
        .map(|_| ())
        .map_err(|e| format!("cedar parse error: {e}"))
}

#[derive(Debug, Deserialize)]
struct EvalRequest {
    principal: String,
    action: String,
    resource: String,
    #[serde(default)]
    context: serde_json::Value,
}

/// Evaluate a Cedar request against a policy set.
///
/// **SCAFFOLD** per T042 — Feature 002+ wires the full evaluation surface
/// (entity store, schema-typed context, telemetry). Returns `"allow"` or
/// `"deny"` today based on:
///   - Parse both the policy source and the request.
///   - Run `Authorizer::is_authorized` against an empty entity store.
///
/// The property-test gate for this function is Feature 002+ (SC-014 surface c
/// only covers the canonicalization path at Phase 1).
#[rustler::nif(schedule = "DirtyCpu")]
fn evaluate(policy_source: String, request_json: String) -> Result<String, String> {
    let policy_set =
        PolicySet::from_str(&policy_source).map_err(|e| format!("cedar parse error: {e}"))?;

    let parsed: EvalRequest =
        serde_json::from_str(&request_json).map_err(|e| format!("request parse error: {e}"))?;

    let principal =
        EntityUid::from_str(&parsed.principal).map_err(|e| format!("bad principal: {e}"))?;
    let action = EntityUid::from_str(&parsed.action).map_err(|e| format!("bad action: {e}"))?;
    let resource =
        EntityUid::from_str(&parsed.resource).map_err(|e| format!("bad resource: {e}"))?;

    let context = if parsed.context.is_null() {
        Context::empty()
    } else {
        Context::from_json_value(parsed.context, None)
            .map_err(|e| format!("context parse error: {e}"))?
    };

    let request = Request::new(principal, action, resource, context, None)
        .map_err(|e| format!("request build error: {e}"))?;

    let entities = Entities::empty();
    let authorizer = cedar_policy::Authorizer::new();
    let response = authorizer.is_authorized(&request, &policy_set, &entities);

    match response.decision() {
        cedar_policy::Decision::Allow => Ok("allow".to_string()),
        cedar_policy::Decision::Deny => Ok("deny".to_string()),
    }
}

#[derive(Debug, serde::Serialize)]
struct EvalWithEntitiesOutput {
    decision: String,
    matched_policies: Vec<String>,
}

/// Evaluate a Cedar request against a policy set, supplying an explicit entity
/// store + context.
///
/// Unlike `evaluate/2`, this function accepts:
///   * `entities_json` — a JSON array in the Cedar entity-JSON format
///     (`[{ "uid": { "type": "...", "id": "..." }, "attrs": { ... }, "parents": [] }, ...]`)
///     used as the in-memory entity store for this authorization call.
///   * request_json: `{"principal": "...", "action": "...", "resource": "...",
///     "context": { ... }}` — same shape as `evaluate/2`.
///
/// Returns `{ "decision": "allow" | "deny", "matched_policies": [policy_id, ...] }`
/// serialized as a JSON string. Callers on the Elixir side parse the JSON —
/// keeping the NIF surface narrow (one JSON blob in, one JSON blob out).
///
/// Matched-policy IDs are sorted ascending so equal responses hash equal, which
/// simplifies property-test invariance assertions.
#[rustler::nif(schedule = "DirtyCpu")]
fn evaluate_with_entities(
    policy_source: String,
    request_json: String,
    entities_json: String,
) -> Result<String, String> {
    let policy_set =
        PolicySet::from_str(&policy_source).map_err(|e| format!("cedar parse error: {e}"))?;

    let parsed: EvalRequest =
        serde_json::from_str(&request_json).map_err(|e| format!("request parse error: {e}"))?;

    let principal =
        EntityUid::from_str(&parsed.principal).map_err(|e| format!("bad principal: {e}"))?;
    let action = EntityUid::from_str(&parsed.action).map_err(|e| format!("bad action: {e}"))?;
    let resource =
        EntityUid::from_str(&parsed.resource).map_err(|e| format!("bad resource: {e}"))?;

    let context = if parsed.context.is_null() {
        Context::empty()
    } else {
        Context::from_json_value(parsed.context, None)
            .map_err(|e| format!("context parse error: {e}"))?
    };

    let request = Request::new(principal, action, resource, context, None)
        .map_err(|e| format!("request build error: {e}"))?;

    let entities_value: serde_json::Value = serde_json::from_str(&entities_json)
        .map_err(|e| format!("entities parse error: {e}"))?;
    let entities = Entities::from_json_value(entities_value, None)
        .map_err(|e| format!("entities build error: {e}"))?;

    let authorizer = cedar_policy::Authorizer::new();
    let response = authorizer.is_authorized(&request, &policy_set, &entities);

    // Dedupe + sort matched policy IDs so equal authorizations hash equal.
    let mut matched: BTreeSet<String> = BTreeSet::new();
    for policy_id in response.diagnostics().reason() {
        matched.insert(policy_id.to_string());
    }

    let output = EvalWithEntitiesOutput {
        decision: match response.decision() {
            cedar_policy::Decision::Allow => "allow".to_string(),
            cedar_policy::Decision::Deny => "deny".to_string(),
        },
        matched_policies: matched.into_iter().collect(),
    };

    serde_json::to_string(&output).map_err(|e| format!("response encode error: {e}"))
}

rustler::init!("Elixir.Recurse.Cedar.Nif");
