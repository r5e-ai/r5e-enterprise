# Mandatory admission amendment (2026-09-04)

This supersedes the transitional dual-write behavior in plan sections 17–21.
It implements the handbook's one-decision and policy-jurisdiction decisions.
The public release candidate uses the kernel as an execution prerequisite.

## Concrete ownership, without a general federation mechanism

The kernel owns admission of core resources and gateway operational records:
CAS, vocabulary, authority, policy configuration, sessions, prompts, completions,
and response observations. Its own admitted policy decides those operations.
Gateway workload policy decides only `gateway.r5e.io/v1alpha1/LlmCall` and
`gateway.r5e.io/v1alpha1/ToolCall`. A gateway PolicyBundle declares those exact
Kind paths in `governs`; the schema cannot name core or policy-management Kinds.
Calls outside this jurisdiction are routed to kernel policy, never treated as
a workload-policy denial or a synthetic allow.

The fold service key signs admissions and exercises its existing, bounded node
Endorsement. Client identity metadata remains observed input. A tenant-supplied
scope cannot alter this routing, widen an Endorsement, define core vocabulary,
or replace kernel policy. Gateway bundle and shape changes require authority
and are constrained to their owner; bootstrap is not a public missing-policy
fallback. General organization/team/session policy hierarchies remain future
work; this release implements the actual core/gateway boundary.

## Workload inputs

LlmCall and ToolCall gain `gatewayContext`, a schema-declared object containing
the gateway policy inputs: tenant, session, model, transport, observed client
principal and groups, request/response hashes, token estimate, tool argument
hash/size and index. These facts are signed by the gateway/fold service as its
observations; they are not a client signature or an identity endorsement.

The gateway-specific Cedar presentation retains the prior `User` principal
vocabulary for these observations while the admission envelope separately
identifies the cryptographically verified service signer and authority. The
evaluation record captures the exact presentation. A policy author can inspect
both; a client-asserted group must never be described as authenticated.

The active admitted bundle is read at each admission and its generation is
rechecked by the kernel commit protocol. An already admitted intent keeps its
decision; a later intent uses current policy. A call-start gateway cache cannot
override that decision. Changes during a stream therefore affect subsequent
intents, not an act already admitted.

## Ordering and failures

1. Before forwarding a model request, retain its bounded raw request bytes,
   admit the Prompt and LlmCall, and keep their references in transport state.
2. At each parser-held tool boundary, admit ToolCall and enforce that result.
   No gateway decision cache and no later re-evaluation grants permission.
3. Record Completion/LlmResponse against those actual references. Completion
   recording is not a second admission of the original model/tool intent.
4. Missing admission, revoked authority, persistence errors, unsupported or
   malformed executable output stop the affected operation. Readiness reports
   availability but cannot replace a per-operation admission.
5. Policy loaders stage bytes and obtain admission before updating their
   local projection. Refused replacement leaves the previous policy effective.

An opening admission followed by no completion is incomplete evidence, never
evidence of success. We cannot retract bytes already delivered before a later
storage failure. Tool bytes do not escape before their own durable admission;
terminal stream handling must report an interruption if completion recording
fails. No claim is made that a permitted client-side tool actually executed.

## Migration

Existing local demo chains retain their original bytes and receipts. Updated
gateway KindDefinitions use the existing signed same-identity transition path.
Deployment policy is replaced by an explicit admitted activation rather than
silently overwritten at every boot. Incompatible old policy scope must be
reported and require admitted replacement; never fall back to unrestricted
work. New release artifacts are not published until Thomas approves the
release-chain sequence.
