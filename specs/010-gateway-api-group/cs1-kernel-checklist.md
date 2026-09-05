# CS-1 — kernel checklist (from the verification pass on contract r2, 2026-09-02)

The concrete kernel functions schema-lite-v2 r2 changes, by section. File:line against r5e-kernel at bookmark `fold/kp-1-4`. Sub-slices: **1a** validator + naming + meta-Kind + receipt + spec text; **1b** refs/resolve/manifest/replay/export/verifier; **1c** CasObject; **1d** commit protocol.

| § | Function | file:line | Change | Sub-slice |
|---|---|---|---|---|
| §2:38 left-split | `resolve_resource_ref/3` | resource_store.ex:93-95 | `String.split(ref, "/")` matching exactly 4 segments → left-split into 3 + remainder; :106 must stop reporting slash-bearing names as unrecognized | 1a |
| §2 / §6 | `resolve/2` `$ref` clause | resource_store.ex:60-75 | dispatches only on `valid_address?` (`sha256:`) vs 4-segment path; add `event:` and `bytes:` hydration arms per §6 | 1b |
| §2 server | `record/5` payload | admission.ex:149 | omit `target.name` for server-mode creates; entry name derived from `event["hash"]` | 1a |
| §2 all modes | `default_name/2` | admission.ex:124-135 | six modes; caller-name rejection/equality rules | 1a |
| §2 readmit | `do_admit/2` + `ResourceStore.put/5` | admission.ex:181-183, resource_store.ex:22-24 | per-mode deny/supersede/idempotent; `supersededBy`, `admissionEvent`, `actor` on the entry | 1a |
| §1/§3 | `R5e.Kind.from_map/1` | kind.ex:33-51 | parse `naming` (deny malformed), `description`; malformed scope denies | 1a |
| §3 | `R5e.Kind.to_map/1` | kind.ex:72-83 | add `naming`, `description`, `derivedFrom` (feeds `GET /apis`, export) | 1a |
| §4 pipeline | `admit/1` with-chain | admission.ex:38-44 | seven stages: authenticate → validateStructure → resolve → authorize → validateConstraints → record → admit | 1a (resolve as pass-through), 1b (real resolve) |
| §3 | `validate_instance/2` | kind.ex:91-117 | `nonEmpty`, `enum`, `pattern` (RE2 full match), `minimum`/`maximum`, `exactlyOne`, `requires`, nested `properties`/`items`/`values`, `additionalProperties`, ref-wrapper form, limits | 1a |
| §0 | `empty?/1` | kind.ex:141-143 | split into `exists` and `nonEmpty` | 1a |
| §3 no floats | `type_matches?/2` | kind.ex:145-151 | `"number"` admits floats; unknown types accepted; add the recursive no-float scan | 1a |
| §1 scope | `scope_or_default/1` | kind.ex:119-124 | malformed must deny | 1a |
| §1 duplicates | `KindRegistry.put/1` | kind_registry.ex:13-15 | deny unless byte-identical; §11 transition is the one exempt act | 1a |
| §1 meta-checks | `check_kind_definition/2` | admission.ex:115-122 | enforce §1:34 (undeclared keywords, illegal combos, undeclared names, empty exactlyOne, uncompilable regex) | 1a |
| §9 receipt | `receipt/7` | admission.ex:194-207 | add `eventRef`, `derivedFrom`; `resolvedRefs` | 1a (eventRef, derivedFrom), 1b (resolvedRefs) |
| §5 | `R5e.CAS.put/1` | cas.ex:20-34 | bytes written only as the admit step of a granted CasObject; reference index for the sweeper | 1c |
| §5/§6 | `RecurseVerify.CAS.valid_address?/1` | r5e-core/verifier/.../cas.ex:11-15 | accept `bytes:sha256:` and `event:sha256:` | 1b |
| §7 | `R5e.Log.handle_call({:append,…})` | log.ex:95-107 | append lock + generation re-check + `contended`/`halted` | 1d |
| §7 | `R5e.Policy.decide/1` | policy.ex:54-62 | captured bundle/shape generation in meta | 1d |
| §6 export | `collect_addrs/1` | export.ex:91-95, :75 | match `bytes:` and `sha256:` bare or inside `$ref` | 1b |
| §4 replay | `R5e.Bootstrap.replay/0` | bootstrap.ex:37-76 | copy `resolvedRefs`; carry `supersededBy`/`admissionEvent`/`actor`; derive server names from `event["hash"]` | 1a (entries), 1b (resolvedRefs) |
| §11 | `seed_core_kinds/0` | bootstrap.ex:86-108 | v2 meta-Kind; the transition act (actor `system:bootstrap`, reason `schema-lite-v2 migration`); `derivedFrom` envelope | 1a |
| §5 router | `R5e.HTTP.Router` | http/router.ex | `PUT /cas`, `GET /cas/:addr` | 1c |
| §2 router | single-instance GET | http/router.ex:60 | slash-bearing names: glob + left-split | 1a |
