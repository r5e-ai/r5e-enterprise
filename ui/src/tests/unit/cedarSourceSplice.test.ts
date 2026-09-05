// cedarSourceSplice — string-level rewrite of `when {…}` blocks (T-PolicySim
// F002 fix; live two-way binding from condition rows back into the editor
// source per `design/briefs/04-policy-simulator.md`).
//
// We assert:
//   1. Splicing into a source that already has a `when {…}` block
//      preserves pre-existing clauses (e.g. the from-receipt tenant guard)
//      AND adds the row-rendered managed region (F001 BLOCKER fix-pass-2).
//   2. Splicing into a source WITHOUT a `when {…}` block inserts one
//      before the rule's terminating `;`.
//   3. Empty rows on a source with no existing when-block render
//      `when { true }` (vacuous match); on a source with a pre-existing
//      when-block + no sentinels, the source is preserved untouched.
//   4. Per-kind rendering matches the canonical Cedar grammar.
//   5. Idempotency — splicing twice with the same rows returns the same
//      source as splicing once.
//   6. Legacy comma-blob `"a,b,c"` value on `in` is preserved as a chip
//      list (F003 — used to be silently dropped).
//   7. `time_window` / `group_member` honor the user-edited `attr` instead
//      of hardcoding `context.timestamp` / `principal` (F007).
//   8. `findMatchingBrace` / `findRuleTerminator` skip Cedar `//` line
//      comments (F008).

import { describe, expect, it } from "vitest";

import {
  CONDITIONS_SENTINEL_END,
  CONDITIONS_SENTINEL_START,
  renderConditionClause,
  renderWhenBody,
  spliceConditionsIntoCedar,
} from "~/lib/cedarSourceSplice";

describe("renderConditionClause", () => {
  it("renders eq with a quoted string literal", () => {
    expect(
      renderConditionClause({
        kind: "eq",
        attr: "resource.tags.tool_kind",
        value: "bash",
      }),
    ).toBe(`resource.tags.tool_kind == "bash"`);
  });

  it("renders neq", () => {
    expect(
      renderConditionClause({
        kind: "neq",
        attr: "principal.role",
        value: "platform_operator",
      }),
    ).toBe(`principal.role != "platform_operator"`);
  });

  it("renders in with a chip-list", () => {
    expect(
      renderConditionClause({
        kind: "in",
        attr: "resource.tags.verb",
        value: ["rm", "sudo", "chmod"],
      }),
    ).toBe(`resource.tags.verb in ["rm", "sudo", "chmod"]`);
  });

  // F003 — legacy comma-blob string value on `in` round-trips through the
  // shared `coerceChipList` instead of being silently dropped.
  it("renders in with a legacy comma-string value (F003 regression test)", () => {
    expect(
      renderConditionClause({
        kind: "in",
        attr: "resource.tags.verb",
        value: "rm,sudo,chmod",
      }),
    ).toBe(`resource.tags.verb in ["rm", "sudo", "chmod"]`);
  });

  it("renders time_window with both endpoints", () => {
    expect(
      renderConditionClause({
        kind: "time_window",
        attr: "context.timestamp",
        value: ["2026-04-24T09:00Z", "2026-04-24T17:00Z"],
      }),
    ).toBe(
      `context.timestamp >= "2026-04-24T09:00Z" && context.timestamp <= "2026-04-24T17:00Z"`,
    );
  });

  // F007 — splicer must honor a user-edited `attr` for time_window.
  it("renders time_window with a custom attr (F007 regression test)", () => {
    expect(
      renderConditionClause({
        kind: "time_window",
        attr: "context.session_age_seconds",
        value: ["0", "3600"],
      }),
    ).toBe(
      `context.session_age_seconds >= "0" && context.session_age_seconds <= "3600"`,
    );
  });

  it("renders group_member with the Cedar EID syntax", () => {
    expect(
      renderConditionClause({
        kind: "group_member",
        attr: "principal",
        value: "eng-platform",
      }),
    ).toBe(`principal in Group::"eng-platform"`);
  });

  // F007 — splicer must honor a user-edited `attr` for group_member.
  it("renders group_member with a custom LHS attr (F007 regression test)", () => {
    expect(
      renderConditionClause({
        kind: "group_member",
        attr: "resource.owner",
        value: "eng-platform",
      }),
    ).toBe(`resource.owner in Group::"eng-platform"`);
  });

  it("returns null for an empty value (incomplete row)", () => {
    expect(
      renderConditionClause({ kind: "eq", attr: "resource.tags.verb", value: "" }),
    ).toBeNull();
  });

  it("returns null for an empty attr (incomplete row)", () => {
    expect(
      renderConditionClause({ kind: "eq", attr: "", value: "rm" }),
    ).toBeNull();
  });

  it("escapes embedded quotes + backslashes in string literals", () => {
    expect(
      renderConditionClause({
        kind: "eq",
        attr: "resource.tags.semantic_args.host",
        value: 'evil"host\\foo',
      }),
    ).toBe(`resource.tags.semantic_args.host == "evil\\"host\\\\foo"`);
  });
});

describe("renderWhenBody", () => {
  it("returns 'true' (vacuous match) for empty rows", () => {
    expect(renderWhenBody([])).toBe("  true");
  });

  it("joins clauses with `&&` on separate lines", () => {
    const body = renderWhenBody([
      { kind: "eq", attr: "resource.tags.tool_kind", value: "bash" },
      { kind: "neq", attr: "principal.role", value: "platform_operator" },
    ]);
    expect(body).toBe(
      `  resource.tags.tool_kind == "bash" &&\n  principal.role != "platform_operator"`,
    );
  });

  it("drops incomplete rows from the body", () => {
    const body = renderWhenBody([
      { kind: "eq", attr: "resource.tags.tool_kind", value: "bash" },
      { kind: "eq", attr: "principal.role", value: "" }, // incomplete
    ]);
    expect(body).toBe(`  resource.tags.tool_kind == "bash"`);
  });
});

describe("spliceConditionsIntoCedar", () => {
  it("appends a sentinel-managed region to an existing when {…} body, preserving the seed clause", () => {
    const source = `permit(
  principal,
  action,
  resource
) when {
  principal.tenant_id == "tenant-acme"
};
`;
    const next = spliceConditionsIntoCedar(source, [
      { kind: "eq", attr: "resource.tags.verb", value: "rm" },
    ]);
    // Pre-existing seed clause preserved.
    expect(next).toContain(`principal.tenant_id == "tenant-acme"`);
    // Sentinel pair emitted.
    expect(next).toContain(CONDITIONS_SENTINEL_START);
    expect(next).toContain(CONDITIONS_SENTINEL_END);
    // Row clause inside the sentinel region.
    expect(next).toContain(`resource.tags.verb == "rm"`);
    expect(next.endsWith("};\n")).toBe(true);
  });

  it("inserts a sentinel-bracketed when {…} block before the terminating `;` when none exists", () => {
    const source = `permit(
  principal,
  action,
  resource
);
`;
    const next = spliceConditionsIntoCedar(source, [
      { kind: "eq", attr: "resource.tags.verb", value: "rm" },
    ]);
    // Per fix-pass-2 — fresh insertion with rows emits the sentinel
    // markers so the next splice can find + replace just the managed
    // region (idempotency contract).
    expect(next).toContain(`resource.tags.verb == "rm"`);
    expect(next).toContain(CONDITIONS_SENTINEL_START);
    expect(next).toContain(CONDITIONS_SENTINEL_END);
    expect(next).toMatch(/;\s*$/); // terminator preserved
  });

  // F001 BLOCKER — the from-receipt skeleton's tenant guard MUST survive
  // the very first splice with empty rows.
  it("preserves the tenant guard when empty rows splice into a from-receipt skeleton (F001)", () => {
    const seed = `permit(
  principal,
  action == Action::"tool_call",
  resource
) when {
  principal.tenant_id == "tenant-acme"
};
`;
    const next = spliceConditionsIntoCedar(seed, []);
    // Tenant guard MUST be intact.
    expect(next).toContain(`principal.tenant_id == "tenant-acme"`);
    // No `when { true }` wipe.
    expect(next).not.toMatch(/when\s*\{\s*true\s*\}/);
    // No-op when there's nothing to manage.
    expect(next).toBe(seed);
  });

  // F001 follow-up — tenant guard survives subsequent edits too: add a
  // row, remove the row, the guard is still there.
  it("preserves the tenant guard across add → remove row cycles (F001)", () => {
    const seed = `permit(
  principal,
  action,
  resource
) when {
  principal.tenant_id == "tenant-acme"
};
`;
    const withRow = spliceConditionsIntoCedar(seed, [
      { kind: "eq", attr: "resource.tags.verb", value: "rm" },
    ]);
    expect(withRow).toContain(`principal.tenant_id == "tenant-acme"`);
    expect(withRow).toContain(`resource.tags.verb == "rm"`);

    const empty = spliceConditionsIntoCedar(withRow, []);
    expect(empty).toContain(`principal.tenant_id == "tenant-acme"`);
    // Sentinel region is preserved (empty managed region) so the next
    // splice can find it; the row clause is gone.
    expect(empty).not.toContain(`resource.tags.verb == "rm"`);
    expect(empty).toContain(CONDITIONS_SENTINEL_START);
  });

  it("renders an empty when {…} block as `when { true }` ONLY when no when-block existed", () => {
    // No when-block + empty rows → freshly-inserted `when { true }`.
    const source = `permit(
  principal,
  action,
  resource
);
`;
    const next = spliceConditionsIntoCedar(source, []);
    expect(next).toContain(`when {\n  true\n}`);
  });

  it("is idempotent under repeated application (no when-block path)", () => {
    const source = `permit(
  principal,
  action,
  resource
);
`;
    const rows = [
      { kind: "eq" as const, attr: "resource.tags.tool_kind", value: "bash" },
      { kind: "in" as const, attr: "resource.tags.verb", value: ["rm", "sudo"] },
    ];
    const once = spliceConditionsIntoCedar(source, rows);
    const twice = spliceConditionsIntoCedar(once, rows);
    expect(twice).toBe(once);
  });

  it("is idempotent under repeated application (existing-when-block path with seed)", () => {
    const source = `permit(
  principal,
  action,
  resource
) when {
  principal.tenant_id == "tenant-acme"
};
`;
    const rows = [
      { kind: "eq" as const, attr: "resource.tags.tool_kind", value: "bash" },
    ];
    const once = spliceConditionsIntoCedar(source, rows);
    const twice = spliceConditionsIntoCedar(once, rows);
    expect(twice).toBe(once);
    // And the tenant guard survives both passes.
    expect(twice).toContain(`principal.tenant_id == "tenant-acme"`);
  });

  it("returns the source unchanged when there is no rule terminator", () => {
    const source = "// just a comment, no permit/forbid";
    expect(
      spliceConditionsIntoCedar(source, [
        { kind: "eq", attr: "resource.tags.tool_kind", value: "bash" },
      ]),
    ).toBe(source);
  });

  // F008 — Cedar `//` line comments don't confuse the brace walker.
  it("walks past `//` line comments containing `}` or `;` (F008)", () => {
    const source = `permit(
  principal,
  action,
  resource
) when {
  // closing brace } in a comment shouldn't end the block;
  principal.tenant_id == "tenant-acme"
};
`;
    const next = spliceConditionsIntoCedar(source, [
      { kind: "eq", attr: "resource.tags.verb", value: "rm" },
    ]);
    expect(next).toContain(`principal.tenant_id == "tenant-acme"`);
    expect(next).toContain(`resource.tags.verb == "rm"`);
    // The comment text is preserved.
    expect(next).toContain(
      `// closing brace } in a comment shouldn't end the block`,
    );
  });
});
