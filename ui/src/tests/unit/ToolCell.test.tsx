// ToolCell — unit tests for the TOOL column pill (!86 fix-pass per
// adversarial review F002 + F004 + F006).
//
// Asserts:
//   - Each tool_kind maps to the correct R4 chart-token via classesFor.
//     Specifically catches the F001 BLOCKER class of bug — a renamed token
//     that doesn't exist in tailwind.config.ts (Tailwind 3 JIT silently
//     drops it; component renders unstyled). The literal class strings
//     emitted into className MUST match the tokens exposed in the config.
//     The cross-cutting tailwindTokens.test.ts catches that automatically;
//     this file pins the per-kind mapping so the cells render the right
//     palette.
//   - MCP[<server>] label format when tags.semantic_args.server is set.
//   - forceDenial=true forces chart-denied tone AND prepends the Lucide
//     Ban (⊘) glyph (R4 Rule 01 — deny-trumps).
//   - Empty cells render only a non-breaking space placeholder.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ToolCell } from "~/components/audit/ToolCell";
import type { ReceiptTags } from "~/lib/tags";

function tagsWith(overrides: Partial<ReceiptTags>): ReceiptTags {
  // Cast to ReceiptTags via Record so we don't redeclare the full schema
  // here — the component only reads tool_kind + semantic_args.server.
  return {
    category: "subprocess_exec",
    display_summary: "irrelevant for these tests",
    tool_kind: "bash",
    verb: "ls",
    argument_body: "-la",
    scope_kind: null,
    scope_value: null,
    target_resources: [],
    semantic_args: {},
    ...overrides,
  } as unknown as ReceiptTags;
}

describe("ToolCell — tool_kind → chart-token mapping", () => {
  // Pin each tool_kind to the canonical short token name. If a future
  // refactor invents a non-existent token (the F001 bug), one of these
  // assertions trips, AND the cross-cutting tailwindTokens.test.ts trips
  // independently. Defense in depth.
  const cases: Array<{ tool_kind: string; expectedToken: string; expectedLabel: string }> = [
    { tool_kind: "bash", expectedToken: "chart-subprocess", expectedLabel: "Bash" },
    { tool_kind: "edit", expectedToken: "chart-file-write", expectedLabel: "Edit" },
    { tool_kind: "notebook_edit", expectedToken: "chart-file-write", expectedLabel: "Notebook" },
    { tool_kind: "read", expectedToken: "chart-file-read", expectedLabel: "Read" },
    { tool_kind: "search", expectedToken: "chart-search", expectedLabel: "Search" },
    { tool_kind: "agent", expectedToken: "chart-agent", expectedLabel: "Agent" },
    { tool_kind: "webfetch", expectedToken: "chart-network", expectedLabel: "WebFetch" },
    { tool_kind: "llm", expectedToken: "chart-llm", expectedLabel: "LLM" },
    { tool_kind: "todo", expectedToken: "chart-todo", expectedLabel: "Todo" },
    { tool_kind: "unknown_kind", expectedToken: "chart-ui", expectedLabel: "—" },
  ];

  it.each(cases)(
    "tool_kind=$tool_kind renders pill with text-r5e-$expectedToken + label '$expectedLabel'",
    ({ tool_kind, expectedToken, expectedLabel }) => {
      render(<ToolCell tags={tagsWith({ tool_kind })} />);
      const pill = screen.getByTestId("tool-pill");
      expect(pill.className).toContain(`text-r5e-${expectedToken}`);
      expect(pill.className).toContain(`bg-r5e-${expectedToken}/15`);
      expect(pill.className).toContain(`border-r5e-${expectedToken}`);
      expect(pill).toHaveAttribute("data-tool-kind", tool_kind);
      // The 'unknown_kind' default branch falls through to chart-ui + label '—'
      if (expectedLabel !== "—") {
        expect(pill).toHaveTextContent(expectedLabel);
      }
    },
  );
});

describe("ToolCell — MCP server-suffix label", () => {
  it("renders 'MCP[datadog]' when tags.semantic_args.server is 'datadog'", () => {
    render(
      <ToolCell
        tags={tagsWith({
          tool_kind: "mcp",
          semantic_args: { server: "datadog" },
        })}
      />,
    );
    expect(screen.getByTestId("tool-pill")).toHaveTextContent("MCP[datadog]");
  });

  it("renders bare 'MCP' when semantic_args.server is missing", () => {
    render(
      <ToolCell
        tags={tagsWith({
          tool_kind: "mcp",
          semantic_args: {},
        })}
      />,
    );
    expect(screen.getByTestId("tool-pill")).toHaveTextContent("MCP");
    expect(screen.getByTestId("tool-pill")).not.toHaveTextContent("MCP[");
  });

  it("escapes bracket syntax — 'MCP[github]' for github server", () => {
    render(
      <ToolCell
        tags={tagsWith({
          tool_kind: "mcp",
          semantic_args: { server: "github" },
        })}
      />,
    );
    expect(screen.getByTestId("tool-pill")).toHaveTextContent("MCP[github]");
  });

  // Runtime-narrow regression guards (F009 from MR !86 GAN review).
  // ReceiptTags.semantic_args is `Record<string, unknown> | null`, so a
  // future producer could put a non-string under `server`. Pre-fix this
  // was a compile-time `as` cast and the label rendered
  // `MCP[[object Object]]` / `MCP[42]` etc.; post-fix the resolver
  // narrows defensively and falls back to bare `MCP`.

  it.each([
    ["object", { kind: "datadog", region: "us" }],
    ["number", 42],
    ["null", null],
    ["array", ["datadog"]],
    ["boolean", true],
  ])(
    "renders bare 'MCP' (no [...]) when semantic_args.server is a %s",
    (_label, badServer) => {
      render(
        <ToolCell
          tags={tagsWith({
            tool_kind: "mcp",
            semantic_args: { server: badServer },
          })}
        />,
      );
      expect(screen.getByTestId("tool-pill")).toHaveTextContent("MCP");
      expect(screen.getByTestId("tool-pill")).not.toHaveTextContent("MCP[");
    },
  );
});

describe("ToolCell — denial branch (R4 Rule 01)", () => {
  it("forceDenial=true forces chart-denied tone regardless of underlying tool_kind", () => {
    render(<ToolCell tags={tagsWith({ tool_kind: "bash" })} forceDenial />);
    const pill = screen.getByTestId("tool-pill");
    expect(pill.className).toContain("text-r5e-chart-denied");
    expect(pill.className).toContain("bg-r5e-chart-denied/15");
    expect(pill.className).toContain("border-r5e-chart-denied");
    // Must NOT have the underlying chart-subprocess token leaking through
    expect(pill.className).not.toContain("text-r5e-chart-subprocess");
    expect(pill).toHaveAttribute("data-denial", "true");
  });

  it("forceDenial=true prepends the Ban icon (⊘ — Lucide Ban)", () => {
    render(<ToolCell tags={tagsWith({ tool_kind: "bash" })} forceDenial />);
    expect(screen.getByTestId("tool-pill-denial-icon")).toBeInTheDocument();
  });

  it("forceDenial=false omits the Ban icon", () => {
    render(<ToolCell tags={tagsWith({ tool_kind: "bash" })} />);
    expect(screen.queryByTestId("tool-pill-denial-icon")).not.toBeInTheDocument();
    expect(screen.getByTestId("tool-pill")).toHaveAttribute("data-denial", "false");
  });
});

describe("ToolCell — empty / null tool_kind", () => {
  it("renders only a non-breaking space when tags is null", () => {
    const { container } = render(<ToolCell tags={null} />);
    expect(screen.queryByTestId("tool-pill")).not.toBeInTheDocument();
    // The component renders <span aria-hidden="true">&nbsp;</span> as a
    // width-holding placeholder; verify it's there.
    const placeholder = container.querySelector('span[aria-hidden="true"]');
    expect(placeholder).toBeInTheDocument();
  });

  it("renders only a non-breaking space when tool_kind is null", () => {
    render(<ToolCell tags={tagsWith({ tool_kind: null as unknown as string })} />);
    expect(screen.queryByTestId("tool-pill")).not.toBeInTheDocument();
  });
});
