// CommandCell — unit tests for the COMMAND column (!86 fix-pass).
//
// Asserts:
//   - Renders tags.verb as compact mono text
//   - Destructive verbs (rm, sudo, chmod, etc.) tinted text-r5e-warning
//   - forceDenial=true tints text-r5e-danger (semantic — NOT chart-denied,
//     which is reserved for accent surfaces per the !86 review F009).
//   - Empty cell when verb is null

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CommandCell } from "~/components/audit/CommandCell";
import type { ReceiptTags } from "~/lib/tags";

function tagsWith(overrides: Partial<ReceiptTags>): ReceiptTags {
  return {
    category: "subprocess_exec",
    display_summary: "x",
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

describe("CommandCell — verb rendering", () => {
  it("renders tags.verb as text", () => {
    render(<CommandCell tags={tagsWith({ verb: "git" })} />);
    expect(screen.getByTestId("command-text")).toHaveTextContent("git");
    expect(screen.getByTestId("command-text")).toHaveAttribute("data-verb", "git");
  });

  it("renders empty placeholder when verb is null", () => {
    const { container } = render(
      <CommandCell tags={tagsWith({ verb: null as unknown as string })} />,
    );
    expect(screen.queryByTestId("command-text")).not.toBeInTheDocument();
    const placeholder = container.querySelector('span[aria-hidden="true"]');
    expect(placeholder).toBeInTheDocument();
  });
});

describe("CommandCell — destructive verb tint", () => {
  // The DESTRUCTIVE_VERBS set in CommandCell flags writes/escalations/
  // disk operations. Each should render in r5e-warning regardless of
  // tool_kind context.
  const destructive = ["rm", "rmdir", "sudo", "chmod", "chown", "kill", "killall", "shutdown", "reboot", "dd", "mkfs", "fdisk"];

  it.each(destructive)("verb=%s renders in text-r5e-warning", (verb) => {
    render(<CommandCell tags={tagsWith({ verb })} />);
    expect(screen.getByTestId("command-text").className).toContain("text-r5e-warning");
  });

  it("non-destructive verb (e.g. 'git') renders in default text color", () => {
    render(<CommandCell tags={tagsWith({ verb: "git" })} />);
    const cell = screen.getByTestId("command-text");
    expect(cell.className).toContain("text-r5e-text");
    expect(cell.className).not.toContain("text-r5e-warning");
  });
});

describe("CommandCell — denial tone (Rule 01)", () => {
  it("forceDenial=true overrides destructive-verb tint with text-r5e-danger", () => {
    // Even for the most destructive verb, denial supersedes — the row is
    // explicitly forbidden, the warning tint becomes redundant.
    render(<CommandCell tags={tagsWith({ verb: "rm" })} forceDenial />);
    const cell = screen.getByTestId("command-text");
    expect(cell.className).toContain("text-r5e-danger");
    expect(cell.className).not.toContain("text-r5e-warning");
    // Crucial: brief reserves chart-denied for accent surfaces (pill bg/
    // border in ToolCell). Inline text uses the semantic `danger` token.
    expect(cell.className).not.toContain("text-r5e-chart-denied");
  });

  it("forceDenial=true overrides default tone too", () => {
    render(<CommandCell tags={tagsWith({ verb: "git" })} forceDenial />);
    const cell = screen.getByTestId("command-text");
    expect(cell.className).toContain("text-r5e-danger");
    expect(cell.className).not.toContain("text-r5e-text");
  });
});
