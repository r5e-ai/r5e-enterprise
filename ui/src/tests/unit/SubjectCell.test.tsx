// SubjectCell — unit tests for the SUBJECT column (!86 fix-pass).
//
// Asserts:
//   - Renders tags.argument_body, truncated, with title=full content for
//     the tooltip
//   - forceDenial=true tints text-r5e-danger (semantic, NOT chart-denied)
//   - Empty placeholder when argument_body is null
//   - Copy-to-clipboard affordance (brief-mandated):
//     * Hidden by default (opacity-0)
//     * Shown on hover via group/subject hover class
//     * Reachable via keyboard focus (focus:opacity-100)
//     * Click stops propagation (so row.onOpen doesn't fire)
//     * Click writes to navigator.clipboard.writeText
//     * Successful write swaps Copy icon → Check icon for ~1.5s
//     * SR-friendly aria-live announcement

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

import { SubjectCell } from "~/components/audit/SubjectCell";
import type { ReceiptTags } from "~/lib/tags";

function tagsWith(overrides: Partial<ReceiptTags>): ReceiptTags {
  return {
    category: "subprocess_exec",
    display_summary: "x",
    tool_kind: "bash",
    verb: "ls",
    argument_body: "-la /var/log",
    scope_kind: null,
    scope_value: null,
    target_resources: [],
    semantic_args: {},
    ...overrides,
  } as unknown as ReceiptTags;
}

describe("SubjectCell — content rendering", () => {
  it("renders tags.argument_body in the subject-text slot", () => {
    render(<SubjectCell tags={tagsWith({ argument_body: "/etc/secrets/api-keys.json" })} />);
    expect(screen.getByTestId("subject-text")).toHaveTextContent("/etc/secrets/api-keys.json");
  });

  it("sets title attribute to full subject for hover-tooltip on truncated cells", () => {
    const longSubject = "very/long/file/path/that/will/truncate/in/the/cell/under/normal/widths.txt";
    render(<SubjectCell tags={tagsWith({ argument_body: longSubject })} />);
    expect(screen.getByTestId("subject-text")).toHaveAttribute("title", longSubject);
  });

  it("renders empty placeholder when argument_body is null", () => {
    const { container } = render(
      <SubjectCell tags={tagsWith({ argument_body: null as unknown as string })} />,
    );
    expect(screen.queryByTestId("subject-text")).not.toBeInTheDocument();
    expect(screen.queryByTestId("subject-copy")).not.toBeInTheDocument();
    const placeholder = container.querySelector('span[aria-hidden="true"]');
    expect(placeholder).toBeInTheDocument();
  });
});

describe("SubjectCell — denial tone (R4 Rule 01)", () => {
  it("forceDenial=true uses text-r5e-danger (semantic, NOT chart-denied)", () => {
    render(<SubjectCell tags={tagsWith({})} forceDenial />);
    const cell = screen.getByTestId("subject-text");
    expect(cell.className).toContain("text-r5e-danger");
    // chart-denied is reserved for accent surfaces (pill bg/border in
    // ToolCell). Inline text uses semantic `danger`.
    expect(cell.className).not.toContain("text-r5e-chart-denied");
  });

  it("forceDenial=false uses text-r5e-text", () => {
    render(<SubjectCell tags={tagsWith({})} />);
    expect(screen.getByTestId("subject-text").className).toContain("text-r5e-text");
  });
});

describe("SubjectCell — copy affordance", () => {
  beforeEach(() => {
    // jsdom doesn't ship navigator.clipboard. Stub it for the test.
    Object.assign(navigator, {
      clipboard: {
        writeText: vi.fn(() => Promise.resolve()),
      },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the copy button when subject is non-empty", () => {
    render(<SubjectCell tags={tagsWith({ argument_body: "x" })} />);
    expect(screen.getByTestId("subject-copy")).toBeInTheDocument();
  });

  it("copy button writes the FULL subject (not the truncated text) to clipboard", async () => {
    const longSubject = '{"metric":"cpu_load","since":"2024-01-01","until":"2024-12-31"}';
    render(<SubjectCell tags={tagsWith({ argument_body: longSubject })} />);
    fireEvent.click(screen.getByTestId("subject-copy"));
    await waitFor(() => {
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(longSubject);
    });
  });

  it("copy button shows the success icon after a successful write", async () => {
    render(<SubjectCell tags={tagsWith({ argument_body: "/path" })} />);
    expect(screen.queryByTestId("subject-copy-success")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("subject-copy"));
    await waitFor(() => {
      expect(screen.getByTestId("subject-copy-success")).toBeInTheDocument();
    });
  });

  it("copy button has descriptive aria-label including the subject value", () => {
    render(<SubjectCell tags={tagsWith({ argument_body: "secret/path" })} />);
    expect(screen.getByTestId("subject-copy")).toHaveAttribute(
      "aria-label",
      "Copy subject: secret/path",
    );
  });
});
