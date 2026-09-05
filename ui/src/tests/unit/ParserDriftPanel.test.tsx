// ParserDriftPanel (spec 012 S4) — renders nothing when empty; lists
// discriminator / format / count / sample when rows exist.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ParserDriftPanelView } from "~/components/audit/ParserDriftPanel";

describe("ParserDriftPanelView", () => {
  it("renders nothing when there are no rows", () => {
    const { container } = render(<ParserDriftPanelView events={[]} newSinceBoot={0} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("lists each drift row with its type, format, count and keys-only sample", () => {
    render(
      <ParserDriftPanelView
        newSinceBoot={1}
        events={[
          {
            id: 1,
            api_format: "anthropic_messages",
            event_type: "block:widget",
            sample_redacted: "keys=payload,type",
            first_seen: "2026-09-02T10:00:00Z",
            last_seen: "2026-09-02T10:05:00Z",
            count: 3,
          },
        ]}
      />,
    );
    expect(screen.getByTestId("parser-drift-panel")).toBeInTheDocument();
    expect(screen.getAllByTestId("parser-drift-row")).toHaveLength(1);
    expect(screen.getByText("block:widget")).toBeInTheDocument();
    expect(screen.getByText("anthropic_messages")).toBeInTheDocument();
    expect(screen.getByText("keys=payload,type")).toBeInTheDocument();
    expect(screen.getByTestId("parser-drift-count")).toHaveTextContent("1 type · 1 new since boot");
    expect(screen.getByText(/×3/)).toBeInTheDocument();
  });
});
