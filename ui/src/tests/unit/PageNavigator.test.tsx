// PageNavigator — tests for the paginated footer (#32).

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { PageNavigator } from "~/components/audit/PageNavigator";

describe("PageNavigator", () => {
  it("renders 'Page 1 — N loaded' when total_count is null (backend lacks total)", () => {
    render(
      <PageNavigator
        currentPageIndex={0}
        loadedCount={42}
        totalCount={null}
        hasMore={false}
        isFetching={false}
        onPageChange={vi.fn()}
      />,
    );
    const status = screen.getByTestId("page-navigator-status");
    expect(status.textContent).toMatch(/Page\s+1\s+—\s+42 loaded/);
  });

  it("renders 'Page X of Y — N total' when total_count is provided", () => {
    render(
      <PageNavigator
        currentPageIndex={1}
        loadedCount={50}
        totalCount={150}
        hasMore={true}
        isFetching={false}
        onPageChange={vi.fn()}
      />,
    );
    expect(screen.getByTestId("page-navigator-status").textContent).toMatch(
      /Page\s+2\s+of\s+3\s+—\s+150 total/,
    );
  });

  it("disables Previous on the first page", () => {
    render(
      <PageNavigator
        currentPageIndex={0}
        loadedCount={50}
        totalCount={null}
        hasMore={true}
        isFetching={false}
        onPageChange={vi.fn()}
      />,
    );
    expect(screen.getByTestId("page-navigator-prev")).toBeDisabled();
  });

  it("disables Next when no more pages exist (totalCount fully loaded)", () => {
    render(
      <PageNavigator
        currentPageIndex={1}
        loadedCount={75}
        totalCount={75}
        hasMore={false}
        isFetching={false}
        onPageChange={vi.fn()}
      />,
    );
    // total=75 → 2 pages (50 + 25); current=1 means we're on the last page.
    expect(screen.getByTestId("page-navigator-next")).toBeDisabled();
  });

  it("enables Next when hasMore=true even without total_count", () => {
    render(
      <PageNavigator
        currentPageIndex={0}
        loadedCount={50}
        totalCount={null}
        hasMore={true}
        isFetching={false}
        onPageChange={vi.fn()}
      />,
    );
    expect(screen.getByTestId("page-navigator-next")).not.toBeDisabled();
  });

  it("disables both Prev/Next while a fetch is in flight", () => {
    render(
      <PageNavigator
        currentPageIndex={1}
        loadedCount={50}
        totalCount={150}
        hasMore={true}
        isFetching={true}
        onPageChange={vi.fn()}
      />,
    );
    expect(screen.getByTestId("page-navigator-prev")).toBeDisabled();
    expect(screen.getByTestId("page-navigator-next")).toBeDisabled();
  });

  it("calls onPageChange with the next page index when Next is clicked", () => {
    const onPageChange = vi.fn();
    render(
      <PageNavigator
        currentPageIndex={1}
        loadedCount={150}
        totalCount={150}
        hasMore={false}
        isFetching={false}
        onPageChange={onPageChange}
      />,
    );
    fireEvent.click(screen.getByTestId("page-navigator-next"));
    expect(onPageChange).toHaveBeenCalledWith(2);
  });

  it("calls onPageChange with the previous page index when Previous is clicked", () => {
    const onPageChange = vi.fn();
    render(
      <PageNavigator
        currentPageIndex={2}
        loadedCount={150}
        totalCount={150}
        hasMore={false}
        isFetching={false}
        onPageChange={onPageChange}
      />,
    );
    fireEvent.click(screen.getByTestId("page-navigator-prev"));
    expect(onPageChange).toHaveBeenCalledWith(1);
  });

  it("renders explicit page-number buttons + marks the current as aria-current", () => {
    render(
      <PageNavigator
        currentPageIndex={1}
        loadedCount={150}
        totalCount={150}
        hasMore={false}
        isFetching={false}
        onPageChange={vi.fn()}
      />,
    );
    // 150 / 50 = 3 pages → labels 1, 2, 3
    const p1 = screen.getByTestId("page-navigator-page-1");
    const p2 = screen.getByTestId("page-navigator-page-2");
    const p3 = screen.getByTestId("page-navigator-page-3");
    expect(p1).not.toHaveAttribute("aria-current", "page");
    expect(p2).toHaveAttribute("aria-current", "page");
    expect(p3).not.toHaveAttribute("aria-current", "page");
  });

  it("clicking a page button jumps directly to that page", () => {
    const onPageChange = vi.fn();
    render(
      <PageNavigator
        currentPageIndex={0}
        loadedCount={500}
        totalCount={500}
        hasMore={false}
        isFetching={false}
        onPageChange={onPageChange}
      />,
    );
    fireEvent.click(screen.getByTestId("page-navigator-page-10"));
    expect(onPageChange).toHaveBeenCalledWith(9);
  });

  it("renders ellipsis sentinels when the page count is large", () => {
    render(
      <PageNavigator
        currentPageIndex={5}
        loadedCount={1000}
        totalCount={1000}
        hasMore={false}
        isFetching={false}
        onPageChange={vi.fn()}
      />,
    );
    expect(screen.getAllByText("…").length).toBeGreaterThan(0);
  });
});
