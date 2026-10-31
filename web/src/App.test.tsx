// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import report from "../example.issues.json";
import type { Workspace } from "./types";

function workspace(): Workspace {
  return {
    report: structuredClone(report) as Workspace["report"],
    scan: {
      name: "Benchmark shop",
      target: "http://127.0.0.1:8088",
      source: "benchmark/shop",
      report_path: "issues.json",
      modified_at: "2026-10-31T10:00:00Z",
      example: false,
      stats: { sast: {}, dast: {} },
      notes: [],
    },
  };
}

let data: Workspace;
beforeEach(() => {
  window.history.replaceState(null, "", "/");
  data = workspace();
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => data })),
  );
  Object.defineProperty(HTMLElement.prototype, "scrollTo", {
    configurable: true,
    value: vi.fn(),
  });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("analyst workspace", () => {
  it("opens a bookmarked held-back finding without silently selecting another issue", async () => {
    const bookmarked = data.report.issues[1];
    bookmarked.reportable = false;
    window.history.replaceState(null, "", `#${bookmarked.issue_id}`);
    render(<App />);
    const detail = await screen.findByRole("complementary", {
      name: "Finding details",
    });
    expect(
      within(detail).getByRole("heading", { name: bookmarked.title }),
    ).toBeTruthy();
    expect(within(detail).getByText("Held back")).toBeTruthy();
    expect(window.location.hash).toBe(`#${bookmarked.issue_id}`);
  });

  it("opens ranked findings and displays matching code and runtime evidence", async () => {
    render(<App />);
    await screen.findByRole("table", { name: "Ranked security findings" });
    const detail = screen.getByRole("complementary", {
      name: "Finding details",
    });
    expect(within(detail).getByText("Database error induced")).toBeTruthy();
    expect(
      within(detail).getAllByText("app/lib/repositories.php:4").length,
    ).toBeGreaterThan(0);
    expect(window.location.hash).toBe(`#${data.report.issues[0].issue_id}`);
    expect(screen.getByText("Coverage unavailable")).toBeTruthy();
  });

  it("combines search and evidence filtering, and recovers from an empty result", async () => {
    const user = userEvent.setup();
    render(<App />);
    const input = await screen.findByRole("textbox", {
      name: "Search findings",
    });
    await user.type(input, "config.php");
    expect(screen.getAllByRole("row")).toHaveLength(2);
    expect(
      screen.getByRole("heading", { name: "Hard-coded secret" }),
    ).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "1 confirmed" }));
    expect(screen.getByText("No matching findings")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Reset filters" }));
    expect(screen.getAllByRole("row")).toHaveLength(
      data.report.issues.length + 1,
    );
  });

  it("navigates using arrow keys and keeps findings bookmarkable", async () => {
    render(<App />);
    await screen.findByRole("table", { name: "Ranked security findings" });
    const first = screen.getByRole("link", {
      name: data.report.issues[0].title,
    });
    fireEvent.keyDown(first, { key: "ArrowDown" });
    await waitFor(() =>
      expect(window.location.hash).toBe(`#${data.report.issues[1].issue_id}`),
    );
    expect(document.activeElement?.getAttribute("data-issue")).toBe(
      data.report.issues[1].issue_id,
    );
  });

  it("shows incomplete analysis and recorded coverage without assuming authentication success", async () => {
    data.scan.stats.dast = {
      coverage: { deadline_reached: true, points_tested: 4, points_found: 10 },
    };
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Incomplete");
    await user.click(screen.getByRole("button", { name: "Coverage" }));
    expect(
      screen.getByRole("heading", { name: "What this report covers" }),
    ).toBeTruthy();
    expect(
      screen.getByText(/Authentication success is not recorded/),
    ).toBeTruthy();
    expect(screen.getByText("4")).toBeTruthy();
  });

  it("renders payloads as text rather than interpreting HTML", async () => {
    data.report.issues[0].evidence.runtime[0].runtime!.payload =
      '<img src=x onerror="alert(1)">';
    const { container } = render(<App />);
    await screen.findByText('<img src=x onerror="alert(1)">');
    expect(container.querySelector("img")).toBeNull();
  });

  it("makes conflicts discoverable without treating them as ranked issues", async () => {
    data.report.conflicts = [
      {
        sast_ids: ["sast:abc"],
        dast_ids: ["dast:def"],
        reason: "Bound query parameter conflicts with runtime evidence.",
      },
    ];
    const user = userEvent.setup();
    render(<App />);
    await user.click(
      await screen.findByRole("button", { name: "1 need review" }),
    );
    expect(
      screen.getByRole("heading", { name: "Conflicting evidence" }),
    ).toBeTruthy();
    expect(
      screen.getByText(
        "Bound query parameter conflicts with runtime evidence.",
      ),
    ).toBeTruthy();
  });

  it("explains report-loading failures and offers retry", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        json: async () => ({ detail: "No report found." }),
      })),
    );
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      "No report found.",
    );
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });
});
