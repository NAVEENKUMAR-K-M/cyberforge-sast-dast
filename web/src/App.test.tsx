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
    await waitFor(() => expect(window.location.hash).toBe(`#${data.report.issues[0].issue_id}`));
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

  it("shows the judge-facing workflow, report kind, and PRD capability labels", async () => {
    data.scan.example = true;
    render(<App />);
    expect(await screen.findByText("EXAMPLE REPORT · SAMPLE DATA")).toBeTruthy();
    expect(screen.getByText("Core · Scan")).toBeTruthy();
    expect(screen.getByText("Core · Correlate + auto-verify")).toBeTruthy();
    expect(screen.getByText("Bonus · AI-assisted, when a provider is configured")).toBeTruthy();
    await userEvent.click(screen.getByText(/PRD capability board/));
    expect(screen.getByText("Core · FR-1–FR-10")).toBeTruthy();
    expect(screen.getByText("Bonus · B-1–B-7")).toBeTruthy();
    expect(screen.getByText("AI-assisted · automatic when configured")).toBeTruthy();
  });

  it("shows a distinct Need review view for conflicts", async () => {
    data.report.conflicts = [{ sast_ids: ["sast:abc"], dast_ids: ["dast:def"], reason: "Review the conflicting evidence." }];
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: /Need review/ }));
    expect(screen.getByRole("heading", { name: "Conflicting evidence" })).toBeTruthy();
    expect(screen.getByText("Review the conflicting evidence.")).toBeTruthy();
  });

  it("separates an AI follow-up plan from executed runtime evidence and its stop reason", async () => {
    data.report.investigations = [{
      case_id: "case-1", issue_id: data.report.issues[0].issue_id, outcome: "unresolved",
      stop_reason: "budget exhausted", rounds: [{ round: 2, plan: { method: "GET", location: "query" },
        requests_sent: [{ method: "GET", url: "http://127.0.0.1:8088/search?q=test", status: 200, length: 42 }],
        outcome: "no reproduction", evidence: { level: "unchecked", reason: "No validated signal." } }],
    }];
    render(<App />);
    expect(await screen.findByText("Investigation outcomes")).toBeTruthy();
    expect(screen.getByText("Stop reason: budget exhausted")).toBeTruthy();
    expect(screen.getByText("Planned request fields:")).toBeTruthy();
    expect(screen.getByText("Requests actually sent (1):")).toBeTruthy();
    expect(screen.getByText(/Only runtime evidence accepted by the correlator/)).toBeTruthy();
  });

  it("keeps many investigation outcomes inside a bounded, scrollable list rather than growing the page", async () => {
    data.report.investigations = Array.from({ length: 15 }, (_, i) => ({
      case_id: `case-${i}`, issue_id: data.report.issues[0].issue_id, outcome: "unresolved",
      stop_reason: "round limit reached", rounds: [{ round: 1, plan: { method: "GET", location: "query" },
        requests_sent: [], outcome: "no reproduction", evidence: null }],
    }));
    render(<App />);
    expect(await screen.findByText("15 cases · AI proposal is not proof")).toBeTruthy();
    const summaries = screen.getAllByText("round limit reached", { exact: false });
    expect(summaries).toHaveLength(15);
    const scrollBox = document.querySelector(".ai-outcomes-scroll")!;
    expect(scrollBox).toBeTruthy();
    expect(scrollBox.querySelectorAll("details")).toHaveLength(15);
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

  it("tags a finding as AI-assisted only when a planner round produced the link", async () => {
    const [assisted, plain] = data.report.issues;
    assisted.investigation = {
      case_id: "case-ai", outcome: "validated", stop_reason: "the runtime evidence shows the weakness itself",
      rounds: 2, ai_assisted: true,
    };
    plain.investigation = {
      case_id: "case-plain", outcome: "unresolved", stop_reason: "round limit reached", rounds: 2, ai_assisted: false,
    };
    render(<App />);
    const assistedLink = await screen.findByRole("link", { name: assisted.title });
    const assistedRow = assistedLink.closest("tr")!;
    expect(within(assistedRow).getByText("AI-assisted")).toBeTruthy();
    const plainRow = screen.getByRole("link", { name: plain.title }).closest("tr")!;
    expect(within(plainRow).queryByText("AI-assisted")).toBeNull();
    await userEvent.click(assistedLink);
    const detail = await screen.findByRole("complementary", { name: "Finding details" });
    expect(within(detail).getByText("AI-assisted")).toBeTruthy();
    expect(within(detail).getByText(/an AI provider proposed/)).toBeTruthy();
  });

  it("scans a custom application from its source folder and URL", async () => {
    const posted: Record<string, unknown>[] = [];
    const queued = {
      id: "j1", target_name: "Custom application (shop)", target_url: "http://host.docker.internal:8081", status: "queued",
      stage: "Queued", created_at: "2026-11-01T00:00:00Z", started_at: null, completed_at: null,
      options: { run_sast: true, run_dast: true }, logs: [], error: null, report_path: "out/scans/j1/issues.json", gate: null,
    };
    const custom = {
      id: "custom", name: "Custom application", url: "", language: "auto", sast_supported: true, source_available: true,
      custom: true, default_source: "/workspace", description: "Scan any application on this machine.",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        const path = String(url);
        if (path.startsWith("/api/targets")) return { ok: true, json: async () => ({ targets: [custom] }) };
        if (path === "/api/scans" && init?.method === "POST") {
          posted.push(JSON.parse(String(init.body)));
          return { ok: true, json: async () => queued };
        }
        if (path.startsWith("/api/scans")) return { ok: true, json: async () => ({ scans: [] }) };
        return { ok: true, json: async () => data };
      }),
    );
    const user = userEvent.setup();
    render(<App />);
    const source = (await screen.findByLabelText("Source folder")) as HTMLInputElement;
    expect(source.value).toBe("/workspace");
    await user.type(screen.getByLabelText("Runtime URL"), "http://host.docker.internal:8081");
    await user.selectOptions(screen.getByLabelText("Source language"), "python");
    await user.click(screen.getByRole("button", { name: /Start scan/ }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toMatchObject({
      target_id: "custom", source_path: "/workspace", language: "python", target_url: "http://host.docker.internal:8081",
      run_sast: true, run_dast: true, use_route_map: true,
    });
  });

  it("explains report-loading failures and offers retry", async () => {
    // Only the report fails. The scan launcher's own requests succeed, so only the report view shows an alert.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        String(url).startsWith("/api/report")
          ? { ok: false, json: async () => ({ detail: "No report found." }) }
          : { ok: true, json: async () => ({ targets: [], scans: [] }) },
      ),
    );
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      "No report found.",
    );
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });
});
