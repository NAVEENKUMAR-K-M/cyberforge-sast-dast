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
import shop from "./fixtures/shop.report.json";
import composer from "./fixtures/composer.dependencies.json";
import type { Dependencies, Report, Workspace } from "./types";

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

/** A workspace built from real scan output: the PHP shop's issues and the SCA benchmark's dependency section. */
function realWorkspace(): Workspace {
  const real = structuredClone(shop) as unknown as Report;
  real.dependencies = structuredClone(composer) as unknown as Dependencies;
  return {
    report: real,
    scan: {
      name: "shop",
      target: "http://127.0.0.1:8088",
      source: "sast-engine/benchmarks/shop",
      report_path: "out/scans/68287b2b9aa1/issues.json",
      modified_at: "2026-11-01T04:40:00Z",
      example: false,
      stats: { sast: {}, dast: {} },
      notes: [],
      elapsed_seconds: 72.17,
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
  // jsdom has no modal dialogs: open and close just toggle the attribute, which is what makes content reachable.
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
    configurable: true,
    value: vi.fn(function (this: HTMLDialogElement) {
      this.setAttribute("open", "");
    }),
  });
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value: vi.fn(function (this: HTMLDialogElement) {
      this.removeAttribute("open");
    }),
  });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const tab = (name: RegExp | string) => screen.getByRole("button", { name });
/** The list row's link for one issue. Real reports repeat titles ("SQL injection" appears many times), so use the id. */
function issueLink(container: HTMLElement, id: string): HTMLAnchorElement {
  const link = container.querySelector<HTMLAnchorElement>(`a[data-issue="${id}"]`);
  if (!link) throw new Error(`no row for ${id}`);
  return link;
}
async function openIssues(user = userEvent.setup()) {
  await screen.findByRole("heading", { name: /./, level: 1 });
  await user.click(tab(/^Issues/));
  return user;
}

describe("dashboard overview", () => {
  it("opens on a summary of the scan, not on the findings list", async () => {
    data = realWorkspace();
    render(<App />);
    expect(await screen.findByRole("heading", { name: "shop", level: 1 })).toBeTruthy();
    expect(screen.getByText("1m 12s")).toBeTruthy();
    expect(screen.getByRole("button", { name: "8 Confirmed" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "4 Code only" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "2 Runtime only" })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "Ranked security findings" })).toBeNull();
    expect(tab(/^Overview/).getAttribute("aria-current")).toBe("page");
  });

  it("shows how strongly the Confirmed issues were proven", async () => {
    data = realWorkspace();
    render(<App />);
    const bar = await screen.findByRole("img", { name: /Of 8 Confirmed issues: 4 validated, 4 partial, 0 not recorded/ });
    expect(bar).toBeTruthy();
    expect(screen.getByText(/The recorded request and response show the weakness itself/)).toBeTruthy();
    expect(screen.getByText(/exploitation is not shown/)).toBeTruthy();
  });

  it("does not guess proof levels for a report that has none", async () => {
    render(<App />);
    expect(await screen.findByRole("img", { name: /1 not recorded/ })).toBeTruthy();
    expect(screen.getByText(/written before proof levels were recorded/)).toBeTruthy();
  });

  it("lists what to fix first, in rank order, and opens an issue from it", async () => {
    data = realWorkspace();
    const user = userEvent.setup();
    render(<App />);
    const list = (await screen.findByRole("heading", { name: "Fix first" })).closest("section")!;
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(5);
    const lowest = Math.min(...data.report.issues.map((i) => i.rank));
    const first = data.report.issues.find((i) => i.rank === lowest)!;
    expect(within(rows[0]).getByText(first.title)).toBeTruthy();
    await user.click(within(rows[0]).getByRole("button"));
    const detail = await screen.findByRole("complementary", { name: "Finding details" });
    expect(within(detail).getByRole("heading", { name: first.title })).toBeTruthy();
    expect(tab(/^Issues/).getAttribute("aria-current")).toBe("page");
  });

  it("does not put an issue in the address while you are on the Overview", async () => {
    data = realWorkspace();
    render(<App />);
    await screen.findByRole("heading", { name: "shop", level: 1 });
    expect(window.location.hash).toBe("");
    cleanup();
    render(<App />);
    expect(await screen.findByRole("button", { name: "8 Confirmed" })).toBeTruthy();   // a reload still lands on the Overview
  });

  it("jumps to the issues of one label when its count is clicked", async () => {
    data = realWorkspace();
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: "4 Code only" }));
    await screen.findByRole("table", { name: "Ranked security findings" });
    expect(screen.getAllByRole("row")).toHaveLength(4 + 1);
  });

  it("reports runtime coverage and warns when the time limit was hit", async () => {
    data = realWorkspace();
    render(<App />);
    expect(await screen.findByText(/inputs tested/)).toBeTruthy();
    expect(screen.getByText("Finished within the time limit.")).toBeTruthy();
    cleanup();
    data = realWorkspace();
    data.report.stats.runtime_coverage = { points_found: 42, points_tested: 10, deadline_reached: true };
    render(<App />);
    expect(await screen.findByText(/Stopped at the time limit/)).toBeTruthy();
    expect(screen.getByText(/not proven/)).toBeTruthy();
  });

  it("breaks the issues down by weakness", async () => {
    data = realWorkspace();
    render(<App />);
    const table = (await screen.findByRole("heading", { name: "Weaknesses" })).closest("section")!;
    expect(within(table).getByText("SQL injection")).toBeTruthy();
    expect(within(table).getByText("CWE-89")).toBeTruthy();
  });

  it("says plainly when there is no dependency analysis or re-testing", async () => {
    render(<App />);
    expect(await screen.findByText(/No dependency analysis in this report/)).toBeTruthy();
    expect(screen.getByText(/were not re-tested in this report/)).toBeTruthy();
  });

  it("summarises re-testing from the report's own numbers", async () => {
    data = realWorkspace();
    render(<App />);
    expect(await screen.findByText(/Code only issues re-tested at runtime/)).toBeTruthy();
    expect(screen.getByText("0 became Confirmed.")).toBeTruthy();
    expect(screen.getByText(/Not reproduced is not the same as safe/)).toBeTruthy();
  });

  it("carries no feature-checklist or pitch material", async () => {
    data = realWorkspace();
    render(<App />);
    await screen.findByRole("heading", { name: "shop", level: 1 });
    for (const text of [/PRD capability board/, /Core ·/, /Bonus ·/, /EXAMPLE REPORT/, /SECURITY ANALYSIS/]) {
      expect(screen.queryByText(text)).toBeNull();
    }
  });
});

describe("dependencies view", () => {
  it("lists affected dependencies with their status and the reason", async () => {
    data = realWorkspace();
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /^Dependencies/ }));
    expect(screen.getByRole("heading", { name: "Dependencies", level: 2 })).toBeTruthy();
    const rows = screen.getAllByRole("listitem").filter((li) => li.classList.contains("dep-row"));
    expect(rows).toHaveLength(3);
    expect(within(rows[0]).getByText("Reachable")).toBeTruthy();
    expect(within(rows[0]).getByText("symfony/http-foundation@v7.4.18")).toBeTruthy();
    expect(within(rows[1]).getByText("Unknown")).toBeTruthy();
    expect(within(rows[2]).getByText("Present-only")).toBeTruthy();
  });

  it("shows the call path to the vulnerable function, step by step", async () => {
    data = realWorkspace();
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /^Dependencies/ }));
    const row = screen.getAllByRole("listitem").find((li) => li.classList.contains("dep-row"))!;
    const steps = within(row).getByRole("heading", { name: "Call path" }).closest("section")!;
    const functions = within(steps).getAllByRole("listitem").map((li) => li.querySelector("code")!.textContent);
    expect(functions[0]).toBe("<public/index.php>");
    expect(functions[functions.length - 1]).toBe("Symfony\\Component\\HttpFoundation\\HeaderUtils::split");
    expect(functions).toContain("Symfony\\Bridge\\PsrHttpMessage\\Factory\\HttpFoundationFactory::createRequest");
  });

  it("marks a call that was not resolved to one target, and lists what was assumed", async () => {
    data = realWorkspace();
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /^Dependencies/ }));
    const unknown = screen.getAllByRole("listitem").filter((li) => li.classList.contains("dep-row"))[1];
    expect(within(unknown).getByText(/not resolved to one target/)).toBeTruthy();
    expect(within(unknown).getByRole("heading", { name: "Limits of this analysis" })).toBeTruthy();
  });

  it("filters by status", async () => {
    data = realWorkspace();
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /^Dependencies/ }));
    await user.click(screen.getByRole("button", { name: /^Unknown/ }));
    expect(screen.getAllByRole("listitem").filter((li) => li.classList.contains("dep-row"))).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: /^Imported-only/ }));
    expect(screen.getByText("No dependency has the status Imported-only.")).toBeTruthy();
  });

  it("does not present a failed advisory lookup as a clean result", async () => {
    data = realWorkspace();
    data.report.dependencies!.advisory_lookup = { status: "unavailable", error: "offline" };
    data.report.dependencies!.rows = [];
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /^Dependencies/ }));
    expect(screen.getByRole("alert").textContent).toMatch(/did not complete \(offline\).*not a clean result/);
  });

  it("explains that no known advisories is not a guarantee", async () => {
    data = realWorkspace();
    data.report.dependencies!.rows = [];
    data.report.dependencies!.advisory_lookup = { status: "ok", source: "OSV", fetched_at: "2026-11-01T03:35:53Z" };
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /^Dependencies/ }));
    expect(screen.getByText(/No known advisories were returned by OSV/)).toBeTruthy();
    expect(screen.getByText(/not a guarantee/)).toBeTruthy();
  });

  it("tells a report with no dependency section where it comes from", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /^Dependencies/ }));
    const view = screen.getByRole("heading", { name: "Dependencies", level: 2 }).closest("div")!;
    expect(within(view).getByText(/This report has no dependency analysis.*composer.lock/)).toBeTruthy();
  });

  it("renders advisory text as text, not markup", async () => {
    data = realWorkspace();
    data.report.dependencies!.rows[0].advisory.summary = '<img src=x onerror="alert(1)">';
    const user = userEvent.setup();
    const { container } = render(<App />);
    await user.click(await screen.findByRole("button", { name: /^Dependencies/ }));
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText('<img src=x onerror="alert(1)">')).toBeTruthy();
  });
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
    await openIssues();
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

  it("shows the runtime proof, its level and its reason, in the list and the detail", async () => {
    data = realWorkspace();
    const { container } = render(<App />);
    await openIssues();
    const confirmed = data.report.issues.find((i) => i.label === "Confirmed" && i.runtime_verification?.level === "validated")!;
    const link = await waitFor(() => issueLink(container, confirmed.issue_id));
    expect(within(link.closest("tr")!).getByText("validated")).toBeTruthy();
    await userEvent.click(link);
    const detail = await screen.findByRole("complementary", { name: "Finding details" });
    const proof = within(detail).getByRole("heading", { name: /Runtime proof/ }).closest("section")!;
    expect(within(proof).getAllByText("validated").length).toBeGreaterThan(0);
    expect(within(proof).getByText(confirmed.runtime_verification!.checks[0].reason)).toBeTruthy();
  });

  it("shows a partial proof as partial, with why it is only partial", async () => {
    data = realWorkspace();
    const { container } = render(<App />);
    await openIssues();
    const partial = data.report.issues.find((i) => i.label === "Confirmed" && i.runtime_verification?.level === "partial")!;
    await userEvent.click(await waitFor(() => issueLink(container, partial.issue_id)));
    const detail = await screen.findByRole("complementary", { name: "Finding details" });
    const proof = within(detail).getByRole("heading", { name: /Runtime proof/ }).closest("section")!;
    expect(within(proof).getByText(/exploitation is not shown/)).toBeTruthy();
    expect(within(proof).getByText(partial.runtime_verification!.checks[0].reason)).toBeTruthy();
  });

  it("combines search and evidence filtering, and recovers from an empty result", async () => {
    render(<App />);
    const user = await openIssues();
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
    await openIssues();
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

  it("keeps the PRD mapping on a small About page, off the dashboard", async () => {
    render(<App />);
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByText("FR-4")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "About" }));
    expect(screen.getByRole("heading", { name: "About this workspace" })).toBeTruthy();
    for (const id of ["FR-1, FR-2", "FR-10", "B-1", "B-7", "SCA note"]) expect(screen.getByText(id)).toBeTruthy();
  });

  it("shows a distinct Need review view for conflicts", async () => {
    data.report.conflicts = [{ sast_ids: ["sast:abc"], dast_ids: ["dast:def"], reason: "Review the conflicting evidence." }];
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Need review 1" }));
    expect(screen.getByRole("heading", { name: "Conflicting evidence" })).toBeTruthy();
    expect(screen.getByText("Review the conflicting evidence.")).toBeTruthy();
  });

  it("only offers the Need review tab when there is something to review", async () => {
    render(<App />);
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByRole("button", { name: /^Need review/ })).toBeNull();
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
    await openIssues();
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
    render(<App />);
    const user = await openIssues();
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
    await openIssues();
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

  it("scans a custom application from its source folder and URL, from the New scan dialog", async () => {
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
    await user.click(await screen.findByRole("button", { name: "New scan" }));
    expect(HTMLDialogElement.prototype.showModal).toHaveBeenCalled();
    const source = (await screen.findByLabelText("Source folder")) as HTMLInputElement;
    expect(source.value).toBe("/workspace");
    await user.type(screen.getByLabelText("Runtime URL"), "http://host.docker.internal:8081");
    await user.selectOptions(screen.getByLabelText("Source language"), "python");
    await user.click(screen.getByRole("button", { name: /Start scan/ }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toMatchObject({
      target_id: "custom", source_path: "/workspace", language: "python", target_url: "http://host.docker.internal:8081",
      run_sast: true, run_dast: true, use_route_map: true, use_sca: true,
    });
  });

  it("lets the dependency analysis be switched off for a scan", async () => {
    const posted: Record<string, unknown>[] = [];
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
          return { ok: false, json: async () => ({ detail: "stop here" }) };
        }
        if (path.startsWith("/api/scans")) return { ok: true, json: async () => ({ scans: [] }) };
        return { ok: true, json: async () => data };
      }),
    );
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: "New scan" }));
    const box = (await screen.findByLabelText(/Dependency analysis/)) as HTMLInputElement;
    expect(box.checked).toBe(true);
    await user.click(box);
    await user.type(screen.getByLabelText("Runtime URL"), "http://localhost:8081");
    await user.click(screen.getByRole("button", { name: /Start scan/ }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].use_sca).toBe(false);
  });

  it("shows that a scan is running on the New scan button", async () => {
    const running = {
      id: "j2", target_name: "Custom application", target_url: "http://localhost:8081", status: "running", stage: "Source analysis",
      created_at: "2026-11-01T00:00:00Z", started_at: "2026-11-01T00:00:01Z", completed_at: null,
      options: { run_sast: true, run_dast: true }, logs: [], error: null, report_path: "out/scans/j2/issues.json", gate: null,
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        const path = String(url);
        if (path.startsWith("/api/targets")) return { ok: true, json: async () => ({ targets: [] }) };
        if (path.startsWith("/api/scans")) return { ok: true, json: async () => ({ scans: [running] }) };
        return { ok: true, json: async () => data };
      }),
    );
    render(<App />);
    expect(await screen.findByRole("button", { name: "Scan running" })).toBeTruthy();
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

describe("dashboard details", () => {
  it("does not print a run time that was never recorded", async () => {
    data = realWorkspace();
    data.scan.elapsed_seconds = null;
    render(<App />);
    const heading = (await screen.findByRole("heading", { name: "shop", level: 1 })).parentElement!;
    expect(heading.textContent).not.toContain("Not recorded");   // (the Scan details dialog may say so; the heading must not)
  });

  it("lists the eight most common weaknesses and lets you see the rest", async () => {
    data = realWorkspace();
    const families = Array.from({ length: 11 }, (_, i) => `CWE-${900 + i}`);
    data.report.issues = data.report.issues.slice(0, 11).map((issue, i) => ({ ...issue, cwe_family: families[i], reportable: true }));
    const user = userEvent.setup();
    render(<App />);
    const card = (await screen.findByRole("heading", { name: "Weaknesses" })).closest("section")!;
    expect(within(card).getAllByRole("row")).toHaveLength(8 + 1);
    await user.click(within(card).getByRole("button", { name: "Show all 11" }));
    expect(within(card).getAllByRole("row")).toHaveLength(11 + 1);
    await user.click(within(card).getByRole("button", { name: "Show fewer" }));
    expect(within(card).getAllByRole("row")).toHaveLength(8 + 1);
  });

  it("offers no toggle when everything fits", async () => {
    data = realWorkspace();
    render(<App />);
    const card = (await screen.findByRole("heading", { name: "Weaknesses" })).closest("section")!;
    expect(within(card).queryByRole("button")).toBeNull();
  });

  it("names an investigated issue by its title and route, not its identifier", async () => {
    data = realWorkspace();
    const issue = data.report.issues[0];
    data.report.investigations = [{ case_id: "c1", issue_id: issue.issue_id, outcome: "unresolved", stop_reason: "round limit reached",
      rounds: [{ round: 1, plan: {}, requests_sent: [], outcome: "no reproduction", evidence: null }] }];
    render(<App />);
    const summary = (await screen.findByText("unresolved")).closest("summary")!;
    expect(summary.textContent).toContain(issue.title);
    expect(summary.textContent).not.toContain(issue.issue_id);
  });
});
