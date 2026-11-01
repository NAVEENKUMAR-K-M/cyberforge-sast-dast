import { describe, expect, it } from "vitest";
import report from "../example.issues.json";
import {
  coverageSummary,
  dependencySummary,
  filterIssues,
  formatDuration,
  locationOf,
  observation,
  proofCounts,
  proofLevel,
  reviewCount,
  scanStatus,
  topIssues,
  weaknessName,
  weaknessRows,
  type Filters,
} from "./lib";
import shop from "./fixtures/shop.report.json";
import composer from "./fixtures/composer.dependencies.json";
import type { Dependencies, Issue, Report, Workspace } from "./types";

const issues = report.issues as Issue[];
const filters: Filters = {
  search: "",
  label: "All",
  severity: "All",
  cwe: "All",
  includeHeld: false,
};

describe("finding investigation", () => {
  it("preserves priority order while combining filters", () => {
    expect(filterIssues(issues, filters)).toEqual(issues);
    const found = filterIssues(issues, {
      ...filters,
      label: "Confirmed",
      search: "SEARCH.PHP",
      cwe: "CWE-89",
    });
    expect(found).toHaveLength(1);
    expect(found[0].label).toBe("Confirmed");
    expect(
      filterIssues(issues, { ...filters, severity: "low", label: "Confirmed" }),
    ).toHaveLength(0);
  });
  it("searches source locations and input names", () => {
    expect(
      filterIssues(issues, { ...filters, search: "config.php" }).some(
        (i) => i.cwe === "CWE-798",
      ),
    ).toBe(true);
    expect(
      filterIssues(issues, { ...filters, search: "password" }).length,
    ).toBeGreaterThan(0);
  });
  it("only includes held-back findings when requested", () => {
    const held = { ...issues[0], reportable: false };
    expect(filterIssues([held], filters)).toHaveLength(0);
    expect(
      filterIssues([held], { ...filters, includeHeld: true }),
    ).toHaveLength(1);
  });
  it("does not claim XSS execution from reflection or persistence", () => {
    expect(observation("stored-marker", "firm")).toContain(
      "execution unverified",
    );
    expect(observation("reflected-html_body", "firm")).toContain(
      "execution unverified",
    );
    expect(observation("computed-marker", "confirmed")).toBe(
      "Command execution demonstrated",
    );
  });
  it("includes a page selector in the displayed location", () => {
    const issue = {
      ...issues[0],
      routes: [
        {
          path: "/shop.php",
          selector: "action=view",
          aliases: [],
          methods: ["GET"],
        },
      ],
    };
    expect(locationOf(issue)).toBe("/shop.php?action=view");
  });
});

describe("coverage honesty", () => {
  const data = {
    scan: { example: false, stats: { sast: {}, dast: {} } },
  } as Workspace;
  it("does not turn missing metadata into scan success", () => {
    expect(scanStatus(data).label).toBe("Coverage unavailable");
  });
  it("makes deadline and static scanner failures visible", () => {
    expect(
      scanStatus({
        ...data,
        scan: {
          ...data.scan,
          stats: { sast: {}, dast: { coverage: { deadline_reached: true } } },
        },
      }).incomplete,
    ).toBe(true);
    expect(
      scanStatus({
        ...data,
        scan: {
          ...data.scan,
          stats: { sast: { semgrep_error: "failed" }, dast: {} },
        },
      }).incomplete,
    ).toBe(true);
  });
});

// These use real scan output (src/fixtures): the PHP shop scanned by `cyberforge scan --no-ai`, and the SCA benchmark.
const real = shop as unknown as Report;
const realIssues = real.issues;

describe("dashboard summaries on real scan output", () => {
  it("counts how strongly the Confirmed issues were proven", () => {
    expect(proofCounts(realIssues)).toEqual({ validated: 4, partial: 4, other: 0, total: 8 });
  });
  it("does not assume a level for a report that recorded none", () => {
    expect(proofCounts(issues)).toMatchObject({ validated: 0, partial: 0, other: 1, total: 1 });
  });
  it("shows a proof level for anything seen at runtime, and none for code-only issues", () => {
    const codeOnly = realIssues.filter((i) => i.label === "Code only");
    const runtime = realIssues.filter((i) => i.evidence.runtime.length);
    expect(codeOnly.length).toBeGreaterThan(0);
    expect(codeOnly.every((i) => proofLevel(i) === null)).toBe(true);
    expect(runtime.every((i) => ["validated", "partial", "unchecked", "none"].includes(proofLevel(i) as string))).toBe(true);
  });
  it("lists the top of the ranked list, listed issues only, in rank order", () => {
    const top = topIssues(realIssues, 5);
    expect(top).toHaveLength(5);
    expect(top.map((i) => i.rank)).toEqual([...top.map((i) => i.rank)].sort((a, b) => a - b));
    expect(top[0].rank).toBe(Math.min(...realIssues.map((i) => i.rank)));
    const held = structuredClone(realIssues);
    held[0].reportable = false;
    expect(topIssues(held, 14).some((i) => i.issue_id === held[0].issue_id)).toBe(false);
  });
  it("breaks issues down by weakness and label", () => {
    const rows = weaknessRows(realIssues);
    expect(rows.reduce((n, r) => n + r.total, 0)).toBe(realIssues.length);
    expect(rows.reduce((n, r) => n + r.confirmed, 0)).toBe(8);
    expect(rows.reduce((n, r) => n + r.codeOnly, 0)).toBe(4);
    expect(rows.reduce((n, r) => n + r.runtimeOnly, 0)).toBe(2);
    expect(rows.find((r) => r.cwe === "CWE-89")?.name).toBe("SQL injection");
    expect(rows.map((r) => r.total)).toEqual([...rows.map((r) => r.total)].sort((a, b) => b - a));
  });
  it("reads runtime coverage from the report, then from the scan's own metadata, then admits it is unknown", () => {
    const base = { report: real, scan: { stats: { sast: {}, dast: {} } } } as unknown as Workspace;
    expect(coverageSummary(base)).toMatchObject({ recorded: true, found: 42, tested: 40, dropped: 2, deadlineReached: false });
    const legacy = {
      report: { ...real, stats: {} },
      scan: { stats: { sast: {}, dast: { coverage: { points_found: 10, points_tested: 4, deadline_reached: true } } } },
    } as unknown as Workspace;
    expect(coverageSummary(legacy)).toMatchObject({ recorded: true, found: 10, tested: 4, deadlineReached: true });
    const none = { report: { ...real, stats: {} }, scan: { stats: { sast: {}, dast: {} } } } as unknown as Workspace;
    expect(coverageSummary(none).recorded).toBe(false);
  });
  it("counts conflicts and ambiguous links as needing review", () => {
    expect(reviewCount(real)).toBe(0);
    const withReview = structuredClone(real);
    withReview.conflicts = [{ sast_ids: ["a"], dast_ids: ["b"], reason: "x" }];
    withReview.issues[0].ambiguous = true;
    expect(reviewCount(withReview)).toBe(2);
  });
  it("formats durations", () => {
    expect(formatDuration(72.17)).toBe("1m 12s");
    expect(formatDuration(24.6)).toBe("25s");
    expect(formatDuration(null)).toBe("Not recorded");
  });
});

describe("dependency summary on the real SCA benchmark output", () => {
  const deps = composer as unknown as Dependencies;
  it("counts rows by status", () => {
    expect(dependencySummary(deps)).toMatchObject({
      present: true,
      counts: { Reachable: 1, Unknown: 1, "Imported-only": 0, "Present-only": 1 },
      knownExploited: 0,
      lookupFailed: false,
    });
  });
  it("tells a report with no dependency section from one with an empty one", () => {
    expect(dependencySummary(undefined).present).toBe(false);
    expect(dependencySummary({ ...deps, rows: [], supply_chain: [] }).present).toBe(true);
  });
  it("flags an advisory lookup that did not complete", () => {
    expect(dependencySummary({ ...deps, advisory_lookup: { status: "unavailable", error: "offline" } }).lookupFailed).toBe(true);
  });
  it("counts known-exploited rows from the advisory's KEV status", () => {
    const rows = structuredClone(deps.rows);
    rows[1].advisory.kev = { status: "listed", date_added: "2026-01-01" };
    expect(dependencySummary({ ...deps, rows }).knownExploited).toBe(1);
  });
});

describe("weakness names", () => {
  it("names the weaknesses scans actually report, including the passive-check ones", () => {
    for (const cwe of ["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-330", "CWE-601", "CWE-693", "CWE-798", "CWE-1004", "CWE-1021", "CWE-1275"])
      expect(weaknessName(cwe), cwe).not.toBe("");
  });
  it("leaves a weakness it has no name for unnamed, rather than inventing one", () => {
    expect(weaknessName("CWE-99999")).toBe("");
  });
});
