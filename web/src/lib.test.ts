import { describe, expect, it } from "vitest";
import report from "../example.issues.json";
import {
  filterIssues,
  locationOf,
  observation,
  scanStatus,
  type Filters,
} from "./lib";
import type { Issue, Workspace } from "./types";

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
