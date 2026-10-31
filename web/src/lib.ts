import type { Issue, Workspace } from "./types";

export type Filters = {
  search: string;
  label: string;
  severity: string;
  cwe: string;
  includeHeld: boolean;
};

export function filterIssues(issues: Issue[], filters: Filters): Issue[] {
  const query = filters.search.trim().toLowerCase();
  return issues.filter((issue) => {
    if (!filters.includeHeld && !issue.reportable) return false;
    if (filters.label !== "All" && issue.label !== filters.label) return false;
    if (filters.severity !== "All" && issue.severity !== filters.severity)
      return false;
    if (filters.cwe !== "All" && issue.cwe_family !== filters.cwe) return false;
    const text = [
      issue.title,
      issue.cwe,
      issue.cwe_family,
      issue.issue_id,
      ...issue.routes.map((r) => r.path + (r.selector ? `?${r.selector}` : "")),
      ...issue.params.map((p) => p.name),
      ...issue.evidence.code.map((f) => f.code?.file ?? ""),
    ]
      .join(" ")
      .toLowerCase();
    return !query || text.includes(query);
  });
}

export function locationOf(issue: Issue): string {
  const route = issue.routes[0];
  return route
    ? route.path + (route.selector ? `?${route.selector}` : "")
    : issue.evidence.code[0]?.code?.file || "Application-wide";
}

export function observation(technique: string, verification: string): string {
  if (technique === "stored-marker")
    return "Persistence observed; script execution unverified";
  if (technique.startsWith("reflected"))
    return "Unsafe reflection observed; script execution unverified";
  if (technique === "error-based") return "Database error induced";
  if (technique === "boolean-based")
    return "Boolean response difference observed";
  if (technique === "time-based") return "Repeated response delay observed";
  if (technique === "computed-marker") return "Command execution demonstrated";
  if (technique === "traversal") return "Known file signature returned";
  if (["location-header", "meta-refresh", "js-location"].includes(technique))
    return "Canary redirect destination observed";
  return verification === "confirmed"
    ? "Scanner-confirmed runtime evidence"
    : "Runtime condition observed";
}

export function scanStatus(data: Workspace): {
  label: string;
  incomplete: boolean;
  note: string;
} {
  const { sast, dast } = data.scan.stats;
  const coverage = dast.coverage ?? {};
  if (
    coverage.deadline_reached === true ||
    Number(sast.budget_exhausted_entries) > 0 ||
    sast.semgrep_error
  ) {
    return {
      label: "Incomplete",
      incomplete: true,
      note: "Some analysis did not finish. Review coverage before interpreting an absent finding.",
    };
  }
  if (data.scan.example)
    return {
      label: "Example report",
      incomplete: false,
      note: "Selected benchmark findings and recorded runtime evidence. No new scan was run.",
    };
  if (Object.keys(coverage).length === 0)
    return {
      label: "Coverage unavailable",
      incomplete: false,
      note: "The report is available, but runtime completeness was not recorded.",
    };
  return { label: "Report available", incomplete: false, note: "" };
}

export function display(value: unknown): string {
  if (value === undefined || value === null || value === "")
    return "Not recorded";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}
