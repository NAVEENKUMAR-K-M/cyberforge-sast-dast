import type {
  Dependencies,
  DependencyStatus,
  Issue,
  ProofLevel,
  Report,
  Workspace,
} from "./types";

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

const CWE_NAMES: Record<string, string> = {
  "CWE-22": "Path traversal",
  "CWE-78": "Command injection",
  "CWE-79": "Cross-site scripting",
  "CWE-89": "SQL injection",
  "CWE-94": "Code injection",
  "CWE-200": "Information exposure",
  "CWE-327": "Weak hash",
  "CWE-330": "Insufficient randomness",
  "CWE-338": "Predictable random value",
  "CWE-489": "Debug or error disclosure",
  "CWE-502": "Unsafe deserialization",
  "CWE-601": "Open redirect",
  "CWE-693": "Protection mechanism failure",
  "CWE-798": "Hard-coded secret",
  "CWE-1004": "Cookie without HttpOnly",
  "CWE-1021": "Missing clickjacking protection",
  "CWE-1275": "Cookie with weak SameSite",
};

export function weaknessName(cwe: string): string {
  return CWE_NAMES[cwe] ?? "";
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return "Not recorded";
  const total = Math.round(seconds);
  if (total < 60) return `${total}s`;
  return `${Math.floor(total / 60)}m ${String(total % 60).padStart(2, "0")}s`;
}

/** Issues the report lists by default: low-confidence code-only issues are held back. */
export function listed(issues: Issue[]): Issue[] {
  return issues.filter((issue) => issue.reportable);
}

/** Conflicts plus ambiguous links: the cases a person has to look at. */
export function reviewCount(report: Report): number {
  return report.conflicts.length + report.issues.filter((issue) => issue.ambiguous).length;
}

export type Proof = { validated: number; partial: number; other: number; total: number };

/**
 * How strongly the runtime side of each Confirmed issue was shown. "Confirmed" means found by both; the level says
 * whether the recorded request and response actually demonstrate the weakness. A report written before levels were
 * recorded has none, which is counted as `other` rather than assumed.
 */
export function proofCounts(issues: Issue[]): Proof {
  const proof: Proof = { validated: 0, partial: 0, other: 0, total: 0 };
  for (const issue of listed(issues)) {
    if (issue.label !== "Confirmed") continue;
    proof.total += 1;
    const level = issue.runtime_verification?.level;
    if (level === "validated") proof.validated += 1;
    else if (level === "partial") proof.partial += 1;
    else proof.other += 1;
  }
  return proof;
}

export const PROOF_MEANING: Record<ProofLevel, string> = {
  validated: "The recorded request and response show the weakness itself.",
  partial: "The input reached the target, but exploitation is not shown.",
  unchecked: "There is runtime evidence, but no check exists for this weakness.",
  none: "Not seen at runtime.",
};

/** The proof level of an issue that has runtime evidence; a Code only issue was never seen at runtime. */
export function proofLevel(issue: Issue): ProofLevel | null {
  return issue.evidence.runtime.length ? (issue.runtime_verification?.level ?? null) : null;
}

/** The top of the ranked list: what to fix first. The report is already ordered by rank. */
export function topIssues(issues: Issue[], count = 5): Issue[] {
  return [...listed(issues)].sort((a, b) => a.rank - b.rank).slice(0, count);
}

export type WeaknessRow = {
  cwe: string;
  name: string;
  confirmed: number;
  codeOnly: number;
  runtimeOnly: number;
  total: number;
};

export function weaknessRows(issues: Issue[]): WeaknessRow[] {
  const rows = new Map<string, WeaknessRow>();
  for (const issue of listed(issues)) {
    const row = rows.get(issue.cwe_family) ?? {
      cwe: issue.cwe_family,
      name: weaknessName(issue.cwe_family),
      confirmed: 0,
      codeOnly: 0,
      runtimeOnly: 0,
      total: 0,
    };
    if (issue.label === "Confirmed") row.confirmed += 1;
    else if (issue.label === "Code only") row.codeOnly += 1;
    else row.runtimeOnly += 1;
    row.total += 1;
    rows.set(issue.cwe_family, row);
  }
  return [...rows.values()].sort((a, b) => b.total - a.total || a.cwe.localeCompare(b.cwe, undefined, { numeric: true }));
}

export type CoverageSummary = {
  recorded: boolean;
  found?: number;
  tested?: number;
  dropped?: number;
  deadlineReached?: boolean;
};

/** Runtime coverage, from the correlated report when it has it and from the DAST scan's own metadata otherwise. */
export function coverageSummary(data: Workspace): CoverageSummary {
  const fromReport = data.report.stats?.runtime_coverage;
  const fromScan = (data.scan.stats.dast.coverage ?? {}) as Record<string, unknown>;
  const pick = <T,>(a: T | undefined, b: unknown): T | undefined => a ?? (b as T | undefined);
  const found = pick(fromReport?.points_found, fromScan.points_found);
  const tested = pick(fromReport?.points_tested, fromScan.points_tested);
  const dropped = pick(fromReport?.points_dropped_by_scope, fromScan.points_dropped_by_scope);
  const deadlineReached = pick(fromReport?.deadline_reached, fromScan.deadline_reached);
  return {
    recorded: found !== undefined || tested !== undefined || deadlineReached !== undefined,
    found,
    tested,
    dropped,
    deadlineReached,
  };
}

export const DEPENDENCY_STATUSES: DependencyStatus[] = ["Reachable", "Unknown", "Imported-only", "Present-only"];

export type DependencySummary = {
  present: boolean;
  counts: Record<DependencyStatus, number>;
  knownExploited: number;
  supplyChain: number;
  lookupFailed: boolean;
};

export function dependencySummary(dependencies: Dependencies | undefined): DependencySummary {
  const counts = { Reachable: 0, Unknown: 0, "Imported-only": 0, "Present-only": 0 };
  for (const row of dependencies?.rows ?? []) counts[row.status] += 1;
  return {
    present: dependencies !== undefined,
    counts,
    knownExploited: (dependencies?.rows ?? []).filter((row) => row.advisory.kev?.status === "listed").length,
    supplyChain: dependencies?.supply_chain.length ?? 0,
    lookupFailed: dependencies !== undefined && dependencies.advisory_lookup.status !== undefined && dependencies.advisory_lookup.status !== "ok",
  };
}
