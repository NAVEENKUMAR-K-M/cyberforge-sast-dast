export type Label = "Confirmed" | "Code only" | "Runtime only";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Param = { name: string; location: string; value?: string };
export type Route = {
  path: string;
  aliases: string[];
  selector: string | null;
  methods: string[];
};
export type Code = {
  file: string;
  line: number;
  snippet: string;
  function: string;
  sink: string;
  trace: { file: string; line: number; note: string }[];
  conditions: string[];
  stored_flow: Record<string, unknown> | null;
  suppression_reason: string | null;
  engines: string[];
};
export type Runtime = {
  method: string;
  url: string;
  payload: string;
  technique: string;
  verification: "confirmed" | "firm" | "tentative";
  evidence: Record<string, unknown>;
};
export type Finding = {
  id: string;
  cwe: string;
  title: string;
  confidence: string;
  params: Param[];
  routes: Route[];
  code: Code | null;
  runtime: Runtime | null;
};
export type Issue = {
  issue_id: string;
  rank: number;
  label: Label;
  cwe: string;
  cwe_family: string;
  title: string;
  severity: Severity;
  confidence: string;
  reportable: boolean;
  stored: boolean;
  ambiguous: boolean;
  candidates: string[];
  routes: Route[];
  params: Param[];
  risk_score: number;
  risk_factors: string[];
  sast_ids: string[];
  dast_ids: string[];
  investigation?: { case_id: string; outcome: string; stop_reason: string | null; rounds: number; ai_assisted: boolean } | null;
  cvss: {
    vector: string;
    base_score: number;
    temporal_score: number;
    rating: string;
    version: string;
  };
  evidence: { code: Finding[]; runtime: Finding[] };
};
export type Link = {
  issue_id: string;
  match_basis: {
    cwe_family: string;
    runtime_route: string;
    code_route: string;
    kind: string;
    parameter: string;
    location: string;
    selector: string | null;
  };
};
export type Report = {
  schema_version: string;
  inputs: Record<"sast" | "dast", { path: string; target: string }>;
  issues: Issue[];
  links: Link[];
  diagnostics: string[];
  conflicts: { dast_ids: string[]; sast_ids: string[]; reason: string }[];
  suppressed: {
    sast_id: string;
    cwe: string;
    file: string;
    line: number;
    reason: string;
  }[];
  stats: Record<string, number>;
  investigations?: {
    case_id: string;
    issue_id: string;
    outcome: string;
    stop_reason?: string | null;
    rounds: { round: number; plan: Record<string, unknown>; requests_sent?: Record<string, unknown>[]; outcome: string; evidence?: Record<string, unknown> | null; effect?: Record<string, unknown> | null; error?: string | null }[];
  }[];
};
export type Stats = Record<string, unknown> & {
  coverage?: Record<string, unknown>;
};
export type Workspace = {
  report: Report;
  scan: {
    name: string;
    target: string;
    source: string;
    report_path: string;
    modified_at: string;
    example: boolean;
    stats: { sast: Stats; dast: Stats };
    notes: string[];
    scan_id?: string | null;
    target_id?: string | null;
    elapsed_seconds?: number | null;
    investigation_run?: boolean;
  };
};
