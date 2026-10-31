import { useEffect, useRef, useState } from "react";
import {
  ArrowDownToLine,
  ArrowLeft,
  ArrowUpRight,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  FileCode2,
  FileText,
  ListFilter,
  LoaderCircle,
  RefreshCw,
  Search,
  X,
} from "lucide-react";
import { Badge, Button, cn } from "./components/ui";
import {
  display,
  filterIssues,
  locationOf,
  observation,
  scanStatus,
  type Filters,
} from "./lib";
import type { Finding, Issue, Report, Workspace } from "./types";

const EMPTY_FILTERS: Filters = {
  search: "",
  label: "All",
  severity: "All",
  cwe: "All",
  includeHeld: false,
};
const LABELS = ["Confirmed", "Code only", "Runtime only"] as const;

function CopyButton({
  value,
  name = "value",
}: {
  value: string;
  name?: string;
}) {
  const [state, setState] = useState("");
  useEffect(() => {
    if (state) {
      const id = setTimeout(() => setState(""), 2200);
      return () => clearTimeout(id);
    }
  }, [state]);
  return (
    <span className="copy-control">
      <Button
        variant="ghost"
        size="icon"
        aria-label={`Copy ${name}`}
        title={`Copy ${name}`}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value);
            setState("Copied");
          } catch {
            setState("Select text to copy");
          }
        }}
      >
        {state === "Copied" ? <Check size={14} /> : <Copy size={14} />}
      </Button>
      <span className="sr-only" role="status">
        {state}
      </span>
      {state === "Select text to copy" && (
        <span className="copy-error">{state}</span>
      )}
    </span>
  );
}

function EvidenceBlock({
  title,
  value,
  copy = false,
}: {
  title: string;
  value: unknown;
  copy?: boolean;
}) {
  if (value === undefined || value === null || value === "") return null;
  const text = display(value);
  return (
    <div className="evidence-block">
      <div className="block-heading">
        <span>{title}</span>
        {copy && <CopyButton value={text} name={title.toLowerCase()} />}
      </div>
      <pre>{text}</pre>
    </div>
  );
}

function RuntimeEvidence({ finding }: { finding: Finding }) {
  const runtime = finding.runtime!;
  const evidence = runtime.evidence;
  return (
    <article className="runtime-item">
      <p className="observation">
        <span className="observation-dot" />
        {observation(runtime.technique, runtime.verification)}
      </p>
      <div className="request-line">
        <Badge>{runtime.method}</Badge>
        <code>{runtime.url}</code>
        <CopyButton value={runtime.url} name="URL" />
      </div>
      <div className="inline-facts">
        {finding.params.map((p) => (
          <span key={p.name + p.location}>
            <code>{p.name}</code>
            <span className="muted"> in {p.location}</span>
          </span>
        ))}
        <span>{runtime.technique || "Passive check"}</span>
      </div>
      <EvidenceBlock title="Payload" value={runtime.payload} copy />
      <EvidenceBlock title="Matched signal" value={evidence.matched} />
      <EvidenceBlock
        title="Response excerpt"
        value={evidence.response_excerpt}
      />
      {Object.keys(evidence).length > 0 && (
        <details className="disclosure">
          <summary>Recorded evidence</summary>
          <pre>{JSON.stringify(evidence, null, 2)}</pre>
        </details>
      )}
    </article>
  );
}

function CodeEvidence({ finding }: { finding: Finding }) {
  const code = finding.code!;
  return (
    <article className="code-item">
      <div className="source-location">
        <FileCode2 size={15} />
        <code>
          {code.file}:{code.line}
        </code>
        <CopyButton
          value={`${code.file}:${code.line}`}
          name="source location"
        />
      </div>
      <p className="source-function">
        <code>{code.function}</code>
        <span> → </span>
        <code>{code.sink}</code>
      </p>
      <div className="source-code">
        <span className="line-number">{code.line}</span>
        <pre>{code.snippet || "No snippet recorded."}</pre>
        <CopyButton value={code.snippet} name="code snippet" />
      </div>
      {!!code.trace.length && (
        <details className="disclosure">
          <summary>
            Input-to-sink trace{" "}
            <span className="muted">{code.trace.length} steps</span>
          </summary>
          <ol className="trace">
            {code.trace.map((step, i) => (
              <li key={i}>
                <span className="trace-number">{i + 1}</span>
                <div>
                  <p>{step.note}</p>
                  <code>
                    {step.file}:{step.line}
                  </code>
                </div>
              </li>
            ))}
          </ol>
        </details>
      )}
      {!!code.conditions.length && (
        <details className="disclosure">
          <summary>Execution conditions</summary>
          <ul className="plain-list">
            {code.conditions.map((condition, i) => (
              <li key={i}>
                <code>{condition}</code>
              </li>
            ))}
          </ul>
        </details>
      )}
      {code.stored_flow && (
        <details className="disclosure">
          <summary>Stored data flow</summary>
          <pre>{JSON.stringify(code.stored_flow, null, 2)}</pre>
        </details>
      )}
    </article>
  );
}

function IssueDetail({
  issue,
  report,
  onClose,
  onSelect,
}: {
  issue: Issue;
  report: Report;
  onClose: () => void;
  onSelect: (id: string) => void;
}) {
  const pane = useRef<HTMLElement>(null);
  useEffect(() => {
    pane.current?.scrollTo(0, 0);
  }, [issue.issue_id]);
  const links = report.links.filter((link) => link.issue_id === issue.issue_id);
  return (
    <aside className="detail-pane" ref={pane} aria-label="Finding details">
      <div className="detail-topline">
        <Button
          variant="ghost"
          size="small"
          className="mobile-back"
          onClick={onClose}
        >
          <ArrowLeft size={14} /> Findings
        </Button>
        <span>FINDING {String(issue.rank).padStart(2, "0")}</span>
        <a
          href={`#${issue.issue_id}`}
          title="Bookmark this finding"
          aria-label="Link to this finding"
        >
          <ArrowUpRight size={16} />
        </a>
      </div>
      <div className="detail-heading">
        <h2>{issue.title}</h2>
        <div className="flex flex-wrap items-center gap-2">
          <Badge
            className={issue.label === "Confirmed" ? "badge-confirmed" : ""}
          >
            {issue.label}
          </Badge>
          <span className="muted">{issue.cwe}</span>
          {issue.stored && <span className="muted">Stored flow</span>}
          {!issue.reportable && <Badge>Held back</Badge>}
        </div>
      </div>
      <div className="risk-summary">
        <span className={cn("risk-number", `risk-${issue.cvss.rating}`)}>
          {issue.risk_score.toFixed(1)}
        </span>
        <div>
          <strong>{issue.cvss.rating} risk</strong>
          <span>
            CVSS v3.0 temporal · base {issue.cvss.base_score.toFixed(1)}
          </span>
        </div>
      </div>
      <section className="detail-section link-explanation">
        <h3>{links.length ? "Why linked" : "Evidence status"}</h3>
        {links.length ? (
          <>
            <p>
              The code and runtime findings share a CWE family, route, and
              input.
            </p>
            {links.map((link, i) => (
              <p className="link-basis" key={i}>
                <code>{link.match_basis.runtime_route}</code> →{" "}
                <code>
                  {link.match_basis.code_route}
                  {link.match_basis.selector
                    ? `?${link.match_basis.selector}`
                    : ""}
                </code>
                <br />
                <code>{link.match_basis.parameter}</code> ·{" "}
                {link.match_basis.location} · {link.match_basis.kind} route
                match
              </p>
            ))}
          </>
        ) : (
          <p>
            {issue.ambiguous
              ? "Multiple code locations fit this runtime finding. It was left unlinked rather than choosing one."
              : issue.label === "Code only"
                ? "Found in source code. No matching runtime evidence is attached to this report."
                : "Observed at runtime. No unique matching source finding was established."}
          </p>
        )}
        {!!issue.candidates.length && (
          <div className="candidate-links">
            {issue.candidates.map((id) => (
              <button key={id} onClick={() => onSelect(id)}>
                Inspect candidate{" "}
                {report.issues.find((i) => i.issue_id === id)?.rank ?? ""}
                <ChevronRight size={13} />
              </button>
            ))}
          </div>
        )}
        {issue.label === "Confirmed" && (
          <p className="qualification">
            Confirmed means linked code and runtime findings. The observation
            below states what the runtime test demonstrated.
          </p>
        )}
      </section>
      {!!issue.evidence.runtime.length && (
        <section className="detail-section">
          <h3>
            Runtime evidence <span>{issue.evidence.runtime.length}</span>
          </h3>
          {issue.evidence.runtime.map((f) => (
            <RuntimeEvidence key={f.id} finding={f} />
          ))}
        </section>
      )}
      {!!issue.evidence.code.length && (
        <section className="detail-section">
          <h3>
            Source code <span>{issue.evidence.code.length}</span>
          </h3>
          {issue.evidence.code.map((f) => (
            <CodeEvidence key={f.id} finding={f} />
          ))}
        </section>
      )}
      <section className="detail-section secondary-details">
        <details className="disclosure">
          <summary>Risk assessment &amp; finding metadata</summary>
          <dl className="facts">
            <dt>Severity</dt>
            <dd>{issue.severity}</dd>
            <dt>Confidence</dt>
            <dd>{issue.confidence}</dd>
            <dt>CWE family</dt>
            <dd>{issue.cwe_family}</dd>
            <dt>CVSS vector</dt>
            <dd>
              <code>{issue.cvss.vector}</code>
            </dd>
            <dt>Finding ID</dt>
            <dd>
              <code>{issue.issue_id}</code>
              <CopyButton value={issue.issue_id} name="finding ID" />
            </dd>
          </dl>
          <ul className="plain-list">
            {issue.risk_factors.map((factor, i) => (
              <li key={i}>{factor}</li>
            ))}
          </ul>
        </details>
        {!!issue.routes.length && (
          <details className="disclosure">
            <summary>All affected routes &amp; inputs</summary>
            <ul className="plain-list">
              {issue.routes.map((r, i) => (
                <li key={i}>
                  <code>
                    {r.methods.join(", ")} {r.path}
                    {r.selector ? `?${r.selector}` : ""}
                  </code>
                  {!!r.aliases.length && <p>Aliases: {r.aliases.join(", ")}</p>}
                </li>
              ))}
            </ul>
            <p>
              {issue.params
                .map((p) => `${p.name} (${p.location})`)
                .join(", ") || "No specific input"}
            </p>
          </details>
        )}
      </section>
    </aside>
  );
}

function Coverage({
  data,
  onShowHeld,
}: {
  data: Workspace;
  onShowHeld: () => void;
}) {
  const { sast, dast } = data.scan.stats;
  const coverage = dast.coverage ?? {};
  const rows = (entries: [string, unknown][]) => (
    <dl className="coverage-facts">
      {entries.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{display(value)}</dd>
        </div>
      ))}
    </dl>
  );
  return (
    <div className="coverage-view">
      <div className="section-intro">
        <h2>What this report covers</h2>
        <p>
          Recorded scan metadata. An absent finding does not establish that an
          input is safe.
        </p>
      </div>
      <div className="coverage-grid">
        <section>
          <h3>Runtime analysis</h3>
          {rows([
            [
              "Injection points discovered",
              coverage.points_found ?? dast.injection_point_count,
            ],
            ["Points tested", coverage.points_tested],
            ["Excluded by scope", coverage.points_dropped_by_scope],
            ["Prioritized by SAST hints", coverage.points_hinted],
            ["Deadline reached", coverage.deadline_reached],
            ["Session recoveries", coverage.session_relogins],
            ["Requests sent", dast.request_count],
            ["Duration (seconds)", dast.elapsed_seconds],
          ])}
          <p className="footnote">
            Point counts do not guarantee that every probe finished.
            Authentication success is not recorded by the current report format.
          </p>
        </section>
        <section>
          <h3>Source analysis</h3>
          {rows([
            ["Source files analyzed", sast.files],
            ["Entry points", sast.entry_points],
            ["Routes discovered", sast.routes],
            [
              "Entries exceeding analysis budget",
              sast.budget_exhausted_entries,
            ],
            ["Duration (seconds)", sast.seconds],
            [
              "Pattern scanner",
              sast.semgrep_error
                ? "Failed"
                : Object.hasOwn(sast, "semgrep_error")
                  ? "No error recorded"
                  : undefined,
            ],
          ])}
          {Boolean(sast.semgrep_error) && (
            <EvidenceBlock
              title="Pattern scanner error"
              value={sast.semgrep_error}
            />
          )}
          <p className="footnote">
            Static analysis uses bounded interpretation. No recorded scanner
            error does not guarantee complete analysis.
          </p>
        </section>
      </div>
      {!!data.scan.notes.length && (
        <section className="metadata-notes">
          <h3>Unavailable metadata</h3>
          {data.scan.notes.map((note) => (
            <p key={note}>{note}</p>
          ))}
        </section>
      )}
      {!!data.report.diagnostics.length && (
        <section className="metadata-notes">
          <h3>Correlation diagnostics</h3>
          {data.report.diagnostics.map((note) => (
            <p key={note}>{note}</p>
          ))}
        </section>
      )}
      <section className="excluded-section">
        <div className="flex items-center justify-between gap-3">
          <h3>Findings outside the default list</h3>
          {data.report.issues.some((i) => !i.reportable) && (
            <Button size="small" onClick={onShowHeld}>
              Include held-back findings
              <ChevronRight size={13} />
            </Button>
          )}
        </div>
        <p>
          {data.report.issues.filter((i) => !i.reportable).length}{" "}
          low-confidence code-only issues held back ·{" "}
          {data.report.suppressed.length} static findings suppressed.
        </p>
        {!!data.report.suppressed.length && (
          <details className="disclosure">
            <summary>Suppressed source findings</summary>
            <div className="suppressed-list">
              {data.report.suppressed.map((f) => (
                <div key={f.sast_id}>
                  <code>
                    {f.file}:{f.line}
                  </code>
                  <span>{f.cwe}</span>
                  <p>{f.reason}</p>
                </div>
              ))}
            </div>
          </details>
        )}
      </section>
    </div>
  );
}

function Review({ report }: { report: Report }) {
  return (
    <div className="review-view">
      <div className="section-intro">
        <h2>Conflicting evidence</h2>
        <p>
          A runtime test reported a weakness that source analysis marked safe.
          These are kept separate from ranked issues for investigation.
        </p>
      </div>
      {report.conflicts.map((conflict, i) => (
        <article className="conflict" key={i}>
          <span className="eyebrow">
            REVIEW {String(i + 1).padStart(2, "0")}
          </span>
          <h3>Runtime and source analysis disagree</h3>
          <p>{conflict.reason}</p>
          <details className="disclosure" open>
            <summary>Finding references</summary>
            <dl className="facts">
              <dt>Source findings</dt>
              <dd>
                {conflict.sast_ids.map((id) => (
                  <code key={id} className="block">
                    {id}
                  </code>
                ))}
              </dd>
              <dt>Runtime findings</dt>
              <dd>
                {conflict.dast_ids.map((id) => (
                  <code key={id} className="block">
                    {id}
                  </code>
                ))}
              </dd>
            </dl>
            <p className="footnote">
              The issue report retains references and a reason. Consult the
              original common reports for the full conflicting evidence.
            </p>
          </details>
        </article>
      ))}
    </div>
  );
}

function ScanDetails({
  data,
  dialog,
}: {
  data: Workspace;
  dialog: React.RefObject<HTMLDialogElement | null>;
}) {
  return (
    <dialog
      ref={dialog}
      className="scan-dialog"
      aria-labelledby="scan-details-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) dialog.current?.close();
      }}
    >
      <div className="dialog-heading">
        <h2 id="scan-details-title">Scan details</h2>
        <Button
          variant="ghost"
          size="icon"
          onClick={() => dialog.current?.close()}
          aria-label="Close scan details"
        >
          <X size={18} />
        </Button>
      </div>
      <dl className="facts">
        <dt>Application</dt>
        <dd>{data.scan.name}</dd>
        <dt>Runtime target</dt>
        <dd>
          <code>{data.scan.target || "Not recorded"}</code>
        </dd>
        <dt>Source</dt>
        <dd>
          <code>{data.scan.source || "Not recorded"}</code>
        </dd>
        <dt>Report</dt>
        <dd>
          <code>{data.scan.report_path}</code>
        </dd>
        <dt>File updated</dt>
        <dd>{new Date(data.scan.modified_at).toLocaleString()}</dd>
        <dt>Format</dt>
        <dd>{data.report.schema_version}</dd>
        <dt>Source input</dt>
        <dd>
          <code>{data.report.inputs.sast.path || "Not recorded"}</code>
        </dd>
        <dt>Runtime input</dt>
        <dd>
          <code>{data.report.inputs.dast.path || "Not recorded"}</code>
        </dd>
      </dl>
      <p className="footnote">
        File update time is not the scan completion time. Engine versions and
        initial authentication outcome are not recorded in this report.
      </p>
    </dialog>
  );
}

export default function App() {
  const [data, setData] = useState<Workspace | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<"findings" | "coverage">("findings");
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [review, setReview] = useState(false);
  const [selected, setSelected] = useState(() => window.location.hash.slice(1));
  const [mobileDetail, setMobileDetail] = useState(
    Boolean(window.location.hash),
  );
  const dialog = useRef<HTMLDialogElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const table = useRef<HTMLTableElement>(null);

  async function load() {
    setLoading(true);
    try {
      const response = await fetch("/api/report", { cache: "no-store" });
      const value = await response.json();
      if (!response.ok)
        throw new Error(
          typeof value.detail === "string"
            ? value.detail
            : "Could not read the report.",
        );
      setData(value);
      if (
        !data &&
        value.report.issues.some(
          (item: Issue) =>
            item.issue_id === window.location.hash.slice(1) && !item.reportable,
        )
      ) {
        setFilters((current) => ({ ...current, includeHeld: true }));
      }
      setError("");
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Could not connect to the report server.",
      );
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, []);
  useEffect(() => {
    const hashChange = () => {
      setSelected(window.location.hash.slice(1));
      setMobileDetail(Boolean(window.location.hash));
    };
    window.addEventListener("hashchange", hashChange);
    return () => window.removeEventListener("hashchange", hashChange);
  }, []);

  const issues = data ? filterIssues(data.report.issues, filters) : [];
  const issue = issues.find((i) => i.issue_id === selected) ?? issues[0];
  useEffect(() => {
    if (issue && issue.issue_id !== selected) {
      setSelected(issue.issue_id);
      window.history.replaceState(null, "", `#${issue.issue_id}`);
    }
  }, [issue, selected]);

  function choose(id: string) {
    setSelected(id);
    setMobileDetail(true);
    window.location.hash = id;
  }
  function changeFilter<K extends keyof Filters>(key: K, value: Filters[K]) {
    setFilters((f) => ({ ...f, [key]: value }));
    setReview(false);
  }
  function inspectCandidate(id: string) {
    setFilters({ ...EMPTY_FILTERS, includeHeld: true });
    choose(id);
  }

  if (!data)
    return (
      <div className="initial-screen">
        <div className="brand">
          <span className="brand-mark" />
          CyberForge
        </div>
        <div className="initial-content">
          {loading ? (
            <>
              <LoaderCircle className="spin" size={22} />
              <h1>Opening report</h1>
            </>
          ) : (
            <>
              <FileText size={28} />
              <h1>Open a scan report</h1>
              <p role="alert">{error}</p>
              <p>
                Generate a report with the correlator, then start the workspace
                with its path:
              </p>
              <pre>python -m web.server --report out/issues.json</pre>
              <Button onClick={() => void load()}>
                <RefreshCw size={14} />
                Try again
              </Button>
            </>
          )}
        </div>
      </div>
    );
  const status = scanStatus(data);
  const reportable = data.report.issues.filter((i) => i.reportable);
  const held = data.report.issues.length - reportable.length;
  const advancedCount =
    Number(filters.severity !== "All") +
    Number(filters.cwe !== "All") +
    Number(filters.includeHeld);
  const filtered =
    filters.search || filters.label !== "All" || advancedCount > 0;
  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="header-left">
          <div className="brand">
            <span className="brand-mark" />
            CyberForge
          </div>
          <span className="header-divider" />
          <span className="workspace-name">{data.scan.name}</span>
          <Badge className="local-badge">Local</Badge>
        </div>
        <div className="header-actions">
          <Button
            variant="ghost"
            size="small"
            onClick={() => dialog.current?.showModal()}
          >
            Scan details
          </Button>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Reload report"
            title="Reload report"
            disabled={loading}
            onClick={() => void load()}
          >
            <RefreshCw size={15} className={loading ? "spin" : ""} />
          </Button>
        </div>
      </header>
      <main className="main-content">
        <div className="page-heading">
          <div>
            <div className="eyebrow">SECURITY ANALYSIS</div>
            <h1>Findings</h1>
            <p className="target-line">
              <span className="target-dot" />
              <code>{data.scan.target || "Runtime target not recorded"}</code>
            </p>
          </div>
          <details className="export-menu">
            <summary className="button button-outline">
              <ArrowDownToLine size={15} />
              Export
              <ChevronDown size={13} />
            </summary>
            <div className="menu-panel">
              <a href="/api/export" download>
                JSON report<span>.json</span>
              </a>
              <a href="/api/export/html" download>
                Standalone report<span>.html</span>
              </a>
            </div>
          </details>
        </div>
        <nav className="view-nav" aria-label="Report views">
          <div className="tabs">
            {(["findings", "coverage"] as const).map((tab) => (
              <button
                key={tab}
                aria-current={view === tab ? "page" : undefined}
                className={view === tab ? "active" : ""}
                onClick={() => setView(tab)}
              >
                {tab === "findings" ? "Findings" : "Coverage"}
                {tab === "findings" && <span>{reportable.length}</span>}
              </button>
            ))}
          </div>
          <span
            className={cn("scan-status", status.incomplete && "incomplete")}
          >
            <span />
            {status.label}
          </span>
        </nav>
        {error && (
          <div className="notice notice-warning" role="alert">
            Could not reload: {error} The previous report remains visible.
          </div>
        )}
        {status.note && (
          <div className={cn("notice", status.incomplete && "notice-warning")}>
            <span>{status.note}</span>
            <button onClick={() => setView("coverage")}>
              View coverage
              <ChevronRight size={13} />
            </button>
          </div>
        )}
        {view === "coverage" ? (
          <Coverage
            data={data}
            onShowHeld={() => {
              setFilters({ ...EMPTY_FILTERS, includeHeld: true });
              setReview(false);
              setView("findings");
            }}
          />
        ) : (
          <>
            <div className="summary-line">
              <button
                className={filters.label === "All" && !review ? "current" : ""}
                onClick={() => {
                  changeFilter("label", "All");
                }}
              >
                {reportable.length}
                <span>total issues</span>
              </button>
              {LABELS.map((label) => (
                <button
                  key={label}
                  className={
                    filters.label === label && !review ? "current" : ""
                  }
                  onClick={() =>
                    changeFilter(
                      "label",
                      filters.label === label ? "All" : label,
                    )
                  }
                >
                  {reportable.filter((i) => i.label === label).length}
                  <span>{label.toLowerCase()}</span>
                </button>
              ))}
              {!!data.report.conflicts.length && (
                <button
                  className={cn("review-count", review && "current")}
                  onClick={() => setReview(!review)}
                >
                  {data.report.conflicts.length}
                  <span>need review</span>
                </button>
              )}
            </div>
            {review ? (
              <Review report={data.report} />
            ) : (
              <div
                className={cn(
                  "workspace",
                  mobileDetail && issue && "show-mobile-detail",
                )}
              >
                <section className="findings-pane" aria-label="Findings list">
                  <div className="filter-toolbar">
                    <label className="search-input">
                      <Search size={16} />
                      <input
                        ref={search}
                        placeholder="Search findings…"
                        aria-label="Search findings"
                        value={filters.search}
                        onChange={(e) => changeFilter("search", e.target.value)}
                      />
                      {filters.search && (
                        <button
                          aria-label="Clear search"
                          onClick={() => {
                            changeFilter("search", "");
                            search.current?.focus();
                          }}
                        >
                          <X size={14} />
                        </button>
                      )}
                    </label>
                    <details className="filter-menu">
                      <summary
                        className={cn(
                          "button button-outline",
                          advancedCount > 0 && "filter-active",
                        )}
                      >
                        <ListFilter size={15} />
                        Filters
                        {advancedCount > 0 && <span>{advancedCount}</span>}
                      </summary>
                      <div className="menu-panel">
                        <label>
                          Severity
                          <select
                            value={filters.severity}
                            onChange={(e) =>
                              changeFilter("severity", e.target.value)
                            }
                          >
                            <option>All</option>
                            {["critical", "high", "medium", "low", "info"].map(
                              (s) => (
                                <option key={s}>{s}</option>
                              ),
                            )}
                          </select>
                        </label>
                        <label>
                          Weakness
                          <select
                            value={filters.cwe}
                            onChange={(e) =>
                              changeFilter("cwe", e.target.value)
                            }
                          >
                            <option>All</option>
                            {[
                              ...new Set(
                                data.report.issues.map((i) => i.cwe_family),
                              ),
                            ]
                              .sort()
                              .map((cwe) => (
                                <option key={cwe}>{cwe}</option>
                              ))}
                          </select>
                        </label>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={filters.includeHeld}
                            onChange={(e) =>
                              changeFilter("includeHeld", e.target.checked)
                            }
                          />
                          Include {held} held-back issues
                        </label>
                        <Button
                          variant="ghost"
                          size="small"
                          onClick={() => setFilters(EMPTY_FILTERS)}
                        >
                          Reset all filters
                        </Button>
                      </div>
                    </details>
                  </div>
                  <div className="list-scroll">
                    <table
                      ref={table}
                      className="findings-table"
                      aria-label="Ranked security findings"
                      onKeyDown={(e) => {
                        if (
                          !["ArrowDown", "ArrowUp", "Home", "End"].includes(
                            e.key,
                          )
                        )
                          return;
                        const anchor = (
                          e.target as HTMLElement
                        ).closest<HTMLAnchorElement>("a[data-issue]");
                        if (!anchor) return;
                        e.preventDefault();
                        const index = issues.findIndex(
                          (i) => i.issue_id === anchor.dataset.issue,
                        );
                        const next =
                          e.key === "Home"
                            ? 0
                            : e.key === "End"
                              ? issues.length - 1
                              : Math.min(
                                  issues.length - 1,
                                  Math.max(
                                    0,
                                    index + (e.key === "ArrowDown" ? 1 : -1),
                                  ),
                                );
                        const id = issues[next]?.issue_id;
                        if (id) {
                          choose(id);
                          table.current
                            ?.querySelector<HTMLAnchorElement>(
                              `a[data-issue="${id}"]`,
                            )
                            ?.focus();
                        }
                      }}
                    >
                      <thead>
                        <tr>
                          <th title="CVSS v3.0 temporal score">Risk</th>
                          <th>Evidence</th>
                          <th>
                            Finding
                            <span className="table-order">Priority order</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {issues.map((i) => (
                          <tr
                            key={i.issue_id}
                            className={cn(
                              issue?.issue_id === i.issue_id && "selected",
                              !i.reportable && "held-row",
                            )}
                            onClick={() => choose(i.issue_id)}
                          >
                            <td>
                              <span
                                className={cn(
                                  "risk-chip",
                                  `risk-${i.cvss.rating}`,
                                )}
                              >
                                {i.risk_score.toFixed(1)}
                              </span>
                            </td>
                            <td>
                              <Badge
                                className={
                                  i.label === "Confirmed"
                                    ? "badge-confirmed"
                                    : ""
                                }
                              >
                                {i.label}
                              </Badge>
                            </td>
                            <td>
                              <a
                                data-issue={i.issue_id}
                                aria-current={
                                  issue?.issue_id === i.issue_id
                                    ? "true"
                                    : undefined
                                }
                                href={`#${i.issue_id}`}
                                onClick={(e) => {
                                  e.preventDefault();
                                  e.stopPropagation();
                                  choose(i.issue_id);
                                }}
                              >
                                {i.title}
                              </a>
                              <div
                                className="finding-location"
                                title={locationOf(i)}
                              >
                                <code>{locationOf(i)}</code>
                                {i.params[0] && (
                                  <>
                                    <span>·</span>
                                    <code>{i.params[0].name}</code>
                                  </>
                                )}
                              </div>
                              {!i.reportable && (
                                <span className="held-label">
                                  Held back · low confidence
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {!issues.length && (
                      <div className="empty-list">
                        <Search size={22} />
                        <h2>
                          {data.report.issues.length
                            ? "No matching findings"
                            : "No ranked issues"}
                        </h2>
                        <p>
                          {data.report.issues.length
                            ? "Try another search or reset the filters."
                            : "Review coverage and any conflicting evidence before drawing conclusions."}
                        </p>
                        {filtered && (
                          <Button
                            size="small"
                            onClick={() => setFilters(EMPTY_FILTERS)}
                          >
                            Reset filters
                          </Button>
                        )}
                      </div>
                    )}
                  </div>
                  <div className="list-footer">
                    <span>
                      {issues.length} of{" "}
                      {filters.includeHeld
                        ? data.report.issues.length
                        : reportable.length}{" "}
                      issues
                      {filtered && (
                        <button onClick={() => setFilters(EMPTY_FILTERS)}>
                          Clear filters
                        </button>
                      )}
                    </span>
                    <span className="keyboard-hint">↑ ↓ to navigate</span>
                  </div>
                </section>
                {issue ? (
                  <IssueDetail
                    issue={issue}
                    report={data.report}
                    onClose={() => setMobileDetail(false)}
                    onSelect={inspectCandidate}
                  />
                ) : (
                  <aside className="detail-pane detail-empty">
                    <FileText size={26} />
                    <p>Select a finding to inspect its evidence.</p>
                  </aside>
                )}
              </div>
            )}
          </>
        )}
        <footer className="app-footer">
          <span>
            CyberForge<span className="footer-separator">/</span>Source +
            runtime analysis
          </span>
          <span>Reports stay on this machine</span>
        </footer>
      </main>
      <ScanDetails data={data} dialog={dialog} />
    </div>
  );
}
