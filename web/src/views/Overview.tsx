import { useState, type ReactNode } from "react";
import { ChevronRight } from "lucide-react";
import { cn } from "../components/ui";
import {
  coverageSummary,
  dependencySummary,
  listed,
  locationOf,
  proofCounts,
  proofLevel,
  PROOF_MEANING,
  reviewCount,
  topIssues,
  weaknessRows,
} from "../lib";
import type { Issue, Label, Workspace } from "../types";

export type View = "overview" | "issues" | "dependencies" | "routes" | "coverage" | "review" | "about";

type Props = {
  data: Workspace;
  onOpenIssue: (id: string) => void;
  onFilterLabel: (label: Label) => void;
  onGo: (view: View) => void;
  /** The optional AI follow-up panel, shown at the bottom. */
  followUp?: ReactNode;
};

function Card({ title, aside, children, className }: { title: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("ov-card", className)}>
      <header>
        <h2>{title}</h2>
        {aside}
      </header>
      {children}
    </section>
  );
}

function LinkButton({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" className="ov-link" onClick={onClick}>
      {children}
      <ChevronRight size={13} />
    </button>
  );
}

function ProofBar({ issues }: { issues: Issue[] }) {
  const proof = proofCounts(issues);
  if (!proof.total) return <p className="ov-empty">No Confirmed issues in this report.</p>;
  const share = (n: number) => `${(n / proof.total) * 100}%`;
  return (
    <>
      <div
        className="ov-bar"
        role="img"
        aria-label={`Of ${proof.total} Confirmed issues: ${proof.validated} validated, ${proof.partial} partial, ${proof.other} not recorded`}
      >
        <span className="proof-validated" style={{ width: share(proof.validated) }} />
        <span className="proof-partial" style={{ width: share(proof.partial) }} />
        <span className="proof-other" style={{ width: share(proof.other) }} />
      </div>
      <dl className="ov-legend">
        <div>
          <dt><i className="proof-validated" />Validated <strong>{proof.validated}</strong></dt>
          <dd>{PROOF_MEANING.validated}</dd>
        </div>
        <div>
          <dt><i className="proof-partial" />Partial <strong>{proof.partial}</strong></dt>
          <dd>{PROOF_MEANING.partial}</dd>
        </div>
        {proof.other > 0 && (
          <div>
            <dt><i className="proof-other" />Not recorded <strong>{proof.other}</strong></dt>
            <dd>This report was written before proof levels were recorded.</dd>
          </div>
        )}
      </dl>
    </>
  );
}

function Coverage({ data, onGo }: { data: Workspace; onGo: Props["onGo"] }) {
  const coverage = coverageSummary(data);
  if (!coverage.recorded)
    return <p className="ov-empty">Runtime coverage was not recorded for this report. An absent finding is not a safe input.</p>;
  const { found, tested, dropped, deadlineReached } = coverage;
  const known = found !== undefined && tested !== undefined && found > 0;
  return (
    <>
      {known ? (
        <>
          <p className="ov-figure">
            <strong>{tested}</strong> of {found} inputs tested
          </p>
          <div className="ov-bar" role="img" aria-label={`${tested} of ${found} inputs tested`}>
            <span className="proof-validated" style={{ width: `${Math.min(100, (tested! / found!) * 100)}%` }} />
          </div>
        </>
      ) : (
        <p className="ov-figure">{tested ?? "Unknown number of"} inputs tested</p>
      )}
      <ul className="ov-notes">
        {!!dropped && <li>{dropped} excluded because they were outside the allowed scope.</li>}
        {deadlineReached === true && <li className="ov-warn">Stopped at the time limit, so some inputs were not tested. A Code only issue then means <em>not proven</em>, not <em>safe</em>.</li>}
        {deadlineReached === false && <li>Finished within the time limit.</li>}
      </ul>
      <LinkButton onClick={() => onGo("coverage")}>Coverage details</LinkButton>
    </>
  );
}

function Retest({ data }: { data: Workspace }) {
  const stats = data.report.stats;
  const issues = data.report.issues;
  if (stats.investigated === undefined)
    return <p className="ov-empty">Code only issues were not re-tested in this report.</p>;
  const aiProven = issues.filter((issue) => issue.investigation?.ai_assisted).length;
  return (
    <>
      <p className="ov-figure">
        <strong>{stats.investigated}</strong> Code only {stats.investigated === 1 ? "issue" : "issues"} re-tested at runtime
      </p>
      <ul className="ov-notes">
        <li>{stats.upgraded ?? 0} became Confirmed.</li>
        {aiProven > 0 && <li>{aiProven} proven by a follow-up test an AI model proposed. The correlator judged the evidence.</li>}
        {(stats.upgraded ?? 0) === 0 && <li>Not reproduced is not the same as safe: those issues stay Code only.</li>}
      </ul>
    </>
  );
}

function Dependencies({ data, onGo }: { data: Workspace; onGo: Props["onGo"] }) {
  const summary = dependencySummary(data.report.dependencies);
  if (!summary.present)
    return <p className="ov-empty">No dependency analysis in this report. It runs for PHP applications that have a composer.lock.</p>;
  const { counts } = summary;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return (
    <>
      {summary.lookupFailed && <p className="ov-warn">The advisory lookup did not complete, so which dependencies are affected is unknown.</p>}
      <p className="ov-figure">
        <strong>{total}</strong> affected {total === 1 ? "dependency" : "dependencies"}
      </p>
      <ul className="ov-notes">
        <li>{counts.Reachable} reachable · {counts.Unknown} unknown · {counts["Imported-only"]} imported only · {counts["Present-only"]} present only</li>
        {summary.knownExploited > 0 && <li className="ov-warn">{summary.knownExploited} listed as actively exploited (CISA KEV).</li>}
        {summary.supplyChain > 0 && <li>{summary.supplyChain} supply-chain {summary.supplyChain === 1 ? "finding" : "findings"}.</li>}
      </ul>
      <LinkButton onClick={() => onGo("dependencies")}>All dependencies</LinkButton>
    </>
  );
}

const WEAKNESS_ROWS = 8;

function WeaknessTable({ rows }: { rows: ReturnType<typeof weaknessRows> }) {
  const [all, setAll] = useState(false);
  if (!rows.length) return <p className="ov-empty">No weaknesses to list.</p>;
  const shown = all ? rows : rows.slice(0, WEAKNESS_ROWS);
  return (
    <>
      <table className="ov-table">
        <thead>
          <tr><th>Weakness</th><th title="Found in code and at runtime">Confirmed</th><th title="In the code, not seen at runtime">Code only</th><th title="Seen at runtime, no code location">Runtime only</th></tr>
        </thead>
        <tbody>
          {shown.map((row) => (
            <tr key={row.cwe}>
              <td>{row.name && <>{row.name} </>}<code>{row.cwe}</code></td>
              <td>{row.confirmed || "–"}</td>
              <td>{row.codeOnly || "–"}</td>
              <td>{row.runtimeOnly || "–"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > WEAKNESS_ROWS && (
        <button type="button" className="ov-link" onClick={() => setAll(!all)}>
          {all ? "Show fewer" : `Show all ${rows.length}`}
        </button>
      )}
    </>
  );
}

export function Overview({ data, onOpenIssue, onFilterLabel, onGo, followUp }: Props) {
  const issues = data.report.issues;
  const shown = listed(issues);
  const count = (label: Label) => shown.filter((issue) => issue.label === label).length;
  const review = reviewCount(data.report);
  const top = topIssues(issues, 5);
  const weaknesses = weaknessRows(issues);
  const tiles: { label: string; value: number; note: string; onClick: () => void }[] = [
    { label: "Confirmed", value: count("Confirmed"), note: "found in the code and at runtime", onClick: () => onFilterLabel("Confirmed") },
    { label: "Code only", value: count("Code only"), note: "in the code, not seen at runtime", onClick: () => onFilterLabel("Code only") },
    { label: "Runtime only", value: count("Runtime only"), note: "seen at runtime, no code location", onClick: () => onFilterLabel("Runtime only") },
    { label: "Need review", value: review, note: "conflicts or ambiguous links", onClick: () => onGo("review") },
  ];
  return (
    <div className="overview">
      <div className="ov-tiles">
        {tiles.map((tile) => (
          <button key={tile.label} type="button" className="ov-tile" onClick={tile.onClick} aria-label={`${tile.value} ${tile.label}`}>
            <strong>{tile.value}</strong>
            <span>{tile.label}</span>
            <small>{tile.note}</small>
          </button>
        ))}
      </div>

      <div className="ov-grid">
        <Card title="How well the Confirmed issues are proven">
          <ProofBar issues={issues} />
        </Card>
        <Card title="Runtime coverage">
          <Coverage data={data} onGo={onGo} />
        </Card>
      </div>

      <Card
        title="Fix first"
        aside={shown.length > top.length ? <LinkButton onClick={() => onGo("issues")}>All {shown.length} issues</LinkButton> : undefined}
      >
        {top.length ? (
          <ol className="ov-top">
            {top.map((issue) => {
              const level = proofLevel(issue);
              return (
                <li key={issue.issue_id}>
                  <button type="button" onClick={() => onOpenIssue(issue.issue_id)}>
                    <span className={cn("risk-chip", `risk-${issue.cvss.rating}`)}>{issue.risk_score.toFixed(1)}</span>
                    <span className="ov-top-title">
                      {issue.title}
                      <code>{locationOf(issue)}{issue.params[0] ? ` · ${issue.params[0].name}` : ""}</code>
                    </span>
                    <span className="ov-top-meta">
                      {issue.label}
                      {level && <small className={`proof-text proof-${level}`}>{level}</small>}
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
        ) : (
          <p className="ov-empty">No ranked issues. Check coverage before drawing conclusions.</p>
        )}
      </Card>

      <div className="ov-grid">
        <Card title="Weaknesses">
          <WeaknessTable rows={weaknesses} />
        </Card>
        <div className="ov-stack">
          <Card title="Re-testing">
            <Retest data={data} />
          </Card>
          <Card title="Dependencies">
            <Dependencies data={data} onGo={onGo} />
          </Card>
        </div>
      </div>

      {followUp}
    </div>
  );
}

