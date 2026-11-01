import { useState } from "react";
import { cn } from "../components/ui";
import { DEPENDENCY_STATUSES, dependencySummary } from "../lib";
import type { Dependencies, DependencyRow, DependencyStatus, Enrichment } from "../types";

const STATUS_MEANING: Record<DependencyStatus, string> = {
  Reachable: "A call path from an entry point to the affected function exists in the source. It is a static path, not a demonstrated exploit.",
  Unknown: "There was not enough evidence to say. This is never a reassurance.",
  "Imported-only": "The package is used, but no path reaches its affected functions, within the stated scope.",
  "Present-only": "Nothing the application uses mentions the package, within the stated scope.",
};

function kevText(kev: Enrichment | null): string {
  if (!kev) return "–";
  if (kev.status === "listed") return `Listed${kev.date_added ? ` ${kev.date_added}` : ""}`;
  if (kev.status === "not listed") return "No";
  return "Unavailable";
}

function epssText(epss: Enrichment | null): string {
  if (!epss) return "–";
  if (epss.status === "ok" && epss.epss !== undefined) return `${(epss.epss * 100).toFixed(1)}%`;
  return epss.status === "not scored" ? "Not scored" : epss.status === "not applicable" ? "–" : "Unavailable";
}

function cvssText(cvss: DependencyRow["advisory"]["cvss"]): string {
  if (!cvss) return "–";
  if (cvss.score !== null) return cvss.score.toFixed(1);
  return cvss.vector ? "Vector only" : "–";
}

function Row({ row }: { row: DependencyRow }) {
  const advisory = row.advisory;
  return (
    <li className="dep-row">
      <details>
        <summary>
          <span className={cn("dep-status", `dep-${row.status.toLowerCase()}`)}>{row.status}</span>
          <span className="dep-package">
            <code>{row.package}@{row.version}</code>
            {row.dev && <small>dev dependency</small>}
          </span>
          <span className="dep-advisory">{advisory.id}</span>
          <span className="dep-fact" title="CISA Known Exploited Vulnerabilities">KEV {kevText(advisory.kev)}</span>
          <span className="dep-fact" title="Chance of exploitation in the next 30 days (FIRST EPSS)">EPSS {epssText(advisory.epss)}</span>
          <span className="dep-fact" title="Published CVSS base score">CVSS {cvssText(advisory.cvss)}</span>
          <span className="dep-reason">{row.reason}</span>
        </summary>
        <div className="dep-detail">
          <section>
            <h3>Advisory</h3>
            <p>{advisory.summary || "No summary recorded."}</p>
            <p className="muted">
              <a href={advisory.url} target="_blank" rel="noreferrer noopener">{advisory.id}</a>
              {advisory.cves.length > 0 && <> · {advisory.cves.join(", ")}</>}
              {advisory.fixed_versions.length > 0 && <> · fixed in {advisory.fixed_versions.join(", ")}</>}
            </p>
          </section>
          <section>
            <h3>How the application depends on it</h3>
            <p className="dep-chain">{row.dependency_path.map((step, i) => <span key={i}>{step}</span>)}</p>
          </section>
          <section>
            <h3>Affected functions</h3>
            {row.symbols.affected.length ? (
              <ul>
                {row.symbols.affected.map((symbol) => (
                  <li key={symbol.symbol}>
                    <code>{symbol.symbol}</code>
                    <small>{symbol.exists ? symbol.provenance : "not found in this version's source"}</small>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No function is established as affected{row.symbols.unresolved.length ? `: ${row.symbols.unresolved.join("; ")}` : ""}.</p>
            )}
            {row.symbols.candidates.length > 0 && (
              <>
                <p className="muted">Changed by the fix, but the advisory does not name them (never enough on their own):</p>
                <ul>
                  {row.symbols.candidates.map((symbol) => (
                    <li key={symbol.symbol}><code>{symbol.symbol}</code></li>
                  ))}
                </ul>
              </>
            )}
          </section>
          <section>
            <h3>Call path</h3>
            {row.path?.length ? (
              <ol className="dep-path">
                {row.path.map((step, i) => (
                  <li key={i}>
                    <code>{step.function}</code>
                    <small>
                      {step.package === "<root>" ? "application" : step.package}
                      {step.called_from && (
                        <>
                          {" · called at "}{step.called_from.file}:{step.called_from.line}
                          {step.called_from.exact ? "" : <strong className="dep-guess"> not resolved to one target</strong>}
                        </>
                      )}
                    </small>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="muted">No path from an entry point to an affected function was found.</p>
            )}
          </section>
          {row.assumptions.length > 0 && (
            <section>
              <h3>Assumed</h3>
              <ul>{row.assumptions.map((item) => <li key={item}>{item}</li>)}</ul>
            </section>
          )}
          {row.limits.length > 0 && (
            <section>
              <h3>Limits of this analysis</h3>
              <ul>{row.limits.map((item) => <li key={item}>{item}</li>)}</ul>
            </section>
          )}
        </div>
      </details>
    </li>
  );
}

export function DependenciesView({ dependencies }: { dependencies?: Dependencies }) {
  const [status, setStatus] = useState<DependencyStatus | "All">("All");
  const summary = dependencySummary(dependencies);
  if (!dependencies)
    return (
      <div className="section-intro">
        <h2>Dependencies</h2>
        <p>This report has no dependency analysis. It runs for PHP applications that have a composer.lock, as part of a scan with both source and runtime selected.</p>
      </div>
    );
  const rows = dependencies.rows.filter((row) => status === "All" || row.status === status);
  const lookup = dependencies.advisory_lookup;
  return (
    <div className="dependencies-view">
      <div className="section-intro">
        <h2>Dependencies</h2>
        <p>Affected library versions, and whether the application can reach the vulnerable function. Advisories come from OSV; reachability is worked out from the application's and the libraries' own source.</p>
      </div>
      {summary.lookupFailed && (
        <div className="notice notice-warning" role="alert">
          The advisory lookup did not complete{lookup.error ? ` (${lookup.error})` : ""}, so which dependencies are affected is unknown. This is not a clean result.
        </div>
      )}
      <div className="dep-filter" role="group" aria-label="Filter by status">
        {(["All", ...DEPENDENCY_STATUSES] as const).map((value) => (
          <button
            key={value}
            type="button"
            aria-pressed={status === value}
            className={status === value ? "current" : ""}
            onClick={() => setStatus(value)}
          >
            {value}
            <span>{value === "All" ? dependencies.rows.length : summary.counts[value]}</span>
          </button>
        ))}
      </div>
      {rows.length ? (
        <ul className="dep-list">{rows.map((row) => <Row key={`${row.package}-${row.advisory.id}`} row={row} />)}</ul>
      ) : (
        <p className="ov-empty">
          {dependencies.rows.length
            ? `No dependency has the status ${status}.`
            : lookup.status === "ok"
              ? `No known advisories were returned by ${lookup.source ?? "OSV"}${lookup.fetched_at ? ` at ${lookup.fetched_at}` : ""}. That is not a guarantee: it only covers what that source knew.`
              : "No affected dependencies could be listed."}
        </p>
      )}
      {dependencies.supply_chain.length > 0 && (
        <section className="dep-supply">
          <h3>Supply chain</h3>
          <ul>
            {dependencies.supply_chain.map((finding, i) => (
              <li key={i}>
                <strong>{finding.kind}</strong> {finding.title}
                <small>{finding.evidence}</small>
              </li>
            ))}
          </ul>
        </section>
      )}
      <dl className="dep-key">
        {DEPENDENCY_STATUSES.map((value) => (
          <div key={value}>
            <dt>{value}</dt>
            <dd>{STATUS_MEANING[value]}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
