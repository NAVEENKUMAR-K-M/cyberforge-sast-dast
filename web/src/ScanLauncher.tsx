import { useEffect, useMemo, useState, type FormEvent } from "react";
import { LoaderCircle, Play, Square, Terminal, GitCompareArrows, Clock3 } from "lucide-react";
import { Button } from "./components/ui";

type Target = {
  id: string;
  name: string;
  url: string;
  language: string;
  sast_supported: boolean;
  source_available: boolean;
  description: string;
  custom?: boolean;
  default_source?: string;
};
type ScanJob = {
  id: string;
  target_name: string;
  target_url: string;
  status: "queued" | "running" | "stopping" | "complete" | "failed" | "stopped";
  stage: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  elapsed_seconds?: number | null;
  options: { run_sast?: boolean; run_dast?: boolean; investigation?: boolean; source_scan_id?: string; active_backend?: string; deadline_seconds?: number; sarif?: boolean; ci_gate?: boolean; semgrep?: boolean; web_root?: string; exclude?: string[] };
  logs: string[];
  error: string | null;
  report_path: string;
  gate: { passed: boolean; threshold: string; count: number } | null;
};
type ComparedIssue = { issue_id: string; title: string; label: string; severity: string; risk_score: number };
type Comparison = {
  baseline: { id: string; target: string };
  current: { id: string; target: string };
  new: ComparedIssue[];
  fixed: ComparedIssue[];
  still_open: ComparedIssue[];
};

const ACTIVE = new Set(["queued", "running", "stopping"]);

function formatElapsed(seconds: number) {
  const total = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const remaining = total % 60;
  if (hours) return `${hours}h ${String(minutes).padStart(2, "0")}m ${String(remaining).padStart(2, "0")}s`;
  if (minutes) return `${minutes}m ${String(remaining).padStart(2, "0")}s`;
  return `${seconds.toFixed(1)}s`;
}

export function ScanLauncher({ onReportReady, onActiveChange }: { onReportReady: () => void; onActiveChange?: (active: boolean) => void }) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [history, setHistory] = useState<ScanJob[]>([]);
  const [targetId, setTargetId] = useState("dvwa");
  const [targetUrl, setTargetUrl] = useState("http://localhost:8080");
  const [sourcePath, setSourcePath] = useState("");
  const [language, setLanguage] = useState("auto");
  const [runSast, setRunSast] = useState(true);
  const [runDast, setRunDast] = useState(true);
  const [backend, setBackend] = useState("python");
  const [deadline, setDeadline] = useState(480);
  const [basePath, setBasePath] = useState("");
  const [sarif, setSarif] = useState(true);
  const [ciGate, setCiGate] = useState(false);
  const [semgrep, setSemgrep] = useState(true);
  const [webRoot, setWebRoot] = useState("");
  const [excludesText, setExcludesText] = useState("");
  const [useRouteMap, setUseRouteMap] = useState(false);
  const [useSastHints, setUseSastHints] = useState(true);
  const [useSca, setUseSca] = useState(true);
  const [loginUrl, setLoginUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [bearerToken, setBearerToken] = useState("");
  const [jsonLogin, setJsonLogin] = useState(false);
  const [headersText, setHeadersText] = useState("");
  const [cookiesText, setCookiesText] = useState("");
  const [job, setJob] = useState<ScanJob | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [baseline, setBaseline] = useState("");
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [comparing, setComparing] = useState(false);

  const selectedTarget = useMemo(() => targets.find((target) => target.id === targetId), [targets, targetId]);
  const active = Boolean(job && ACTIVE.has(job.status));
  useEffect(() => {
    onActiveChange?.(active);
  }, [active, onActiveChange]);

  async function refreshHistory() {
    const response = await fetch("/api/scans", { cache: "no-store" });
    const body = await response.json();
    if (response.ok) {
      const scans = (body.scans ?? []) as ScanJob[];
      setHistory(scans);
      const running = scans.find((scan) => ACTIVE.has(scan.status));
      if (running) setJob(running);
      return scans;
    }
    return [];
  }

  useEffect(() => {
    void (async () => {
      try {
        const [targetResponse] = await Promise.all([fetch("/api/targets", { cache: "no-store" }), refreshHistory()]);
        const body = await targetResponse.json();
        if (!targetResponse.ok) throw new Error(body.detail || "Could not load scan targets.");
        const available = (body.targets ?? []) as Target[];
        setTargets(available);
        const first = available.find((item) => item.id === "dvwa") ?? available[0];
        if (first) {
          setTargetId(first.id);
          setTargetUrl(first.url);
          setSourcePath(first.default_source ?? "");
          setRunSast(first.sast_supported && first.source_available);
          setUseRouteMap(first.id === "benchmark_shop" || Boolean(first.custom));
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not load scan options.");
      }
    })();
  }, []);

  useEffect(() => {
    if (!job || !ACTIVE.has(job.status)) return;
    const timer = window.setInterval(() => {
      void fetch(`/api/scans/${job.id}`, { cache: "no-store" })
        .then(async (response) => {
          const body = await response.json();
          if (!response.ok) throw new Error(body.detail || "Could not read scan status.");
          return body as ScanJob;
        })
        .then((updated) => {
          setJob(updated);
          if (!ACTIVE.has(updated.status)) {
            void refreshHistory();
            if (updated.status === "complete") onReportReady();
          }
        })
        .catch((e) => setError(e instanceof Error ? e.message : "Could not read scan status."));
    }, 1200);
    return () => window.clearInterval(timer);
  }, [job?.id, job?.status, onReportReady]);

  async function startScan(event: FormEvent) {
    event.preventDefault();
    setError("");
    setComparison(null);
    setLoading(true);
    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: targetId,
          target_url: targetUrl,
          ...(selectedTarget?.custom ? { source_path: sourcePath, language } : {}),
          run_sast: runSast,
          run_dast: runDast,
          active_backend: backend,
          deadline_seconds: deadline,
          base_path: basePath,
          sarif,
          ci_gate: ciGate,
          semgrep,
          web_root: webRoot,
          exclude: excludesText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
          use_route_map: useRouteMap,
          use_sast_hints: useSastHints,
          use_sca: useSca,
          auth: {
            login_url: loginUrl,
            username,
            password,
            bearer_token: bearerToken,
            json_login: jsonLogin,
            headers: headersText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
            cookies: cookiesText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
          },
        }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not start scan.");
      setJob(body as ScanJob);
      void refreshHistory();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not start scan.");
    } finally {
      setLoading(false);
    }
  }

  async function stopScan() {
    if (!job) return;
    try {
      const response = await fetch(`/api/scans/${job.id}/stop`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not stop scan.");
      setJob(body as ScanJob);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not stop scan.");
    }
  }

  async function compare() {
    const current = history.find((item) => item.status === "complete");
    if (!baseline || !current || baseline === current.id) return;
    setComparing(true);
    setError("");
    try {
      const url = `/api/scans/compare?baseline=${encodeURIComponent(baseline)}&current=${encodeURIComponent(current.id)}`;
      const response = await fetch(url);
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not compare scans.");
      setComparison(body as Comparison);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not compare scans.");
    } finally {
      setComparing(false);
    }
  }

  function chooseTarget(id: string) {
    const next = targets.find((item) => item.id === id);
    setTargetId(id);
    if (next) {
      setTargetUrl(next.url);
      setSourcePath(next.default_source ?? "");
      setLanguage("auto");
      setRunSast(next.sast_supported && next.source_available);
      // The benchmark shop's interesting handlers are not all reachable from
      // its home page. Use its SAST route map by default, and for a custom
      // application, whose pages we can't know in advance; DVWA's much larger
      // map stays opt-in so its default scan can finish within the normal budget.
      setUseRouteMap(id === "benchmark_shop" || Boolean(next.custom));
      setDeadline(480);
    }
  }

  const completed = history.filter((item) => item.status === "complete" && !item.options.investigation);
  const newest = completed[0];
  const elapsedLabel = job?.elapsed_seconds != null
    ? formatElapsed(job.elapsed_seconds)
    : job?.started_at
      ? formatElapsed((Date.now() - Date.parse(job.started_at)) / 1000)
      : "Not recorded";

  return (
    <section className="scan-console" aria-labelledby="scan-console-title">
      <div className="scan-console-heading">
        <div>
          <h2 id="scan-console-title">New scan</h2>
          <p>Start the application first, then scan its source code, the running application, or both.</p>
        </div>
        <span className="local-badge">This machine only</span>
      </div>

      <form className="scan-form" onSubmit={(event) => void startScan(event)}>
        <div className="scan-form-grid">
          <label>
            Application
            <select value={targetId} onChange={(event) => chooseTarget(event.target.value)}>
              {targets.map((target) => <option key={target.id} value={target.id}>{target.name}</option>)}
            </select>
          </label>
          <label>
            Runtime URL
            <input value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder={selectedTarget?.custom ? "http://localhost:8081, or http://host.docker.internal:8081 in Docker" : "http://localhost:8080"} />
          </label>
          {selectedTarget?.custom && (
            <>
              <label>
                Source folder
                <input value={sourcePath} onChange={(event) => setSourcePath(event.target.value)} placeholder={selectedTarget.default_source || "/path/to/the/application/source"} />
              </label>
              <label>
                Source language
                <select value={language} onChange={(event) => setLanguage(event.target.value)}>
                  <option value="auto">Detect automatically</option>
                  <option value="php">PHP</option>
                  <option value="python">Python</option>
                </select>
              </label>
            </>
          )}
          <div className="scan-engine-options" role="group" aria-label="Scanners to run">
            <label className="scan-check">
              <input type="checkbox" checked={runSast} disabled={!selectedTarget?.sast_supported || !selectedTarget.source_available} onChange={(event) => setRunSast(event.target.checked)} />
              <span><strong>SAST</strong><small>{selectedTarget?.sast_supported ? (selectedTarget.source_available ? `${selectedTarget.language} source` : "Source checkout missing") : "PHP and Python engines; JavaScript is not supported"}</small></span>
            </label>
            <label className="scan-check">
              <input type="checkbox" checked={runDast} onChange={(event) => setRunDast(event.target.checked)} />
              <span><strong>DAST</strong><small>Scan the running local app</small></span>
            </label>
          </div>
        </div>

        {!!selectedTarget && <p className="target-capability">{selectedTarget.description}{selectedTarget.id === "juice_shop" && " Juice Shop results will be Runtime only until a JavaScript SAST engine is added."}</p>}

        <details className="scan-advanced">
          <summary>Advanced controls</summary>
          <div className="scan-advanced-grid">
            <label>DAST backend<select value={backend} onChange={(event) => setBackend(event.target.value)}><option value="python">CyberForge active probes</option><option value="none">Passive checks only</option><option value="zap">OWASP ZAP</option><option value="nuclei">Nuclei</option></select></label>
            <label>Runtime budget (seconds)<input type="number" min={30} max={600} step={30} value={deadline} onChange={(event) => setDeadline(Number(event.target.value))} /></label>
            <label>URL base path<input value={basePath} onChange={(event) => setBasePath(event.target.value)} placeholder="/app (optional)" /></label>
            <label className="scan-check"><input type="checkbox" checked={sarif} onChange={(event) => setSarif(event.target.checked)} /><span><strong>Produce SAST SARIF</strong><small>Write a SARIF file with the static findings.</small></span></label>
            <label className="scan-check"><input type="checkbox" checked={ciGate} onChange={(event) => setCiGate(event.target.checked)} /><span><strong>CI gate</strong><small>Mark the gate failed for confirmed high or critical issues.</small></span></label>
            <label className="scan-check"><input type="checkbox" checked={semgrep} disabled={!runSast} onChange={(event) => setSemgrep(event.target.checked)} /><span><strong>Pattern rules</strong><small>Run Semgrep alongside taint analysis.</small></span></label>
            <label className="scan-check"><input type="checkbox" checked={useSastHints} disabled={!runSast || !runDast} onChange={(event) => setUseSastHints(event.target.checked)} /><span><strong>Prioritize SAST hints</strong><small>Probe discovered inputs linked to source findings first.</small></span></label>
            <label className="scan-check"><input type="checkbox" checked={useSca} disabled={!runSast} onChange={(event) => setUseSca(event.target.checked)} /><span><strong>Dependency analysis</strong><small>For PHP apps with a composer.lock. Sends package names and versions, never source code, to public advisory services.</small></span></label>
            <label className="scan-check"><input type="checkbox" checked={useRouteMap} disabled={!runSast || !runDast} onChange={(event) => setUseRouteMap(event.target.checked)} /><span><strong>Expand with SAST route map</strong><small>{selectedTarget?.id === "benchmark_shop" ? "Enabled by default for this target to cover the discovered handlers." : "Discovers more routes, but can use the DAST time budget before active probes finish."}</small></span></label>
            <label>Source web root<input value={webRoot} disabled={!runSast} onChange={(event) => setWebRoot(event.target.value)} placeholder="Detected automatically" /></label>
            <label>Exclude folders <span className="muted">one folder name per line</span><textarea disabled={!runSast} value={excludesText} onChange={(event) => setExcludesText(event.target.value)} rows={2} placeholder="vendor\nthird_party" /></label>
            <label>Login URL<input value={loginUrl} onChange={(event) => setLoginUrl(event.target.value)} placeholder="Optional; same local host and port" /></label>
            <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /></label>
            <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></label>
            <label>Bearer token<input type="password" value={bearerToken} onChange={(event) => setBearerToken(event.target.value)} /></label>
            <label className="scan-check"><input type="checkbox" checked={jsonLogin} onChange={(event) => setJsonLogin(event.target.checked)} /><span><strong>JSON login body</strong><small>Use a JSON request for the configured login endpoint.</small></span></label>
            <label>Extra headers <span className="muted">one Name:Value per line</span><textarea value={headersText} onChange={(event) => setHeadersText(event.target.value)} rows={2} placeholder="X-Test-Mode: true" /></label>
            <label>Cookies <span className="muted">one name=value per line</span><textarea value={cookiesText} onChange={(event) => setCookiesText(event.target.value)} rows={2} placeholder="session=..." /></label>
          </div>
          <p className="footnote">Credentials are sent only to the selected local target and are not saved in scan history.</p>
        </details>

        <div className="scan-actions">
          <Button type="submit" disabled={loading || active || !targets.length || (!runSast && !runDast) || (runSast && !selectedTarget?.sast_supported)}>
            {loading ? <LoaderCircle className="spin" size={15} /> : <Play size={15} />}
            Start scan
          </Button>
          {active && <Button type="button" variant="outline" onClick={() => void stopScan()}><Square size={14} /> Stop scan</Button>}
          {newest && <a className="button button-outline" href="/api/export/sarif">Export current report as SARIF</a>}
        </div>
      </form>

      {error && <div className="notice notice-warning" role="alert">{error}</div>}

      {job && (
        <div className={`scan-run-state ${job.status}`}>
          <div className="scan-run-heading">
            <div><span className="eyebrow">{job.status.toUpperCase()}</span><h3>{job.target_name} <span>·</span> {job.stage}</h3><code>{job.target_url}</code></div>
            <span className="elapsed-chip"><Clock3 size={13} /> {job.options.investigation ? "Investigation time" : "Total run time"} <strong>{elapsedLabel}</strong></span>
            {job.gate && <span className={job.gate.passed ? "gate-passed" : "gate-failed"}>{job.gate.passed ? "CI gate passed" : "CI gate failed"} · {job.gate.count} blocking issues</span>}
          </div>
          {!job.options.investigation && <ol className="scan-stage-rail" aria-label="Scan progress">
            {["Source analysis", "Runtime analysis", "Correlating findings"].map((stage, index) => {
              const current = String(job.stage || "");
              const skipped = (index === 0 && job.options.run_sast === false) || (index === 1 && job.options.run_dast === false);
              const done = job.status === "complete" || (index === 0 && /Runtime|Correlat|Complete/i.test(current)) || (index === 1 && /Correlat|Complete/i.test(current));
              const activeStage = current.toLowerCase().includes(stage.split(" ")[0].toLowerCase());
              return <li key={stage} className={skipped ? "skipped" : done ? "done" : activeStage ? "active" : ""}><span>{skipped ? "–" : done ? "✓" : index + 1}</span>{stage}{skipped ? " · skipped" : ""}</li>;
            })}
          </ol>}
          {!!job.error && <p className="notice notice-warning">{job.error}</p>}
          {!!job.logs.length && <details className="scan-log" open={active}><summary><Terminal size={14} /> Scan log <span>{job.logs.length} lines</span></summary><pre>{job.logs.join("\n")}</pre></details>}
          {job.status === "complete" && <p className="footnote">Combined report saved at <code>{job.report_path}</code>. The findings view refreshes when the scan completes.</p>}
        </div>
      )}

      {completed.length > 1 && (
        <div className="scan-compare-control">
          <div><strong>Compare scans</strong><p>Show issues added, fixed, and still open between completed scans.</p></div>
          <label>Compare against<select value={baseline} onChange={(event) => setBaseline(event.target.value)}><option value="">Choose an earlier scan</option>{completed.slice(1).map((scan) => <option key={scan.id} value={scan.id}>{scan.target_name} · {new Date(scan.created_at).toLocaleString()}</option>)}</select></label>
          <Button type="button" variant="outline" disabled={!baseline || comparing} onClick={() => void compare()}>{comparing ? <LoaderCircle className="spin" size={14} /> : <GitCompareArrows size={14} />}Compare</Button>
        </div>
      )}
      {comparison && <div className="comparison-results"><h3>{comparison.baseline.target} → {comparison.current.target}</h3><div className="comparison-counts"><span>New <strong>{comparison.new.length}</strong></span><span>Fixed <strong>{comparison.fixed.length}</strong></span><span>Still open <strong>{comparison.still_open.length}</strong></span></div><ComparisonGroup title="New" issues={comparison.new} /><ComparisonGroup title="Fixed" issues={comparison.fixed} /><ComparisonGroup title="Still open" issues={comparison.still_open} /></div>}
      {history.length > 0 && <p className="scan-history-note">{history.length} saved local scan{history.length === 1 ? "" : "s"}. Scan reports and elapsed times are stored under <code>out/scans/</code>.</p>}
    </section>
  );
}

function ComparisonGroup({ title, issues }: { title: string; issues: ComparedIssue[] }) {
  return <details className="comparison-group"><summary>{title} <span>{issues.length}</span></summary>{issues.length ? <ul>{issues.map((issue) => <li key={issue.issue_id}><span>{issue.title}</span><code>{issue.label} · {issue.severity} · CVSS {issue.risk_score.toFixed(1)}</code></li>)}</ul> : <p>None</p>}</details>;
}
