import { useEffect, useState } from "react";
import { BrainCircuit, LoaderCircle, ShieldCheck } from "lucide-react";
import { Button } from "./components/ui";

type Provider = { id: string; label: string; configured: boolean };
type Investigation = {
  case_id: string;
  issue_id: string;
  outcome: string;
  stop_reason?: string | null;
  rounds: { round: number; plan: Record<string, unknown>; requests_sent?: Record<string, unknown>[]; outcome: string; evidence?: Record<string, unknown> | null; effect?: Record<string, unknown> | null; error?: string | null }[];
};
type Props = { scanId: string | null; example: boolean; investigationRun?: boolean; investigations?: Investigation[]; titles?: Record<string, string>; onComplete: () => void };

export function AIAssistant({ scanId, example, investigationRun = false, investigations = [], titles = {}, onComplete }: Props) {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [consent, setConsent] = useState(false);
  const [job, setJob] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    fetch("/api/ai/status").then((response) => response.json()).then((data) => {
      if (!active) return;
      const available = (data.providers ?? []) as Provider[];
      setProviders(available);
      setProvider((current) => current || available.find((item) => item.configured)?.id || available[0]?.id || "");
    }).catch(() => { if (active) setError("AI provider status is unavailable."); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    const id = job?.id;
    if (typeof id !== "string" || !["queued", "running"].includes(String(job?.status))) return;
    const timer = window.setInterval(async () => {
      try {
        const response = await fetch(`/api/scans/${encodeURIComponent(id)}`);
        if (!response.ok) return;
        const next = await response.json();
        setJob(next);
        if (["complete", "failed", "stopped"].includes(next.status)) {
          setBusy(false);
          if (next.status === "complete") onComplete();
        }
      } catch { /* Keep the last visible progress while the local server reconnects. */ }
    }, 900);
    return () => window.clearInterval(timer);
  }, [job?.id, job?.status, onComplete]);

  async function start() {
    if (!scanId || !provider) return;
    setError("");
    setBusy(true);
    try {
      const response = await fetch(`/api/scans/${encodeURIComponent(scanId)}/investigate`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider, model: model.trim() || null, consent }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not start AI investigation.");
      setJob(data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not start AI investigation.");
      setBusy(false);
    }
  }

  const selected = providers.find((item) => item.id === provider);
  const active = job && ["queued", "running"].includes(String(job.status));
  return <section className="ai-panel" aria-labelledby="ai-title">
    <div className="ai-panel-title">
      <div><h2 id="ai-title">AI-assisted follow-up</h2></div>
      <span className="provider-state">{selected?.configured ? `${selected.label} configured` : "Provider not configured"}</span>
    </div>
    <p>A full scan re-tests Code only issues automatically. When one can't be proven, a language model may propose one more request. It can only adjust the request, and the correlator alone decides whether the result counts as proof. This panel runs that step by hand for a scan that didn't get it.</p>
    <details className="ai-disclosure">
      <summary>Review what may be shared when an AI provider is used</summary>
      <div><ShieldCheck size={15} /><span>When a configured provider is used, it may receive the relevant finding, handler source snippets (up to three files, with obvious secrets redacted), trace details, and prior runtime test results. The API key stays on this machine and is never shown here. Without a configured provider, follow-up re-testing still runs, but no data leaves this machine. The investigation is bounded (up to 20 cases and 180 seconds) so a hard case can't hang the scan, while the scan, correlation and investigation together stay comfortably inside a 15-minute run.</span></div>
    </details>
    {!example && scanId && !investigationRun && <div className="ai-controls">
      <label>Provider<select value={provider} onChange={(event) => setProvider(event.target.value)}>{providers.map((item) => <option key={item.id} value={item.id}>{item.label}{item.configured ? " · ready" : " · not configured"}</option>)}</select></label>
      <label>Model <span className="muted">{provider === "openai" ? "required for OpenAI" : "optional; Groq CLI default if blank"}</span><input value={model} onChange={(event) => setModel(event.target.value)} placeholder={provider === "openai" ? "Enter OpenAI model id" : "Groq default model"} /></label>
      <label className="ai-consent"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} /><span>I understand that source and runtime evidence described above may be sent to the selected provider.</span></label>
      <Button type="button" variant="outline" disabled={busy || !consent || !selected?.configured || (provider === "openai" && !model.trim())} onClick={() => void start()}>{busy ? <LoaderCircle className="spin" size={14} /> : <BrainCircuit size={14} />}Investigate with AI</Button>
    </div>}
    {example && <p className="ai-inline-note">Example reports cannot start a live investigation. Select a target and run a scan first.</p>}
    {investigationRun && <p className="ai-inline-note">This scan already ran follow-up re-testing. Its outcome is shown below.</p>}
    {!example && !scanId && <p className="ai-inline-note">Run a live scan to enable investigation.</p>}
    {error && <p className="notice notice-warning" role="alert">{error}</p>}
    {active && <><div className="ai-progress" role="status"><LoaderCircle className="spin" size={15} /><strong>{String(job?.stage || "Investigation running")}</strong><span>{Array.isArray(job?.logs) ? `${(job.logs as unknown[]).length} log lines` : "Preparing"}</span></div>{Array.isArray(job?.logs) && (job.logs as string[]).length > 0 && <details className="ai-live-log"><summary>Investigation log</summary><pre>{(job.logs as string[]).slice(-12).join("\n")}</pre></details>}</>}
    {job && !active && <p className={`ai-inline-note ${job.status === "complete" ? "ai-success" : ""}`} role="status">Investigation {String(job.status)}{job.error ? `: ${String(job.error)}` : ". The report has been refreshed with its outcome."}</p>}
    {!!investigations.length && <div className="ai-outcomes"><h3>Investigation outcomes <span>{investigations.length} case{investigations.length === 1 ? "" : "s"} · AI proposal is not proof</span></h3><div className="ai-outcomes-scroll">{investigations.map((item, index) => <details key={`${item.case_id}-${index}`}><summary><strong>{item.outcome}</strong> · {titles[item.issue_id] ?? item.issue_id} · {item.rounds.length} test round{item.rounds.length === 1 ? "" : "s"}</summary><p>Stop reason: {item.stop_reason || "Not recorded"}</p>{item.rounds.map((round) => <div className="ai-round" key={round.round}><strong>Round {round.round}: follow-up plan and executed test</strong><p>Planned request fields:</p><pre>{JSON.stringify(round.plan, null, 2)}</pre><p>Requests actually sent ({round.requests_sent?.length ?? 0}):</p>{!!round.requests_sent?.length && <pre>{JSON.stringify(round.requests_sent.map((attempt) => Object.fromEntries(Object.entries(attempt).filter(([key]) => ["method", "url", "status", "length", "location"].includes(key)))), null, 2)}</pre>}<p>Scanner outcome: {round.outcome}{round.error ? ` · ${round.error}` : ""}</p>{round.evidence && <><p>Correlator evidence:</p><pre>{JSON.stringify(round.evidence, null, 2)}</pre></>}</div>)}</details>)}</div></div>}
    <p className="ai-validation-note">Only runtime evidence accepted by the correlator can change an issue label. A model proposal by itself never confirms a finding.</p>
  </section>;
}
