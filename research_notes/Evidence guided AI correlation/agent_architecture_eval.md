# Evidence gated agents and evaluation

## What should autonomy and multiple agents actually do?

### Takeaway
Use autonomous investigation inside a deterministic controller. Models propose explanations and the next evidence-gathering action; tool results and explicit policy determine whether an issue is linked, verified, contradicted or unresolved. This is a design recommendation, not a demonstrated performance result for this repository.

### Cited Findings
- Anthropic distinguishes predefined workflows from agents that direct their own tool use; recommends beginning with the simplest adequate design; notes latency/cost tradeoffs; and recommends environmental feedback and iteration limits. This supports selective escalation, not replacing the whole engine with a free-form agent. — [Building effective agents](https://www.anthropic.com/research/building-effective-agents)
- Its research system uses orchestrator/workers and benefits from independently parallelisable searches. Its reported research-evaluation gain is not a PHP-security result; the same article says shared-context/dependency-heavy tasks can be poor fits and reports substantially higher token consumption. Do not market its numbers as evidence our correlator will improve. — [Multi-agent research system](https://www.anthropic.com/research/multi-agent-research-system)
- The attachment describes deterministic CWE/route/input gating, pre-match SAST union-find grouping, runtime aggregation without method/location, and attaching any runtime evidence as sufficient for Confirmed. These are baseline claims supplied by the user; another research task is checking source. — [User-supplied engine description](/Users/ntbnaren7/.codex/attachments/1efb93d4-c38a-43e6-97eb-e83acb0abe51/Pasted%20text.txt)

### Inferences
**First fix baseline semantics.** If multiple root causes have already been collapsed into one SAST group, an LLM cannot recover them from the group's summary. Preserve atomic findings, method/input location and branch/security/session distinctions. Separate the proposition that an endpoint is vulnerable from the proposition that a particular source operation caused it. A unique metadata candidate is not by itself proof of either.

**Controller (ordinary code):** validates report/run identities; generates candidate links; dispatches only ambiguous, unmatched or contradictory cases; enforces a per-case budget and destination allowlist; caches analysis; records artifacts; and executes the final state-transition policy. Clean existing matches can stay on a fast path, but require evidence appropriate to their claimed status.

**Agent 1 — semantic investigator, read-only:** receives a bounded case packet containing raw findings, deployment identity, route/selector/method/input details, code graph slices, traces if available, and candidate alternatives. It can retrieve exact source snippets and adjacent callers/includes. It returns competing hypotheses, source spans, required preconditions, counterevidence, unresolved questions and a discriminating next test. Retrieval should combine explicit graph edges with lexical/semantic search; text similarity alone misses renamed variables and shared helpers. Every cited file, line and graph edge must be resolved by tooling.

**Agent 2 — verification planner:** converts an unresolved distinction into a concrete, non-destructive local test plan. Its required output is baseline action, changed input/state, expected observations under each hypothesis, reset/replay instructions, evidence to capture, and stop conditions. A deterministic executor—not free-form model shell access—performs permitted HTTP/browser/trace actions and returns immutable observations. The planner can adapt after results rather than merely selecting one fixed payload per CWE. For an MVP, investigator and planner can be one agent loop; split them when independent tool contexts justify it.

**Agent 3 — evidence reviewer, read-only:** searches for alternative explanations: source/deployment mismatch, stale session, multiple sinks, same error on a control request, reflection without browser execution, safe escaping, stored-flow writer mismatch, missing trace scope. It can reject unsupported assertions or request one additional controlled test; it cannot create supporting evidence by writing an explanation. Agreement between agents is not an independent observation, and model diversity is not a mathematical independence guarantee.

**Final adjudication:** maintain separate attribution states (unlinked/candidate/supported/ambiguous/contradicted) and runtime verification states (untested/inconclusive/reproduced/not reproduced). Preserve PRD labels as a derived compatibility view; document precisely which combination yields Confirmed. Do not encode model prose or a self-reported 95% confidence as an acceptance rule. A supported static path can justify attribution with stated limits when runtime instrumentation is unavailable; avoid pretending every case has exact dynamic proof.

**Bounded defaults to try, not research-established constants:** at most three candidate hypotheses; two investigation rounds; a fixed local request cap; wall-time and token caps per case; one optional review pass. On exhaustion: unresolved with the best evidence and next recommended action. Never turn timeout, auth failure, unavailable model or unsupported syntax into safe/not vulnerable. Provider choice should be replaceable; store model/version/prompt/tool schema settings for repeatability and allow deterministic-only operation.

**Privilege boundaries:** code browsing agents get read-only source/evidence tools; test executor gets explicitly configured local targets, same-origin redirect checks and approved test actions, not arbitrary internet/shell access; models cannot mark their own evidence verified or alter original reports. Source comments, HTML, error pages and scanner messages are untrusted data. Redact credentials/secrets from model context and preserve relevant raw artifacts locally with controlled access. This is necessary engineering for this tool, not a new user approval flow.

### Gaps
- No benchmark found demonstrates that three agents outperform one bounded investigator for this exact PHP correlation task. Compare both rather than claiming multiagent superiority.
- No provider/model was benchmarked, and no implementation or agent execution was performed in this research.
- Runtime instrumentation availability during judging is unresolved. It must be an optional capability tier, not a hidden requirement for core functionality.

## How do we handle unknown templates, unreliable observations and runtime variation?

### Takeaway
Unknown syntax, unknown labels, missing code context and intermittent runtime behaviour are different failures. A flexible evidence representation plus bounded hypothesis testing can handle some of them; adding agents does not remove the need for an explicit evidence contract.

### Cited Findings
- SARIF supports custom property bags and optional result taxonomies, separating extensible metadata from core result structures. That offers a precedent for extension fields rather than forcing every observation into a fixed CWE-shaped record. — [OASIS SARIF 2.1.0, property bags and taxonomies](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
- MITRE recommends specific actionable Base/Variant CWE mapping where adequate information exists. This is guidance for classification, not evidence that two records with matching classifications are one root cause. — [CWE root cause mapping guidance](https://cwe.mitre.org/documents/cwe_usage/guidance.html)
- OpenTelemetry models spans, relationships and links for operations, including subsequent/asynchronous operations. Sampling can intentionally omit traces/spans; absence of exported evidence cannot establish absence of execution. — [Traces](https://opentelemetry.io/docs/concepts/signals/traces/), [Sampling](https://opentelemetry.io/docs/concepts/sampling/)
- PHP automatic OpenTelemetry instrumentation requires PHP 8+, Composer autoloading, the extension, SDK and instrumentation libraries/configuration. The extension alone does not generate traces. This is not a universal drop-in for legacy PHP applications. — [PHP zero-code instrumentation](https://opentelemetry.io/docs/zero-code/php/auto/)
- AgentDojo evaluates agents using tools over untrusted data and demonstrates prompt-injection and ordinary task failures. Its application domains differ from PHP scanning, but it supplies direct evidence that tool output can redirect agent behaviour. — [AgentDojo](https://arxiv.org/abs/2406.13352)

### Inferences
Keep four explicit categories:

1. **Unseen app, familiar weakness:** route/parameter names and framework conventions differ. Graph retrieval and semantic code inspection can recover relationships that exact-string gates miss.
2. **Unknown or conflicting classification:** retain original scanner rule, raw CWE values, observed mechanism and candidate mappings. Use a nullable/unknown classification with reason; do not coerce an unfamiliar issue into an existing family merely to pass schema validation.
3. **Unknown mechanism or business-logic weakness:** record an evidence-backed hypothesis even when no existing verifier fits. A planner can design a task-specific local experiment, but no test/evidence means unverified—not universal zero-day detection.
4. **Unreliable state or observation:** request timing, authentication, role, cache, security level, asynchronous execution or data state changes the result. Establish session validity and controls, reset state where possible and record repeated observations. Environmental variation and stochastic LLM decisions are separate uncertainty sources.

Maintain a versioned core observation envelope with observation ID, origin/tool/version, run/deployment ID, artifact references, time, request/session/configuration identity, location(s), raw description, hypothesis/assertion and verification status; use typed optional evidence and extensions for new mechanisms. Missing properties are unknown, not empty-string matches. Schema-invalid model output is rejected/retried within budget; valid but unsupported output is preserved as a hypothesis. Schema compliance checks structure, not factual truth.

The common schema is valuable; the failure is conflating its field set with a closed list of vulnerabilities. Unknown categories must remain ingestible and visible without weakening required provenance. A database-write/read XSS sequence, for example, needs multiple related observations and storage/entity linkage rather than one route field. An agent may identify the candidate writer/reader, while a unique marker, recorded steps and controls establish the tested relationship.

For conditional includes, request configuration and executed branch matter. For query and body fields both named id, method and input location matter. For two SQL sinks within a handler, distinguish the operation identities; an HTTP error or function hit alone cannot identify which sink caused it. For async jobs, correlate the scheduling action and later worker with explicit context/entity IDs and document coverage limitations. Traces are execution evidence, not a taint oracle and not automatically exploit proof.

For nondeterministic timing, do controlled repeated baseline/test observations, avoid interpreting one slow response as an exploit and report sample counts/results rather than unsupported probability claims. For authenticated workflows, a scanner must recognise a redirected login page as a prerequisite failure. Keep each observation immutable: agent conclusions refer to its ID, not a mutable summary that could silently change.

### Gaps
- No schema extension can guarantee detection of vulnerability classes the source analyser/runtime observation system never observes. Open-ended intake and novel hypothesis generation improve adaptability, not completeness.
- Generic OpenTelemetry spans do not supply PHP statement-level sink attribution or data-flow tracking; targeted instrumentation, if available, would need its own design and validation.
- Textual prompt delimiters are not a complete prompt-injection defence. Enforced tool capabilities and scope limits remain necessary, and the complete system still needs adversarial tests.

## How do we prove AI improves the engine rather than the pitch?

### Takeaway
Measure correct root-cause links and wrong-link rate, alongside coverage, abstentions and expense. Evaluate incremental architecture changes against the existing baseline on held-out applications and deliberately difficult cases; do not use an LLM's own explanation as the answer key.

### Cited Findings
- Anthropic's agent-evaluation guidance distinguishes the transcript from the actual environmental outcome, and describes deterministic, model and human graders with different tradeoffs. A model saying it succeeded is not the outcome. — [Demystifying evals for AI agents](https://www.anthropic.com/research/demystifying-evals-for-ai-agents)
- PrimeVul identifies noisy labels, duplication and unrealistic evaluation as obstacles in vulnerability-detection datasets and introduces deduplication and chronological splitting. Its results concern code vulnerability detection, not PHP SAST/DAST correlation; its methodological warning is relevant. — [Vulnerability Detection with Code Language Models: How Far Are We?](https://arxiv.org/abs/2403.18624)
- Selective classification explicitly trades coverage for error risk by rejecting uncertain cases. Its statistical guarantees apply to its defined setting and cannot be borrowed for uncalibrated LLM self-confidence. — [Selective Classification for Deep Neural Networks](https://arxiv.org/abs/1705.08500)

### Inferences
Use five fixed experimental arms: A current deterministic baseline; B corrected grouping/verification/deployment semantics; C B plus one semantic investigator without new runtime actions; D C plus controlled adaptive verification; E D plus independent evidence reviewer/multiagent separation. Keep the tool permissions, request/token budget and evaluated apps fixed when comparing D versus E, otherwise extra compute confounds architecture claims. Make budget-matched and unrestricted comparisons separately if useful.

Measure candidate-generation recall, correct final root-cause links divided by manually verified linkable bugs, incorrect accepted links divided by all accepted links, false Confirmed labels, overmerges/oversplits and duplicate stability. Also show ambiguous/unresolved count and fraction, genuinely runtime-only findings, unsupported cases, scan time, P50/P95 case latency, model tokens/cost, requests, retries and failure counts. Candidate recall matters: a great adjudicator cannot select a true cause excluded from its evidence packet.

Report accuracy conditional on accepted links together with coverage: 100% precision at 5% coverage may be useless. Plot wrong-link risk versus accepted fraction; select thresholds using a development validation set, freeze before held-out testing, and publish numerator/denominator because small samples are unstable. Evidence tiers may be more defensible than pretend probabilities. With enough labelled cases, calibrate scores on held-out data and assess reliability; do not assume a model-generated percentage is calibrated.

Evaluate two kinds of reproducibility: replay the same recorded evidence to isolate model decision variance, and rerun live cases from reset state to expose environmental variance. Preserve model/prompt versions and tool transcripts, but acceptance must check artifact content and actual observed state. A model's final summary and a second model's endorsement do not establish correctness.

Use cases covering: one input/two sinks in one function; query/body fields with the same name; front-controller selectors; security-level-selected includes; changed routes/parameter names; helper-mediated flows; GET/POST reaching different handlers; stored-XSS write/read sequences; role/session-dependent access; transient 500 errors on both controls and tests; unknown/mislabelled CWE; unrelated findings with semantically similar descriptions; source/runtime revision mismatch; safe parameterisation; and instructions hidden in source comments or HTTP responses. Name/path mutations must be checked to preserve semantics; security patches intentionally change semantics and are paired controls, not invariance tests.

Reserve an application before prompt/rule tuning, deduplicate fixtures across partitions, and distinguish lab-derived known answers from cases independently assessed by the team. Public DVWA examples can be memorised by models, so anonymised or semantics-preserving variants plus another application are stronger checks than one familiar demo. Keep unassessed observations outside precision/recall denominators until reviewed. The user's teammate can implement this evaluation; the engine work should emit evidence and decisions needed to make it possible.

Practical implementation order: preserve atomic evidence and honest states first; add deterministic candidate retrieval plus read-only semantic investigation second; add controlled adaptive verification third; add an independent reviewer only if ablations justify its cost. A strong hackathon demonstration shows an old ambiguous case, the agent's competing explanations, the test it selected, the actual discriminating evidence and either a supported link or an explicit unresolved result.

### Gaps
- No measured result yet establishes an AI uplift for this engine. Proposed arms and example cases are an evaluation plan, not results.
- The available case count may be too small for reliable calibration or fine-grained significance claims. Publish raw counts and limits rather than claiming a statistically proven threshold.
