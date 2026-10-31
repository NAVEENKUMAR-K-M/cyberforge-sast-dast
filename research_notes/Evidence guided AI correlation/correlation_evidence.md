# Current correlation engine and evidence guided attribution

## What must change in the existing engine before AI can help?

### Takeaway

The current engine is a useful conservative metadata join in several cases, but its early grouping and label semantics can erase distinctions and overstate proof. AI should investigate unresolved links over preserved observations; it cannot reconstruct evidence that was collapsed before it received the case. This assessment verifies the pasted description against the current source, without running tests or changing implementation.

### Cited Findings

- The input schema already requires a sink, source trace, conditions and stored-flow field on code findings, but `_match()` only checks family, input name/location, route/selector and optional stored write-route metadata. Richer evidence exists upstream but is not assessed during matching. [Schema](/Users/ntbnaren7/Dev/cyberforge-sast-dast/common/finding.schema.json:40), [Matcher](/Users/ntbnaren7/Dev/cyberforge-sast-dast/correlator/correlate.py:109).
- `_code_groups()` merges code findings in the same family/file/function when input-name sets overlap. Transitive union can connect A=`{id}`, B=`{id,name}` and C=`{name}` despite no direct A–C overlap; sinks, lines and execution conditions are not compared. The transitivity is a deduction from the actual union loop, not an observed failure on a runtime app. [Grouping](/Users/ntbnaren7/Dev/cyberforge-sast-dast/correlator/correlate.py:141).
- Runtime grouping uses family/path/selector/first parameter name. It excludes method, input location, verification and configuration. When any member establishes one strong code-group candidate, all runtime members are attached to that group. An early GET/POST merge can therefore contaminate attribution across distinct handlers. This is a structural risk rather than a claim that every cross-method merge is wrong. [Runtime grouping](/Users/ntbnaren7/Dev/cyberforge-sast-dast/correlator/correlate.py:166), [Attach group](/Users/ntbnaren7/Dev/cyberforge-sast-dast/correlator/correlate.py:254).
- The label is `Confirmed` whenever runtime evidence is attached. It does not require `runtime.verification == confirmed`, although that tier is preserved in the schema and used later for ranking. Consequently a tentative DAST result can become a Confirmed issue. [Label](/Users/ntbnaren7/Dev/cyberforge-sast-dast/correlator/correlate.py:283), [Verification schema](/Users/ntbnaren7/Dev/cyberforge-sast-dast/common/finding.schema.json:64), [Rank](/Users/ntbnaren7/Dev/cyberforge-sast-dast/correlator/rank.py:63).
- Suppressed SAST matches cause a conflict record and `continue`, rather than retaining a Runtime only issue. This removes a runtime finding from the issue list because static suppression disagrees with it. The disagreement is preserved in a separate conflict list, but not as an actionable issue. [Conflict branch](/Users/ntbnaren7/Dev/cyberforge-sast-dast/correlator/correlate.py:269).
- The common report schema has no required build digest, deployment identifier, session/security profile or source/container mapping. A route-overlap diagnostic is not a deployment identity check. Same-path findings from different versions can link. [Report properties](/Users/ntbnaren7/Dev/cyberforge-sast-dast/common/finding.schema.json:7), [Diagnostic](/Users/ntbnaren7/Dev/cyberforge-sast-dast/correlator/correlate.py:290).
- The family table maps CWE-943→89 and CWE-98→22. MITRE defines 943 as a broad query-logic class whose children include SQL, LDAP and XPath injection. CWE-98 is PHP include/require filename control; CWE-22 concerns escaping a restricted path. They can relate or occur in a chain, but those relationships do not establish identity. [Current map](/Users/ntbnaren7/Dev/cyberforge-sast-dast/common/cwe_families.json:1), [MITRE 943](https://cwe.mitre.org/data/definitions/943.html), [MITRE 98](https://cwe.mitre.org/data/definitions/98.html), [MITRE 22](https://cwe.mitre.org/data/definitions/22.html).

### Inferences

- Preserve each scanner observation as immutable evidence with its original type and provenance. Generate candidate links before deciding underlying bug identity. Deduplicate exact repeated observations early, but delay semantic issue merging until attribution is established. Keep relatedness separate from equivalence; uncertain edges must not participate in unrestricted union-find closure.
- Use a candidate graph: request observations, input occurrences, entry points, source statements, transformations, sinks, storage entities, browser observations and execution conditions are typed nodes/edges. A graph can be stored as ordinary indexed records; a graph database is not required. Pairwise rules remain useful for generating and rejecting candidates. Do not force one-to-one matching: one sink may be exposed by several routes, and one request can exercise multiple distinct sinks.
- Distinguish `exploit_status` from `attribution_status`. Suggested exploit values: untested/suspected/validated/inconclusive; attribution values: unmapped/candidate/ambiguous/supported/contradicted. Compute public labels from these axes. A validated runtime weakness with ambiguous code attribution remains Runtime only plus candidates; a plausible join with tentative runtime evidence is correlated but not exploit-validated. If retaining the PRD's broad Confirmed label, explicitly expose its weaker definition and a separate proof tier.
- Treat an explicit contradiction differently from missing information. Known POST-only handler versus observed GET may reject that candidate; an incomplete static method list is an unknown, not a contradiction. Apply the same distinction to unknown input location, unresolved include and sanitizer state.
- Keep runtime findings visible when they contradict suppression. The engine should open an investigation with both evidence sets, not treat static suppression as stronger ground truth. Suppression may be stale, context-specific or wrong; the runtime alert may also be wrong.
- Do not use maximum member confidence as evidence of confidence in the joined issue. Grouping and attribution have their own failure modes. A confident observation can be attached to the wrong root cause.

### Gaps

- The pasted description reports 67 passing tests. No test suite was executed here, and passing unit tests would not independently establish real-world correlation accuracy.
- The audit did not assess every scanner's construction of its trace, conditions or suppression metadata. Such fields are evidence claims, not automatically verified facts.

## What runtime evidence can establish beyond CWE and path similarity?

### Takeaway

When local deployment access permits it, correlate test requests with observed execution and specific operations. This can resolve dynamic include and handler ambiguity that an LLM alone cannot. Observed execution is stronger attribution evidence than a plausible path, but it still does not by itself prove that a particular operation caused the security outcome.

### Cited Findings

- PHP includes inherit the variable scope of the include location; functions/classes defined in the included file have global scope. An include inside a function therefore has different shared-variable context from a top-level include. This is why filename connectivity alone is not a taint model. [PHP include semantics](https://www.php.net/manual/en/function.include.php).
- `get_included_files()` returns files loaded using include/require variants, includes the initially called script and lists repeatedly included files once. This supplies a loaded-file set, not values, variable flow or repeated execution history. [PHP included-files API](https://www.php.net/manual/en/function.get-included-files.php).
- Xdebug supports function traces with call locations and configurable parameter, return and assignment recording, including a machine-readable format. Tracing can start with a request or be triggered. It is therefore a practical candidate for request-level execution evidence, subject to version/configuration checks. Its trace is not a complete PHP dynamic-taint engine. [Xdebug tracing](https://xdebug.org/docs/trace).
- Xdebug coverage records executed lines/files and can additionally collect branches/paths with overhead. Collection/filtering must begin at the appropriate point; filtering is established when executable units are first included. A missing hit is only meaningful within the collection's actual scope. [Xdebug coverage](https://xdebug.org/docs/code_coverage).
- W3C Trace Context defines HTTP headers for propagating trace identity across services. A trace identifier connects associated observations; it is not itself a security proof or a guarantee that an arbitrary application records internal source activity. [W3C Trace Context](https://www.w3.org/TR/trace-context/).
- PHP OpenTelemetry automatic instrumentation requires PHP 8+, extension, Composer autoloading, SDK and suitable instrumentation libraries. Installing the extension alone produces no traces; available spans depend on libraries and paths exercised. Existing PHP 5-era labs cannot be assumed compatible. [OpenTelemetry PHP](https://opentelemetry.io/docs/zero-code/php/auto/).
- OWASP SQL-injection testing discusses Boolean-controlled comparisons and response-template handling for inference. Its stored-XSS guidance covers persistent inputs and later execution contexts. These support controlled outcome validation instead of treating errors or text reflection as universal proof. [SQLi testing](https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection), [Stored XSS testing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting/).

### Inferences

Recommended evidence ladder, treating levels as support categories rather than calibrated probabilities:

1. **Metadata compatibility:** same broad mechanism, candidate entry point and input. Useful retrieval evidence; insufficient to prove identity.
2. **Static contextual path:** explicit source-to-sink path, include/function transitions and branch assumptions, with relevant protections examined. A plausible path can be infeasible.
3. **Observed request execution:** request ID maps to actual entry point, included files, calls, lines and conditions. This rejects inactive candidates but does not show which input influenced which sink.
4. **Observed influence:** controlled marker or paired input differences are visible at a specific operation, with exact source mapping and transformations recorded. Repeated strings still need disambiguation; seeing a marker in a SQL argument may represent safely bound data.
5. **Validated security outcome plus supported attribution:** mechanism-specific behavioral evidence, negative controls and repeatability support both the weakness and the link to the particular operation.

Request-level instrumentation is best used selectively on ambiguous cases, not on every request: normalise scanner evidence, find candidate operations, then capture a bounded trace. Require trace-completeness metadata. File-level or line-level coverage must not be represented as dynamic taint proof. Output constructs or operations not visible as traceable calls may require separate observation; do not promise that every `echo` or every sink is automatically captured by a function tracer.

Two deployment modes are necessary. **Source+HTTP mode** works without modifying the target and may stop at supported/ambiguous attribution. **Instrumented local mode** adds observed execution/influence when the organiser allows extensions or hooks. A solution must not quietly depend on installing Xdebug into an unseen app whose environment cannot be modified.

Schema additions should record: application/build ID, source-file digest, container-to-source path map, configuration/security profile ID, role/session profile, request/attempt ID, browser/workflow ID, timestamp, method and input occurrence, baseline/control/test artifact IDs, observed sink call-site ID, coverage scope/completeness, observation type and original producer. A call site needs original file and statement/AST fingerprint, not merely a function name. Proposed/observed/inferred must be distinguishable on every edge.

For stored flows, preserve write request → storage record/key → read request → rendering site → browser execution. Merely placing a writer route in static metadata cannot establish that a later effect originated from that write. Use a harmless unique marker, isolated lab state and workflow linkage; account for different roles and multiple requests. Avoid persisting raw session secrets in model context or reports.

For response validation, keep baseline and controls with exact observations. Random page tokens, timestamps, rotating records and network latency can create superficial differences. A source location can be strongly attributed while the exploit remains inconclusive; conversely a browser outcome can be validated without exact source attribution.

Optional counterfactual checks on a disposable copy—such as comparing an upstream fixed version or a narrowly controlled protection change—can strengthen attribution. They remain a hypothesis test: broad edits alter many behaviors, and a changed response can come from broken application functionality rather than corrected security. No production mutation belongs in the default investigation loop.

### Gaps

- Instrumentation feasibility for the unseen app is unknown. PHP/runtime versions, installation rights, sampling, generated templates, caching and source path mapping need checking.
- No trace setup or browser verification was executed in this research. Instrumentation suggestions are designs grounded in documented capabilities, not measured integrations.

## How should autonomous investigators handle unknown and unreliable cases?

### Takeaway

The useful shift is from one-shot matching to a bounded investigation that acquires missing evidence. Unfamiliar code structure is usually an epistemic problem—insufficient knowledge—not a reason to make the correlator nondeterministic. Actual timing/state variability requires repeated controlled observation, while model sampling variability is a separate concern.

### Cited Findings

- The current correlator reads the two scanner reports and has no active evidence-acquisition step; unsupported or missing scanner context cannot be recovered by more elaborate sorting. [Module contract](/Users/ntbnaren7/Dev/cyberforge-sast-dast/correlator/correlate.py:1).
- It already records multiple strong candidates as Runtime only/ambiguous and keeps link explanations. This is a useful foundation for an investigation queue, rather than functionality to discard in favour of model guesses. [Ambiguity branch](/Users/ntbnaren7/Dev/cyberforge-sast-dast/correlator/correlate.py:278).

### Inferences

Suggested investigation contract: present an agent with preserved observations and a bounded source slice. Require its output to name candidate source statements, supporting artifact IDs, unresolved assumptions, contradictory facts, and the next discriminating observation. The agent proposes hypotheses and tests; a tool runner collects observations, and a deterministic evidence policy commits statuses. Model certainty and agreement among agents are not artifacts.

Concrete cases:

- **Dynamic include:** agent traces selection logic and proposes two possible implementation files. A request-scoped loaded-file/line observation distinguishes the active implementation. An inactive static finding remains Code only; it is not globally safe.
- **Two sinks in one handler:** agent identifies two operations reached from the same parameter. Runtime execution plus operation-specific input influence may distinguish them; otherwise keep two candidates and avoid merging. Executing both still does not identify which caused an observed effect.
- **Parameter renamed by a wrapper:** semantic source analysis can map external `q` to helper `$term`, overcoming exact-name matching. The proposed mapping must cite assignments/calls and be checked against source or runtime evidence.
- **Custom protection:** agent explains what a wrapper actually checks instead of trusting a name such as `sanitize`. Positive and negative examples can challenge the hypothesis. No unsupported general claim that every user-defined sanitizer is safe or unsafe.
- **Previously unknown weakness:** retain a mechanism description and evidence even with CWE unknown/provisional; then broaden source search by operations and trust boundaries. AI can suggest a new detector or lab verification recipe, but absence of a reviewed oracle means tentative status, not automatic confirmation. Correlation does not discover observations scanners and exploration never collected.
- **Flaky runtime:** reset known state when possible, repeat baseline/control/test in interleaved order, record role/session/configuration, and stop with inconclusive when effects fail to separate from noise. More model reasoning cannot remove missing authentication or unstable test state.

Highest-priority improvements: preserve observations and deployment identity; correct proof labels and suppressed conflicts; move from destructive grouping to candidate edges; use source trace/conditions and an explicit contradiction model; add one selective runtime attribution mechanism; then make agents request evidence for unresolved cases. This ordering is a recommendation based on the verified limitations, not a claim of experimentally proven optimality.

### Gaps

- There is no measured calibration set for assigning numerical probabilities to links. Use ordinal evidence states initially; any numerical confidence needs validation on independent, held-out cases.
- General new vulnerability classes, races and missing business-logic checks can require new exploration strategies and outcome oracles. A flexible schema and LLM do not provide universal vulnerability discovery.
