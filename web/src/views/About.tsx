const COVERAGE: [string, string, string][] = [
  ["FR-1, FR-2", "Source scan and runtime scan", "New scan"],
  ["FR-3", "One finding format with a CWE for every issue", "Every issue shows its CWE; both scanners write the format in common/"],
  ["FR-4", "Route map: URL to function and lines", "Routes"],
  ["FR-5, FR-6", "Linking runtime findings to code, and merging duplicates", "Issues: Why linked"],
  ["FR-7", "Confirmed, Code only or Runtime only", "Overview and Issues"],
  ["FR-8", "Issue detail: URL, parameter, payload, file, line, snippet", "Issues: the detail pane"],
  ["FR-9", "Confirmed first, then CVSS v3.0 risk", "Overview: Fix first. Issues: priority order"],
  ["FR-10", "Command line, API and page", "python -m cyberforge scan, /api/report, and this page"],
  ["B-1", "Re-test Code only issues at runtime", "Overview: Re-testing. Issue detail: Verify this finding"],
  ["B-2", "Cut SAST noise with reasons", "Coverage: suppressed findings"],
  ["B-3", "Explain every link", "Issues: Why linked"],
  ["B-4", "Fix guidance", "Issues: Fix guidance"],
  ["B-5", "Compare two scans", "New scan: Compare scans"],
  ["B-6", "SARIF export and CI gate", "Export. CI gate under New scan: Advanced controls"],
  ["B-7", "A second language and framework", "PHP and Python: Laravel, Flask, FastAPI, Django"],
  ["SCA note", "Reachability-aware dependency analysis", "Dependencies (Composer applications)"],
];

export function AboutView() {
  return (
    <div className="about-view">
      <div className="section-intro">
        <h2>About this workspace</h2>
        <p>
          Where each requirement of the brief lives in the application. Scans only reach this machine:
          localhost, 127.0.0.1 and, inside Docker, host.docker.internal. Reports stay on this machine.
        </p>
      </div>
      <table className="ov-table about-table">
        <thead>
          <tr><th>ID</th><th>Requirement</th><th>Where</th></tr>
        </thead>
        <tbody>
          {COVERAGE.map(([id, what, where]) => (
            <tr key={id}>
              <td><code>{id}</code></td>
              <td>{what}</td>
              <td>{where}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
