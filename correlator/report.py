"""Writes one HTML page from issues.json (FR-8): a ranked list, then for each issue where to look
in the running app (URL, parameter, payload) and in the code (file, line, snippet).

Everything shown is escaped: payloads and snippets are attack strings and must never run here.
"""
from __future__ import annotations

from html import escape

STYLE = """
body { font: 14px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 70rem; padding: 0 1rem; color: #1a1a1a; background: #fff; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #ddd; vertical-align: top; }
code, pre { font: 13px ui-monospace, monospace; background: #f4f4f4; }
pre { padding: .6rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
section { border: 1px solid #ddd; border-radius: 6px; padding: .5rem 1rem 1rem; margin: 1rem 0; }
dl { display: grid; grid-template-columns: 9rem 1fr; gap: .2rem 1rem; }
dt { color: #555; }
.label { font-weight: 600; }
.muted { color: #666; }
@media (prefers-color-scheme: dark) {
  body { color: #e6e6e6; background: #161616; }
  th, td, section { border-color: #333; }
  code, pre { background: #232323; }
  dt, .muted { color: #aaa; }
}
"""


def _e(value) -> str:
    return escape(str(value), quote=True)


def _where_short(issue: dict) -> str:
    code = issue["evidence"]["code"]
    url = issue["routes"][0]["path"] if issue["routes"] else ""
    place = f"{code[0]['code']['file']}:{code[0]['code']['line']}" if code else ""
    return " · ".join(_e(p) for p in (url, place) if p) or '<span class="muted">whole app</span>'


def _runtime_rows(issue: dict) -> str:
    rows = []
    for f in issue["evidence"]["runtime"]:
        runtime = f["runtime"]
        params = ", ".join(f"{p['name']} ({p['location']})" for p in f["params"]) or "—"
        rows.append(f"<tr><td>{_e(runtime['method'])}</td><td><code>{_e(runtime['url'])}</code></td><td>{_e(params)}</td>"
                    f"<td><code>{_e(runtime['payload']) or '—'}</code></td><td>{_e(runtime['technique']) or '—'}</td></tr>")
    if not rows:
        return ""
    return ("<h4>Proven at runtime</h4><table><tr><th>Method</th><th>URL</th><th>Parameter</th><th>Payload</th><th>How</th></tr>"
            + "".join(rows) + "</table>")


def _code_blocks(issue: dict) -> str:
    blocks = []
    for f in issue["evidence"]["code"]:
        code = f["code"]
        trace = "".join(f"<li><code>{_e(s['file'])}:{_e(s['line'])}</code> {_e(s['note'])}</li>" for s in code["trace"])
        blocks.append(f"<p><code>{_e(code['file'])}:{_e(code['line'])}</code> in <code>{_e(code['function'])}</code>, "
                      f"reaching <code>{_e(code['sink'])}</code></p><pre>{_e(code['snippet'])}</pre>"
                      + (f"<details><summary>How the input gets there</summary><ol>{trace}</ol></details>" if trace else ""))
    return "<h4>In the code</h4>" + "".join(blocks) if blocks else ""


def _detail(issue: dict, links: dict) -> str:
    params = ", ".join(f"{p['name']} ({p['location']})" for p in issue["params"]) or "—"
    urls = ", ".join(r["path"] + (f"?{r['selector']}" if r["selector"] else "") for r in issue["routes"]) or "the whole app"
    rows = [("Label", issue["label"]), ("CWE", f"{issue['cwe']} (family {issue['cwe_family']})"), ("Severity", issue["severity"]),
            ("CVSS v3.0", f"{issue['cvss']['temporal_score']} {issue['cvss']['rating']} (base {issue['cvss']['base_score']}), "
                          f"{issue['cvss']['vector']}"),
            ("Why this score", "; ".join(issue["risk_factors"])), ("URL", urls), ("Parameter", params)]
    if issue["issue_id"] in links:
        basis = links[issue["issue_id"]]
        rows.append(("Why linked", f"same {basis['cwe_family']}, runtime route {basis['runtime_route']} matched the code's "
                                   f"route {basis['code_route']} ({basis['kind']}), same parameter {basis['parameter']}"))
    if issue["ambiguous"]:
        rows.append(("Not linked", f"{len(issue['candidates'])} different places in the code fit; see the Code only issues"))
    facts = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in rows)
    return (f'<section id="{_e(issue["issue_id"])}"><h3>#{issue["rank"]} {_e(issue["title"])} '
            f'<span class="muted">{_e(issue["label"])}</span></h3><dl>{facts}</dl>'
            f"{_runtime_rows(issue)}{_code_blocks(issue)}</section>")


def render(result: dict) -> str:
    stats = result["stats"]
    reported = [i for i in result["issues"] if i["reportable"]]
    held = [i for i in result["issues"] if not i["reportable"]]
    links = {}
    for link in result["links"]:
        links.setdefault(link["issue_id"], link["match_basis"])
    rows = "".join(
        f'<tr><td>{i["rank"]}</td><td class="label">{_e(i["label"])}</td><td>{_e(i["cvss"]["rating"])}</td><td>{i["risk_score"]}</td>'
        f'<td>{_e(i["cwe"])}</td><td><a href="#{_e(i["issue_id"])}">{_e(i["title"])}</a></td><td>{_where_short(i)}</td></tr>'
        for i in reported)
    held_note = f'<p class="muted">{len(held)} low-confidence issue(s) are kept in issues.json but not listed.</p>' if held else ""
    conflicts = "".join(f"<li>{_e(c['reason'])}: <code>{_e(', '.join(c['dast_ids']))}</code></li>" for c in result["conflicts"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security issues</title><style>{STYLE}</style></head><body>
<h1>Security issues</h1>
<p>{stats['confirmed']} Confirmed, {stats['code_only']} Code only, {stats['runtime_only']} Runtime only.
Confirmed issues come first, then the highest CVSS v3.0 score.</p>
<table><tr><th>#</th><th>Label</th><th>Rating</th><th>CVSS</th><th>CWE</th><th>Issue</th><th>Where</th></tr>{rows}</table>
{held_note}
{('<h2>For review</h2><p>A runtime test reported these, but the code was marked safe.</p><ul>' + conflicts + '</ul>') if conflicts else ''}
<h2>Details</h2>
{''.join(_detail(i, links) for i in reported)}
</body></html>
"""
