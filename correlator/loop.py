"""The closed loop: correlate, investigate one unresolved case, run a supported test, take the result
back into correlation, and stop.

A case is a Code only issue that looks real but has no runtime proof, or a runtime bug that several
code bugs fit. Each case gets at most MAX_ROUNDS tests. Round 1 is the plain re-test of what the code
says. Round 2 is a test a planner chose after seeing round 1's actual requests and responses. The
planner is optional; without one a case stops after round 1.

The planner never makes a link. It only proposes a request. Whatever comes back is a new DAST finding,
which goes through the same matching and the same evidence checks as every other finding.
"""
from __future__ import annotations

import copy
import json
import re
import subprocess
import time

from correlator import evidence
from correlator.correlate import SEVERITY_ORDER, _hash, correlate
from correlator.planner import HINTABLE

MAX_ROUNDS = 2
# The weaknesses DAST can re-test (dast-engine/api.py).
SUPPORTED = {"CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"}
LOCATIONS = {"query", "body", "json", "path", "header", "cookie"}
MAX_FIELDS, MAX_VALUE = 10, 200


# ---- cases ----

def find_cases(result: dict) -> list:
    """The issues worth another test, most severe first. Every case is kept, even when no test exists
    for it, so the report says why instead of leaving it out."""
    cases = []
    for issue in result["issues"]:
        if issue["cwe_family"] not in SUPPORTED:
            continue
        if issue["label"] == "Code only" and issue["reportable"]:
            subject = next((f for f in issue["evidence"]["code"]
                            if f["confidence"] != "low" and f["routes"]
                            and any(p["name"] != "*" for p in f["params"])), None)
            if subject:
                cases.append(_case("verify", issue, subject))
        elif issue["label"] == "Runtime only" and issue["ambiguous"]:
            cases.append(_case("attribute", issue, issue["evidence"]["runtime"][0]))
    return sorted(cases, key=lambda c: (-SEVERITY_ORDER.index(c["severity"]), c["case_id"]))


def _case(kind: str, issue: dict, subject: dict) -> dict:
    route = subject["routes"][0] if subject["routes"] else {"path": "", "selector": None, "methods": []}
    param = next((p for p in subject["params"] if p["name"] != "*"), subject["params"][0] if subject["params"] else None)
    code = subject.get("code") or {}
    return {
        "case_id": _hash("case", [kind, issue["issue_id"]]),
        "kind": kind,
        "issue_id": issue["issue_id"],
        "sast_ids": issue["sast_ids"],
        "cwe": issue["cwe_family"],
        "severity": issue["severity"],
        "route": route["path"], "selector": route["selector"], "methods": route["methods"],
        "param": param["name"] if param else "", "location": param["location"] if param else "",
        "file": code.get("file"), "line": code.get("line"), "snippet": code.get("snippet"),
        "trace": code.get("trace", []),
        "stored": bool(code.get("stored_flow")),
        "candidates": issue["candidates"],
    }


# ---- plans ----

def default_plan(case: dict):
    """The re-test the code itself describes, or None with the reason there isn't one."""
    if case["kind"] == "attribute":
        return None, (f"{len(case['candidates'])} code bugs fit this runtime bug equally. "
                      "Re-testing the same request can't separate them")
    if case["stored"]:
        return None, "the bug is stored: it needs a write step and then a read, which a single re-test doesn't do"
    location, methods = case["location"], case["methods"] or ["GET"]
    if location == "any":
        method = methods[0]
        location = "query" if method in ("GET", "HEAD") else "body"
    elif location in ("body", "json"):
        method = next((m for m in methods if m not in ("GET", "HEAD")), methods[0])
    elif location in LOCATIONS:
        method = "GET" if "GET" in methods else methods[0]
    else:
        return None, f"the input is read from {location or 'an unknown place'}, which a re-test can't set"
    return _plan(case, method, location, origin="default", reason="re-test of what the code describes"), None


def _plan(case, method, location, fields=None, hint=None, origin="planner", reason=""):
    return {"cwe": case["cwe"], "method": method, "route": case["route"], "selector": case["selector"],
            "param": case["param"], "location": location, "fields": dict(fields or {}), "hint": hint,
            "origin": origin, "reason": reason}


def attempt_key(plan: dict) -> tuple:
    return (plan["method"], plan["location"], tuple(sorted(plan["fields"].items())), plan["hint"])


def check_plan(raw, case: dict, history: list):
    """A planner's proposal, or None with the reason it was refused. A plan can change how the request
    is shaped, but not where it goes: the route, parameter and weakness come from the case."""
    if not isinstance(raw, dict):
        return None, "the planner returned nothing usable"
    if raw.get("give_up"):
        return None, "the planner found no further useful test: " + str(raw.get("reason") or "no reason given")[:300]
    # What the planner doesn't say stays as the last round had it.
    previous = history[-1]["plan"] if history else default_plan(case)[0] or {}
    method = str(raw.get("method") or previous.get("method") or "GET").upper()
    location = raw.get("location") or previous.get("location") or case["location"]
    if location == "any":
        location = "query" if method in ("GET", "HEAD") else "body"
    if case["location"] not in ("any", location) or location not in LOCATIONS:
        return None, f"the input is read from {case['location']}, not {location}"
    if method not in (case["methods"] or ["GET"]):
        return None, f"the code route accepts {', '.join(case['methods'] or ['GET'])}, not {method}"
    fields, hint = raw.get("fields") or {}, raw.get("hint")
    if not isinstance(fields, dict) or len(fields) > MAX_FIELDS or any(
            not isinstance(k, str) or not isinstance(v, str) or not _clean(k, 64) or not _clean(v, MAX_VALUE, empty_ok=True)
            for k, v in fields.items()):
        return None, "the extra fields are not short single-line name=value pairs"
    if hint is not None and not (isinstance(hint, str) and _clean(hint, MAX_VALUE)):
        return None, "the hint is not 1 to 200 printable characters on one line"
    if case["param"] in fields:
        return None, "the extra fields include the tested parameter itself, which the test already sets"
    if hint is not None and case["cwe"] not in HINTABLE:
        return None, f"the {case['cwe']} test doesn't take a hint"
    plan = _plan(case, method, location, fields, hint, origin="planner", reason=str(raw.get("reason") or "")[:300])
    if raw.get("_audit"):
        plan["audit"] = raw["_audit"]    # model, prompt hash, raw reply and token use, for replay and cost
    if attempt_key(plan) in {attempt_key(r["plan"]) for r in history}:
        return None, "this request was already tried"
    return plan, None


def _clean(text: str, limit: int, empty_ok: bool = False) -> bool:
    return (empty_ok or bool(text)) and len(text) <= limit and not re.search(r"[\x00-\x1f\x7f]", text)


# ---- running a test ----

def dast_executor(engine_dir: str, python: str, config: str | None, target: str, timeout: int = 60):
    """Runs one re-test with the DAST engine's `main.py verify`. Returns what happened, never raises."""
    def run(plan: dict) -> dict:
        args = [python, "main.py", "verify", "--target", target, "--cwe", plan["cwe"], "--method", plan["method"],
                "--route", plan["route"], "--param", plan["param"], "--param-location", plan["location"]]
        if config:
            args += ["--config", config]
        if plan["selector"]:
            args += ["--selector", plan["selector"]]
        for name, value in plan["fields"].items():
            args += ["--field", f"{name}={value}"]
        if plan["hint"]:
            args += ["--hint", plan["hint"]]
        try:
            done = subprocess.run(args, cwd=engine_dir, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"error": f"the DAST engine did not run ({type(exc).__name__})"}
        try:
            outcome = json.loads(done.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            outcome = None
        if done.returncode != 0 or outcome is None:
            tail = (done.stderr.strip().splitlines() or ["no error text"])[-1][:160]
            return {"error": f"the DAST engine exited with code {done.returncode}: {tail}"}
        return outcome
    return run


def _outcome(result: dict | None) -> str:
    if result is None or result.get("error"):
        return "error"
    if result.get("reproduced") and result.get("finding_common"):
        return "reproduced"
    # Nothing was sent: the route is out of scope or denylisted, which is a policy block, not a negative.
    return "not reproduced" if result.get("attempts") else "blocked"


# ---- the loop ----

def run_loop(sast_doc: dict, dast_doc: dict, executor, planner=None, *, base_path=None, sources=None,
             max_cases: int = 10, budget_seconds: float = 120.0, clock=time.monotonic) -> tuple:
    """Returns (result, dast_doc): the correlation after the loop, and the DAST report with the new
    findings added. `executor(plan)` runs a test; `planner(case, history)` proposes round 2 or returns None."""
    dast_doc = copy.deepcopy(dast_doc)
    result = correlate(sast_doc, dast_doc, base_path, sources)
    cases = find_cases(result)[:max_cases]
    records = {c["case_id"]: {"case_id": c["case_id"], "kind": c["kind"], "issue_id": c["issue_id"],
                              "source": {k: c[k] for k in ("sast_ids", "cwe", "route", "selector", "param", "location",
                                                           "methods", "file", "line")},
                              "rounds": [], "outcome": "open", "stop_reason": None} for c in cases}
    started = clock()
    open_cases = list(cases)
    before = {}

    for number in range(1, MAX_ROUNDS + 1):
        tested = []
        for case in list(open_cases):
            record = records[case["case_id"]]
            if clock() - started > budget_seconds:
                _close(record, "unresolved", "budget exhausted")
                open_cases.remove(case)
                continue
            if number == 1:
                plan, why = default_plan(case)
            else:
                plan, why = (check_plan(planner(case, record["rounds"]), case, record["rounds"])
                             if planner else (None, "no planner is configured"))
            if plan is None:
                _close(record, "no supported test" if number == 1 else "unresolved", why)
                open_cases.remove(case)
                continue
            before[case["case_id"]] = _state(result, case)
            run = executor(plan)
            found = (run or {}).get("finding_common")
            record["rounds"].append({"round": number, "plan": plan, "requests_sent": (run or {}).get("attempts", []),
                                     "outcome": _outcome(run), "error": (run or {}).get("error"),
                                     "finding_id": found["id"] if found else None, "evidence": None, "effect": None})
            if found and found["id"] not in {f["id"] for f in dast_doc["findings"]}:
                dast_doc["findings"].append(found)
            tested.append(case)

        if not tested:
            break
        result = correlate(sast_doc, dast_doc, base_path, sources)   # the new evidence is matched and checked again
        for case in tested:
            record, last = records[case["case_id"]], records[case["case_id"]]["rounds"][-1]
            _reassess(last, result, case, dast_doc, before[case["case_id"]])
            if last["outcome"] == "blocked":
                _close(record, "blocked", "no request was sent: the route is out of scope or denylisted")
            elif last["outcome"] == "error":
                _close(record, "unresolved", last["error"])
            elif last["evidence"] and last["evidence"]["level"] == "validated" and last["effect"]["linked"]:
                _close(record, "validated", "the runtime evidence shows the weakness itself")
            else:
                if number == MAX_ROUNDS:
                    _close(record, "unresolved", "round limit reached")
                    open_cases.remove(case)
                continue
            open_cases.remove(case)
        if not open_cases:
            break

    for record in records.values():
        if record["outcome"] == "open":
            _close(record, "unresolved", "round limit reached")
    for issue in result["issues"]:
        mine = next((r for r in records.values() if r["issue_id"] == issue["issue_id"]), None)
        if mine:
            # True only when a planner-proposed round (not the deterministic round 1) is the one whose
            # evidence is actually linked into this issue -- an AI proposal that was tried and didn't
            # pan out, or wasn't needed because round 1 already proved it, doesn't earn the tag.
            ai_assisted = any(r["plan"].get("origin") == "planner" and r["effect"] and r["effect"]["linked"]
                              for r in mine["rounds"])
            issue["investigation"] = {"case_id": mine["case_id"], "outcome": mine["outcome"],
                                      "stop_reason": mine["stop_reason"], "rounds": len(mine["rounds"]),
                                      "ai_assisted": ai_assisted}
    result["investigations"] = [records[c["case_id"]] for c in cases]
    result["stats"]["investigated"] = len(cases)
    result["stats"]["upgraded"] = sum(1 for r in result["investigations"] if any(
        x["effect"] and x["effect"]["before"]["label"] != "Confirmed" and x["effect"]["after"]["label"] == "Confirmed" for x in r["rounds"]))
    return result, dast_doc


def _close(record: dict, outcome: str, reason: str) -> None:
    record["outcome"], record["stop_reason"] = outcome, reason


def _state(result: dict, case: dict) -> dict:
    issue = next((i for i in result["issues"] if i["issue_id"] == case["issue_id"]), None)
    return {"label": issue["label"], "level": issue["runtime_verification"]["level"]} if issue else {"label": None, "level": None}


def _reassess(last: dict, result: dict, case: dict, dast_doc: dict, before: dict) -> None:
    """What the new evidence did to the case: the evidence level of the finding it produced, and what
    happened to the issue once everything was matched again."""
    found = next((f for f in dast_doc["findings"] if f["id"] == last["finding_id"]), None)
    if found:
        last["evidence"] = evidence.check(found)
    after = _state(result, case)
    linked = bool(found) and any(found["id"] in i["dast_ids"] and i["label"] == "Confirmed" for i in result["issues"])
    last["effect"] = {"linked": linked, "changed": before != after, "before": before, "after": after}
