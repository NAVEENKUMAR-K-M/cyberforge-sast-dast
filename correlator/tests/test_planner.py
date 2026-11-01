"""The OpenAI planner, against a fake HTTP function: what it sends, what it accepts, how it fails."""
import json
import os
import urllib.error

import pytest

from correlator.correlate import correlate
from correlator.loop import check_plan, default_plan, find_cases, run_loop
from correlator.planner import ChatPlanner, build_bundle
from correlator.tests.test_correlate import route, sast
from correlator.tests.test_loop import FakeExecutor, docs


def clear_keys(monkeypatch, prefix="GROQ_API_KEY"):
    """Removes every key variable that is set, whatever its number: the planner reads GROQ_API_KEY, _2, _3 and on, and a
    developer's own .env (loaded by other tests) can define any of them."""
    for name in [n for n in os.environ if n.startswith(prefix)]:
        monkeypatch.delenv(name)

KEY = "sk-test-not-a-real-key-1234567890"
SOURCE = '<?php\n$password = "hunter2-real-secret";\n$back = $_GET["back"];\nif (strpos($back, "forge-shop") !== false) { header("Location: " . $back); }\n'


@pytest.fixture
def case(tmp_path):
    (tmp_path / "go.php").write_text(SOURCE)
    code = sast("s1", cwe="CWE-601", file="go.php", params=(("back", "query"),), routes=[route("/go.php")])
    code["code"]["snippet"] = 'header("Location: " . $back);'
    code["code"]["trace"] = [{"file": "go.php", "line": 3, "note": "read from query parameter 'back'"}]
    return find_cases(correlate(*docs([code])))[0], tmp_path


def reply(**plan):
    body = {"give_up": False, "reason": "r", "method": None, "location": None, "fields": [], "hint": None, **plan}
    return {"choices": [{"message": {"content": json.dumps(body)}}], "usage": {"prompt_tokens": 900, "completion_tokens": 40}}


class Recorder:
    def __init__(self, answer):
        self.answer, self.bodies = answer, []

    def __call__(self, body):
        self.bodies.append(body)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def history_of(case):
    plan = default_plan(case)[0]
    return [{"round": 1, "plan": plan, "outcome": "not reproduced", "evidence": None,
             "requests_sent": [{"method": "GET", "url": "http://h/go.php", "query": {"back": "https://x/"}, "body": {}, "status": 200,
                                "length": 14, "excerpt": "Language saved"}]}]


def test_the_prompt_carries_the_source_and_what_round_one_got_back_but_not_secrets(case):
    case, root = case
    fake = Recorder(reply(hint="https://{canary}/forge-shop"))
    plan = ChatPlanner("groq", "gpt-test", str(root), api_key=KEY, post=fake)(case, history_of(case))
    prompt = fake.bodies[0]["messages"][1]["content"]
    assert 'strpos($back, "forge-shop")' in prompt and "3: $back" in prompt          # numbered source
    assert "Language saved" in prompt and "not reproduced" in prompt                  # what round 1 sent and got back
    assert "hunter2-real-secret" not in prompt and "[removed]" in prompt              # secrets stripped
    assert KEY not in json.dumps(fake.bodies)
    assert plan["hint"] == "https://{canary}/forge-shop" and plan["_audit"]["files_sent"] == ["go.php"]


def test_a_valid_reply_becomes_a_checked_plan_with_its_audit(case):
    case, root = case
    planner = ChatPlanner("groq", "gpt-test", str(root), api_key=KEY, post=Recorder(reply(hint="https://{canary}/forge-shop", reason="line 4 needs forge-shop")))
    plan, why = check_plan(planner(case, history_of(case)), case, history_of(case))
    assert why is None and plan["hint"] == "https://{canary}/forge-shop" and plan["origin"] == "planner"
    assert plan["audit"]["model"] == "gpt-test" and len(plan["audit"]["prompt_sha256"]) == 64
    assert plan["audit"]["usage"] == {"prompt_tokens": 900, "completion_tokens": 40} and json.loads(plan["audit"]["response"])["hint"]


def test_fields_come_back_as_a_mapping(case):
    case, root = case
    planner = ChatPlanner("groq", "gpt-test", str(root), api_key=KEY, post=Recorder(reply(fields=[{"name": "password", "value": "x"}])))
    assert planner(case, history_of(case))["fields"] == {"password": "x"}


@pytest.mark.parametrize("model,expects", [("llama-3.3-70b", "temperature"), ("openai/gpt-oss-20b", "reasoning_effort")])
def test_model_families_get_the_settings_they_accept(case, model, expects):
    case, root = case
    fake = Recorder(reply())
    ChatPlanner("groq", model, str(root), api_key=KEY, post=fake)(case, [])
    assert expects in fake.bodies[0] and ("temperature" in fake.bodies[0]) == (expects == "temperature")


@pytest.mark.parametrize("failure", [urllib.error.HTTPError("u", 401, "no", {}, None), TimeoutError(), ValueError("bad"),
                                     {"choices": []}, {"choices": [{"message": {"content": "not json"}}]}])
def test_a_failed_call_is_a_give_up_that_never_leaks_the_key(case, failure):
    case, root = case
    plan = ChatPlanner("groq", "gpt-test", str(root), api_key=KEY, post=Recorder(failure))(case, [])
    assert plan["give_up"] is True and KEY not in json.dumps(plan)
    assert check_plan(plan, case, [])[0] is None


def test_no_key_means_no_call(case, monkeypatch):
    case, _ = case
    clear_keys(monkeypatch)
    fake = Recorder(reply())
    assert ChatPlanner("groq", "gpt-test", None, post=fake)(case, [])["reason"] .startswith("no GROQ_API_KEY is set") and fake.bodies == []


def test_only_files_inside_the_scanned_folder_are_read(case, tmp_path):
    case, root = case
    outside = tmp_path.parent / "outside-secret.php"
    outside.write_text("<?php // outside")
    case = {**case, "file": "../outside-secret.php", "trace": [{"file": "/etc/passwd", "line": 1, "note": "x"}]}
    assert build_bundle(case, [], str(root))["source_files"] == {}


def test_source_is_not_sent_unless_a_root_is_given(case):
    case, _ = case
    assert build_bundle(case, [], None)["source_files"] == {}


def test_a_long_test_is_sampled_not_dumped(case):
    case, root = case
    history = history_of(case)
    history[0]["requests_sent"] = [{"method": "GET", "url": "http://h/go.php", "query": {"back": str(n)}, "body": {}, "status": 200,
                                    "length": 14, "excerpt": "Language saved"} for n in range(80)]
    sent = build_bundle(case, history, str(root))["tests_so_far"][0]["requests_sent"]
    assert len(sent) <= 9 and sent[-1] == {"note": "80 requests in all"}


def test_the_whole_loop_with_the_planner_and_a_fake_model(case):
    case, root = case
    code = sast("s1", cwe="CWE-601", file="go.php", params=(("back", "query"),), routes=[route("/go.php")])
    from correlator.tests.test_correlate import dast
    proof = dast("hit", cwe="CWE-601", path="/go.php", param="back", payload="https://dast-canary.invalid/forge-shop",
                 evidence={"matched": "https://dast-canary.invalid/forge-shop", "probe_status": 302})
    ex = FakeExecutor(None, {"reproduced": True, "finding": {}, "finding_common": proof, "attempts": [{"method": "GET", "url": "http://h/go.php", "query": {"back": "x"}, "body": {}, "status": 302, "length": 0, "seconds": 0.1}]})
    ex.answers[0] = {"reproduced": False, "finding": None, "finding_common": None, "attempts": [{"method": "GET", "url": "http://h/go.php", "query": {"back": "https://x/"}, "body": {}, "status": 200, "length": 14, "seconds": 0.1, "excerpt": "Language saved"}]}
    planner = ChatPlanner("groq", "gpt-test", str(root), api_key=KEY, post=Recorder(reply(hint="https://{canary}/forge-shop", reason="the handler redirects only values containing forge-shop")))
    result, _ = run_loop(*docs([code]), ex, planner)
    record = result["investigations"][0]
    assert record["outcome"] == "validated" and [r["outcome"] for r in record["rounds"]] == ["not reproduced", "reproduced"]
    assert record["rounds"][1]["plan"]["audit"]["model"] == "gpt-test" and record["rounds"][1]["plan"]["reason"].startswith("the handler")
    assert ex.plans[1]["hint"] == "https://{canary}/forge-shop"


def test_groq_is_asked_for_plain_json_with_the_shape_in_the_prompt_and_openai_for_a_strict_schema(case):
    case, root = case
    groq, openai = Recorder(reply()), Recorder(reply())
    ChatPlanner("groq", "m", str(root), api_key=KEY, post=groq)(case, [])
    ChatPlanner("openai", "m", str(root), api_key=KEY, post=openai)(case, [])
    assert groq.bodies[0]["response_format"] == {"type": "json_object"} and "give_up (boolean)" in groq.bodies[0]["messages"][0]["content"]
    assert openai.bodies[0]["response_format"]["type"] == "json_schema"


def test_fields_may_come_as_a_mapping_too(case):
    case, root = case
    answer = {"choices": [{"message": {"content": json.dumps({"give_up": False, "reason": "r", "fields": {"password": "x"}, "hint": None})}}]}
    assert ChatPlanner("groq", "m", str(root), api_key=KEY, post=Recorder(answer))(case, [])["fields"] == {"password": "x"}


def test_extra_fields_cannot_name_the_tested_parameter(case):
    case, _ = case
    assert "tested parameter itself" in check_plan({"fields": {case["param"]: "x"}}, case, [])[1]


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def http_error(code, headers, body):
    import io
    return urllib.error.HTTPError("u", code, "x", headers, io.BytesIO(json.dumps(body).encode()))


def test_a_rate_limit_is_waited_out_but_missing_credit_is_not(monkeypatch):
    import email.message
    import urllib.request
    from correlator import planner as planner_module
    waits, attempts = [], []
    monkeypatch.setattr(planner_module.time, "sleep", waits.append)
    limited = email.message.Message()
    limited["retry-after"] = "2"

    def flaky(request, timeout):
        attempts.append(1)
        if len(attempts) == 1:
            raise http_error(429, limited, {"error": {"code": "rate_limit_exceeded"}})
        return FakeResponse({"ok": True})

    monkeypatch.setattr(urllib.request, "urlopen", flaky)
    assert ChatPlanner("groq", "m", api_key=KEY)._http_post({}) == {"ok": True} and len(waits) == 1 and 1.5 < waits[0] <= 2.0

    attempts.clear(), waits.clear()
    monkeypatch.setattr(urllib.request, "urlopen", lambda r, timeout: (_ for _ in ()).throw(
        http_error(429, email.message.Message(), {"error": {"type": "insufficient_quota", "code": "credit_balance_exhausted"}})))
    with pytest.raises(urllib.error.HTTPError):
        ChatPlanner("groq", "m", api_key=KEY)._http_post({})
    assert waits == []


# ---- spreading calls over several keys, and not calling when it can't help ----

def test_keys_are_used_in_turn_and_a_resting_or_dropped_key_is_skipped():
    from correlator.planner import KeyPool
    pool = KeyPool(["a", "b", "c"])
    assert [pool.take()[0] for _ in range(4)] == [0, 1, 2, 0]
    pool.rest(1, 100)
    pool.drop(2)
    assert [pool.take()[0] for _ in range(3)] == [0, 0, 0] and len(pool) == 2


def test_when_every_key_rests_the_pool_waits_for_the_soonest_and_gives_up_on_a_long_wait():
    from correlator.planner import MAX_WAIT, KeyPool
    waits = []
    pool = KeyPool(["a", "b"], sleep=waits.append)
    pool.rest(0, 9), pool.rest(1, 4)
    assert pool.take()[0] == 1 and 3.5 < waits[0] <= 4.0
    pool.rest(0, MAX_WAIT + 100), pool.rest(1, MAX_WAIT + 100)
    assert pool.take() is None and len(waits) == 1


def test_keys_come_from_the_environment_in_order_and_empty_ones_are_ignored(monkeypatch):
    from correlator.planner import keys_from_env
    clear_keys(monkeypatch)
    monkeypatch.setenv("GROQ_API_KEY_10", "k10"), monkeypatch.setenv("GROQ_API_KEY", "k1"), monkeypatch.setenv("GROQ_API_KEY_3", "k3")
    monkeypatch.setenv("GROQ_API_KEY_2", ""), monkeypatch.setenv("GROQ_API_KEYS_X", "other")
    assert keys_from_env("GROQ_API_KEY") == ["k1", "k3", "k10"]


def test_a_rate_limited_key_hands_over_to_the_next_without_waiting(case, monkeypatch):
    import email.message
    import urllib.request
    from correlator import planner as planner_module
    case, root = case
    waits, used = [], []
    monkeypatch.setattr(planner_module.time, "sleep", waits.append)
    limited = email.message.Message()
    limited["retry-after"] = "20"

    def urlopen(request, timeout):
        used.append(request.get_header("Authorization"))
        if len(used) == 1:
            raise http_error(429, limited, {"error": {"code": "rate_limit_exceeded"}})
        return FakeResponse(reply(give_up=True, reason="done"))

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    planner = ChatPlanner("groq", "m", str(root), api_key="k-one")
    planner.pool = planner_module.KeyPool(["k-one", "k-two"])
    plan = planner(case, [])
    assert used == ["Bearer k-one", "Bearer k-two"] and waits == [] and plan["_audit"]["key"] == "#1"
    assert "k-one" not in json.dumps(plan) and "k-two" not in json.dumps(plan)


def test_a_key_that_is_refused_is_dropped_for_the_rest_of_the_run(case, monkeypatch):
    import email.message
    import urllib.request
    from correlator import planner as planner_module
    case, root = case
    used = []

    def urlopen(request, timeout):
        used.append(request.get_header("Authorization"))
        if request.get_header("Authorization") == "Bearer bad":
            raise http_error(401, email.message.Message(), {"error": {"code": "invalid_api_key"}})
        return FakeResponse(reply(give_up=True, reason="done"))

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    planner = ChatPlanner("groq", "m", str(root), api_key="bad")
    planner.pool = planner_module.KeyPool(["bad", "good"])
    planner(case, []), planner(case, [])
    assert used == ["Bearer bad", "Bearer good", "Bearer good"] and len(planner.pool) == 1


def test_no_call_is_made_without_source_or_when_there_is_nothing_for_the_model_to_change(tmp_path):
    (tmp_path / "ping.php").write_text('<?php\n$out = shell_exec("ping " . $_POST["host"]);\n')
    (tmp_path / "login.php").write_text('<?php\n$u = $_POST["username"]; $p = $_POST["password"];\n')
    cmd = sast("c1", cwe="CWE-78", file="ping.php", params=(("host", "body"),), routes=[route("/ping.php", methods=("POST",))])
    sql = sast("s1", cwe="CWE-89", file="login.php", params=(("username", "body"),), routes=[route("/login.php", methods=("POST",))])
    cases = {c["cwe"]: c for c in find_cases(correlate(*docs([cmd, sql])))}
    fake = Recorder(reply(give_up=True, reason="n/a"))
    planner = ChatPlanner("groq", "m", str(tmp_path), api_key=KEY, post=fake)
    assert "nothing for a planner to change" in planner(cases["CWE-78"], [])["reason"] and fake.bodies == []      # reads only host
    assert planner(cases["CWE-89"], [])["reason"] == "n/a" and len(fake.bodies) == 1                              # also reads password
    assert "no source to read" in ChatPlanner("groq", "m", None, api_key=KEY, post=fake)(cases["CWE-89"], [])["reason"] and len(fake.bodies) == 1


def test_an_unknown_way_of_reading_input_is_not_taken_to_mean_none():
    from correlator.planner import reads_other_inputs
    assert reads_other_inputs({"a.php": "$x = $request->input('q');"}, "q") is True
    assert reads_other_inputs({"a.php": "extract($_POST);"}, "q") is True
    assert reads_other_inputs({"a.php": "$x = $_GET['q'];"}, "q") is False
