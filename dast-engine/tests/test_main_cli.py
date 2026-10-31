import json
from unittest.mock import AsyncMock, patch

import yaml
from click.testing import CliRunner

import main


def test_output_path_from_config_is_not_overridden_by_cli_default(tmp_path):
    """Regression test: --output's default used to unconditionally
    overwrite output_path from the config file, so dvwa.yaml's
    output_path: "output/dvwa_results.json" was silently ignored and
    everything landed in output/dast_results.json instead."""
    config_path = tmp_path / "test_config.yaml"
    config_path.write_text(yaml.dump({"output_path": "output/custom_results.json"}), encoding="utf-8")

    captured_cfg = {}

    async def fake_run_scan(cfg):
        captured_cfg.update(cfg)
        return {"finding_count": 0, "request_count": 0, "elapsed_seconds": 0.0}

    runner = CliRunner()
    with patch.object(main, "run_scan", AsyncMock(side_effect=fake_run_scan)):
        result = runner.invoke(main.cli, ["scan", "--target", "http://localhost:8080", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert captured_cfg["output_path"] == "output/custom_results.json"


def test_explicit_output_flag_overrides_config():
    captured_cfg = {}

    async def fake_run_scan(cfg):
        captured_cfg.update(cfg)
        return {"finding_count": 0, "request_count": 0, "elapsed_seconds": 0.0}

    runner = CliRunner()
    with patch.object(main, "run_scan", AsyncMock(side_effect=fake_run_scan)):
        result = runner.invoke(
            main.cli,
            ["scan", "--target", "http://localhost:8080", "--output", "output/explicit.json"],
        )

    assert result.exit_code == 0, result.output
    assert captured_cfg["output_path"] == "output/explicit.json"


def test_default_output_path_when_nothing_specified():
    captured_cfg = {}

    async def fake_run_scan(cfg):
        captured_cfg.update(cfg)
        return {"finding_count": 0, "request_count": 0, "elapsed_seconds": 0.0}

    runner = CliRunner()
    with patch.object(main, "run_scan", AsyncMock(side_effect=fake_run_scan)):
        result = runner.invoke(main.cli, ["scan", "--target", "http://localhost:8080"])

    assert result.exit_code == 0, result.output
    assert captured_cfg["output_path"] == "output/dast_results.json"


def run_verify(target, *extra):
    result = CliRunner().invoke(main.cli, ["verify", "--target", target, "--cwe", "CWE-89", "--param", "id", *extra])
    assert result.exit_code == 0, result.output
    return json.loads(result.output.splitlines()[-1])


def test_verify_reports_a_finding_that_reproduces(vuln_app_url):
    outcome = run_verify(vuln_app_url, "--route", "/sqli")
    assert outcome["reproduced"] is True
    assert outcome["finding"]["cwe"] == "CWE-89"


def test_verify_reports_a_finding_that_doesnt(vuln_app_url):
    outcome = run_verify(vuln_app_url, "--route", "/sqli_decoy")
    assert outcome["reproduced"] is False and outcome["finding"] is None and outcome["finding_common"] is None
    assert outcome["attempts"]  # what was tried is still reported


def test_verify_records_the_requests_it_sent(vuln_app_url):
    outcome = run_verify(vuln_app_url, "--route", "/sqli")
    assert outcome["finding_common"]["source"] == "dast" and outcome["finding_common"]["cwe"] == "CWE-89"
    first_probe = next(a for a in outcome["attempts"] if "id" in a["query"] and a["query"]["id"] == "'")
    assert first_probe["method"] == "GET" and first_probe["url"].endswith("/sqli") and first_probe["status"] == 500
    assert "sqlite3.OperationalError" in first_probe["excerpt"]     # the start of the reply, so a reader can see why


def run_verify_as(target, route, cwe, param, *extra, method="GET", location="query"):
    return run_verify(target, "--route", route, "--cwe", cwe, "--param", param, "--method", method,
                      "--param-location", location, *extra)


def test_verify_sends_the_other_fields_a_request_needs(vuln_app_url):
    args = (vuln_app_url, "/needs_field", "CWE-89", "name")
    assert run_verify_as(*args, method="POST", location="body")["reproduced"] is False
    outcome = run_verify_as(*args, "--field", "password=secret-value", method="POST", location="body")
    assert outcome["reproduced"] is True
    sent = next(a for a in outcome["attempts"] if a["body"].get("name") == "'")
    assert sent["body"]["password"] == "[masked]" and "secret-value" not in json.dumps(outcome["attempts"])


def test_verify_tries_a_hinted_redirect_destination_first(vuln_app_url):
    args = (vuln_app_url, "/guarded_redirect", "CWE-601", "next")
    assert run_verify_as(*args)["reproduced"] is False
    outcome = run_verify_as(*args, "--hint", "https://{canary}/keep-me")
    assert outcome["reproduced"] is True and outcome["finding"]["payload"] == "https://dast-canary.invalid/keep-me"


def test_verify_tries_a_hinted_traversal_prefix_first(vuln_app_url):
    args = (vuln_app_url, "/filtered_traversal", "CWE-22", "page")
    assert run_verify_as(*args)["reproduced"] is False
    outcome = run_verify_as(*args, "--hint", "....//" * 12)
    assert outcome["reproduced"] is True and outcome["finding"]["payload"].startswith("....//")


def test_verify_tries_a_hinted_xss_shape_first(vuln_app_url):
    """The probe now covers unquoted attributes on its own, so the hint is what picks the shape, not what makes it work."""
    args = (vuln_app_url, "/xss_unquoted", "CWE-79", "img")
    assert run_verify_as(*args)["finding"]["technique"] == "reflected-attribute_unquoted"
    outcome = run_verify_as(*args, "--hint", "a onerror={marker}")
    assert outcome["reproduced"] is True and outcome["finding"]["payload"].startswith("a onerror=")


def test_verify_refuses_a_malformed_hint_or_field(vuln_app_url):
    for bad in (["--hint", "a\nb"], ["--hint", "x" * 201], ["--field", "no-equals-sign"], ["--field", "a=\r\nb"]):
        result = CliRunner().invoke(main.cli, ["verify", "--target", vuln_app_url, "--cwe", "CWE-79", "--route", "/xss",
                                               "--param", "q", *bad])
        assert result.exit_code == 2, bad


def test_verify_passes_the_selector_through(vuln_app_url):
    assert run_verify(vuln_app_url, "--route", "/dispatch")["reproduced"] is False
    outcome = run_verify(vuln_app_url, "--route", "/dispatch", "--selector", "action=view")
    assert outcome["reproduced"] is True
    assert outcome["finding"]["selector"] == "action=view"
