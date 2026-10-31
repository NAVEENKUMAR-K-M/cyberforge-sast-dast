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
    assert run_verify(vuln_app_url, "--route", "/sqli_decoy") == {"reproduced": False, "finding": None}


def test_verify_passes_the_selector_through(vuln_app_url):
    assert run_verify(vuln_app_url, "--route", "/dispatch")["reproduced"] is False
    outcome = run_verify(vuln_app_url, "--route", "/dispatch", "--selector", "action=view")
    assert outcome["reproduced"] is True
    assert outcome["finding"]["selector"] == "action=view"
