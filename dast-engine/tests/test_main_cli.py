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
