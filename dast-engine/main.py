"""CLI entry point.

Usage:
    python main.py scan --target http://localhost:8080 --config dvwa.yaml
"""
from __future__ import annotations

import asyncio
import logging
import sys

import click
import yaml

from core.controller import run_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _load_config(config_path: str | None) -> dict:
    cfg = {}
    if config_path:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    return cfg


@click.group()
def cli():
    pass


@cli.command()
@click.option("--target", required=True, help="Base URL of the target application")
@click.option("--config", "config_path", default=None, help="Path to config.yaml")
@click.option("--route-map", "route_map_path", default=None, help="Path to route_map.json from SAST")
@click.option("--hints", "hints_path", default=None, help="Path to SAST hints JSON")
@click.option("--output", "output_path", default="output/dast_results.json", help="Output JSON path")
@click.option("--active-backend", default=None, help="zap | nuclei | none")
@click.option("--deadline", "deadline_seconds", default=None, type=float, help="Total scan budget in seconds")
def scan(target, config_path, route_map_path, hints_path, output_path, active_backend, deadline_seconds):
    cfg = _load_config(config_path)
    cfg["target"] = target
    cfg.setdefault("allowlist", [target])
    if route_map_path:
        cfg["route_map_path"] = route_map_path
    if hints_path:
        cfg["hints_path"] = hints_path
    if active_backend:
        cfg["active_backend"] = active_backend
    if deadline_seconds:
        cfg["deadline_seconds"] = deadline_seconds
    cfg["output_path"] = output_path

    result = asyncio.run(run_scan(cfg))
    click.echo(
        f"Scan complete: {result['finding_count']} findings, "
        f"{result['request_count']} requests, {result['elapsed_seconds']}s elapsed"
    )


if __name__ == "__main__":
    cli()
