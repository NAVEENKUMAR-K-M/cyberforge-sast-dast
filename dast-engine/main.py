"""CLI entry point.

Usage:
    python main.py scan --target http://localhost:8080 --config dvwa.yaml
    python main.py verify --target http://localhost:8080 --config dvwa.yaml \\
        --cwe CWE-89 --method GET --route /vulnerabilities/sqli/ --param id
"""
from __future__ import annotations

import asyncio
import json
import logging

import click
import yaml

from api import verify as verify_finding
from core.controller import run_scan
from core.scope_guard import DEFAULT_DENYLIST

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _load_config(config_path: str | None) -> dict:
    cfg = {}
    if config_path:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    cfg.setdefault("denylist", list(DEFAULT_DENYLIST))
    return cfg


def _auth_options(fn):
    """Everything an app needs to be scanned without writing a config file."""
    for option in reversed([
        click.option("--login-url", default=None, help="Login page or JSON login endpoint"),
        click.option("--username", default=None),
        click.option("--password", default=None),
        click.option("--json-login", is_flag=True, help="Log in with a JSON body and keep the returned token"),
        click.option("--header", "headers", multiple=True, help="Extra request header, as Name:Value; can be repeated"),
        click.option("--cookie", "cookies", multiple=True, help="Existing session cookie, as name=value; can be repeated"),
        click.option("--bearer-token", default=None, help="Bearer token to send on every request"),
    ]):
        fn = option(fn)
    return fn


def _apply_auth_options(cfg, login_url, username, password, json_login, headers, cookies, bearer_token):
    auth = cfg.setdefault("auth", {})
    if login_url:
        auth.update({"enabled": True, "login_url": login_url, "json": json_login})
    if username is not None:
        auth["username"] = username
    if password is not None:
        auth["password"] = password
    if bearer_token:
        auth["bearer_token"] = bearer_token
    auth.setdefault("headers", {}).update(dict(h.split(":", 1) for h in headers))
    auth["headers"] = {k.strip(): v.strip() for k, v in auth["headers"].items()}
    auth.setdefault("cookies", {}).update(dict(c.split("=", 1) for c in cookies))


@click.group()
def cli():
    pass


@cli.command()
@click.option("--target", required=True, help="Base URL of the target application")
@click.option("--config", "config_path", default=None, help="Path to config.yaml")
@click.option("--route-map", "route_map_path", default=None, help="Path to route_map.json from SAST")
@click.option("--hints", "hints_path", default=None, help="Path to SAST hints JSON")
@click.option("--output", "output_path", default=None, help="Output JSON path (overrides the config file's output_path)")
@click.option("--active-backend", default=None, help="zap | nuclei | none")
@click.option("--deadline", "deadline_seconds", default=None, type=float, help="Total scan budget in seconds")
@click.option("--allow-destructive", is_flag=True, help="Also test DELETE endpoints, which are skipped by default because a request can remove real records")
@_auth_options
def scan(target, config_path, route_map_path, hints_path, output_path, active_backend, deadline_seconds, allow_destructive,
         login_url, username, password, json_login, headers, cookies, bearer_token):
    cfg = _load_config(config_path)
    _apply_auth_options(cfg, login_url, username, password, json_login, headers, cookies, bearer_token)
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
    if allow_destructive:
        cfg["allow_destructive"] = True
    if output_path:
        cfg["output_path"] = output_path
    cfg.setdefault("output_path", "output/dast_results.json")

    result = asyncio.run(run_scan(cfg))
    click.echo(
        f"Scan complete: {result['finding_count']} findings, "
        f"{result['request_count']} requests, {result['elapsed_seconds']}s elapsed"
    )
    coverage = result.get("coverage", {})
    if "points_tested" in coverage:
        click.echo(f"Coverage: tested {coverage['points_tested']} of {coverage['points_found'] - coverage['points_dropped_by_scope']} "
                   f"injection points ({coverage['points_hinted']} hinted by SAST, {coverage['points_dropped_by_scope']} blocked by scope)")
    if coverage.get("pairs_skipped_destructive"):
        click.echo(f"Skipped {coverage['pairs_skipped_destructive']} test(s) on DELETE endpoints; --allow-destructive includes them.")
    if coverage.get("deadline_reached"):
        click.echo("WARNING: the deadline cut this scan short, so some points weren't tested. Results are incomplete.")


@cli.command()
@click.option("--target", required=True, help="Base URL of the target application")
@click.option("--config", "config_path", default=None, help="Path to config.yaml")
@click.option("--cwe", required=True, help="CWE to re-test, such as CWE-89")
@click.option("--method", default="GET", help="HTTP method")
@click.option("--route", required=True, help="Route path, such as /api/orders.php")
@click.option("--param", required=True, help="Parameter name")
@click.option("--param-location", default="query", help="query, body, json, path, header or cookie")
@click.option("--selector", default=None, help="Query value that picks the page, such as action=view")
@_auth_options
def verify(target, config_path, cwe, method, route, param, param_location, selector,
           login_url, username, password, json_login, headers, cookies, bearer_token):
    """Re-test one finding. Prints JSON on stdout; logs go to stderr."""
    cfg = _load_config(config_path)
    _apply_auth_options(cfg, login_url, username, password, json_login, headers, cookies, bearer_token)
    cfg.setdefault("allowlist", [target])
    finding = asyncio.run(
        verify_finding(cwe, method, route, param, target=target, config=cfg, param_location=param_location, selector=selector)
    )
    click.echo(json.dumps({"reproduced": finding is not None, "finding": finding}))


if __name__ == "__main__":
    cli()
