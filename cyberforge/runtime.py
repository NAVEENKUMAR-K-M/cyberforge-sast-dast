"""Settings shared by the scan CLI, the web workspace and the correlator.

Everything here reads the environment, so the same code runs natively (where the defaults apply) and
in Docker (where Compose sets the variables).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CUSTOM_TARGET_ID = "custom"
CUSTOM_LANGUAGES = ("auto", "php", "python")
DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1")
_ENGINE_FOLDERS = {"sast": "sast-engine", "dast": "dast-engine"}


def allowed_hosts() -> set[str]:
    """Hosts a scan may touch. Native runs allow only this machine; Docker adds `host.docker.internal`,
    which always resolves to the host machine running the container, so the rule still means "your own machine"."""
    configured = {host.strip().lower() for host in os.environ.get("CYBERFORGE_ALLOWED_HOSTS", "").split(",") if host.strip()}
    return configured or set(DEFAULT_ALLOWED_HOSTS)


def python_for(engine: str) -> Path:
    """The interpreter that runs an engine: an explicit override, else that engine's own virtualenv if it
    exists, else the interpreter running this process (a single-environment install)."""
    override = os.environ.get(f"CYBERFORGE_{engine.upper()}_PYTHON")
    if override:
        return Path(override)
    folder = ROOT / _ENGINE_FOLDERS[engine] / ".venv"
    venv_python = folder / "Scripts" / "python.exe" if sys.platform == "win32" else folder / "bin" / "python"
    return venv_python if venv_python.is_file() else Path(sys.executable)


def workspace_root() -> Path | None:
    """The only folder a custom application's source may come from, when one is set (Docker: /workspace)."""
    configured = os.environ.get("CYBERFORGE_WORKSPACE", "").strip()
    return Path(configured).resolve() if configured else None


def custom_only() -> bool:
    """Docker hides the built-in demo targets: their 127.0.0.1 URLs would point at the container itself."""
    return os.environ.get("CYBERFORGE_CUSTOM_ONLY", "").strip().lower() in {"1", "true", "yes"}


def resolve_source(value) -> Path:
    """Validates a custom application's source folder. Symlinks are followed before the workspace check,
    so a link inside the workspace can't lead out of it."""
    if not isinstance(value, str) or not value.strip() or len(value) > 1024 or "\0" in value:
        raise ValueError("Enter the folder that holds the application's source code.")
    candidate = Path(value.strip())
    root = workspace_root()
    if root is not None and not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    if root is not None:
        try:
            resolved.relative_to(root)
        except ValueError:
            raise ValueError(f"The source folder must be inside {root}.") from None
    if not resolved.is_dir():
        raise ValueError(f"Source folder not found: {resolved}")
    return resolved
