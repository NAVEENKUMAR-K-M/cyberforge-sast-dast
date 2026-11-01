"""The SCA is a separate tool the correlator reads from; it must not import the correlator back."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def loaded_after_a_scan(tmp_path):
    """Modules loaded once a whole scan has run: a lazy import inside a function only shows up if the scan runs."""
    app = ROOT / "sca" / "benchmarks" / "composer-app"
    code = ("import sys; from sca import cli\n"
            f"cli.main(['scan', {str(app)!r}, '--out', {str(tmp_path / 'out')!r}, '--cache-dir', {str(app / 'snapshot')!r}, '--offline'])\n"
            "print('\\n'.join(sorted(m for m in sys.modules if m == 'correlator' or m.startswith('correlator.'))))")
    done = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return [line for line in done.stdout.splitlines() if line.startswith("correlator")]


def test_a_whole_scan_does_not_import_the_correlator(tmp_path):
    assert loaded_after_a_scan(tmp_path) == []


def test_the_sca_cli_still_loads_a_token_from_the_env_file(tmp_path):
    """GITHUB_TOKEN is optional but must still be picked up from .env, now via common/env.py."""
    app = ROOT / "sca" / "benchmarks" / "composer-app"
    env = tmp_path / ".env"
    env.write_text("GITHUB_TOKEN=from-the-file\n")
    code = ("import os, sys; from sca import cli; from sca.http import Fetcher\n"
            "seen = {}\n"
            "orig = Fetcher.__init__\n"
            "def spy(self, *a, **k): seen['token'] = k.get('token'); orig(self, *a, **k)\n"
            "Fetcher.__init__ = spy\n"
            f"cli.main(['scan', {str(app)!r}, '--out', {str(tmp_path / 'o')!r}, '--cache-dir', {str(app / 'snapshot')!r}, '--offline'])\n"
            "print('TOKEN=' + str(seen['token']))")
    done = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT)})
    assert "TOKEN=from-the-file" in done.stdout, done.stdout + done.stderr
