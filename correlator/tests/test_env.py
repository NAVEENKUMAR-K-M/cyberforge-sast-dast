"""The .env loader: keys come from a file, never from code, and the environment wins."""
import os

from correlator.env import load_env


def test_reads_keys_skips_comments_and_strips_quotes(tmp_path, monkeypatch):
    for name in ("A_KEY", "B_KEY", "C_KEY", "EMPTY_KEY"):
        monkeypatch.delenv(name, raising=False)
    env = tmp_path / ".env"
    env.write_text('# a comment\n\nA_KEY=plain\nB_KEY="quoted value"\nexport C_KEY = \'single\'\nEMPTY_KEY=\nnot a line\n')
    assert load_env(str(env)) == ["A_KEY", "B_KEY", "C_KEY"]
    assert (os.environ["A_KEY"], os.environ["B_KEY"], os.environ["C_KEY"]) == ("plain", "quoted value", "single")
    assert "EMPTY_KEY" not in os.environ


def test_a_variable_already_set_wins_and_a_missing_file_is_fine(tmp_path, monkeypatch):
    monkeypatch.setenv("A_KEY", "from the shell")
    env = tmp_path / ".env"
    env.write_text("A_KEY=from the file\n")
    assert load_env(str(env)) == [] and os.environ["A_KEY"] == "from the shell"
    assert load_env(str(tmp_path / "missing.env")) == []


def test_the_repo_ignores_env_files_but_keeps_the_example():
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    ignored = subprocess.run(["git", "check-ignore", ".env", ".env.local"], cwd=root, capture_output=True, text=True).stdout.split()
    assert ignored == [".env", ".env.local"]
    assert subprocess.run(["git", "check-ignore", ".env.example"], cwd=root, capture_output=True).returncode == 1
