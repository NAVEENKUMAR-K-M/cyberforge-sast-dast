import sys

import pytest

from cyberforge import runtime


def test_only_this_machine_is_allowed_by_default(monkeypatch):
    monkeypatch.delenv("CYBERFORGE_ALLOWED_HOSTS", raising=False)
    assert runtime.allowed_hosts() == {"localhost", "127.0.0.1"}


def test_the_allow_list_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("CYBERFORGE_ALLOWED_HOSTS", "localhost, 127.0.0.1 ,Host.Docker.Internal,")
    assert runtime.allowed_hosts() == {"localhost", "127.0.0.1", "host.docker.internal"}


def test_an_empty_setting_falls_back_to_the_safe_default(monkeypatch):
    monkeypatch.setenv("CYBERFORGE_ALLOWED_HOSTS", " , ")
    assert runtime.allowed_hosts() == {"localhost", "127.0.0.1"}


def test_python_for_prefers_an_explicit_override(monkeypatch):
    monkeypatch.setenv("CYBERFORGE_SAST_PYTHON", "/custom/python")
    assert str(runtime.python_for("sast")).replace("\\", "/") == "/custom/python"


def test_python_for_uses_the_engines_own_virtualenv_when_it_exists(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERFORGE_DAST_PYTHON", raising=False)
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    bin_dir = tmp_path / "dast-engine" / ".venv" / ("Scripts" if sys.platform == "win32" else "bin")
    bin_dir.mkdir(parents=True)
    interpreter = bin_dir / ("python.exe" if sys.platform == "win32" else "python")
    interpreter.write_text("")
    assert runtime.python_for("dast") == interpreter


def test_python_for_falls_back_to_this_interpreter_in_a_single_environment_install(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERFORGE_SAST_PYTHON", raising=False)
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    assert str(runtime.python_for("sast")) == sys.executable


def test_custom_only_mode_is_opt_in(monkeypatch):
    monkeypatch.delenv("CYBERFORGE_CUSTOM_ONLY", raising=False)
    assert runtime.custom_only() is False
    monkeypatch.setenv("CYBERFORGE_CUSTOM_ONLY", "1")
    assert runtime.custom_only() is True


def test_any_existing_folder_is_accepted_when_no_workspace_is_set(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERFORGE_WORKSPACE", raising=False)
    assert runtime.resolve_source(str(tmp_path)) == tmp_path.resolve()


def test_a_relative_source_is_read_inside_the_workspace(monkeypatch, tmp_path):
    (tmp_path / "shop").mkdir()
    monkeypatch.setenv("CYBERFORGE_WORKSPACE", str(tmp_path))
    assert runtime.resolve_source("shop") == (tmp_path / "shop").resolve()
    assert runtime.resolve_source(str(tmp_path)) == tmp_path.resolve()


@pytest.mark.parametrize("value", ["../outside", "shop/../../outside"])
def test_a_source_that_climbs_out_of_the_workspace_is_refused(monkeypatch, tmp_path, value):
    workspace = tmp_path / "ws"
    (workspace / "shop").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    monkeypatch.setenv("CYBERFORGE_WORKSPACE", str(workspace))
    with pytest.raises(ValueError, match="must be inside"):
        runtime.resolve_source(value)


@pytest.mark.parametrize("value", [None, "", "   ", 5, "a\0b"])
def test_nonsense_sources_are_refused(value):
    with pytest.raises(ValueError, match="folder that holds"):
        runtime.resolve_source(value)


def test_a_missing_folder_is_refused(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERFORGE_WORKSPACE", raising=False)
    with pytest.raises(ValueError, match="not found"):
        runtime.resolve_source(str(tmp_path / "nope"))
