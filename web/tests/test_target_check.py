"""A runtime scan needs the application to be there: say so at once, not after minutes of failed requests."""
import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from web import scan_manager
from web.scan_manager import ScanManager, _unreachable


@pytest.fixture(autouse=True)
def isolated_scan_history(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_manager, "OUT", tmp_path / "scan-history")


class Answer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(self.server.status)
        self.end_headers()
        self.wfile.write(b"x")

    def log_message(self, *args):
        pass


def serve(status):
    server = HTTPServer(("127.0.0.1", 0), Answer)
    server.status = status
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def closed_port_url():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{sock.getsockname()[1]}"


@pytest.mark.parametrize("status", [200, 302, 404, 500])
def test_any_http_answer_means_the_application_is_there(status):
    server, url = serve(status)
    try:
        assert _unreachable(url) is None
    finally:
        server.shutdown()


def test_a_closed_port_is_reported_with_the_url_and_what_to_check():
    url = closed_port_url()
    message = _unreachable(url)
    assert message and url in message and "Is the application running, and is the URL right?" in message


def test_a_bad_address_is_reported_not_raised():
    assert "Nothing answered" in _unreachable("http://nonexistent.invalid:81/", timeout=3)


def scan(monkeypatch, tmp_path, url, **request):
    ran = []

    async def command(self, scan_id, label, executable, args, cwd):
        ran.append(label)

    monkeypatch.setattr(ScanManager, "_command", command)
    source = tmp_path / "app"
    source.mkdir(exist_ok=True)

    async def go():
        manager = ScanManager()
        job = await manager.start({"target_id": "custom", "source_path": str(source), "language": "php", "target_url": url,
                                   "run_sast": True, "run_dast": True, **request})
        await manager.tasks[job["id"]]
        return manager.jobs[job["id"]]

    return asyncio.run(go()), ran


def test_a_scan_of_an_application_that_is_not_up_stops_at_once_and_says_why(monkeypatch, tmp_path):
    url = closed_port_url().replace("127.0.0.1", "localhost")
    job, ran = scan(monkeypatch, tmp_path, url)
    assert job["status"] == "failed" and "Nothing answered at" in job["error"] and url in job["error"]
    assert ran == []      # not even the source scan: the whole scan is refused before any work is done


def test_a_scan_of_an_application_that_answers_goes_ahead(monkeypatch, tmp_path):
    server, url = serve(404)
    try:
        job, ran = scan(monkeypatch, tmp_path, url.replace("127.0.0.1", "localhost"))
    finally:
        server.shutdown()
    assert "Nothing answered" not in str(job.get("error"))
    assert ran[:1] == ["SAST scan"]


def test_a_source_only_scan_does_not_need_a_running_application(monkeypatch, tmp_path):
    job, ran = scan(monkeypatch, tmp_path, closed_port_url().replace("127.0.0.1", "localhost"), run_dast=False)
    assert "Nothing answered" not in str(job.get("error")) and ran[:1] == ["SAST scan"]
