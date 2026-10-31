import socket
import threading
import time

import pytest


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def fixture_app_url():
    from tests.fixtures.app import app

    port = _free_port()
    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False),
        daemon=True,
    )
    thread.start()
    time.sleep(0.5)
    yield f"http://127.0.0.1:{port}"


@pytest.fixture(scope="session")
def vuln_app_url():
    from tests.fixtures.vuln_app import app

    port = _free_port()
    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False, threaded=True),
        daemon=True,
    )
    thread.start()
    time.sleep(0.5)
    yield f"http://127.0.0.1:{port}"
