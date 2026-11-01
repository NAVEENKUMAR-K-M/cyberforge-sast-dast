import pytest

from sca.http import Fetcher, Unavailable


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


def test_a_reply_is_cached_with_when_it_was_fetched(tmp_path):
    sent = []

    def send(url, body, headers, timeout):
        sent.append(url)
        return 200, '{"ok": true}'

    clock = Clock()
    fetcher = Fetcher(str(tmp_path), send=send, clock=clock)
    status, data, meta = fetcher.get_json("https://example.test/a")
    assert (status, data, meta["source"]) == (200, {"ok": True}, "live")
    assert fetcher.get_json("https://example.test/a")[2]["source"] == "cache" and len(sent) == 1
    clock.now += 2 * 86400
    fetcher.get_json("https://example.test/a")
    assert len(sent) == 2                       # past its time to live, it is fetched again


def test_offline_reads_only_the_cache(tmp_path):
    Fetcher(str(tmp_path), send=lambda *a: (200, "[]")).get_json("https://example.test/a")
    offline = Fetcher(str(tmp_path), offline=True, send=lambda *a: pytest.fail("no network offline"))
    assert offline.get_json("https://example.test/a")[1] == []
    with pytest.raises(Unavailable):
        offline.get_json("https://example.test/other")


def test_rate_limits_are_unavailable_and_never_cached(tmp_path):
    fetcher = Fetcher(str(tmp_path), send=lambda *a: (403, "rate limited"))
    with pytest.raises(Unavailable):
        fetcher.get_json("https://api.github.com/advisories/X")
    assert list(tmp_path.iterdir()) == []


def test_a_failure_falls_back_to_a_stale_copy(tmp_path):
    clock = Clock()
    Fetcher(str(tmp_path), send=lambda *a: (200, "1"), clock=clock).get_json("https://example.test/a")
    clock.now += 10 * 86400

    def broken(*a):
        raise OSError("network down")

    status, data, meta = Fetcher(str(tmp_path), send=broken, clock=clock).get_json("https://example.test/a")
    assert data == 1 and meta["source"] == "cache (stale)"


def test_a_404_is_an_answer_not_a_failure(tmp_path):
    status, data, _ = Fetcher(str(tmp_path), send=lambda *a: (404, "nope")).get_json("https://example.test/missing")
    assert status == 404 and data is None


def test_the_token_goes_only_to_github(tmp_path):
    seen = {}

    def send(url, body, headers, timeout):
        seen[url] = headers.get("Authorization")
        return 200, "{}"

    fetcher = Fetcher(str(tmp_path), token="t0k", send=send)
    fetcher.get_json("https://api.github.com/advisories/X")
    fetcher.get_json("https://api.osv.dev/v1/vulns/X")
    assert seen == {"https://api.github.com/advisories/X": "Bearer t0k", "https://api.osv.dev/v1/vulns/X": None}
