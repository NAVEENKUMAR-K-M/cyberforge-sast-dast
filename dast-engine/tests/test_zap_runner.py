from scanners.zap_runner import ZapRunner


def make_runner(scan_target=None):
    return ZapRunner(
        zap_api_url="http://localhost:8090",
        target="http://localhost:8080",
        deadline_ts=0,
        scan_target=scan_target,
    )


def test_to_scan_url_rewrites_host_when_override_given():
    runner = make_runner(scan_target="http://dvwa:80")
    assert runner._to_scan_url("http://localhost:8080/vulnerabilities/sqli/?id=1") == "http://dvwa:80/vulnerabilities/sqli/?id=1"


def test_to_public_url_rewrites_back():
    runner = make_runner(scan_target="http://dvwa:80")
    assert runner._to_public_url("http://dvwa:80/vulnerabilities/sqli/?id=1") == "http://localhost:8080/vulnerabilities/sqli/?id=1"


def test_no_rewrite_when_scan_target_not_set():
    runner = make_runner(scan_target=None)
    url = "http://localhost:8080/vulnerabilities/sqli/?id=1"
    assert runner._to_scan_url(url) == url
    assert runner._to_public_url(url) == url


def test_unrelated_host_is_left_untouched():
    runner = make_runner(scan_target="http://dvwa:80")
    # a URL that doesn't match target's netloc at all should pass through unchanged
    assert runner._to_scan_url("http://evil.example.com/x") == "http://evil.example.com/x"
