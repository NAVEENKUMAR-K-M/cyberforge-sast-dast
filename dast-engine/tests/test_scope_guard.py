from core.scope_guard import ScopeGuard


def make_guard():
    return ScopeGuard(allowed_hosts=["localhost", "127.0.0.1"], denylist_patterns=["logout", "setup"])


def test_allows_allowlisted_host():
    guard = make_guard()
    assert guard.is_in_scope("http://localhost:8080/vulnerabilities/sqli/?id=1")
    assert guard.is_in_scope("http://127.0.0.1:8080/")


def test_refuses_non_allowlisted_host():
    guard = make_guard()
    assert not guard.is_in_scope("http://evil.example.com/")
    assert not guard.is_in_scope("https://attacker.invalid/steal")


def test_refuses_denylisted_path():
    guard = make_guard()
    assert not guard.is_in_scope("http://localhost:8080/logout.php")
    assert not guard.is_in_scope("http://localhost:8080/setup.php")


def test_refuses_off_host_redirect():
    guard = make_guard()
    assert not guard.check_redirect("http://localhost:8080/login.php", "http://evil.example.com/phish")
    assert not guard.check_redirect("http://localhost:8080/login.php", "//evil.example.com/phish")


def test_allows_same_host_redirect():
    guard = make_guard()
    assert guard.check_redirect("http://localhost:8080/login.php", "/dashboard.php")


def test_refuses_non_http_scheme():
    guard = make_guard()
    assert not guard.is_in_scope("file:///etc/passwd")
    assert not guard.is_in_scope("javascript:alert(1)")


def test_is_allowed_host_ignores_denylist_but_not_allowlist():
    guard = make_guard()
    # denylisted path, allowlisted host -> allowed-host check passes
    assert guard.is_allowed_host("http://localhost:8080/setup.php")
    # non-allowlisted host -> still refused
    assert not guard.is_allowed_host("http://evil.example.com/setup.php")
