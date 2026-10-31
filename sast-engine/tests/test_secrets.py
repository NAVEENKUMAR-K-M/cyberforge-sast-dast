"""Pattern rules through real Semgrep, including the filter on what counts as a secret."""
import pytest

from conftest import open_findings
from sast.semgrep_runner import looks_like_real_secret


@pytest.mark.parametrize("line", [
    "$password = 'hunter2';",
    "define('DB_PASSWORD', 'mutillidae');",
    "private const ACCESS_TOKEN_SECRET = \"12345\";",
    "'api_key' => 'pk_9f8e7d6c5b4a39281706',",
    "$this->secret = 'abc';",
    "$apiToken = 'a8f3k29dk3kd92kd';",
])
def test_real_secrets(line):
    assert looks_like_real_secret(line)


@pytest.mark.parametrize("line", [
    '$passwordField = "user_password";',
    '$tokenHeader = "X-Request-Id";',
    "'password' => 'xsd:string',",
    '"token_type" => "bearer",',
    '$token = "userid:2";',
    '$this->mTokenValid = "Token is valid";',
    '$this->mCSRFTokenStrength = "NONE";',
    '$row->password = "******";',
    "define('DB_PASSWORD', '');",
    "$password = 'changeme';",
    '$password_help = "Enter your password here";',
])
def test_not_secrets(line):
    assert not looks_like_real_secret(line)


def test_semgrep_rules_end_to_end(scan):
    result = scan({
        "config.php": "<?php\ndefine('DB_PASSWORD', 'Sup3r!');\n$awsKey = 'AKIAIOSFODNN7EXAMPLE';\n$dbHost = getenv('H');\n",
        "settings.inc": "<?php\n$secret = 'inc-file-secret';\n",
        "page.php": "<?php\n$p = md5($password);\n$t = uniqid();\n$resetToken = md5(mt_rand());\nini_set('display_errors', '1');\nphpinfo();\n",
    }, semgrep=True)
    assert result["stats"]["semgrep_error"] is None
    secrets = {(f["file"], f["line"]) for f in open_findings(result, 798)}
    assert secrets == {("config.php", 2), ("config.php", 3), ("settings.inc", 2)}
    assert open_findings(result, 327)
    assert open_findings(result, 330)
    assert len(open_findings(result, 489)) == 2


def test_taint_and_pattern_hit_on_one_line_merge(scan):
    result = scan({"page.php": "<?php\n$h = md5($_POST['password']);\n"}, semgrep=True)
    found = open_findings(result, 327)
    assert len(found) == 1
    assert found[0]["engines"] == ["semgrep", "taint"]
