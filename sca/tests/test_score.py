"""The scorer decides what counts as a wrong answer, so its rules are tested on their own."""
import pytest

from sca.eval.score import score


def result(status, truth, expected=None):
    report = {"dependencies": [{"package": "a/b", "advisory": {"id": "ADV"}, "status": status}]}
    key = {"rows": [{"package": "a/b", "advisory": "ADV", "truth": truth, "expected": expected or truth}]}
    return score(report, key)


@pytest.mark.parametrize("status,truth,false_reachable,unsafe", [
    ("Reachable", "Reachable", False, False),
    ("Reachable", "Unknown", True, False),           # a Reachable the truth doesn't support
    ("Reachable", "Imported-only", True, False),
    ("Unknown", "Reachable", False, False),          # imprecise but safe
    ("Unknown", "Present-only", False, False),
    ("Imported-only", "Imported-only", False, False),
    ("Imported-only", "Reachable", False, True),     # reassures where the function is reachable
    ("Imported-only", "Unknown", False, True),       # reassures where it can't be settled
    ("Present-only", "Present-only", False, False),
    ("Present-only", "Imported-only", False, True),  # "nothing uses it", when the app does use it
    ("Present-only", "Reachable", False, True),
])
def test_the_two_error_kinds(status, truth, false_reachable, unsafe):
    got = result(status, truth)
    assert bool(got["false_reachable"]) is false_reachable and bool(got["unsafe_reassurance"]) is unsafe


def test_a_row_the_report_lacks_is_missing_not_matched():
    got = score({"dependencies": []}, {"rows": [{"package": "a/b", "advisory": "ADV", "truth": "Unknown", "expected": "Unknown"}]})
    assert got["status_matches"] == "0/1" and got["rows"][0]["got"] == "missing"


def test_a_row_the_key_lacks_is_reported():
    got = score({"dependencies": [{"package": "x/y", "advisory": {"id": "Z"}, "status": "Unknown"}]}, {"rows": []})
    assert got["not_in_key"] == ["x/y Z"]
