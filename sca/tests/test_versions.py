"""Version ordering against Composer itself.

`data/composer_order.json` holds version pairs ordered by Composer's own comparator, on real versions (Packagist
releases and the bounds of Packagist advisories), sampled so every shape of version appears: plain, release
candidates (`RC-8`), patch levels, build metadata, dates, four-part numbers, and strings Composer rejects. The code
under test is checked against Composer's answers, not against what it was written to return.
"""
import json
import os

import pytest

from sca.advisories import _in_range, _key

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "composer_order.json")) as handle:
    DATA = json.load(handle)


def order(a, b):
    ka, kb = _key(a), _key(b)
    return 0 if ka == kb else (-1 if ka < kb else 1)


@pytest.mark.parametrize("section", ["order", "forms"])
def test_ordering_matches_composer_on_every_sampled_pair(section):
    wrong = [(v, b, want, order(v, b)) for v, b, want in DATA[section] if order(v, b) != want]
    assert not wrong, f"{len(wrong)} of {len(DATA[section])} pairs ordered differently from Composer, e.g. {wrong[:5]}"


@pytest.mark.parametrize("section", ["readable", "forms_readable"])
def test_a_version_is_readable_exactly_when_composer_accepts_it(section):
    wrong = [(s, ok) for s, ok in DATA[section] if (_key(s) is not None) != ok]
    assert not wrong, f"readability differs from Composer for {wrong}"


def test_the_data_covers_the_hard_shapes():
    """A guard on the data, so the checks above can't pass by sampling only easy versions."""
    strings = {s for key in ("order", "forms") for pair in DATA[key] for s in pair[:2]}
    text = " ".join(strings).lower()
    for needle in ("rc-", "-pl", "-patch", "-p1", "+", "-beta", "-alpha", "-dev", "stable", "rc.", "20200101"):
        assert needle in text, f"no version in the data has {needle!r}"
    assert any(not ok for _, ok in DATA["readable"]) and len(DATA["order"]) > 1000 and len(DATA["forms"]) > 2000
    assert {o for _, _, o in DATA["order"]} == {-1, 0, 1}


def test_a_hyphenated_release_candidate_number_is_ordered():
    """Found by checking real data: `RC-8` and `RC-1` used to compare equal."""
    assert _key("6.0.0-RC-8") > _key("6.0.0-RC-1") and _key("6.0.0-RC-1") < _key("6.0.0")


def test_an_unreadable_bound_makes_the_range_unknown_not_skipped():
    events = [{"introduced": "1.5.7c"}, {"fixed": "2.0.0"}]
    assert _in_range("1.9.0", events) is None
    assert _in_range("1.5.7c", [{"introduced": "0"}, {"fixed": "2.0.0"}]) is None
    assert _in_range("1.9.0", [{"introduced": "1.0.0"}, {"fixed": "1.5.7c"}]) is None


@pytest.mark.parametrize("version,events,expected", [
    ("v7.4.18", [{"introduced": "6.0.1"}, {"fixed": "6.4.46"}, {"introduced": "7.0.0"}, {"fixed": "7.4.19"}], True),
    ("7.4.19", [{"introduced": "7.0.0"}, {"fixed": "7.4.19"}], False),            # the fixed version is not affected
    ("7.4.19", [{"introduced": "7.0.0"}, {"last_affected": "7.4.19"}], True),     # last_affected is
    ("3.3", [{"introduced": "0"}, {"fixed": "3.3.0"}], False),                    # 3.3 is 3.3.0 in Composer
    ("8.0.2+build.7", [{"introduced": "0"}, {"fixed": "8.0.2"}], False),          # build metadata is ignored
    ("3.1.7", [{"introduced": "0"}, {"fixed": "3.1.7-PL1"}], True),               # a patch level sorts above the release
    ("1.2.0-RC1", [{"introduced": "1.2.0"}, {"fixed": "1.3.0"}], False),          # a pre-release sorts below its release
    ("99.0.0", [{"introduced": "1.0.0"}], True),                                  # no fix: affected from there on
])
def test_range_semantics_follow_composer(version, events, expected):
    assert _in_range(version, events) is expected
