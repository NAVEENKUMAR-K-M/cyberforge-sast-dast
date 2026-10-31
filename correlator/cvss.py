"""CVSS v3.0 Base and Temporal scores, following the FIRST v3.0 specification.

https://www.first.org/cvss/v3.0/specification-document (section 8, the equations)
"""
from __future__ import annotations

import math

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    "E": {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91},
    "RL": {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95},
    "RC": {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92},
}
# Privileges Required weighs more when the attack reaches past the vulnerable component.
PRIVILEGES = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.50}}
BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(value: float) -> float:
    """The smallest number with one decimal place that is >= value. Computed on integers so that
    float error can't push 4.0 up to 4.1 (the approach FIRST later adopted in v3.1)."""
    scaled = round(value * 100_000)
    return scaled / 100_000 if scaled % 10_000 == 0 else (math.floor(scaled / 10_000) + 1) / 10.0


def parse(vector: str) -> dict:
    """`AV:N/AC:L/...` (with or without the `CVSS:3.0/` prefix) into a dict."""
    parts = dict(part.split(":", 1) for part in vector.split("/") if not part.startswith("CVSS"))
    missing = [m for m in BASE_METRICS if m not in parts]
    if missing:
        raise ValueError(f"CVSS vector is missing {', '.join(missing)}: {vector}")
    return parts


def base_score(metrics: dict) -> float:
    scope = metrics["S"]
    impact_base = 1 - (1 - WEIGHTS["C"][metrics["C"]]) * (1 - WEIGHTS["I"][metrics["I"]]) * (1 - WEIGHTS["A"][metrics["A"]])
    if scope == "U":
        impact = 6.42 * impact_base
    else:
        impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
    exploitability = (8.22 * WEIGHTS["AV"][metrics["AV"]] * WEIGHTS["AC"][metrics["AC"]]
                      * PRIVILEGES[scope][metrics["PR"]] * WEIGHTS["UI"][metrics["UI"]])
    if impact <= 0:
        return 0.0
    if scope == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def temporal_score(base: float, metrics: dict) -> float:
    return roundup(base * WEIGHTS["E"][metrics.get("E", "X")] * WEIGHTS["RL"][metrics.get("RL", "X")]
                   * WEIGHTS["RC"][metrics.get("RC", "X")])


def rating(score: float) -> str:
    """The qualitative severity rating scale from the specification."""
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def vector_string(metrics: dict) -> str:
    order = [*BASE_METRICS, "E", "RL", "RC"]
    return "CVSS:3.0/" + "/".join(f"{m}:{metrics[m]}" for m in order if m in metrics)
