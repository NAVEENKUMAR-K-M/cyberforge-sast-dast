"""CWE normalisation and default severities."""

# Exact CWEs that describe the same class of bug as a family head. A later
# correlator compares families, because scanners often label one bug differently.
FAMILY = {
    89: 89, 564: 89, 943: 89,
    79: 79, 80: 79, 83: 79, 87: 79,
    78: 78, 77: 78, 88: 78,
    22: 22, 23: 22, 36: 22, 73: 22, 98: 22,
    601: 601,
    798: 798, 259: 798, 321: 798,
    327: 327, 328: 327, 916: 327,
    330: 330, 338: 330,
    502: 502,
    94: 94, 95: 94,
    489: 489, 200: 489, 209: 489,
}

TITLES = {
    89: "SQL injection",
    79: "Cross-site scripting",
    78: "Command injection",
    22: "Path traversal",
    601: "Open redirect",
    798: "Hard-coded secret",
    327: "Weak password hash",
    330: "Insecure randomness",
    502: "Unsafe deserialization",
    94: "Code injection",
    489: "Debug feature enabled",
}

SEVERITY = {
    89: "critical",
    78: "critical",
    94: "critical",
    502: "high",
    22: "high",
    79: "high",
    798: "high",
    601: "medium",
    327: "medium",
    330: "medium",
    489: "low",
}


def family(cwe: int) -> int:
    return FAMILY.get(cwe, cwe)


def fmt(cwe: int) -> str:
    return f"CWE-{cwe}"
