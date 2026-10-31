"""Works out which column each input lands in, so a stored flow names the right parameter."""
from __future__ import annotations

import re

from .values import Val, union

INSERT = re.compile(r"\b(?:insert|replace)\s+(?:ignore\s+)?into\s+\S+?\s*\(([^)]*)\)\s*values\s*\((.*)\)", re.I | re.S)
UPDATE = re.compile(r"\bupdate\s+\S+\s+set\s+(.*?)(?:\s+where\b.*)?;?\s*$", re.I | re.S)
ASSIGN = re.compile(r"^\s*[`\"\[]?(\w+)[`\"\]]?\s*=\s*(.*)$", re.S)


def _split(text: str) -> list:
    """Splits on commas outside quotes and brackets."""
    parts, depth, quote, current = [], 0, None, ""
    for char in text:
        if quote:
            quote = None if char == quote else quote
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(current)
            current = ""
            continue
        current += char
    parts.append(current)
    return parts


def _clean(name: str) -> str:
    return name.strip().strip("`\"[]").lower()


def _assignments(text: str) -> list | None:
    """Returns [(column, value text)] for an INSERT or UPDATE, or None when it can't be parsed."""
    match = INSERT.search(text)
    if match:
        columns, values = _split(match.group(1)), _split(match.group(2))
        if len(columns) != len(values):
            return None
        return [(_clean(c), v.strip()) for c, v in zip(columns, values)]
    match = UPDATE.search(text)
    if match:
        out = []
        for piece in _split(match.group(1)):
            assign = ASSIGN.match(piece)
            if not assign:
                return None
            out.append((assign.group(1).lower(), assign.group(2).strip()))
        return out
    return None


def string_columns(text: str, target: Val) -> dict | None:
    """For SQL built by concatenation: matches each * to the input recorded as filling it."""
    parts = target.parts
    pairs = _assignments(text)
    if parts is None or pairs is None:
        return None
    # A WHERE clause can hold more *s after the columns, so only too few is a mismatch.
    if sum(value.count("*") for _, value in pairs) > len(parts):
        return None
    columns, index = {}, 0
    taints = list(target.flat().taints.values())
    for column, value in pairs:
        for _ in range(value.count("*")):
            wanted = parts[index]
            index += 1
            chosen = {t.key: t for t in taints if (t.name, t.location) in wanted}
            if chosen:
                columns[column] = union(columns.get(column), Val(chosen))
    return columns or None


def bound_pairs(method, args, literal_of, arg_nodes, fr) -> list:
    """Returns [(placeholder or position, value)] for a bind or execute call."""
    if method in ("bindparam", "bindvalue") and len(args) >= 2:
        key = literal_of(arg_nodes[0], fr)
        return [(key, args[1])] if key is not None else []
    if method == "bind_param":
        return [(str(i), value) for i, value in enumerate(args[1:])]
    if method == "execute" and args and args[0].fields:
        return list(args[0].fields.items())
    return []


def bound_columns(text: str, pairs) -> dict | None:
    """For prepared statements: matches each ? or :name to its column."""
    assignments = _assignments(text)
    if assignments is None or not pairs:
        return None
    by_placeholder, positions = {}, []
    for column, value in assignments:
        if value == "?":
            positions.append(column)
        elif value.startswith(":"):
            by_placeholder[value.lstrip(":").lower()] = column
    # execute([...]) counts from 0, while bindParam(1, ...) counts from 1.
    offset = 1 if any(str(key).isdigit() for key, _ in pairs) and all(str(key) != "0" for key, _ in pairs) else 0
    columns = {}
    for key, value in pairs:
        name = str(key).lstrip(":").lower()
        if name.isdigit():
            index = int(name) - offset
            column = positions[index] if 0 <= index < len(positions) else None
        else:
            column = by_placeholder.get(name)
        if column is None:
            return None
        columns[column] = union(columns.get(column), value)
    return {k: v for k, v in columns.items() if v.tainted} or None
