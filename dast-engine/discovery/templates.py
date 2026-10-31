"""Route templates as different frameworks and tools write them.

SAST writes `/orders/{order_id}`, a crawl names the same spot `/orders/{id}`, an OpenAPI document may say
`/orders/{id}` or `/orders/<int:id>`, and a hint can use any of them. Matching them by position instead of by
name is what lets a hint reach a point that was found another way.
"""
from __future__ import annotations

import re

# {name}, {name?}, {name:int}, <name>, <int:name>, :name
_PLACEHOLDER = re.compile(r"\{[^{}/]*\}|<[^<>/]*>|(?<=/):[A-Za-z_]\w*(?=/|$)")
_BRACE_NAME = re.compile(r"\{(\w+)")
_ANGLE_NAME = re.compile(r"<(?:\w+:)?(\w+)>")
_COLON_NAME = re.compile(r"^:(\w+)$")


def normalize(template: str) -> str:
    """The template with every placeholder written `{}` and no trailing slash."""
    path = _PLACEHOLDER.sub("{}", template).split("?")[0]  # a placeholder may itself end in ?
    return path.rstrip("/") or "/"


def placeholder_names(template: str) -> list[str]:
    names = []
    for match in _PLACEHOLDER.finditer(template):
        text = match.group(0)
        found = _BRACE_NAME.match(text) or _ANGLE_NAME.match(text) or _COLON_NAME.match(text)
        names.append(found.group(1) if found else "")
    return names


def path_index(template: str, name: str) -> int | None:
    """Which placeholder (counting from 0) is called `name`."""
    names = placeholder_names(template)
    return names.index(name) if name in names else None
