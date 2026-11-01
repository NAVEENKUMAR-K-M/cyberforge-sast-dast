"""Stage 5, part 2: what the roots can reach, once through exact calls only and once through any call.

A function reached through exact calls is on a path every step of which we could resolve to one target. One reached
only through the second walk depends on a candidate step (an override, a method found by name, a closure that may
never run), so it can only ever make a result Unknown, never Reachable.
"""
from __future__ import annotations

import time
from collections import deque

ASSUMPTIONS = {
    "new": "new X runs X's constructor",
    "$this": "a call on $this runs in the class the object was created as, when that is known",
    "typed receiver": "a receiver's declared type is the object passed in (every override we index was considered)",
    "receiver created with new": "a method called on an object created with new runs that class's method",
    "function": "a function call resolves the way PHP does: the current namespace first, then the global one",
    "include": "a literal include runs the included file",
    "autoload": "loading vendor/autoload.php runs every package's autoload files",
    "static call": "a static call runs the named class's method",
    "self::": "self:: runs the declaring class's method",
    "parent::": "parent:: runs the parent class's method",
    "static::": "static:: runs in the class the object was created as",
}


class Reach:
    def __init__(self):
        self.exact: dict = {}       # state -> (previous state, site) or None for a root
        self.any: dict = {}
        self.unresolved: list = []  # (state, site) for every unresolved site the roots can reach
        self.complete = True
        self.limit = None

    def reached(self, key: str, exact: bool) -> bool:
        return any(state[0] == key for state in (self.exact if exact else self.any))


def explore(index, roots: list, autoload_roots: list, max_states: int = 200_000, timeout: float = 60.0,
            clock=time.monotonic) -> Reach:
    reach = Reach()
    started = clock()
    for exact_only in (True, False):
        parents, queue = {}, deque()
        for fn in roots:
            state = (fn.key, None)
            if state not in parents:
                parents[state] = None
                queue.append(state)
        while queue:
            if len(parents) > max_states or clock() - started > timeout:
                reach.complete = False
                reach.limit = (f"stopped after {len(parents)} functions" if len(parents) > max_states
                               else f"stopped after {timeout:g} seconds")
                break
            state = queue.popleft()
            fn = index.funcs[state[0]]
            for site in index.calls(fn, state[1]):
                if not exact_only and site.unresolved:
                    reach.unresolved.append((state, site))
                if exact_only and not site.exact:
                    continue
                targets = [(f, None) for f in autoload_roots] if site.how == "autoload" else site.targets
                for target, this in targets:
                    nxt = (target.key, this)
                    if nxt not in parents:
                        parents[nxt] = (state, site)
                        queue.append(nxt)
        if exact_only:
            reach.exact = parents
        else:
            reach.any = parents
    return reach


def path_to(index, parents: dict, key: str):
    """The shortest path from a root to the function, as steps; None when it isn't reached. A BFS finds each state
    first by its shortest path, so the first state for the function in discovery order is the one to report."""
    state = next((s for s in parents if s[0] == key), None)
    if state is None:
        return None
    chain = []
    while state is not None:
        link = parents[state]
        chain.append((state, link[1] if link else None))
        state = link[0] if link else None
    chain.reverse()
    steps = []
    for (fkey, _), site in chain:
        fn = index.funcs[fkey]
        step = {"function": fn.label, "package": fn.package, "file": fn.sf.rel, "line": fn.line}
        if site is not None:
            step["called_from"] = {"file": site.file, "line": site.line, "code": site.text, "how": site.how, "exact": site.exact}
        steps.append(step)
    return steps


def path_assumptions(steps) -> list:
    hows = []
    for step in steps or []:
        how = (step.get("called_from") or {}).get("how")
        if how and how not in hows:
            hows.append(how)
    return [ASSUMPTIONS.get(how, how) for how in hows]


def first_doubt(steps):
    """The first step of a path that isn't an exact call: why the path isn't proof."""
    for step in steps or []:
        call = step.get("called_from")
        if call and not call["exact"]:
            return call
    return None
