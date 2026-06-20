"""mitmproxy-style flow filter (plan §7.3), ported for the MCP search_flows tool.

Same surface as the TUI's compile_filter: space-separated ANDed terms over a flow
summary — `~m/~d/~u/~c/~t`, `~s/~q`, `~fav`, annotation fields
`~mark/~tag/~group/~comment`, a naked regex (matches the URL), leading `!` negates.
"""

from __future__ import annotations

import re


def flow_url(f) -> str:
    u = f"{f.scheme or 'https'}://{f.authority}{f.path}"
    if f.query:
        u += f"?{f.query}"
    return u


_FIELDS = {
    "~m": lambda f: f.method,
    "~d": lambda f: f.authority,
    "~u": flow_url,
    "~c": lambda f: str(f.status) if f.status else "",
    "~t": lambda f: f.content_type,
}


def compile_filter(expr: str, tagnames: dict | None = None, groupnames: dict | None = None):
    """Compile a filter expression to predicate(flow)->bool, or None if empty.

    Raises ValueError on a bad regex or a field term missing its argument.
    """
    tagnames = tagnames or {}
    groupnames = groupnames or {}
    fields = {
        **_FIELDS,
        "~mark": lambda f: f.mark_color,
        "~tag": lambda f: " ".join(tagnames.get(t, t) for t in f.tag_ids),
        "~group": lambda f: " ".join(groupnames.get(g, g) for g in f.group_ids),
        "~comment": lambda f: " ".join(c.body for c in f.comments),
    }

    def _rx(s: str):
        try:
            return re.compile(s, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"bad regex {s!r}: {e}")

    expr = (expr or "").strip()
    if not expr:
        return None
    toks = expr.split()
    preds = []
    i = 0
    while i < len(toks):
        t, neg = toks[i], False
        if t == "!":
            neg, i = True, i + 1
            if i >= len(toks):
                break
            t = toks[i]
        elif t.startswith("!") and len(t) > 1:
            neg, t = True, t[1:]

        if t in ("~s", "~q"):
            base = (lambda f: bool(f.status)) if t == "~s" else (lambda f: not f.status)
            i += 1
        elif t == "~fav":
            base = lambda f: f.favorite
            i += 1
        elif t in fields:
            i += 1
            if i >= len(toks):
                raise ValueError(f"{t} needs an argument")
            rx, getter, i = _rx(toks[i]), fields[t], i + 1
            base = lambda f, rx=rx, g=getter: bool(rx.search(g(f) or ""))
        else:
            rx = _rx(t)
            base = lambda f, rx=rx: bool(rx.search(flow_url(f)))
            i += 1
        preds.append(lambda f, b=base, n=neg: (not b(f)) if n else b(f))
    return lambda f: all(p(f) for p in preds)
