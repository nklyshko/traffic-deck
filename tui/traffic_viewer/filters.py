"""mitmproxy-style filter DSL: compile a filter expression into a flow predicate."""

from __future__ import annotations

import re

from .render import url

# Filter fields (subset) over the flow summary.
_FILTER_FIELDS = {
    "~m": lambda f: f.method,
    "~d": lambda f: f.authority,
    "~u": url,
    "~c": lambda f: str(f.status) if f.status else "",
    "~t": lambda f: f.content_type,
}


# Cheat sheet for the filter DSL, shown in the TUI while the filter input is focused.
# Kept next to the operators above so it stays in sync as they change.
FILTER_HELP = (
    "Filter terms are space-separated and ANDed; prefix ! to negate a term.\n"
    "  ~m <re> method     ~d <re> domain      ~u <re> url        ~c <re> status\n"
    "  ~t <re> type       ~mark <re> color    ~tag <re> name     ~group <re> name\n"
    "  ~comment <re>      ~s has response     ~q no response     ~fav favorited\n"
    "  ~meta <key>=<re>   (source metadata; ~meta <key> alone matches presence)\n"
    "  <re>  a bare regex matches the URL           Enter apply · Esc cancel"
)


def _comment_text(f) -> str:
    return " ".join(c.body for c in f.comments)


def compile_filter(expr: str, tagnames: dict | None = None, groupnames: dict | None = None):
    """Compile a filter expression to a predicate(flow)->bool, or None if empty.

    Terms (space-separated, ANDed): `~m/~d/~u/~c/~t <regex>`, `~s`/`~q` (has/no
    response), `~fav` (favorited), annotation fields `~mark/~tag/~group/~comment
    <regex>`, `~meta <key>=<regex>` (a source metadata value; `~meta <key>` alone
    matches presence), a naked regex (matches the URL), and a leading `!` negates a
    term. Raises ValueError on a bad regex. (Full `& | ()` grammar is future.)
    """
    tagnames = tagnames or {}
    groupnames = groupnames or {}
    fields = {
        **_FILTER_FIELDS,
        "~mark": lambda f: f.mark_color,
        "~tag": lambda f: " ".join(tagnames.get(t, t) for t in f.tag_ids),
        "~group": lambda f: " ".join(groupnames.get(g, g) for g in f.group_ids),
        "~comment": _comment_text,
    }

    def _rx(s: str):
        try:
            return re.compile(s, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"bad regex {s!r}: {e}")

    expr = expr.strip()
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
        elif t == "~meta":
            i += 1
            if i >= len(toks):
                raise ValueError("~meta needs a key=regex (or key) argument")
            key, _, pat = toks[i].partition("=")
            i += 1
            if pat:
                rx = _rx(pat)
                base = lambda f, rx=rx, k=key: bool(rx.search(f.metadata.get(k, "")))
            else:  # `~meta key` (no =) matches flows that have the key at all
                base = lambda f, k=key: k in f.metadata
        elif t in fields:
            i += 1
            if i >= len(toks):
                raise ValueError(f"{t} needs an argument")
            rx, getter, i = _rx(toks[i]), fields[t], i + 1
            base = lambda f, rx=rx, g=getter: bool(rx.search(g(f) or ""))
        else:
            rx = _rx(t)
            base = lambda f, rx=rx: bool(rx.search(url(f)))
            i += 1
        preds.append(lambda f, b=base, n=neg: (not b(f)) if n else b(f))
    return lambda f: all(p(f) for p in preds)
