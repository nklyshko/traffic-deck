"""mitmproxy-style flow filter, ported for the MCP search_flows tool.

Same surface as the TUI's compile_filter: space-separated ANDed terms over a flow
summary — `~m/~d/~u/~c/~t`, `~s/~q`, `~fav`, annotation fields
`~mark/~tag/~group/~comment`, a naked regex (matches the URL), leading `!` negates.

`FILTER_SYNTAX` and `filter_hints` exist for callers to hand back on a filter that
parsed but matched nothing: the DSL has no boolean operators, so a plausible-looking
`~d a & ~c 200` silently degrades into extra URL regexes instead of failing, and an
agent writing it gets an empty result with no clue why.
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

# Terms taking a regex argument, and the flag terms taking none. Names only — the
# getters live in `_FIELDS`/`compile_filter` — so `_parse` stays independent of them.
_ARG_TERMS = (*_FIELDS, "~mark", "~tag", "~group", "~comment")
_FLAG_TERMS = ("~s", "~q", "~fav")


# The full syntax reference, handed back with an empty or rejected filter so a caller
# that guessed the dialect wrong can correct itself without another round trip. Keep in
# sync with the search_flows docstring in server.py (which is the shorter summary).
FILTER_SYNTAX = """\
Filter syntax (mitmproxy-style)

Terms are separated by SPACES and are ANDed automatically. There are no boolean
operators: `&`, `&&`, `|`, `||`, `and`, `or` and parentheses are NOT supported, and a
stray one is parsed as another regex to match against the URL. Prefix a term with `!`
to negate it.

Terms taking a <regex> argument:
  ~m <re>        request method
  ~d <re>        domain — the authority/host alone ("api.example.com"), no scheme or path
  ~u <re>        the full URL: scheme://domain/path?query
  ~c <re>        response status code
  ~t <re>        content-type
  ~mark <re>     color mark      ~tag <re>      tag name
  ~group <re>    group name      ~comment <re>  comment body

Terms taking NO argument:
  ~s   has a response      ~q   has no response      ~fav   favorited

A bare regex with no ~term matches the URL, so `200` on its own matches URLs
containing "200" — it does NOT filter by status. Use `~c 200` for that.

Arguments are regexes and are NOT quoted: `'x'` or `"x"` matches those literal quote
characters. Escape dots, since `.` matches any character.

Examples:
  ~d vseinstrumenti\\.ru ~u /product/ ~c 200      domain + path + status
  ~m POST ~c ^4 !~u /health                       POSTs that 4xx'd, health checks out
  ~d example\\.com ~q                             requests to a host that got no response
"""

_BOOLEAN_TOKENS = {"&", "&&", "|", "||", "and", "or"}


def _parse(expr: str) -> list[tuple[str, str | None, bool]]:
    """Tokenize into (term, argument, negated) triples; term is "" for a naked URL regex
    and argument None for a flag term. Shared by `compile_filter` and `filter_hints` so
    the diagnostics always describe the same parse the predicate was built from.

    Raises ValueError when a term taking an argument is missing it.
    """
    toks = expr.split()
    out: list[tuple[str, str | None, bool]] = []
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

        if t in _FLAG_TERMS:
            out.append((t, None, neg))
            i += 1
        elif t in _ARG_TERMS:
            i += 1
            if i >= len(toks):
                raise ValueError(f"{t} needs an argument")
            out.append((t, toks[i], neg))
            i += 1
        else:
            out.append(("", t, neg))
            i += 1
    return out


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
    preds = []
    for term, arg, neg in _parse(expr):
        if term == "~s":
            base = lambda f: bool(f.status)
        elif term == "~q":
            base = lambda f: not f.status
        elif term == "~fav":
            base = lambda f: f.favorite
        elif term == "":
            base = lambda f, rx=_rx(arg): bool(rx.search(flow_url(f)))
        else:
            base = lambda f, rx=_rx(arg), g=fields[term]: bool(rx.search(g(f) or ""))
        preds.append(lambda f, b=base, n=neg: (not b(f)) if n else b(f))
    return lambda f: all(p(f) for p in preds)


def filter_hints(expr: str) -> list[str]:
    """Diagnostics for an expression that parses but doesn't mean what it looks like.

    Every check here is for a mistake the grammar cannot catch — a token that is legal
    as a URL regex but was plainly meant as something else — so these are advisory and
    reported alongside results, not raised. Returns [] for an expression with nothing
    suspicious in it.
    """
    try:
        terms = _parse((expr or "").strip())
    except ValueError:
        return []  # a genuine parse error is reported on its own
    hints: list[str] = []
    bare = [arg for term, arg, _ in terms if term == "" and arg]

    if ops := [b for b in bare if b.lower() in _BOOLEAN_TOKENS]:
        hints.append(
            f"`{ops[0]}` is not an operator — terms are separated by spaces and ANDed "
            f"automatically, and `{ops[0]}` was applied as a regex against the URL. "
            f"Write `~d example\\.com ~c 200`, not `~d example\\.com {ops[0]} ~c 200`.")
    if parens := [b for b in bare if b.startswith("(") or b.endswith(")")]:
        hints.append(
            f"`{parens[0]}` — parentheses are not supported for grouping; the DSL is a "
            f"flat list of ANDed terms.")
    if codes := [b for b in bare if re.fullmatch(r"\d{3}", b)]:
        hints.append(
            f"a bare `{codes[0]}` matches the URL, not the status code — use "
            f"`~c {codes[0]}`. (`~s`/`~q` take no argument: they only test whether a "
            f"response is present.)")
    if quoted := [a for _, a, _ in terms
                  if a and len(a) > 1 and a[0] == a[-1] and a[0] in "'\""]:
        hints.append(
            f"{quoted[0]!r} is quoted — arguments are not quote-parsed, so the quotes "
            f"are matched literally. Write {quoted[0][1:-1]} instead.")
    return hints
