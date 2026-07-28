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
    # Connection identity: ~conn is the transport connection (a tcp.stream index, or
    # "quic:<conn-id>"), ~stream the HTTP/2/3 stream within it. Together they show how
    # multiplexed requests share one connection. Both are regex-matched like every other
    # term, so anchor to pin an exact id: `~conn '^12$'`.
    "~conn": lambda f: f.tcp_stream,
    "~stream": lambda f: f.h2_stream_id,
}


# Terms taking a regex argument, and the flag terms taking none. Names only — the getters
# live in `_FILTER_FIELDS`/`compile_filter` — so `_parse` stays independent of them.
_ARG_TERMS = (*_FILTER_FIELDS, "~mark", "~tag", "~group", "~comment", "~meta")
_FLAG_TERMS = ("~s", "~q", "~fav")


# Cheat sheet for the filter DSL, shown in the TUI while the filter input is focused.
# Kept next to the operators above so it stays in sync as they change. The "no operators"
# line leads because the DSL accepts `&`/`|` as a plain URL regex rather than rejecting
# them, so writing `~d a & ~c 200` silently filters on something else entirely.
FILTER_HELP = (
    "Filter terms are space-separated and ANDed; prefix ! to negate a term.\n"
    "  No & | and or ( ) — a stray one is matched as a regex against the URL.\n"
    "  ~m <re> method     ~d <re> domain      ~u <re> url        ~c <re> status\n"
    "  ~t <re> type       ~mark <re> color    ~tag <re> name     ~group <re> name\n"
    "  ~comment <re>      ~s has response     ~q no response     ~fav favorited\n"
    "  ~conn <re> conn    ~stream <re> h2 stream id\n"
    "  ~meta <key>=<re>   (source metadata; ~meta <key> alone matches presence)\n"
    "  <re>  a bare regex matches the URL — a lone 200 is a URL match, not ~c 200\n"
    "  args are unquoted regexes: escape dots, quotes match literally\n"
    "                                               Enter apply · Esc cancel"
)

_BOOLEAN_TOKENS = {"&", "&&", "|", "||", "and", "or"}


def _comment_text(f) -> str:
    return " ".join(c.body for c in f.comments)


def _parse(expr: str) -> list[tuple[str, str | None, bool]]:
    """Tokenize into (term, argument, negated) triples; term is "" for a naked URL regex
    and argument None for a flag term. Shared by `compile_filter` and `filter_hints` so
    the hints always describe the same parse the predicate was built from.

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
                raise ValueError("~meta needs a key=regex (or key) argument"
                                 if t == "~meta" else f"{t} needs an argument")
            out.append((t, toks[i], neg))
            i += 1
        else:
            out.append(("", t, neg))
            i += 1
    return out


def filter_hints(expr: str) -> list[str]:
    """Diagnostics for an expression that parses but doesn't mean what it looks like.

    Every check is for a mistake the grammar cannot catch — a token that is legal as a
    URL regex but was plainly meant as something else — so these are advisory (the TUI
    shows them as a warning next to the results) rather than errors. Returns [] when
    there is nothing suspicious.
    """
    try:
        terms = _parse((expr or "").strip())
    except ValueError:
        return []  # a genuine parse error is reported on its own
    hints: list[str] = []
    bare = [arg for term, arg, _ in terms if term == "" and arg]

    if ops := [b for b in bare if b.lower() in _BOOLEAN_TOKENS]:
        hints.append(f"`{ops[0]}` is not an operator — terms are ANDed automatically, so "
                     f"it was matched as a regex against the URL. Just drop it.")
    if parens := [b for b in bare if b.startswith("(") or b.endswith(")")]:
        hints.append(f"`{parens[0]}` — parentheses are not supported for grouping; the "
                     f"filter is a flat list of ANDed terms.")
    if codes := [b for b in bare if re.fullmatch(r"\d{3}", b)]:
        hints.append(f"a bare `{codes[0]}` matches the URL, not the status — use "
                     f"`~c {codes[0]}`. (~s/~q take no argument.)")
    if quoted := [a for _, a, _ in terms
                  if a and len(a) > 1 and a[0] == a[-1] and a[0] in "'\""]:
        hints.append(f"{quoted[0]!r} is quoted — arguments are not quote-parsed, so the "
                     f"quotes match literally. Write {quoted[0][1:-1]} instead.")
    return hints


def compile_filter(expr: str, tagnames: dict | None = None, groupnames: dict | None = None):
    """Compile a filter expression to a predicate(flow)->bool, or None if empty.

    Terms (space-separated, ANDed): `~m/~d/~u/~c/~t <regex>`, `~s`/`~q` (has/no
    response), `~fav` (favorited), annotation fields `~mark/~tag/~group/~comment
    <regex>`, connection identity `~conn/~stream <regex>`, `~meta <key>=<regex>` (a
    source metadata value; `~meta <key>` alone matches presence), a naked regex
    (matches the URL), and a leading `!` negates a term. Raises ValueError on a bad
    regex. (Full `& | ()` grammar is future.)
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
    preds = []
    for term, arg, neg in _parse(expr):
        if term == "~s":
            base = lambda f: bool(f.status)
        elif term == "~q":
            base = lambda f: not f.status
        elif term == "~fav":
            base = lambda f: f.favorite
        elif term == "~meta":
            key, _, pat = arg.partition("=")
            if pat:
                base = lambda f, rx=_rx(pat), k=key: bool(rx.search(f.metadata.get(k, "")))
            else:  # `~meta key` (no =) matches flows that have the key at all
                base = lambda f, k=key: k in f.metadata
        elif term == "":
            base = lambda f, rx=_rx(arg): bool(rx.search(url(f)))
        else:
            base = lambda f, rx=_rx(arg), g=fields[term]: bool(rx.search(g(f) or ""))
        preds.append(lambda f, b=base, n=neg: (not b(f)) if n else b(f))
    return lambda f: all(p(f) for p in preds)
