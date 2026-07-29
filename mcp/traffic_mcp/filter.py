"""The filter DSL's syntax reference, and the URL a flow is matched on.

The language itself lives in the gateway now (ADR-0012): expressions are sent as typed,
and parse errors and advisory hints come back with the page. What stays here is the
reference text handed back to a caller whose filter was rejected, and the URL helper the
structured `search` tool still uses for its own match previews.
"""

from __future__ import annotations


def flow_url(f) -> str:
    u = f"{f.scheme or 'https'}://{f.authority}{f.path}"
    if f.query:
        u += f"?{f.query}"
    return u


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

Body terms (read the stored body; slower, so put them with other terms):
  ~b <regex>     either direction    ~bq <regex>  request body
  ~bs <regex>    response body

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
