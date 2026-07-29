# Filter syntax

A mitmproxy-style filter language, used by the TUI's `f` prompt and by the MCP
`search_flows` tool. The language lives in the **gateway** — viewers send the expression
as typed and render what comes back, so the TUI, MCP and any third-party viewer get
identical results by construction ([ADR-0012](adr/0012-server-side-filtering-and-pagination.md)).

## Grammar

Terms are separated by **spaces** and ANDed. `!` before a term negates it. A bare regex
matches the URL.

```
~d api\.example\.com ~c 4.. !~t json
```

There are **no boolean operators**. `&`, `|`, `and`, `or` and parentheses are not part of
the grammar, and a stray one is matched as a regex against the URL rather than rejected —
so `~d example\.com & ~c 200` quietly filters on something else. Arguments are unquoted
regexes (`~d api\.example\.com`, not `~d 'api\.example\.com'` — the quotes would match
literally), and `~s`/`~q`/`~fav` take no argument, so a status code goes in `~c 200`,
never `~s 200`.

Expressions that parse but probably don't mean what they look like come back with
**advisory hints** — a stray boolean token, parentheses, a bare three-digit number, a
quoted argument — shown as warnings beside the results. The hints are part of the
language, so every client gets them.

## Terms

Taking a regex argument:

| Term | Matches |
|---|---|
| `~m <re>` | request method |
| `~d <re>` | domain (the authority alone — no scheme, no path) |
| `~u <re>` | full URL |
| `~c <re>` | response status code |
| `~t <re>` | content type |
| `~conn <re>` | transport connection id (`tcp.stream` index, or `quic:<id>`) |
| `~stream <re>` | HTTP/2/3 stream id within the connection |
| `~h <re>` | headers, either direction |
| `~hq <re>` / `~hs <re>` | request / response headers |
| `~b <re>` | body, either direction |
| `~bq <re>` / `~bs <re>` | request / response body |
| `~tag <re>` | tag name |
| `~group <re>` | group name |
| `~mark <re>` | color mark |
| `~comment <re>` | comment text |
| `~meta <key>=<re>` | source metadata (`~meta <key>` alone matches presence) |

Taking no argument: `~s` has a response · `~q` has no response · `~fav` favorited.

Headers are matched as `name: value` lines, so `~hs set-cookie` finds a `Set-Cookie` and
`~h 'x-api-key: abc'` — without the quotes — pins a value.

**`~h*` and `~b*` are new**, and only possible because filtering moved server-side: the
viewer used to hold only the bodies it had been sent, so the terms were unimplementable
there. Together they cover what MCP's separate content search used to do.

## Cost, and what it means for a big session

Terms are evaluated cheapest-first: **columns, then headers, then bodies**. A row rejected
by `~m` never reads a header, and one rejected by a header never reads a body. So put the
narrowing metadata terms in the same expression as a `~b` — `~d api\.example\.com ~c 5..
~bs BanShadow` reads bodies only for the handful of rows that already passed the rest.

A filter matching very little costs a scan. Each query is bounded by a scan cap (20,000
rows); when it is reached the reported count is a lower bound, which the TUI renders as
`N+ matching`. Navigation never depends on that number — see
[the TUI guide](tui.md#the-flow-table-is-a-window-not-a-page).

## Regexes are RE2

The gateway uses Go's RE2, so **lookarounds and backreferences are not supported** and are
refused at compile time with an error naming the construct — never accepted and silently
matching something else. Matching is case-insensitive.

This also matters for safety: MCP listens on a port, so a filter expression is remote
input to the gateway's CPU, and RE2 has no catastrophic backtracking.
