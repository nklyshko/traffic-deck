"""The filter DSL's on-screen cheat sheet.

The language itself lives in the gateway now (ADR-0012): expressions are sent as typed,
and parse errors and advisory hints come back with the page. Only the help text stays
here, because it is UI chrome rather than part of the language.
"""

from __future__ import annotations

FILTER_HELP = (
    "Filter terms are space-separated and ANDed; prefix ! to negate a term.\n"
    "  No & | and or ( ) — a stray one is matched as a regex against the URL.\n"
    "  ~m <re> method     ~d <re> domain      ~u <re> url        ~c <re> status\n"
    "  ~t <re> type       ~mark <re> color    ~tag <re> name     ~group <re> name\n"
    "  ~comment <re>      ~s has response     ~q no response     ~fav favorited\n"
    "  ~conn <re> conn    ~stream <re> h2 stream id\n"
    "  ~h <re> headers    ~hq <re> request hdrs   ~hs <re> response hdrs\n"
    "  ~b <re> body       ~bq <re> request body   ~bs <re> response body\n"
    "  ~meta <key>=<re>   (source metadata; ~meta <key> alone matches presence)\n"
    "  <re>  a bare regex matches the URL — a lone 200 is a URL match, not ~c 200\n"
    "  args are unquoted RE2 regexes: escape dots, quotes match literally,\n"
    "  no lookarounds or backreferences · headers match as \"name: value\" lines\n"
    "                                               Enter apply · Esc cancel"
)

# The message timeline's own dialect. A frame has a payload, an opcode and a direction and
# no URL, so the term set is different — and a flow term (~m, ~c, ~h) is refused by name
# rather than quietly matched against the payload.
MSG_FILTER_HELP = (
    "Message terms are space-separated and ANDed; prefix ! to negate a term.\n"
    "  ~b <re> payload    ~op <re> opcode     ~from <re> client|server\n"
    "  ~mark <re> color   ~tag <re> name      ~group <re> name\n"
    "  ~comment <re>      ~fav favorited\n"
    "  <re>  a bare regex matches the payload — there is no URL on a frame\n"
    "  args are unquoted RE2 regexes: escape dots, quotes match literally\n"
    "  flow terms (~m ~c ~d ~h …) are not message terms and are rejected\n"
    "                                               Enter apply · Esc cancel"
)
