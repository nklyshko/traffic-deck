# TLS client fingerprint names

Every decrypted ClientHello already yields a **JA3** and **JA4**. On top of that the
gateway names the client — `Chrome 150`, `OkHttp (Android)`, `Firefox`, … — shown as
**Client:** in a flow's *TLS ClientHello* detail block. Names come from a registry of
well-known fingerprints: a **compiled-in builtin set**
([`gateway/internal/tlsfp/builtin.json`](../gateway/internal/tlsfp/builtin.json), embedded)
plus any files you drop in — no rebuild.

Classification is a pure function of the fingerprint, run **at serve time**, so editing the
registry re-labels flows you already captured — no re-decode.

## Register your own

Like [`plugins/`](modules.md), it's just a drop-in dir: put `*.json` in
`~/.traffic-deck/fingerprints/` (override with `TRAFFICDECK_FP_DIR`). Same schema as the
builtin; **later files win ties**, so a row can add a new name or override a builtin one:

```json
{"fingerprints": [
  {"name": "AcmeApp", "version": "3", "ja4": "t13d1516h2_8daaf6152771_806a8c22fdea"},
  {"name": "Internal tool", "ja4_pre": "t13d1715h2_5b57614c22b0", "sni": "api.acme.internal"}
]}
```

Match keys, most specific wins: **`ja4`** (exact) › **`ja4_pre`** (a JA4 prefix — the
`a_b` sections, i.e. client + version era, robust while only the trailing extension hash
changes across minor versions) › **`ja4_b`** (just the cipher-list hash = a whole client
family) › **`ja3`** (legacy, exact). An optional **`sni`** further constrains any row.
Malformed rows are skipped and logged, never fatal; the dir is hot-reloaded, so a new file
takes effect on the next flow without a restart.

> **On versions:** JA4 is deliberately stable across browser releases — one JA4 spans many
> versions (Chrome 120–131 all share `…_02713d6af862`), and FoxIO's ja4db doesn't version
> Chrome at all. So builtin rows carry a version *range*, and the `ja4_b` family rows
> recognize **any** version — including ones with no exact row, like Chrome 139/144. To pin
> a version you care about, capture it once and add its exact `ja4` as a user row. The seed
> set is real (computed by this repo's parser over uTLS ClientHellos + FoxIO ja4db + local
> captures); grow it from <https://ja4db.com>.

> **A cipher list no longer names an engine:** Firefox 155 presents Chromium's TLS-1.3
> cipher list (`8daaf6152771`) and Chromium's QUIC one (`55b375c5d22e`), and it shares the
> whole `a_b` prefix with Chrome 150 — only the trailing extension hash differs. So those
> two `ja4_b` rows are named `Chrome/Chromium or Firefox`, because that is all a
> cipher-list match can honestly say, and telling the two engines apart needs an exact
> `ja4` row — a `ja4_pre` cannot do it. Worth remembering when you add rows of your own:
> a `ja4_b` row claims every client that shares a cipher list, which may be more than the
> one you captured.
