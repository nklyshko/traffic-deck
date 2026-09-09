package decode

// Transport encoding of a body — what the bytes looked like on the wire, and undoing it
// where we can. Every decode path funnels through here so that a body means the same
// thing whichever protocol carried it: the bytes a flow holds are plain, and the encoding
// they arrived in is recorded alongside them.
//
// The encoding is recorded from the message's content-encoding header, but it describes
// the *bytes*, not the header: a header naming an encoding the body was not actually sent
// in leaves the bytes as they came (decoding is a no-op), and an encoding we cannot undo
// (brotli) leaves them compressed with the field saying so. Consumers trust the field.

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
)

// noBodyLimit tells maybeGunzip not to cap its output — the batch paths keep whole
// bodies, unlike the live ones, which decode into a capped preview.
const noBodyLimit = -1

// bodyEncoding returns the transport encoding a message's headers name, lower-cased
// ("" = none). "identity" is spelled-out absence, so it folds to none.
func bodyEncoding(headers []Header) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "content-encoding") {
			return normalizeEncoding(h.Value)
		}
	}
	return ""
}

// normalizeEncoding canonicalizes a content-encoding header value. A chain
// ("gzip, br") is kept verbatim — we don't unwrap chains, so it stays as a truthful
// label for what the bytes are.
func normalizeEncoding(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "identity" {
		return ""
	}
	return v
}

// decodeBody undoes enc, returning the plain bytes; limit caps the output
// (noBodyLimit = uncapped). Anything we can't undo comes back untouched — the caller
// still records the encoding, so a consumer is told what these bytes are rather than
// handed compressed bytes labelled plain. That is deflate (stdlib-decodable, but
// ambiguous on the wire: raw vs zlib-wrapped) and brotli (a new dependency).
func decodeBody(enc string, b []byte, limit int64) []byte {
	if enc == "gzip" {
		return maybeGunzip(b, limit)
	}
	return b
}

// maybeGunzip returns raw decompressed, or raw itself when it isn't gzip after all.
// A body cut short (a live preview cap, a capture that ended mid-response) decompresses
// to as much as it has rather than to nothing.
func maybeGunzip(raw []byte, limit int64) []byte {
	if len(raw) == 0 {
		return raw
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return raw // not gzip, or a header cut short — leave the raw bytes
	}
	defer zr.Close()
	var r io.Reader = zr
	if limit >= 0 {
		r = io.LimitReader(zr, limit)
	}
	out, err := io.ReadAll(r)
	if err != nil && len(out) == 0 {
		return raw
	}
	return out
}
