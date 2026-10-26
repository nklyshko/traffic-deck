package decode

// Transport encoding of a body — what the bytes looked like on the wire, and undoing it
// where we can. Every decode path funnels through here so that a body means the same
// thing whichever protocol carried it: the bytes a flow holds are plain, and the encoding
// they arrived in is recorded alongside them.
//
// The encoding is recorded from the message's content-encoding header, but it describes
// the *bytes*, not the header: a header naming an encoding the body was not actually sent
// in leaves the bytes as they came (decoding is a no-op), and an encoding we cannot undo
// leaves them compressed with the field saying so. Consumers trust the field.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

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

// attempt is one way to undo an encoding: how to open a reader over the bytes, and how
// much proof we need that the bytes really were in that format.
//
// strict is the whole point. gzip, zlib and zstd carry a magic number, so opening one over
// foreign bytes fails and the originals survive untouched. Brotli and raw deflate carry no
// header at all: raw deflate will happily "decode" a JSON body into five bytes of noise,
// which is worse than leaving it compressed — a search that misses is recoverable, a body
// silently replaced by garbage is not. So those two are kept only on a clean decode.
type attempt struct {
	open   func(io.Reader) (io.ReadCloser, error)
	strict bool
}

// attemptsFor returns how to undo enc, in order, or nil for an encoding we leave alone (a
// chain, or something new). Content-Encoding: deflate is ambiguous on the wire — RFC 9110
// says zlib-wrapped and some servers send raw — so it is two attempts: the checkable one
// first, then the headerless fallback that has to prove itself.
func attemptsFor(enc string) []attempt {
	switch enc {
	case "gzip":
		return []attempt{{open: func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) }}}
	case "br":
		return []attempt{{strict: true, open: func(r io.Reader) (io.ReadCloser, error) {
			return io.NopCloser(brotli.NewReader(r)), nil
		}}}
	case "zstd":
		return []attempt{{open: func(r io.Reader) (io.ReadCloser, error) {
			d, err := zstd.NewReader(r)
			if err != nil {
				return nil, err
			}
			return d.IOReadCloser(), nil
		}}}
	case "deflate":
		return []attempt{
			{open: func(r io.Reader) (io.ReadCloser, error) { return zlib.NewReader(r) }},
			{strict: true, open: func(r io.Reader) (io.ReadCloser, error) {
				return flate.NewReader(r), nil
			}},
		}
	}
	return nil
}

// decoderFor is attemptsFor for a caller that can only read forward once — the live
// HTTP/1.1 path, decoding a response as it arrives. There is no retrying a stream, so it
// takes the first attempt and trusts the label; that path reads the wire bytes itself, so
// the label does describe what it is holding.
func decoderFor(enc string) func(io.Reader) (io.ReadCloser, error) {
	if as := attemptsFor(enc); len(as) > 0 {
		return as[0].open
	}
	return nil
}

// decodeBody undoes enc, returning the plain bytes. Anything we can't undo comes back untouched — the caller
// still records the encoding, so a consumer is told what these bytes are rather than
// handed compressed bytes labelled plain.
//
// A body cut short (a capture that ended mid-response) decompresses to
// as much as it has rather than to nothing, which is why a truncated read with output still
// counts as a success.
func decodeBody(enc string, b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	for _, a := range attemptsFor(enc) {
		zr, err := a.open(bytes.NewReader(b))
		if err != nil {
			continue // its header says these are not those bytes
		}
		out, rerr := io.ReadAll(zr)
		_ = zr.Close()
		if len(out) == 0 {
			continue
		}
		// A headerless format has to decode cleanly, or to the end of what it was given;
		// anything else means we were almost certainly not looking at that format at all.
		if a.strict && rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) {
			continue
		}
		return out
	}
	return b
}
