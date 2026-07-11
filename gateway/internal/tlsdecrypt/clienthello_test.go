package tlsdecrypt

import (
	"crypto/md5"
	"encoding/hex"
	"reflect"
	"testing"
)

// TLS vector builders.
func u16b(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func vec16(b []byte) []byte {
	return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)
}
func vec8(b []byte) []byte { return append([]byte{byte(len(b))}, b...) }
func tlsExt(typ uint16, body []byte) []byte {
	return append(append(u16b(typ), u16b(uint16(len(body)))...), body...)
}

func TestParseClientHelloJA3JA4(t *testing.T) {
	sni := tlsExt(0, vec16(append([]byte{0}, vec16([]byte("example.com"))...)))
	// supported_versions: TLS 1.3 + a GREASE value (must be dropped).
	supVers := tlsExt(43, vec8(append(u16b(0x0304), u16b(0x0a0a)...)))
	groups := tlsExt(10, vec16(append(u16b(0x001d), u16b(0x0017)...)))
	alpn := tlsExt(16, vec16(append(vec8([]byte("h2")), vec8([]byte("http/1.1"))...)))
	sigAlgs := tlsExt(13, vec16(append(u16b(0x0403), u16b(0x0804)...)))
	pointFmts := tlsExt(11, vec8([]byte{0x00}))
	exts := vec16(concat(sni, supVers, groups, alpn, sigAlgs, pointFmts))

	ciphers := vec16(concat(u16b(0x1301), u16b(0x1302), u16b(0x0a0a))) // last is GREASE
	body := concat(
		u16b(0x0303),       // legacy_version TLS 1.2
		make([]byte, 32),   // random
		vec8(nil),          // session_id
		ciphers,            // cipher_suites
		vec8([]byte{0x00}), // compression_methods
		exts,               // extensions
	)

	ci := parseClientHelloInfo(body)
	if ci == nil {
		t.Fatal("parse returned nil")
	}
	if ci.SNI != "example.com" {
		t.Errorf("SNI = %q", ci.SNI)
	}
	if ci.Version != 0x0304 || ci.LegacyVersion != 0x0303 {
		t.Errorf("version = %#04x legacy = %#04x", ci.Version, ci.LegacyVersion)
	}
	if !reflect.DeepEqual(ci.Ciphers, []uint16{0x1301, 0x1302, 0x0a0a}) {
		t.Errorf("ciphers = %v", ci.Ciphers)
	}
	if !reflect.DeepEqual(ci.Extensions, []uint16{0, 43, 10, 16, 13, 11}) {
		t.Errorf("extensions = %v", ci.Extensions)
	}
	if !reflect.DeepEqual(ci.Curves, []uint16{29, 23}) {
		t.Errorf("curves = %v", ci.Curves)
	}
	if !reflect.DeepEqual(ci.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("alpn = %v", ci.ALPN)
	}

	// JA3 over the GREASE-stripped lists.
	wantJA3Text := "771,4865-4866,0-43-10-16-13-11,29-23,0"
	if ci.JA3Text != wantJA3Text {
		t.Errorf("JA3 text = %q, want %q", ci.JA3Text, wantJA3Text)
	}
	sum := md5.Sum([]byte(wantJA3Text))
	if ci.JA3 != hex.EncodeToString(sum[:]) {
		t.Errorf("JA3 = %q", ci.JA3)
	}

	// JA4: t=TCP, 13=TLS1.3, d=SNI present, 02 ciphers, 06 extensions, h2=first ALPN;
	// then sorted-cipher hash and (sorted-ext-minus-SNI/ALPN + sig-algs) hash.
	wantJA4 := "t13d0206h2_" + sha12("1301,1302") + "_" + sha12("000a,000b,000d,002b_0403,0804")
	if ci.JA4 != wantJA4 {
		t.Errorf("JA4 = %q, want %q", ci.JA4, wantJA4)
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xdada, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%#04x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0000, 0x002b, 0x0a0b, 0x0b0a} {
		if isGREASE(v) {
			t.Errorf("%#04x should not be GREASE", v)
		}
	}
}

func concat(bs ...[]byte) []byte {
	var out []byte
	for _, b := range bs {
		out = append(out, b...)
	}
	return out
}
