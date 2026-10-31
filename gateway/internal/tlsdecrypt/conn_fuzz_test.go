package tlsdecrypt

import "testing"

// FuzzConnFeed drives the TLS record layer with arbitrary bytes in both directions, with no
// key-log secrets: record framing, handshake parsing (ClientHello/ServerHello, HRR) and the
// version/suite checks. It must never panic.
func FuzzConnFeed(f *testing.F) {
	// A truncated ClientHello record and a ServerHello-shaped record.
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03}, []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00})
	f.Add([]byte{0x17, 0x03, 0x03, 0xff, 0xff}, []byte{})
	f.Fuzz(func(_ *testing.T, client, server []byte) {
		c := NewConn(NewKeylog(""), func(bool, []byte) {})
		c.Feed(true, client)
		c.Feed(false, server)
		c.Feed(true, client)
		_ = c.ClientHello()
	})
}
