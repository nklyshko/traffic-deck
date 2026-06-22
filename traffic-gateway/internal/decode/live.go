package decode

import (
	"context"
	"io"
)

// LiveDecode runs `tshark -r -` reading a growing pcap stream from r (the gateway
// writes captured bytes to it), decrypting with the growing keylog file, and
// invokes onFlow for each created (isNew=true) or updated flow, and onMsg for each
// decoded WebSocket frame, until r reaches EOF or ctx is cancelled. This is the live
// decode path. onMsg may be nil.
//
// We use `-r -` (read a capture file from stdin), not `-i -` (live interface):
// `-i` would invoke dumpcap and require capture privileges even for a pipe, while
// `-r -` decodes a streamed pcap incrementally (with -l) and needs none.
func LiveDecode(ctx context.Context, tsharkPath, keylogPath string, r io.Reader, onFlow func(f *Flow, isNew bool), onMsg func(m *WsMessage)) error {
	ds := &Dataset{Engine: "tshark", TLSKeyLogUsed: keylogPath != ""}
	st := newStitcher(ds, onFlow)
	st.onMessage = onMsg
	return runTshark(ctx, tsharkPath, tsharkArgs([]string{"-r", "-"}, keylogPath, true), r, st)
}
