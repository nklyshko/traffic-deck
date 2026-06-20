package decode

import (
	"context"
	"io"
)

// LiveDecode runs `tshark -r -` reading a growing pcap stream from r (the gateway
// writes captured bytes to it), decrypting with the growing keylog file, and
// invokes onFlow for each created (isNew=true) or updated flow until r reaches EOF
// or ctx is cancelled. This is the live decode path (plan §8.2).
//
// We use `-r -` (read a capture file from stdin), not `-i -` (live interface):
// `-i` would invoke dumpcap and require capture privileges even for a pipe, while
// `-r -` decodes a streamed pcap incrementally (with -l) and needs none.
func LiveDecode(ctx context.Context, tsharkPath, keylogPath string, r io.Reader, onFlow func(f *Flow, isNew bool)) error {
	ds := &Dataset{Engine: "tshark", TLSKeyLogUsed: keylogPath != ""}
	st := newStitcher(ds, onFlow)
	return runTshark(ctx, tsharkPath, tsharkArgs([]string{"-r", "-"}, keylogPath, true), r, st)
}
