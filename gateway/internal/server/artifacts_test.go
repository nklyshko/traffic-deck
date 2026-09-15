package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"github.com/nklyshko/traffic-deck/gateway/internal/store"
)

// TestGetSessionArtifacts covers the lookup the viewer makes before handing a session's
// capture to an external analyzer (the TUI's "open in Wireshark"): an imported session
// reports on-disk paths for both its pcap and its key.log, sized as stored.
func TestGetSessionArtifacts(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obj, err := objstore.NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := NewControl(st, obj, dir, "", nil, nil)

	pcap, _ := filepath.Abs("../decode/testdata/sample.pcap")
	keylog, _ := filepath.Abs("../decode/testdata/sample.key.log")
	imp, err := c.ImportCapture(ctx, &trafficv1.ImportCaptureRequest{
		PcapPath: pcap, KeylogPath: keylog, Label: "ws", Engine: "native",
	})
	if err != nil {
		t.Fatalf("ImportCapture: %v", err)
	}
	sid := imp.GetSession().GetId()

	art, err := c.GetSessionArtifacts(ctx, &trafficv1.GetSessionArtifactsRequest{SessionId: sid})
	if err != nil {
		t.Fatalf("GetSessionArtifacts: %v", err)
	}
	for _, tc := range []struct {
		what string
		path string
		size uint64
	}{
		{"pcap", art.GetPcapPath(), art.GetPcapBytes()},
		{"key.log", art.GetKeylogPath(), art.GetKeylogBytes()},
	} {
		fi, err := os.Stat(tc.path)
		if err != nil {
			t.Fatalf("%s path %q: %v", tc.what, tc.path, err)
		}
		if uint64(fi.Size()) != tc.size {
			t.Errorf("%s bytes = %d, on disk %d", tc.what, tc.size, fi.Size())
		}
	}
	if art.GetHostname() == "" {
		t.Error("hostname empty — a remote viewer can't tell whose paths these are")
	}
}

// TestGetSessionArtifactsUnknownSession: the lookup is scoped to a real session, so an
// unknown id is NotFound rather than a reply with empty paths.
func TestGetSessionArtifactsUnknownSession(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obj, err := objstore.NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := NewControl(st, obj, dir, "", nil, nil)

	if _, err := c.GetSessionArtifacts(ctx, &trafficv1.GetSessionArtifactsRequest{
		SessionId: "nope",
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
	if _, err := c.GetSessionArtifacts(ctx, &trafficv1.GetSessionArtifactsRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty id err = %v, want InvalidArgument", err)
	}
}
