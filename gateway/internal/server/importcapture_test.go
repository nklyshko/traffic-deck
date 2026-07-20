package server

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// TestImportCaptureNative covers the viewer-driven pcap import (the TUI's "Import pcap")
// end to end through the ControlService: a stored pcapng is decoded with the native engine
// (no tshark) and registered as a closed session with flows.
func TestImportCaptureNative(t *testing.T) {
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
	resp, err := c.ImportCapture(ctx, &trafficv1.ImportCaptureRequest{
		PcapPath: pcap, KeylogPath: keylog, Label: "imp", Engine: "native",
	})
	if err != nil {
		t.Fatalf("ImportCapture: %v", err)
	}
	sess := resp.GetSession()
	if sess.GetLabel() != "imp" {
		t.Errorf("label = %q, want %q", sess.GetLabel(), "imp")
	}
	if sess.GetStatus() != trafficv1.SessionStatus_SESSION_STATUS_CLOSED {
		t.Errorf("status = %v, want CLOSED", sess.GetStatus())
	}
	if sess.GetFlowCount() == 0 {
		t.Error("no flows imported from the pcapng sample")
	}
}

// TestImportCaptureRequiresPcapPath checks the empty-path guard returns InvalidArgument
// (and never dereferences the store/objstore).
func TestImportCaptureRequiresPcapPath(t *testing.T) {
	c := NewControl(nil, nil, t.TempDir(), "", nil, nil)
	_, err := c.ImportCapture(context.Background(), &trafficv1.ImportCaptureRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
}
