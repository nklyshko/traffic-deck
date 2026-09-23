package server

import (
	"bytes"
	"context"
	"os"
	"testing"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"github.com/nklyshko/traffic-deck/gateway/internal/store"
)

func pruneTestIngest(t *testing.T) *Ingest {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	obj, err := objstore.NewFSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return NewIngest(st, obj, "", newLiveHub(false), false, false, false)
}

// TestParseCapturePIDs covers the wire form a source reports. A partial list still
// narrows the capture, so junk entries are skipped rather than failing the whole set —
// and a list that parses to nothing must stay empty, since the pruner treats an empty
// keep set as "drop everything" and refuses it.
func TestParseCapturePIDs(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []int32
	}{
		{"1166", []int32{1166}},
		{"1166,3056", []int32{1166, 3056}},
		{" 1166 , 3056 ", []int32{1166, 3056}},
		{"1166,junk,3056", []int32{1166, 3056}},
		{"", nil},
		{"junk", nil},
		{"0,-4", nil}, // a pid is always positive; 0 and negatives are not pids
	} {
		got := sortedPIDs(parseCapturePIDs(tc.in))
		if len(got) != len(tc.want) {
			t.Errorf("parseCapturePIDs(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseCapturePIDs(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}

// TestCloseSessionMergesReportedMetadata is the contract the per-process source depends
// on: what it learned while capturing has to be on the session by the time finalization
// runs, and must not displace what it declared at open.
func TestCloseSessionMergesReportedMetadata(t *testing.T) {
	ctx := context.Background()
	ing := pruneTestIngest(t)

	handle, err := ing.OpenSession(ctx, &trafficv1.OpenSessionRequest{
		Label: "pktap", Source: "pktap", Shape: trafficv1.SourceShape_SOURCE_SHAPE_PCAP,
		Metadata: map[string]string{"viewer.columns": "pcap"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := handle.GetSessionId()

	if _, err := ing.CloseSession(ctx, &trafficv1.CloseSessionRequest{
		SessionId: sid,
		Metadata:  map[string]string{pidsCaptureKey: "1166,3056"},
	}); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}

	sess, err := ing.st.GetSession(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	md := sess.GetMetadata()
	if md[pidsCaptureKey] != "1166,3056" {
		t.Errorf("metadata[%s] = %q, want %q", pidsCaptureKey, md[pidsCaptureKey], "1166,3056")
	}
	if md["viewer.columns"] != "pcap" {
		t.Errorf("open-time metadata was lost: %v", md)
	}
}

// TestPruneToCapturePIDsLeavesOtherCapturesAlone is the guard that matters most: a
// session that is not a per-process capture must come out of finalization with its pcap
// untouched, whether it reported no pids at all or reported pids for an ordinary capture
// that has no per-packet process to prune by.
func TestPruneToCapturePIDsLeavesOtherCapturesAlone(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		md   map[string]string
	}{
		{"no pids reported", nil},
		{"pids on a non-pktap capture", map[string]string{pidsCaptureKey: "1166"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ing := pruneTestIngest(t)
			handle, err := ing.OpenSession(ctx, &trafficv1.OpenSessionRequest{
				Label: tc.name, Source: "chrome", Shape: trafficv1.SourceShape_SOURCE_SHAPE_PCAP,
			})
			if err != nil {
				t.Fatal(err)
			}
			sid := handle.GetSessionId()
			// A classic Ethernet pcap header: a real capture shape, with no per-packet
			// process anywhere in it.
			pcap := []byte{
				0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
				0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
			}
			if _, err := ing.obj.Put(pcapKey(sid), bytes.NewReader(pcap)); err != nil {
				t.Fatal(err)
			}
			if tc.md != nil {
				if err := ing.st.SetSessionMetadata(ctx, sid, tc.md); err != nil {
					t.Fatal(err)
				}
			}

			ing.pruneToCapturePIDs(ctx, sid)

			local, ok := ing.obj.LocalPath(pcapKey(sid))
			if !ok {
				t.Fatal("no local path for the capture")
			}
			after, err := os.ReadFile(local)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, pcap) {
				t.Errorf("capture was modified: %d bytes, want the original %d", len(after), len(pcap))
			}
		})
	}
}
