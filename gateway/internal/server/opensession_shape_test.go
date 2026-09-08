package server

import (
	"context"
	"testing"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// A pushed source has no UploadBegin to bring its live session into being, so OpenSession
// registers one up front. Without that, a viewer following between OpenSession and the
// first PushFlows finds nothing — the window these tests pin down.
//
// The trigger is the session's *shape*, not which tool it is: any source that pushes
// flows (mitmproxy, a third-party module — which a closed enum could never name) gets the
// same treatment.
func TestOpenSessionRegistersLiveSessionForPushedShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		shape trafficv1.SourceShape
		want  bool
	}{
		{"flows source is live at once", trafficv1.SourceShape_SOURCE_SHAPE_FLOWS, true},
		{"module pushing flows, same as mitmproxy", trafficv1.SourceShape_SOURCE_SHAPE_FLOWS, true},
		// A pcap source's live session is started by its first upload instead, so there is
		// nothing to register yet.
		{"pcap source waits for its upload", trafficv1.SourceShape_SOURCE_SHAPE_PCAP, false},
		{"unset shape registers nothing", trafficv1.SourceShape_SOURCE_SHAPE_UNSPECIFIED, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, err := store.Open(ctx, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(st.Close)
			hub := newLiveHub(false)
			ing := &Ingest{st: st, hub: hub}

			handle, err := ing.OpenSession(ctx, &trafficv1.OpenSessionRequest{
				Label: "s", Source: "acme-module", Shape: tc.shape,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := hub.get(handle.GetSessionId()) != nil; got != tc.want {
				t.Errorf("live session registered = %v, want %v", got, tc.want)
			}
		})
	}
}

// The producing tool's name round-trips to the viewer verbatim, including a name no
// build knows in advance (a third-party module's).
func TestOpenSessionRecordsSourceName(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	ing := &Ingest{st: st, hub: newLiveHub(false)}

	handle, err := ing.OpenSession(ctx, &trafficv1.OpenSessionRequest{
		Label: "s", Source: "acme-module", Shape: trafficv1.SourceShape_SOURCE_SHAPE_FLOWS,
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := st.GetSession(ctx, handle.GetSessionId())
	if err != nil {
		t.Fatal(err)
	}
	if sess.GetSource() != "acme-module" {
		t.Errorf("source = %q, want acme-module", sess.GetSource())
	}
}
