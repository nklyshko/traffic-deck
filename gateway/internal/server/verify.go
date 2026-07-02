package server

import (
	"context"
	"fmt"
	"log"
	"sort"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// verifyRecordedLive batch-decodes the session's pcap (without persisting the result)
// and compares the just-recorded live flows against it, logging any differences — the
// verification pass for record-live mode, where the authoritative batch decode on close
// is otherwise skipped. Failures are logged rather than returned: the session is already
// persisted and closed, and a broken verification must not fail the close.
func (i *Ingest) verifyRecordedLive(ctx context.Context, sid string, ls *liveSession, keylogPath string) {
	pcapLocal, ok := i.obj.LocalPath(pcapKey(sid))
	if !ok {
		log.Printf("verify %s: pcap not available locally; skipping batch verification", sid)
		return
	}
	ds, err := decode.Decode(ctx, i.tshark, pcapLocal, keylogPath)
	if err != nil {
		log.Printf("verify %s: batch decode failed: %v", sid, err)
		return
	}
	batch := make([]*trafficv1.Flow, 0, len(ds.Flows))
	for _, f := range ds.Flows {
		batch = append(batch, flowToProto(f))
	}
	verifyLiveVsBatch(sid, ls.protoFlows(), batch)
}

// verifyLiveVsBatch compares the live-decoded flows against the authoritative batch
// (tshark) decode and logs any differences, so a live-decoder gap (a missed or extra
// flow) is surfaced rather than silent. Flows are matched by a natural key
// (protocol/method/authority/path) counted per side — live and batch assign independent
// ids, so exact id matching isn't possible. Returns the human-readable difference lines
// (empty when they match).
func verifyLiveVsBatch(sessionID string, live, batch []*trafficv1.Flow) []string {
	liveCounts := countByFlowKey(live)
	batchCounts := countByFlowKey(batch)

	seen := map[string]bool{}
	var diffs []string
	for k, bc := range batchCounts {
		seen[k] = true
		if lc := liveCounts[k]; lc != bc {
			diffs = append(diffs, fmt.Sprintf("%s: live=%d batch=%d", k, lc, bc))
		}
	}
	for k, lc := range liveCounts {
		if !seen[k] {
			diffs = append(diffs, fmt.Sprintf("%s: live=%d batch=0 (live-only)", k, lc))
		}
	}
	sort.Strings(diffs)

	if len(diffs) == 0 {
		log.Printf("verify %s: live decode matches batch (%d flows)", sessionID, len(batch))
		return nil
	}
	log.Printf("verify %s: live decode differs from batch (live=%d, batch=%d flows); %d key(s) differ:",
		sessionID, len(live), len(batch), len(diffs))
	for _, d := range diffs {
		log.Printf("verify %s:   %s", sessionID, d)
	}
	return diffs
}

// countByFlowKey tallies flows by a stable natural key. WebSocket/custom flows key on
// protocol+authority (they have no method/path), so a per-endpoint count comparison still
// catches missing connections.
func countByFlowKey(flows []*trafficv1.Flow) map[string]int {
	out := map[string]int{}
	for _, f := range flows {
		key := f.GetProtocol() + " " + f.GetMethod() + " " + f.GetAuthority() + f.GetPath()
		out[key]++
	}
	return out
}
