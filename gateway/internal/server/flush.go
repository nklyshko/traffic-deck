package server

// Incremental persistence for a record-live session (ADR-0011). Flows and WebSocket
// frames are written to the session bundle *during* capture and released from memory,
// rather than accumulating in the hub until CloseSession writes them in one transaction.
//
// Every viewer read path already tries the store first and falls back to the hub, so
// moving a flow's bytes to disk is invisible to readers: a body whose ref is still NULL
// (or a frame not yet written) is found in the hub, and everything else in the bundle.

import (
	"context"
	"log"
	"time"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
	"github.com/nklyshko/traffic-deck/gateway/internal/store"
)

const (
	// flushMaxDirty and flushInterval bound the unflushed window; whichever comes first
	// triggers a flush. Deliberately small: the memory ceiling is what this buys, not
	// write throughput (ADR-0011 §1).
	flushMaxDirty = 128
	flushInterval = 2 * time.Second
)

// flushSink is what the flusher writes through. An interface (rather than *store.Store)
// so the flush loop can be exercised without a bundle on disk, and so a failing write is
// easy to inject in tests.
type flushSink interface {
	InsertFlowWrites(ctx context.Context, sessionID, analysisID string, writes []store.FlowWrite) (int, error)
	InsertWsMessages(ctx context.Context, sessionID string, msgs []*decode.WsMessage) (int, error)
}

// storedBody remembers where a flow's released bodies went, so a later re-flush of that
// flow quotes the refs back instead of nulling them (store.BodiesStored).
type storedBody struct{ req, resp string }

// startFlusher runs the flush loop until stopFlusher. A session without a sink (the
// pushed path, or record-live off) keeps everything until close, as before.
func (ls *liveSession) startFlusher() {
	if ls.sink == nil {
		return
	}
	go func() {
		defer close(ls.flushDone)
		t := time.NewTicker(flushInterval)
		defer t.Stop()
		for {
			select {
			case <-ls.stopFlush:
				return
			case <-ls.wake: // dirty set crossed flushMaxDirty
			case <-t.C:
			}
			if err := ls.flush(context.Background(), false); err != nil {
				ls.failFlush(err)
				return
			}
		}
	}()
}

// stopFlusher ends the flush loop and waits for it, so a caller can run the final flush
// without racing the loop. Safe to call on a session that never had one.
func (ls *liveSession) stopFlusher() {
	if ls.sink == nil {
		return
	}
	close(ls.stopFlush)
	<-ls.flushDone
}

// markDirtyLocked records that a flow changed and nudges the flusher once enough have.
// Caller holds mu. The nudge is best-effort: a full channel already means a wake-up is
// pending, and the ticker is the backstop either way.
func (ls *liveSession) markDirtyLocked(id string) {
	if ls.sink == nil {
		return
	}
	ls.dirty[id] = struct{}{}
	if len(ls.dirty) >= flushMaxDirty {
		select {
		case ls.wake <- struct{}{}:
		default:
		}
	}
}

// bodiesSettled reports whether a flow's bodies are final and can be written and
// released. A response (or a failure) means nothing more is arriving; a WebSocket flow is
// excluded because an upgraded connection goes on producing frames (ADR-0011 §3).
func bodiesSettled(f *decode.Flow) bool {
	if f.Websocket {
		return false
	}
	return f.Status != 0 || f.Error != ""
}

// flush writes one batch: flows changed since the last flush (rows only — their bodies
// may still be arriving), flows that have since settled (bodies too, then released), and
// every WebSocket frame decoded since the last flush. When final is set — the flush at
// close — every retained flow is written with its bodies regardless of settling.
//
// The store write happens with mu released: the decoder publishes through that same
// mutex, so holding it across SQLite I/O would stall decode behind disk.
func (ls *liveSession) flush(ctx context.Context, final bool) error {
	ls.mu.Lock()
	if ls.flushErr != nil {
		err := ls.flushErr
		ls.mu.Unlock()
		return err
	}

	// Take the dirty set out rather than clearing it after the write: a flow the decoder
	// touches while we are writing then lands in the fresh map and is picked up next
	// cycle, instead of having its dirty mark cleared for an update we never wrote.
	flushing := ls.dirty
	ls.dirty = make(map[string]struct{}, len(flushing))

	writes := make([]store.FlowWrite, 0, len(flushing)+len(ls.pending))
	// Changed since the last flush: write the row now and hold the body back until it is
	// final, so a growing body is never content-addressed as a prefix (ADR-0011 §3b).
	for id := range flushing {
		df := ls.dflows[id]
		if df == nil {
			continue
		}
		w := store.FlowWrite{Flow: df, Bodies: store.BodiesPending}
		switch sb, done := ls.stored[id]; {
		case done:
			w.Bodies, w.ReqRef, w.RespRef = store.BodiesStored, sb.req, sb.resp
		case final:
			w.Bodies = store.BodiesFinal
		}
		writes = append(writes, w)
	}
	// Written in an earlier cycle and untouched since: their bodies are final now.
	for id := range ls.pending {
		if _, stillDirty := flushing[id]; stillDirty {
			continue // changed again; it gets another quiet cycle first
		}
		df := ls.dflows[id]
		if df == nil {
			continue
		}
		if !final && !bodiesSettled(df) {
			continue
		}
		writes = append(writes, store.FlowWrite{Flow: df, Bodies: store.BodiesFinal})
	}

	// Frames are immutable once decoded and the slice is append-only, so the batch is
	// simply everything seen so far; it is trimmed after the write succeeds.
	nmsgs := len(ls.messages)
	var msgs []*decode.WsMessage
	if nmsgs > 0 {
		msgs = make([]*decode.WsMessage, 0, nmsgs)
		for _, pm := range ls.messages[:nmsgs] {
			msgs = append(msgs, protoToDecodeWsMessage(pm))
		}
	}
	sessionID, analysisID, sink := ls.sessionID, ls.analysisID, ls.sink
	ls.mu.Unlock()

	if len(writes) == 0 && nmsgs == 0 {
		return nil
	}
	if len(writes) > 0 {
		if _, err := sink.InsertFlowWrites(ctx, sessionID, analysisID, writes); err != nil {
			return err
		}
	}
	if nmsgs > 0 {
		if _, err := sink.InsertWsMessages(ctx, sessionID, msgs); err != nil {
			return err
		}
	}

	ls.mu.Lock()
	defer ls.mu.Unlock()
	// Whatever went in with its bodies is now on disk: remember the refs, so a re-flush
	// quotes them rather than writing NULL over a body already written, and drop the
	// bytes from memory.
	for i := range writes {
		w := &writes[i]
		if w.Bodies != store.BodiesFinal {
			continue
		}
		id := w.Flow.ID
		if _, touched := ls.dirty[id]; touched {
			// The decoder changed this flow while the write was in flight, so what went
			// to disk may already be stale. Leave it owed: the next cycle rewrites it,
			// and until then the bytes stay in memory rather than being dropped for a
			// body that might have grown.
			continue
		}
		ls.stored[id] = storedBody{req: w.ReqRef, resp: w.RespRef}
		delete(ls.pending, id)
		ls.releaseBodiesLocked(id)
	}
	// The rest were written without their bodies, so they are owed a later cycle.
	for id := range flushing {
		if _, done := ls.stored[id]; !done {
			ls.pending[id] = struct{}{}
		}
	}
	ls.messages = ls.messages[nmsgs:] // frames are on disk; reads find them there
	return nil
}

// copyFlow snapshots a decode.Flow at the moment the decoder hands it over. The decoder
// mutates one Flow in place across callbacks while holding no lock of ours, so onFlow is
// the only point at which reading it is safe; everything that reads a retained flow later
// — the flusher, a body served from the hub — must read a copy taken here.
//
// Shallow is enough. It captures every scalar and slice header atomically, and the
// decoder only ever *appends* to those slices: existing elements are never rewritten, and
// a reallocation leaves this copy pointing at the old array. So the bytes this snapshot
// can see never change underneath it.
func copyFlow(f *decode.Flow) *decode.Flow {
	cp := *f
	return &cp
}

// releaseBodiesLocked drops a flow's body bytes now that they are in the bundle, and
// clears the inline copy from the published proto. Size and content-type stay set: the
// viewers gate the view/save affordance on size and fetch the bytes over GetBody, so a
// zeroed size would read as "no body" and lose the affordance entirely (ADR-0011 §3).
func (ls *liveSession) releaseBodiesLocked(id string) {
	if df := ls.dflows[id]; df != nil {
		df.RequestBody, df.ResponseBody = nil, nil
	}
	if pf := ls.flows[id]; pf != nil {
		clearInline(pf.GetRequestBody())
		clearInline(pf.GetResponseBody())
	}
}

func clearInline(b *trafficv1.Body) {
	if b != nil {
		b.Content = nil
	}
}

// failFlush records the first flush error and hands it to the owner, which ends the
// session and stops the capture (ADR-0011 §5). Continuing is not an option: retrying
// while holding the batch reinstates unbounded memory, and dropping it loses traffic
// silently — the one outcome a capture tool must never choose.
func (ls *liveSession) failFlush(err error) {
	ls.mu.Lock()
	if ls.flushErr == nil {
		ls.flushErr = err
	}
	onErr, sid := ls.onFlushErr, ls.sessionID
	ls.mu.Unlock()
	log.Printf("session %s: flush failed, ending capture: %v", sid, err)
	if onErr != nil {
		onErr(sid, err)
	}
}
