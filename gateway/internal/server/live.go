package server

import (
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/tlsfp"
)

const liveEventBuffer = 256

// flowSub is one viewer's subscription: its event channel, and whether anything meant for
// it had to be thrown away because the channel was full.
//
// Dropping is still what a slow subscriber gets — publish runs on the decode path, under
// the mutex the whole session shares, and blocking it there would stall the capture to
// serve a viewer. What a drop must not be is silent: the viewer's rows come from
// QueryFlows and only its *updates* come from here (ADR-0012 §4), so an event dropped in
// the middle of a live session leaves a row missing or stale with nothing to correct it —
// until the user reopens the session, which is how this was found. `missed` is the
// gateway remembering it owes this subscriber a resync; StreamFlows pays it with the
// same "subscription live, query again" event the stream opens with.
type flowSub struct {
	ch     chan *trafficv1.FlowEvent
	missed atomic.Bool
}

// send queues an event, recording a drop instead of blocking when the channel is full.
func (s *flowSub) send(ev *trafficv1.FlowEvent) {
	select {
	case s.ch <- ev:
	default:
		s.missed.Store(true)
	}
}

// liveHub tracks in-progress streaming sessions and fans decoded flows out to
// viewer subscribers. In record-live mode (the default) the live decode is
// authoritative and persisted on close; otherwise an optional batch pass re-decodes.
type liveHub struct {
	mu         sync.Mutex
	sessions   map[string]*liveSession
	recordLive bool // retain full decode flows so they can be persisted on close

	// Incremental persistence wiring (ADR-0011), set by setPersistence once the owner
	// that can reach the store exists. Unset means sessions accumulate until close.
	sink        flushSink
	analysisFor func(sessionID string) (string, error)
	onFlushErr  func(sessionID string, err error)
}

func newLiveHub(recordLive bool) *liveHub {
	return &liveHub{sessions: map[string]*liveSession{}, recordLive: recordLive}
}

// setPersistence gives the hub what its flushers need: somewhere to write, the session's
// analysis id, and what to do when a write fails.
func (h *liveHub) setPersistence(sink flushSink, analysisFor func(string) (string, error),
	onFlushErr func(string, error)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sink, h.analysisFor, h.onFlushErr = sink, analysisFor, onFlushErr
}

type liveSession struct {
	pw   *io.PipeWriter // feeds the in-process Go decode pipeline (nil for a pushed session)
	done chan struct{}  // closed when the decode goroutine exits

	recordLive bool // retain full decode flows (dflows) for persistence on close

	mu     sync.Mutex
	flows  map[string]*trafficv1.Flow
	dflows map[string]*decode.Flow // full-body decode flows, kept only in record-live mode
	order  []string
	subs   map[int]*flowSub
	nextID int
	closed bool

	// WebSocket frames decoded so far and not yet written, plus their subscribers. Frames
	// are immutable once decoded, so this is append-only until the flusher trims what it
	// has persisted; with no flusher it holds the whole session, as before.
	messages []*trafficv1.WsMessage
	msgSubs  map[int]chan *trafficv1.WsMessage

	// Incremental persistence (ADR-0011), active only when sink is set. Without it the
	// session accumulates until close — the pushed path, which persists itself, and
	// record-live off, which re-decodes the pcap instead.
	sink       flushSink
	sessionID  string
	analysisID string
	onFlushErr func(sessionID string, err error)
	wake       chan struct{}
	stopFlush  chan struct{}
	flushDone  chan struct{}

	// Flush bookkeeping, guarded by mu. dirty is what changed since the last flush;
	// pending is what has been written but whose bodies are still arriving; stored is
	// what has been written in full and released from memory.
	dirty    map[string]struct{}
	pending  map[string]struct{}
	stored   map[string]storedBody
	flushErr error
}

func (h *liveHub) get(sessionID string) *liveSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[sessionID]
}

// liveFlowCount reports the running flow count for an in-progress session, or (0, false)
// if no live session is registered (already closed, or never live). The catalog's
// flow_count is only written on close, so this is the source of truth for an open
// session's count.
func (h *liveHub) liveFlowCount(sessionID string) (int, bool) {
	if ls := h.get(sessionID); ls != nil {
		return ls.flowCount(), true
	}
	return 0, false
}

// start spins up the live decode for sessionID, fed by the pipe via write(). keylogPath
// must already exist (it may be empty and grow). One in-process Go pipeline decodes the
// whole capture — reassembling TCP/QUIC, decrypting TLS from the growing key-log, and
// framing HTTP/1.1, HTTP/2, HTTP/3, WebSocket, and custom raw-TCP protocols, plaintext or
// TLS — with no tshark. In record-live mode its flows are persisted on close.
func (h *liveHub) start(sessionID, keylogPath string) {
	pr, pw := io.Pipe()
	ls := &liveSession{
		pw:         pw,
		done:       make(chan struct{}),
		recordLive: h.recordLive,
		flows:      map[string]*trafficv1.Flow{},
		dflows:     map[string]*decode.Flow{},
		subs:       map[int]*flowSub{},
		msgSubs:    map[int]chan *trafficv1.WsMessage{},
		sessionID:  sessionID,
		dirty:      map[string]struct{}{},
		pending:    map[string]struct{}{},
		stored:     map[string]storedBody{},
		wake:       make(chan struct{}, 1),
		stopFlush:  make(chan struct{}),
		flushDone:  make(chan struct{}),
	}
	h.mu.Lock()
	sink, analysisFor, onFlushErr := h.sink, h.analysisFor, h.onFlushErr
	h.sessions[sessionID] = ls
	h.mu.Unlock()

	// Record-live persists as it goes; the analysis those rows reference is created up
	// front rather than at close, since they now reference it throughout the capture
	// (ADR-0011 §7). Without one the session simply accumulates until close, as before.
	if h.recordLive && sink != nil && analysisFor != nil {
		if aid, err := analysisFor(sessionID); err == nil {
			ls.sink, ls.analysisID, ls.onFlushErr = sink, aid, onFlushErr
			ls.startFlusher()
		} else {
			log.Printf("session %s: no analysis; keeping flows in memory until close: %v", sessionID, err)
		}
	}

	go func() {
		defer close(ls.done)
		// Close the read end when decode exits so write() can't block forever if the
		// decoder returns early (writes get ErrClosedPipe instead).
		defer pr.Close()
		_ = decode.LiveTCPDecode(pr, keylogPath, ls.onFlow, ls.onMessage, h.recordLive)
	}()
}

// startPassive registers a tshark-less live session for a *pushed* source
// (PushFlows / mitmproxy): no pipe, no decode goroutine — flows are published
// directly via publish(). Idempotent: returns the existing session if present.
func (h *liveHub) startPassive(sessionID string) *liveSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ls, ok := h.sessions[sessionID]; ok {
		return ls
	}
	ls := &liveSession{
		flows:   map[string]*trafficv1.Flow{},
		subs:    map[int]*flowSub{},
		msgSubs: map[int]chan *trafficv1.WsMessage{},
	}
	h.sessions[sessionID] = ls
	return ls
}

func (h *liveHub) write(sessionID string, b []byte) {
	if ls := h.get(sessionID); ls != nil && ls.pw != nil {
		_, _ = ls.pw.Write(b)
	}
}

// stop ends a session's live decode: close the pipe (EOF tshark), wait for all
// flows to be emitted, publish a closed session_event, and close subscribers. It
// returns the finalized session (or nil) so the caller can persist its flows in
// record-live mode; the accumulated flows/messages stay readable after close.
func (h *liveHub) stop(sessionID string) *liveSession {
	h.mu.Lock()
	ls := h.sessions[sessionID]
	delete(h.sessions, sessionID)
	h.mu.Unlock()
	if ls == nil {
		return nil
	}
	if ls.pw != nil { // decode-fed session: close the pipe (EOF) and wait for decode to drain
		_ = ls.pw.Close()
		<-ls.done
	}
	// End the flush loop before the caller runs the final flush, so the two can't race
	// over the dirty set.
	ls.stopFlusher()

	ls.mu.Lock()
	closedEv := &trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_SessionEvent{
		SessionEvent: &trafficv1.SessionEvent{SessionId: sessionID, Status: trafficv1.SessionStatus_SESSION_STATUS_CLOSED},
	}}
	for _, sub := range ls.subs {
		sub.send(closedEv)
		close(sub.ch)
	}
	for _, ch := range ls.msgSubs {
		close(ch) // closing the channel signals end-of-stream to message followers
	}
	ls.closed = true
	ls.subs = nil
	ls.msgSubs = nil
	ls.mu.Unlock()
	return ls
}

// snapshotForRecord returns the final full-body decode flows (in arrival order) and the
// WebSocket messages, for persisting a record-live session on close. WS message payloads
// are carried inline in the proto (uncapped once SetUnlimitedLiveBodies is set).
func (ls *liveSession) snapshotForRecord() ([]*decode.Flow, []*decode.WsMessage) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	flows := make([]*decode.Flow, 0, len(ls.order))
	for _, id := range ls.order {
		if f := ls.dflows[id]; f != nil {
			flows = append(flows, f)
		}
	}
	msgs := make([]*decode.WsMessage, 0, len(ls.messages))
	for _, pm := range ls.messages {
		msgs = append(msgs, protoToDecodeWsMessage(pm))
	}
	return flows, msgs
}

// flowCount returns the number of distinct flows published so far — the live count for an
// open session, shown until the catalog's stored count is finalized on close.
func (ls *liveSession) flowCount() int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return len(ls.order)
}

// flow returns a clone of the live flow with the given id, or nil if it isn't present.
// A clone (not the shared pointer) so callers — e.g. the live GetFlow path attaching
// annotations — don't mutate the proto fanned out to every subscriber.
func (ls *liveSession) flow(id string) *trafficv1.Flow {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if f := ls.flows[id]; f != nil {
		return proto.Clone(f).(*trafficv1.Flow)
	}
	return nil
}

// liveFlows returns clones of the flows published so far, in arrival order — the
// unpersisted counterpart of store.ListFlows, for reading a session that is still open
// (the live decode paths persist nothing until close).
func (ls *liveSession) liveFlows() []*trafficv1.Flow {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	out := make([]*trafficv1.Flow, 0, len(ls.order))
	for _, id := range ls.order {
		if f := ls.flows[id]; f != nil {
			out = append(out, proto.Clone(f).(*trafficv1.Flow))
		}
	}
	return out
}

// messagesForFlow returns clones of the frames decoded so far for one flow, in order —
// the live counterpart of store.ListMessages.
func (ls *liveSession) messagesForFlow(flowID string) []*trafficv1.WsMessage {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	var out []*trafficv1.WsMessage
	for _, m := range ls.messages {
		if m.GetFlowId() == flowID {
			out = append(out, proto.Clone(m).(*trafficv1.WsMessage))
		}
	}
	return out
}

// bodyBytes serves a live flow's request or response body: the bytes held for it, and
// whether those are a prefix (the live cap cut the body short) rather than the whole
// thing. ok is false only when there is no such live flow, or that direction has no body.
//
// Under record-live the retained decode flow carries whole bodies of any size, so it wins
// over the proto's copy, which inlines only up to InlineBlobMax. Without it the flow's
// preview is all there is until the batch decode on close.
func (ls *liveSession) bodyBytes(flowID string, response bool) (data []byte, truncated, ok bool) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if df := ls.dflows[flowID]; df != nil {
		b, cut := df.RequestBody, df.RequestBodyTruncated
		if response {
			b, cut = df.ResponseBody, df.ResponseBodyTruncated
		}
		if len(b) > 0 {
			return b, cut, true
		}
	}
	f := ls.flows[flowID]
	if f == nil {
		return nil, false, false
	}
	body := f.GetRequestBody()
	if response {
		body = f.GetResponseBody()
	}
	if body.GetSize() == 0 {
		return nil, false, false
	}
	if inline := body.GetInline(); len(inline) > 0 {
		return inline, body.GetTruncated(), true
	}
	// The flow says the body exists but carries none of it (a pushed flow whose bytes
	// went to the store, which the caller has already missed). Nothing to hand over —
	// report it as a truncated body of zero bytes rather than as a body-less flow.
	return nil, true, true
}

// messageBody returns a live message's decoded payload (or its original undecoded bytes
// when raw is set) and whether it was found. Live frames carry both inline, so unlike
// bodyBytes there is no "present but unavailable" case.
func (ls *liveSession) messageBody(messageID string, raw bool) ([]byte, bool) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for _, m := range ls.messages {
		if m.GetId() != messageID {
			continue
		}
		body := m.GetPayload()
		if raw {
			body = m.GetRaw()
		}
		if body == nil {
			return nil, false
		}
		return body.GetInline(), true
	}
	return nil, false
}

// message returns a clone of the live WebSocket/parsed message with the given id, or nil.
// Cloned for the same reason as flow: the live proto is shared with subscribers.
func (ls *liveSession) message(id string) *trafficv1.WsMessage {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for _, m := range ls.messages {
		if m.Id == id {
			return proto.Clone(m).(*trafficv1.WsMessage)
		}
	}
	return nil
}

// protoFlows returns the live-decoded flows (final state, arrival order) as protos — used
// to compare against the batch decode for verification on close.
func (ls *liveSession) protoFlows() []*trafficv1.Flow {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	flows := make([]*trafficv1.Flow, 0, len(ls.order))
	for _, id := range ls.order {
		flows = append(flows, ls.flows[id])
	}
	return flows
}

func (ls *liveSession) onFlow(f *decode.Flow, isNew bool) {
	if ls.recordLive {
		// Retain the full-body decode flow (the proto below is a capped preview for
		// streaming). Snapshot rather than keep f: the decoder mutates one Flow in place
		// across callbacks and holds no lock of ours while doing it, so only this
		// callback is synchronous with it. Keeping the pointer would race with every
		// later reader — the flusher, and a body read served from the hub.
		ls.mu.Lock()
		ls.dflows[f.ID] = copyFlow(f)
		ls.mu.Unlock()
	}
	ls.publish(flowToProto(f), isNew)
}

func (ls *liveSession) onMessage(m *decode.WsMessage) {
	ls.publishMessage(wsMsgToProto(m))
}

// publishMessage records a decoded WebSocket frame and fans it to message followers.
func (ls *liveSession) publishMessage(pm *trafficv1.WsMessage) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.closed {
		return
	}
	ls.messages = append(ls.messages, pm)
	for _, ch := range ls.msgSubs {
		select {
		case ch <- pm:
		default: // slow subscriber: drop (it re-backfills from the store after close)
		}
	}
	// Keep the parent flow's live ⇅ count current so the flow row reflects the messages
	// (the decode paths bump this on the Flow; the pushed path publishes messages
	// separately, so bump it here) and re-publish the flow as an update.
	if f := ls.flows[pm.GetFlowId()]; f != nil {
		f.Websocket = true
		f.WsMessageCount++
		ls.markDirtyLocked(pm.GetFlowId())
		ev := &trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowUpdated{FlowUpdated: f}}
		for _, sub := range ls.subs {
			sub.send(ev)
		}
	}
}

// subscribeMessages returns the frames seen so far for one flow, a channel of
// subsequent frames (for that flow), and a cancel func. ch is nil if already closed.
func (ls *liveSession) subscribeMessages(flowID string) (snapshot []*trafficv1.WsMessage, ch chan *trafficv1.WsMessage, cancel func()) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.closed {
		return nil, nil, func() {}
	}
	for _, m := range ls.messages {
		if m.FlowId == flowID {
			snapshot = append(snapshot, m)
		}
	}
	ch = make(chan *trafficv1.WsMessage, liveEventBuffer)
	id := ls.nextID
	ls.nextID++
	ls.msgSubs[id] = ch
	cancel = func() {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		if c, ok := ls.msgSubs[id]; ok {
			delete(ls.msgSubs, id)
			close(c)
		}
	}
	return snapshot, ch, cancel
}

// publish records a (proto) flow and fans an added/updated event to subscribers.
// Shared by the tshark live path (onFlow) and the PushFlows path. A flow id seen
// before is an update even if isNew is set.
func (ls *liveSession) publish(pf *trafficv1.Flow, isNew bool) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.closed {
		return
	}
	_, existed := ls.flows[pf.Id]
	if old := ls.flows[pf.Id]; old != nil {
		// A pushed flow is re-sent whole as it progresses (mitmproxy re-pushes on
		// response and again on websocket_end), and build_flow carries no
		// WsMessageCount — the pushed path accumulates it here from frames (see
		// publishMessage). Without this, the websocket_end re-push resets the live ⇅
		// count to zero. Carry the accumulated count/flag forward on any re-publish;
		// for the native decode path the count only grows, so max() is a no-op there.
		if old.WsMessageCount > pf.WsMessageCount {
			pf.WsMessageCount = old.WsMessageCount
		}
		pf.Websocket = pf.Websocket || old.Websocket
	}
	ls.flows[pf.Id] = pf
	ls.markDirtyLocked(pf.Id)
	var ev *trafficv1.FlowEvent
	if isNew && !existed {
		ls.order = append(ls.order, pf.Id)
		ev = &trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowAdded{FlowAdded: pf}}
	} else {
		ev = &trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowUpdated{FlowUpdated: pf}}
	}
	for _, sub := range ls.subs {
		sub.send(ev)
	}
}

// subscribe returns a snapshot of current flows (as flow_added events), the subscription
// carrying subsequent events, and a cancel func. sub is nil if the session already closed.
func (ls *liveSession) subscribe() (snapshot []*trafficv1.FlowEvent, sub *flowSub, cancel func()) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.closed {
		return nil, nil, func() {}
	}
	for _, id := range ls.order {
		snapshot = append(snapshot, &trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowAdded{FlowAdded: ls.flows[id]}})
	}
	sub = &flowSub{ch: make(chan *trafficv1.FlowEvent, liveEventBuffer)}
	id := ls.nextID
	ls.nextID++
	ls.subs[id] = sub
	cancel = func() {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		if s, ok := ls.subs[id]; ok {
			delete(ls.subs, id)
			close(s.ch)
		}
	}
	return snapshot, sub, cancel
}

// flowToProto converts a decoded flow to the proto type for live events, inlining
// small bodies (large bodies are available in full after the session is persisted).
func flowToProto(f *decode.Flow) *trafficv1.Flow {
	pf := &trafficv1.Flow{
		Id:               f.ID,
		FrameNumber:      f.FrameNumber,
		TsUnixMicros:     f.TSUnixMicros,
		Method:           f.Method,
		Scheme:           f.Scheme,
		Authority:        f.Authority,
		Path:             f.Path,
		Query:            f.Query,
		Protocol:         f.Protocol,
		Status:           f.Status,
		SrcAddr:          f.SrcAddr,
		DstAddr:          f.DstAddr,
		UserAgent:        f.UserAgent,
		ContentType:      f.ContentType,
		RequestBytes:     f.RequestBytes,
		TlsDecrypted:     f.TLSDecrypted,
		TcpStream:        f.TCPStream,
		H2StreamId:       f.H2StreamID,
		Websocket:        f.Websocket,
		WsMessageCount:   f.WsMessageCount,
		Error:            f.Error,
		DurationMicros:   f.DurationMicros,
		Http2Fingerprint: f.Http2Fingerprint,
		Ja3:              f.JA3,
		Ja4:              f.JA4,
		TlsClientName:    tlsfp.Name(tlsfp.Fingerprint{JA4: f.JA4, JA3: f.JA3, SNI: f.Authority}),
		TlsClientHello:   f.TLSClientHello,
		ClientHellos:     f.ClientHellos,
		TlsHrr:           f.TLSHRR,
	}
	if f.Proxy != nil {
		pf.Proxy = &trafficv1.Proxy{
			Addr: f.Proxy.Addr, Type: f.Proxy.Type,
			Username: f.Proxy.Username, Password: f.Proxy.Password,
		}
	}
	for _, h := range f.RequestHeaders {
		pf.RequestHeaders = append(pf.RequestHeaders, &trafficv1.Header{Name: h.Name, Value: h.Value})
	}
	for _, h := range f.ResponseHeaders {
		pf.ResponseHeaders = append(pf.ResponseHeaders, &trafficv1.Header{Name: h.Name, Value: h.Value})
	}
	pf.RequestBody = liveBody(f.RequestBody, contentType(f.RequestHeaders), f.RequestBodyTruncated)
	pf.ResponseBody = liveBody(f.ResponseBody, contentType(f.ResponseHeaders), f.ResponseBodyTruncated)
	return pf
}

// wsMsgToProto converts a decoded WebSocket frame to the proto type for live events,
// inlining the payload (frames are small; the stored path serves large ones via
// GetMessageBody after persistence).
func wsMsgToProto(m *decode.WsMessage) *trafficv1.WsMessage {
	pm := &trafficv1.WsMessage{
		Id:           m.ID,
		FlowId:       m.FlowID,
		FrameNumber:  m.FrameNumber,
		TsUnixMicros: m.TSUnixMicros,
		FromClient:   m.FromClient,
		Opcode:       m.Opcode,
		Metadata:     m.Metadata,
	}
	if len(m.Payload) > 0 {
		pm.Payload = &trafficv1.Body{
			Size:    uint64(len(m.Payload)),
			Content: &trafficv1.Body_Inline{Inline: m.Payload},
		}
	}
	if len(m.Raw) > 0 {
		pm.Raw = &trafficv1.Body{
			Size:    uint64(len(m.Raw)),
			Content: &trafficv1.Body_Inline{Inline: m.Raw},
		}
	}
	return pm
}

func liveBody(b []byte, ct string, truncated bool) *trafficv1.Body {
	if len(b) == 0 {
		return nil
	}
	body := &trafficv1.Body{Size: uint64(len(b)), ContentType: ct, Truncated: truncated}
	if len(b) <= store.InlineBlobMax {
		body.Content = &trafficv1.Body_Inline{Inline: b}
	}
	return body
}

func contentType(hs []decode.Header) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, "content-type") {
			return h.Value
		}
	}
	return ""
}

// unflushedFlows returns clones of the flows the flusher has not written to the bundle
// yet — the tail a stored query must merge, since the bundle does not have them
// (ADR-0012 §8). A session with no flusher has no such tail to distinguish, so every live
// flow is a candidate and the caller dedupes.
func (ls *liveSession) unflushedFlows() []*trafficv1.Flow {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	out := make([]*trafficv1.Flow, 0, 8)
	for _, id := range ls.order {
		if ls.sink != nil {
			if _, written := ls.pending[id]; written {
				continue
			}
			if _, written := ls.stored[id]; written {
				continue
			}
		}
		if f := ls.flows[id]; f != nil {
			out = append(out, proto.Clone(f).(*trafficv1.Flow))
		}
	}
	return out
}
