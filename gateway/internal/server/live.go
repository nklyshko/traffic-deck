package server

import (
	"io"
	"strings"
	"sync"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

const liveEventBuffer = 256

// liveHub tracks in-progress streaming sessions and fans decoded flows out to
// viewer subscribers. In record-live mode (the default) the live decode is
// authoritative and persisted on close; otherwise an optional batch pass re-decodes.
type liveHub struct {
	mu         sync.Mutex
	sessions   map[string]*liveSession
	recordLive bool // retain full decode flows so they can be persisted on close
}

func newLiveHub(recordLive bool) *liveHub {
	return &liveHub{sessions: map[string]*liveSession{}, recordLive: recordLive}
}

type liveSession struct {
	pw   *io.PipeWriter // feeds the in-process Go decode pipeline (nil for a pushed session)
	done chan struct{}  // closed when the decode goroutine exits

	recordLive bool // retain full decode flows (dflows) for persistence on close

	mu     sync.Mutex
	flows  map[string]*trafficv1.Flow
	dflows map[string]*decode.Flow // full-body decode flows, kept only in record-live mode
	order  []string
	subs   map[int]chan *trafficv1.FlowEvent
	nextID int
	closed bool

	// WebSocket frames decoded so far (live), and their subscribers. Frames are
	// immutable once decoded, so this is append-only; the stored path is empty until
	// the session is persisted on close.
	messages []*trafficv1.WsMessage
	msgSubs  map[int]chan *trafficv1.WsMessage
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
		subs:       map[int]chan *trafficv1.FlowEvent{},
		msgSubs:    map[int]chan *trafficv1.WsMessage{},
	}

	h.mu.Lock()
	h.sessions[sessionID] = ls
	h.mu.Unlock()

	go func() {
		defer close(ls.done)
		// Close the read end when decode exits so write() can't block forever if the
		// decoder returns early (writes get ErrClosedPipe instead).
		defer pr.Close()
		_ = decode.LiveTCPDecode(pr, keylogPath, ls.onFlow, ls.onMessage)
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
		subs:    map[int]chan *trafficv1.FlowEvent{},
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

	ls.mu.Lock()
	closedEv := &trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_SessionEvent{
		SessionEvent: &trafficv1.SessionEvent{SessionId: sessionID, Status: trafficv1.SessionStatus_SESSION_STATUS_CLOSED},
	}}
	for _, ch := range ls.subs {
		select {
		case ch <- closedEv:
		default:
		}
		close(ch)
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
		// streaming). f is updated in place across calls, so this holds its final state.
		ls.mu.Lock()
		ls.dflows[f.ID] = f
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
		ev := &trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowUpdated{FlowUpdated: f}}
		for _, ch := range ls.subs {
			select {
			case ch <- ev:
			default:
			}
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
	ls.flows[pf.Id] = pf
	var ev *trafficv1.FlowEvent
	if isNew && !existed {
		ls.order = append(ls.order, pf.Id)
		ev = &trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowAdded{FlowAdded: pf}}
	} else {
		ev = &trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowUpdated{FlowUpdated: pf}}
	}
	for _, ch := range ls.subs {
		select {
		case ch <- ev:
		default: // slow subscriber: drop (it can re-backfill after close)
		}
	}
}

// subscribe returns a snapshot of current flows (as flow_added events), a channel
// of subsequent events, and a cancel func. ch is nil if the session already closed.
func (ls *liveSession) subscribe() (snapshot []*trafficv1.FlowEvent, ch chan *trafficv1.FlowEvent, cancel func()) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.closed {
		return nil, nil, func() {}
	}
	for _, id := range ls.order {
		snapshot = append(snapshot, &trafficv1.FlowEvent{Event: &trafficv1.FlowEvent_FlowAdded{FlowAdded: ls.flows[id]}})
	}
	ch = make(chan *trafficv1.FlowEvent, liveEventBuffer)
	id := ls.nextID
	ls.nextID++
	ls.subs[id] = ch
	cancel = func() {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		if c, ok := ls.subs[id]; ok {
			delete(ls.subs, id)
			close(c)
		}
	}
	return snapshot, ch, cancel
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
	pf.RequestBody = liveBody(f.RequestBody, contentType(f.RequestHeaders))
	pf.ResponseBody = liveBody(f.ResponseBody, contentType(f.ResponseHeaders))
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

func liveBody(b []byte, ct string) *trafficv1.Body {
	if len(b) == 0 {
		return nil
	}
	body := &trafficv1.Body{Size: uint64(len(b)), ContentType: ct}
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
