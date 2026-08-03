package server

// Message-side filtering. The message timeline is the one list in the viewer that was not
// covered by ADR-0012 — a chatty WebSocket flow can carry tens of thousands of frames, and
// the only way to find one was to scroll. The language lives here for the same reason the
// flow language does: one implementation, so the TUI, MCP and any third-party viewer get
// identical results, and the payload is matched in the process that holds it.

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/filter"
)

// compileMessageFilter builds the predicate for a session's message timeline, resolving
// the tag and group names `~tag`/`~group` match. A bad expression is the client's error:
// it comes back as InvalidArgument carrying the parser's message, which is what makes an
// unknown term (`~m` brought over from the flow language) a visible failure rather than a
// payload regex that matches nothing.
func (v *Viewer) compileMessageFilter(ctx context.Context, sessionID, expr string) (*filter.MessagePredicate, error) {
	if expr == "" {
		return nil, nil
	}
	tags, groups, err := v.st.AnnotationNames(ctx, sessionID)
	if err != nil {
		return nil, storeStatus(err, "filter")
	}
	p, err := filter.CompileMessage(expr, tags, groups)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return p, nil
}

// messageMatcher adapts a compiled predicate to the protos both message paths carry. The
// returned func matches everything when pred is nil, so neither caller needs a branch.
func (v *Viewer) messageMatcher(ctx context.Context, sessionID string, pred *filter.MessagePredicate) func(*trafficv1.WsMessage) bool {
	if pred == nil {
		return func(*trafficv1.WsMessage) bool { return true }
	}
	readsPayloads := pred.ReadsPayloads()
	return func(m *trafficv1.WsMessage) bool {
		fm := filter.Message{
			Opcode: m.GetOpcode(), FromClient: m.GetFromClient(),
			MarkColor: m.GetMarkColor(), Favorite: m.GetFavorite(),
			TagNames: m.GetTagIds(), GroupNames: m.GetGroupIds(),
			Metadata: m.GetMetadata(),
		}
		for _, c := range m.GetComments() {
			fm.Comments = append(fm.Comments, c.GetBody())
		}
		if readsPayloads {
			fm.Payload = v.payloadLoader(ctx, sessionID, m)
		}
		return pred.Match(&fm)
	}
}

// payloadLoader returns a lazy reader for one frame's payload text. Small payloads are
// already inline in the proto; a large one is an object_ref, and is read from the bundle
// (or, for a frame the flusher has not written yet, from the live hub). Memoized because a
// frame is tested once but an expression can hold several payload terms.
func (v *Viewer) payloadLoader(ctx context.Context, sessionID string, m *trafficv1.WsMessage) func() string {
	var cached *string
	return func() string {
		if cached != nil {
			return *cached
		}
		out := ""
		if b := m.GetPayload(); b != nil {
			if inline := b.GetInline(); len(inline) > 0 {
				out = string(inline)
			} else if b.GetSize() > 0 {
				if data, err := v.st.GetWsMessageBody(ctx, sessionID, m.GetId(), false); err == nil {
					out = string(data)
				} else if ls := v.hub.get(sessionID); ls != nil {
					if data, ok := ls.messageBody(m.GetId(), false); ok {
						out = string(data)
					}
				}
			}
		}
		cached = &out
		return out
	}
}
