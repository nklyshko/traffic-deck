package server

// Server-side filtering and paging (ADR-0012): QueryFlows serves a page, StreamFlows
// carries the same filter for liveness, and a flow that stops matching is retracted so a
// viewer without the predicate is not left showing a stale row.

import (
	"context"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/filter"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// compileFilter builds the predicate for a session, resolving the tag and group names
// `~tag`/`~group` match. A bad expression is the client's error, not the gateway's, so it
// comes back as InvalidArgument with the parser's message — which is the whole point of
// refusing unsupported regexes loudly (ADR-0012 §3).
func (v *Viewer) compileFilter(ctx context.Context, sessionID, expr string) (*filter.Predicate, error) {
	if expr == "" {
		return nil, nil
	}
	tags, groups, err := v.st.AnnotationNames(ctx, sessionID)
	if err != nil {
		return nil, storeStatus(err, "filter")
	}
	p, err := filter.Compile(expr, tags, groups)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return p, nil
}

func cursorFromProto(c *trafficv1.FlowCursor) *store.Cursor {
	if c == nil {
		return nil
	}
	return &store.Cursor{TSMicros: c.GetTsMicros(), FrameNumber: c.GetFrameNumber()}
}

func cursorToProto(c *store.Cursor) *trafficv1.FlowCursor {
	if c == nil {
		return nil
	}
	return &trafficv1.FlowCursor{TsMicros: c.TSMicros, FrameNumber: c.FrameNumber}
}

// QueryFlows returns one page of a session's flows. For an open session the bundle holds
// everything up to the last flush, so the page is the stored result merged with the
// unflushed tail — which ADR-0011 is what keeps small enough to be uninteresting.
func (v *Viewer) QueryFlows(ctx context.Context, req *trafficv1.QueryFlowsRequest) (*trafficv1.FlowPage, error) {
	sid := req.GetSessionId()
	pred, err := v.compileFilter(ctx, sid, req.GetFilter())
	if err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	page, err := v.st.QueryFlows(ctx, sid, store.FlowQuery{
		Filter: pred,
		Limit:  limit,
		After:  cursorFromProto(req.GetAfter()),
		Before: cursorFromProto(req.GetBefore()),
		Last:   req.GetLast(),

		SinceMicros: req.GetSinceMicros(),
		UntilMicros: req.GetUntilMicros(),
	})
	if err != nil {
		return nil, storeStatus(err, "query flows")
	}

	out := &trafficv1.FlowPage{
		Flows:       page.Flows,
		Hints:       filter.Hints(req.GetFilter()),
		Next:        cursorToProto(page.Next),
		Prev:        cursorToProto(page.Prev),
		Matched:     page.Matched,
		CountCapped: page.CountCapped,
		Scanned:     page.Scanned,
	}
	v.mergeUnflushed(ctx, sid, pred, req, out)
	return out, nil
}

// mergeUnflushed folds an open session's not-yet-written flows into a page. They are
// dropped from the bundle's view entirely until the flusher runs, so without this a
// viewer would see the newest traffic appear a flush late.
func (v *Viewer) mergeUnflushed(ctx context.Context, sid string, pred *filter.Predicate,
	req *trafficv1.QueryFlowsRequest, page *trafficv1.FlowPage) {
	ls := v.hub.get(sid)
	if ls == nil {
		return // closed session: the bundle is the whole truth
	}
	tail := ls.unflushedFlows()
	if len(tail) == 0 {
		return
	}
	_ = v.st.AttachFlowAnnotations(ctx, sid, tail...)

	have := make(map[string]bool, len(page.Flows))
	for _, f := range page.Flows {
		have[f.GetId()] = true
	}
	tags, groups, _ := v.st.AnnotationNames(ctx, sid)

	after, before := cursorFromProto(req.GetAfter()), cursorFromProto(req.GetBefore())
	var add []*trafficv1.Flow
	for _, f := range tail {
		if have[f.GetId()] {
			continue // already served from the bundle
		}
		if after != nil && !afterCursor(f, after) {
			continue
		}
		if before != nil && afterCursor(f, before) {
			continue
		}
		ff := filterFlowFromProto(f, tags, groups)
		if !pred.Match(&ff) {
			continue
		}
		add = append(add, summarize(f))
		page.Matched++
	}
	if len(add) == 0 {
		return
	}

	all := append(page.Flows, add...)
	sort.SliceStable(all, func(i, j int) bool { return flowLess(all[i], all[j]) })
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}
	// Which end of the merged set had to be dropped to fit the window decides which cursor
	// is owed: dropping from the back leaves newer flows after it (a Next), from the front
	// leaves older flows before it (a Prev). A window that reaches an end of the list drops
	// nothing there and must offer no cursor past it — otherwise the viewer reads "there is
	// more that way", marks itself off-end, and quietly stops folding in live arrivals until
	// it is reopened (ADR-0012 §5). Setting Next unconditionally here was that bug: a live
	// session whose flows all fit one page still came back with a Next, freezing the table.
	droppedFront, droppedBack := false, false
	if len(all) > limit {
		// A page taken from the end keeps its tail, everything else its head — the tail
		// is where the newest flows are, and it is what "jump to the end" asked for.
		if req.GetLast() || req.GetBefore() != nil {
			all = all[len(all)-limit:]
			droppedFront = true
		} else {
			all = all[:limit]
			droppedBack = true
		}
	}
	page.Flows = all
	page.Next, page.Prev = nil, nil
	if n := len(all); n > 0 {
		// Next (newer flows exist after this window): because some were dropped to fit, or
		// because a backward page started from a later point.
		if droppedBack || req.GetBefore() != nil {
			page.Next = &trafficv1.FlowCursor{
				TsMicros: all[n-1].GetTsUnixMicros(), FrameNumber: all[n-1].GetFrameNumber()}
		}
		// Prev (older flows exist before this window): because some were dropped to fit, or
		// because a forward page started from an earlier point.
		if droppedFront || req.GetAfter() != nil {
			page.Prev = &trafficv1.FlowCursor{
				TsMicros: all[0].GetTsUnixMicros(), FrameNumber: all[0].GetFrameNumber()}
		}
	}
}

// summarize strips a live flow down to the shape a page carries. The hub's protos inline
// bodies up to InlineBlobMax and hold every header, which is right for an event stream and
// wrong for a page: a few hundred of them exceed the gRPC message limit on their own. The
// stored side of a page is already a summary; this makes the tail match it.
func summarize(f *trafficv1.Flow) *trafficv1.Flow {
	f.RequestHeaders, f.ResponseHeaders = nil, nil
	if b := f.GetRequestBody(); b != nil {
		b.Content = nil // keep size and content-type: the viewer gates its body actions on them
	}
	if b := f.GetResponseBody(); b != nil {
		b.Content = nil
	}
	f.ClientHellos = nil
	return f
}

func flowLess(a, b *trafficv1.Flow) bool {
	if a.GetTsUnixMicros() != b.GetTsUnixMicros() {
		return a.GetTsUnixMicros() < b.GetTsUnixMicros()
	}
	return a.GetFrameNumber() < b.GetFrameNumber()
}

func afterCursor(f *trafficv1.Flow, c *store.Cursor) bool {
	if f.GetTsUnixMicros() != c.TSMicros {
		return f.GetTsUnixMicros() > c.TSMicros
	}
	return f.GetFrameNumber() > c.FrameNumber
}

// filterFlowFromProto views a proto flow through the filter language. Bodies come from
// the inline copy: a live flow that still has one can be matched on, and one whose bytes
// have been released simply does not match a body term — the bundle-backed path is
// QueryFlows' job, and this only ever sees the unflushed tail.
func filterFlowFromProto(f *trafficv1.Flow, tagNames, groupNames map[string]string) filter.Flow {
	ff := filter.Flow{
		Scheme: f.GetScheme(), Method: f.GetMethod(), Authority: f.GetAuthority(),
		Path: f.GetPath(), Query: f.GetQuery(), Status: f.GetStatus(),
		ContentTyp: f.GetContentType(), TCPStream: f.GetTcpStream(),
		H2StreamID: f.GetH2StreamId(),
		MarkColor:  f.GetMarkColor(), Favorite: f.GetFavorite(),
		TagNames: f.GetTagIds(), GroupNames: f.GetGroupIds(),
		Metadata: f.GetMetadata(),
		Body: func(d filter.Direction) string {
			if d == filter.Request {
				return string(f.GetRequestBody().GetInline())
			}
			return string(f.GetResponseBody().GetInline())
		},
	}
	for _, c := range f.GetComments() {
		ff.Comments = append(ff.Comments, c.GetBody())
	}
	return ff
}
