package server

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// connBytesCap bounds how much of one direction a GetConnectionBytes read reassembles: a
// connection's whole stream is rebuilt to serve any window of it, so this is what one
// call can cost. Past it, total is a floor and truncated says so.
const connBytesCap = 64 << 20

const connBytesPage = 256 << 10

// undecodedOf is a session's undecoded index: the bundle's, plus — while it is still
// capturing — what the live decode has found so far.
func (v *Viewer) undecodedOf(ctx context.Context, sid string) ([]*decode.UndecodedConn, error) {
	conns, err := v.st.ListUndecoded(ctx, sid)
	if err != nil {
		return nil, storeStatus(err, "list undecoded connections")
	}
	if ls := v.hub.get(sid); ls != nil {
		seen := make(map[string]bool, len(conns))
		for _, c := range conns {
			seen[c.ConnectionID] = true
		}
		for _, c := range ls.undecodedSnapshot(nil) {
			if !seen[c.ConnectionID] {
				conns = append(conns, c)
			}
		}
	}
	return conns, nil
}

func (v *Viewer) ListUndecodedConnections(ctx context.Context, req *trafficv1.ListUndecodedRequest) (*trafficv1.UndecodedList, error) {
	sid := req.GetSessionId()
	sess, err := v.st.GetSession(ctx, sid)
	if err != nil {
		return nil, storeStatus(err, "get session")
	}
	conns, err := v.undecodedOf(ctx, sid)
	if err != nil {
		return nil, err
	}
	// A session that recorded the index carries its counts; one that did not cannot say
	// "nothing went undecoded", only "not looked".
	_, indexed := sess.GetMetadata()["undecoded."+decode.UndecodedNoKey]
	out := &trafficv1.UndecodedList{ByReason: map[string]uint64{},
		Indexed: indexed || len(conns) > 0 || v.hub.get(sid) != nil}
	host := strings.ToLower(req.GetHost())
	var match []*decode.UndecodedConn
	for _, c := range conns {
		out.ByReason[c.Reason]++
		if r := req.GetReason(); r != "" && c.Reason != r {
			continue
		}
		if host != "" && !strings.Contains(strings.ToLower(c.SNI), host) && !strings.Contains(strings.ToLower(c.Server), host) {
			continue
		}
		match = append(match, c)
	}
	// The store hands them back largest first; a live session's tail is appended unordered.
	sortByVolume(match)
	out.Total = uint64(len(match))
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}
	start := min(int(req.GetOffset()), len(match))
	for _, c := range match[start:min(start+limit, len(match))] {
		out.Connections = append(out.Connections, undecodedToProto(c))
	}
	return out, nil
}

func (v *Viewer) GetConnectionBytes(ctx context.Context, req *trafficv1.GetConnectionBytesRequest) (*trafficv1.ConnectionBytes, error) {
	sid := req.GetSessionId()
	conns, err := v.undecodedOf(ctx, sid)
	if err != nil {
		return nil, err
	}
	var conn *decode.UndecodedConn
	for _, c := range conns {
		if c.ConnectionID == req.GetConnectionId() {
			conn = c
		}
	}
	if conn == nil {
		return nil, status.Errorf(codes.NotFound, "no undecoded connection %q in session %s", req.GetConnectionId(), sid)
	}
	if v.obj == nil {
		return nil, status.Error(codes.Unavailable, "this gateway has no capture store to read from")
	}
	path, ok := v.obj.LocalPath(pcapKey(sid))
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "session %s has no local capture.pcap to read", sid)
	}
	b, err := decode.ReadConnection(path, conn, connBytesCap)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read connection %s: %v", conn.ConnectionID, err)
	}
	data := b.Down
	if req.GetFromClient() {
		data = b.Up
	}
	limit := int(req.GetLimit())
	if limit <= 0 || limit > connBytesPage {
		limit = connBytesPage
	}
	start := min(int(req.GetByteOffset()), len(data))
	out := &trafficv1.ConnectionBytes{
		Data: data[start:min(start+limit, len(data))], ByteOffset: uint64(start),
		Total: uint64(len(data)), Truncated: b.Truncated, Gaps: uint32(b.Gaps),
	}
	if conn.Transport == "tcp" {
		out.Tls = decode.DescribeTLS(b.Up, b.Down)
	}
	return out, nil
}

func sortByVolume(cs []*decode.UndecodedConn) {
	vol := func(c *decode.UndecodedConn) uint64 { return c.BytesUp + c.BytesDown }
	for i := 1; i < len(cs); i++ { // insertion sort: the list is nearly sorted already
		for j := i; j > 0 && (vol(cs[j]) > vol(cs[j-1]) ||
			vol(cs[j]) == vol(cs[j-1]) && cs[j].FirstTSMicros < cs[j-1].FirstTSMicros); j-- {
			cs[j], cs[j-1] = cs[j-1], cs[j]
		}
	}
}

func undecodedToProto(c *decode.UndecodedConn) *trafficv1.UndecodedConnection {
	return &trafficv1.UndecodedConnection{
		ConnectionId: c.ConnectionID, Transport: c.Transport, Client: c.Client, Server: c.Server,
		Sni: c.SNI, Ja4: c.JA4, Reason: c.Reason, Detail: c.Detail,
		BytesUp: c.BytesUp, BytesDown: c.BytesDown,
		FirstTsMicros: c.FirstTSMicros, LastTsMicros: c.LastTSMicros,
	}
}
