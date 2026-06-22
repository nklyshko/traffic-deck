package server

import (
	"context"
	"errors"
	"io"
	"path"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nikitak/parsing/traffic-gateway/gen/traffic/v1"
	"github.com/nikitak/parsing/traffic-gateway/internal/decode"
	"github.com/nikitak/parsing/traffic-gateway/internal/importer"
	"github.com/nikitak/parsing/traffic-gateway/internal/objstore"
	"github.com/nikitak/parsing/traffic-gateway/internal/store"
)

const maxChunkBytes = 1 << 20 // advertised upload chunk size

// Ingest implements trafficv1.IngestServiceServer: streamed capture upload (decoded
// live and/or on close) and the pushed-flow path for already-decoded sources.
type Ingest struct {
	trafficv1.UnimplementedIngestServiceServer
	st         *store.Store
	obj        objstore.Store
	tshark     string
	hub        *liveHub
	liveDecode bool // when false, streaming uploads are archived and decoded only on close
}

func NewIngest(st *store.Store, obj objstore.Store, tshark string, hub *liveHub, liveDecode bool) *Ingest {
	return &Ingest{st: st, obj: obj, tshark: tshark, hub: hub, liveDecode: liveDecode}
}

func pcapKey(sid string) string   { return path.Join("sessions", sid, "capture.pcap") }
func keylogKey(sid string) string { return path.Join("sessions", sid, "key.log") }

func (i *Ingest) OpenSession(ctx context.Context, req *trafficv1.OpenSessionRequest) (*trafficv1.SessionHandle, error) {
	sid := uuid.NewString()
	if err := i.st.CreateSession(ctx, store.NewSession{
		ID:         sid,
		Label:      req.GetLabel(),
		SourceKind: req.GetSourceKind(),
		Status:     trafficv1.SessionStatus_SESSION_STATUS_OPEN,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "create session: %v", err)
	}
	// Supplied (pushed) sources have no UploadBegin to start a live session, so
	// register a passive one now — viewers can follow from the moment it exists.
	if req.GetSourceKind() == trafficv1.SourceKind_SOURCE_KIND_MITMPROXY {
		i.hub.startPassive(sid)
	}
	return &trafficv1.SessionHandle{SessionId: sid, MaxChunkBytes: maxChunkBytes}, nil
}

// UploadCapture streams pcap + key.log chunks into the session bundle, writing
// each at its byte offset (ordered, resumable). Decode happens on CloseSession.
func (i *Ingest) UploadCapture(stream grpc.ClientStreamingServer[trafficv1.CaptureChunk, trafficv1.UploadAck]) error {
	var sid, uploadID string
	var pcapN, keylogN uint64
	var live bool

	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch m := msg.GetMsg().(type) {
		case *trafficv1.CaptureChunk_Begin:
			sid = m.Begin.GetSessionId()
			uploadID = m.Begin.GetUploadId()
			if m.Begin.GetMode() == trafficv1.CaptureMode_CAPTURE_MODE_STREAMING_LIVE && i.liveDecode {
				live = true
				// Ensure the key.log exists so tshark can watch it, then start live decode.
				_ = i.obj.WriteAt(keylogKey(sid), nil, 0)
				keylogLocal, _ := i.obj.LocalPath(keylogKey(sid))
				i.hub.start(sid, keylogLocal)
			}
		case *trafficv1.CaptureChunk_Data:
			if sid == "" {
				return status.Error(codes.InvalidArgument, "UploadBegin must precede data chunks")
			}
			key, dir := pcapKey(sid), m.Data.GetKind()
			if dir == trafficv1.FileKind_FILE_KIND_KEYLOG {
				key = keylogKey(sid)
			}
			if err := i.obj.WriteAt(key, m.Data.GetPayload(), int64(m.Data.GetOffset())); err != nil {
				return status.Errorf(codes.Internal, "write chunk: %v", err)
			}
			n := uint64(len(m.Data.GetPayload()))
			if dir == trafficv1.FileKind_FILE_KIND_KEYLOG {
				keylogN += n
			} else {
				pcapN += n
				if live { // tee the pcap bytes to the live decoder
					i.hub.write(sid, m.Data.GetPayload())
				}
			}
		case *trafficv1.CaptureChunk_End:
			// terminal frame; loop will exit on EOF
		}
	}
	return stream.SendAndClose(&trafficv1.UploadAck{
		UploadId: uploadID, PcapReceived: pcapN, KeylogReceived: keylogN,
	})
}

// PushFlows ingests already-decoded flows (the mitmproxy/supplied path):
// each batch is persisted to the session bundle and live-published to viewers. No
// pcap/tshark is involved; the session is a tshark-less ("passive") live session.
func (i *Ingest) PushFlows(stream grpc.ClientStreamingServer[trafficv1.FlowBatch, trafficv1.PushAck]) error {
	ctx := stream.Context()
	var accepted uint32
	analyses := map[string]string{} // session id -> analysis id (created once)

	for {
		batch, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		sid := batch.GetSessionId()
		if sid == "" {
			return status.Error(codes.InvalidArgument, "FlowBatch.session_id required")
		}
		ls := i.hub.startPassive(sid)

		aid, ok := analyses[sid]
		if !ok {
			aid = uuid.NewString()
			if err := i.st.CreateAnalysis(ctx, store.NewAnalysis{ID: aid, SessionID: sid, Engine: "mitmproxy"}); err != nil {
				return status.Errorf(codes.Internal, "create analysis: %v", err)
			}
			analyses[sid] = aid
		}

		flows := batch.GetFlows()
		dflows := make([]*decode.Flow, 0, len(flows))
		for _, pf := range flows {
			if pf.GetId() == "" {
				pf.Id = uuid.NewString() // keep persisted + live ids in sync
			}
			dflows = append(dflows, protoToDecodeFlow(pf))
		}
		if _, err := i.st.InsertFlows(ctx, sid, aid, dflows); err != nil {
			return status.Errorf(codes.Internal, "insert flows: %v", err)
		}
		for _, pf := range flows {
			ls.publish(pf, true)
		}
		accepted += uint32(len(flows))
	}
	return stream.SendAndClose(&trafficv1.PushAck{Accepted: accepted})
}

// protoToDecodeFlow converts a pushed proto Flow to the decode.Flow the store
// persists (extracting inline body bytes; pushed bodies are inline).
func protoToDecodeFlow(pf *trafficv1.Flow) *decode.Flow {
	df := &decode.Flow{
		ID:           pf.GetId(),
		FrameNumber:  pf.GetFrameNumber(),
		TSUnixMicros: pf.GetTsUnixMicros(),
		Method:       pf.GetMethod(),
		Scheme:       pf.GetScheme(),
		Authority:    pf.GetAuthority(),
		Path:         pf.GetPath(),
		Query:        pf.GetQuery(),
		Protocol:     pf.GetProtocol(),
		Status:       pf.GetStatus(),
		SrcAddr:      pf.GetSrcAddr(),
		DstAddr:      pf.GetDstAddr(),
		UserAgent:    pf.GetUserAgent(),
		ContentType:  pf.GetContentType(),
		RequestBytes: pf.GetRequestBytes(),
		TLSDecrypted: pf.GetTlsDecrypted(),
		TCPStream:    pf.GetTcpStream(),
		H2StreamID:   pf.GetH2StreamId(),
		RequestBody:  pf.GetRequestBody().GetInline(),
		ResponseBody: pf.GetResponseBody().GetInline(),
	}
	for _, h := range pf.GetRequestHeaders() {
		df.RequestHeaders = append(df.RequestHeaders, decode.Header{Name: h.GetName(), Value: h.GetValue()})
	}
	for _, h := range pf.GetResponseHeaders() {
		df.ResponseHeaders = append(df.ResponseHeaders, decode.Header{Name: h.GetName(), Value: h.GetValue()})
	}
	return df
}

// CloseSession finalizes a session: record sizes, batch-decode the bundle, and
// return the closed session summary.
func (i *Ingest) CloseSession(ctx context.Context, req *trafficv1.CloseSessionRequest) (*trafficv1.SessionSummary, error) {
	sid := req.GetSessionId()

	// Stop live decode (if any) before the authoritative batch decode.
	i.hub.stop(sid)

	var pcapBytes, keylogBytes int64
	if fi, err := i.obj.Stat(pcapKey(sid)); err == nil {
		pcapBytes = fi.Size
	}
	keylogLocal := ""
	if fi, err := i.obj.Stat(keylogKey(sid)); err == nil && fi.Size > 0 {
		keylogBytes = fi.Size
		keylogLocal, _ = i.obj.LocalPath(keylogKey(sid))
	}
	if err := i.st.SetSessionBytes(ctx, sid, pcapBytes, keylogBytes); err != nil {
		return nil, status.Errorf(codes.Internal, "set sizes: %v", err)
	}

	if pcapBytes > 0 {
		// PACKET source: authoritative batch decode over the finalized pcap.
		pcapLocal, _ := i.obj.LocalPath(pcapKey(sid))
		if _, err := importer.Finalize(ctx, i.st, i.tshark, sid, pcapLocal, keylogLocal); err != nil {
			return nil, status.Errorf(codes.Internal, "finalize: %v", err)
		}
	} else {
		// Supplied/pushed source (PushFlows): flows were persisted incrementally;
		// there's nothing to decode — just mark the session closed with its count.
		n, err := i.st.CountFlows(ctx, sid)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "count flows: %v", err)
		}
		if err := i.st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, n); err != nil {
			return nil, status.Errorf(codes.Internal, "finish session: %v", err)
		}
	}

	sess, err := i.st.GetSession(ctx, sid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get session: %v", err)
	}
	return &trafficv1.SessionSummary{Session: sess}, nil
}
