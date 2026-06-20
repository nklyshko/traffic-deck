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
	"github.com/nikitak/parsing/traffic-gateway/internal/importer"
	"github.com/nikitak/parsing/traffic-gateway/internal/objstore"
	"github.com/nikitak/parsing/traffic-gateway/internal/store"
)

const maxChunkBytes = 1 << 20 // advertised upload chunk size

// Ingest implements trafficv1.IngestServiceServer.
//
// Phase 2 step 1: streamed capture upload with decode-on-close (BATCH_ON_CLOSE).
// Live streaming decode is a later step.
type Ingest struct {
	trafficv1.UnimplementedIngestServiceServer
	st     *store.Store
	obj    objstore.Store
	tshark string
}

func NewIngest(st *store.Store, obj objstore.Store, tshark string) *Ingest {
	return &Ingest{st: st, obj: obj, tshark: tshark}
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
	return &trafficv1.SessionHandle{SessionId: sid, MaxChunkBytes: maxChunkBytes}, nil
}

// UploadCapture streams pcap + key.log chunks into the session bundle, writing
// each at its byte offset (ordered, resumable). Decode happens on CloseSession.
func (i *Ingest) UploadCapture(stream grpc.ClientStreamingServer[trafficv1.CaptureChunk, trafficv1.UploadAck]) error {
	var sid, uploadID string
	var pcapN, keylogN uint64

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
			}
		case *trafficv1.CaptureChunk_End:
			// terminal frame; loop will exit on EOF
		}
	}
	return stream.SendAndClose(&trafficv1.UploadAck{
		UploadId: uploadID, PcapReceived: pcapN, KeylogReceived: keylogN,
	})
}

// CloseSession finalizes a session: record sizes, batch-decode the bundle, and
// return the closed session summary.
func (i *Ingest) CloseSession(ctx context.Context, req *trafficv1.CloseSessionRequest) (*trafficv1.SessionSummary, error) {
	sid := req.GetSessionId()

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

	pcapLocal, _ := i.obj.LocalPath(pcapKey(sid))
	if _, err := importer.Finalize(ctx, i.st, i.tshark, sid, pcapLocal, keylogLocal); err != nil {
		return nil, status.Errorf(codes.Internal, "finalize: %v", err)
	}

	sess, err := i.st.GetSession(ctx, sid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get session: %v", err)
	}
	return &trafficv1.SessionSummary{Session: sess}, nil
}
