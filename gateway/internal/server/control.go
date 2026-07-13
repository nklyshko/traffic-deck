package server

import (
	"context"
	"errors"
	"io"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/bundle"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/sourcemgr"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// Control implements trafficv1.ControlServiceServer — annotations, session export, and
// capture control (StartCapture/StopCapture), which it dispatches to the source manager.
// ReDecode is still unwired and falls through to the Unimplemented base.
type Control struct {
	trafficv1.UnimplementedControlServiceServer
	st       *store.Store
	dataRoot string
	mgr      *sourcemgr.Manager // nil disables capture control
}

func NewControl(st *store.Store, dataRoot string, mgr *sourcemgr.Manager) *Control {
	return &Control{st: st, dataRoot: dataRoot, mgr: mgr}
}

// StartCapture launches (or reuses) the named source and starts a capture, returning the
// opened session id. The source name comes from StartCaptureRequest.source.
func (c *Control) StartCapture(ctx context.Context, req *trafficv1.StartCaptureRequest) (*trafficv1.StartCaptureResponse, error) {
	if c.mgr == nil {
		return nil, status.Error(codes.Unimplemented, "capture control is disabled")
	}
	if req.GetSource() == "" {
		return nil, status.Error(codes.InvalidArgument, "start capture: source is required")
	}
	sid, err := c.mgr.StartCapture(ctx, req.GetSource(), req.GetLabel(), req.GetParams())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "start capture: %v", err)
	}
	return &trafficv1.StartCaptureResponse{SessionId: sid}, nil
}

// StopCapture ends a running capture by session id, routing to the source that started it,
// and returns the finalized session.
func (c *Control) StopCapture(ctx context.Context, req *trafficv1.StopCaptureRequest) (*trafficv1.StopCaptureResponse, error) {
	if c.mgr == nil {
		return nil, status.Error(codes.Unimplemented, "capture control is disabled")
	}
	if err := c.mgr.StopCapture(ctx, req.GetSessionId()); err != nil {
		return nil, status.Errorf(codes.Internal, "stop capture: %v", err)
	}
	sess, err := c.st.GetSession(ctx, req.GetSessionId())
	if err != nil {
		return &trafficv1.StopCaptureResponse{}, nil // stopped, but the row isn't readable yet
	}
	return &trafficv1.StopCaptureResponse{Session: sess}, nil
}

// ExportSession streams a session's bundle as a .tar.gz. The archive is
// produced on the fly and chunked over the stream.
func (c *Control) ExportSession(req *trafficv1.ExportSessionRequest, srv grpc.ServerStreamingServer[trafficv1.ExportChunk]) error {
	w := &exportChunkWriter{srv: srv}
	err := bundle.Export(srv.Context(), c.st, c.dataRoot, req.GetSessionId(), w)
	if errors.Is(err, store.ErrNotFound) {
		return status.Errorf(codes.NotFound, "export session: session %s not found", req.GetSessionId())
	}
	if err != nil {
		return storeStatus(err, "export session")
	}
	return nil
}

// exportChunkWriter adapts the export stream to io.Writer, splitting writes into
// bounded gRPC messages.
type exportChunkWriter struct {
	srv grpc.ServerStreamingServer[trafficv1.ExportChunk]
}

func (w *exportChunkWriter) Write(p []byte) (int, error) {
	const max = 64 << 10
	for off := 0; off < len(p); off += max {
		end := min(off+max, len(p))
		if err := w.srv.Send(&trafficv1.ExportChunk{Data: p[off:end]}); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

func ctrlErr(what string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return status.Errorf(codes.NotFound, "%s: not found", what)
	case errors.Is(err, store.ErrProtected):
		return status.Errorf(codes.InvalidArgument, "%s: protected object", what)
	case errors.Is(err, store.ErrSchemaOutdated):
		return status.Errorf(codes.FailedPrecondition, "%s: %v", what, err)
	case err != nil:
		return status.Errorf(codes.Internal, "%s: %v", what, err)
	}
	return nil
}

var empty = &trafficv1.Empty{}

// --- tags ---

func (c *Control) CreateTag(ctx context.Context, req *trafficv1.CreateTagRequest) (*trafficv1.Tag, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "tag name required")
	}
	t, err := c.st.CreateTag(ctx, req.GetName(), req.GetColor())
	return t, ctrlErr("create tag", err)
}

func (c *Control) DeleteTag(ctx context.Context, req *trafficv1.DeleteTagRequest) (*trafficv1.Empty, error) {
	return empty, ctrlErr("delete tag", c.st.DeleteTag(ctx, req.GetId()))
}

func (c *Control) ListTags(ctx context.Context, _ *trafficv1.ListTagsRequest) (*trafficv1.TagList, error) {
	tags, err := c.st.ListTags(ctx)
	if err != nil {
		return nil, ctrlErr("list tags", err)
	}
	return &trafficv1.TagList{Tags: tags}, nil
}

func (c *Control) SetTags(ctx context.Context, req *trafficv1.SetTagsRequest) (*trafficv1.Empty, error) {
	err := c.st.SetTags(ctx, req.GetSessionId(), req.GetRecordIds(), req.GetAddTagIds(), req.GetRemoveTagIds())
	return empty, ctrlErr("set tags", err)
}

func (c *Control) ToggleFavorite(ctx context.Context, req *trafficv1.ToggleFavoriteRequest) (*trafficv1.Empty, error) {
	return empty, ctrlErr("toggle favorite", c.st.ToggleFavorite(ctx, req.GetSessionId(), req.GetRecordIds()))
}

// --- comments ---

func (c *Control) AddComment(ctx context.Context, req *trafficv1.AddCommentRequest) (*trafficv1.Comment, error) {
	cm, err := c.st.AddComment(ctx, req.GetSessionId(), req.GetRecordId(), req.GetBody())
	return cm, ctrlErr("add comment", err)
}

func (c *Control) EditComment(ctx context.Context, req *trafficv1.EditCommentRequest) (*trafficv1.Comment, error) {
	cm, err := c.st.EditComment(ctx, req.GetSessionId(), req.GetId(), req.GetBody())
	return cm, ctrlErr("edit comment", err)
}

func (c *Control) DeleteComment(ctx context.Context, req *trafficv1.DeleteCommentRequest) (*trafficv1.Empty, error) {
	return empty, ctrlErr("delete comment", c.st.DeleteComment(ctx, req.GetSessionId(), req.GetId()))
}

// --- color marks ---

func (c *Control) SetMark(ctx context.Context, req *trafficv1.SetMarkRequest) (*trafficv1.Empty, error) {
	return empty, ctrlErr("set mark", c.st.SetMark(ctx, req.GetSessionId(), req.GetRecordIds(), req.GetColor()))
}

func (c *Control) ClearMark(ctx context.Context, req *trafficv1.ClearMarkRequest) (*trafficv1.Empty, error) {
	return empty, ctrlErr("clear mark", c.st.ClearMark(ctx, req.GetSessionId(), req.GetRecordIds()))
}

func (c *Control) SetSessionGroup(ctx context.Context, req *trafficv1.SetSessionGroupRequest) (*trafficv1.Empty, error) {
	if req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id required")
	}
	return empty, ctrlErr("set session group", c.st.SetSessionGroup(ctx, req.GetSessionId(), req.GetGroup()))
}

func (c *Control) SetSessionLabel(ctx context.Context, req *trafficv1.SetSessionLabelRequest) (*trafficv1.Empty, error) {
	if req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id required")
	}
	return empty, ctrlErr("set session label", c.st.SetSessionLabel(ctx, req.GetSessionId(), req.GetLabel()))
}

func (c *Control) DeleteSession(ctx context.Context, req *trafficv1.DeleteSessionRequest) (*trafficv1.Empty, error) {
	if req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id required")
	}
	return empty, ctrlErr("delete session", c.st.DeleteSession(ctx, req.GetSessionId()))
}

// ImportSession receives a streamed .tar.gz session bundle, extracts it under a fresh id,
// and returns the imported session. The upload is buffered to a temp file so the bundle
// reader can seek/stream it.
func (c *Control) ImportSession(stream grpc.ClientStreamingServer[trafficv1.ImportChunk, trafficv1.ImportSessionResponse]) error {
	ctx := stream.Context()
	tmp, err := os.CreateTemp("", "td-import-*.tar.gz")
	if err != nil {
		return status.Errorf(codes.Internal, "import session: temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if _, err := tmp.Write(chunk.GetData()); err != nil {
			return status.Errorf(codes.Internal, "import session: write: %v", err)
		}
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return status.Errorf(codes.Internal, "import session: %v", err)
	}
	sid, err := bundle.Import(ctx, c.st, c.dataRoot, tmp, bundle.ImportOptions{NewID: true})
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "import session: %v", err)
	}
	sess, err := c.st.GetSession(ctx, sid)
	if err != nil {
		return storeStatus(err, "import session")
	}
	return stream.SendAndClose(&trafficv1.ImportSessionResponse{Session: sess})
}

// --- groups ---

func (c *Control) CreateGroup(ctx context.Context, req *trafficv1.CreateGroupRequest) (*trafficv1.Group, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "group name required")
	}
	g, err := c.st.CreateGroup(ctx, req.GetName(), req.GetColor(), req.GetParentId())
	return g, ctrlErr("create group", err)
}

func (c *Control) UpdateGroup(ctx context.Context, req *trafficv1.UpdateGroupRequest) (*trafficv1.Group, error) {
	g, err := c.st.UpdateGroup(ctx, req.GetId(), req.GetName(), req.GetColor(), req.GetParentId())
	return g, ctrlErr("update group", err)
}

func (c *Control) DeleteGroup(ctx context.Context, req *trafficv1.DeleteGroupRequest) (*trafficv1.Empty, error) {
	return empty, ctrlErr("delete group", c.st.DeleteGroup(ctx, req.GetId()))
}

func (c *Control) ListGroups(ctx context.Context, _ *trafficv1.ListGroupsRequest) (*trafficv1.GroupList, error) {
	groups, err := c.st.ListGroups(ctx)
	if err != nil {
		return nil, ctrlErr("list groups", err)
	}
	return &trafficv1.GroupList{Groups: groups}, nil
}

func (c *Control) SetGroups(ctx context.Context, req *trafficv1.SetGroupsRequest) (*trafficv1.Empty, error) {
	err := c.st.SetGroups(ctx, req.GetSessionId(), req.GetRecordIds(), req.GetAddGroupIds(), req.GetRemoveGroupIds())
	return empty, ctrlErr("set groups", err)
}
