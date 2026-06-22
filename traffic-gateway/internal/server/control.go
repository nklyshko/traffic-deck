package server

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nikitak/parsing/traffic-gateway/gen/traffic/v1"
	"github.com/nikitak/parsing/traffic-gateway/internal/bundle"
	"github.com/nikitak/parsing/traffic-gateway/internal/store"
)

// Control implements trafficv1.ControlServiceServer — annotations and
// session export. Capture control / re-decode (StartCapture/StopCapture/
// ReDecode) are not wired yet and fall through to the Unimplemented base.
type Control struct {
	trafficv1.UnimplementedControlServiceServer
	st       *store.Store
	dataRoot string
}

func NewControl(st *store.Store, dataRoot string) *Control {
	return &Control{st: st, dataRoot: dataRoot}
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
		return status.Errorf(codes.Internal, "export session: %v", err)
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
