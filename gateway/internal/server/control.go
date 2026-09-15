package server

import (
	"context"
	"errors"
	"io"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/bundle"
	"github.com/nklyshko/traffic-deck/gateway/internal/importer"
	"github.com/nklyshko/traffic-deck/gateway/internal/logging"
	"github.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"github.com/nklyshko/traffic-deck/gateway/internal/sourcemgr"
	"github.com/nklyshko/traffic-deck/gateway/internal/store"
)

// Control implements trafficv1.ControlServiceServer — annotations, session export, and
// capture control (StartCapture/StopCapture), which it dispatches to the source manager.
// ReDecode is still unwired and falls through to the Unimplemented base.
type Control struct {
	trafficv1.UnimplementedControlServiceServer
	st       *store.Store
	obj      objstore.Store // for pcap import (ImportCapture)
	dataRoot string
	tshark   string              // tshark binary, for a tshark-engine pcap import
	mgr      *sourcemgr.Manager  // nil disables capture control
	svcs     *sourcemgr.Services // nil disables auxiliary services
}

func NewControl(st *store.Store, obj objstore.Store, dataRoot, tshark string, mgr *sourcemgr.Manager, svcs *sourcemgr.Services) *Control {
	return &Control{st: st, obj: obj, dataRoot: dataRoot, tshark: tshark, mgr: mgr, svcs: svcs}
}

// ListServices reports the auxiliary services (MCP, module UIs) and whether each is running.
func (c *Control) ListServices(ctx context.Context, _ *trafficv1.Empty) (*trafficv1.ServiceList, error) {
	if c.svcs == nil {
		return &trafficv1.ServiceList{}, nil
	}
	out := &trafficv1.ServiceList{}
	for _, s := range c.svcs.List() {
		out.Services = append(out.Services, serviceInfo(s))
	}
	return out, nil
}

// StartService launches an auxiliary service (gateway-owned, so it outlives the viewer).
func (c *Control) StartService(ctx context.Context, req *trafficv1.ServiceRequest) (*trafficv1.ServiceInfo, error) {
	if c.svcs == nil {
		return nil, status.Error(codes.Unimplemented, "services are disabled")
	}
	info, err := c.svcs.Start(req.GetName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "start service: %v", err)
	}
	return serviceInfo(info), nil
}

// StopService stops an auxiliary service.
func (c *Control) StopService(ctx context.Context, req *trafficv1.ServiceRequest) (*trafficv1.Empty, error) {
	if c.svcs == nil {
		return nil, status.Error(codes.Unimplemented, "services are disabled")
	}
	if err := c.svcs.Stop(req.GetName()); err != nil {
		return nil, status.Errorf(codes.Internal, "stop service: %v", err)
	}
	return &trafficv1.Empty{}, nil
}

func serviceInfo(s sourcemgr.ServiceInfo) *trafficv1.ServiceInfo {
	return &trafficv1.ServiceInfo{
		Name: s.Name, Label: s.Label, Running: s.Running, Url: s.URL, Detail: s.Detail}
}

// How much of a log's tail GetLog returns by default, and the ceiling on a client request —
// enough to see recent output without shipping a whole rolling file.
const (
	defaultLogTail = 256 << 10
	maxLogTail     = 4 << 20
)

// logEntry pairs a log's stable name and human label with the file backing it.
type logEntry struct{ name, label, path string }

// logCatalog is every log the gateway can serve: its own, then one per capture source and
// per auxiliary/module service. Paths come from the logging package (ChildLog writes each
// child's file there), so GetLog can only ever read a catalogued path — never an arbitrary
// one a client names.
func (c *Control) logCatalog() []logEntry {
	var out []logEntry
	if p := logging.MainLogPath(); p != "" {
		out = append(out, logEntry{name: "gateway", label: "gateway", path: p})
	}
	if c.mgr != nil {
		for _, s := range c.mgr.Sources() {
			out = append(out, logEntry{s.Name, orLabel(s.Label, s.Name), logging.ChildLogPath(s.Name)})
		}
	}
	if c.svcs != nil {
		for _, s := range c.svcs.List() {
			out = append(out, logEntry{s.Name, orLabel(s.Label, s.Name), logging.ChildLogPath(s.Name)})
		}
	}
	return out
}

func orLabel(label, name string) string {
	if label == "" {
		return name
	}
	return label
}

// ListLogs reports the logs that actually exist on disk (a source that never ran has no
// file yet), with each one's current size and last-modified time.
func (c *Control) ListLogs(ctx context.Context, _ *trafficv1.Empty) (*trafficv1.LogList, error) {
	out := &trafficv1.LogList{}
	for _, e := range c.logCatalog() {
		if e.path == "" {
			continue // file logging is off
		}
		fi, err := os.Stat(e.path)
		if err != nil {
			continue // not created yet, or unreadable — simply not listable
		}
		out.Logs = append(out.Logs, &trafficv1.LogInfo{
			Name:           e.name,
			Label:          e.label,
			SizeBytes:      fi.Size(),
			ModifiedUnixMs: fi.ModTime().UnixMilli(),
		})
	}
	return out, nil
}

// GetLog streams the tail of a named log (from ListLogs) in chunks, capped at maxLogTail.
func (c *Control) GetLog(req *trafficv1.GetLogRequest, srv grpc.ServerStreamingServer[trafficv1.LogChunk]) error {
	var path string
	for _, e := range c.logCatalog() {
		if e.name == req.GetName() {
			path = e.path
			break
		}
	}
	if path == "" {
		return status.Errorf(codes.NotFound, "log %q not found", req.GetName())
	}
	max := req.GetMaxBytes()
	if max <= 0 {
		max = defaultLogTail
	}
	if max > maxLogTail {
		max = maxLogTail
	}
	b, err := logging.ReadTail(path, max)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return status.Errorf(codes.NotFound, "log %q not found", req.GetName())
		}
		return status.Errorf(codes.Internal, "read log %q: %v", req.GetName(), err)
	}
	const chunk = 64 << 10
	for off := 0; off < len(b); off += chunk {
		end := off + chunk
		if end > len(b) {
			end = len(b)
		}
		if err := srv.Send(&trafficv1.LogChunk{Payload: b[off:end]}); err != nil {
			return err
		}
	}
	return nil
}

// ListCaptureSources enumerates the sources the gateway can drive, for the viewer's picker.
func (c *Control) ListCaptureSources(ctx context.Context, _ *trafficv1.Empty) (*trafficv1.CaptureSourceList, error) {
	if c.mgr == nil {
		return &trafficv1.CaptureSourceList{}, nil
	}
	out := &trafficv1.CaptureSourceList{}
	for _, s := range c.mgr.Sources() {
		out.Sources = append(out.Sources, &trafficv1.CaptureSourceInfo{
			Name: s.Name, Label: s.Label, KeepWarm: s.KeepWarm})
	}
	return out, nil
}

// DescribeCaptureSource returns a source's option form for the partial selection so far,
// re-called by the viewer as fields fill in (cascading).
func (c *Control) DescribeCaptureSource(ctx context.Context, req *trafficv1.DescribeCaptureSourceRequest) (*trafficv1.SourceDescriptor, error) {
	if c.mgr == nil {
		return nil, status.Error(codes.Unimplemented, "capture control is disabled")
	}
	if req.GetSource() == "" {
		return nil, status.Error(codes.InvalidArgument, "describe: source is required")
	}
	d, err := c.mgr.Describe(ctx, req.GetSource(), req.GetParams())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "describe %s: %v", req.GetSource(), err)
	}
	return d, nil
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

// ImportCapture decodes a pre-captured pcap (+ optional key.log) already on the gateway
// host with the chosen engine and registers the session — the gRPC face of the `gateway
// import` CLI, so a viewer (TUI, MCP) can import without shelling out. Paths resolve on the
// gateway host (the local host under one-command mode).
func (c *Control) ImportCapture(ctx context.Context, req *trafficv1.ImportCaptureRequest) (*trafficv1.ImportCaptureResponse, error) {
	if req.GetPcapPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "import capture: pcap_path is required")
	}
	res, err := importer.Import(ctx, c.st, c.obj, importer.Options{
		PcapPath:   req.GetPcapPath(),
		KeylogPath: req.GetKeylogPath(),
		Label:      req.GetLabel(),
		TsharkPath: c.tshark,
		Engine:     req.GetEngine(),
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "import capture: %v", err)
	}
	sess, err := c.st.GetSession(ctx, res.SessionID)
	if err != nil {
		return nil, storeStatus(err, "import capture")
	}
	return &trafficv1.ImportCaptureResponse{Session: sess}, nil
}

// GetSessionArtifacts reports where a session's pcap + key.log sit on the gateway host,
// for a viewer that wants to open them in an external analyzer (the TUI's "open in
// Wireshark"). Absent, empty, or non-local artifacts come back as empty paths rather than
// an error — the session itself still exists, it just has nothing to hand over.
func (c *Control) GetSessionArtifacts(ctx context.Context, req *trafficv1.GetSessionArtifactsRequest) (*trafficv1.SessionArtifacts, error) {
	sid := req.GetSessionId()
	if sid == "" {
		return nil, status.Error(codes.InvalidArgument, "get session artifacts: session_id required")
	}
	if _, err := c.st.GetSession(ctx, sid); err != nil {
		return nil, ctrlErr("get session artifacts", err)
	}
	host, _ := os.Hostname()
	out := &trafficv1.SessionArtifacts{Hostname: host}
	out.PcapPath, out.PcapBytes = c.localArtifact(pcapKey(sid))
	out.KeylogPath, out.KeylogBytes = c.localArtifact(keylogKey(sid))
	return out, nil
}

// localArtifact resolves a bundle object to an on-disk path, if the object store is
// filesystem-backed and the file exists with content. An S3-backed store (or a missing
// artifact) yields ("", 0).
func (c *Control) localArtifact(key string) (string, uint64) {
	path, ok := c.obj.LocalPath(key)
	if !ok {
		return "", 0
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		return "", 0
	}
	return path, uint64(fi.Size())
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
