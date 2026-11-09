package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

func (s *server) sessions(w http.ResponseWriter, r *http.Request) {
	limit, err := queryUint(r, "limit", 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	offset, err := queryUint(r, "offset", 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.viewer.ListSessions(r.Context(), &trafficv1.ListSessionsRequest{Limit: limit, Offset: offset})
	writeProto(w, "ListSessions", resp, err)
}

func flowsRequest(r *http.Request) (*trafficv1.QueryFlowsRequest, error) {
	q := r.URL.Query()
	req := &trafficv1.QueryFlowsRequest{
		SessionId:     q.Get("session"),
		Filter:        q.Get("filter"),
		Last:          q.Get("last") == "1",
		IncludeHidden: q.Get("hidden") == "1",
	}
	var err error
	if req.Limit, err = queryUint(r, "limit", 250); err != nil {
		return nil, err
	}
	if req.After, err = parseCursor(q.Get("after")); err != nil {
		return nil, err
	}
	if req.Before, err = parseCursor(q.Get("before")); err != nil {
		return nil, err
	}
	if req.SinceMicros, err = queryInt(r, "since"); err != nil {
		return nil, err
	}
	if req.UntilMicros, err = queryInt(r, "until"); err != nil {
		return nil, err
	}
	return req, nil
}

func (s *server) flows(w http.ResponseWriter, r *http.Request) {
	req, err := flowsRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.viewer.QueryFlows(r.Context(), req)
	writeProto(w, "QueryFlows", resp, err)
}

func (s *server) flow(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	resp, err := s.viewer.GetFlow(r.Context(), &trafficv1.GetFlowRequest{SessionId: q.Get("session"), FlowId: q.Get("id")})
	writeProto(w, "GetFlow", resp, err)
}

// message re-reads one frame with its annotations, after the viewer changed them.
func (s *server) message(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	resp, err := s.viewer.GetMessage(r.Context(), &trafficv1.GetMessageRequest{SessionId: q.Get("session"), MessageId: q.Get("id")})
	writeProto(w, "GetMessage", resp, err)
}

func (s *server) body(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stream, err := s.viewer.GetBody(r.Context(), &trafficv1.GetBodyRequest{
		SessionId: q.Get("session"), FlowId: q.Get("id"), Response: q.Get("response") == "1",
	})
	if err != nil {
		rpcError(w, "GetBody", err)
		return
	}
	streamBytes(w, "GetBody", capturedBytes, func() ([]byte, error) {
		c, err := stream.Recv()
		return c.GetPayload(), err
	})
}

func (s *server) messages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	resp, err := s.viewer.ListMessages(r.Context(), &trafficv1.ListMessagesRequest{
		SessionId: q.Get("session"), FlowId: q.Get("flow"), Filter: q.Get("filter"),
	})
	writeProto(w, "ListMessages", resp, err)
}

func (s *server) messageBody(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stream, err := s.viewer.GetMessageBody(r.Context(), &trafficv1.GetMessageBodyRequest{
		SessionId: q.Get("session"), MessageId: q.Get("id"), Raw: q.Get("raw") == "1",
	})
	if err != nil {
		rpcError(w, "GetMessageBody", err)
		return
	}
	streamBytes(w, "GetMessageBody", capturedBytes, func() ([]byte, error) {
		c, err := stream.Recv()
		return c.GetPayload(), err
	})
}

func (s *server) log(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	maxBytes, err := queryInt(r, "max")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stream, err := s.control.GetLog(r.Context(), &trafficv1.GetLogRequest{Name: q.Get("name"), MaxBytes: maxBytes})
	if err != nil {
		rpcError(w, "GetLog", err)
		return
	}
	streamBytes(w, "GetLog", func(h http.Header) {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("X-Content-Type-Options", "nosniff")
	}, func() ([]byte, error) {
		c, err := stream.Recv()
		return c.GetPayload(), err
	})
}

func (s *server) exportSession(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("session")
	stream, err := s.control.ExportSession(r.Context(), &trafficv1.ExportSessionRequest{SessionId: id})
	if err != nil {
		rpcError(w, "ExportSession", err)
		return
	}
	streamBytes(w, "ExportSession", func(h http.Header) {
		h.Set("Content-Type", "application/gzip")
		h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.tar.gz"`, sanitizeFilename(id)))
	}, func() ([]byte, error) {
		c, err := stream.Recv()
		return c.GetData(), err
	})
}

func (s *server) importSession(w http.ResponseWriter, r *http.Request) {
	if !contentTypeIs(r, "application/octet-stream") {
		http.Error(w, "Content-Type must be application/octet-stream", http.StatusUnsupportedMediaType)
		return
	}
	stream, err := s.control.ImportSession(r.Context())
	if err != nil {
		rpcError(w, "ImportSession", err)
		return
	}
	buf := make([]byte, uploadChunk)
	for {
		n, rerr := io.ReadFull(r.Body, buf)
		if n > 0 {
			// EOF here means the gateway ended the stream; CloseAndRecv below has its reason.
			if err := stream.Send(&trafficv1.ImportChunk{Data: append([]byte(nil), buf[:n]...)}); err != nil {
				break
			}
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			http.Error(w, "reading upload: "+rerr.Error(), http.StatusBadRequest)
			return
		}
	}
	resp, err := stream.CloseAndRecv()
	writeProto(w, "ImportSession", resp, err)
}

// --- SSE ---

func (s *server) streamFlows(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stream, err := s.viewer.StreamFlows(r.Context(), &trafficv1.StreamFlowsRequest{
		SessionId: q.Get("session"), Filter: q.Get("filter"), Follow: q.Get("follow") != "0",
		IncludeHidden: q.Get("hidden") == "1",
	})
	if err != nil {
		rpcError(w, "StreamFlows", err)
		return
	}
	serveSSE(w, streamOf(stream))
}

func (s *server) streamMessages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stream, err := s.viewer.StreamMessages(r.Context(), &trafficv1.StreamMessagesRequest{
		SessionId: q.Get("session"), FlowId: q.Get("flow"), Filter: q.Get("filter"), Follow: q.Get("follow") != "0",
	})
	if err != nil {
		rpcError(w, "StreamMessages", err)
		return
	}
	serveSSE(w, streamOf(stream))
}

func streamOf[T any](stream grpc.ServerStreamingClient[T]) func() (proto.Message, error) {
	return func() (proto.Message, error) {
		ev, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		return any(ev).(proto.Message), nil
	}
}

// serveSSE relays gateway events verbatim. It always finishes with `end`: EventSource
// reconnects to anything that merely closes, so a finished session would otherwise be
// re-read forever.
func serveSSE(w http.ResponseWriter, recv func() (proto.Message, error)) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher := http.NewResponseController(w)
	_ = flusher.Flush()
	for {
		ev, err := recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				// A second line in a data field would need its own `data:` prefix.
				fmt.Fprintf(w, "event: error\ndata: %s\n\n", strings.ReplaceAll(err.Error(), "\n", " "))
			}
			fmt.Fprint(w, "event: end\ndata: {}\n\n")
			_ = flusher.Flush()
			return
		}
		data, err := protojson.Marshal(ev)
		if err != nil {
			continue
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return
		}
		_ = flusher.Flush()
	}
}
