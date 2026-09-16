package server

// ViewerService.QuerySQL: the read-only SQL escape hatch onto a session bundle. The
// gateway's job here is the deadline and the error mapping — the store owns opening the
// file in a way that cannot write to it.

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/store"
)

// SQL query deadlines. A cross join over a 273k-flow bundle is one keystroke away, and
// an agent writes the keystrokes, so an ad-hoc query gets a deadline the read path does
// not need: the statement is abandoned rather than left holding a connection.
const (
	sqlDefaultTimeout = 10 * time.Second
	sqlMaxTimeout     = 60 * time.Second
)

func (v *Viewer) QuerySQL(ctx context.Context, req *trafficv1.QuerySQLRequest) (*trafficv1.QuerySQLResponse, error) {
	if req.GetSql() == "" {
		return nil, status.Error(codes.InvalidArgument, "query sql: sql required")
	}
	timeout := time.Duration(req.GetTimeoutMillis()) * time.Millisecond
	if timeout <= 0 {
		timeout = sqlDefaultTimeout
	}
	if timeout > sqlMaxTimeout {
		timeout = sqlMaxTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	res, err := v.st.QuerySQL(ctx, req.GetSessionId(), req.GetSql(), req.GetParams(), int(req.GetLimit()))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, status.Error(codes.NotFound, "no such session bundle")
	case errors.Is(err, context.DeadlineExceeded):
		return nil, status.Errorf(codes.DeadlineExceeded,
			"query ran longer than %s — narrow it, add a LIMIT, or raise timeout_millis", timeout)
	case err != nil:
		// A syntax error or an unknown column is the caller's to fix and SQLite's message
		// names the token, so it is handed back verbatim as InvalidArgument rather than
		// flattened into an opaque Internal.
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &trafficv1.QuerySQLResponse{
		Columns:       res.Columns,
		RowsJson:      res.RowsJSON,
		Truncated:     res.Truncated,
		ElapsedMicros: uint64(time.Since(start).Microseconds()),
	}, nil
}
