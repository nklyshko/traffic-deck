package store

// Prepared-statement reuse for the bulk insert paths. The driver (modernc.org/sqlite)
// is pure Go, so parsing SQL is expensive relative to executing it — and persisting a
// large session issues millions of statements from a handful of distinct queries. Left
// unprepared, that parse cost dominates the close-time persist.

import (
	"context"
	"database/sql"
	"strings"
)

// txStmts prepares each distinct SQL statement once per transaction and reuses it for
// every subsequent exec of the same query. Not safe for concurrent use; a txStmts
// belongs to the one goroutine driving its transaction.
type txStmts struct {
	ctx   context.Context
	tx    *sql.Tx
	cache map[string]*sql.Stmt
}

func newTxStmts(ctx context.Context, tx *sql.Tx) *txStmts {
	return &txStmts{ctx: ctx, tx: tx, cache: make(map[string]*sql.Stmt)}
}

// exec runs query with args, preparing it on first use.
func (t *txStmts) exec(query string, args ...any) error {
	stmt, ok := t.cache[query]
	if !ok {
		var err error
		if stmt, err = t.tx.PrepareContext(t.ctx, query); err != nil {
			return err
		}
		t.cache[query] = stmt
	}
	_, err := stmt.ExecContext(t.ctx, args...)
	return err
}

// close releases the prepared statements. Statements prepared on a transaction are
// closed by Commit/Rollback anyway, so this is belt-and-braces; call it deferred.
func (t *txStmts) close() {
	for _, s := range t.cache {
		_ = s.Close()
	}
	clear(t.cache)
}

// headerChunk is the most flow_headers rows written per statement. Headers are the
// highest-volume side table (tens of rows per flow), so they go in as multi-row
// INSERTs rather than one statement each; chunking bounds both the bound-parameter
// count and the number of distinct statements prepared.
const headerChunk = 64

// headerInsertSQL[n] is a flow_headers INSERT for exactly n rows (index 0 unused).
// Precomputed so the hot path neither builds nor re-parses the SQL.
var headerInsertSQL = func() [headerChunk + 1]string {
	var out [headerChunk + 1]string
	for n := 1; n <= headerChunk; n++ {
		var b strings.Builder
		b.WriteString(`INSERT INTO flow_headers (flow_id, direction, ord, name, value) VALUES `)
		for i := range n {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`(?,?,?,?,?)`)
		}
		out[n] = b.String()
	}
	return out
}()
