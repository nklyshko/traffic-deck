package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestANewDatabaseStartsAtTheLatestVersionWithoutMigrating(t *testing.T) {
	ran := false
	steps := []migration{func(context.Context, *sql.Tx) error { ran = true; return nil }}
	db, err := openVersioned(context.Background(), filepath.Join(t.TempDir(), "x.sqlite"),
		`CREATE TABLE IF NOT EXISTS t (a TEXT)`, steps)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if ran {
		t.Fatal("a migration ran on a new database")
	}
	if v := userVersion(t, db); v != 1 {
		t.Fatalf("user_version = %d, want 1", v)
	}
}

func TestOnlyTheMigrationsPastADatabasesVersionRun(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "x.sqlite")
	schema := `CREATE TABLE IF NOT EXISTS t (a TEXT)`
	db, err := openVersioned(ctx, path, schema, []migration{
		func(context.Context, *sql.Tx) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	var ran []int
	step := func(i int, stmt string) migration {
		return func(ctx context.Context, tx *sql.Tx) error {
			ran = append(ran, i)
			_, err := tx.ExecContext(ctx, stmt)
			return err
		}
	}
	steps := []migration{
		step(1, `SELECT 1`),
		step(2, `ALTER TABLE t ADD COLUMN b TEXT`),
		step(3, `ALTER TABLE t ADD COLUMN c TEXT`),
	}
	db, err = openVersioned(ctx, path, schema, steps)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if len(ran) != 2 || ran[0] != 2 || ran[1] != 3 {
		t.Fatalf("ran %v, want [2 3]", ran)
	}
	if v := userVersion(t, db); v != 3 {
		t.Fatalf("user_version = %d, want 3", v)
	}
	db.Close()

	ran = nil
	db, err = openVersioned(ctx, path, schema, steps)
	if err != nil {
		t.Fatal(err)
	}
	if len(ran) != 0 {
		t.Fatalf("a current database ran %v", ran)
	}
}

func TestAFailedMigrationLeavesTheDatabaseAsItWas(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "x.sqlite")
	schema := `CREATE TABLE IF NOT EXISTS t (a TEXT)`
	db, err := openVersioned(ctx, path, schema, nil)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, err = openVersioned(ctx, path, schema, []migration{
		func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `ALTER TABLE t ADD COLUMN b TEXT`)
			return err
		},
		func(context.Context, *sql.Tx) error { return errors.New("boom") },
	})
	if err == nil {
		t.Fatal("want the migration's error")
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if v := userVersion(t, db); v != 0 {
		t.Fatalf("user_version = %d, want 0", v)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('t') WHERE name = 'b'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("column b kept after a failed migration (n=%d, err=%v)", n, err)
	}
}

func TestADatabaseFromANewerGatewayIsRefused(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, NewSession{ID: "s1", Label: "x"}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	path := filepath.Join(dir, "sessions", "s1", "flows.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.ListFlows(ctx, "s1"); !errors.Is(err, ErrSchemaNewer) {
		t.Fatalf("want ErrSchemaNewer, got %v", err)
	}
	if _, err := st.QuerySQL(ctx, "s1", `SELECT 1`, nil, 0); !errors.Is(err, ErrSchemaNewer) {
		t.Fatalf("QuerySQL: want ErrSchemaNewer, got %v", err)
	}
}
