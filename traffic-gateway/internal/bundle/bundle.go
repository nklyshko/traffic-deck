// Package bundle exports and imports whole session bundles as self-contained
// .tar.gz archives (plan §10). A bundle is portable on its own: tag/group defs are
// mirrored into flows.sqlite (store §annotations), so the archive carries the
// catalog row (manifest.json) plus the per-session files.
//
// Archive layout:
//
//	manifest.json          — Manifest (format + catalog SessionRow)
//	flows.sqlite           — VACUUM INTO snapshot of the session DB
//	capture.pcap           — raw capture (omitted if absent/empty)
//	key.log                — TLS keylog   (omitted if absent/empty)
//	blobs/<sha256>         — spilled large bodies (one file each, if any)
package bundle

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nikitak/parsing/traffic-gateway/internal/store"
)

// FormatV1 identifies the archive format in the manifest.
const FormatV1 = "traffic-session/v1"

const manifestName = "manifest.json"

// Manifest is the archive's metadata entry (always the first tar member).
type Manifest struct {
	Format           string            `json:"format"`
	ExportedAtUnixMs int64             `json:"exported_at_unix_ms"`
	Session          *store.SessionRow `json:"session"`
}

// Export writes a session's bundle as a gzip-compressed tar to w. The store
// provides the catalog row and a consistent flows.sqlite snapshot; pcap/key.log/blobs
// are read from the data root. Returns ErrNotFound (via store) for an unknown session.
func Export(ctx context.Context, st *store.Store, dataRoot, sessionID string, w io.Writer) error {
	row, err := st.ExportSessionRow(ctx, sessionID)
	if err != nil {
		return err
	}

	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	mf := Manifest{Format: FormatV1, ExportedAtUnixMs: nowUnixMs(), Session: row}
	mfBytes, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return err
	}
	if err := writeTar(tw, manifestName, mfBytes); err != nil {
		return err
	}

	// flows.sqlite: VACUUM INTO a temp file (a clean snapshot), then stream it in.
	tmp, err := os.CreateTemp("", "flows-*.sqlite")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	os.Remove(tmpPath) // VACUUM INTO requires the destination not to exist
	defer os.Remove(tmpPath)
	if err := st.SnapshotSessionDB(ctx, sessionID, tmpPath); err != nil {
		return fmt.Errorf("snapshot flows.sqlite: %w", err)
	}
	if err := copyFileToTar(tw, "flows.sqlite", tmpPath); err != nil {
		return err
	}

	bundleDir := filepath.Join(dataRoot, "sessions", sessionID)
	for _, name := range []string{"capture.pcap", "key.log"} {
		p := filepath.Join(bundleDir, name)
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			if err := copyFileToTar(tw, name, p); err != nil {
				return err
			}
		}
	}

	blobsDir := filepath.Join(bundleDir, "blobs")
	entries, _ := os.ReadDir(blobsDir) // absent dir → no spilled blobs
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := copyFileToTar(tw, path.Join("blobs", e.Name()), filepath.Join(blobsDir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// ImportOptions tunes an import.
type ImportOptions struct {
	NewID bool   // assign a fresh session id (use when the original id collides)
	Label string // override the session label (empty: keep the manifest's)
}

// Import reads a .tar.gz bundle from r, extracts it under dataRoot, and registers the
// session in the catalog. Returns the resulting session id. By default it keeps the
// manifest's id and fails if it already exists; with NewID it remaps to a fresh id.
func Import(ctx context.Context, st *store.Store, dataRoot string, r io.Reader, opts ImportOptions) (string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return "", fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	// The manifest is always the first member; read it to learn the target id/dir.
	hdr, err := tr.Next()
	if err != nil || hdr.Name != manifestName {
		return "", fmt.Errorf("not a session bundle: missing %s", manifestName)
	}
	mfBytes, err := io.ReadAll(tr)
	if err != nil {
		return "", err
	}
	var mf Manifest
	if err := json.Unmarshal(mfBytes, &mf); err != nil {
		return "", fmt.Errorf("parse manifest: %w", err)
	}
	if mf.Format != FormatV1 || mf.Session == nil {
		return "", fmt.Errorf("unsupported bundle format %q", mf.Format)
	}

	oldID := mf.Session.ID
	targetID := oldID
	if opts.NewID {
		targetID = uuid.NewString()
	}
	exists, err := st.SessionExists(ctx, targetID)
	if err != nil {
		return "", err
	}
	if exists {
		return "", fmt.Errorf("session %s already exists (use --new-id to import a copy)", targetID)
	}

	destDir := filepath.Join(dataRoot, "sessions", targetID)
	if err := os.MkdirAll(filepath.Join(destDir, "blobs"), 0o755); err != nil {
		return "", err
	}
	cleanup := func() { os.RemoveAll(destDir) }

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return "", err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel, ok := safeMember(hdr.Name)
		if !ok {
			cleanup()
			return "", fmt.Errorf("unsafe bundle member %q", hdr.Name)
		}
		out := filepath.Join(destDir, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			cleanup()
			return "", err
		}
		if err := writeFile(out, tr); err != nil {
			cleanup()
			return "", err
		}
	}

	mf.Session.ID = targetID
	if opts.Label != "" {
		mf.Session.Label = opts.Label
	}
	if opts.NewID {
		if err := store.RewriteSessionID(ctx, filepath.Join(destDir, "flows.sqlite"), oldID, targetID); err != nil {
			cleanup()
			return "", fmt.Errorf("rebind session id: %w", err)
		}
	}
	if err := st.ImportSessionRow(ctx, mf.Session); err != nil {
		cleanup()
		return "", fmt.Errorf("register session: %w", err)
	}
	if err := st.MergeBundleDefsIntoCatalog(ctx, targetID); err != nil {
		// Non-fatal: the bundle is usable; tag/group palette merge is best-effort.
		return targetID, fmt.Errorf("imported %s but merging tag/group defs failed: %w", targetID, err)
	}
	return targetID, nil
}

// safeMember validates an archive member name and returns its cleaned relative path.
// Only the known top-level files and blobs/<name> are allowed; anything with a path
// traversal or an unexpected location is rejected.
func safeMember(name string) (string, bool) {
	clean := path.Clean("/" + name)[1:] // strip leading slash, normalize
	if clean == "" || strings.Contains(clean, "..") {
		return "", false
	}
	switch clean {
	case "flows.sqlite", "capture.pcap", "key.log":
		return clean, true
	}
	if dir, file := path.Split(clean); dir == "blobs/" && file != "" {
		return clean, true
	}
	return "", false
}

func writeTar(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func copyFileToTar(tw *tar.Writer, name, srcPath string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: fi.Size()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func nowUnixMs() int64 { return time.Now().UnixMilli() }

func writeFile(dest string, r io.Reader) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, r)
	return err
}
