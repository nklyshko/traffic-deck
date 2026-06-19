// Package objstore is the gateway's blob storage abstraction (plan §6.2).
//
// v1 is filesystem-backed; a MinIO/S3 impl can replace it behind this interface
// with no schema change. Storing pcap/key.log and assembling pcapng are pure-Go
// byte I/O — no pcap library, no shell (plan §7.1).
package objstore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FileInfo is the subset of stat we need.
type FileInfo struct {
	Size int64
}

// Store is the blob interface used across the gateway.
type Store interface {
	// Put writes r to key, replacing any existing object, and returns bytes written.
	Put(key string, r io.Reader) (int64, error)
	// WriteAt writes p at byte offset off, growing the object as needed.
	// Used for chunked, ordered upload writes (plan §5 DataChunk.offset).
	WriteAt(key string, p []byte, off int64) error
	// Open returns a reader for the whole object.
	Open(key string) (io.ReadCloser, error)
	// Stat reports object metadata.
	Stat(key string) (FileInfo, error)
	// LocalPath returns an on-disk path for key if the backend is local, or
	// ("", false) otherwise. Lets the gateway tee/tail files directly in the
	// single-user-local case (plan §8.1) without round-tripping bytes.
	LocalPath(key string) (string, bool)
}

// ErrInvalidKey is returned for keys that escape the store root.
var ErrInvalidKey = errors.New("objstore: invalid key")

// FSStore is a filesystem-backed Store rooted at Root.
type FSStore struct {
	Root string
}

// NewFSStore creates the root directory if needed and returns a store.
func NewFSStore(root string) (*FSStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &FSStore{Root: abs}, nil
}

// resolve maps a key to an absolute path under Root, rejecting traversal.
func (s *FSStore) resolve(key string) (string, error) {
	norm := strings.ReplaceAll(key, "\\", "/")
	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return "", ErrInvalidKey
		}
	}
	full := filepath.Join(s.Root, filepath.Clean("/"+norm))
	if full != s.Root && !strings.HasPrefix(full, s.Root+string(os.PathSeparator)) {
		return "", ErrInvalidKey
	}
	return full, nil
}

func (s *FSStore) Put(key string, r io.Reader) (int64, error) {
	full, err := s.resolve(key)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return 0, err
	}
	f, err := os.Create(full)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.Copy(f, r)
}

func (s *FSStore) WriteAt(key string, p []byte, off int64) error {
	full, err := s.resolve(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(full, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteAt(p, off)
	return err
}

func (s *FSStore) Open(key string) (io.ReadCloser, error) {
	full, err := s.resolve(key)
	if err != nil {
		return nil, err
	}
	return os.Open(full)
}

func (s *FSStore) Stat(key string) (FileInfo, error) {
	full, err := s.resolve(key)
	if err != nil {
		return FileInfo{}, err
	}
	fi, err := os.Stat(full)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{Size: fi.Size()}, nil
}

func (s *FSStore) LocalPath(key string) (string, bool) {
	full, err := s.resolve(key)
	if err != nil {
		return "", false
	}
	return full, true
}

// compile-time check
var _ Store = (*FSStore)(nil)
