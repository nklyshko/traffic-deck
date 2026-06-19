package objstore

import (
	"io"
	"strings"
	"testing"
)

func TestPutOpenStat(t *testing.T) {
	s, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("sessions/a/capture.pcap", strings.NewReader("hello")); err != nil {
		t.Fatal(err)
	}
	fi, err := s.Stat("sessions/a/capture.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size != 5 {
		t.Fatalf("size = %d, want 5", fi.Size)
	}
	r, err := s.Open("sessions/a/capture.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, _ := io.ReadAll(r)
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestWriteAtOrdering(t *testing.T) {
	s, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Out-of-order chunked writes, as offset-tagged DataChunks may arrive.
	if err := s.WriteAt("k", []byte("world"), 5); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteAt("k", []byte("hello"), 0); err != nil {
		t.Fatal(err)
	}
	r, _ := s.Open("k")
	defer r.Close()
	got, _ := io.ReadAll(r)
	if string(got) != "helloworld" {
		t.Fatalf("got %q, want helloworld", got)
	}
}

func TestRejectsTraversal(t *testing.T) {
	s, _ := NewFSStore(t.TempDir())
	if _, err := s.Put("../escape", strings.NewReader("x")); err != ErrInvalidKey {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}
