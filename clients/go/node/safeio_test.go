package node

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileFromDirRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	if _, err := readFileFromDir(dir, "../x"); err == nil {
		t.Fatalf("expected error for traversal name")
	}
	if _, err := readFileFromDir(dir, ".."); err == nil {
		t.Fatalf("expected error for ..")
	}
	if _, err := readFileFromDir(dir, ""); err == nil {
		t.Fatalf("expected error for empty name")
	}
}

func TestReadFileFromDirReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.bin")
	if err := os.WriteFile(path, []byte("hi"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := readFileFromDir(dir, "ok.bin")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(b) != "hi" {
		t.Fatalf("unexpected bytes: %q", string(b))
	}
}
