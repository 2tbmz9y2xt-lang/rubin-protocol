package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMustWriteFixtureWritesTrailingNewlineAndTightPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "CV-TEST.json")

	f := &fixtureFile{
		Gate: "CV-TEST",
		Vectors: []map[string]any{
			{"id": "X", "op": "noop"},
		},
	}

	mustWriteFixture(path, f)

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Must not be world/group readable or writable.
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("expected tight perms (no group/other bits), got %o", st.Mode().Perm())
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		t.Fatalf("expected trailing newline")
	}
	var parsed fixtureFile
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if parsed.Gate != "CV-TEST" {
		t.Fatalf("gate mismatch: %q", parsed.Gate)
	}
	if len(parsed.Vectors) != 1 || parsed.Vectors[0]["id"] != "X" {
		t.Fatalf("vectors mismatch: %#v", parsed.Vectors)
	}
}
