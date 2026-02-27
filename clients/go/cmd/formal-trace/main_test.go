package main

import (
	"crypto/sha3"
	"os"
	"path/filepath"
	"testing"
)

func TestListFixtureNamesSortedAndFiltered(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	// Should include:
	mustWrite("CV-B.json", `{"gate":"CV-PARSE"}`)
	mustWrite("CV-A.json", `{"gate":"CV-PARSE"}`)
	// Should ignore:
	mustWrite("not-a-fixture.json", `{}`)
	if err := os.Mkdir(filepath.Join(dir, "CV-DIR.json"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	names, err := listFixtureNames(dir)
	if err != nil {
		t.Fatalf("listFixtureNames: %v", err)
	}
	if len(names) != 2 || names[0] != "CV-A.json" || names[1] != "CV-B.json" {
		t.Fatalf("unexpected names: %#v", names)
	}
}

func TestReadFixtureFileDirFS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "CV-X.json")
	want := []byte(`{"gate":"CV-PARSE"}`)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := readFixtureFile(dir, "CV-X.json")
	if err != nil {
		t.Fatalf("readFixtureFile: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("read mismatch: got=%q want=%q", string(got), string(want))
	}
}

func TestDigestFixturesDeterministicAndSensitive(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("CV-A.json", `{"gate":"CV-PARSE","vectors":[{"id":"A"}]}`)
	write("CV-B.json", `{"gate":"CV-SIGHASH","vectors":[{"id":"B"}]}`)

	d1, err := digestFixtures(dir)
	if err != nil {
		t.Fatalf("digestFixtures: %v", err)
	}
	d2, err := digestFixtures(dir)
	if err != nil {
		t.Fatalf("digestFixtures: %v", err)
	}
	if d1 != d2 {
		t.Fatalf("digest not deterministic: d1=%s d2=%s", d1, d2)
	}

	// Mutate one file content: digest MUST change.
	write("CV-B.json", `{"gate":"CV-SIGHASH","vectors":[{"id":"B2"}]}`)
	d3, err := digestFixtures(dir)
	if err != nil {
		t.Fatalf("digestFixtures: %v", err)
	}
	if d3 == d1 {
		t.Fatalf("digest did not change after content change: d1=%s d3=%s", d1, d3)
	}

	// Sanity: digest is a SHA3-256 hex string.
	if len(d1) != sha3.New256().Size()*2 {
		t.Fatalf("unexpected digest length: %d", len(d1))
	}
}

