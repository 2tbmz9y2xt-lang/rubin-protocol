//go:build !unix

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFromKeyDERRejectsFromKeyFileUnsupported(t *testing.T) {
	_, err := loadFromKeyDER("", filepath.Join(t.TempDir(), "from-key.hex"))
	if err == nil {
		t.Fatal("expected unsupported from-key-file error")
	}
	if !strings.Contains(err.Error(), "from-key-file unsupported on this platform") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRejectsFromKeyFileUnsupported(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--from-key-file", filepath.Join(t.TempDir(), "from-key.hex"),
		"--to-key", "00",
		"--amount", "1",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unsupported from-key-file exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "invalid from-key: from-key-file unsupported on this platform") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
