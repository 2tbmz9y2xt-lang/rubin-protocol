//go:build unix

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLoadFromKeyDERReadsFromKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "from-key.hex")
	if err := os.WriteFile(path, []byte("00\n"), 0o600); err != nil {
		t.Fatalf("WriteFile from-key: %v", err)
	}

	der, err := loadFromKeyDER("", path)
	if err != nil {
		t.Fatalf("loadFromKeyDER: %v", err)
	}
	if !bytes.Equal(der, []byte{0x00}) {
		t.Fatalf("der=%x, want 00", der)
	}
}

func TestRunRejectsUnreadableFromKeyFile(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--from-key-file", filepath.Join(t.TempDir(), "missing.hex"),
		"--to-key", "00",
		"--amount", "1",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("missing from-key-file exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "invalid from-key-file: read from-key-file") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestOpenRegularFromKeyFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.hex")
	if err := os.WriteFile(target, []byte("00"), 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	link := filepath.Join(dir, "from-key.hex")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	f, err := openRegularFromKeyFile(link)
	if err == nil {
		_ = f.Close()
		t.Fatal("expected symlink rejection")
	}
	if !strings.Contains(err.Error(), "from-key-file must be a regular file") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRejectsNonRegularFromKeyFile(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--from-key-file", t.TempDir(),
		"--to-key", "00",
		"--amount", "1",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("non-regular from-key-file exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "invalid from-key-file: from-key-file must be a regular file") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunRejectsFIFOFromKeyFileWithoutBlocking(t *testing.T) {
	fifoPath := filepath.Join(t.TempDir(), "from-key.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	dataDir := t.TempDir()

	done := make(chan string, 1)
	go func() {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := run([]string{
			"--datadir", dataDir,
			"--from-key-file", fifoPath,
			"--to-key", "00",
			"--amount", "1",
		}, &stdout, &stderr)
		done <- fmt.Sprintf("%d:%s", code, stderr.String())
	}()

	select {
	case got := <-done:
		if !strings.HasPrefix(got, "2:") {
			t.Fatalf("fifo from-key-file result=%q", got)
		}
		if !strings.Contains(got, "invalid from-key-file: from-key-file must be a regular file") {
			t.Fatalf("fifo from-key-file stderr=%q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run blocked opening FIFO from-key-file")
	}
}

func TestLoadFromKeyDERRejectsOversizedFromKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "from-key.hex")
	if err := os.WriteFile(path, bytes.Repeat([]byte("0"), maxFromKeyFileBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile oversized from-key: %v", err)
	}

	_, err := loadFromKeyDER("", path)
	if err == nil {
		t.Fatal("expected oversized from-key-file error")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("from-key-file exceeds %d bytes", maxFromKeyFileBytes)) {
		t.Fatalf("err=%v", err)
	}
}
