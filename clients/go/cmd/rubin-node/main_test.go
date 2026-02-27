package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestRunDryRunOK(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(
		[]string{"--dry-run", "--datadir", dir, "--log-level", "INFO"},
		&out,
		&errOut,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}
	if out.Len() == 0 {
		t.Fatalf("expected stdout output")
	}
	// Basic sanity: should have created chainstate file.
	if _, err := os.Stat(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("expected chainstate file to exist: %v", err)
	}
}

func TestRunInvalidConfigMaxPeers(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(
		[]string{"--dry-run", "--datadir", dir, "--max-peers", "0"},
		&out,
		&errOut,
	)
	if code == 0 {
		t.Fatalf("expected non-zero exit code")
	}
}
