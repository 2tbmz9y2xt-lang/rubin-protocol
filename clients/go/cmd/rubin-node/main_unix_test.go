//go:build unix

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// Startup rows that provoke a write failure by chmod'ing the datadir
// read-only. They live in a `//go:build unix` file because os.Geteuid() is
// Unix-only and would prevent main_test.go from compiling under
// GOOS=windows (Copilot review feedback on PR #1218).
//
// Every row here skips as root: root bypasses the mode check on most
// filesystems, so the chmod stops nothing and the row would either assert
// against a write that succeeded or — where the row has no terminator —
// run on into the service loop and hang until the package timeout.

func TestRunStartupFailsWhenChainstateSaveFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based permission check does not apply")
	}
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	store, err := node.CreateBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	state := node.NewChainState()
	engine, err := node.NewSyncEngine(state, store, node.DefaultSyncConfig(&target, node.DevnetGenesisChainID(), chainStatePath))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	var lockStderr bytes.Buffer
	lock, lockExit := acquireDatadirLock(dir, &lockStderr)
	if lockExit != 0 || lock == nil {
		t.Fatalf("create datadir lock: exit=%d stderr=%q", lockExit, lockStderr.String())
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("release datadir lock: %v", err)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod(readonly datadir): %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	stopAfterChainStateSave(t)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--datadir", dir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(errOut.Bytes(), []byte("chainstate save failed")) {
		t.Fatalf("expected chainstate save failure in stderr, got %q", errOut.String())
	}
}

// The datadir must be PREPARED, not empty: on an empty one the run rejects at
// "blockstore open failed" and never reaches the save, which made this row a
// silent duplicate of TestRunFailsWhenBlockStoreOpenFails. The stderr
// assertion is what keeps it honest. This row has no injected terminator, so
// the root skip above is what stops it reaching the service loop.
func TestRunChainstateSaveFailsWhenDatadirNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based permission check does not apply")
	}
	datadir := preparedDatadir(t)
	if err := os.Chmod(datadir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(datadir, 0o700) })

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--datadir", datadir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "chainstate save failed") {
		t.Fatalf("must reach and fail at the save, got stderr=%q", errOut.String())
	}
}

// TestRunDryRunReportsOnAReadOnlyDatadir is the hostile case the mode exists
// for: an operator inspecting a datadir they cannot write. Pre-fix the
// unconditional Save made this exit 2 with "chainstate save failed", so the
// one datadir safest to inspect was the one --dry-run refused.
//
// This is one of the three hostile rows RUB-1071 contracts for, and it does
// NOT run as root — on a root CI the read-only shape goes unexercised and
// the surviving coverage is the plain healthy-datadir row.
func TestRunDryRunReportsOnAReadOnlyDatadir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based permission check does not apply")
	}
	dir := preparedDatadir(t)
	before := datadirSnapshot(t, dir)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod 0500: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	report := dryRunReport(t, dir)

	// Restore before snapshotting: the mode axis would otherwise flag the
	// test's own chmod as the write it is looking for.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("restore 0700: %v", err)
	}
	assertNoFilesystemWrite(t, before, datadirSnapshot(t, dir))
	if !strings.Contains(report, "blockstore: tip_height=1 ") {
		t.Fatalf("a read-only datadir must still produce the report, stdout=%q", report)
	}
}
