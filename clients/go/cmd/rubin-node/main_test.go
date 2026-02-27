package main

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestMustTipReturnsExitCode2OnError(t *testing.T) {
	var errOut bytes.Buffer
	_, _, _, code := mustTip(0, [32]byte{}, false, errors.New("boom"), &errOut)
	if code != 2 {
		t.Fatalf("code=%d, want 2", code)
	}
	if errOut.Len() == 0 {
		t.Fatalf("expected stderr output")
	}
}

func TestRunReturnsTipExitCodeWhenMustTipNonZero(t *testing.T) {
	prev := mustTipFn
	mustTipFn = func(uint64, [32]byte, bool, error, io.Writer) (uint64, [32]byte, bool, int) {
		return 0, [32]byte{}, false, 2
	}
	t.Cleanup(func() { mustTipFn = prev })

	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestMultiStringFlagSetAppends(t *testing.T) {
	var m multiStringFlag
	if err := m.Set("a"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := m.Set("b"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := m.String(); got != "a,b" {
		t.Fatalf("string=%q, want %q", got, "a,b")
	}
}

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

func TestRunDryRunShowsTipWhenBlockstoreHasTip(t *testing.T) {
	dir := t.TempDir()

	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	header := make([]byte, 116) // consensus.BLOCK_HEADER_BYTES
	hash, err := consensus.BlockHash(header)
	if err != nil {
		t.Fatalf("block hash: %v", err)
	}
	if err := blockStore.PutBlock(0, hash, header, nil); err != nil {
		t.Fatalf("put block: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("blockstore: tip_height=")) {
		t.Fatalf("expected tip output, got %q", out.String())
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

func TestRunMineBlocksExitOK(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(
		[]string{"--datadir", dir, "--mine-blocks", "1", "--mine-exit"},
		&out,
		&errOut,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("mined:")) {
		t.Fatalf("expected mined output, got %q", out.String())
	}
}

func TestRunMineBlocksFailsOnHeightOverflow(t *testing.T) {
	dir := t.TempDir()
	chainState := node.NewChainState()
	chainState.HasTip = true
	chainState.Height = uint64(math.MaxUint32)
	if err := chainState.Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("save chainstate: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{"--datadir", dir, "--mine-blocks", "1", "--mine-exit"},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
}

func TestRunMineBlocksFailsWhenMinerInitFails(t *testing.T) {
	prev := newMinerFn
	newMinerFn = func(*node.ChainState, *node.BlockStore, *node.SyncEngine, node.MinerConfig) (*node.Miner, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { newMinerFn = prev })

	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--datadir", dir, "--mine-blocks", "1", "--mine-exit"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunFailsWhenSyncEngineInitFails(t *testing.T) {
	prev := newSyncEngineFn
	newSyncEngineFn = func(*node.ChainState, *node.BlockStore, node.SyncConfig) (*node.SyncEngine, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { newSyncEngineFn = prev })

	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunParseErrorUnknownFlag(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(
		[]string{"--dry-run", "--datadir", dir, "--unknown-flag"},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunDatadirCreateFailsWhenDatadirIsFile(t *testing.T) {
	tmp := t.TempDir()
	datadir := filepath.Join(tmp, "notadir")
	if err := os.WriteFile(datadir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", datadir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunChainstateLoadFailsWhenChainstatePathIsDir(t *testing.T) {
	datadir := t.TempDir()
	chainstatePath := node.ChainStatePath(datadir)
	if err := os.MkdirAll(chainstatePath, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", datadir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunChainstateSaveFailsWhenDatadirNotWritable(t *testing.T) {
	datadir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(datadir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(datadir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(datadir, 0o700) })

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", datadir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunFailsWhenBlockStoreOpenFails(t *testing.T) {
	datadir := t.TempDir()
	blockStorePath := node.BlockStorePath(datadir)
	if err := os.WriteFile(blockStorePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", datadir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunPrintConfigFailsWhenStdoutFails(t *testing.T) {
	datadir := t.TempDir()
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", datadir}, failWriter{}, &errOut)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestNowUnixU64ReturnsZeroWhenUnixTimeNonPositive(t *testing.T) {
	prev := nowUnix
	nowUnix = func() int64 { return 0 }
	t.Cleanup(func() { nowUnix = prev })

	if got := nowUnixU64(); got != 0 {
		t.Fatalf("nowUnixU64=%d, want 0", got)
	}
}

func TestMainExitCodeIs0OnDryRun(t *testing.T) {
	if os.Getenv("RUBIN_NODE_CHILD") == "1" {
		datadir := t.TempDir()
		os.Args = []string{"rubin-node", "--dry-run", "--datadir", datadir}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainExitCodeIs0OnDryRun")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_CHILD=1")
	err := cmd.Run()
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if ok {
			t.Fatalf("exit code=%d, want 0 (stderr=%s)", ee.ExitCode(), string(ee.Stderr))
		}
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunNonDryRunExitsOnSignal(t *testing.T) {
	if os.Getenv("RUBIN_NODE_SIGNAL_CHILD") == "1" {
		dir := t.TempDir()
		go func() {
			time.Sleep(200 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(syscall.SIGINT)
		}()
		code := run([]string{"--datadir", dir}, os.Stdout, os.Stderr)
		os.Exit(code)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunNonDryRunExitsOnSignal")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_SIGNAL_CHILD=1")
	err := cmd.Run()
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if ok {
			t.Fatalf("exit code=%d, want 0 (stderr=%s)", ee.ExitCode(), string(ee.Stderr))
		}
		t.Fatalf("unexpected error: %v", err)
	}
}
