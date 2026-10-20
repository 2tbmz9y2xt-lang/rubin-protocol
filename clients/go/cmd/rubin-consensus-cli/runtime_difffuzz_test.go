package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

var (
	rustConsensusCLIBuildOnce sync.Once
	rustConsensusCLIBuildErr  error
	rustConsensusCLIBinPath   string
)

type parseTxParityResponse struct {
	Ok       bool
	Err      string
	TxidHex  string
	WtxidHex string
	Consumed int
}

type merkleParityResponse struct {
	Ok      bool
	Err     string
	RootHex string
}

type sighashParityResponse struct {
	Ok        bool
	Err       string
	DigestHex string
}

type cargoCompilerArtifactForDiffFuzz struct {
	Reason     string `json:"reason"`
	Executable string `json:"executable"`
	Target     struct {
		Name string   `json:"name"`
		Kind []string `json:"kind"`
	} `json:"target"`
}

func TestRubinConsensusCLI_RustParity_SeedRequests(t *testing.T) {
	bin := requireRustConsensusCLI(t)

	txBytes := buildAnchorOnlyCoinbaseLikeTxBytes(t, 0, [32]byte{})
	txHex := mustHexBytes(txBytes)

	var chainID [32]byte
	chainID[31] = 9

	var a, b [32]byte
	a[31] = 1
	b[31] = 2

	assertParseTxParity(t, bin, Request{Op: "parse_tx", TxHex: txHex})
	assertParseTxParity(t, bin, Request{Op: "parse_tx", TxHex: "00"})
	assertMerkleParity(t, bin, Request{Op: "merkle_root", Txids: []string{mustHex32(a), mustHex32(b)}}, false)
	assertMerkleParity(t, bin, Request{Op: "merkle_root", Txids: []string{"00"}}, false)
	assertMerkleParity(t, bin, Request{Op: "witness_merkle_root", Wtxids: []string{mustHex32(a), mustHex32(b)}}, true)
	assertSighashParity(t, bin, Request{
		Op:         "sighash_v1",
		TxHex:      txHex,
		InputIndex: 0,
		InputValue: 0,
		ChainIDHex: mustHex32(chainID),
	})
	assertSighashParity(t, bin, Request{
		Op:         "sighash_v1",
		TxHex:      txHex,
		InputIndex: 0,
		InputValue: 0,
		ChainIDHex: "00",
	})
}

func FuzzRubinConsensusCLI_RustParity_ParseTx(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x01, 0x02, 0x03, 0x04})
	f.Add(anchorOnlyCoinbaseLikeTxSeed())

	f.Fuzz(func(t *testing.T, data []byte) {
		bin := requireRustConsensusCLI(t)
		assertParseTxParity(t, bin, Request{
			Op:    "parse_tx",
			TxHex: hex.EncodeToString(data),
		})
	})
}

func FuzzRubinConsensusCLI_RustParity_MerkleRoots(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x11}, 32))
	f.Add(bytes.Repeat([]byte{0x22}, 64))
	f.Add(append(bytes.Repeat([]byte{0x33}, 64), 0x44))

	f.Fuzz(func(t *testing.T, data []byte) {
		bin := requireRustConsensusCLI(t)
		hexItems := deriveHex32List(data)
		assertMerkleParity(t, bin, Request{Op: "merkle_root", Txids: hexItems}, false)
		assertMerkleParity(t, bin, Request{Op: "witness_merkle_root", Wtxids: hexItems}, true)
	})
}

func FuzzRubinConsensusCLI_RustParity_Sighash(f *testing.F) {
	var chainID [32]byte
	chainID[31] = 1

	f.Add(anchorOnlyCoinbaseLikeTxSeed(), chainID[:], uint32(0), uint64(0))
	f.Add([]byte{0x00}, []byte{0x01}, uint32(0), uint64(0))
	f.Add([]byte{}, []byte{}, uint32(3), uint64(7))

	f.Fuzz(func(t *testing.T, txData []byte, chainIDData []byte, inputIndex uint32, inputValue uint64) {
		bin := requireRustConsensusCLI(t)
		assertSighashParity(t, bin, Request{
			Op:         "sighash_v1",
			TxHex:      hex.EncodeToString(txData),
			InputIndex: inputIndex,
			InputValue: inputValue,
			ChainIDHex: hex.EncodeToString(chainIDData),
		})
	})
}

func TestCargoExecutablePathForDiffFuzz_UsesExecutableField(t *testing.T) {
	const expected = "/tmp/target/difffuzz-cache/fingerprint/x86_64-unknown-linux-gnu/debug/rubin-consensus-cli"
	stdout := []byte(
		"{\"reason\":\"build-script-executed\"}\n" +
			"{\"reason\":\"compiler-artifact\",\"target\":{\"name\":\"rubin-consensus\",\"kind\":[\"lib\"]}}\n" +
			"{\"reason\":\"compiler-artifact\",\"target\":{\"name\":\"rubin-consensus-cli\",\"kind\":[\"bin\"]},\"executable\":\"" + expected + "\"}\n",
	)

	got, err := cargoExecutablePathForDiffFuzz(stdout, "rubin-consensus-cli")
	if err != nil {
		t.Fatalf("cargoExecutablePathForDiffFuzz: %v", err)
	}
	if got != expected {
		t.Fatalf("unexpected executable path: got %q want %q", got, expected)
	}
}

func assertParseTxParity(t *testing.T, bin string, req Request) {
	t.Helper()

	goResp := normalizeParseTx(runRequest(t, req))
	rustResp := normalizeParseTx(runRustConsensusCLIRequest(t, bin, req))
	if goResp != rustResp {
		t.Fatalf("parse_tx parity mismatch\nreq=%+v\ngo=%+v\nrust=%+v", req, goResp, rustResp)
	}
}

func assertMerkleParity(t *testing.T, bin string, req Request, witness bool) {
	t.Helper()

	goResp := normalizeMerkle(runRequest(t, req), witness)
	rustResp := normalizeMerkle(runRustConsensusCLIRequest(t, bin, req), witness)
	if goResp != rustResp {
		t.Fatalf("merkle parity mismatch\nreq=%+v\ngo=%+v\nrust=%+v", req, goResp, rustResp)
	}
}

func assertSighashParity(t *testing.T, bin string, req Request) {
	t.Helper()

	goResp := normalizeSighash(runRequest(t, req))
	rustResp := normalizeSighash(runRustConsensusCLIRequest(t, bin, req))
	if goResp != rustResp {
		t.Fatalf("sighash parity mismatch\nreq=%+v\ngo=%+v\nrust=%+v", req, goResp, rustResp)
	}
}

func normalizeParseTx(resp Response) parseTxParityResponse {
	return parseTxParityResponse{
		Ok:       resp.Ok,
		Err:      resp.Err,
		TxidHex:  resp.TxidHex,
		WtxidHex: resp.WtxidHex,
		Consumed: resp.Consumed,
	}
}

func normalizeMerkle(resp Response, witness bool) merkleParityResponse {
	root := resp.MerkleHex
	if witness {
		root = resp.WitnessMerkleHex
	}
	return merkleParityResponse{
		Ok:      resp.Ok,
		Err:     resp.Err,
		RootHex: root,
	}
}

func normalizeSighash(resp Response) sighashParityResponse {
	return sighashParityResponse{
		Ok:        resp.Ok,
		Err:       resp.Err,
		DigestHex: resp.DigestHex,
	}
}

func requireRustConsensusCLI(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found")
	}

	rustConsensusCLIBuildOnce.Do(func() {
		root := repoRootForDiffFuzz(t)
		rustDir := filepath.Join(root, "clients", "rust")
		fingerprint, err := rustConsensusSourceFingerprint(root)
		if err != nil {
			rustConsensusCLIBuildErr = fmt.Errorf("fingerprint rust consensus sources: %w", err)
			return
		}
		targetDir := filepath.Join(rustDir, "target", "difffuzz-cache", fingerprint)
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			rustConsensusCLIBuildErr = fmt.Errorf("mkdir difffuzz target dir: %w", err)
			return
		}
		rustConsensusCLIBinPath, rustConsensusCLIBuildErr = publishRustConsensusCLIForDiffFuzz(targetDir, 10*time.Minute,
			func() (string, error) { return cargoBuildRustConsensusCLIForDiffFuzz(rustDir, targetDir) })
	})
	if rustConsensusCLIBuildErr != nil {
		t.Fatalf("build rust consensus cli: %v", rustConsensusCLIBuildErr)
	}
	return rustConsensusCLIBinPath
}

func cargoBuildRustConsensusCLIForDiffFuzz(rustDir, targetDir string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "cargo", "build", "--message-format=json-render-diagnostics", "--target-dir", targetDir, "-p", "rubin-consensus-cli", "--bin", "rubin-consensus-cli")
	cmd.Dir = rustDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cargo build rubin-consensus-cli: %w\n%s", err, stderr.String())
	}
	binPath, err := cargoExecutablePathForDiffFuzz(stdout.Bytes(), "rubin-consensus-cli")
	if err != nil {
		return "", fmt.Errorf("resolve cargo executable path: %w", err)
	}
	return binPath, nil
}

// publishRustConsensusCLIForDiffFuzz runs build under a cross-process lock and renames a
// copy of its output to one fixed path, so no worker execs a file cargo is replacing.
func publishRustConsensusCLIForDiffFuzz(targetDir string, wait time.Duration, build func() (string, error)) (string, error) {
	lock, err := acquireDiffFuzzBuildLock(filepath.Join(targetDir, "difffuzz-build.lock"), wait)
	if err != nil {
		return "", err
	}
	defer func() { _ = lock.Release() }()
	src, err := build()
	if err != nil {
		return "", err
	}
	return publishDiffFuzzBinary(src, filepath.Join(targetDir, "difffuzz-bin"))
}

func acquireDiffFuzzBuildLock(path string, wait time.Duration) (*filelock.Handle, error) {
	deadline := time.Now().Add(wait)
	for {
		lock, result, err := filelock.Acquire(path)
		if err == nil {
			return lock, nil
		}
		if result != filelock.ResultContended {
			return nil, fmt.Errorf("acquire difffuzz build lock %s (%s): %w", path, result, err)
		}
		// The last sleep ends at the deadline, and the check after it keeps any attempt from starting later.
		time.Sleep(min(100*time.Millisecond, time.Until(deadline)))
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("difffuzz build lock %s still contended after %s", path, wait)
		}
	}
}

func publishDiffFuzzBinary(src, binDir string) (string, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(binDir, "rubin-consensus-cli.tmp-*")
	if err != nil {
		return "", err
	}
	dst := filepath.Join(binDir, "rubin-consensus-cli")
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Chmod(0o755)
	}
	if err = errors.Join(err, tmp.Close()); err == nil {
		err = os.Rename(tmp.Name(), dst)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return dst, nil
}

func runRustConsensusCLIRequest(t *testing.T, bin string, req Request) Response {
	t.Helper()

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal rust request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = bytes.NewReader(raw)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("run rust consensus cli: %v\nstderr:\n%s", err, stderr.String())
	}

	var resp Response
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal rust resp: %v; raw=%q", err, stdout.String())
	}
	return resp
}

func deriveHex32List(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	mode := data[0] % 4
	rest := data[1:]
	out := make([]string, 0, 4)

	switch mode {
	case 0:
		for len(rest) > 0 && len(out) < 4 {
			n := minDiffFuzzInt(len(rest), 32)
			out = append(out, hex.EncodeToString(rest[:n]))
			rest = rest[n:]
		}
	case 1:
		for len(rest) >= 32 && len(out) < 4 {
			out = append(out, hex.EncodeToString(rest[:32]))
			rest = rest[32:]
		}
	case 2:
		for len(rest) >= 32 && len(out) < 3 {
			out = append(out, hex.EncodeToString(rest[:32]))
			rest = rest[32:]
		}
		if len(rest) > 0 && len(out) < 4 {
			out = append(out, hex.EncodeToString(rest[:minDiffFuzzInt(len(rest), 31)]))
		}
	default:
		out = append(out, "")
		if len(rest) > 0 && len(out) < 4 {
			out = append(out, hex.EncodeToString(rest[:minDiffFuzzInt(len(rest), 16)]))
		}
	}

	return out
}

func anchorOnlyCoinbaseLikeTxSeed() []byte {
	var tmp [8]byte
	out := make([]byte, 0, 200)

	binary.LittleEndian.PutUint32(tmp[:4], 1)
	out = append(out, tmp[:4]...)
	out = append(out, 0x00)
	binary.LittleEndian.PutUint64(tmp[:], 0)
	out = append(out, tmp[:]...)

	out = append(out, consensus.EncodeCompactSize(1)...)
	out = append(out, make([]byte, 32)...)
	binary.LittleEndian.PutUint32(tmp[:4], ^uint32(0))
	out = append(out, tmp[:4]...)
	out = append(out, consensus.EncodeCompactSize(0)...)
	binary.LittleEndian.PutUint32(tmp[:4], ^uint32(0))
	out = append(out, tmp[:4]...)

	out = append(out, consensus.EncodeCompactSize(1)...)
	binary.LittleEndian.PutUint64(tmp[:], 0)
	out = append(out, tmp[:]...)
	binary.LittleEndian.PutUint16(tmp[:2], consensus.COV_TYPE_ANCHOR)
	out = append(out, tmp[:2]...)
	out = append(out, consensus.EncodeCompactSize(32)...)
	out = append(out, make([]byte, 32)...)

	binary.LittleEndian.PutUint32(tmp[:4], 0)
	out = append(out, tmp[:4]...)
	out = append(out, consensus.EncodeCompactSize(0)...)
	out = append(out, consensus.EncodeCompactSize(0)...)
	return out
}

func rustConsensusSourceFingerprint(root string) (string, error) {
	hasher := sha256.New()
	paths := []string{
		filepath.Join(root, "clients", "rust", "Cargo.toml"),
		filepath.Join(root, "clients", "rust", "Cargo.lock"),
		filepath.Join(root, "clients", "rust", "crates", "rubin-consensus"),
		filepath.Join(root, "clients", "rust", "crates", "rubin-consensus-cli"),
	}
	for _, path := range paths {
		if err := hashPathForDiffFuzz(hasher, root, path); err != nil {
			return "", err
		}
	}
	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum[:8]), nil
}

func hashPathForDiffFuzz(hasher io.Writer, root, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return hashFileForDiffFuzz(hasher, root, path)
	}
	return filepath.WalkDir(path, func(entryPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(entryPath)
		if filepath.Ext(entryPath) != ".rs" && base != "Cargo.toml" {
			return nil
		}
		return hashFileForDiffFuzz(hasher, root, entryPath)
	})
}

func cargoExecutablePathForDiffFuzz(stdout []byte, targetName string) (string, error) {
	var sawArtifact bool
	for _, line := range bytes.Split(stdout, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var msg cargoCompilerArtifactForDiffFuzz
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}
		if msg.Reason != "compiler-artifact" {
			continue
		}
		sawArtifact = true
		if msg.Target.Name == targetName && msg.Executable != "" {
			return msg.Executable, nil
		}
	}
	if !sawArtifact {
		return "", fmt.Errorf("cargo emitted no compiler-artifact messages")
	}
	return "", fmt.Errorf("compiler-artifact for %s not found", targetName)
}

func hashFileForDiffFuzz(hasher io.Writer, root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(hasher, rel); err != nil {
		return err
	}
	if _, err := io.WriteString(hasher, "\n"); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, err := hasher.Write(data); err != nil {
		return err
	}
	_, err = io.WriteString(hasher, "\n")
	return err
}

func minDiffFuzzInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func repoRootForDiffFuzz(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))
}

func newDiffFuzzTarget(t *testing.T, binary []byte) (string, string) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("difffuzz build lock is unsupported on %s", runtime.GOOS)
	}
	targetDir := t.TempDir()
	src := filepath.Join(targetDir, "cargo-out")
	writeDiffFuzzFile(t, src, binary)
	return targetDir, src
}

func writeDiffFuzzFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := errors.Join(os.MkdirAll(filepath.Dir(path), 0o755), os.WriteFile(path, data, 0o644)); err != nil {
		t.Fatal(err)
	}
}

func assertDiffFuzzFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s holds %q (err %v), want %q", path, got, err, want)
	}
}

func publishDiffFuzzOnce(t *testing.T, targetDir, src string) string {
	t.Helper()
	calls := 0
	got, err := publishRustConsensusCLIForDiffFuzz(targetDir, time.Second, func() (string, error) { calls++; return src, nil })
	if err != nil || calls != 1 {
		t.Fatalf("publish: err=%v calls=%d", err, calls)
	}
	return got
}

func TestPublishRustConsensusCLIForDiffFuzz_ReplacesEarlierFile(t *testing.T) {
	targetDir, src := newDiffFuzzTarget(t, []byte("new-binary"))
	published, earlier := filepath.Join(targetDir, "difffuzz-bin", "rubin-consensus-cli"), filepath.Join(targetDir, "earlier-link")
	writeDiffFuzzFile(t, published, []byte("old"))
	if err := os.Link(published, earlier); err != nil {
		t.Fatal(err)
	}
	assertDiffFuzzFileBytes(t, publishDiffFuzzOnce(t, targetDir, src), []byte("new-binary"))
	if got, err := os.ReadFile(earlier); err != nil || !bytes.Equal(got, []byte("old")) {
		t.Fatalf("earlier published inode was rewritten in place: its link holds %q (err %v), want %q", got, err, "old")
	}
}

func TestPublishRustConsensusCLIForDiffFuzz_PublishesCompleteCopy(t *testing.T) {
	targetDir, src := newDiffFuzzTarget(t, []byte("binary-v1"))
	got := publishDiffFuzzOnce(t, targetDir, src)
	if want := filepath.Join(targetDir, "difffuzz-bin", "rubin-consensus-cli"); got != want {
		t.Fatalf("published path %q, want %q", got, want)
	}
	info, err := os.Lstat(got)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 {
		t.Fatalf("published file: info=%v err=%v", info, err)
	}
	writeDiffFuzzFile(t, src, []byte("binary-v2-rewritten"))
	assertDiffFuzzFileBytes(t, got, []byte("binary-v1"))
}

func TestPublishRustConsensusCLIForDiffFuzz_SerializesBuilds(t *testing.T) {
	binary := bytes.Repeat([]byte{0x5a}, 1<<16)
	targetDir, src := newDiffFuzzTarget(t, binary)
	var running, maxRunning atomic.Int32
	build := func() (string, error) {
		n := running.Add(1)
		for cur := maxRunning.Load(); n > cur && !maxRunning.CompareAndSwap(cur, n); cur = maxRunning.Load() {
		}
		time.Sleep(50 * time.Millisecond)
		running.Add(-1)
		return src, nil
	}
	want := filepath.Join(targetDir, "difffuzz-bin", "rubin-consensus-cli")
	results, start := make(chan string, 8), make(chan struct{})
	for range 8 {
		go func() {
			<-start
			got, err := publishRustConsensusCLIForDiffFuzz(targetDir, 5*time.Second, build)
			results <- fmt.Sprintf("%s err=%v", got, err)
		}()
	}
	close(start)
	timeout := time.After(10 * time.Second)
	for range 8 {
		select {
		case got := <-results:
			if got != want+" err=<nil>" {
				t.Fatalf("publish returned %q, want %q", got, want)
			}
		case <-timeout:
			t.Fatal("publishers did not finish within 10s")
		}
	}
	if maxRunning.Load() != 1 {
		t.Fatalf("max concurrent builds %d, want 1", maxRunning.Load())
	}
	assertDiffFuzzFileBytes(t, want, binary)
}

func TestPublishRustConsensusCLIForDiffFuzz_ContendedLockTimesOut(t *testing.T) {
	targetDir, _ := newDiffFuzzTarget(t, nil)
	held, _, err := filelock.Acquire(filepath.Join(targetDir, "difffuzz-build.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Release() }()
	calls, done := 0, make(chan error, 1)
	go func() {
		_, err := publishRustConsensusCLIForDiffFuzz(targetDir, 300*time.Millisecond, func() (string, error) { calls++; return "", nil })
		done <- err
	}()
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("contended publish ignored its 300ms wait bound")
	}
	if err == nil || calls != 0 {
		t.Fatalf("contended publish: err=%v calls=%d", err, calls)
	}
}

func TestPublishRustConsensusCLIForDiffFuzz_StopsAtWaitBound(t *testing.T) {
	// A correct publish returns once its bound has passed. One more 100ms retry interval ends at
	// least 100ms after start, which is the 10ms bound plus this slack.
	const slack = 90 * time.Millisecond
	for _, tc := range []struct {
		name          string
		wait, release time.Duration
	}{
		{"lock held throughout, 10ms bound", 10 * time.Millisecond, 0},
		{"lock released 50ms after start, 100ms bound", 100 * time.Millisecond, 50 * time.Millisecond},
	} {
		targetDir, _ := newDiffFuzzTarget(t, nil)
		lockPath := filepath.Join(targetDir, "difffuzz-build.lock")
		calls, elapsed, err := publishAgainstHeldDiffFuzzLock(t, lockPath, targetDir, tc.wait, tc.release)
		if calls != 0 {
			t.Errorf("%s: a build ran (%d calls)", tc.name, calls)
		}
		if err == nil || !strings.Contains(err.Error(), lockPath) {
			t.Errorf("%s: publish returned %v, not an error naming %s", tc.name, err, lockPath)
		}
		if elapsed < tc.wait || elapsed >= tc.wait+slack {
			t.Errorf("%s: publish returned %s after start, want at least %s and under %s", tc.name, elapsed, tc.wait, tc.wait+slack)
		}
	}
}

// publishAgainstHeldDiffFuzzLock holds the build lock at lockPath and calls publish with the wait
// bound. Start is the time the publish goroutine takes before it calls publish; when release is
// positive, the lock is released once release has passed after start. It returns the build
// calls, the time publish took from start and its error.
func publishAgainstHeldDiffFuzzLock(t *testing.T, lockPath, targetDir string, wait, release time.Duration) (int, time.Duration, error) {
	t.Helper()
	held, _, err := filelock.Acquire(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Release() })
	calls, elapsed, started, done := 0, time.Duration(0), make(chan time.Time, 1), make(chan error, 1)
	go func() {
		start := time.Now()
		started <- start
		_, err := publishRustConsensusCLIForDiffFuzz(targetDir, wait, func() (string, error) { calls++; return "", errors.New("build called") })
		elapsed = time.Since(start)
		done <- err
	}()
	if start := <-started; release > 0 {
		time.Sleep(time.Until(start.Add(release)))
		_ = held.Release()
	}
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publish did not return within 5s")
	}
	return calls, elapsed, err
}

func TestPublishRustConsensusCLIForDiffFuzz_BuildOrCopyErrorKeepsEarlierFile(t *testing.T) {
	buildErr := errors.New("cargo failed")
	for _, tc := range []struct {
		name           string
		buildErr, want error
	}{{"build error", buildErr, buildErr}, {"read error of the build output", nil, fs.ErrNotExist}} {
		targetDir, _ := newDiffFuzzTarget(t, nil)
		published := filepath.Join(targetDir, "difffuzz-bin", "rubin-consensus-cli")
		writeDiffFuzzFile(t, published, []byte("old"))
		missing := filepath.Join(targetDir, "missing-cargo-out")
		_, err := publishRustConsensusCLIForDiffFuzz(targetDir, time.Second, func() (string, error) { return missing, tc.buildErr })
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: publish returned %v, want %v", tc.name, err, tc.want)
		}
		assertDiffFuzzFileBytes(t, published, []byte("old"))
		assertDiffFuzzLockFree(t, targetDir)
	}
}

func TestPublishRustConsensusCLIForDiffFuzz_MkdirOrRenameErrorKeepsEarlierEntry(t *testing.T) {
	for _, tc := range []struct{ name, earlier, op string }{
		{"rename onto an existing directory", "difffuzz-bin/rubin-consensus-cli/keep", "rename"},
		{"mkdir over a regular file", "difffuzz-bin", "mkdir"},
	} {
		targetDir, src := newDiffFuzzTarget(t, []byte("new-binary"))
		earlier := filepath.Join(targetDir, filepath.FromSlash(tc.earlier))
		writeDiffFuzzFile(t, earlier, []byte("old"))
		_, err := publishRustConsensusCLIForDiffFuzz(targetDir, time.Second, func() (string, error) { return src, nil })
		if op := diffFuzzErrOp(err); op != tc.op {
			t.Fatalf("%s: publish returned %v (op %q), want a %q error", tc.name, err, op, tc.op)
		}
		assertDiffFuzzFileBytes(t, earlier, []byte("old"))
		assertDiffFuzzLockFree(t, targetDir)
	}
}

func diffFuzzErrOp(err error) string {
	var linkErr *os.LinkError
	var pathErr *os.PathError
	switch {
	case errors.As(err, &linkErr):
		return linkErr.Op
	case errors.As(err, &pathErr):
		return pathErr.Op
	}
	return ""
}

func assertDiffFuzzLockFree(t *testing.T, targetDir string) {
	t.Helper()
	probe, result, err := filelock.Acquire(filepath.Join(targetDir, "difffuzz-build.lock"))
	if err != nil {
		t.Fatalf("probe could not acquire the build lock after publish returned: result %q, err %v", result, err)
	}
	_ = probe.Release()
}

func TestPublishRustConsensusCLIForDiffFuzz_CopiesUnderLock(t *testing.T) {
	targetDir, _ := newDiffFuzzTarget(t, nil)
	fifo := filepath.Join(targetDir, "cargo-fifo")
	if out, err := exec.CommandContext(t.Context(), "mkfifo", fifo).CombinedOutput(); err != nil {
		t.Fatalf("mkfifo: %v %s", err, out)
	}
	done := make(chan error, 1)
	go func() {
		_, err := publishRustConsensusCLIForDiffFuzz(targetDir, time.Second, func() (string, error) { return fifo, nil })
		done <- err
	}()
	w := openDiffFuzzFIFOWriter(t, fifo, done)
	if probe, result, err := filelock.Acquire(filepath.Join(targetDir, "difffuzz-build.lock")); result != filelock.ResultContended {
		_ = probe.Release()
		t.Errorf("probe did not find the build lock contended while publish read the build output: result %q, err %v", result, err)
	}
	_, err := w.Write([]byte("fifo-binary"))
	err = errors.Join(err, w.Close())
	select {
	case pubErr := <-done:
		err = errors.Join(err, pubErr)
	case <-time.After(5 * time.Second):
		t.Fatal("publish did not return within 5s after the build output was closed")
	}
	if err != nil {
		t.Fatal(err)
	}
	assertDiffFuzzFileBytes(t, filepath.Join(targetDir, "difffuzz-bin", "rubin-consensus-cli"), []byte("fifo-binary"))
}

// openDiffFuzzFIFOWriter returns the write end of fifo once publish has opened it to read the
// build output, and fails the test if the open fails, publish returns first, or neither
// happens within 5s.
func openDiffFuzzFIFOWriter(t *testing.T, fifo string, done <-chan error) *os.File {
	t.Helper()
	opened := make(chan *os.File, 1)
	go func() {
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Errorf("open %s for writing: %v", fifo, err)
		}
		opened <- w
	}()
	select {
	case w := <-opened:
		if w != nil {
			return w
		}
		opened <- nil // the open error is already reported; the drain below closes nothing
	case err := <-done:
		t.Errorf("publish returned before it opened the build output for reading: %v", err)
	case <-time.After(5 * time.Second):
		t.Error("publish did not open the build output for reading within 5s")
	}
	// An O_RDWR open of a FIFO does not block on darwin or linux; it completes the open pending on
	// the other end, the writer goroutine's or publish's.
	if r, err := os.OpenFile(fifo, os.O_RDWR, 0); err == nil {
		_ = errors.Join((<-opened).Close(), r.Close())
	}
	t.FailNow()
	return nil
}
