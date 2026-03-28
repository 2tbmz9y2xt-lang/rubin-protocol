package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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
		cmd := exec.Command("cargo", "build", "--target-dir", targetDir, "-p", "rubin-consensus-cli", "--bin", "rubin-consensus-cli")
		cmd.Dir = rustDir
		cmd.Stdout = io.Discard
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			rustConsensusCLIBuildErr = fmt.Errorf("cargo build rubin-consensus-cli: %w\n%s", err, stderr.String())
			return
		}
		rustConsensusCLIBinPath = filepath.Join(targetDir, "debug", binaryNameForDiffFuzz("rubin-consensus-cli"))
	})
	if rustConsensusCLIBuildErr != nil {
		t.Fatalf("build rust consensus cli: %v", rustConsensusCLIBuildErr)
	}
	return rustConsensusCLIBinPath
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

func binaryNameForDiffFuzz(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
