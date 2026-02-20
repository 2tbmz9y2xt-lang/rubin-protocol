package p2p

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rubin.dev/node/crypto"
)

func TestInterop_GoClient_RustServer_ChainIDMismatchReject(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found; skipping interop test")
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// We are in clients/go/node/p2p when running `go test ./...` from clients/go.
	repoRoot := filepath.Clean(filepath.Join(wd, "..", "..", "..", ".."))

	magic := uint32(0x0B110907)
	serverChainHex := strings.Repeat("11", 32)
	clientChainHex := strings.Repeat("22", 32)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		"cargo", "run", "--quiet",
		"--manifest-path", filepath.Join(repoRoot, "clients/rust/Cargo.toml"),
		"-p", "rubin-p2p",
		"--bin", "rubin-p2p",
		"--",
		"listen-handshake",
		"--chain-id-hex", serverChainHex,
		"--magic", "0x0B110907",
	)
	cmd.Dir = repoRoot
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start rust server: %v (stderr=%s)", err, stderr.String())
	}
	defer func() { _ = cmd.Process.Kill() }()

	sc := bufio.NewScanner(stdout)
	if !sc.Scan() {
		t.Fatalf("rust server did not print LISTEN line (stderr=%s)", stderr.String())
	}
	line := sc.Text()
	if !strings.HasPrefix(line, "LISTEN ") {
		t.Fatalf("unexpected rust server stdout: %q (stderr=%s)", line, stderr.String())
	}
	addr := strings.TrimSpace(strings.TrimPrefix(line, "LISTEN "))

	var cp crypto.DevStdCryptoProvider
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial rust server: %v", err)
	}
	defer conn.Close()

	clientChainID := mustHex32(t, clientChainHex)
	_, herr := Handshake(conn, cp, magic, VersionPayload{}, clientChainID)
	if herr == nil {
		t.Fatalf("expected handshake error on chain_id mismatch")
	}
	if !strings.Contains(herr.Error(), "reject") {
		t.Fatalf("expected reject in error, got: %v", herr)
	}

	_ = cmd.Wait()
}

func mustHex32(t *testing.T, hexStr string) [32]byte {
	t.Helper()
	b := make([]byte, 0, 32)
	for i := 0; i < len(hexStr); i += 2 {
		var v byte
		for j := 0; j < 2; j++ {
			c := hexStr[i+j]
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v |= c - 'A' + 10
			default:
				t.Fatalf("invalid hex: %q", hexStr)
			}
		}
		b = append(b, v)
	}
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
