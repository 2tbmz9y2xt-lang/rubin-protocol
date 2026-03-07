package p2p

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

var (
	rustInteropBuildOnce sync.Once
	rustInteropBuildErr  error
	rustInteropBinPath   string
)

func TestRustInterop_GoDialRustServerHandshake(t *testing.T) {
	bin := requireRustInterop(t)
	cmd, ready, logs := startRustInteropServer(t, bin, "idle")
	defer terminateHelper(cmd)

	conn, err := net.Dial("tcp", ready)
	if err != nil {
		t.Fatalf("dial rust helper: %v", err)
	}
	defer conn.Close()

	state := completeGoInteropHandshake(t, conn, 7)
	if !state.HandshakeComplete {
		t.Fatalf("expected handshake complete: %+v", state)
	}
	if state.RemoteVersion.BestHeight != 0 {
		t.Fatalf("remote best height=%d, want 0", state.RemoteVersion.BestHeight)
	}

	waitRustInterop(t, cmd, logs)
}

func TestRustInterop_RustClientDialGoServerHandshake(t *testing.T) {
	bin := requireRustInterop(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	cmd, logs := startRustInteropClient(t, bin, listener.Addr().String(), "idle")
	defer terminateHelper(cmd)

	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	state := completeGoInteropHandshake(t, conn, 9)
	if !state.HandshakeComplete {
		t.Fatalf("expected handshake complete: %+v", state)
	}

	waitRustInterop(t, cmd, logs)
}

func TestRustInterop_RustServerPingGoClientPong(t *testing.T) {
	bin := requireRustInterop(t)
	cmd, ready, logs := startRustInteropServer(t, bin, "send-ping-expect-pong")
	defer terminateHelper(cmd)

	conn, err := net.Dial("tcp", ready)
	if err != nil {
		t.Fatalf("dial rust helper: %v", err)
	}
	defer conn.Close()

	state := completeGoInteropHandshake(t, conn, 5)
	if !state.HandshakeComplete {
		t.Fatalf("expected handshake complete: %+v", state)
	}
	setInteropDeadline(t, conn)
	frame, err := readFrame(conn, networkMagic("devnet"), node.DefaultPeerRuntimeConfig("devnet", 8).MaxMessageSize)
	if err != nil {
		t.Fatalf("read ping: %v", err)
	}
	if frame.Command != messagePing {
		t.Fatalf("command=%q, want %q", frame.Command, messagePing)
	}
	if len(frame.Payload) != 0 {
		t.Fatalf("ping payload len=%d, want 0", len(frame.Payload))
	}
	if err := writeFrame(conn, networkMagic("devnet"), message{Command: messagePong}, node.DefaultPeerRuntimeConfig("devnet", 8).MaxMessageSize); err != nil {
		t.Fatalf("write pong: %v", err)
	}

	waitRustInterop(t, cmd, logs)
}

func TestRustInterop_RustClientReceivesTxFromGo(t *testing.T) {
	bin := requireRustInterop(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	payload := []byte{0x52, 0x55, 0x42, 0x49, 0x4e}
	cmd, logs := startRustInteropClient(
		t,
		bin,
		listener.Addr().String(),
		"expect-tx",
		"--payload-hex", fmt.Sprintf("%x", payload),
	)
	defer terminateHelper(cmd)

	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	state := completeGoInteropHandshake(t, conn, 3)
	if !state.HandshakeComplete {
		t.Fatalf("expected handshake complete: %+v", state)
	}
	setInteropDeadline(t, conn)
	if err := writeFrame(conn, networkMagic("devnet"), message{Command: messageTx, Payload: payload}, node.DefaultPeerRuntimeConfig("devnet", 8).MaxMessageSize); err != nil {
		t.Fatalf("write tx: %v", err)
	}

	waitRustInterop(t, cmd, logs)
}

func TestRustInterop_RustClientSyncsFiveBlocksFromGo(t *testing.T) {
	bin := requireRustInterop(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	if err := source.service.Start(ctx); err != nil {
		t.Fatalf("source.Start: %v", err)
	}
	defer source.service.Close()

	cmd, logs := startRustInteropClient(t, bin, source.service.Addr(), "sync-blocks")
	defer terminateHelper(cmd)

	waitRustInterop(t, cmd, logs)
}

func requireRustInterop(t *testing.T) string {
	t.Helper()
	if os.Getenv("RUBIN_P2P_INTEROP") != "1" {
		t.Skip("set RUBIN_P2P_INTEROP=1 to enable Go↔Rust live interop gate")
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found")
	}
	rustInteropBuildOnce.Do(func() {
		root := repoRoot(t)
		rustDir := filepath.Join(root, "clients", "rust")
		cmd := exec.Command("cargo", "build", "-p", "rubin-node", "--bin", "p2p-interop-helper")
		cmd.Dir = rustDir
		var stderr bytes.Buffer
		cmd.Stdout = ioDiscard{}
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			rustInteropBuildErr = fmt.Errorf("cargo build p2p-interop-helper: %w\n%s", err, stderr.String())
			return
		}
		rustInteropBinPath = filepath.Join(rustDir, "target", "debug", binaryName("p2p-interop-helper"))
	})
	if rustInteropBuildErr != nil {
		t.Fatalf("build rust helper: %v", rustInteropBuildErr)
	}
	return rustInteropBinPath
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func startRustInteropServer(t *testing.T, bin, action string, extraArgs ...string) (*exec.Cmd, string, *bytes.Buffer) {
	t.Helper()
	args := append([]string{"server", "--action", action}, extraArgs...)
	cmd := exec.Command(bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start rust helper server: %v", err)
	}
	ready, err := readReadyLine(stdout)
	if err != nil {
		terminateHelper(cmd)
		t.Fatalf("read helper ready line: %v\nstderr:\n%s", err, stderr.String())
	}
	return cmd, ready, &stderr
}

func startRustInteropClient(t *testing.T, bin, addr, action string, extraArgs ...string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	args := []string{"client", "--connect", addr, "--action", action}
	args = append(args, extraArgs...)
	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stdout = ioDiscard{}
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start rust helper client: %v", err)
	}
	return cmd, &stderr
}

func readReadyLine(stdout netOrPipeReader) (string, error) {
	scanner := bufio.NewScanner(stdout)
	done := make(chan struct{})
	var line string
	var scanErr error
	go func() {
		defer close(done)
		if scanner.Scan() {
			line = scanner.Text()
		} else {
			scanErr = scanner.Err()
			if scanErr == nil {
				scanErr = fmt.Errorf("helper exited before READY line")
			}
		}
	}()
	select {
	case <-done:
		if scanErr != nil {
			return "", scanErr
		}
	case <-time.After(5 * time.Second):
		return "", fmt.Errorf("timeout waiting for READY line")
	}
	const prefix = "READY "
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("unexpected ready line: %q", line)
	}
	return strings.TrimSpace(strings.TrimPrefix(line, prefix)), nil
}

type netOrPipeReader interface {
	Read([]byte) (int, error)
}

func completeGoInteropHandshake(t *testing.T, conn net.Conn, bestHeight uint64) node.PeerState {
	t.Helper()
	cfg := node.DefaultPeerRuntimeConfig("devnet", 8)
	cfg.HandshakeTimeout = 3 * time.Second
	localVersion := testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "go-interop", bestHeight)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	state, err := performHandshake(ctx, conn, cfg, localVersion, localVersion.ChainID, localVersion.GenesisHash)
	if err != nil {
		t.Fatalf("performHandshake: %v", err)
	}
	return state
}

func setInteropDeadline(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.SetDeadline(time.Time{})
	})
}

func waitRustInterop(t *testing.T, cmd *exec.Cmd, logs *bytes.Buffer) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("rust helper failed: %v\nstderr:\n%s", err, logs.String())
		}
	case <-time.After(5 * time.Second):
		terminateHelper(cmd)
		t.Fatalf("rust helper timeout\nstderr:\n%s", logs.String())
	}
}

func terminateHelper(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))
}

func binaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
