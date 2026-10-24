package p2p

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

func TestRustInterop_GoToRustSendCmpctUnsupportedVersionKeepsSession(t *testing.T) {
	cmd, logs, injected := startGoSendCmpctProxySync(t, []byte{2, 2, 0, 0, 0, 0, 0, 0, 0})
	waitRustInterop(t, cmd, logs)
	requireOneInjection(t, injected)
}

func TestRustInterop_GoToRustSendCmpctMalformedModeEndsSession(t *testing.T) {
	cmd, logs, injected := startGoSendCmpctProxySync(t, []byte{3, 2, 0, 0, 0, 0, 0, 0, 0})
	stderr := waitRustInteropExit1(t, cmd, logs)
	if !strings.Contains(stderr, "unsupported compact relay mode") {
		t.Fatalf("stderr=%q, want unsupported compact relay mode", stderr)
	}
	requireOneInjection(t, injected)
}

func TestRustInterop_RustToGoSendCmpctUnsupportedVersionKeepsSession(t *testing.T) {
	cmd, logs := startRustSendCmpctSync(t, "2:2")
	waitRustInterop(t, cmd, logs)
}

func TestRustInterop_RustToGoSendCmpctSupportedVersionBaseline(t *testing.T) {
	cmd, logs := startRustSendCmpctSync(t, "2:1")
	waitRustInterop(t, cmd, logs)
}

func TestRustInterop_RustToGoSendCmpctMalformedModeEndsSession(t *testing.T) {
	cmd, logs := startRustSendCmpctSync(t, "3:2")
	stderr := waitRustInteropExit1(t, cmd, logs)
	if err := checkPeerCloseActionError(stderr); err != nil {
		t.Fatal(err)
	}
}

var peerCloseOSError = regexp.MustCompile(`^(Connection reset by peer|Broken pipe|Software caused connection abort|Invalid argument) \(os error [0-9]+\)$`)

// checkPeerCloseActionError accepts helper stderr only when the session ended
// after the handshake because the peer closed it, not because the helper's
// own read deadline expired.
func checkPeerCloseActionError(stderr string) error {
	text, ok := strings.CutPrefix(strings.TrimSuffix(stderr, "\n"), "action: ")
	if !ok {
		return fmt.Errorf("stderr=%q, want prefix %q", stderr, "action: ")
	}
	for _, bad := range []string{"peer read timeout", "deadline exceeded", "timed out", "temporarily unavailable"} {
		if strings.Contains(text, bad) {
			return fmt.Errorf("stderr=%q contains %q, want a peer close", stderr, bad)
		}
	}
	if text == "peer closed connection" || peerCloseOSError.MatchString(text) {
		return nil
	}
	return fmt.Errorf("stderr=%q, want a peer close error", stderr)
}

func TestRustInterop_SendCmpctPeerCloseCheckClassifiesStderr(t *testing.T) {
	for _, stderr := range []string{
		"action: peer closed connection\n",
		"action: Connection reset by peer (os error 54)\n",
		"action: Broken pipe (os error 32)",
		"action: Software caused connection abort (os error 103)\n",
		"action: Invalid argument (os error 22)\n",
	} {
		if err := checkPeerCloseActionError(stderr); err != nil {
			t.Errorf("accept %q: %v", stderr, err)
		}
	}
	for _, stderr := range []string{
		"action: peer read timeout\n",
		"action: Resource temporarily unavailable (os error 35)\n",
		"action: operation timed out (os error 60)\n",
		"handshake: peer closed connection\n",
		"action: sync height mismatch: got 1 want 5\n",
		"action: (os error x)\n",
		"action: No space left on device (os error 28)\n",
		"action: A connection attempt failed (os error 10060)\n",
		"action: Connection reset by peer (os error x)\n",
		"action: Broken pipe (os error 32) x\n",
		"action: create blockstore directory /x: Invalid argument (os error 22)\n",
		"action: read: peer closed connection\n",
		"action: peer closed connection after peer read timeout\n",
	} {
		if checkPeerCloseActionError(stderr) == nil {
			t.Errorf("reject %q: accepted", stderr)
		}
	}
}

func startInteropSyncSource(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	if err := source.service.Start(ctx); err != nil {
		t.Fatalf("source.Start: %v", err)
	}
	t.Cleanup(func() { _ = source.service.Close() })
	return source.service.Addr()
}

func startRustSendCmpctSync(t *testing.T, value string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	bin := requireRustInterop(t)
	addr := startInteropSyncSource(t)
	cmd, logs := startRustInteropClient(t, bin, addr, "sync-blocks", "--sendcmpct", value)
	t.Cleanup(func() { terminateHelper(cmd) })
	return cmd, logs
}

// sendCmpctProxy records the injection result. settled is closed once the
// injection is written or the proxy has stopped, so a reader of injected that
// waits on settled observes the final count.
type sendCmpctProxy struct {
	injected atomic.Int32
	settled  chan struct{}
}

func startGoSendCmpctProxySync(t *testing.T, payload []byte) (*exec.Cmd, *bytes.Buffer, *sendCmpctProxy) {
	t.Helper()
	bin := requireRustInterop(t)
	addr := startInteropSyncSource(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	proxy := &sendCmpctProxy{settled: make(chan struct{})}
	go runSendCmpctProxy(ctx, listener, addr, payload, proxy)
	cmd, logs := startRustInteropClient(t, bin, listener.Addr().String(), "sync-blocks")
	t.Cleanup(func() { terminateHelper(cmd) })
	return cmd, logs, proxy
}

// runSendCmpctProxy forwards one Rust connection to the Go Service. Rust-to-Go
// bytes are copied unchanged; Go-to-Rust frames are forwarded by this single
// goroutine, which writes the injected sendcmpct right after the Service's own
// sendcmpct and before reading any further Service frame.
func runSendCmpctProxy(ctx context.Context, listener net.Listener, serviceAddr string, payload []byte, proxy *sendCmpctProxy) {
	settled := false
	defer func() {
		if !settled {
			close(proxy.settled)
		}
	}()
	rustConn, err := listener.Accept()
	if err != nil {
		return
	}
	defer rustConn.Close()
	var dialer net.Dialer
	goConn, err := dialer.DialContext(ctx, "tcp", serviceAddr)
	if err != nil {
		return
	}
	defer goConn.Close()
	go func() {
		_, _ = io.Copy(goConn, rustConn)
		_ = goConn.Close()
	}()
	magic := networkMagic("devnet")
	maxSize := node.DefaultPeerRuntimeConfig("devnet", 8).MaxMessageSize
	pending := true
	for {
		frame, err := readFrame(goConn, magic, maxSize)
		if err != nil || writeFrame(rustConn, magic, frame, maxSize) != nil {
			return
		}
		if !pending || frame.Command != messageSendCmpct {
			continue
		}
		pending = false
		if writeFrame(rustConn, magic, message{Command: messageSendCmpct, Payload: payload}, maxSize) != nil {
			return
		}
		proxy.injected.Add(1)
		settled = true
		close(proxy.settled)
	}
}

func requireOneInjection(t *testing.T, proxy *sendCmpctProxy) {
	t.Helper()
	select {
	case <-proxy.settled:
	case <-time.After(5 * time.Second):
	}
	if got := proxy.injected.Load(); got != 1 {
		t.Fatalf("injected sendcmpct frames=%d, want 1", got)
	}
}

// waitRustInteropExit1 requires the helper to exit with code 1 before the
// 5-second deadline and returns its stderr.
func waitRustInteropExit1(t *testing.T, cmd *exec.Cmd, logs *bytes.Buffer) string {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case <-done:
		if code := cmd.ProcessState.ExitCode(); code != 1 {
			t.Fatalf("rust helper exit code=%d, want 1\nstderr:\n%s", code, logs.String())
		}
		return logs.String()
	case <-time.After(5 * time.Second):
		terminateHelper(cmd)
		<-done
		t.Fatalf("rust helper timeout, want exit 1\nstderr:\n%s", logs.String())
	}
	return ""
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
		_ = cmd.Wait()
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
		<-done
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
