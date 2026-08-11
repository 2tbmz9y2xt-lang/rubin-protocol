package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// Service work lifecycle evidence. Barriers are channels and sockets; time-based
// waits are only watchdogs and the negative window asserting Close stays blocked.
const (
	lifecycleWatchdog = 5 * time.Second
	lifecycleSettle   = 100 * time.Millisecond
)

func lifecycleService(t *testing.T) *Service {
	t.Helper()
	s := newTestHarness(t, 0, "127.0.0.1:0", nil).service
	s.ctx = context.Background()
	return s
}

func lifecycleClose(s *Service) chan error {
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	return done
}

// deadAddr returns a loopback address that refuses connections: the
// listener that owned the ephemeral port is closed before returning.
func deadAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err, "reserve dead port")
	addr := l.Addr().String()
	must(t, l.Close(), "release dead port")
	return addr
}

func must(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
}

func requireZero(t *testing.T, got int, label string) {
	t.Helper()
	if got != 0 {
		t.Fatalf("%s=%d, want 0", label, got)
	}
}

// requireStillBlocked asserts a registered lease still pins the operation. It is
// parked on a barrier this test owns, so a return inside the window is a lost drain.
func requireStillBlocked(t *testing.T, done <-chan error, label string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("%s returned (err=%v) while a registered lease was held", label, err)
	case <-time.After(lifecycleSettle):
	}
}

func requireReturned(t *testing.T, done <-chan error, label string) {
	t.Helper()
	select {
	case err := <-done:
		must(t, err, label)
	case <-time.After(lifecycleWatchdog):
		t.Fatalf("%s did not return within %s", label, lifecycleWatchdog)
	}
}

// waitDraining blocks until Close published the non-OPEN state, so no later assertion can pass merely because Close had not started yet.
func waitDraining(t *testing.T, s *Service) {
	t.Helper()
	deadline := time.Now().Add(lifecycleWatchdog)
	for s.workAuthorized() {
		if time.Now().After(deadline) {
			t.Fatal("Close did not publish the non-OPEN state")
		}
		time.Sleep(time.Millisecond)
	}
}

func requireClosedRejection(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil || err.Error() != "service already closed" {
		t.Fatalf("%s err=%v, want %q", label, err, "service already closed")
	}
}

// lifecycleGateConn holds the first Write until the test releases it, parking a public call inside a real socket write while Close runs.
type lifecycleGateConn struct {
	net.Conn
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (c *lifecycleGateConn) Write(b []byte) (int, error) {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return c.Conn.Write(b)
}

type lifecycleCountingConn struct {
	net.Conn
	writes *atomic.Int64
}

func (c *lifecycleCountingConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(b)
}

func lifecycleReadFrame(p *peer, r net.Conn) chan message {
	magic := networkMagic(p.service.cfg.PeerRuntimeConfig.Network)
	maxSize := p.service.cfg.PeerRuntimeConfig.MaxMessageSize
	out := make(chan message, 1)
	go func() {
		header, err := readFrameHeader(r, magic, maxSize)
		if err != nil {
			out <- message{}
			return
		}
		payload, err := readPayloadWithChecksum(r, header.Size, header.Checksum)
		if err != nil {
			out <- message{}
			return
		}
		out <- message{Command: header.Command, Payload: payload}
	}()
	return out
}

// TestServiceWorkLifecycleEntryMatrix covers every Table A entry in OPEN and in DRAINING/CLOSED, plus the registration-versus-Close race.
func TestServiceWorkLifecycleEntryMatrix(t *testing.T) {
	s := newTestHarness(t, 0, "127.0.0.1:0", nil).service
	// Raised before Start so the accept-path child below stays parked in its read.
	s.cfg.PeerRuntimeConfig.HandshakeTimeout = lifecycleWatchdog
	must(t, s.Start(context.Background()), "Start")
	txBytes := minimalValidTxBytes(t)
	blockBytes := node.DevnetGenesisBlockBytes()
	must(t, s.AnnounceTx(txBytes), "OPEN AnnounceTx")
	must(t, s.AnnounceBlock(blockBytes), "OPEN AnnounceBlock")
	must(t, s.ConsumeAcceptedBlockDASets(blockBytes), "OPEN ConsumeAcceptedBlockDASets")
	must(t, s.consumeCompleteDASetIDs(nil), "OPEN synchronous internal callee")
	if !s.startDialPeer(deadAddr(t)) {
		t.Fatal("OPEN outbound dial was not registered")
	}

	// Accept path in OPEN: the gate registers the accepted worker before it mutates a handshake slot or spawns the child that writes this frame.
	open, err := net.Dial("tcp", s.Addr())
	must(t, err, "dial the OPEN listener")
	must(t, open.SetReadDeadline(time.Now().Add(lifecycleWatchdog)), "SetReadDeadline")
	if _, err := open.Read(make([]byte, 1)); err != nil {
		t.Fatalf("the OPEN accepted child never wrote its version frame: %v", err)
	}
	if got := len(s.handshakeSlots); got != 1 {
		t.Fatalf("handshake slots while OPEN=%d, want 1", got)
	}
	// Closing the client fails that handshake; the child releases its one slot.
	must(t, open.Close(), "close the OPEN client conn")
	for deadline := time.Now().Add(lifecycleWatchdog); len(s.handshakeSlots) != 0; {
		if time.Now().After(deadline) {
			t.Fatal("the accepted child did not release its handshake slot")
		}
		time.Sleep(time.Millisecond)
	}

	// Registration racing the first Close: the only admissible outcomes are
	// registered-and-waited or rejected-without-Done. A third outcome (a lease added after
	// Close began waiting) panics the WaitGroup, strands Close, or leaks a reservation.
	var registered atomic.Int64
	var starts sync.WaitGroup
	for i := 0; i < 16; i++ {
		addr := deadAddr(t)
		starts.Add(1)
		go func() {
			defer starts.Done()
			if s.startDialPeer(addr) {
				registered.Add(1)
			}
		}()
	}
	// startWG parks Close between its registration cutoff and the listener teardown (phase 2 waits on startWG, only
	// phase 3 closes the listener), so the accept loop is still accepting while the Service is no longer OPEN.
	s.startWG.Add(1)
	closeDone := lifecycleClose(s)
	waitDraining(t, s)
	drained, err := net.Dial("tcp", s.Addr())
	must(t, err, "dial the draining listener")
	must(t, drained.SetReadDeadline(time.Now().Add(lifecycleWatchdog)), "SetReadDeadline")
	// The gate closed the socket with no child behind it: a spawned child would have written its version frame here first.
	if n, err := drained.Read(make([]byte, 1)); err == nil {
		t.Fatalf("the rejected inbound connection received %d bytes", n)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the rejected inbound connection was never accepted before the deadline")
	}
	requireZero(t, len(s.handshakeSlots), "handshake slots after the rejected accept")
	requireZero(t, s.connectedPeerCount(), "peers after the rejected accept")
	must(t, drained.Close(), "close the rejected client conn")
	s.startWG.Done()
	requireReturned(t, closeDone, "Close")
	starts.Wait()
	requireZero(t, s.inFlightDialCount(), "in-flight dial reservations after Close")
	t.Logf("registration race: %d of 16 dial workers registered before the cutoff", registered.Load())

	requireClosedRejection(t, s.AnnounceTx(minimalValidTxBytes(t)), "CLOSED AnnounceTx")
	requireClosedRejection(t, s.AnnounceBlock(blockBytes), "CLOSED AnnounceBlock")
	requireClosedRejection(t, s.ConsumeAcceptedBlockDASets(blockBytes), "CLOSED ConsumeAcceptedBlockDASets")
	requireClosedRejection(t, s.Start(context.Background()), "CLOSED Start")
	if s.startDialPeer(deadAddr(t)) {
		t.Fatal("CLOSED Service registered an outbound dial worker")
	}
	s.connectDiscoveredAddrs([]string{deadAddr(t)})
	requireZero(t, s.inFlightDialCount(), "CLOSED discovered dial reservations")
	// Synchronous internal callees inherit and never register a nested lease,
	// so they behave identically after the drain; read-only queries stay valid.
	must(t, s.consumeCompleteDASetIDs(nil), "CLOSED synchronous internal callee")
	if s.Addr() == "" {
		t.Fatal("CLOSED read-only Addr() returned empty")
	}
}

// TestServiceWorkLifecycleCloseWaitsForPublicCallbacks parks each real public entry on a
// producer, socket-write or DA-owner-lock barrier while Close runs, then observes the owners.
func TestServiceWorkLifecycleCloseWaitsForPublicCallbacks(t *testing.T) {
	t.Run("producer barrier in AnnounceTx", func(t *testing.T) {
		s := lifecycleService(t)
		entered, release := make(chan struct{}), make(chan struct{})
		s.cfg.TxMetadataFunc = func(b []byte) (node.RelayTxMetadata, error) {
			close(entered)
			<-release
			return node.RelayTxMetadata{Fee: consensus.Uint128FromU64(0), Size: len(b)}, nil
		}
		txBytes := minimalValidTxBytes(t)
		_, txid, err := parseCanonicalTx(txBytes)
		must(t, err, "parseCanonicalTx")
		announce := make(chan error, 1)
		go func() { announce <- s.AnnounceTx(txBytes) }()
		<-entered
		closeDone := lifecycleClose(s)
		waitDraining(t, s)
		requireStillBlocked(t, closeDone, "Close")
		close(release)
		requireReturned(t, closeDone, "Close")
		must(t, <-announce, "pre-authorized AnnounceTx")
		if _, ok := s.cfg.TxPool.Get(txid); !ok {
			t.Fatal("pre-authorized AnnounceTx did not reach the real relay pool")
		}
	})

	t.Run("socket write barrier in AnnounceBlock", func(t *testing.T) {
		s := lifecycleService(t)
		s.cfg.PeerRuntimeConfig.WriteDeadline = 0
		local, remote := net.Pipe()
		defer func() { _ = remote.Close() }()
		gate := &lifecycleGateConn{Conn: local, entered: make(chan struct{}), release: make(chan struct{})}
		p := &peer{conn: gate, service: s, state: node.PeerState{Addr: "lifecycle-write-peer"}}
		s.peers[p.addr()] = p
		received := lifecycleReadFrame(p, remote)
		announce := make(chan error, 1)
		go func() { announce <- s.AnnounceBlock(node.DevnetGenesisBlockBytes()) }()
		<-gate.entered
		// The broadcast already snapshotted its peer list, so removing the entry here
		// leaves the in-flight write owned solely by the call: Close cannot shortcut it.
		s.peersMu.Lock()
		delete(s.peers, p.addr())
		s.peersMu.Unlock()
		closeDone := lifecycleClose(s)
		waitDraining(t, s)
		requireStillBlocked(t, closeDone, "Close")
		close(gate.release)
		requireReturned(t, closeDone, "Close")
		must(t, <-announce, "pre-authorized AnnounceBlock")
		frame := <-received
		items, err := decodeInventoryVectors(frame.Payload)
		if frame.Command != messageInv || err != nil || len(items) != 1 || items[0].Hash != node.DevnetGenesisBlockHash() {
			t.Fatalf("socket owner received command=%q inventory=%+v err=%v", frame.Command, items, err)
		}
		must(t, remote.SetReadDeadline(time.Now().Add(lifecycleSettle)), "SetReadDeadline")
		if n, err := remote.Read(make([]byte, 1)); err == nil {
			t.Fatalf("socket owner received %d more bytes after Close returned", n)
		}
	})

	t.Run("DA owner lock barrier in ConsumeAcceptedBlockDASets", func(t *testing.T) {
		s := lifecycleService(t)
		daID := daRelayTestID(0x7d)
		blockBytes := stageCompleteDASet(t, s.daRelay, daID, "lifecycle", []byte("lifecycle-payload"))
		s.daRelay.mu.Lock()
		consume := make(chan error, 1)
		go func() { consume <- s.ConsumeAcceptedBlockDASets(blockBytes) }()
		// The Service is still OPEN, so the call cannot have been rejected: not
		// returning here means it holds its lease and is parked on the DA owner lock.
		select {
		case err := <-consume:
			t.Fatalf("ConsumeAcceptedBlockDASets returned early: %v", err)
		case <-time.After(lifecycleSettle):
		}
		closeDone := lifecycleClose(s)
		waitDraining(t, s)
		requireStillBlocked(t, closeDone, "Close")
		s.daRelay.mu.Unlock()
		requireReturned(t, closeDone, "Close")
		must(t, <-consume, "pre-authorized ConsumeAcceptedBlockDASets")
		if lifecycleDASetPresent(s, daID) {
			t.Fatal("pre-authorized DA consume did not reach the real DA state owner")
		}
	})
}

func lifecycleDASetPresent(s *Service, daID [32]byte) bool {
	s.daRelay.mu.Lock()
	defer s.daRelay.mu.Unlock()
	_, ok := s.daRelay.sets[daID]
	return ok
}

// TestServiceWorkLifecyclePeerWorkerInheritance runs a real peer loop and handler stack: one
// authorized message finishes its publication while Close waits, and no further read begins.
func TestServiceWorkLifecyclePeerWorkerInheritance(t *testing.T) {
	s := lifecycleService(t)
	s.cfg.PeerRuntimeConfig.ReadDeadline = 0
	s.cfg.PeerRuntimeConfig.WriteDeadline = 0
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	p := &peer{conn: local, service: s, state: node.PeerState{Addr: "lifecycle-loop-peer"}}
	must(t, s.cfg.PeerManager.AddPeer(&p.state), "AddPeer")
	if !s.acquireWork() {
		t.Fatal("OPEN peer worker was not registered")
	}
	runDone := make(chan error, 1)
	go func() {
		defer s.releaseWork()
		runDone <- p.run(context.Background())
	}()

	// The write returns once the worker consumed the frame and nothing reads the reply yet, so the worker is provably
	// parked inside the handler's publication when the drain is published. The loop context is never cancelled and the
	// socket is never closed, so only the read-authorization observation stops this worker.
	_, err := remote.Write(mustPeerRuntimeFrameBytes(t, p, message{Command: messageGetAddr}))
	must(t, err, "write authorized message")
	closeDone := lifecycleClose(s)
	waitDraining(t, s)
	requireStillBlocked(t, closeDone, "Close")
	if frame := <-lifecycleReadFrame(p, remote); frame.Command != messageAddr {
		t.Fatalf("authorized message reply command=%q, want %q", frame.Command, messageAddr)
	}
	requireReturned(t, runDone, "peer worker")
	requireReturned(t, closeDone, "Close")

	// No next read was authorized: a further frame is never consumed.
	must(t, remote.SetWriteDeadline(time.Now().Add(lifecycleSettle)), "SetWriteDeadline")
	if _, err := remote.Write(mustPeerRuntimeFrameBytes(t, p, message{Command: messageGetAddr})); err == nil {
		t.Fatal("peer worker consumed a second frame after the drain was published")
	}
}

// TestServiceWorkLifecycleDiscoveredDialRejectedDuringDrain proves the discovered-dial child
// is waited for while OPEN, and a rejected dial leaves no goroutine, reservation or attempt.
func TestServiceWorkLifecycleDiscoveredDialRejectedDuringDrain(t *testing.T) {
	s := lifecycleService(t)
	openAddr, drainAddr := deadAddr(t), deadAddr(t)
	s.addrMgr.AddAddrs([]string{openAddr, drainAddr})
	s.connectDiscoveredAddrs([]string{openAddr})
	if attempts := lifecycleAddrAttempts(s, openAddr); attempts != 1 {
		t.Fatalf("OPEN discovered dial attempts=%d, want 1", attempts)
	}
	// Close returns only after the discovered child released its lease, so the child's own reservation cleanup has already run.
	requireReturned(t, lifecycleClose(s), "Close")
	requireZero(t, s.inFlightDialCount(), "in-flight dial reservations after Close")

	s.connectDiscoveredAddrs([]string{drainAddr})
	requireZero(t, s.inFlightDialCount(), "rejected discovered dial reservations")
	requireZero(t, lifecycleAddrAttempts(s, drainAddr), "rejected discovered dial attempts")
}

func lifecycleAddrAttempts(s *Service, addr string) int {
	s.addrMgr.mu.Lock()
	defer s.addrMgr.mu.Unlock()
	return s.addrMgr.addrs[normalizeNetAddr(addr)].attempts
}

// lifecycleDeadlineConn records connection-deadline mutations that are still in flight, so the test can prove no
// handshake child touches the connection after performHandshake returned. Only non-zero deadlines — the interrupter
// always sets one — are delayed and counted: delaying performHandshake's own reset-to-zero defer would let the
// parent's own delay mask an unjoined interrupter instead of exposing it.
type lifecycleDeadlineConn struct {
	net.Conn
	inFlight atomic.Int64
	late     atomic.Int64
	returned atomic.Bool
}

func (c *lifecycleDeadlineConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return c.Conn.SetDeadline(deadline)
	}
	c.inFlight.Add(1)
	defer c.inFlight.Add(-1)
	if c.returned.Load() {
		c.late.Add(1)
	}
	err := c.Conn.SetDeadline(deadline)
	// Widen the window in which a non-joined interrupter would still be mutating the
	// connection: with the reset defer undelayed, an unjoined interrupter is provably still
	// inside this sleep when performHandshake returns, so the in-flight check fails.
	time.Sleep(50 * time.Millisecond)
	return err
}

// TestServiceWorkLifecycleFaultMatrix covers Table C: the real cancellation child exits before
// performHandshake returns, and error, write-failure and no-publication exits release once.
func TestServiceWorkLifecycleFaultMatrix(t *testing.T) {
	t.Run("handshake cancellation child exits before return", func(t *testing.T) {
		local, remote := net.Pipe()
		defer func() { _ = remote.Close() }()
		conn := &lifecycleDeadlineConn{Conn: local}
		ctx, cancel := context.WithCancel(context.Background())
		cfg := node.DefaultPeerRuntimeConfig("devnet", 8)
		cfg.HandshakeTimeout = lifecycleWatchdog
		handshakeDone := make(chan struct{})
		go func() {
			defer close(handshakeDone)
			// The remote never answers, so only the cancellation child can unblock the handshake read.
			_, err := performHandshake(ctx, conn, cfg, node.VersionPayloadV1{ProtocolVersion: ProtocolVersion},
				node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash())
			conn.returned.Store(true)
			if err == nil {
				t.Error("performHandshake returned nil error on a cancelled handshake")
			}
		}()
		_, err := readFrameHeader(remote, networkMagic(cfg.Network), cfg.MaxMessageSize)
		must(t, err, "read handshake version header")
		cancel()
		select {
		case <-handshakeDone:
		case <-time.After(lifecycleWatchdog):
			t.Fatal("performHandshake did not return after cancellation")
		}
		requireZero(t, int(conn.inFlight.Load()), "deadline mutations in flight when performHandshake returned")
		time.Sleep(lifecycleSettle)
		requireZero(t, int(conn.late.Load()), "SetDeadline calls after performHandshake returned")
	})

	t.Run("error and no-publication exits release once", func(t *testing.T) {
		s := lifecycleService(t)
		if err := s.AnnounceBlock([]byte{0x00}); err == nil {
			t.Fatal("AnnounceBlock(malformed) must preserve the parse error")
		}
		s.cfg.TxMetadataFunc = func([]byte) (node.RelayTxMetadata, error) {
			return node.RelayTxMetadata{}, fmt.Errorf("producer failure")
		}
		if err := s.AnnounceTx(minimalValidTxBytes(t)); err == nil {
			t.Fatal("AnnounceTx must preserve the producer error")
		}
		// Socket-owner write-failure and no-publication rows: the first announcement writes
		// and fails against a socket nobody reads, the deduplicated second never publishes.
		s.cfg.PeerRuntimeConfig.WriteDeadline = time.Millisecond
		local, remote := net.Pipe()
		defer func() { _ = remote.Close() }()
		var writes atomic.Int64
		p := &peer{conn: &lifecycleCountingConn{Conn: local, writes: &writes}, service: s,
			state: node.PeerState{Addr: "lifecycle-fault-peer"}}
		s.peers[p.addr()] = p
		must(t, s.AnnounceBlock(node.DevnetGenesisBlockBytes()), "AnnounceBlock over a failing socket")
		if got := writes.Load(); got != 1 {
			t.Fatalf("write attempts on the first announcement=%d, want 1", got)
		}
		must(t, s.AnnounceBlock(node.DevnetGenesisBlockBytes()), "deduplicated AnnounceBlock")
		if got := writes.Load(); got != 1 {
			t.Fatalf("write attempts after the no-publication return=%d, want 1", got)
		}
		// Every one of those exits released its lease exactly once: a leak strands Close past the watchdog, an extra release panics it.
		requireReturned(t, lifecycleClose(s), "Close")
	})
}

// TestServiceWorkLifecyclePanicRelease proves a native panic unwind releases the call lease
// before propagating, so Close is not stranded; the only recover is this test's own frame.
func TestServiceWorkLifecyclePanicRelease(t *testing.T) {
	s := lifecycleService(t)
	s.cfg.TxMetadataFunc = func([]byte) (node.RelayTxMetadata, error) {
		panic("lifecycle test panic")
	}
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		_ = s.AnnounceTx(minimalValidTxBytes(t))
	}()
	if !panicked {
		t.Fatal("AnnounceTx did not propagate the producer panic")
	}
	requireReturned(t, lifecycleClose(s), "Close after a panicking call")
}

// TestServiceWorkLifecycleConcurrentClose proves concurrent and repeated Close
// calls join one teardown and all return only after it completes.
func TestServiceWorkLifecycleConcurrentClose(t *testing.T) {
	s := newTestHarness(t, 0, "127.0.0.1:0", nil).service
	must(t, s.Start(context.Background()), "Start")
	bound := s.Addr()
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() { results <- s.Close() }()
	}
	for i := 0; i < 8; i++ {
		requireReturned(t, results, "concurrent Close")
	}
	s.peersMu.RLock()
	shared := s.closeDone
	s.peersMu.RUnlock()
	if shared == nil {
		t.Fatal("no shared close completion was published")
	}
	select {
	case <-shared:
	default:
		t.Fatal("the shared close completion is not published as complete")
	}
	must(t, s.Close(), "repeated Close")
	// One teardown actually happened: the port is immediately rebindable.
	rebind, err := net.Listen("tcp", bound)
	must(t, err, fmt.Sprintf("port %q still bound after the shared teardown", bound))
	_ = rebind.Close()
}

// TestServiceWorkLifecycleReadOnlyAfterClose proves read-only queries stay callable without
// a lease and a retained callback rejects with the exact error and zero state/queue/send delta.
func TestServiceWorkLifecycleReadOnlyAfterClose(t *testing.T) {
	s := lifecycleService(t)
	daID, snapshotID := daRelayTestID(0x7e), daRelayTestID(0x7f)
	blockBytes := stageCompleteDASet(t, s.daRelay, daID, "lifecycle-readonly", []byte("readonly-payload"))
	payload := []byte("snapshot-payload")
	mustAddDACommit(t, s.daRelay, "lifecycle-snapshot",
		daRelayTestCommitWithTxBytes(snapshotID, 1, []byte("commit-tx"), payload))
	mustAddDAChunk(t, s.daRelay, "lifecycle-snapshot",
		daRelayTestChunkWithTxBytes(snapshotID, 0, uint64(len(payload)), []byte("chunk-tx"), payload))
	txBytes := minimalValidTxBytes(t)
	_, txid, err := parseCanonicalTx(txBytes)
	must(t, err, "parseCanonicalTx")
	exitsBefore := s.PeerLifecycleExits()
	requireReturned(t, lifecycleClose(s), "Close")

	if s.Addr() == "" {
		t.Fatal("Addr() after Close returned empty")
	}
	if got := s.PeerLifecycleExits(); got != exitsBefore {
		t.Fatalf("PeerLifecycleExits after Close=%d, want %d", got, exitsBefore)
	}
	if got := s.CompleteDASetCandidates(1 << 20); len(got) != 1 {
		t.Fatalf("defensive DA snapshot after Close returned %d candidates, want 1", len(got))
	}
	requireZero(t, s.connectedPeerCount(), "connectedPeerCount after Close")

	requireClosedRejection(t, s.AnnounceTx(txBytes), "retained AnnounceTx callback")
	requireClosedRejection(t, s.AnnounceBlock(blockBytes), "retained AnnounceBlock callback")
	requireClosedRejection(t, s.ConsumeAcceptedBlockDASets(blockBytes), "retained DA consume callback")
	if _, ok := s.cfg.TxPool.Get(txid); ok {
		t.Fatal("rejected AnnounceTx mutated the relay pool")
	}
	if !lifecycleDASetPresent(s, daID) {
		t.Fatal("rejected DA consume mutated the DA state owner")
	}
	if s.blockSeen.Has(node.DevnetGenesisBlockHash()) {
		t.Fatal("rejected AnnounceBlock mutated the block seen-set")
	}
}

// TestServiceWorkLifecycleFreshServiceIndependent proves a closed Service never
// revives and that a fresh Service owns an independent OPEN lifecycle.
func TestServiceWorkLifecycleFreshServiceIndependent(t *testing.T) {
	closedService := lifecycleService(t)
	requireReturned(t, lifecycleClose(closedService), "Close")
	requireClosedRejection(t, closedService.AnnounceTx(minimalValidTxBytes(t)), "closed AnnounceTx")
	fresh := lifecycleService(t)
	must(t, fresh.AnnounceTx(minimalValidTxBytes(t)), "fresh Service AnnounceTx")
	must(t, fresh.AnnounceBlock(node.DevnetGenesisBlockBytes()), "fresh Service AnnounceBlock")
	requireClosedRejection(t, closedService.AnnounceBlock(node.DevnetGenesisBlockBytes()), "closed AnnounceBlock")
	requireReturned(t, lifecycleClose(fresh), "fresh Close")
}
