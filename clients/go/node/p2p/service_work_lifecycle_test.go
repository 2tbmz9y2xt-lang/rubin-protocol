package p2p

import (
	"bytes"
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

// Service work lifecycle evidence. Barriers are channels and sockets; time-based waits are only watchdogs and the negative window asserting Close stays blocked.
// Dead dial targets are structurally dead: no process can ever listen on TCP port 0, so "127.0.0.%d:0" dials fail immediately with no rebind window at all.
// normalizeNetAddr rejects port 0, so the never-dialed rejection rows on the normalize-first surfaces (connectDiscoveredAddrs, addrMgr) use loopback port 1 — each is rejected before any dial; the one dialed discovered endpoint is a test-owned listener.
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

// requireStillBlocked asserts a registered lease still pins the operation. It is parked on a barrier this test owns, so a return inside the window is a lost drain.
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
	waitUntil(t, func() bool { return !s.workAuthorized() }, "Close publishing the non-OPEN state")
}

func requireClosedRejection(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil || err.Error() != "service already closed" {
		t.Fatalf("%s err=%v, want %q", label, err, "service already closed")
	}
}

// waitUntil polls cond until it holds, failing after the watchdog.
func waitUntil(t *testing.T, cond func() bool, label string) {
	t.Helper()
	for deadline := time.Now().Add(lifecycleWatchdog); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen before the watchdog", label)
		}
		time.Sleep(time.Millisecond)
	}
}

// requireRejectedInbound dials the listener and requires the accepted socket to be closed without any spawned child writing its version frame first.
func requireRejectedInbound(t *testing.T, s *Service, label string) {
	t.Helper()
	conn, err := net.Dial("tcp", s.Addr())
	must(t, err, "dial "+label)
	must(t, conn.SetReadDeadline(time.Now().Add(lifecycleWatchdog)), "SetReadDeadline")
	if n, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatalf("%s: the rejected inbound connection received %d bytes", label, n)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("%s: the inbound connection was never rejected before the deadline", label)
	}
	must(t, conn.Close(), "close "+label)
}

// lifecycleGateConn optionally holds the first Write until the test releases it (entered/release non-nil), parking a call inside a real socket write while Close runs;
// optionally counts every Write (writes non-nil) and every SetReadDeadline made after postDrain is set — a drained worker must arm none.
type lifecycleGateConn struct {
	net.Conn
	once      sync.Once
	entered   chan struct{}
	release   chan struct{}
	writes    *atomic.Int64
	postDrain atomic.Bool
	lateArms  atomic.Int64
}

func (c *lifecycleGateConn) Write(b []byte) (int, error) {
	if c.writes != nil {
		c.writes.Add(1)
	}
	if c.entered != nil {
		c.once.Do(func() {
			close(c.entered)
			<-c.release
		})
	}
	return c.Conn.Write(b)
}

func (c *lifecycleGateConn) SetReadDeadline(deadline time.Time) error {
	if c.postDrain.Load() {
		c.lateArms.Add(1)
	}
	return c.Conn.SetReadDeadline(deadline)
}

func lifecycleReadFrame(p *peer, r net.Conn) chan message {
	cfg := p.service.cfg.PeerRuntimeConfig
	out := make(chan message, 1)
	go func() {
		var frame message
		header, err := readFrameHeader(r, networkMagic(cfg.Network), cfg.MaxMessageSize)
		if err == nil {
			if payload, perr := readPayloadWithChecksum(r, header.Size, header.Checksum); perr == nil {
				frame = message{Command: header.Command, Payload: payload}
			}
		}
		out <- frame
	}()
	return out
}

// TestServiceWorkLifecycleEntryMatrix covers every Table A entry in OPEN and in DRAINING/CLOSED, plus the registration-versus-Close race.
func TestServiceWorkLifecycleEntryMatrix(t *testing.T) {
	s := newTestHarness(t, 0, "127.0.0.1:0", nil).service
	// Raised before Start so the accept-path child below stays parked in its read.
	s.cfg.PeerRuntimeConfig.HandshakeTimeout = lifecycleWatchdog
	must(t, s.Start(context.Background()), "Start")
	blockBytes := node.DevnetGenesisBlockBytes()
	must(t, s.AnnounceTx(minimalValidTxBytes(t)), "OPEN AnnounceTx")
	must(t, s.AnnounceBlock(blockBytes), "OPEN AnnounceBlock")
	must(t, s.ConsumeAcceptedBlockDASets(blockBytes), "OPEN ConsumeAcceptedBlockDASets")
	must(t, s.consumeCompleteDASetIDs(nil), "OPEN synchronous internal callee")
	// Registered-then-rejected register paths release the lease and add no reservation; a leaked lease would strand the final Close past its watchdog.
	if !s.trackDialPeer("127.0.0.21:0") || !s.trackDialPeer("127.0.0.22:1") {
		t.Fatal("pre-insert dial reservations")
	}
	if s.startDialPeer("127.0.0.21:0") {
		t.Fatal("duplicate outbound dial was registered")
	}
	s.connectDiscoveredAddrs([]string{"127.0.0.22:1"})
	if got := s.inFlightDialCount(); got != 2 {
		t.Fatalf("rejected register paths left %d reservations, want the 2 pre-inserted", got)
	}
	s.finishDialPeer("127.0.0.21:0")
	s.finishDialPeer("127.0.0.22:1")
	if !s.startDialPeer("127.0.0.1:0") {
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
	waitUntil(t, func() bool { return len(s.handshakeSlots) == 0 }, "the accepted child's handshake-slot release")
	// Slot-saturated accept: the worker lease registered before the slot check is released on rejection, or the final Close strands past its watchdog.
	for i := 0; i < cap(s.handshakeSlots); i++ {
		s.handshakeSlots <- struct{}{}
	}
	requireRejectedInbound(t, s, "the slot-saturated listener")
	for i := 0; i < cap(s.handshakeSlots); i++ {
		<-s.handshakeSlots
	}
	// Registration racing the first Close: the only admissible outcomes are registered-and-waited or rejected-without-Done. A third outcome (a lease added after Close began waiting) panics the WaitGroup, strands Close, or leaks a reservation.
	var starts sync.WaitGroup
	for i := 0; i < 16; i++ {
		addr := fmt.Sprintf("127.0.0.%d:0", 100+i)
		starts.Add(1)
		go func() { defer starts.Done(); s.startDialPeer(addr) }()
	}
	// startWG parks Close between its registration cutoff and the listener teardown (phase 2 waits on startWG, only phase 3 closes the listener), so the accept loop is still accepting while the Service is no longer OPEN.
	s.startWG.Add(1)
	closeDone := lifecycleClose(s)
	waitDraining(t, s)
	requireRejectedInbound(t, s, "the draining listener")
	requireZero(t, len(s.handshakeSlots), "handshake slots after the rejected accept")
	requireZero(t, s.connectedPeerCount(), "peers after the rejected accept")
	s.startWG.Done()
	requireReturned(t, closeDone, "Close")
	starts.Wait()
	requireZero(t, s.inFlightDialCount(), "in-flight dial reservations after Close")
	// Malformed bytes after Close pin the priority row: the registration gate precedes parsing, so the rejection is the exact closed error, never a parse error.
	requireClosedRejection(t, s.AnnounceTx([]byte{0x00}), "CLOSED malformed AnnounceTx")
	requireClosedRejection(t, s.AnnounceBlock([]byte{0x00}), "CLOSED malformed AnnounceBlock")
	requireClosedRejection(t, s.ConsumeAcceptedBlockDASets([]byte{0x00}), "CLOSED malformed ConsumeAcceptedBlockDASets")
	requireClosedRejection(t, s.Start(context.Background()), "CLOSED Start")
	if s.startDialPeer("127.0.0.30:0") {
		t.Fatal("CLOSED Service registered an outbound dial worker")
	}
	s.connectDiscoveredAddrs([]string{"127.0.0.31:1"})
	requireZero(t, s.inFlightDialCount(), "CLOSED discovered dial reservations")
	// Synchronous internal callees inherit and never register a nested lease, so they behave identically after the drain.
	must(t, s.consumeCompleteDASetIDs(nil), "CLOSED synchronous internal callee")
}

// TestServiceWorkLifecycleCloseWaitsForPublicCallbacks parks each real public entry on a producer, socket-write or DA-owner-lock barrier while Close runs, then observes the owners.
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
		// The broadcast already snapshotted its peer list, so removing the entry here leaves the in-flight write owned solely by the call: Close cannot shortcut it.
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
		// The Service is still OPEN, so the call cannot have been rejected: not returning here means it holds its lease and is parked on the DA owner lock.
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

// TestServiceWorkLifecyclePeerWorkerInheritance runs a real peer loop and handler stack: one authorized message finishes its publication and its owed compact fallback while Close waits, and after the drain the worker arms no read deadline and starts no further read.
func TestServiceWorkLifecyclePeerWorkerInheritance(t *testing.T) {
	s := lifecycleService(t)
	s.cfg.PeerRuntimeConfig.ReadDeadline = 0
	s.cfg.PeerRuntimeConfig.WriteDeadline = 0
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	gate := &lifecycleGateConn{Conn: local, entered: make(chan struct{}), release: make(chan struct{})}
	p := &peer{conn: gate, service: s, state: node.PeerState{Addr: "lifecycle-loop-peer"}}
	must(t, s.cfg.PeerManager.AddPeer(&p.state), "AddPeer")
	if !s.acquireWork() {
		t.Fatal("OPEN peer worker was not registered")
	}
	runDone := make(chan error, 1)
	go func() { defer s.releaseWork(); runDone <- p.run(context.Background()) }()
	// The gate parks the worker inside its reply write, past every deadline arm of this iteration. The loop context is never cancelled and the socket is never closed, so only the read-authorization gate stops it.
	_, err := remote.Write(mustPeerRuntimeFrameBytes(t, p, message{Command: messageGetAddr}))
	must(t, err, "write authorized message")
	<-gate.entered
	// An already-expired compact outstanding staged while the worker is parked is owed exactly one getdata fallback.
	fallbackHash := node.DevnetGenesisBlockHash()
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: fallbackHash, BlockTxnPayloadCap: 1, ExpiresAt: time.Unix(1, 0)})
	closeDone := lifecycleClose(s)
	waitDraining(t, s)
	requireStillBlocked(t, closeDone, "Close")
	gate.postDrain.Store(true)
	must(t, remote.SetReadDeadline(time.Now().Add(lifecycleWatchdog)), "SetReadDeadline")
	close(gate.release)
	if frame := <-lifecycleReadFrame(p, remote); frame.Command != messageAddr {
		t.Fatalf("authorized message reply command=%q, want %q", frame.Command, messageAddr)
	}
	// The owed fallback is still delivered after the drain was published: the guard sits between the fallback flush and the next deadline arm, never above the flush.
	fallback := <-lifecycleReadFrame(p, remote)
	if fallback.Command != messageGetData || !bytes.Equal(fallback.Payload, append([]byte{MSG_BLOCK}, fallbackHash[:]...)) {
		t.Fatalf("owed compact fallback command=%q payload=%x", fallback.Command, fallback.Payload)
	}
	requireReturned(t, runDone, "peer worker")
	requireReturned(t, closeDone, "Close")
	// Every read attempt in the loop arms the deadline first, so zero post-drain arms plus the worker's exit prove no further read began after the drain was published.
	requireZero(t, int(gate.lateArms.Load()), "post-drain read-deadline arms on the worker conn")
}

// TestServiceWorkLifecycleDiscoveredDialRejectedDuringDrain proves the discovered-dial child is waited for while OPEN, and that while Close is provably still in flight a concurrent discovered burst leaves no attempt, no reservation and no dial child.
func TestServiceWorkLifecycleDiscoveredDialRejectedDuringDrain(t *testing.T) {
	s := lifecycleService(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err, "listen for the discovered dial target")
	defer func() { _ = lis.Close() }()
	go func() {
		if conn, aerr := lis.Accept(); aerr == nil {
			_ = conn.Close()
		}
	}()
	openAddr, drainAddr := lis.Addr().String(), "127.0.0.2:1"
	s.addrMgr.AddAddrs([]string{openAddr, drainAddr})
	s.connectDiscoveredAddrs([]string{openAddr})
	if attempts := lifecycleAddrAttempts(s, openAddr); attempts != 1 {
		t.Fatalf("OPEN discovered dial attempts=%d, want 1", attempts)
	}
	// The OPEN child's own cleanup releases its reservation before any Close runs.
	waitUntil(t, func() bool { return s.inFlightDialCount() == 0 }, "the OPEN discovered dial reservation release")
	// Park Close in phase 2: every rejection below happens while the drain is published and the teardown is demonstrably unfinished, not merely after it.
	s.startWG.Add(1)
	closeDone := lifecycleClose(s)
	waitDraining(t, s)
	var burst sync.WaitGroup
	for i := 0; i < 4; i++ {
		burst.Add(1)
		go func() { defer burst.Done(); s.connectDiscoveredAddrs([]string{drainAddr}) }()
	}
	burst.Wait()
	requireStillBlocked(t, closeDone, "Close")
	requireZero(t, lifecycleAddrAttempts(s, drainAddr), "draining discovered dial attempts")
	requireZero(t, s.inFlightDialCount(), "draining discovered dial reservations")
	s.startWG.Done()
	requireReturned(t, closeDone, "Close")
}

func lifecycleAddrAttempts(s *Service, addr string) int {
	s.addrMgr.mu.Lock()
	defer s.addrMgr.mu.Unlock()
	return s.addrMgr.addrs[normalizeNetAddr(addr)].attempts
}

// lifecycleDeadlineConn records connection-deadline mutations that are still in flight, so the test can prove no handshake child touches the connection after performHandshake returned.
// Only non-zero deadlines — the interrupter always sets one — are delayed and counted: delaying performHandshake's own reset-to-zero defer would let the parent's own delay mask an unjoined interrupter instead of exposing it.
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
	// Widen the window in which a non-joined interrupter would still be mutating the connection: with the reset defer undelayed, an unjoined interrupter is provably still inside this sleep when performHandshake returns, so the in-flight check fails.
	time.Sleep(50 * time.Millisecond)
	return err
}

// TestServiceWorkLifecycleFaultMatrix covers Table C: the real cancellation child exits before performHandshake returns, and error, write-failure and no-publication exits release once.
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
			_, err := performHandshake(ctx, conn, cfg, node.VersionPayloadV1{ProtocolVersion: ProtocolVersion}, node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash())
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
		// Socket-owner write-failure and no-publication rows: the first announcement writes and fails against a socket nobody reads, the deduplicated second never publishes.
		s.cfg.PeerRuntimeConfig.WriteDeadline = time.Millisecond
		local, remote := net.Pipe()
		defer func() { _ = remote.Close() }()
		var writes atomic.Int64
		p := &peer{conn: &lifecycleGateConn{Conn: local, writes: &writes}, service: s, state: node.PeerState{Addr: "lifecycle-fault-peer"}}
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

// TestServiceWorkLifecyclePanicRelease proves a native panic unwind releases the call lease before propagating, so Close is not stranded; the only recover is this test's own frame.
func TestServiceWorkLifecyclePanicRelease(t *testing.T) {
	s := lifecycleService(t)
	s.cfg.TxMetadataFunc = func([]byte) (node.RelayTxMetadata, error) { panic("lifecycle test panic") }
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

// TestServiceWorkLifecycleConcurrentClose parks the owning Close in phase 2 and proves later Close calls join that one teardown:
// every joiner stays parked on the shared completion while the teardown is demonstrably unfinished, and exactly one teardown runs.
func TestServiceWorkLifecycleConcurrentClose(t *testing.T) {
	s := newTestHarness(t, 0, "127.0.0.1:0", nil).service
	must(t, s.Start(context.Background()), "Start")
	bound := s.Addr()
	s.startWG.Add(1)
	closes := []chan error{lifecycleClose(s)}
	waitDraining(t, s)
	for i := 0; i < 4; i++ {
		closes = append(closes, lifecycleClose(s))
	}
	for i, done := range closes {
		requireStillBlocked(t, done, fmt.Sprintf("Close %d", i))
	}
	s.startWG.Done()
	for i, done := range closes {
		requireReturned(t, done, fmt.Sprintf("Close %d", i))
	}
	s.peersMu.RLock()
	shared := s.closeDone
	s.peersMu.RUnlock()
	// A nil shared channel is never ready, so this also fails when no completion was published.
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

// TestServiceWorkLifecycleReadOnlyAfterClose proves read-only queries stay callable without a lease and a retained callback rejects with the exact error and zero state/queue/send delta.
func TestServiceWorkLifecycleReadOnlyAfterClose(t *testing.T) {
	s := lifecycleService(t)
	daID, snapshotID := daRelayTestID(0x7e), daRelayTestID(0x7f)
	blockBytes := stageCompleteDASet(t, s.daRelay, daID, "lifecycle-readonly", []byte("readonly-payload"))
	payload := []byte("snapshot-payload")
	mustAddDACommit(t, s.daRelay, "lifecycle-snapshot", daRelayTestCommitWithTxBytes(snapshotID, 1, []byte("commit-tx"), payload))
	mustAddDAChunk(t, s.daRelay, "lifecycle-snapshot", daRelayTestChunkWithTxBytes(snapshotID, 0, uint64(len(payload)), []byte("chunk-tx"), payload))
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

// TestServiceWorkLifecycleFreshServiceIndependent proves a closed Service never revives and that a fresh Service owns an independent OPEN lifecycle.
func TestServiceWorkLifecycleFreshServiceIndependent(t *testing.T) {
	closedService := lifecycleService(t)
	requireReturned(t, lifecycleClose(closedService), "Close")
	requireClosedRejection(t, closedService.AnnounceTx(minimalValidTxBytes(t)), "closed AnnounceTx")
	fresh := lifecycleService(t)
	must(t, fresh.AnnounceTx(minimalValidTxBytes(t)), "fresh Service AnnounceTx")
	requireClosedRejection(t, closedService.AnnounceBlock(node.DevnetGenesisBlockBytes()), "closed AnnounceBlock")
	requireReturned(t, lifecycleClose(fresh), "fresh Close")
}
