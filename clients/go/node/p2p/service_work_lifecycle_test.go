package p2p

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// Service work lifecycle evidence. Barriers are channels and sockets; time-based waits are only watchdogs and the negative window asserting Close stays blocked.
// Dead dial targets are structurally dead: no process can ever listen on TCP port 0, so "127.0.0.%d:0" dials fail immediately with no rebind window at all. normalizeNetAddr rejects port 0, so the never-dialed rejection rows on the normalize-first surfaces (connectDiscoveredAddrs, addrMgr) use loopback port 1 — each is rejected before any dial; the one dialed discovered endpoint is a test-owned listener.
const (
	lifecycleWatchdog = 5 * time.Second
	lifecycleSettle   = 100 * time.Millisecond
)

type localDAAdmissionBarrier struct {
	consensus.DefaultRotationProvider
	entered    chan struct{}
	release    chan struct{}
	armed      *atomic.Bool
	panicValue any
	once       sync.Once
}

func (b *localDAAdmissionBarrier) NativeSpendSuites(height uint64) *consensus.NativeSuiteSet {
	if b.armed != nil && !b.armed.Load() {
		return b.DefaultRotationProvider.NativeSpendSuites(height)
	}
	b.once.Do(func() { close(b.entered) })
	<-b.release
	if b.panicValue != nil {
		panic(b.panicValue)
	}
	return b.DefaultRotationProvider.NativeSpendSuites(height)
}

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

// requireEqual fails unless got equals want; the label names the observed quantity.
func requireEqual[T comparable](t *testing.T, got, want T, label string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s=%v, want %v", label, got, want)
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
// optionally counts every Write (writes non-nil), fails every Write with a caller-owned sentinel (writeErr non-nil) with no timer or scheduler dependence at all, and counts every SetReadDeadline made after postDrain is set — a drained worker must arm none.
type lifecycleGateConn struct {
	net.Conn
	once      sync.Once
	entered   chan struct{}
	release   chan struct{}
	writes    *atomic.Int64
	writeErr  error
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
	if c.writeErr != nil {
		return 0, c.writeErr
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
	s.cfg.PeerRuntimeConfig.HandshakeTimeout = lifecycleWatchdog // raised before Start so the accept-path child below stays parked in its read
	must(t, s.Start(context.Background()), "Start")
	blockBytes := node.DevnetGenesisBlockBytes()
	must(t, s.AnnounceTx(minimalValidTxBytes(t)), "OPEN AnnounceTx")
	must(t, s.AnnounceBlock(blockBytes), "OPEN AnnounceBlock")
	requireEqual(t, s.trackDialPeer("127.0.0.21:0") && s.trackDialPeer("127.0.0.22:1"), true, "the pre-inserted dial reservations") // Registered-then-rejected register paths release the lease and add no reservation; a leaked lease would strand the final Close past its watchdog.
	requireEqual(t, s.startDialPeer("127.0.0.21:0"), false, "the duplicate outbound dial registration")
	s.connectDiscoveredAddrs([]string{"127.0.0.22:1"})
	requireEqual(t, s.inFlightDialCount(), 2, "reservations left by the rejected register paths (the 2 pre-inserted)")
	s.finishDialPeer("127.0.0.21:0")
	s.finishDialPeer("127.0.0.22:1")
	requireEqual(t, s.startDialPeer("127.0.0.1:0"), true, "the OPEN outbound dial registration")
	open, err := net.Dial("tcp", s.Addr()) // Accept path in OPEN: the gate registers the accepted worker before it mutates a handshake slot or spawns the child that writes this frame.
	must(t, err, "dial the OPEN listener")
	must(t, open.SetReadDeadline(time.Now().Add(lifecycleWatchdog)), "SetReadDeadline")
	_, err = open.Read(make([]byte, 1))
	must(t, err, "the version frame written by the OPEN accepted child")
	requireEqual(t, len(s.handshakeSlots), 1, "handshake slots while OPEN")
	must(t, open.Close(), "close the OPEN client conn") // closing the client fails that handshake; the child releases its one slot
	waitUntil(t, func() bool { return len(s.handshakeSlots) == 0 }, "the accepted child's handshake-slot release")
	for i := 0; i < cap(s.handshakeSlots); i++ { // Slot-saturated accept: the worker lease registered before the slot check is released on rejection, or the final Close strands past its watchdog.
		s.handshakeSlots <- struct{}{}
	}
	requireRejectedInbound(t, s, "the slot-saturated listener")
	for i := 0; i < cap(s.handshakeSlots); i++ {
		<-s.handshakeSlots
	}
	var starts sync.WaitGroup // Registration racing the first Close: the only admissible outcomes are registered-and-waited or rejected-without-Done. A third outcome (a lease added after Close began waiting) panics the WaitGroup, strands Close, or leaks a reservation.
	for i := 0; i < 16; i++ {
		addr := fmt.Sprintf("127.0.0.%d:0", 100+i)
		starts.Add(1)
		go func() { defer starts.Done(); s.startDialPeer(addr) }()
	}
	s.startWG.Add(1) // startWG parks Close between its registration cutoff and the listener teardown (phase 2 waits on startWG, only phase 3 closes the listener), so the accept loop is still accepting while the Service is no longer OPEN.
	closeDone := lifecycleClose(s)
	waitDraining(t, s)
	requireRejectedInbound(t, s, "the draining listener")
	requireEqual(t, len(s.handshakeSlots), 0, "handshake slots after the rejected accept")
	requireEqual(t, s.connectedPeerCount(), 0, "peers after the rejected accept")
	s.startWG.Done()
	requireReturned(t, closeDone, "Close")
	starts.Wait()
	requireEqual(t, s.inFlightDialCount(), 0, "in-flight dial reservations after Close")
	requireClosedRejection(t, s.AnnounceTx([]byte{0x00}), "CLOSED malformed AnnounceTx") // Malformed bytes after Close pin the priority row: the registration gate precedes parsing, so the rejection is the exact closed error, never a parse error.
	requireClosedRejection(t, s.AnnounceBlock([]byte{0x00}), "CLOSED malformed AnnounceBlock")
	requireClosedRejection(t, s.Start(context.Background()), "CLOSED Start")
	requireEqual(t, s.startDialPeer("127.0.0.30:0"), false, "the CLOSED outbound dial registration")
	s.connectDiscoveredAddrs([]string{"127.0.0.31:1"})
	requireEqual(t, s.inFlightDialCount(), 0, "CLOSED discovered dial reservations")
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
		_, pooled := s.cfg.TxPool.Get(txid)
		requireEqual(t, pooled, true, "the pre-authorized AnnounceTx reaching the real relay pool")
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
		s.peersMu.Lock() // The broadcast already snapshotted its peer list, so removing the entry here leaves the in-flight write owned solely by the call: Close cannot shortcut it.
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
}

func TestServiceLocalDAWorkLifecycle(t *testing.T) {
	t.Run("nil and closed reject before effects", func(t *testing.T) {
		var nilService *Service
		got, err := nilService.AdmitLocalDA(nil)
		var admitErr *node.TxAdmitError
		if got != (node.DAAdmissionResult{}) || !errors.As(err, &admitErr) || admitErr.Kind != node.TxAdmitUnavailable || err.Error() != "nil service" {
			t.Fatalf("nil AdmitLocalDA=(%+v,%v)", got, err)
		}
		if err := nilService.ScheduleLocalDAPrefetch([32]byte{}); err == nil || err.Error() != "nil service" {
			t.Fatalf("nil ScheduleLocalDAPrefetch=%v", err)
		}
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		raw := newDAIngressFixture(t, h).commit(daRelayTestID(0xe1), 2)
		must(t, h.service.Close(), "Close")
		got, err = h.service.AdmitLocalDA(raw)
		admitErr = nil
		if got != (node.DAAdmissionResult{}) || !errors.As(err, &admitErr) || admitErr.Kind != node.TxAdmitUnavailable || err.Error() != "service already closed" {
			t.Fatalf("closed AdmitLocalDA=(%+v,%v)", got, err)
		}
		if err := h.service.ScheduleLocalDAPrefetch([32]byte{}); !errors.Is(err, errServiceClosed) {
			t.Fatalf("closed ScheduleLocalDAPrefetch=%v", err)
		}
	})
	t.Run("accepted calls release their work", func(t *testing.T) {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		f := newDAIngressFixture(t, h)
		got, err := h.service.AdmitLocalDA(f.commit(daRelayTestID(0xe2), 2))
		if err != nil || got.Disposition != node.DAAdmissionRetained {
			t.Fatalf("AdmitLocalDA=(%+v,%v)", got, err)
		}
		if _, err := h.service.AdmitLocalDA([]byte{0x00}); err == nil {
			t.Fatal("malformed AdmitLocalDA returned nil")
		}
		requireReturned(t, lifecycleClose(h.service), "Close after retained and error exits")
	})
	t.Run("Close waits for panicking accepted admission", func(t *testing.T) {
		base := newTestHarness(t, 1, "127.0.0.1:0", nil)
		sentinel := &struct{ message string }{message: "local DA admission panic"}
		barrier := &localDAAdmissionBarrier{entered: make(chan struct{}), release: make(chan struct{}), panicValue: sentinel}
		var releaseOnce sync.Once
		releaseBarrier := func() { releaseOnce.Do(func() { close(barrier.release) }) }
		engine, err := node.NewSyncEngine(base.chainState, base.blockStore, base.syncCfg)
		must(t, err, "NewSyncEngine")
		mempoolCfg := node.DefaultMempoolConfig()
		mempoolCfg.RotationProvider = barrier
		mempool, err := node.NewMempoolWithConfig(base.chainState, base.blockStore, node.DevnetGenesisChainID(), mempoolCfg)
		must(t, err, "NewMempoolWithConfig")
		engine.SetMempool(mempool)
		serviceCfg := base.service.cfg
		serviceCfg.SyncEngine, serviceCfg.TxPool = engine, NewCanonicalMempoolTxPool(mempool)
		service, err := NewService(serviceCfg)
		must(t, err, "NewService")
		defer releaseBarrier()
		h := &testHarness{chainState: base.chainState, service: service}
		raw := newDAIngressFixture(t, h).commit(daRelayTestID(0xe4), 2)
		done := make(chan any, 1)
		go func() { defer func() { done <- recover() }(); _, _ = service.AdmitLocalDA(raw) }()
		select {
		case <-barrier.entered:
		case <-time.After(lifecycleWatchdog):
			t.Fatal("admission barrier not entered")
		}
		closeDone := lifecycleClose(service)
		waitDraining(t, service)
		requireStillBlocked(t, closeDone, "Close")
		releaseBarrier()
		select {
		case recovered := <-done:
			if recovered != sentinel {
				t.Fatalf("panic=%v, want original %v", recovered, sentinel)
			}
		case <-time.After(lifecycleWatchdog):
			t.Fatal("AdmitLocalDA did not return")
		}
		requireReturned(t, closeDone, "Close")
	})
	t.Run("Close waits for accepted prefetch", func(t *testing.T) {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		f := newDAIngressFixture(t, h)
		daID := daRelayTestID(0xe3)
		f.admit(f.commit(daID, 2), "127.0.0.9:19119")
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		releaseBarrier := func() { releaseOnce.Do(func() { close(release) }) }
		defer releaseBarrier()
		h.service.cfg.Now = func() time.Time { close(entered); <-release; return time.Unix(1, 0) }
		done := make(chan error, 1)
		go func() { done <- h.service.ScheduleLocalDAPrefetch(daID) }()
		select {
		case <-entered:
		case <-time.After(lifecycleWatchdog):
			t.Fatal("prefetch barrier not entered")
		}
		closeDone := lifecycleClose(h.service)
		waitDraining(t, h.service)
		requireStillBlocked(t, closeDone, "Close")
		rejected := f.commit(daRelayTestID(0xe5), 2)
		got, err := h.service.AdmitLocalDA(rejected)
		var admitErr *node.TxAdmitError
		if got != (node.DAAdmissionResult{}) || !errors.As(err, &admitErr) || admitErr.Kind != node.TxAdmitUnavailable || err.Error() != "service already closed" {
			t.Fatalf("draining AdmitLocalDA=(%+v,%v)", got, err)
		}
		if err := h.service.ScheduleLocalDAPrefetch(daID); !errors.Is(err, errServiceClosed) {
			t.Fatalf("draining ScheduleLocalDAPrefetch=%v", err)
		}
		releaseBarrier()
		select {
		case err := <-done:
			must(t, err, "ScheduleLocalDAPrefetch")
		case <-time.After(lifecycleWatchdog):
			t.Fatal("prefetch did not return")
		}
		requireReturned(t, closeDone, "Close")
		retained, err := h.service.daRelay.AdmitDA(rejected, node.LocalDAProvenance())
		if err != nil || retained.Disposition != node.DAAdmissionRetained {
			t.Fatalf("draining rejection changed owner: (%+v,%v)", retained, err)
		}
	})
}

func TestServiceDetachedDAWorkLifecycle(t *testing.T) {
	joinDone := func(t *testing.T, done <-chan struct{}, label string) {
		select {
		case <-done:
		case <-time.After(lifecycleWatchdog):
			t.Errorf("%s did not return within %s", label, lifecycleWatchdog)
		}
	}
	t.Run("nil closed error and normal drain", func(t *testing.T) {
		var nilService *Service
		err := runDetachedReorgDAAdmission(nilService, nil)
		var admitErr *node.TxAdmitError
		require(t, errors.As(err, &admitErr) && admitErr != nil && errors.Unwrap(err) == nil && errors.Is(admitErr, err) && admitErr.Kind == node.TxAdmitUnavailable && admitErr.Message == "nil service", "nil detached admission=%v", err)
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		f := newDAIngressFixture(t, h)
		require(t, runDetachedReorgDAAdmission(h.service, []byte{0x00}) != nil, "detached owner error returned nil")
		finish, err := h.service.admitDetachedReorgDA(f.commit(daRelayTestID(0xec), 2))
		must(t, err, "open detached admission")
		require(t, finish != nil, "retained detached admission has no completion")
		t.Cleanup(func() { finish(false) })
		h.service.cfg.Now = func() time.Time { t.Fatal("cancelled completion read scheduler clock"); return time.Time{} }
		closed := lifecycleClose(h.service)
		waitDraining(t, h.service)
		requireStillBlocked(t, closed, "pending detached completion lease")
		finish(false)
		finish(false)
		finish(true)
		requireReturned(t, closed, "detached work did not drain after normal/error exits")
		err = runDetachedReorgDAAdmission(h.service, nil)
		require(t, errors.As(err, &admitErr) && admitErr != nil && errors.Unwrap(err) == nil && errors.Is(admitErr, err) && admitErr.Kind == node.TxAdmitUnavailable && admitErr.Message == "service already closed", "closed detached admission=%v", err)
	})
	t.Run("owner unavailable releases work for the next operation", func(t *testing.T) {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		raw := newDAIngressFixture(t, h).commit(daRelayTestID(0xeb), 2)
		latchDAHarness(t, h, newTestHarness(t, 2, "127.0.0.1:0", nil))
		for range 2 {
			err := runDetachedReorgDAAdmission(h.service, raw)
			var admitErr *node.TxAdmitError
			require(t, errors.As(err, &admitErr) && admitErr != nil && errors.Unwrap(err) == nil && errors.Is(admitErr, err) && admitErr.Kind == node.TxAdmitUnavailable && admitErr.Message == "pending-outpoint owner admission context unavailable", "detached owner unavailable=%T %v", err, err)
		}
		requireReturned(t, lifecycleClose(h.service), "detached unavailable work did not drain")
	})
	newBarrierService := func(t *testing.T, panicValue any) (*Service, *daIngressFixture, *localDAAdmissionBarrier) {
		t.Helper()
		base := newTestHarness(t, 1, "127.0.0.1:0", nil)
		barrier := &localDAAdmissionBarrier{entered: make(chan struct{}), release: make(chan struct{}), panicValue: panicValue}
		engine, err := node.NewSyncEngine(base.chainState, base.blockStore, base.syncCfg)
		must(t, err, "NewSyncEngine")
		cfg := node.DefaultMempoolConfig()
		cfg.RotationProvider = barrier
		mempool, err := node.NewMempoolWithConfig(base.chainState, base.blockStore, node.DevnetGenesisChainID(), cfg)
		must(t, err, "NewMempoolWithConfig")
		engine.SetMempool(mempool)
		serviceCfg := base.service.cfg
		serviceCfg.SyncEngine, serviceCfg.TxPool = engine, NewCanonicalMempoolTxPool(mempool)
		service, err := NewService(serviceCfg)
		must(t, err, "NewService")
		h := &testHarness{chainState: base.chainState, service: service, mempool: mempool}
		return service, newDAIngressFixture(t, h), barrier
	}
	t.Run("ordinary admission guard holds registered detached work", func(t *testing.T) {
		service, f, barrier := newBarrierService(t, nil)
		barrier.armed = &atomic.Bool{}
		raw, standard := f.commit(daRelayTestID(0xea), 2), mustBuildSignedP2PTx(t, f.h.chainState.Utxos, []consensus.Outpoint{f.op()}, 800_000, 100_000, 1, f.signer, f.address, f.address)
		must(t, f.h.mempool.AddTx(standard), "resident ordinary admission")
		barrier.armed.Store(true)
		_, block := testHarnessBlockAtHeight(t, newTestHarness(t, 2, "127.0.0.1:0", nil), 1)
		apply, applyDone := make(chan error, 1), make(chan struct{})
		go func() { defer close(applyDone); _, err := service.cfg.SyncEngine.ApplyBlock(block, nil); apply <- err }()
		var releaseOnce sync.Once
		releaseBarrier := func() { releaseOnce.Do(func() { close(barrier.release) }) }
		t.Cleanup(func() {
			releaseBarrier()
			joinDone(t, applyDone, "canonical admission guard cleanup")
			requireReturned(t, lifecycleClose(service), "Close after canonical admission guard cleanup")
		})
		select {
		case <-barrier.entered:
		case <-time.After(lifecycleWatchdog):
			t.Fatal("canonical admission guard barrier did not enter")
		}
		admitted, admissionDone := make(chan error, 1), make(chan struct{})
		go func() { defer close(admissionDone); admitted <- runDetachedReorgDAAdmission(service, raw) }()
		t.Cleanup(func() { releaseBarrier(); joinDone(t, admissionDone, "guarded detached admission cleanup") })
		stack := make([]byte, 1<<20)
		waitUntil(t, func() bool {
			n := runtime.Stack(stack, true)
			return bytes.Contains(stack[:n], []byte("(*admissionMutex).RLockUnlessTerminal")) && bytes.Contains(stack[:n], []byte("admitDetachedReorgDA"))
		}, "detached admission guard contention")
		closeDone := lifecycleClose(service)
		waitDraining(t, service)
		requireStillBlocked(t, closeDone, "Close")
		releaseBarrier()
		requireReturned(t, apply, "canonical admission guard")
		requireReturned(t, admitted, "guarded detached admission")
		requireReturned(t, closeDone, "Close after admission guard")
		requireEqual(t, f.h.mempool.Len(), 1, "ordinary admission guard retained transactions")
		f.requireRetained(raw, "guarded detached admission")
	})
	t.Run("accepted effect stays under lease during Close", func(t *testing.T) {
		service, f, barrier := newBarrierService(t, nil)
		var scheduler atomic.Int32
		inner := service.cfg.Now
		service.cfg.Now = func() time.Time { scheduler.Add(1); return inner() }
		raw := f.commit(daRelayTestID(0xed), 2)
		admitted, admissionDone := make(chan error, 1), make(chan struct{})
		go func() { defer close(admissionDone); admitted <- runDetachedReorgDAAdmission(service, raw) }()
		var releaseOnce sync.Once
		releaseBarrier := func() { releaseOnce.Do(func() { close(barrier.release) }) }
		t.Cleanup(func() {
			releaseBarrier()
			joinDone(t, admissionDone, "detached admission cleanup")
			requireReturned(t, lifecycleClose(service), "Close after detached admission cleanup")
		})
		select {
		case <-barrier.entered:
		case <-time.After(lifecycleWatchdog):
			t.Fatalf("detached admission barrier did not enter within %s", lifecycleWatchdog)
		}
		closeDone := lifecycleClose(service)
		waitDraining(t, service)
		requireStillBlocked(t, closeDone, "Close")
		releaseBarrier()
		requireReturned(t, admitted, "accepted detached effect lost during Close")
		require(t, scheduler.Load() == 1, "accepted detached effect lost during Close: scheduler=%d", scheduler.Load())
		requireReturned(t, closeDone, "detached work did not drain after Close-during-admission")
		f.requireRetained(raw, "retained during Close")
	})
	t.Run("pre-result panic keeps identity and drains", func(t *testing.T) {
		sentinel := &struct{ label string }{"detached admission panic"}
		service, f, barrier := newBarrierService(t, sentinel)
		done := make(chan any, 1)
		panicDone := make(chan struct{})
		go func() {
			defer close(panicDone)
			defer func() { done <- recover() }()
			_ = runDetachedReorgDAAdmission(service, f.commit(daRelayTestID(0xee), 2))
		}()
		var releaseOnce sync.Once
		releaseBarrier := func() { releaseOnce.Do(func() { close(barrier.release) }) }
		t.Cleanup(func() {
			releaseBarrier()
			joinDone(t, panicDone, "detached panic cleanup")
			requireReturned(t, lifecycleClose(service), "Close after detached panic cleanup")
		})
		select {
		case <-barrier.entered:
		case <-time.After(lifecycleWatchdog):
			t.Fatalf("detached panic barrier did not enter within %s", lifecycleWatchdog)
		}
		closeDone := lifecycleClose(service)
		waitDraining(t, service)
		requireStillBlocked(t, closeDone, "Close")
		releaseBarrier()
		var recovered any
		select {
		case recovered = <-done:
		case <-time.After(lifecycleWatchdog):
			t.Fatalf("detached panic did not return within %s", lifecycleWatchdog)
		}
		require(t, recovered == sentinel, "detached panic identity changed: got %v want %v", recovered, sentinel)
		requireReturned(t, closeDone, "detached work did not drain after pre-result panic")
	})
	t.Run("post-retained panic preserves state and drains", func(t *testing.T) {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		f := newDAIngressFixture(t, h)
		raw := f.commit(daRelayTestID(0xef), 2)
		sentinel := &struct{ label string }{"detached scheduler panic"}
		h.service.cfg.Now = func() time.Time { panic(sentinel) }
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			_ = runDetachedReorgDAAdmission(h.service, raw)
		}()
		require(t, recovered == sentinel, "detached panic identity changed: got %v want %v", recovered, sentinel)
		requireReturned(t, lifecycleClose(h.service), "detached work did not drain after retained panic")
		f.requireRetained(raw, "retained state changed after scheduler panic")
	})
	t.Run("blocked write and writeMu remain inside lease", func(t *testing.T) {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		h.service.cfg.EnableCompactReceive = true
		current := addDAPrefetchTestPeer(h.service, "127.0.0.7:19119", nil)
		current.writeMu.Lock()
		unlocked := false
		defer func() {
			if !unlocked {
				current.writeMu.Unlock()
			}
		}()
		entered := make(chan struct{})
		var enteredOnce sync.Once
		inner := h.service.cfg.Now
		h.service.cfg.Now = func() time.Time { enteredOnce.Do(func() { close(entered) }); return inner() }
		raw := newDAIngressFixture(t, h).commit(daRelayTestID(0xf0), 2)
		admitted, admissionDone := make(chan error, 1), make(chan struct{})
		go func() { defer close(admissionDone); admitted <- runDetachedReorgDAAdmission(h.service, raw) }()
		t.Cleanup(func() {
			joinDone(t, admissionDone, "blocked-write admission cleanup")
			requireReturned(t, lifecycleClose(h.service), "Close after blocked-write admission cleanup")
		})
		select {
		case <-entered:
		case <-time.After(lifecycleWatchdog):
			t.Fatalf("blocked-write admission did not enter within %s", lifecycleWatchdog)
		}
		closeDone := lifecycleClose(h.service)
		waitDraining(t, h.service)
		requireStillBlocked(t, closeDone, "Close")
		current.writeMu.Unlock()
		unlocked = true
		requireReturned(t, admitted, "blocked-write detached admission")
		requireReturned(t, closeDone, "detached work did not drain after blocked write")
	})
	t.Run("retained scheduler Write stays under the lease", func(t *testing.T) {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		h.service.cfg.EnableCompactReceive = true
		local, remote := net.Pipe()
		defer remote.Close()
		entered, release := make(chan struct{}), make(chan struct{})
		current := addDAPrefetchTestPeer(h.service, "peer-a", nil)
		current.conn = &lifecycleGateConn{Conn: local, entered: entered, release: release, writeErr: errors.New("paused write failure")}
		f, daID := newDAIngressFixture(t, h), daRelayTestID(0xf1)
		raw := f.commit(daID, 2)
		admitted, admissionDone := make(chan error, 1), make(chan struct{})
		go func() { defer close(admissionDone); admitted <- runDetachedReorgDAAdmission(h.service, raw) }()
		var releaseOnce sync.Once
		releaseWrite := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(func() {
			releaseWrite()
			joinDone(t, admissionDone, "scheduler Write admission cleanup")
			requireReturned(t, lifecycleClose(h.service), "Close after scheduler Write cleanup")
		})
		select {
		case <-entered:
		case <-time.After(lifecycleWatchdog):
			t.Fatal("retained scheduler did not enter connection Write")
		}
		type probeResult struct {
			result node.DAAdmissionResult
			err    error
		}
		probed, probeDone := make(chan probeResult, 1), make(chan struct{})
		go func() {
			defer close(probeDone)
			result, err := f.probe(raw)
			probed <- probeResult{result, err}
		}()
		t.Cleanup(func() { releaseWrite(); joinDone(t, probeDone, "retained scheduler probe cleanup") })
		select {
		case got := <-probed:
			require(t, got.err == nil && got.result == (node.DAAdmissionResult{DAID: daID, Disposition: node.DAAdmissionDuplicate}), "retained scheduler probe result=(%+v,%v)", got.result, got.err)
		case <-time.After(lifecycleWatchdog):
			t.Fatal("retained scheduler probe blocked while Write is paused")
		}
		closeDone := lifecycleClose(h.service)
		waitDraining(t, h.service)
		requireStillBlocked(t, closeDone, "Close")
		releaseWrite()
		requireReturned(t, admitted, "detached admission after scheduler Write failure")
		requireReturned(t, closeDone, "Close after scheduler Write failure")
		retry, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, h.service.cfg.Now())
		require(t, len(retry) == 1 && len(retry[0].Indexes) == 2 && diagnostic == "", "scheduler Write cleanup retry=%+v diagnostic=%q", retry, diagnostic)
	})
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
	requireEqual(t, s.acquireWork(), true, "the OPEN peer worker registration")
	runDone := make(chan error, 1)
	go func() { defer s.releaseWork(); runDone <- p.run(context.Background()) }()
	_, err := remote.Write(mustPeerRuntimeFrameBytes(t, p, message{Command: messageGetAddr})) // The gate parks the worker inside its reply write, past every deadline arm of this iteration. The loop context is never cancelled and the socket is never closed, so only the read-authorization gate stops it.
	must(t, err, "write authorized message")
	<-gate.entered
	fallbackHash := node.DevnetGenesisBlockHash() // An already-expired compact outstanding staged while the worker is parked is owed exactly one getdata fallback.
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: fallbackHash, BlockTxnPayloadCap: 1, ExpiresAt: time.Unix(1, 0)})
	closeDone := lifecycleClose(s)
	waitDraining(t, s)
	requireStillBlocked(t, closeDone, "Close")
	gate.postDrain.Store(true)
	must(t, remote.SetReadDeadline(time.Now().Add(lifecycleWatchdog)), "SetReadDeadline")
	close(gate.release)
	requireEqual(t, (<-lifecycleReadFrame(p, remote)).Command, messageAddr, "the authorized message reply command")
	fallback := <-lifecycleReadFrame(p, remote) // The owed fallback is still delivered after the drain was published: the guard sits between the fallback flush and the next deadline arm, never above the flush.
	if fallback.Command != messageGetData || !bytes.Equal(fallback.Payload, append([]byte{MSG_BLOCK}, fallbackHash[:]...)) {
		t.Fatalf("owed compact fallback command=%q payload=%x", fallback.Command, fallback.Payload)
	}
	requireReturned(t, runDone, "peer worker")
	requireReturned(t, closeDone, "Close")
	requireEqual(t, gate.lateArms.Load(), int64(0), "post-drain read-deadline arms on the worker conn") // Every read attempt in the loop arms the deadline first, so zero post-drain arms plus the worker's exit prove no further read began after the drain was published.
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
	requireEqual(t, lifecycleAddrAttempts(s, openAddr), 1, "OPEN discovered dial attempts")
	waitUntil(t, func() bool { return s.inFlightDialCount() == 0 }, "the OPEN discovered dial reservation release") // The OPEN child's own cleanup releases its reservation before any Close runs.
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
	requireEqual(t, lifecycleAddrAttempts(s, drainAddr), 0, "draining discovered dial attempts")
	requireEqual(t, s.inFlightDialCount(), 0, "draining discovered dial reservations")
	s.startWG.Done()
	requireReturned(t, closeDone, "Close")
}

func lifecycleAddrAttempts(s *Service, addr string) int {
	s.addrMgr.mu.Lock()
	defer s.addrMgr.mu.Unlock()
	return s.addrMgr.addrs[normalizeNetAddr(addr)].attempts
}

// lifecycleClock pins the reconnect rows' notion of now so no wall-clock drift can decide whether a row is due.
var lifecycleClock = time.Unix(1<<30, 0)

// lifecycleReconnectService gives the Service exactly one outbound address carrying a reconnect entry due at lifecycleClock+offset.
func lifecycleReconnectService(t *testing.T, offset time.Duration) (*Service, string) {
	t.Helper()
	s := lifecycleService(t)
	addr := "127.0.0.40:1"
	s.cfg.Now = func() time.Time { return lifecycleClock }
	s.outboundAddrs = []string{addr}
	s.reconnectState[addr] = &reconnectEntry{failures: 3, nextRetry: lifecycleClock.Add(offset)}
	return s, addr
}

// lifecycleReconnectSnapshot renders the entire reconnectState map — key set, failure counts and retry instants — so a comparison catches a newly created entry as well as an advanced one. fmt prints map keys in sorted order, so the rendering is deterministic.
func lifecycleReconnectSnapshot(s *Service) string {
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	rows := make(map[string]string, len(s.reconnectState))
	for addr, entry := range s.reconnectState {
		rows[addr] = fmt.Sprintf("failures=%d nextRetry=%s", entry.failures, entry.nextRetry.UTC())
	}
	return fmt.Sprint(rows)
}

// requireReconnectUntouched asserts a rejected reconnect row moved nothing an accepted one would have: no reconnectState entry or backoff advance, no reservation past the pre-existing ones, no addr-manager attempt, and no spawned child (a child owns the transferred lease and would strand the Close every row ends with).
func requireReconnectUntouched(t *testing.T, s *Service, before string, reservations int, addr, label string) {
	t.Helper()
	requireEqual(t, lifecycleReconnectSnapshot(s), before, label+" reconnect state")
	requireEqual(t, s.inFlightDialCount(), reservations, label+" in-flight reservations")
	requireEqual(t, lifecycleAddrAttempts(s, addr), 0, label+" addr-manager attempts")
}

// TestServiceWorkLifecycleReconnectRejectedDuringDrain drives the real reconnectDuePeers over its three rejection rows: a due attempt losing to Close, a not-due entry, and an address already in flight.
func TestServiceWorkLifecycleReconnectRejectedDuringDrain(t *testing.T) {
	t.Run("Close wins the due reconnect", func(t *testing.T) {
		s, addr := lifecycleReconnectService(t, -time.Minute)
		before := lifecycleReconnectSnapshot(s)
		s.startWG.Add(1) // startWG parks Close between its registration cutoff and the teardown, so the rejection happens while the drain is published and the teardown demonstrably unfinished.
		closeDone := lifecycleClose(s)
		waitDraining(t, s)
		s.reconnectDuePeers()
		requireReconnectUntouched(t, s, before, 0, addr, "the Close-losing due reconnect")
		s.startWG.Done()
		requireReturned(t, closeDone, "Close")
	})
	t.Run("the entry is not due", func(t *testing.T) {
		s, addr := lifecycleReconnectService(t, time.Hour)
		before := lifecycleReconnectSnapshot(s)
		entered, release := make(chan struct{}), make(chan struct{})
		pinned := s.cfg.Now
		var once sync.Once
		s.cfg.Now = func() time.Time {
			once.Do(func() { close(entered); <-release })
			return pinned()
		}
		reconnected := make(chan struct{})
		go func() { defer close(reconnected); s.reconnectDuePeers() }()
		<-entered
		closeDone := lifecycleClose(s) // The lease is owned before the clock producer whose value the due check consumes, so Close must already be waiting on this not-due iteration; an iteration that reached the clock without a lease leaves Close nothing to wait for and it returns inside the window.
		requireStillBlocked(t, closeDone, "Close")
		close(release)
		<-reconnected
		requireReturned(t, closeDone, "Close")
		requireReconnectUntouched(t, s, before, 0, addr, "the not-due reconnect")
	})
	t.Run("the address is already in flight", func(t *testing.T) {
		s, addr := lifecycleReconnectService(t, -time.Minute)
		requireEqual(t, s.trackDialPeer(addr), true, "the pre-inserted in-flight reservation")
		before := lifecycleReconnectSnapshot(s)
		s.reconnectDuePeers()
		requireReconnectUntouched(t, s, before, 1, addr, "the duplicate in-flight reconnect")
		s.finishDialPeer(addr)
		requireReturned(t, lifecycleClose(s), "Close") // Each rejected row released its lease exactly once: a leak strands this Close past its watchdog, a double release panics it.
	})
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
	time.Sleep(50 * time.Millisecond) // Widen the window in which a non-joined interrupter would still be mutating the connection: with the reset defer undelayed, an unjoined interrupter is provably still inside this sleep when performHandshake returns, so the in-flight check fails.
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
			_, err := performHandshake(ctx, conn, cfg, node.VersionPayloadV1{ProtocolVersion: ProtocolVersion}, node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash()) // The remote never answers, so only the cancellation child can unblock the handshake read.
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
		requireEqual(t, conn.inFlight.Load(), int64(0), "deadline mutations in flight when performHandshake returned")
		time.Sleep(lifecycleSettle)
		requireEqual(t, conn.late.Load(), int64(0), "SetDeadline calls after performHandshake returned")
	})
	t.Run("error and no-publication exits release once", func(t *testing.T) {
		s := lifecycleService(t)
		requireEqual(t, s.AnnounceBlock([]byte{0x00}) != nil, true, "the parse error AnnounceBlock(malformed) must preserve")
		s.cfg.TxMetadataFunc = func([]byte) (node.RelayTxMetadata, error) {
			return node.RelayTxMetadata{}, fmt.Errorf("producer failure")
		}
		requireEqual(t, s.AnnounceTx(minimalValidTxBytes(t)) != nil, true, "the producer error AnnounceTx must preserve")
		local, remote := net.Pipe() // Socket-owner write-failure and no-publication rows: the first announcement writes and the conn fails it with this test's own sentinel, the deduplicated second never publishes.
		defer func() { _ = remote.Close() }()
		var writes atomic.Int64
		sentinel := errors.New("lifecycle sentinel write failure")
		p := &peer{conn: &lifecycleGateConn{Conn: local, writes: &writes, writeErr: sentinel}, service: s, state: node.PeerState{Addr: "lifecycle-fault-peer"}}
		s.peers[p.addr()] = p
		must(t, s.AnnounceBlock(node.DevnetGenesisBlockBytes()), "AnnounceBlock over a failing socket")
		requireEqual(t, writes.Load(), int64(1), "write attempts on the first announcement")
		requireEqual(t, p.snapshotState().LastError, sentinel.Error(), "the recorded write failure") // The sentinel is what the announcement actually observed, so the single attempt is a real write failure and not an unrelated early return.
		must(t, s.AnnounceBlock(node.DevnetGenesisBlockBytes()), "deduplicated AnnounceBlock")
		requireEqual(t, writes.Load(), int64(1), "write attempts after the failure and the no-publication return")
		requireReturned(t, lifecycleClose(s), "Close") // Every one of those exits released its lease exactly once: a leak strands Close past the watchdog, an extra release panics it.
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
	requireEqual(t, panicked, true, "the producer panic propagated out of AnnounceTx")
	requireReturned(t, lifecycleClose(s), "Close after a panicking call")
}

// TestServiceWorkLifecycleConcurrentClose parks the owning Close in phase 2 and proves the seven later Close calls join that one teardown: all eight callers stay parked on the shared completion while the teardown is demonstrably unfinished, and exactly one teardown runs.
func TestServiceWorkLifecycleConcurrentClose(t *testing.T) {
	s := newTestHarness(t, 0, "127.0.0.1:0", nil).service
	must(t, s.Start(context.Background()), "Start")
	bound := s.Addr()
	s.startWG.Add(1)
	closes := []chan error{lifecycleClose(s)}
	waitDraining(t, s)
	for i := 0; i < 7; i++ {
		closes = append(closes, lifecycleClose(s))
	}
	requireEqual(t, len(closes), 8, "concurrent Close callers")
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
	select { // A nil shared channel is never ready, so this also fails when no completion was published.
	case <-shared:
	default:
		t.Fatal("the shared close completion is not published as complete")
	}
	must(t, s.Close(), "repeated Close")
	rebind, err := net.Listen("tcp", bound) // one teardown actually happened: the port is immediately rebindable
	must(t, err, fmt.Sprintf("port %q still bound after the shared teardown", bound))
	_ = rebind.Close()
}

// TestServiceWorkLifecycleReadOnlyAfterClose proves read-only queries stay callable without a lease and a retained callback rejects with the exact error and zero state/queue/send delta.
func TestServiceWorkLifecycleReadOnlyAfterClose(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	s := h.service
	s.ctx = context.Background()
	f := newDAIngressFixture(t, h)
	daID, snapshotID := daRelayTestID(0x7e), daRelayTestID(0x7f)
	payload := []byte("readonly-payload")
	retainedSet, snapshotSet := f.commit(daID, 2), f.commit(snapshotID, 2)
	f.admit(retainedSet, "127.0.0.9:19119")
	blockBytes := compactTestBlockBytesWithTxs(t, [][]byte{
		minimalValidTxBytes(t),
		daCommitRelayTxBytes(t, daID, 1, payload),
		daChunkRelayTxBytes(t, daID, 0, 2, payload),
	})
	f.admit(snapshotSet, "127.0.0.9:19119")
	txBytes := minimalValidTxBytes(t)
	_, txid, err := parseCanonicalTx(txBytes)
	must(t, err, "parseCanonicalTx")
	var metaCalls, writes atomic.Int64 // Real owners installed before Close: the config's own metadata producer, and a connected peer whose queue/socket owner counts every frame write.
	producer := s.cfg.TxMetadataFunc
	s.cfg.TxMetadataFunc = func(b []byte) (node.RelayTxMetadata, error) { metaCalls.Add(1); return producer(b) }
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	retained := &peer{conn: &lifecycleGateConn{Conn: local, writes: &writes}, service: s, state: node.PeerState{Addr: "lifecycle-readonly-peer"}}
	s.peers[retained.addr()] = retained
	exitsBefore := s.PeerLifecycleExits()
	requireReturned(t, lifecycleClose(s), "Close")
	requireEqual(t, s.Addr() != "", true, "a non-empty Addr() after Close")
	requireEqual(t, s.PeerLifecycleExits(), exitsBefore, "PeerLifecycleExits after Close")
	requireEqual(t, len(s.CompleteDASetCandidates(1<<20)), 0, "complete candidates after Close: both retained sets are incomplete")
	requireClosedRejection(t, s.AnnounceTx(txBytes), "retained AnnounceTx callback")
	requireClosedRejection(t, s.AnnounceBlock(blockBytes), "retained AnnounceBlock callback")
	requireEqual(t, metaCalls.Load(), int64(0), "TxMetadataFunc calls after Close") // Every observable owner a won call would have moved: the metadata producer was never invoked, the retained peer's socket saw no frame, and the state owners below are unchanged.
	requireEqual(t, writes.Load(), int64(0), "frame writes on the retained peer socket after Close")
	_, pooled := s.cfg.TxPool.Get(txid)
	requireEqual(t, pooled, false, "the relay-pool entry a rejected AnnounceTx would have added")
	// blockBytes carries this exact da_id's complete commit+chunk pair, so a
	// Service that still owned any post-return retained-DA cleanup would have
	// taken the set here. There is no such authority left: both sets survive.
	f.requireRetained(retainedSet, "the retained DA set after Close and both rejected callbacks")
	f.requireRetained(snapshotSet, "the second retained DA set after Close")
	requireEqual(t, s.blockSeen.Has(node.DevnetGenesisBlockHash()), false, "the block seen-set entry a rejected AnnounceBlock would have added")
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

// TestTerminalPersistenceNewSkipsTheFencedTTLAdvance pins that a published
// terminal result still skips the post-return TTL mutation. The shared fence
// now refuses a truly latched race; this row separately preserves the existing
// no-TTL-effect branch selected from the returned terminal shape.
func TestTerminalPersistenceNewSkipsTheFencedTTLAdvance(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := testPeerForService(h.service, "remote", 2)
	summary, err := p.processRelayedBlock(blockAtHeight(t, source, 1))
	must(t, err, "processRelayedBlock")
	f := newDAIngressFixture(t, h)
	commit := f.commit(daRelayTestID(109), 2)
	must(t, daRelayTestPeer(h, "127.0.0.1:19111").handleTx(commit), "retain the commit")
	// Primed to ONE tick from expiry, so the tick this row skips is the one that
	// decides: with the gate reverted the record is released and the replay
	// below readmits instead of reporting the DUPLICATE.
	must(t, h.service.daRelay.AdvanceOrphanTTL(), "prime the TTL")
	must(t, h.service.daRelay.AdvanceOrphanTTL(), "prime the TTL")
	terminal := errors.New("storage persistence fault")
	p.acceptRelayedBlockResult(summary.BlockHash, summary, terminal)
	f.requireRetained(commit, "the retained record the skipped TTL tick left in place")
	requireEqual(t, h.service.blockSeen.Has(summary.BlockHash), true, "the seen-set entry the unfenced effects still added")
}

// latchDAHarness GENUINELY latches h's engine, which then RETAINS ChainState.admissionMu
// exclusively: a finalized standard-domain owner claim with no resident pool entry is the
// orphan the next canonical transition's mempool validation refuses terminally before the
// durable commit. Every fixture write to h belongs before this call.
func latchDAHarness(t *testing.T, h, source *testHarness) {
	t.Helper()
	owner := h.mempool.PendingOutpointOwner()
	ctx, ok := owner.AdmissionContext()
	requireEqual(t, ok, true, "owner admission context")
	orphan := [32]byte{0x6a}
	token, err := owner.Reserve(ctx, node.PendingOutpointStandardMempool, orphan, []consensus.Outpoint{{Txid: orphan}})
	must(t, err, "Reserve")
	must(t, owner.Finalize(token), "Finalize")
	summary, err := h.syncEngine.ApplyBlock(blockAtHeight(t, source, 1), nil)
	if want := fmt.Sprintf("canonical mempool invariant: orphan standard pending-outpoint claim for %x", orphan); summary != nil || err == nil || err.Error() != want {
		t.Fatalf("ApplyBlock=(%+v,%v), want a nil summary and %q", summary, err, want)
	}
	requireEqual(t, h.syncEngine.TerminalFaulted(), true, "the engine terminal latch")
}

func TestLocalDATerminalWorkDrains(t *testing.T) {
	const unavailable = "pending-outpoint owner admission context unavailable"
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	raw := newDAIngressFixture(t, h).commit(daRelayTestID(0xe8), 2)
	latchDAHarness(t, h, newTestHarness(t, 2, "127.0.0.1:0", nil))

	type admissionOutcome struct {
		result node.DAAdmissionResult
		err    error
	}
	admitted := make(chan admissionOutcome, 1)
	go func() {
		result, err := h.service.AdmitLocalDA(raw)
		admitted <- admissionOutcome{result: result, err: err}
	}()
	var got admissionOutcome
	select {
	case got = <-admitted:
	case <-time.After(lifecycleWatchdog):
		t.Fatal("terminal AdmitLocalDA did not return")
	}
	var typed *node.TxAdmitError
	if got.result != (node.DAAdmissionResult{}) || !errors.As(got.err, &typed) || typed.Kind != node.TxAdmitUnavailable || got.err.Error() != unavailable {
		t.Fatalf("terminal AdmitLocalDA=(%+v,%T %v), want exact unavailable", got.result, got.err, got.err)
	}

	prefetched := make(chan error, 1)
	go func() { prefetched <- h.service.ScheduleLocalDAPrefetch(daRelayTestID(0xe8)) }()
	requireReturned(t, prefetched, "terminal ScheduleLocalDAPrefetch")
	requireReturned(t, lifecycleClose(h.service), "Service.Close after terminal local work")

	retained := newTestHarness(t, 1, "127.0.0.1:0", nil)
	daID := daRelayTestID(0xe9)
	if result, err := retained.service.AdmitLocalDA(newDAIngressFixture(t, retained).commit(daID, 2)); err != nil || result.Disposition != node.DAAdmissionRetained {
		t.Fatalf("retained AdmitLocalDA=(%+v,%v)", result, err)
	}
	latchDAHarness(t, retained, newTestHarness(t, 2, "127.0.0.1:0", nil))
	prefetched = make(chan error, 1)
	go func() { prefetched <- retained.service.ScheduleLocalDAPrefetch(daID) }()
	requireReturned(t, prefetched, "post-retained terminal ScheduleLocalDAPrefetch")
	requireReturned(t, lifecycleClose(retained.service), "Service.Close after retained terminal prefetch")
}

// TestLatchedEngineSkipsTheAnnounceBlockTTLAdvance preserves the early
// already-latched skip. A latch racing this check is refused by the shared
// fence; this row also proves the unfenced seen-set effect ahead of the check
// still lands.
func TestLatchedEngineSkipsTheAnnounceBlockTTLAdvance(t *testing.T) {
	source := newTestHarness(t, 4, "127.0.0.1:0", nil)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	latchDAHarness(t, h, source)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 2)
	done := make(chan error, 1)
	go func() { done <- h.service.AnnounceBlock(blockBytes) }()
	requireReturned(t, done, "AnnounceBlock on a latched engine")
	requireEqual(t, h.service.blockSeen.Has(blockHash), true, "the seen-set entry the unfenced effects still added")
}

// TestLatchedEngineSkipsThePeerQuotaRelease preserves the early already-latched
// cleanup skip. A latch racing this check is refused by the shared fence. The
// lifecycle-exit counter observes that teardown ran past the skip.
//
// The skipped release itself is not observed here because package p2p has no
// read-only retained-image accessor; the node fence tests pin that state.
func TestLatchedEngineSkipsThePeerQuotaRelease(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	latchDAHarness(t, h, newTestHarness(t, 2, "127.0.0.1:0", nil))
	p := &peer{service: h.service, state: node.PeerState{Addr: "127.0.0.1:19111"}}
	must(t, h.service.registerPeer(p), "registerPeer")
	exits := h.service.PeerLifecycleExits()
	done := make(chan error, 1)
	go func() { h.service.unregisterPeer(p); done <- nil }()
	requireReturned(t, done, "unregisterPeer on a latched engine")
	requireEqual(t, h.service.PeerLifecycleExits(), exits+1, "the lifecycle exit the completed teardown recorded")
}

// TestResolvedOrphanTerminalResultSkipsTheFencedTTLAdvance is the RESOLVED-ORPHAN
// entry's own killer for the same skip. acceptResolvedOrphanResult forwards the
// apply error into noteAcceptedBlock, so a resolved orphan whose apply returns
// the terminal shape — a published summary alongside a non-nil error — skips the
// fenced TTL advance exactly like the relayed-block entry does. Forwarding nil
// instead would advance the TTL, and the orphan primed one advance from expiry
// below is what makes that difference observable.
//
// This entry reaches noteAcceptedBlock through its OWN call site, which the
// relayed-block row above never executes; neither row can stand in for the other.
func TestResolvedOrphanTerminalResultSkipsTheFencedTTLAdvance(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := testPeerForService(h.service, "remote", 2)
	summary, err := p.processRelayedBlock(blockAtHeight(t, source, 1))
	must(t, err, "processRelayedBlock")
	f := newDAIngressFixture(t, h)
	commit := f.commit(daRelayTestID(111), 2)
	must(t, daRelayTestPeer(h, "127.0.0.1:19111").handleTx(commit), "retain the commit")
	must(t, h.service.daRelay.AdvanceOrphanTTL(), "prime the TTL")
	must(t, h.service.daRelay.AdvanceOrphanTTL(), "prime the TTL")
	terminal := errors.New("storage persistence fault")
	stop := h.service.acceptResolvedOrphanResult(p, summary.BlockHash, summary.BlockHash, summary, terminal)
	requireEqual(t, stop, true, "the resolved-orphan walk stop a terminal result forces")
	f.requireRetained(commit, "the retained record the skipped TTL tick left in place")
}
