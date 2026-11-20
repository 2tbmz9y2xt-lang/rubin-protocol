package p2p

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

const (
	errPeerManagerClaimed   = "peer manager is already claimed"
	errDARelayUninitialized = "sync engine DA relay state is not initialized"
)

// claimConfig returns a valid ServiceConfig over a fresh initialized SyncEngine that uses pm.
func claimConfig(t *testing.T, pm *node.PeerManager) (*testHarness, ServiceConfig) {
	t.Helper()
	sink, cfg := unclaimedServiceSink(t)
	cfg.PeerManager = pm
	return sink, cfg
}

func freshPeerManager() *node.PeerManager {
	return node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))
}

// requireClaimRefused requires NewService(cfg) to return no Service and the claim refusal.
func requireClaimRefused(t *testing.T, cfg ServiceConfig, label string) {
	t.Helper()
	service, err := NewService(cfg)
	require(t, service == nil && err != nil && err.Error() == errPeerManagerClaimed, "%s: NewService=(%p,%v), want %q", label, service, err, errPeerManagerClaimed)
}

// requireClaimFree requires NewService(cfg) to succeed and closes the result in cleanup.
func requireClaimFree(t *testing.T, cfg ServiceConfig, label string) *Service {
	t.Helper()
	service, err := NewService(cfg)
	require(t, err == nil && service != nil, "%s: NewService: %v", label, err)
	t.Cleanup(func() { _ = service.Close() })
	return service
}

// requireDARelayUninitialized requires NewService(cfg) to return no Service and the uninitialized DA relay state refusal.
func requireDARelayUninitialized(t *testing.T, cfg ServiceConfig, label string) {
	t.Helper()
	service, err := NewService(cfg)
	require(t, service == nil && err != nil && err.Error() == errDARelayUninitialized, "%s: NewService=(%p,%v), want %q", label, service, err, errDARelayUninitialized)
}

// startServing starts s with a context canceled in cleanup.
func startServing(t *testing.T, s *Service) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	must(t, s.Start(ctx), "Start")
}

// startWithInboundPeer starts s and completes one inbound handshake through its listener.
func startWithInboundPeer(t *testing.T, s *Service) (string, net.Conn) {
	t.Helper()
	startServing(t, s)
	deadline := time.Now().Add(lifecycleWatchdog)
	dialer := net.Dialer{Deadline: deadline}
	remote, err := dialer.DialContext(t.Context(), "tcp", s.Addr())
	must(t, err, "dial")
	t.Cleanup(func() { _ = remote.Close() })
	must(t, remote.SetDeadline(deadline), "set handshake deadline")
	must(t, completeRemoteHandshake(remote, s.cfg.PeerRuntimeConfig, testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 0)), "remote handshake")
	must(t, remote.SetDeadline(time.Time{}), "clear handshake deadline")
	addr := remote.LocalAddr().String()
	waitUntil(t, func() bool { return snapshotHas(s.cfg.PeerManager, addr) }, "inbound peer registered")
	return addr, remote
}

func snapshotHas(pm *node.PeerManager, addr string) bool {
	for _, state := range pm.Snapshot() {
		if state.Addr == addr {
			return true
		}
	}
	return false
}

func closeOwned(s *Service) bool {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	return s.closeDone != nil
}

// holdPeerExit takes the DA quota key lock of the connection registered at addr, so that
// connection's exit parks in unregisterPeer before its PeerManager effect. The returned
// release runs once, by the test or its cleanup.
func holdPeerExit(t *testing.T, s *Service, addr string) func() {
	t.Helper()
	s.peersMu.RLock()
	current := s.peers[addr]
	key := ""
	if current != nil {
		key = current.daQuotaIdentity
	}
	s.peersMu.RUnlock()
	require(t, key != "", "connection at %s has no DA quota identity", addr)
	var once sync.Once
	unlock := s.lockPeerQuotaKey(key)
	release := func() { once.Do(unlock) }
	t.Cleanup(release)
	return release
}

// requireParked waits until one goroutine's stack holds the fragments.
func requireParked(t *testing.T, label string, fragments ...string) {
	t.Helper()
	waitUntil(t, func() bool { return goroutineParked(fragments...) }, label)
}

// requireNotParked requires that no goroutine's stack holds the fragments.
func requireNotParked(t *testing.T, label string, fragments ...string) {
	t.Helper()
	require(t, !goroutineParked(fragments...), "%s before the step that parks it", label)
}

// closeDrainFrames match a Close started by the test closure frame and parked in a
// WaitGroup wait; with no Start in flight that wait is loopWG.Wait, the final worker drain.
func closeDrainFrames(testFrame string) []string {
	return []string{"[sync.WaitGroup.Wait", "sync.(*WaitGroup).Wait(", "p2p.(*Service).Close(", testFrame}
}

// peerExitFrames match a connection worker parked on a DA quota key lock inside its exit.
var peerExitFrames = []string{"[sync.Mutex.Lock", "p2p.(*Service).lockPeerQuotaKey(", "p2p.(*Service).unregisterPeer(", "p2p.(*Service).handleConn(", "p2p.(*Service).runConn("}

func TestPeerManagerClaimRefusesHeldPeerManager(t *testing.T) {
	_, cfg1 := unclaimedServiceSink(t)
	pm := cfg1.PeerManager
	s1 := requireClaimFree(t, cfg1, "S1")
	sink2, cfg2 := claimConfig(t, pm)
	requireClaimRefused(t, cfg2, "second construction")
	require(t, cfg2.SyncEngine.DATTLBindingService() == nil, "refused construction published a binding")
	requireClaimRefused(t, cfg2, "third construction")
	first, err := NewService(freePeerManager(cfg2))
	require(t, err == nil && first != nil, "construction over a fresh PeerManager: %v", err)
	requireFirstClaimant(t, sink2, cfg2, first)
	require(t, !closeOwned(s1), "S1 was closed during the refusals")
}

func TestPeerManagerClaimRefusalPrecedesDARelayRefusal(t *testing.T) {
	h, cfg1 := unclaimedServiceSink(t)
	requireClaimFree(t, cfg1, "S1")
	uninitialized, err := node.NewSyncEngine(h.chainState, h.blockStore, cfg1.SyncConfig)
	must(t, err, "NewSyncEngine")
	cfg := cfg1
	cfg.SyncEngine = uninitialized
	requireDARelayUninitialized(t, freePeerManager(cfg), "uninitialized engine over a fresh PeerManager")
	requireClaimRefused(t, cfg, "held PeerManager with an uninitialized engine")
}

func TestPeerManagerClaimReusableAfterClose(t *testing.T) {
	_, cfg1 := unclaimedServiceSink(t)
	pm := cfg1.PeerManager
	s1 := requireClaimFree(t, cfg1, "S1")
	s1Addr, _ := startWithInboundPeer(t, s1)
	require(t, pm.Count() == 1, "PeerManager count=%d with one S1 peer, want 1", pm.Count())
	must(t, s1.Close(), "Close(S1)")
	require(t, pm.Count() == 0, "PeerManager count=%d after Close(S1), want 0", pm.Count())
	_, cfg2 := claimConfig(t, pm)
	s2 := requireClaimFree(t, cfg2, "S2 after Close(S1)")
	s2Addr, _ := startWithInboundPeer(t, s2)
	snapshot := pm.Snapshot()
	require(t, len(snapshot) == 1 && snapshot[0].Addr == s2Addr, "snapshot=%+v, want only the S2 peer %s (S1 peer %s)", snapshot, s2Addr, s1Addr)
}

func TestPeerManagerClaimReleasedAfterFinalDrain(t *testing.T) {
	_, cfg1 := unclaimedServiceSink(t)
	pm := cfg1.PeerManager
	s1 := requireClaimFree(t, cfg1, "S1")
	addr, _ := startWithInboundPeer(t, s1)
	letExitGo := holdPeerExit(t, s1, addr)
	closeFrames := closeDrainFrames("p2p." + t.Name() + ".func")
	requireNotParked(t, "a parked S1 connection exit", peerExitFrames...)
	requireNotParked(t, "a Close parked in the worker drain", closeFrames...)
	closed := make(chan error, 1)
	closeExit := goDone(func() { closed <- s1.Close() })
	requireParked(t, "S1 connection exit parked in its worker", peerExitFrames...)
	requireParked(t, "Close(S1) parked in the final worker drain", closeFrames...)
	require(t, pm.Count() == 1 && snapshotHas(pm, addr), "PeerManager count=%d, want the S1 peer %s kept while its exit is held", pm.Count(), addr)
	_, cfg2 := claimConfig(t, pm)
	requireClaimRefused(t, cfg2, "construction while Close waits for the held connection exit")
	letExitGo()
	requireJoined(t, "Close(S1)", closeExit)
	require(t, <-closed == nil && pm.Count() == 0, "Close(S1) left PeerManager count=%d", pm.Count())
	requireClaimFree(t, cfg2, "construction after Close(S1) returned")
}

func TestPeerManagerClaimJoinedCloseReturnsAfterRelease(t *testing.T) {
	_, cfg1 := unclaimedServiceSink(t)
	pm := cfg1.PeerManager
	s1 := requireClaimFree(t, cfg1, "S1")
	releaseLease := holdWorkLease(t, s1)
	testFrame := "p2p." + t.Name() + ".func"
	joinedFrames := []string{"[chan receive", "p2p.(*Service).Close(", testFrame}
	requireNotParked(t, "a Close parked in the worker drain", closeDrainFrames(testFrame)...)
	closed := make(chan error, 2)
	firstExit := goDone(func() { closed <- s1.Close() })
	requireParked(t, "first Close(S1) parked in the final worker drain", closeDrainFrames(testFrame)...)
	requireNotParked(t, "a joined Close", joinedFrames...)
	joinedExit := goDone(func() { closed <- s1.Close() })
	requireParked(t, "second Close(S1) waiting on the first Close's completion", joinedFrames...)
	_, cfg2 := claimConfig(t, pm)
	requireClaimRefused(t, cfg2, "construction while both Close calls wait")
	releaseLease()
	requireJoined(t, "joined Close(S1)", joinedExit)
	requireClaimFree(t, cfg2, "construction after the joined Close returned")
	requireJoined(t, "first Close(S1)", firstExit)
	errA, errB := <-closed, <-closed
	require(t, errA == nil && errB == nil, "Close(S1) returned an error")
}

func TestPeerManagerClaimLaterCloseReleasesNothing(t *testing.T) {
	_, cfg1 := unclaimedServiceSink(t)
	pm := cfg1.PeerManager
	s1 := requireClaimFree(t, cfg1, "S1")
	must(t, s1.Close(), "first Close(S1)")
	_, cfg2 := claimConfig(t, pm)
	requireClaimFree(t, cfg2, "S2")
	must(t, s1.Close(), "second Close(S1)")
	_, cfg3 := claimConfig(t, pm)
	requireClaimRefused(t, cfg3, "construction while S2 holds the PeerManager")
}

func TestPeerManagerClaimRollbackOnDARelayRefusal(t *testing.T) {
	h, cfg := claimConfig(t, freshPeerManager())
	uninitialized, err := node.NewSyncEngine(h.chainState, h.blockStore, cfg.SyncConfig)
	must(t, err, "NewSyncEngine")
	bad := cfg
	bad.SyncEngine = uninitialized
	requireDARelayUninitialized(t, bad, "uninitialized engine")
	requireClaimFree(t, cfg, "construction after the DA relay refusal")
}

func TestPeerManagerClaimEarlierRefusalsTakeNoClaim(t *testing.T) {
	_, cfg := claimConfig(t, freshPeerManager())
	for _, tc := range []struct {
		want   string
		mutate func(*ServiceConfig)
	}{
		{"bind address is required", func(c *ServiceConfig) { c.BindAddr = "" }},
		{"nil peer manager", func(c *ServiceConfig) { c.PeerManager = nil }},
		{"nil sync engine", func(c *ServiceConfig) { c.SyncEngine = nil }},
		{"nil blockstore", func(c *ServiceConfig) { c.BlockStore = nil }},
		{"nil tx metadata func", func(c *ServiceConfig) { c.TxMetadataFunc = nil }},
		{"inbound block budget must be zero or between 1073741824 and 8589934592 bytes", func(c *ServiceConfig) { c.InboundBlockBudgetBytes = maxInboundBlockBudgetBytes + 1 }},
	} {
		t.Run(tc.want, func(t *testing.T) {
			bad := cfg
			tc.mutate(&bad)
			requireEarlyClaimRefusal(t, bad, tc.want, "free PeerManager")
			s1 := requireClaimFree(t, cfg, "construction after the earlier refusal")
			requireEarlyClaimRefusal(t, bad, tc.want, "held PeerManager")
			require(t, cfg.SyncEngine.DATTLBindingService() == node.DATTLMutationService(s1), "earlier refusal changed the DA TTL binding")
			requireClaimRefused(t, cfg, "retry with the held PeerManager")
			require(t, cfg.SyncEngine.DATTLBindingService() == node.DATTLMutationService(s1), "retry changed the DA TTL binding")
		})
	}
}

func requireEarlyClaimRefusal(t *testing.T, cfg ServiceConfig, want, label string) {
	t.Helper()
	service, err := NewService(cfg)
	require(t, service == nil && err != nil && err.Error() == want, "%s: NewService=(%p,%v), want %q", label, service, err, want)
}

type claimResult struct {
	service *Service
	err     error
}

// constructConcurrently releases the constructors together and collects their results.
func constructConcurrently(t *testing.T, cfgs []ServiceConfig) []claimResult {
	t.Helper()
	start := make(chan struct{})
	results := make([]claimResult, len(cfgs))
	done := make([]<-chan struct{}, len(cfgs))
	for i, cfg := range cfgs {
		done[i] = goDone(func() {
			<-start
			results[i].service, results[i].err = NewService(cfg)
		})
	}
	close(start)
	requireJoined(t, "NewService constructors", done...)
	for _, result := range results {
		if result.service != nil {
			t.Cleanup(func() { _ = result.service.Close() })
		}
	}
	return results
}

func TestPeerManagerClaimAtomicAcrossConstructions(t *testing.T) {
	const racers = 8
	pm := freshPeerManager()
	cfgs := make([]ServiceConfig, racers)
	for i := range cfgs {
		_, cfgs[i] = claimConfig(t, pm)
	}
	winners, refused := 0, 0
	for _, r := range constructConcurrently(t, cfgs) {
		if r.err == nil && r.service != nil {
			winners++
			continue
		}
		require(t, r.service == nil && r.err != nil && r.err.Error() == errPeerManagerClaimed, "NewService=(%p,%v), want %q", r.service, r.err, errPeerManagerClaimed)
		refused++
	}
	require(t, winners == 1 && refused == racers-1, "winners=%d refused=%d, want 1 and %d", winners, refused, racers-1)
}

func TestPeerManagerClaimSharedSyncEngineStillBinds(t *testing.T) {
	_, cfg := unclaimedServiceSink(t)
	requireClaimFree(t, cfg, "S1")
	s2 := requireClaimFree(t, freePeerManager(cfg), "S2 over the same SyncEngine")
	require(t, cfg.SyncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "S2 is not the DA TTL binding")
}
