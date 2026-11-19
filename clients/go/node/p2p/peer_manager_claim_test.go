package p2p

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

const errPeerManagerClaimed = "peer manager is already claimed"

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

// startWithInboundPeer starts s and completes one inbound handshake through its listener.
func startWithInboundPeer(t *testing.T, s *Service) (string, net.Conn) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	must(t, s.Start(ctx), "Start")
	remote, err := net.Dial("tcp", s.Addr())
	must(t, err, "dial")
	t.Cleanup(func() { _ = remote.Close() })
	must(t, completeRemoteHandshake(remote, s.cfg.PeerRuntimeConfig, testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 0)), "remote handshake")
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

func closeCanceled(s *Service) bool {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	return s.ctx != nil && s.ctx.Err() != nil
}

func closeOwned(s *Service) bool {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	return s.closeDone != nil
}

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
	startWithInboundPeer(t, s1)
	releaseExit := holdWorkLease(t, s1)
	_, closeExit := startClose(s1)
	waitUntil(t, func() bool { return closeCanceled(s1) }, "Close cancels S1")
	_, cfg2 := claimConfig(t, pm)
	for deadline := time.Now().Add(50 * time.Millisecond); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		requireClaimRefused(t, cfg2, "construction while Close waits for the worker drain")
	}
	releaseExit()
	requireJoined(t, "Close(S1)", closeExit)
	requireClaimFree(t, cfg2, "construction after Close(S1) returned")
}

func TestPeerManagerClaimJoinedCloseReturnsAfterRelease(t *testing.T) {
	_, cfg1 := unclaimedServiceSink(t)
	pm := cfg1.PeerManager
	s1 := requireClaimFree(t, cfg1, "S1")
	releaseExit := holdWorkLease(t, s1)
	_, firstExit := startClose(s1)
	waitUntil(t, func() bool { return closeOwned(s1) }, "first Close owns the teardown")
	_, joinedExit := startClose(s1)
	releaseExit()
	requireJoined(t, "joined Close(S1)", joinedExit)
	_, cfg2 := claimConfig(t, pm)
	requireClaimFree(t, cfg2, "construction after the joined Close returned")
	requireJoined(t, "first Close(S1)", firstExit)
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
	service, err := NewService(bad)
	require(t, service == nil && err != nil && err.Error() == "sync engine DA relay state is not initialized", "NewService=(%p,%v)", service, err)
	requireClaimFree(t, cfg, "construction after the DA relay refusal")
}

func TestPeerManagerClaimEarlierRefusalsTakeNoClaim(t *testing.T) {
	pm := freshPeerManager()
	_, cfg := claimConfig(t, pm)
	for _, tc := range []struct {
		want   string
		mutate func(*ServiceConfig)
	}{
		{"bind address is required", func(c *ServiceConfig) { c.BindAddr = "" }},
		{"nil sync engine", func(c *ServiceConfig) { c.SyncEngine = nil }},
		{errInboundBlockBudgetRange.Error(), func(c *ServiceConfig) { c.InboundBlockBudgetBytes = maxInboundBlockBudgetBytes + 1 }},
	} {
		bad := cfg
		tc.mutate(&bad)
		service, err := NewService(bad)
		require(t, service == nil && err != nil && err.Error() == tc.want, "NewService=(%p,%v), want %q", service, err, tc.want)
	}
	nilPM := cfg
	nilPM.PeerManager = nil
	service, err := NewService(nilPM)
	require(t, service == nil && err != nil && err.Error() == "nil peer manager", "nil PeerManager: NewService=(%p,%v)", service, err)
	requireClaimFree(t, cfg, "construction after the earlier refusals")
}

type claimResult struct {
	service *Service
	err     error
}

// constructConcurrently runs NewService over every cfg at once and returns the results.
func constructConcurrently(cfgs []ServiceConfig) []claimResult {
	results := make([]claimResult, len(cfgs))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, cfg := range cfgs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i].service, results[i].err = NewService(cfg)
		}()
	}
	close(start)
	wg.Wait()
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
	for _, r := range constructConcurrently(cfgs) {
		if r.err == nil && r.service != nil {
			winners++
			t.Cleanup(func() { _ = r.service.Close() })
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
