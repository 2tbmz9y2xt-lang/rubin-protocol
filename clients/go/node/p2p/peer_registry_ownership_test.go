package p2p

import (
	"fmt"
	"sync"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// registryPeer is a handshaken connection with logical address addr whose socket reports
// endpoint, so registerPeer installs endpoint as its alias when that key is free.
func registryPeer(h *testHarness, addr, endpoint string) *peer {
	p := daRelayTestPeer(h, addr, endpoint)
	p.conn = &scriptedConn{remote: stubAddr(endpoint)}
	return p
}

// managerStates returns every PeerManager entry for addr.
func managerStates(h *testHarness, addr string) []node.PeerState {
	var out []node.PeerState
	for _, state := range h.service.cfg.PeerManager.Snapshot() {
		if state.Addr == addr {
			out = append(out, state)
		}
	}
	return out
}

// requireOwner pins Invariant P for addr: owner nil means no Service.peers owner and no
// PeerManager entry; otherwise Service.peers[addr] is owner and the PeerManager holds exactly
// owner's current state for addr.
func requireOwner(t *testing.T, h *testHarness, addr string, owner *peer, label string) {
	t.Helper()
	h.service.peersMu.RLock()
	got := h.service.peers[addr]
	h.service.peersMu.RUnlock()
	states := managerStates(h, addr)
	if owner == nil {
		require(t, got == nil && len(states) == 0 && !h.service.isConnected(addr), "%s: owner=%v manager=%+v connected=%v, want %s gone", label, got != nil, states, h.service.isConnected(addr), addr)
		return
	}
	want := owner.snapshotState()
	require(t, got == owner && len(states) == 1 && states[0].LastError == want.LastError && states[0].BanScore == want.BanScore && h.service.isConnected(addr), "%s: owner=%s manager=%+v, want %s's state %q/%d", label, peerAddrOrNil(got), states, owner.daQuotaIdentity, want.LastError, want.BanScore)
}

func mustRegister(t *testing.T, h *testHarness, peers ...*peer) {
	t.Helper()
	for _, p := range peers {
		must(t, h.service.registerPeer(p), "register "+p.addr())
	}
}

// P1: a replaced connection that still holds its alias exits without touching the owner's entry.
func TestPeerRegistryOwnershipStaleExitKeepsReplacement(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	const addr = "configured.example:19111"
	older, newer := registryPeer(h, addr, "198.51.100.1:1"), registryPeer(h, addr, "198.51.100.2:2")
	mustRegister(t, h, older, newer)
	newer.setLastError("newer state")
	require(t, h.service.isConnected("198.51.100.1:1"), "the replaced connection lost its alias entry before exiting")
	exits := h.service.PeerLifecycleExits()
	h.service.unregisterPeer(older)
	require(t, h.service.PeerLifecycleExits() == exits+1 && !h.service.isConnected("198.51.100.1:1"), "stale exit: exits=%d alias connected=%v", h.service.PeerLifecycleExits()-exits, h.service.isConnected("198.51.100.1:1"))
	requireOwner(t, h, addr, newer, "after the stale exit")
	h.service.unregisterPeer(newer)
	requireOwner(t, h, addr, nil, "after the owner's exit")
}

// P2: a stale exit racing a same-address registration under different quota keys always ends
// with the registered connection owning the address and its state in the PeerManager. While a
// test holds peersMu no registration reaches the PeerManager, and an observer reading both
// registries under peersMu throughout the race never sees one hold the address without the other.
func TestPeerRegistryOwnershipInterleavedExitAndRegistration(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	const addr = "configured.example:19112"
	held := registryPeer(h, addr, "198.51.100.30:1")
	h.service.peersMu.Lock()
	registeredHeld := make(chan error, 1)
	go func() { registeredHeld <- h.service.registerPeer(held) }()
	requireStillBlocked(t, registeredHeld, "registerPeer while peersMu is held")
	early := len(managerStates(h, addr))
	h.service.peersMu.Unlock()
	requireReturned(t, registeredHeld, "registerPeer after peersMu is released")
	require(t, early == 0, "the PeerManager admitted %d entries while peersMu was held", early)
	h.service.unregisterPeer(held)
	stop, split := make(chan struct{}), make(chan string, 1)
	observed := make(chan struct{})
	go func() {
		defer close(observed)
		for {
			select {
			case <-stop:
				return
			default:
			}
			h.service.peersMu.RLock()
			inPeers, inManager := h.service.peers[addr] != nil, len(managerStates(h, addr)) == 1
			h.service.peersMu.RUnlock()
			if inPeers != inManager {
				select {
				case split <- fmt.Sprintf("Service.peers=%v PeerManager=%v", inPeers, inManager):
				default:
				}
			}
		}
	}()
	defer func() {
		close(stop)
		<-observed
		select {
		case got := <-split:
			t.Fatalf("an observer under peersMu saw the registries split: %s", got)
		default:
		}
	}()
	for i := 0; i < 200; i++ {
		older := registryPeer(h, addr, fmt.Sprintf("198.51.100.%d:1", 1+i%2))
		newer := registryPeer(h, addr, fmt.Sprintf("203.0.113.%d:2", 1+i%2))
		mustRegister(t, h, older)
		var wg sync.WaitGroup
		var registered error
		wg.Add(2)
		go func() { defer wg.Done(); h.service.unregisterPeer(older) }()
		go func() { defer wg.Done(); registered = h.service.registerPeer(newer) }()
		wg.Wait()
		must(t, registered, "racing registration")
		requireOwner(t, h, addr, newer, fmt.Sprintf("round %d", i))
		h.service.unregisterPeer(newer)
		requireOwner(t, h, addr, nil, fmt.Sprintf("round %d final exit", i))
	}
}

// P3/P5: an exiting owner hands its address to the live replaced connection, publishing that
// connection's current state; a replaced connection's own publishes never reach the
// PeerManager, while bumpBan still returns its own threshold decision.
func TestPeerRegistryOwnershipHandoverAndNonOwnerPublish(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	const addr = "configured.example:19113"
	older, newer := registryPeer(h, addr, "198.51.100.3:3"), registryPeer(h, addr, "198.51.100.4:4")
	mustRegister(t, h, older, newer)
	newer.setLastError("owner state")
	older.setLastError("replaced state")
	banned := older.bumpBan(h.service.cfg.PeerRuntimeConfig.BanThreshold, "replaced ban")
	state := older.snapshotState()
	require(t, banned && state.BanScore == h.service.cfg.PeerRuntimeConfig.BanThreshold && state.LastError == "replaced ban", "replaced bumpBan=%v state=%+v, want its own threshold decision and local state", banned, state)
	requireOwner(t, h, addr, newer, "after the replaced connection's publishes")
	h.service.unregisterPeer(newer)
	requireOwner(t, h, addr, older, "after the owner's exit hands the address over")
	h.service.unregisterPeer(older)
	requireOwner(t, h, addr, nil, "after the successor's exit")
}

// P4: after its own removal a connection's setLastError and bumpBan (the calls unregisterPeer's
// DA-release error path and late handlers make) never recreate its PeerManager entry.
func TestPeerRegistryOwnershipNoGhostAfterRemoval(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	const addr = "configured.example:19114"
	p := registryPeer(h, addr, "198.51.100.5:5")
	mustRegister(t, h, p)
	h.service.unregisterPeer(p)
	p.setLastError("late diagnostic")
	require(t, p.bumpBan(1, "late ban") == false, "a late one-point bump crossed the threshold")
	requireOwner(t, h, addr, nil, "after late publishes from the removed connection")
	require(t, h.service.cfg.PeerManager.Count() == 0, "peer manager count=%d, want 0", h.service.cfg.PeerManager.Count())
}

// P6: an alias equal to another live connection's logical address never displaces it, in either
// registration order, and that connection's exit still removes its address.
func TestPeerRegistryOwnershipAliasNeverDisplacesOwner(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	const shared = "198.51.100.7:7"
	owner := registryPeer(h, shared, shared)
	aliased := registryPeer(h, "configured.example:19115", shared)
	mustRegister(t, h, owner, aliased)
	requireOwner(t, h, shared, owner, "an alias registered after the owner")
	h.service.unregisterPeer(owner)
	requireOwner(t, h, shared, nil, "the owner's exit with a colliding alias live")
	requireOwner(t, h, "configured.example:19115", aliased, "the aliased connection after the owner's exit")
	h.service.unregisterPeer(aliased)
	requireOwner(t, h, "configured.example:19115", nil, "the aliased connection's exit")
	// Reverse order: the logical owner registered after the alias takes its key.
	aliased = registryPeer(h, "configured.example:19116", shared)
	owner = registryPeer(h, shared, shared)
	mustRegister(t, h, aliased, owner)
	requireOwner(t, h, shared, owner, "an owner registered after the alias")
	h.service.unregisterPeer(aliased)
	requireOwner(t, h, shared, owner, "the alias holder's exit")
	h.service.unregisterPeer(owner)
	requireOwner(t, h, shared, nil, "the owner's final exit")
}

// P7: three connections of one address; every exit order hands the address to the most
// recently registered survivor.
func TestPeerRegistryOwnershipNewestSurvivorOwns(t *testing.T) {
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		const addr = "configured.example:19117"
		peers := []*peer{registryPeer(h, addr, "198.51.100.10:1"), registryPeer(h, addr, "198.51.100.11:2"), registryPeer(h, addr, "198.51.100.12:3")}
		mustRegister(t, h, peers...)
		for i, p := range peers {
			p.setLastError(fmt.Sprintf("session %d", i))
		}
		live := map[int]bool{0: true, 1: true, 2: true}
		for _, exit := range order {
			h.service.unregisterPeer(peers[exit])
			delete(live, exit)
			var want *peer
			for i := 2; i >= 0; i-- {
				if live[i] {
					want = peers[i]
					break
				}
			}
			requireOwner(t, h, addr, want, fmt.Sprintf("order %v after exit %d", order, exit))
		}
	}
}

// P8: single-connection registration, MaxPeers refusal, removal and the exit counter.
func TestPeerRegistryOwnershipSingleConnectionPaths(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	runtimeCfg := node.DefaultPeerRuntimeConfig("devnet", 1)
	h.peerManager = node.NewPeerManager(runtimeCfg)
	h.service.cfg.PeerManager = h.peerManager
	first, refused := registryPeer(h, "configured-1.example:1", "198.51.100.20:1"), registryPeer(h, "configured-2.example:2", "198.51.100.21:2")
	mustRegister(t, h, first)
	err := h.service.registerPeer(refused)
	require(t, err != nil && err.Error() == "max peers reached" && !h.service.isConnected("configured-2.example:2") && !h.service.isConnected("198.51.100.21:2"), "refusal err=%v left map entries", err)
	requireOwner(t, h, "configured-1.example:1", first, "after the refusal")
	exits := h.service.PeerLifecycleExits()
	h.service.unregisterPeer(first)
	h.service.unregisterPeer(first)
	require(t, h.service.PeerLifecycleExits() == exits+1, "exits=%d, want exactly one", h.service.PeerLifecycleExits()-exits)
	requireOwner(t, h, "configured-1.example:1", nil, "after the exit")
	mustRegister(t, h, refused)
	requireOwner(t, h, "configured-2.example:2", refused, "the refused connection after capacity freed")
}
