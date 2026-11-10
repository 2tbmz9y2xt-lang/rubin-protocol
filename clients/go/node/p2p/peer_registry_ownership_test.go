package p2p

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	require(t, got == owner && len(states) == 1 && reflect.DeepEqual(states[0], want) && h.service.isConnected(addr), "%s: owner=%s manager=%+v, want %s's state %q/%d", label, peerAddrOrNil(got), states, owner.daQuotaIdentity, want.LastError, want.BanScore)
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
// with the registered connection owning the address and its state in the PeerManager (bounded
// behavioral evidence of Invariant P; P10 and P11 are the critical-section kills).
func TestPeerRegistryOwnershipInterleavedExitAndRegistration(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	const addr = "configured.example:19112"
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
	// Three same-address connections: the owner's exit hands the address to the newest survivor,
	// not the oldest, in both Service.peers and the PeerManager.
	oldest, middle, newest := registryPeer(h, addr, "198.51.100.31:1"), registryPeer(h, addr, "198.51.100.32:2"), registryPeer(h, addr, "198.51.100.33:3")
	mustRegister(t, h, oldest, middle, newest)
	oldest.setLastError("oldest state")
	middle.setLastError("middle state")
	h.service.unregisterPeer(newest)
	requireOwner(t, h, addr, middle, "after the newest owner's exit")
	h.service.unregisterPeer(middle)
	requireOwner(t, h, addr, oldest, "after the middle owner's exit")
	h.service.unregisterPeer(oldest)
	requireOwner(t, h, addr, nil, "after the last exit")
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
	h.service.peersMu.RLock()
	peersBefore, liveBefore, orderBefore := maps.Clone(h.service.peers), maps.Clone(h.service.livePeers), h.service.peerRegistrations
	h.service.peersMu.RUnlock()
	err := h.service.registerPeer(refused)
	require(t, err != nil && err.Error() == "max peers reached" && !h.service.isConnected("configured-2.example:2") && !h.service.isConnected("198.51.100.21:2"), "refusal err=%v left map entries", err)
	h.service.peersMu.RLock()
	peersUnchanged, liveUnchanged, orderAfter := maps.Equal(h.service.peers, peersBefore), maps.Equal(h.service.livePeers, liveBefore), h.service.peerRegistrations
	_, refusedLive := h.service.livePeers[refused]
	h.service.peersMu.RUnlock()
	require(t, peersUnchanged && liveUnchanged && !refusedLive && orderAfter == orderBefore && refused.registrationOrder == 0, "refusal changed registry state: peers unchanged=%v live unchanged=%v refused live=%v order %d -> %d refused order=%d", peersUnchanged, liveUnchanged, refusedLive, orderBefore, orderAfter, refused.registrationOrder)
	requireOwner(t, h, "configured-2.example:2", nil, "the refused address")
	requireOwner(t, h, "configured-1.example:1", first, "after the refusal")
	exits := h.service.PeerLifecycleExits()
	h.service.unregisterPeer(first)
	h.service.unregisterPeer(first)
	require(t, h.service.PeerLifecycleExits() == exits+1, "exits=%d, want exactly one", h.service.PeerLifecycleExits()-exits)
	requireOwner(t, h, "configured-1.example:1", nil, "after the exit")
	require(t, h.service.reconnectSnapshot("configured-1.example:1") == (reconnectEntry{}), "an address that is not outbound gained reconnect state %+v", h.service.reconnectSnapshot("configured-1.example:1"))
	mustRegister(t, h, refused)
	requireOwner(t, h, "configured-2.example:2", refused, "the refused connection after capacity freed")
}

// P8/P12/R5(i): reconnect scheduling runs exactly once per exiting connection of an outbound
// address, whether that connection is the only one, a replaced one that still holds its alias, or
// a hidden one with no Service.peers entry. A repeated unregister of the same connection, and an
// exit of a connection that never registered, leave the entry exactly as they found it.
func TestPeerRegistryOwnershipReconnectOncePerExit(t *testing.T) {
	const backoff = 5 * time.Second // reconnectBaseDelay at zero failures
	for _, row := range []struct {
		name, addr string
		endpoints  []string
	}{
		{"single connection", "configured.example:19122", []string{"198.51.100.50:1"}},
		{"replaced with alias", "configured.example:19123", []string{"198.51.100.51:1", "198.51.100.52:2"}},
		{"hidden", "198.51.100.53:9000", []string{"198.51.100.53:9000", "198.51.100.53:9000"}},
	} {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		h.service.ensureOutboundAddr(row.addr)
		now := time.Unix(1000, 0)
		h.service.cfg.Now = func() time.Time { return now }
		peers := make([]*peer, 0, len(row.endpoints))
		for _, endpoint := range row.endpoints {
			peers = append(peers, registryPeer(h, row.addr, endpoint))
		}
		mustRegister(t, h, peers...)
		require(t, h.service.reconnectSnapshot(row.addr) == (reconnectEntry{}), "%s: reconnect state before any exit", row.name)
		for i, exiting := range peers {
			now = now.Add(time.Minute)
			want := now.Add(backoff)
			exits := h.service.PeerLifecycleExits()
			h.service.unregisterPeer(exiting)
			entry := h.service.reconnectSnapshot(row.addr)
			require(t, entry.nextRetry.Equal(want) && entry.failures == 0 && h.service.PeerLifecycleExits() == exits+1, "%s: exit %d: entry=%+v exits=%d, want nextRetry %v and one exit", row.name, i, entry, h.service.PeerLifecycleExits()-exits, want)
			now = now.Add(time.Minute)
			h.service.unregisterPeer(exiting)
			entry = h.service.reconnectSnapshot(row.addr)
			require(t, entry.nextRetry.Equal(want) && h.service.PeerLifecycleExits() == exits+1, "%s: repeated exit %d: entry=%+v exits=%d, want the first exit's schedule and count", row.name, i, entry, h.service.PeerLifecycleExits()-exits)
		}
		last := h.service.reconnectSnapshot(row.addr)
		now = now.Add(time.Minute)
		h.service.unregisterPeer(registryPeer(h, row.addr, row.endpoints[0]))
		require(t, h.service.reconnectSnapshot(row.addr).nextRetry.Equal(last.nextRetry), "%s: a never-registered connection's exit rescheduled reconnect", row.name)
	}
}

// P12: a replaced connection whose alias equals its logical address holds no Service.peers entry
// but stays live: it exits exactly once while still hidden, and the owner's exit hands it the
// address; each connection exits exactly once.
func TestPeerRegistryOwnershipHiddenLiveConnection(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	const addr = "198.51.100.40:9000"
	hidden, newer := registryPeer(h, addr, addr), registryPeer(h, addr, addr)
	mustRegister(t, h, hidden, newer)
	exits := h.service.PeerLifecycleExits()
	h.service.unregisterPeer(hidden)
	h.service.unregisterPeer(hidden)
	require(t, h.service.PeerLifecycleExits() == exits+1, "hidden exit counted %d times", h.service.PeerLifecycleExits()-exits)
	requireOwner(t, h, addr, newer, "after the hidden connection's exit")
	hidden = registryPeer(h, addr, addr)
	mustRegister(t, h, hidden)
	exits = h.service.PeerLifecycleExits()
	h.service.unregisterPeer(newer) // the replaced connection exits while hidden
	require(t, h.service.PeerLifecycleExits() == exits+1, "replaced hidden exit counted %d times", h.service.PeerLifecycleExits()-exits)
	hidden.setLastError("hidden state")
	requireOwner(t, h, addr, hidden, "after the replaced connection's exit")
	newer = registryPeer(h, addr, addr)
	mustRegister(t, h, newer)
	exits = h.service.PeerLifecycleExits()
	h.service.unregisterPeer(newer)
	require(t, h.service.PeerLifecycleExits() == exits+1, "owner exit counted %d times", h.service.PeerLifecycleExits()-exits)
	requireOwner(t, h, addr, hidden, "after the owner's exit hands the address to the hidden connection")
	h.service.unregisterPeer(hidden)
	h.service.unregisterPeer(hidden)
	require(t, h.service.PeerLifecycleExits() == exits+2, "hidden exit counted %d times", h.service.PeerLifecycleExits()-exits-1)
	requireOwner(t, h, addr, nil, "after the hidden connection's exit")
}

// P13: no same-key DA release runs while a hidden live connection holds the key, even when the
// exiting same-key connection has another logical address; the hidden connection's own exit,
// taken while it is still hidden, releases the key's retained state.
func TestPeerRegistryOwnershipHiddenConnectionKeepsDAQuota(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	const addr = "198.51.100.41:9000"
	hidden, newer := registryPeer(h, addr, addr), registryPeer(h, addr, "198.51.100.44:9000")
	sameKey := registryPeer(h, "configured.example:19120", "198.51.100.41:5")
	mustRegister(t, h, hidden)
	chunk := f.chunk(daRelayTestID(0xf8), 0, []byte("hidden"))
	must(t, hidden.handleTx(chunk), "hidden connection chunk")
	mustRegister(t, h, newer, sameKey)
	h.service.unregisterPeer(sameKey)
	f.requireRetained(chunk, "the hidden connection's chunk after another same-key connection's exit")
	h.service.unregisterPeer(hidden)
	f.requireAbsent(chunk, "the chunk after the hidden connection's exit")
	requireOwner(t, h, addr, newer, "the owner after the hidden connection's exit")
}

// P14: a connection whose only alias key is another connection's logical address and whose
// logical entry was replaced still exits once, with the successor and DA decisions intact.
func TestPeerRegistryOwnershipAliasHeldByAnotherOwner(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	const shared, addr = "198.51.100.42:7", "configured.example:19119"
	owner := registryPeer(h, shared, shared)
	hidden, newer := registryPeer(h, addr, shared), registryPeer(h, addr, "198.51.100.43:8")
	mustRegister(t, h, owner, hidden, newer)
	chunk := f.chunk(daRelayTestID(0xf9), 0, []byte("aliased"))
	must(t, hidden.handleTx(chunk), "hidden connection chunk")
	exits := h.service.PeerLifecycleExits()
	h.service.unregisterPeer(newer)
	requireOwner(t, h, addr, hidden, "after the owner of the hidden connection's address exits")
	h.service.unregisterPeer(owner)
	requireOwner(t, h, shared, nil, "after the alias-key owner exits")
	f.requireRetained(chunk, "the hidden connection's chunk after a same-key exit")
	h.service.unregisterPeer(hidden)
	require(t, h.service.PeerLifecycleExits() == exits+3, "exits=%d, want one per connection", h.service.PeerLifecycleExits()-exits)
	requireOwner(t, h, addr, nil, "after the hidden connection's exit")
	f.requireAbsent(chunk, "the chunk after the hidden connection's exit")
}

// closeCountingConn counts Close calls on a scripted connection with an explicit endpoint.
type closeCountingConn struct {
	scriptedConn
	closes int32
}

func (c *closeCountingConn) Close() error { atomic.AddInt32(&c.closes, 1); return nil }

// P16: Service.Close closes a hidden live connection directly, and every live connection once.
func TestPeerRegistryOwnershipCloseReachesHiddenConnection(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	const addr = "198.51.100.45:9000"
	hidden, owner := registryPeer(h, addr, addr), registryPeer(h, "configured.example:19121", "198.51.100.46:1")
	hiddenConn, ownerConn := &closeCountingConn{scriptedConn: scriptedConn{remote: stubAddr(addr)}}, &closeCountingConn{scriptedConn: scriptedConn{remote: stubAddr("198.51.100.46:1")}}
	hidden.conn, owner.conn = hiddenConn, ownerConn
	newer := registryPeer(h, addr, addr)
	newerConn := &closeCountingConn{scriptedConn: scriptedConn{remote: stubAddr(addr)}}
	newer.conn = newerConn
	mustRegister(t, h, hidden, owner, newer)
	h.service.peersMu.RLock()
	_, visible := h.service.peers[addr]
	hiddenListed := false
	for _, current := range h.service.peers {
		hiddenListed = hiddenListed || current == hidden
	}
	h.service.peersMu.RUnlock()
	require(t, visible && !hiddenListed, "fixture: the replaced connection still has a Service.peers entry")
	closed := make(chan error, 1)
	go func() { closed <- h.service.Close() }()
	requireReturned(t, closed, "Service.Close")
	for label, conn := range map[string]*closeCountingConn{"hidden": hiddenConn, "aliased owner": ownerConn, "newer": newerConn} {
		require(t, atomic.LoadInt32(&conn.closes) == 1, "%s connection closed %d times, want exactly once", label, atomic.LoadInt32(&conn.closes))
	}
}

// registerPeerParkedOnPeersMu reports whether some goroutine is blocked acquiring an RWMutex
// write lock directly from registerPeer, read from the full goroutine dump.
func registerPeerParkedOnPeersMu() bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	for _, goroutine := range strings.Split(string(buf), "\n\n") {
		var caller string
		for _, line := range strings.Split(goroutine, "\n") {
			if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "goroutine ") {
				continue
			}
			if strings.HasPrefix(line, "sync.") || strings.HasPrefix(line, "runtime.") || strings.HasPrefix(line, "internal/") {
				continue
			}
			caller = line
			break
		}
		if strings.Contains(goroutine, "sync.(*RWMutex).Lock(") && strings.Contains(caller, "p2p.(*Service).registerPeer(") {
			return true
		}
	}
	return false
}

// P10: while the test holds Service.peersMu and the registering goroutine is parked on it inside
// registerPeer, the PeerManager has no entry for the registering address.
func TestPeerRegistryOwnershipRegistrationIsAtomic(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	const addr = "configured.example:19118"
	p := registryPeer(h, addr, "198.51.100.30:1")
	h.service.peersMu.Lock()
	registered := make(chan error, 1)
	go func() { registered <- h.service.registerPeer(p) }()
	parked := false
	for deadline := time.Now().Add(5 * time.Second); !parked && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		parked = registerPeerParkedOnPeersMu()
	}
	early := managerStates(h, addr)
	h.service.peersMu.Unlock()
	require(t, parked, "registerPeer was never observed parked on peersMu")
	require(t, len(early) == 0, "the PeerManager held %+v for %s while registerPeer was parked on peersMu", early, addr)
	requireReturned(t, registered, "registerPeer after peersMu is released")
	requireOwner(t, h, addr, p, "after the registration completes")
}

// peerManagerMutation reports whether call is a PeerManager AddPeer, RemovePeer or UpsertPeer call.
func peerManagerMutation(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (selector.Sel.Name != "AddPeer" && selector.Sel.Name != "RemovePeer" && selector.Sel.Name != "UpsertPeer") {
		return false
	}
	owner, ok := selector.X.(*ast.SelectorExpr)
	return ok && owner.Sel.Name == "PeerManager"
}

// peersMuCall returns the method name of a Service.peersMu call, "" otherwise.
func peersMuCall(call *ast.CallExpr) string {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if mu, ok := selector.X.(*ast.SelectorExpr); ok && mu.Sel.Name == "peersMu" {
		return selector.Sel.Name
	}
	return ""
}

// P11: in service_peer_lifecycle.go and peer_runtime.go every PeerManager mutation lies after a
// Service.peersMu Lock/RLock with no non-deferred Unlock/RUnlock between them, and that span (up
// to the function's last non-deferred unlock, or its end under a deferred one) also reads or
// writes Service.peers, so the PeerManager effect and the Service.peers decision are one section.
func TestPeerRegistryOwnershipPeerManagerMutationsShareThePeersSection(t *testing.T) {
	seen := map[string]int{}
	for _, path := range []string{"service_peer_lifecycle.go", "peer_runtime.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		must(t, err, "parse "+path)
		for _, decl := range file.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			deferred := map[*ast.CallExpr]bool{}
			var locks, unlocks []token.Pos
			var mutations []*ast.CallExpr
			var peersAccess []token.Pos
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.DeferStmt:
					deferred[typed.Call] = true
				case *ast.CallExpr:
					switch name := peersMuCall(typed); {
					case name == "Lock" || name == "RLock":
						locks = append(locks, typed.Pos())
					case (name == "Unlock" || name == "RUnlock") && !deferred[typed]:
						unlocks = append(unlocks, typed.Pos())
					case peerManagerMutation(typed):
						mutations = append(mutations, typed)
					}
				case *ast.IndexExpr:
					if selector, ok := typed.X.(*ast.SelectorExpr); ok && selector.Sel.Name == "peers" {
						peersAccess = append(peersAccess, typed.Pos())
					}
				}
				return true
			})
			for _, mutation := range mutations {
				name := function.Name.Name + "." + mutation.Fun.(*ast.SelectorExpr).Sel.Name
				seen[name]++
				lock := token.NoPos
				for _, pos := range locks {
					if pos < mutation.Pos() {
						lock = pos
					}
				}
				require(t, lock.IsValid(), "%s: %s runs before any peersMu lock", path, name)
				spanEnd := function.Body.End()
				for _, pos := range unlocks {
					require(t, pos < lock || pos > mutation.Pos(), "%s: %s runs after peersMu was released", path, name)
				}
				if len(unlocks) > 0 && unlocks[len(unlocks)-1] > mutation.Pos() {
					spanEnd = unlocks[len(unlocks)-1]
				}
				shared := false
				for _, pos := range peersAccess {
					shared = shared || (pos > lock && pos < spanEnd)
				}
				require(t, shared, "%s: %s's peersMu section neither changes nor checks Service.peers", path, name)
			}
		}
	}
	for _, name := range []string{"registerPeer.AddPeer", "removePeerEntries.RemovePeer", "removePeerEntries.UpsertPeer", "publishPeerStateIfOwner.UpsertPeer"} {
		require(t, seen[name] == 1, "%s calls=%d, want exactly one (all calls: %v)", name, seen[name], seen)
	}
	require(t, len(seen) == 4, "PeerManager mutations outside the R1-R3 sections: %v", seen)
}
