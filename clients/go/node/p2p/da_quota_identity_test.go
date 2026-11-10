package p2p

import (
	"context"
	"io"
	"maps"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// TestDAQuotaIdentityForEndpoint pins the DA quota identity table (RUBIN_COMPACT_BLOCKS.md Section
// 5.0.1) with literals independent of the helper: port and zone removed, IPv4-mapped IPv6 equal to
// the IPv4 identity, exact address equality with no prefix grouping, and no identity for a nil,
// empty or non-IP endpoint.
func TestDAQuotaIdentityForEndpoint(t *testing.T) {
	for _, row := range []struct {
		remote net.Addr
		want   string
	}{
		{stubAddr("192.0.2.7:1"), "192.0.2.7"},
		{stubAddr("192.0.2.7:65535"), "192.0.2.7"},
		{stubAddr("[::ffff:192.0.2.7]:9"), "192.0.2.7"},
		{stubAddr("[::ffff:c000:207]:10"), "192.0.2.7"},
		{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 11}, "192.0.2.7"},
		{stubAddr("192.0.2.7"), "192.0.2.7"},
		{stubAddr("::ffff:192.0.2.7"), "192.0.2.7"},
		{stubAddr("[2001:db8::1]:1"), "2001:db8::1"},
		{stubAddr("[2001:0db8:0000:0000:0000:0000:0000:0001]:5"), "2001:db8::1"},
		{stubAddr("2001:db8::1"), "2001:db8::1"},
		{stubAddr("[2001:db8::2]:1"), "2001:db8::2"},
		{stubAddr("[fe80::1%en0]:7"), "fe80::1"},
		{stubAddr("[fe80::1%en1]:7"), "fe80::1"},
		{stubAddr("fe80::1%en0"), "fe80::1"},
		{&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 7, Zone: "en2"}, "fe80::1"},
		{stubAddr("0.0.0.0:1"), "0.0.0.0"},
		{stubAddr("[::]:1"), "::"},
		{nil, ""},
		{(*net.TCPAddr)(nil), ""},
		{&net.TCPAddr{Port: 19111}, ""},
		{stubAddr(""), ""},
		{stubAddr("remote"), ""},
		{stubAddr("configured.example:19111"), ""},
		{stubAddr("localhost:19111"), ""},
		{stubAddr(":19111"), ""},
		{stubAddr("[2001:db8::1]"), ""},
		{stubAddr("192.0.2.7:1:2"), ""},
		{stubAddr("192.0.2.0/24"), ""},
	} {
		label := "<nil>"
		if row.remote != nil {
			label = row.remote.String()
		}
		got, ok := daQuotaIdentityForEndpoint(row.remote)
		require(t, got == row.want && ok == (row.want != ""), "%q: identity=(%q,%v), want %q", label, got, ok, row.want)
	}
	// The canonical text is the exact 4- or 16-byte identity: the mapped spelling decodes to the
	// IPv4 bytes, an IPv6 identity to its literal 16 bytes.
	v4, _ := daQuotaIdentityForEndpoint(stubAddr("[::ffff:192.0.2.7]:9"))
	v6, _ := daQuotaIdentityForEndpoint(stubAddr("[2001:db8::1]:1"))
	require(t, netip.MustParseAddr(v4).Is4() && netip.MustParseAddr(v4).As4() == [4]byte{192, 0, 2, 7}, "mapped identity %q is not the IPv4 bytes", v4)
	require(t, netip.MustParseAddr(v6).As16() == [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}, "IPv6 identity %q is not its literal bytes", v6)
}

// endpointConn reports an explicit actual socket endpoint for an in-memory pipe.
type endpointConn struct {
	net.Conn
	remote net.Addr
}

func (c endpointConn) RemoteAddr() net.Addr { return c.remote }

// startEndpointConn runs the real handleConn over a pipe whose socket reports endpoint and completes
// the remote handshake; the returned stop closes the remote side and joins handleConn.
func startEndpointConn(t *testing.T, h *testHarness, outboundAddr string, endpoint net.Addr) (net.Conn, func()) {
	t.Helper()
	local, remote := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.service.handleConn(endpointConn{Conn: local, remote: endpoint}, outboundAddr)
	}()
	must(t, completeRemoteHandshake(remote, h.service.cfg.PeerRuntimeConfig, testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 1)), "remote handshake")
	go func() { _, _ = io.Copy(io.Discard, remote) }()
	return local, func() { _ = remote.Close(); <-done }
}

// registeredPeerOn returns the published peer whose connection is local, nil if none is.
func registeredPeerOn(h *testHarness, local net.Conn) *peer {
	h.service.peersMu.RLock()
	defer h.service.peersMu.RUnlock()
	for _, current := range h.service.peers {
		if conn, ok := current.conn.(endpointConn); ok && conn.Conn == local {
			return current
		}
	}
	return nil
}

func waitRegisteredPeerOn(t *testing.T, h *testHarness, local net.Conn) *peer {
	t.Helper()
	var current *peer
	waitFor(t, 5*time.Second, func() bool { current = registeredPeerOn(h, local); return current != nil })
	return current
}

// TestDAQuotaIdentityCapturedByHandleConn: through the real handleConn, the actual socket
// endpoint alone supplies the DA key, installed before registration on both the outbound and the
// inbound path; a configured DNS name, a logical-address change and a valid-IP configured name
// with a non-IP socket never supply one, and the final exit releases under the socket key.
func TestDAQuotaIdentityCapturedByHandleConn(t *testing.T) {
	h := newTestHarness(t, 2, "127.0.0.1:0", nil)
	h.service.ctx = context.Background()
	h.service.cfg.PeerRuntimeConfig.ReadDeadline, h.service.cfg.PeerRuntimeConfig.WriteDeadline = 0, 0
	f := newDAIngressFixture(t, h)
	// Outbound: a configured DNS name over an IPv4-mapped socket. Registration parks on the
	// socket key, so the key exists before registerPeer publishes the peer.
	unlock := h.service.lockPeerQuotaKey("198.51.100.7")
	outLocal, stopOut := startEndpointConn(t, h, "configured.example:19111", stubAddr("[::ffff:198.51.100.7]:40000"))
	waitForPeerQuotaLockRefs(t, h.service, "198.51.100.7", 2)
	require(t, registeredPeerOn(h, outLocal) == nil, "the outbound peer was published while its socket key was held")
	unlock()
	out := waitRegisteredPeerOn(t, h, outLocal)
	logical, quota, _, ok := out.remoteDAProvenance()
	require(t, out.addr() == "configured.example:19111" && out.daQuotaIdentity == "198.51.100.7" && ok && logical == out.addr() && quota == "198.51.100.7", "outbound addr=%q key=%q provenance=(%q,%q,%v), want the socket key under the configured name", out.addr(), out.daQuotaIdentity, logical, quota, ok)
	out.stateMu.Lock()
	out.state.Addr = "198.51.100.99:19111" // a later logical/advertised change
	out.stateMu.Unlock()
	_, quota, _, ok = out.remoteDAProvenance()
	require(t, ok && quota == "198.51.100.7", "provenance key after a logical change=%q ok=%v", quota, ok)
	out.stateMu.Lock()
	out.state.Addr = "configured.example:19111"
	out.stateMu.Unlock()
	commit := f.commit(daRelayTestID(0xe0), 2)
	must(t, out.handleTx(commit), "outbound DA commit")
	f.requireRetained(commit, "the outbound session's commit")
	// Inbound: the logical address is the socket text; the same capture precedes registration.
	unlock = h.service.lockPeerQuotaKey("203.0.113.9")
	inLocal, stopIn := startEndpointConn(t, h, "", stubAddr("203.0.113.9:5555"))
	waitForPeerQuotaLockRefs(t, h.service, "203.0.113.9", 2)
	require(t, registeredPeerOn(h, inLocal) == nil, "the inbound peer was published while its socket key was held")
	unlock()
	in := waitRegisteredPeerOn(t, h, inLocal)
	require(t, in.daQuotaIdentity == "203.0.113.9", "inbound key=%q", in.daQuotaIdentity)
	// H1: a configured name that is a valid IP over a non-IP socket has no key: no DA effect, the
	// connection stays registered for every other message.
	badLocal, stopBad := startEndpointConn(t, h, "198.51.100.8:19111", stubAddr("remote"))
	bad := waitRegisteredPeerOn(t, h, badLocal)
	_, _, _, ok = bad.remoteDAProvenance()
	require(t, bad.addr() == "198.51.100.8:19111" && bad.daQuotaIdentity == "" && !ok, "non-IP socket addr=%q key=%q provenance ok=%v", bad.addr(), bad.daQuotaIdentity, ok)
	refused, before, calls := f.commit(daRelayTestID(0xe1), 2), effectsOf(bad), nowCalls(h)
	must(t, bad.handleTx(refused), "non-IP socket DA commit")
	require(t, effectsOf(bad) == before && calls.Load() == 0 && registeredPeerOn(h, badLocal) == bad, "non-IP socket: effects %+v -> %+v scheduler=%d registered=%v", before, effectsOf(bad), calls.Load(), registeredPeerOn(h, badLocal) == bad)
	f.requireAbsent(refused, "the non-IP socket's commit")
	stopBad()
	stopIn()
	f.requireRetained(commit, "the outbound commit after other keys' exits")
	stopOut()
	f.requireAbsent(commit, "the outbound commit after its socket key's final exit")
}

// TestDAQuotaIdentityInvalidEndpointZeroEffects (A3/H4): a session whose socket endpoint is empty or
// not an IP, whatever its logical name, takes no DA quota lock on registration, ingress or removal,
// has a valid DA commit refused with zero peer, scheduler and retained effects, and still registers
// and exits exactly once. A held empty-key lock proves no empty-string lock row is ever taken.
func TestDAQuotaIdentityInvalidEndpointZeroEffects(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	calls := nowCalls(h)
	unlockEmpty := h.service.lockPeerQuotaKey("")
	defer unlockEmpty()
	for i, row := range []struct{ addr, endpoint string }{
		{"198.51.100.8:19111", ""},
		{"198.51.100.8:19112", "remote"},
		{"configured.example:19111", "configured.example:19111"},
		{"198.51.100.8:19113", ":19113"},
		{"peer-a", "localhost:19114"},
	} {
		p := daRelayTestPeer(h, row.addr, row.endpoint)
		require(t, p.daQuotaIdentity == "", "%q: key=%q from a non-IP endpoint", row.endpoint, p.daQuotaIdentity)
		registered := make(chan error, 1)
		go func() { registered <- h.service.registerPeer(p) }()
		requireReturned(t, registered, row.endpoint+": registerPeer under a held empty-key lock")
		raw, before, exits := f.commit(daRelayTestID(0xe8+byte(i)), 2), effectsOf(p), h.service.PeerLifecycleExits()
		calls.Store(0)
		handled := make(chan error, 1)
		go func() { handled <- p.handleTx(raw) }()
		requireReturned(t, handled, row.endpoint+": handleTx under a held empty-key lock")
		require(t, effectsOf(p) == before && calls.Load() == 0, "%q: effects %+v -> %+v scheduler=%d", row.endpoint, before, effectsOf(p), calls.Load())
		unregistered := make(chan error, 1)
		go func() { h.service.unregisterPeer(p); unregistered <- nil }()
		requireReturned(t, unregistered, row.endpoint+": unregisterPeer under a held empty-key lock")
		h.service.peersMu.RLock()
		_, present := h.service.peers[row.addr]
		h.service.peersMu.RUnlock()
		require(t, !present && h.service.PeerLifecycleExits() == exits+1, "%q: present=%v exits=%d, want removed once", row.endpoint, present, h.service.PeerLifecycleExits()-exits)
		f.requireAbsent(raw, row.endpoint+": the refused commit")
	}
	released := make(chan error, 1)
	go func() { released <- h.service.releaseDAQuotaIfInactive("") }()
	requireReturned(t, released, "releaseDAQuotaIfInactive(\"\") under a held empty-key lock")
	h.service.peersMu.Lock()
	go func() { released <- h.service.releaseDAQuotaIfInactiveLocked("") }()
	select {
	case err := <-released:
		h.service.peersMu.Unlock()
		must(t, err, "releaseDAQuotaIfInactiveLocked(\"\")")
	case <-time.After(5 * time.Second):
		h.service.peersMu.Unlock()
		t.Fatal("releaseDAQuotaIfInactiveLocked(\"\") reached the active-key scan")
	}
}

// TestDAQuotaIdentityInvalidEndpointThroughHandleConn (A3/H1/H4): through the real handleConn, each
// listed non-nil invalid socket endpoint, inbound or under a configured name that may itself be a
// valid IP, leaves the connection registered with no DA key; a valid DA commit is refused with
// exact equality of the retained DA state and zero peer and scheduler effects, the connection
// exits exactly once, and no empty-string quota lock is ever taken (a held empty-key lock would
// park any such acquisition).
func TestDAQuotaIdentityInvalidEndpointThroughHandleConn(t *testing.T) {
	h := newTestHarness(t, 2, "127.0.0.1:0", nil)
	h.service.ctx = context.Background()
	h.service.cfg.PeerRuntimeConfig.ReadDeadline, h.service.cfg.PeerRuntimeConfig.WriteDeadline = 0, 0
	f := newDAIngressFixture(t, h)
	completeID := daRelayTestID(0xd0)
	retainedCommit, retainedChunk := f.commit(completeID, 1), f.chunk(completeID, 0, completeID[:])
	f.admit(retainedCommit, "127.0.0.9:19119")
	f.admit(retainedChunk, "127.0.0.9:19119")
	const anyPayload = uint64(1) << 40
	retained := h.service.daRelay.CompleteSetCandidates(anyPayload)
	require(t, len(retained) == 1, "fixture: complete sets=%d, want the one retained set", len(retained))
	calls := nowCalls(h)
	unlockEmpty := h.service.lockPeerQuotaKey("")
	defer unlockEmpty()
	for i, row := range []struct{ outbound, endpoint string }{
		{"198.51.100.8:19111", ""},
		{"", "remote"},
		{"configured-remote.example:1", "remote"},
		{"", "configured.example:19111"},
		{"configured.example:19112", "configured.example:19111"},
		{"198.51.100.8:19113", ":19113"},
		{"peer-a", "localhost:19114"},
	} {
		local, stop := startEndpointConn(t, h, row.outbound, stubAddr(row.endpoint))
		current := waitRegisteredPeerOn(t, h, local)
		_, _, _, ok := current.remoteDAProvenance()
		require(t, current.daQuotaIdentity == "" && !ok, "%q: key=%q provenance ok=%v, want no DA identity", row.endpoint, current.daQuotaIdentity, ok)
		raw, before, exits := f.commit(daRelayTestID(0xd8+byte(i)), 2), effectsOf(current), h.service.PeerLifecycleExits()
		calls.Store(0)
		handled := make(chan error, 1)
		go func() { handled <- current.handleTx(raw) }()
		requireReturned(t, handled, row.endpoint+": handleTx under a held empty-key lock")
		require(t, effectsOf(current) == before && calls.Load() == 0 && registeredPeerOn(h, local) == current, "%q: effects %+v -> %+v scheduler=%d registered=%v", row.endpoint, before, effectsOf(current), calls.Load(), registeredPeerOn(h, local) == current)
		f.requireAbsent(raw, row.endpoint+": the refused commit")
		f.requireRetained(retainedCommit, row.endpoint+": the retained commit")
		f.requireRetained(retainedChunk, row.endpoint+": the retained chunk")
		after := h.service.daRelay.CompleteSetCandidates(anyPayload)
		require(t, reflect.DeepEqual(after, retained), "%q: complete sets changed: %+v -> %+v", row.endpoint, retained, after)
		stop()
		require(t, h.service.PeerLifecycleExits() == exits+1 && registeredPeerOn(h, local) == nil, "%q: exits=%d registered=%v, want one exit and removal", row.endpoint, h.service.PeerLifecycleExits()-exits, registeredPeerOn(h, local) != nil)
		waitForPeerQuotaLockRefs(t, h.service, "", 1)
	}
}

// TestDAQuotaIdentitySameKeyConservation (A4/A8): an IPv4 session and an IPv4-mapped session of the
// same host on different ports share one State A per-source quota and one provenance key: their
// combined retained chunks reach the 4 MiB per-peer cap, a distinct host still admits the refused
// chunk, and a release of the literal socket key removes every member either session retained.
func TestDAQuotaIdentitySameKeyConservation(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	calls := nowCalls(h)
	v4 := daRelayTestPeer(h, "configured-v4.example:1", "192.0.2.7:1")
	mapped := daRelayTestPeer(h, "configured-v6.example:2", "[::ffff:192.0.2.7]:2")
	other := daRelayTestPeer(h, "198.51.100.1:1", "198.51.100.1:1")
	_, quota, _, ok := mapped.remoteDAProvenance()
	require(t, ok && quota == "192.0.2.7" && v4.daQuotaIdentity == quota, "mapped provenance key=%q ok=%v v4 key=%q", quota, ok, v4.daQuotaIdentity)
	daID := daRelayTestID(0xe4)
	payload := make([]byte, consensus.CHUNK_BYTES) // a full chunk pays its Stage C DA fee floor
	var retained [][]byte
	for i := uint16(0); i < 3; i++ { // three full chunks fit the per-peer cap under the incomplete-member charge; a fourth does not
		payload[0] = byte(i)
		raw := f.tx(daTxSpec{kind: 0x02, daID: daID, index: i, payload: payload, fee: 600_000})
		sender := []*peer{v4, mapped}[i%2]
		calls.Store(0)
		must(t, sender.handleTx(raw), "same-key chunk")
		require(t, calls.Load() == 1, "chunk %d: scheduler entries=%d, want the RETAINED entry", i, calls.Load())
		retained = append(retained, raw)
	}
	payload[0] = 3
	overflow := f.tx(daTxSpec{kind: 0x02, daID: daID, index: 3, payload: payload, fee: 600_000})
	before := effectsOf(mapped)
	calls.Store(0)
	must(t, mapped.handleTx(overflow), "over-cap chunk")
	require(t, calls.Load() == 0 && effectsOf(mapped) == before, "over-cap chunk: scheduler entries=%d effects %+v -> %+v, want a peer-neutral refusal", calls.Load(), before, effectsOf(mapped))
	must(t, other.handleTx(overflow), "distinct-host chunk")
	require(t, calls.Load() == 1, "distinct host: scheduler entries=%d, want the RETAINED entry", calls.Load())
	must(t, h.service.releaseDAQuotaIfInactive("192.0.2.7"), "release the socket key")
	for i, raw := range retained {
		f.requireAbsent(raw, "same-key chunk "+string(rune('0'+i))+" after the socket-key release")
	}
	f.requireRetained(overflow, "the distinct host's chunk")
}

// TestDAQuotaIdentityExactAddressesAndZones (H3): two IPv6 peers sharing a long prefix keep
// independent quotas, while two zones of one link-local address are one identity.
func TestDAQuotaIdentityExactAddressesAndZones(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	first := daRelayTestPeer(h, "configured-1.example:1", "[2001:db8::1]:1")
	second := daRelayTestPeer(h, "configured-2.example:1", "[2001:db8::2]:1")
	zoneA := daRelayTestPeer(h, "configured-a.example:7", "[fe80::1%en0]:7")
	zoneB := daRelayTestPeer(h, "configured-b.example:8", "[fe80::1%en1]:8")
	for _, p := range []*peer{first, second, zoneA, zoneB} {
		must(t, h.service.registerPeer(p), "register "+p.addr())
	}
	firstChunk, secondChunk := f.chunk(daRelayTestID(0xe5), 0, []byte("first")), f.chunk(daRelayTestID(0xe6), 0, []byte("second"))
	zoneChunk := f.chunk(daRelayTestID(0xe7), 0, []byte("zone"))
	must(t, first.handleTx(firstChunk), "first chunk")
	must(t, second.handleTx(secondChunk), "second chunk")
	must(t, zoneA.handleTx(zoneChunk), "zone chunk")
	h.service.unregisterPeer(first)
	f.requireAbsent(firstChunk, "2001:db8::1's chunk after its exit")
	f.requireRetained(secondChunk, "2001:db8::2's chunk after 2001:db8::1 exited")
	h.service.unregisterPeer(zoneA)
	f.requireRetained(zoneChunk, "the link-local chunk while the other zone's session is active")
	h.service.unregisterPeer(zoneB)
	f.requireAbsent(zoneChunk, "the link-local chunk after the last zone's exit")
}

// TestDAPrefetchGroupsBySocketQuotaIdentity (A7): prefetch keys are the connections' socket
// identities, never their logical names: an IPv4 session and an IPv4-mapped session of one host
// form one group, two IPv6 addresses sharing a prefix form two, a non-IP socket is no candidate,
// and the preferred trigger leads under its socket key with its exact session as representative.
func TestDAPrefetchGroupsBySocketQuotaIdentity(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.EnableCompactReceive = true
	v4 := addDAPrefetchTestPeer(h.service, "configured-v4.example:1", "192.0.2.5:1", nil)
	mapped := addDAPrefetchTestPeer(h.service, "configured-mapped.example:2", "[::ffff:192.0.2.5]:2", nil)
	low := addDAPrefetchTestPeer(h.service, "configured-low.example:1", "[2001:db8::1]:1", nil)
	high := addDAPrefetchTestPeer(h.service, "configured-high.example:1", "[2001:db8::2]:1", nil)
	blank := addDAPrefetchTestPeer(h.service, "198.51.100.9:1", "remote", nil)
	require(t, blank.daQuotaIdentity == "", "non-IP socket key=%q", blank.daQuotaIdentity)
	all := []string{"192.0.2.5", "2001:db8::1", "2001:db8::2"}
	peers, keys := h.service.daPrefetchPeers(nil)
	require(t, reflect.DeepEqual(keys, all) && len(peers) == 3 && (peers["192.0.2.5"] == v4 || peers["192.0.2.5"] == mapped) && peers["2001:db8::1"] == low && peers["2001:db8::2"] == high, "no trigger: keys=%v peers=%d", keys, len(peers))
	peers, keys = h.service.daPrefetchPeers(high)
	require(t, reflect.DeepEqual(keys, []string{"2001:db8::2", "192.0.2.5", "2001:db8::1"}) && peers["2001:db8::2"] == high, "IPv6 trigger: keys=%v representative=%s", keys, peerAddrOrNil(peers["2001:db8::2"]))
	peers, keys = h.service.daPrefetchPeers(blank)
	require(t, reflect.DeepEqual(keys, all) && len(peers) == 3, "non-IP trigger: keys=%v peers=%d, want the unpreferred socket keys", keys, len(peers))
	for _, row := range []struct {
		trigger *peer
		seeded  *peer
	}{{mapped, v4}, {v4, mapped}} {
		seed := map[string]*peer{"192.0.2.5": row.seeded, "2001:db8::1": low}
		h.service.peersMu.RLock()
		key := h.service.preferredDAPrefetchPeerKeyLocked(row.trigger, 1, seed)
		h.service.peersMu.RUnlock()
		require(t, key == "192.0.2.5" && maps.Equal(seed, map[string]*peer{"192.0.2.5": row.trigger, "2001:db8::1": low}), "trigger %s: key=%q representative=%s, want the exact trigger session", row.trigger.addr(), key, peerAddrOrNil(seed["192.0.2.5"]))
	}
	require(t, !strings.Contains(strings.Join(keys, ","), "configured"), "a logical name leaked into the prefetch keys %v", keys)
}
