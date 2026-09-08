package p2p

import (
	"bytes"
	"errors"
	"maps"
	"reflect"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// readScriptedFrames decodes every getdachunk request written to current's scripted socket.
func readScriptedFrames(t *testing.T, h *testHarness, current *peer) []getDAChunkPayload {
	t.Helper()
	reader := bytes.NewReader(current.conn.(*scriptedConn).Bytes())
	var requests []getDAChunkPayload
	for reader.Len() > 0 {
		frame, err := readFrame(reader, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		must(t, err, "readFrame("+current.addr()+")")
		request, err := decodeGetDAChunkPayload(frame.Payload)
		require(t, err == nil && frame.Command == messageGetDAChunk, "frame=%+v request=%+v err=%v", frame, request, err)
		requests = append(requests, request)
	}
	return requests
}

func TestDAPrefetchTracksCurrentMissingIndexesAndCompletion(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	daID := daRelayTestID(140)
	f.admit(f.commit(daID, 2), "127.0.0.9:19119")
	now := time.Unix(1000, 0)
	plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, now)
	require(t, len(plans) == 1 && diagnostic == "" && reflect.DeepEqual(plans[0].Indexes, []uint16{0, 1}), "initial plans=%+v diagnostic=%q", plans, diagnostic)
	f.admit(f.chunk(daID, 0, []byte{1}), "127.0.0.9:19119")
	retry, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, now)
	require(t, len(retry) == 0 && diagnostic == "", "fulfilled-index retry=%+v diagnostic=%q", retry, diagnostic)
	h.service.daRelay.ReleasePrefetchPlan(node.DARelayPrefetchPlan{DAID: daID, PeerKey: plans[0].PeerKey, Indexes: []uint16{1}})
	retry, diagnostic = h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, now)
	require(t, len(retry) == 1 && diagnostic == "" && reflect.DeepEqual(retry[0].Indexes, []uint16{1}), "released retry=%+v diagnostic=%q, want index 1 alone", retry, diagnostic)
}

func TestScheduleLocalDAPrefetchUsesAllEligiblePeers(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.EnableCompactReceive = true
	a := addDAPrefetchTestPeer(h.service, "127.0.0.2:1", nil)
	b := addDAPrefetchTestPeer(h.service, "127.0.0.3:1", nil)
	daID := daRelayTestID(0xd1)
	result, err := h.service.AdmitLocalDA(newDAIngressFixture(t, h).commit(daID, 2))
	require(t, err == nil && result == (node.DAAdmissionResult{DAID: daID, Disposition: node.DAAdmissionRetained}) && h.service.txSeen.Len() == 0, "local admission=(%+v,%v) txSeen=%d", result, err, h.service.txSeen.Len())
	must(t, h.service.ScheduleLocalDAPrefetch(daID), "ScheduleLocalDAPrefetch")
	expectPrefetchRequests(t, h, map[*peer][]byte{}, "local all-peer prefetch", daID, 2, a, b)
}

func TestDAPrefetchSendWritesGetDAChunkFrame(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.EnableCompactReceive = true
	f := newDAIngressFixture(t, h)
	current := addDAPrefetchTestPeer(h.service, "peer-a", nil)
	daID := daRelayTestID(141)
	f.admit(f.commit(daID, 2), "127.0.0.9:19119")
	h.service.scheduleDAPrefetch("peer-a", daID)
	requests := readScriptedFrames(t, h, current)
	require(t, len(requests) == 1 && requests[0].DAID == daID && reflect.DeepEqual(requests[0].Indexes, []uint16{0, 1}), "requests=%+v", requests)
}

func TestDAPrefetchSendFailureReleasesPlan(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.EnableCompactReceive = true
	f := newDAIngressFixture(t, h)
	current := addDAPrefetchTestPeer(h.service, "peer-a", errors.New("write failed"))
	daID := daRelayTestID(132)
	f.admit(f.commit(daID, 2), "127.0.0.9:19119")
	h.service.scheduleDAPrefetch("peer-a", daID)
	require(t, current.snapshotState().BanScore == 0 && current.snapshotState().LastError != "", "state=%+v, want diagnostic without ban", current.snapshotState())
	retry, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, h.service.cfg.Now())
	require(t, len(retry) == 1 && len(retry[0].Indexes) == 2 && diagnostic == "", "released retry plans=%+v diagnostic=%q, want one plan with two indexes", retry, diagnostic)
}

func TestDAPrefetchMissingPeerReleasesPlan(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	daID := daRelayTestID(135)
	f.admit(f.commit(daID, 1), "127.0.0.9:19119")
	plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, time.Unix(1000, 0))
	require(t, len(plans) == 1 && diagnostic == "", "plans=%d diagnostic=%q, want one", len(plans), diagnostic)
	h.service.sendDAPrefetchPlan(map[string]*peer{}, plans[0])
	retry, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, time.Unix(1000, 0))
	require(t, len(retry) == 1 && diagnostic == "", "released retry=%d diagnostic=%q", len(retry), diagnostic)
}

func TestDAPrefetchReportsDiagnostic(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	current := addDAPrefetchTestPeer(h.service, "peer-a", nil)
	reportDAPrefetchDiagnostic(map[string]*peer{"peer-a": current}, []string{"peer-a"}, "diagnostic")
	if state := current.snapshotState(); state.LastError != "diagnostic" || state.BanScore != 0 {
		t.Fatalf("state=%+v, want diagnostic without ban", state)
	}
}

// TestDAPrefetchPeersPreferTriggerWithoutDroppingOthers pins the consumer of
// COMPETING_SCORE_V1: six real conflicts at 1440 take peer-b to 38 so its fresh set
// requests first from peer-a, 288 blocks later 40 restores the preference; a low
// score never removes a key, aliases and sessions on one host collapse to one key.
func TestDAPrefetchPeersPreferTriggerWithoutDroppingOthers(t *testing.T) {
	h := highTipHarness(t, 1440)
	h.service.cfg.EnableCompactReceive = true
	f := newDAIngressFixture(t, h)
	a := addDAPrefetchTestPeer(h.service, "peer-a", nil)
	b := addDAPrefetchTestPeer(h.service, "peer-b", nil)
	c := addDAPrefetchTestPeer(h.service, "peer-c", nil)
	disabled := testPeerForService(h.service, "peer-disabled", 0)
	disabled.state.Addr = "peer-disabled"
	h.service.peersMu.Lock()
	h.service.peers["peer-disabled"], h.service.peers["alias-of-b"] = disabled, b
	h.service.peersMu.Unlock()
	expect := func(label, trigger string, want []string) {
		t.Helper()
		_, keys := h.service.daPrefetchPeers(trigger)
		require(t, reflect.DeepEqual(keys, want), "%s: keys=%v, want %v", label, keys, want)
	}
	all, bFirst := []string{"peer-a", "peer-b", "peer-c"}, []string{"peer-b", "peer-a", "peer-c"}
	expect("a preferred trigger leads", "peer-b", bFirst)
	expect("an alias of the preferred trigger", "alias-of-b", bFirst)
	expect("an absent trigger", "peer-x", all)
	expect("a compact-disabled trigger", "peer-disabled", all)
	expect("no trigger", "", all)
	daID := daRelayTestID(0xb0)
	f.admit(f.commit(daID, 2), "127.0.0.9:19119") // the first-seen commit, retained without a scheduler entry
	competitor := f.commit(daID, 2)
	for i := 0; i < 6; i++ {
		must(t, b.handleTx(competitor), "competing commit")
	}
	score, anchor := peerQuality(b)
	require(t, score == 38 && anchor == 1440, "six conflicts: score=%d anchor=%d, want 38 at 1440", score, anchor)
	expect("score 38 loses the front and nothing else", "peer-b", all)
	wire := map[*peer][]byte{}
	demoted := daRelayTestID(0xb1)
	must(t, b.handleTx(f.commit(demoted, 15)), "a fresh set from the demoted peer")
	expectPrefetchRequests(t, h, wire, "demoted trigger", demoted, 15, a, b, c)
	b.stateMu.Lock()
	b.qualityScore = 39
	b.stateMu.Unlock()
	expect("score 39 loses the front", "peer-b", all)
	// A sole low-score peer is still the fallback, two sessions on one host are one key,
	// and a disabled compact receive leaves no eligible key.
	h.service.peersMu.Lock()
	delete(h.service.peers, "peer-a")
	delete(h.service.peers, "peer-c")
	h.service.peersMu.Unlock()
	expect("a sole low-score peer", "peer-b", []string{"peer-b"})
	sole := daRelayTestID(0xb3)
	must(t, b.handleTx(f.commit(sole, 2)), "a fresh set with the sole peer")
	expectPrefetchRequests(t, h, wire, "sole peer", sole, 2, b)
	addDAPrefetchTestPeer(h.service, "127.0.0.5:1", nil)
	addDAPrefetchTestPeer(h.service, "127.0.0.5:2", nil)
	expect("sessions sharing a quota key", "127.0.0.5:2", []string{"127.0.0.5", "peer-b"})
	h.service.cfg.EnableCompactReceive = false
	expect("compact receive disabled", "peer-b", []string{})
	// 288 blocks later: a synthetic tip move breaks the owner's tip coherence, so the tuple the
	// six conflicts produced (38 at 1440) is carried onto a harness at tip 1728, where b normalizes to 40.
	later := highTipHarness(t, 1728)
	later.service.cfg.EnableCompactReceive = true
	lf := newDAIngressFixture(t, later)
	la, lb, lc := addDAPrefetchTestPeer(later.service, "peer-a", nil), addDAPrefetchTestPeer(later.service, "peer-b", nil), addDAPrefetchTestPeer(later.service, "peer-c", nil)
	lb.stateMu.Lock()
	lb.qualityScore, lb.qualityHeight = 38, 1440
	lb.stateMu.Unlock()
	restored := daRelayTestID(0xb2)
	must(t, lb.handleTx(lf.commit(restored, 15)), "a fresh set from the restored peer")
	score, anchor = peerQuality(lb)
	require(t, score == 40 && anchor == 1728, "288 blocks later: score=%d anchor=%d, want 40 at 1728", score, anchor)
	expectPrefetchRequests(t, later, wire, "restored trigger", restored, 15, lb, la, lc)
}

// TestDAPrefetchPreferredConnectionOwnsQuotaKey pins the representative binding: sessions a
// and b share host 127.0.0.5 (one quota key), c is another host. After six real conflicts
// take b to 38, the preference helper called for a replaces the seeded wrong representative
// b with the exact a pointer, directly and through an alias of a (the seeding makes the
// assertion independent of map order), and a fresh set from a is requested through a, never
// b, while c keeps its ordinary round-robin share. The low-score, missing, disabled and
// empty trigger rows and the absent and empty key rows return "" without touching the map.
func TestDAPrefetchPreferredConnectionOwnsQuotaKey(t *testing.T) {
	h := highTipHarness(t, 1440)
	h.service.cfg.EnableCompactReceive = true
	f := newDAIngressFixture(t, h)
	a := addDAPrefetchTestPeer(h.service, "127.0.0.5:1", nil)
	b := addDAPrefetchTestPeer(h.service, "127.0.0.5:2", nil)
	c := addDAPrefetchTestPeer(h.service, "127.0.0.4:1", nil)
	blank := addDAPrefetchTestPeer(h.service, "blank", nil)
	blank.state.Addr = "" // an accepting session whose address yields no quota key
	disabled := testPeerForService(h.service, "peer-disabled", 0)
	disabled.state.Addr = "peer-disabled"
	h.service.peersMu.Lock()
	h.service.peers["peer-disabled"], h.service.peers["alias-of-a"] = disabled, a
	h.service.peersMu.Unlock()
	daID := daRelayTestID(0xc0)
	f.admit(f.commit(daID, 2), "127.0.0.9:19119")
	competitor := f.commit(daID, 2)
	for i := 0; i < 6; i++ {
		must(t, b.handleTx(competitor), "competing commit")
	}
	score, anchor := peerQuality(b)
	require(t, score == 38 && anchor == 1440, "six conflicts: score=%d anchor=%d, want 38 at 1440", score, anchor)
	shared, other := "127.0.0.5", "127.0.0.4"
	// prefer calls the production helper under peersMu.RLock on a seeded map and pins the
	// returned key plus the exact pointer per key (maps.Equal compares pointers with ==).
	prefer := func(label, trigger string, seed, want map[string]*peer, wantKey string) {
		t.Helper()
		h.service.peersMu.RLock()
		key := h.service.preferredDAPrefetchPeerKeyLocked(trigger, 1440, seed)
		h.service.peersMu.RUnlock()
		require(t, key == wantKey && maps.Equal(seed, want), "%s: key=%q shared=%s other=%s len=%d, want %q shared=%s other=%s len=%d", label, key, peerAddrOrNil(seed[shared]), peerAddrOrNil(seed[other]), len(seed), wantKey, peerAddrOrNil(want[shared]), peerAddrOrNil(want[other]), len(want))
	}
	prefer("the preferred session replaces the forced wrong representative", a.addr(), map[string]*peer{shared: b, other: c}, map[string]*peer{shared: a, other: c}, shared)
	prefer("an alias of the preferred session binds the same pointer", "alias-of-a", map[string]*peer{shared: b, other: c}, map[string]*peer{shared: a, other: c}, shared)
	prefer("a low-score trigger neither replaces nor leads", b.addr(), map[string]*peer{shared: a, other: c}, map[string]*peer{shared: a, other: c}, "")
	prefer("a missing trigger", "peer-x", map[string]*peer{shared: b, other: c}, map[string]*peer{shared: b, other: c}, "")
	prefer("a compact-disabled trigger", "peer-disabled", map[string]*peer{shared: b, other: c}, map[string]*peer{shared: b, other: c}, "")
	prefer("an empty trigger", "", map[string]*peer{shared: b, other: c}, map[string]*peer{shared: b, other: c}, "")
	prefer("a trigger whose key is absent from the map", a.addr(), map[string]*peer{other: c}, map[string]*peer{other: c}, "")
	prefer("a trigger with an empty key", "blank", map[string]*peer{"": b, shared: b, other: c}, map[string]*peer{"": b, shared: b, other: c}, "")
	peers, keys := h.service.daPrefetchPeers(b.addr())
	require(t, reflect.DeepEqual(keys, []string{other, shared}) && len(peers) == 2, "low-score b stays an ordinary fallback: keys=%v peers=%d", keys, len(peers))
	peers, keys = h.service.daPrefetchPeers("alias-of-a")
	require(t, reflect.DeepEqual(keys, []string{shared, other}) && len(peers) == 2 && peers[shared] == a && peers[other] == c, "alias of a: keys=%v shared=%s, want one key per host led by %s bound to %s", keys, peerAddrOrNil(peers[shared]), shared, a.addr())
	// The real path: a's fresh set is planned round-robin over the two host keys within the
	// per-key budget (7 chunks each) and the shared key's frames reach a, none reach b.
	fresh := daRelayTestID(0xc1)
	must(t, a.handleTx(f.commit(fresh, 14)), "a fresh set from the preferred session")
	expectPrefetchRequests(t, h, map[*peer][]byte{}, "preferred session", fresh, 14, a, c)
	require(t, len(b.conn.(*scriptedConn).Bytes()) == 0, "b received %d bytes, want no getdachunk frame on the demoted session", len(b.conn.(*scriptedConn).Bytes()))
}

func peerAddrOrNil(current *peer) string {
	if current == nil {
		return "<nil>"
	}
	return current.addr()
}

// expectPrefetchRequests pins the round-robin split of count missing chunks (within the
// per-peer per-second budget) in peer order, decoded and as exact connection bytes; wire
// accumulates the exact frame bytes each scripted peer socket must carry so far.
func expectPrefetchRequests(t *testing.T, h *testHarness, wire map[*peer][]byte, label string, daID [32]byte, count uint16, order ...*peer) {
	t.Helper()
	for position, current := range order {
		indexes := []uint16{}
		for index := uint16(position); index < count; index += uint16(len(order)) {
			indexes = append(indexes, index)
		}
		payload, err := encodeDAPrefetchPlanPayload(node.DARelayPrefetchPlan{DAID: daID, Indexes: indexes})
		must(t, err, "encodeDAPrefetchPlanPayload")
		wire[current] = append(wire[current], mustPeerRuntimeFrameBytes(t, current, message{Command: messageGetDAChunk, Payload: payload})...)
		requests := readScriptedFrames(t, h, current)
		require(t, len(requests) > 0, "%s: %s received no getdachunk frame", label, current.addr())
		last := requests[len(requests)-1]
		require(t, last.DAID == daID && reflect.DeepEqual(last.Indexes, indexes) && bytes.Equal(current.conn.(*scriptedConn).Bytes(), wire[current]), "%s: %s request=%+v, want %x indexes %v with the exact frame bytes", label, current.addr(), last, daID, indexes)
	}
}

func daRelayTestID(seed byte) (out [32]byte) {
	out[0] = seed
	return out
}

func addDAPrefetchTestPeer(svc *Service, addr string, writeErr error) *peer {
	current := testPeerForService(svc, addr, 0)
	current.state.Addr = addr
	current.conn = &scriptedConn{writeErr: writeErr}
	current.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	svc.peersMu.Lock()
	svc.peers[addr] = current
	svc.peersMu.Unlock()
	return current
}
