package p2p

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestDAPrefetchPlansAreBoundedDeduplicatedAndReleasable(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 16)
	daID := daRelayTestID(130)
	// The largest chunk count the DECLARED-BUDGET policy admits. A commit above
	// it is refused by DA admission itself, so the bound this row exercises is the
	// prefetch planner's, not the policy's.
	chunkCount := uint16(node.DefaultMinerConfig().PolicyMaxDaBytesPerBlock / consensus.CHUNK_BYTES)
	f.retainCommit(t, daID, chunkCount, "127.0.0.1:19130")
	keys := []string{"peer-a", "peer-b", "peer-c", "peer-d", "peer-e", "peer-f", "peer-g", "peer-h", "peer-i"}
	now := time.Unix(1000, 0)
	for seed := byte(131); seed < 139; seed++ {
		id := daRelayTestID(seed)
		f.retainCommit(t, id, 1, "127.0.0.1:19130")
		if empty, diagnostic := h.service.daRelay.PlanPrefetch(id, nil, now); len(empty) != 0 || diagnostic != "" {
			t.Fatalf("empty plans=%+v diagnostic=%q", empty, diagnostic)
		}
	}
	plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, keys, now)
	total, unique, maxPeerBytes := summarizeDAPrefetchPlans(plans)
	if diagnostic != "" || total != int(chunkCount) || unique != total || maxPeerBytes > 4_000_000 {
		t.Fatalf("diagnostic=%q total=%d unique=%d max_peer_bytes=%d", diagnostic, total, unique, maxPeerBytes)
	}
	if duplicate, diagnostic := h.service.daRelay.PlanPrefetch(daID, keys, now); len(duplicate) != 0 || diagnostic != "" {
		t.Fatalf("duplicate plans=%d diagnostic=%q", len(duplicate), diagnostic)
	}
	if retry, diagnostic := h.service.daRelay.PlanPrefetch(daID, keys, now.Add(time.Second+time.Nanosecond)); len(retry) != len(plans) || diagnostic != "" {
		t.Fatalf("expired plans=%d diagnostic=%q, want %d", len(retry), diagnostic, len(plans))
	}
}

// TestDAPrefetchPerPeerByteCapIsReachable drives the production planner into
// the per-peer byte cap with a REACHABLE fixture: one peer, and a retained
// commit declaring more chunks than one peer's per-second byte budget covers
// (per-peer cap 4,000,000 admits exactly 7 CHUNK_BYTES reservations). The
// planner reserves exactly that budget and reports the per-peer diagnostic for
// the remainder, so the cap branch is executed rather than argued from bounds.
func TestDAPrefetchPerPeerByteCapIsReachable(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 2)
	daID := daRelayTestID(136)
	perPeerChunks := int(4_000_000 / consensus.CHUNK_BYTES)
	declared := uint16(perPeerChunks + 1)
	f.retainCommit(t, daID, declared, "127.0.0.1:19136")
	plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"only-peer"}, time.Unix(1000, 0))
	if diagnostic != "da prefetch per-peer byte cap exceeded" {
		t.Fatalf("diagnostic=%q, want the per-peer byte cap", diagnostic)
	}
	if len(plans) != 1 || plans[0].PeerKey != "only-peer" || len(plans[0].Indexes) != perPeerChunks {
		t.Fatalf("plans=%+v, want one plan holding exactly the %d-chunk per-peer budget", plans, perPeerChunks)
	}
}

func TestDAPrefetchTracksCurrentMissingIndexesAndCompletion(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 16)
	daID := daRelayTestID(140)
	first, second := []byte{1}, []byte{2}
	f.admit(t, f.commitTx(t, daID, 2, sha3.Sum256(append(append([]byte(nil), first...), second...))), "127.0.0.1:19140")
	now := time.Unix(1000, 0)
	plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, now)
	if len(plans) != 1 || diagnostic != "" || !reflect.DeepEqual(plans[0].Indexes, []uint16{0, 1}) {
		t.Fatalf("initial plans=%+v diagnostic=%q", plans, diagnostic)
	}
	f.admit(t, f.chunkTx(t, daID, 0, first), "127.0.0.1:19140")
	if retry, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, now); len(retry) != 0 || diagnostic != "" {
		t.Fatalf("fulfilled-index retry=%+v diagnostic=%q", retry, diagnostic)
	}
	h.service.daRelay.ReleasePrefetchPlan(node.DARelayPrefetchPlan{DAID: daID, PeerKey: plans[0].PeerKey, Indexes: []uint16{1}})
	reserveDAPrefetchSlots(t, f, 142)
}

func TestDAPrefetchCompletionReleasesReservations(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 16)
	daID, payload := daRelayTestID(150), []byte{1}
	f.admit(t, f.commitTx(t, daID, 1, sha3.Sum256(payload)), "127.0.0.1:19150")
	if plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, time.Unix(1000, 0)); len(plans) != 1 || diagnostic != "" {
		t.Fatalf("plans=%+v diagnostic=%q", plans, diagnostic)
	}
	f.admit(t, f.chunkTx(t, daID, 0, payload), "127.0.0.1:19150")
	if plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, time.Unix(1000, 0)); len(plans) != 0 || diagnostic != "" {
		t.Fatalf("complete plans=%+v diagnostic=%q", plans, diagnostic)
	}
	reserveDAPrefetchSlots(t, f, 160)
}

func TestDAPrefetchSendWritesGetDAChunkFrame(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.EnableCompactReceive = true
	current := addDAPrefetchTestPeer(h.service, "peer-a", nil)
	f := newDAIngressFixture(t, h, 2)
	daID := daRelayTestID(141)
	f.retainCommit(t, daID, 2, "peer-a")
	h.service.scheduleDAPrefetch("peer-a", daID)
	frame, err := readFrame(bytes.NewReader(current.conn.(*scriptedConn).Bytes()), networkMagic(h.service.cfg.PeerRuntimeConfig.Network), h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	request, err := decodeGetDAChunkPayload(frame.Payload)
	if err != nil || frame.Command != messageGetDAChunk || request.DAID != daID || !reflect.DeepEqual(request.Indexes, []uint16{0, 1}) {
		t.Fatalf("frame=%+v request=%+v err=%v", frame, request, err)
	}
}

func TestDAPrefetchSendFailureReleasesPlan(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.EnableCompactReceive = true
	current := addDAPrefetchTestPeer(h.service, "peer-a", errors.New("write failed"))
	f := newDAIngressFixture(t, h, 2)
	daID := daRelayTestID(132)
	f.retainCommit(t, daID, 2, "peer-a")
	h.service.scheduleDAPrefetch("peer-a", daID)
	if current.snapshotState().BanScore != 0 || current.snapshotState().LastError == "" {
		t.Fatalf("state=%+v, want diagnostic without ban", current.snapshotState())
	}
	if retry, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, h.service.cfg.Now()); len(retry) != 1 || len(retry[0].Indexes) != 2 || diagnostic != "" {
		t.Fatalf("released retry plans=%+v diagnostic=%q, want one plan with two indexes", retry, diagnostic)
	}
}

func TestDAPrefetchMissingPeerReleasesPlan(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 2)
	daID := daRelayTestID(135)
	f.retainCommit(t, daID, 1, "peer-a")
	plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, time.Unix(1000, 0))
	if len(plans) != 1 || diagnostic != "" {
		t.Fatalf("plans=%d diagnostic=%q, want one", len(plans), diagnostic)
	}
	h.service.sendDAPrefetchPlan(map[string]*peer{}, plans[0])
	if retry, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, time.Unix(1000, 0)); len(retry) != 1 || diagnostic != "" {
		t.Fatalf("released retry=%d diagnostic=%q", len(retry), diagnostic)
	}
}

func TestDAPrefetchPayloadMismatchSchedulesSnapshot(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.EnableCompactReceive = true
	current := addDAPrefetchTestPeer(h.service, "peer-a", nil)
	f := newDAIngressFixture(t, h, 4)
	daID := daRelayTestID(134)
	// chunk_count 1, so the mismatching chunk COMPLETES the set by shape and the
	// aggregate payload commitment is actually compared.
	f.retainCommit(t, daID, 1, "peer-a")
	// A chunk-last payload-commitment mismatch retains nothing and reschedules
	// the set's still-missing chunks, without a peer consequence.
	mismatch := f.chunkTx(t, daID, 0, []byte("not-the-committed-payload"))
	if _, err := h.service.admitRelayDATx("peer-a", mismatch, mustParseDATxForTest(t, mismatch), mustPeerDAProvenance(t, "peer-a")); err == nil {
		t.Fatal("a chunk-last mismatch was admitted")
	}
	if plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, h.service.cfg.Now()); len(plans) != 0 || diagnostic != "" || current.snapshotState().BanScore != 0 {
		t.Fatalf("plans=%d diagnostic=%q state=%+v", len(plans), diagnostic, current.snapshotState())
	}
}

func TestDAPrefetchReportsDiagnostic(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	current := addDAPrefetchTestPeer(h.service, "peer-a", nil)
	reportDAPrefetchDiagnostic(map[string]*peer{"peer-a": current}, []string{"peer-a"}, "diagnostic")
	if state := current.snapshotState(); state.LastError != "diagnostic" || state.BanScore != 0 {
		t.Fatalf("state=%+v, want diagnostic without ban", state)
	}
}

func TestDAPrefetchPeersPreferTriggerWithoutDroppingOthers(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.EnableCompactReceive = true
	addDAPrefetchTestPeer(h.service, "peer-a", nil)
	addDAPrefetchTestPeer(h.service, "peer-b", nil)
	addDAPrefetchTestPeer(h.service, "peer-c", nil)
	disabled := testPeerForService(h.service, "peer-disabled", 0)
	disabled.state.Addr = "peer-disabled"
	h.service.peersMu.Lock()
	h.service.peers["peer-disabled"] = disabled
	h.service.peersMu.Unlock()
	_, keys := h.service.daPrefetchPeers("peer-b")
	if want := []string{"peer-b", "peer-a", "peer-c"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys=%v, want %v", keys, want)
	}
}

func daRelayTestID(seed byte) (out [32]byte) {
	out[0] = seed
	return out
}

func summarizeDAPrefetchPlans(plans []node.DARelayPrefetchPlan) (int, int, uint64) {
	seen := map[uint16]bool{}
	var total int
	var maxPeerBytes uint64
	for _, plan := range plans {
		total += len(plan.Indexes)
		for _, index := range plan.Indexes {
			seen[index] = true
		}
		if bytes := uint64(len(plan.Indexes)) * consensus.CHUNK_BYTES; bytes > maxPeerBytes {
			maxPeerBytes = bytes
		}
	}
	return total, len(seen), maxPeerBytes
}

func reserveDAPrefetchSlots(t *testing.T, f *daIngressFixture, seed byte) {
	svc := f.h.service
	for i := byte(0); i < 8; i++ {
		id := daRelayTestID(seed + i)
		f.retainCommit(t, id, 1, fmt.Sprintf("127.0.0.1:191%02d", i))
		if plans, diagnostic := svc.daRelay.PlanPrefetch(id, []string{fmt.Sprintf("peer-%d", i)}, time.Unix(1000, 0)); len(plans) != 1 || diagnostic != "" {
			t.Fatalf("plans(%d)=%+v diagnostic=%q", i, plans, diagnostic)
		}
	}
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
