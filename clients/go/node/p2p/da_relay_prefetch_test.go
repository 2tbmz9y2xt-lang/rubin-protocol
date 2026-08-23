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
	daID := daRelayTestID(130)
	if err := h.service.daRelay.StageCommit("", node.DARelayCommit{
		DAID:       daID,
		ChunkCount: uint16(consensus.MAX_DA_CHUNK_COUNT),
		WireBytes:  1,
	}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
	keys := []string{"peer-a", "peer-b", "peer-c", "peer-d", "peer-e", "peer-f", "peer-g", "peer-h", "peer-i"}
	now := time.Unix(1000, 0)
	for seed := byte(131); seed < 139; seed++ {
		id := daRelayTestID(seed)
		if err := h.service.daRelay.StageCommit("", node.DARelayCommit{DAID: id, ChunkCount: 1, WireBytes: 1}); err != nil {
			t.Fatalf("StageCommit(%d): %v", seed, err)
		}
		if empty, diagnostic := h.service.daRelay.PlanPrefetch(id, nil, now); len(empty) != 0 || diagnostic != "" {
			t.Fatalf("empty plans=%+v diagnostic=%q", empty, diagnostic)
		}
	}
	plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, keys, now)
	total, unique, maxPeerBytes := summarizeDAPrefetchPlans(plans)
	if diagnostic != "" || total != int(consensus.MAX_DA_CHUNK_COUNT) || unique != total || maxPeerBytes > 4_000_000 {
		t.Fatalf("diagnostic=%q total=%d unique=%d max_peer_bytes=%d", diagnostic, total, unique, maxPeerBytes)
	}
	if duplicate, diagnostic := h.service.daRelay.PlanPrefetch(daID, keys, now); len(duplicate) != 0 || diagnostic != "" {
		t.Fatalf("duplicate plans=%d diagnostic=%q", len(duplicate), diagnostic)
	}
	if retry, diagnostic := h.service.daRelay.PlanPrefetch(daID, keys, now.Add(time.Second+time.Nanosecond)); len(retry) != len(plans) || diagnostic != "" {
		t.Fatalf("expired plans=%d diagnostic=%q, want %d", len(retry), diagnostic, len(plans))
	}
}

func TestDAPrefetchTracksCurrentMissingIndexesAndCompletion(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	daID := daRelayTestID(140)
	first, second := []byte{1}, []byte{2}
	if err := h.service.daRelay.StageCommit("", node.DARelayCommit{DAID: daID, PayloadCommitment: sha3.Sum256(append(first, second...)), ChunkCount: 2, WireBytes: 1}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
	now := time.Unix(1000, 0)
	plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, now)
	if len(plans) != 1 || diagnostic != "" || !reflect.DeepEqual(plans[0].Indexes, []uint16{0, 1}) {
		t.Fatalf("initial plans=%+v diagnostic=%q", plans, diagnostic)
	}
	if err := h.service.daRelay.StageChunk("", node.DARelayChunk{DAID: daID, ChunkIndex: 0, Payload: first, WireBytes: 1, HashChecked: true}); err != nil {
		t.Fatalf("StageChunk(0): %v", err)
	}
	if retry, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, now); len(retry) != 0 || diagnostic != "" {
		t.Fatalf("fulfilled-index retry=%+v diagnostic=%q", retry, diagnostic)
	}
	h.service.daRelay.ReleasePrefetchPlan(node.DARelayPrefetchPlan{DAID: daID, PeerKey: plans[0].PeerKey, Indexes: []uint16{1}})
	reserveDAPrefetchSlots(t, h.service, 142)
}

func TestDAPrefetchCompletionReleasesReservations(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	daID, payload := daRelayTestID(150), []byte{1}
	commit := node.DARelayCommit{DAID: daID, PayloadCommitment: sha3.Sum256(payload), ChunkCount: 1, WireBytes: 1}
	if err := h.service.daRelay.StageCommit("", commit); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
	if plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, time.Unix(1000, 0)); len(plans) != 1 || diagnostic != "" {
		t.Fatalf("plans=%+v diagnostic=%q", plans, diagnostic)
	}
	if err := h.service.daRelay.StageChunk("", node.DARelayChunk{DAID: daID, Payload: payload, WireBytes: 1, HashChecked: true}); err != nil {
		t.Fatalf("StageChunk: %v", err)
	}
	if plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer-a"}, time.Unix(1000, 0)); len(plans) != 0 || diagnostic != "" {
		t.Fatalf("complete plans=%+v diagnostic=%q", plans, diagnostic)
	}
	reserveDAPrefetchSlots(t, h.service, 160)
}

func TestDAPrefetchSendWritesGetDAChunkFrame(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.EnableCompactReceive = true
	current := addDAPrefetchTestPeer(h.service, "peer-a", nil)
	daID := daRelayTestID(141)
	if err := h.service.daRelay.StageCommit("", node.DARelayCommit{DAID: daID, ChunkCount: 2, WireBytes: 1}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
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
	daID := daRelayTestID(132)
	if err := h.service.daRelay.StageCommit("", node.DARelayCommit{DAID: daID, ChunkCount: 2, WireBytes: 1}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
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
	daID := daRelayTestID(135)
	if err := h.service.daRelay.StageCommit("", node.DARelayCommit{DAID: daID, ChunkCount: 1, WireBytes: 1}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
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
	daID := daRelayTestID(134)
	if err := h.service.daRelay.StageCommit("peer-a", node.DARelayCommit{DAID: daID, ChunkCount: 2, WireBytes: 1}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
	err := h.service.finishDAPrefetch("peer-a", daID, node.ErrDARelayPayloadCommitmentMismatch)
	if !errors.Is(err, node.ErrDARelayPayloadCommitmentMismatch) {
		t.Fatalf("finish err=%v, want payload mismatch", err)
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

func reserveDAPrefetchSlots(t *testing.T, svc *Service, seed byte) {
	for i := byte(0); i < 8; i++ {
		id := daRelayTestID(seed + i)
		if err := svc.daRelay.StageCommit("", node.DARelayCommit{DAID: id, ChunkCount: 1, WireBytes: 1}); err != nil {
			t.Fatalf("StageCommit(%d): %v", i, err)
		}
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
