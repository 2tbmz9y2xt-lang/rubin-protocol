package p2p

import (
	"errors"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestDAPrefetchPlansBoundedDedupTimeoutAndComplete(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(130)
	record := mustAddDACommit(t, state, "", daRelayTestCommit(daID, uint16(consensus.MAX_DA_CHUNK_COUNT), 1))
	keys := []string{"peer-a", "peer-b", "peer-c", "peer-d", "peer-e", "peer-f", "peer-g", "peer-h", "peer-i"}
	now := time.Unix(1000, 0)
	total := requireBoundedDAPrefetchPlan(t, state, record, keys, now)
	requireNoDuplicateDAPrefetch(t, state, record, keys, now)
	requireNoEmptyDAPrefetchReservations(t, state, keys, now)
	requireDAPrefetchRetryAfterTTL(t, state, record, keys, now, total)
	requireDAPrefetchCompleteCleanup(t, state, record, keys, now)
}

func TestDAPrefetchSendFailureReleasesSlotWithoutBan(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.EnableCompactReceive = true
	current := addDAPrefetchTestPeer(h.service, "peer-a", errors.New("write failed"))
	record := mustAddDACommit(t, h.service.daRelay, "", daRelayTestCommit(daRelayTestID(132), 2, 1))
	h.service.scheduleDAPrefetch("peer-a", record)
	state := current.snapshotState()
	if len(h.service.daRelay.prefetch.indexes) != 0 || state.BanScore != 0 || state.LastError == "" {
		t.Fatalf("inflight=%d state=%+v, want released diagnostic without ban", len(h.service.daRelay.prefetch.indexes), state)
	}
}

func summarizeDAPrefetchPlans(plans []daRelayPrefetchPlan) (int, int, uint64) {
	seen := map[uint16]bool{}
	var total int
	var maxPeerBytes uint64
	for _, plan := range plans {
		total += len(plan.indexes)
		for _, index := range plan.indexes {
			seen[index] = true
		}
		if bytes := uint64(len(plan.indexes)) * consensus.CHUNK_BYTES; bytes > maxPeerBytes {
			maxPeerBytes = bytes
		}
	}
	return total, len(seen), maxPeerBytes
}

func requireBoundedDAPrefetchPlan(t *testing.T, state *daRelayState, record daRelaySetRecord, keys []string, now time.Time) int {
	t.Helper()
	plans, diagnostic := state.planDAPrefetch(record, keys, now)
	total, unique, maxPeerBytes := summarizeDAPrefetchPlans(plans)
	if diagnostic != "" || total != int(consensus.MAX_DA_CHUNK_COUNT) || unique != total || maxPeerBytes > daPrefetchPerPeerBytesPerSecond {
		t.Fatalf("diagnostic=%q total=%d unique=%d maxPeerBytes=%d", diagnostic, total, unique, maxPeerBytes)
	}
	return total
}

func requireNoDuplicateDAPrefetch(t *testing.T, state *daRelayState, record daRelaySetRecord, keys []string, now time.Time) {
	t.Helper()
	plans, diagnostic := state.planDAPrefetch(record, keys, now)
	if len(plans) != 0 || diagnostic != "" {
		t.Fatalf("duplicate trigger plans=%d diagnostic=%q, want no duplicate", len(plans), diagnostic)
	}
}

func requireNoEmptyDAPrefetchReservations(t *testing.T, state *daRelayState, keys []string, now time.Time) {
	t.Helper()
	for i := 0; i < daPrefetchMaxConcurrentSets-1; i++ {
		blocked := mustAddDACommit(t, state, "", daRelayTestCommit(daRelayTestID(byte(131+i)), 1, 1))
		plans, diagnostic := state.planDAPrefetch(blocked, keys, now)
		if len(plans) != 0 || diagnostic != "da prefetch global byte cap exceeded" {
			t.Fatalf("blocked plans=%d diagnostic=%q, want byte-cap diagnostic", len(plans), diagnostic)
		}
	}
	if got := len(state.prefetch.indexes); got != 1 {
		t.Fatalf("prefetch reservations=%d, want only active set", got)
	}
}

func requireDAPrefetchRetryAfterTTL(t *testing.T, state *daRelayState, record daRelaySetRecord, keys []string, now time.Time, wantTotal int) {
	t.Helper()
	plans, diagnostic := state.planDAPrefetch(record, keys, now.Add(daPrefetchRequestTTL+time.Nanosecond))
	if retryTotal, _, _ := summarizeDAPrefetchPlans(plans); diagnostic != "" || retryTotal != wantTotal {
		t.Fatalf("retry total=%d diagnostic=%q, want %d", retryTotal, diagnostic, wantTotal)
	}
}

func requireDAPrefetchCompleteCleanup(t *testing.T, state *daRelayState, record daRelaySetRecord, keys []string, now time.Time) {
	t.Helper()
	record.state = daRelayStateCompleteSet
	plans, diagnostic := state.planDAPrefetch(record, keys, now)
	if len(plans) != 0 || diagnostic != "" || len(state.prefetch.indexes) != 0 {
		t.Fatalf("complete cleanup plans=%d diagnostic=%q inflight=%d", len(plans), diagnostic, len(state.prefetch.indexes))
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
