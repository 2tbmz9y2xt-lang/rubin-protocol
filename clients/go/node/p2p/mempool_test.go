package p2p

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// TestCanonicalMempoolTxPoolPendingOutpointOwner proves the relay adapter hands
// back the POINTER-IDENTICAL owner of the mempool it adapts, so a relay-side
// consumer binds to the one authority instead of starting a second, and that
// the accessor stays off the generic TxPool interface.
func TestCanonicalMempoolTxPoolPendingOutpointOwner(t *testing.T) {
	mempool, err := node.NewMempool(node.NewChainState(), nil, [32]byte{})
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	owner := mempool.PendingOutpointOwner()
	if owner == nil {
		t.Fatal("mempool has no owner")
	}
	if got := NewCanonicalMempoolTxPool(mempool).PendingOutpointOwner(); got != owner {
		t.Fatalf("adapter owner=%p, want the pointer-identical mempool owner %p", got, owner)
	}

	var nilAdapter *CanonicalMempoolTxPool
	if got := nilAdapter.PendingOutpointOwner(); got != nil {
		t.Fatalf("nil adapter owner=%p, want nil", got)
	}
	if got := NewCanonicalMempoolTxPool(nil).PendingOutpointOwner(); got != nil {
		t.Fatalf("nil-backed adapter owner=%p, want nil", got)
	}

	// Widening the generic TxPool interface with the accessor would force every
	// implementation to carry it. MemoryTxPool must not.
	var generic TxPool = NewMemoryTxPool()
	if _, widened := generic.(interface {
		PendingOutpointOwner() *node.PendingOutpointOwner
	}); widened {
		t.Fatal("the generic TxPool surface was widened with the owner accessor")
	}
}

// TestCanonicalMempoolTxPoolRetainedTxByID proves the adapter surface: nil
// adapter, nil-backed adapter, and a live miss all return the zero snapshot
// and false; a healthy canonically-admitted hit carries the producer's own
// identities and the owner's defensive copy survives caller mutation; the
// generic TxPool interface stays non-widened. Package p2p cannot construct a
// corrupted owner row (node internals are unexported with no product
// mutation hook), so owner-row corruption forwarding (R3-R7) is pinned by
// the owner-side tests in package node, not through this adapter.
func TestCanonicalMempoolTxPoolRetainedTxByID(t *testing.T) {
	chainState := node.NewChainState()
	raw, txid, utxos := signedCanonicalP2PTxWithoutSeeding(t, 1)
	for op, entry := range utxos {
		chainState.Utxos[op] = entry
	}
	mempool, err := node.NewMempool(chainState, nil, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	adapter := NewCanonicalMempoolTxPool(mempool)

	var nilAdapter *CanonicalMempoolTxPool
	for name, pool := range map[string]*CanonicalMempoolTxPool{
		"nil adapter":               nilAdapter,
		"nil-backed adapter":        NewCanonicalMempoolTxPool(nil),
		"live adapter, absent txid": adapter,
	} {
		got, ok := pool.RetainedTxByID(txid)
		if ok || got.IndexedTxID != ([32]byte{}) || got.AdmissionWTxID != ([32]byte{}) || got.Raw != nil {
			t.Fatalf("%s=(%x,%x,%x,%v), want the zero snapshot and false", name, got.IndexedTxID, got.AdmissionWTxID, got.Raw, ok)
		}
	}

	admitted := adapter.AddRemoteTxForRelay(txid, raw, nil)
	if admitted.Disposition != node.RelayAdmissionRetained {
		t.Fatalf("disposition=%v, want RETAINED (err=%v)", admitted.Disposition, admitted.Err)
	}
	got, ok := adapter.RetainedTxByID(txid)
	if !ok || got.IndexedTxID != admitted.TxID || got.AdmissionWTxID != admitted.WTxID || !bytes.Equal(got.Raw, raw) {
		t.Fatalf("snapshot=(%x,%x,%x,%v), want the producer's (%x,%x) and the exact retained bytes", got.IndexedTxID, got.AdmissionWTxID, got.Raw, ok, admitted.TxID, admitted.WTxID)
	}
	got.Raw[0] ^= 0xFF
	again, _ := adapter.RetainedTxByID(txid)
	if !bytes.Equal(again.Raw, raw) {
		t.Fatal("the adapter forwarded a mutable alias of the retained bytes")
	}

	// Widening the generic TxPool interface would force every implementation to
	// carry the retained accessor. MemoryTxPool must not.
	var generic TxPool = NewMemoryTxPool()
	if _, widened := generic.(interface {
		RetainedTxByID([32]byte) (node.RetainedTxSnapshot, bool)
	}); widened {
		t.Fatal("the generic TxPool surface was widened with the retained snapshot accessor")
	}
}

func TestMemoryTxPool_PutAndGet(t *testing.T) {
	pool := NewMemoryTxPool()
	var txid1 [32]byte
	txid1[0] = 0x01
	raw := []byte{0xAA, 0xBB}

	if !pool.Put(txid1, raw, consensus.Uint128FromU64(5), len(raw)) {
		t.Fatal("first Put should return true (new)")
	}
	if pool.Put(txid1, raw, consensus.Uint128FromU64(5), len(raw)) {
		t.Fatal("second Put should return false (overwrite)")
	}

	got, ok := pool.Get(txid1)
	if !ok {
		t.Fatal("Get should return true for existing txid")
	}
	if len(got) != 2 || got[0] != 0xAA || got[1] != 0xBB {
		t.Fatalf("unexpected data: %x", got)
	}
	// Verify defensive copy: modifying returned slice doesn't alter pool
	got[0] = 0xFF
	got2, _ := pool.Get(txid1)
	if got2[0] != 0xAA {
		t.Fatal("Get must return a defensive copy")
	}
}

func TestMemoryTxPool_Has(t *testing.T) {
	pool := NewMemoryTxPool()
	var txid1, txid2 [32]byte
	txid1[0] = 0x01
	txid2[0] = 0x02

	pool.Put(txid1, []byte{0x01}, consensus.Uint128FromU64(1), 1)

	if !pool.Has(txid1) {
		t.Fatal("Has should return true for known txid")
	}
	if pool.Has(txid2) {
		t.Fatal("Has should return false for unknown txid")
	}
}

func TestMemoryTxPool_GetMissing(t *testing.T) {
	pool := NewMemoryTxPool()
	var txid [32]byte
	txid[0] = 0x99

	raw, ok := pool.Get(txid)
	if ok {
		t.Fatal("Get should return false for missing txid")
	}
	if raw != nil {
		t.Fatal("raw should be nil for missing txid")
	}
}

func TestMemoryTxPool_NilReceiver(t *testing.T) {
	var pool *MemoryTxPool

	if pool.Put([32]byte{}, []byte{0x01}, consensus.Uint128FromU64(1), 1) {
		t.Fatal("nil pool Put should return false")
	}
	if pool.Has([32]byte{}) {
		t.Fatal("nil pool Has should return false")
	}
	raw, ok := pool.Get([32]byte{})
	if ok || raw != nil {
		t.Fatal("nil pool Get should return nil, false")
	}
}

func TestCanonicalMempoolTxPoolNilSafe(t *testing.T) {
	var nilPool *CanonicalMempoolTxPool
	var txid [32]byte
	if raw, ok := nilPool.Get(txid); ok || raw != nil {
		t.Fatalf("nil adapter Get=(%x,%v), want nil,false", raw, ok)
	}
	if nilPool.Has(txid) {
		t.Fatal("nil adapter Has should return false")
	}
	if nilPool.Put(txid, []byte{0x01}, consensus.Uint128FromU64(1), 1) {
		t.Fatal("nil adapter Put should return false")
	}

	emptyAdapter := NewCanonicalMempoolTxPool(nil)
	if raw, ok := emptyAdapter.Get(txid); ok || raw != nil {
		t.Fatalf("nil-backed adapter Get=(%x,%v), want nil,false", raw, ok)
	}
	if emptyAdapter.Has(txid) {
		t.Fatal("nil-backed adapter Has should return false")
	}
	if emptyAdapter.Put(txid, []byte{0x01}, consensus.Uint128FromU64(1), 1) {
		t.Fatal("nil-backed adapter Put should return false")
	}
}

func TestMemoryTxPool_ConcurrentSafe(t *testing.T) {
	pool := NewMemoryTxPool()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var txid [32]byte
			txid[0] = byte(idx)
			pool.Put(txid, []byte{byte(idx)}, consensus.Uint128FromU64(uint64(idx+1)), 1)
			pool.Has(txid)
			pool.Get(txid)
		}(i)
	}
	wg.Wait()
}

func TestMemoryTxPoolEvictsWorstFeeRate(t *testing.T) {
	pool := NewMemoryTxPoolWithLimit(2)
	var low [32]byte
	low[0] = 0x10
	var mid [32]byte
	mid[0] = 0x20
	var high [32]byte
	high[0] = 0x30

	if !pool.Put(low, []byte{0x01}, consensus.Uint128FromU64(1), 4) {
		t.Fatal("low Put should succeed")
	}
	if !pool.Put(mid, []byte{0x02}, consensus.Uint128FromU64(2), 4) {
		t.Fatal("mid Put should succeed")
	}
	if !pool.Put(high, []byte{0x03}, consensus.Uint128FromU64(9), 4) {
		t.Fatal("high Put should evict the lowest feerate entry")
	}
	if pool.Has(low) {
		t.Fatal("lowest feerate tx should be evicted")
	}
	if !pool.Has(mid) || !pool.Has(high) {
		t.Fatal("higher priority entries should remain")
	}
}

func TestMemoryTxPoolRejectsWorseCandidateWhenFull(t *testing.T) {
	pool := NewMemoryTxPoolWithLimit(2)
	var a [32]byte
	a[0] = 0x01
	var b [32]byte
	b[0] = 0x02
	var candidate [32]byte
	candidate[0] = 0x03

	if !pool.Put(a, []byte{0x01}, consensus.Uint128FromU64(10), 2) {
		t.Fatal("first Put should succeed")
	}
	if !pool.Put(b, []byte{0x02}, consensus.Uint128FromU64(8), 2) {
		t.Fatal("second Put should succeed")
	}
	if pool.Put(candidate, []byte{0x03}, consensus.Uint128FromU64(1), 4) {
		t.Fatal("worse feerate candidate should be rejected")
	}
	if !pool.Has(a) || !pool.Has(b) {
		t.Fatal("existing entries should remain after rejecting worse candidate")
	}
}

// RUB-1127: relay metadata and relay-pool ordering carry the exact u128 fee.
// The two entries straddle u64 at equal size, so a fee narrowed to its low
// limb turns 2^64 into 0 and inverts both the eviction and the rejection.
func TestMemoryTxPoolOrdersAboveU64FeesExactly(t *testing.T) {
	aboveU64 := consensus.Uint128{Hi: 1}             // exactly 2^64
	belowU64 := consensus.Uint128FromU64(^uint64(0)) // 2^64-1

	pool := NewMemoryTxPoolWithLimit(1)
	var resident [32]byte
	resident[0] = 0x61
	var wide [32]byte
	wide[0] = 0x62

	if !pool.Put(resident, []byte{0x01}, belowU64, 4) {
		t.Fatal("first Put should succeed")
	}
	if !pool.Put(wide, []byte{0x02}, aboveU64, 4) {
		t.Fatal("above-u64 fee should evict the 2^64-1 entry at equal size")
	}
	if pool.Has(resident) || !pool.Has(wide) {
		t.Fatal("pool should hold only the above-u64 entry")
	}
	// The reverse direction: 2^64-1 must not displace 2^64.
	if pool.Put(resident, []byte{0x01}, belowU64, 4) {
		t.Fatal("below-u64 fee should be rejected against an above-u64 pool")
	}
	if !pool.Has(wide) || pool.Has(resident) {
		t.Fatal("rejected candidate must leave the pool unchanged")
	}

	// The relay metadata provider itself: the size it reports is what the
	// comparator divides the exact fee by.
	meta, err := CanonicalMempoolRelayMetadata([]byte{0x01, 0x02, 0x03})
	if err != nil || meta.Size != 3 {
		t.Fatalf("relay metadata = (%+v, %v), want size 3", meta, err)
	}
	if got := compareRelayPriority(aboveU64, meta.Size, wide, belowU64, meta.Size, resident); got <= 0 {
		t.Fatalf("relay priority for the above-u64 fee = %d, want > 0", got)
	}
}

func TestMemoryTxPoolPutFallsBackToRawLength(t *testing.T) {
	pool := NewMemoryTxPool()
	var txid [32]byte
	txid[0] = 0x44
	raw := []byte{0xAA, 0xBB, 0xCC}
	if !pool.Put(txid, raw, consensus.Uint128FromU64(5), 0) {
		t.Fatal("Put with size=0 should fall back to len(raw)")
	}
	if !pool.Has(txid) {
		t.Fatal("pool should contain tx admitted via size fallback")
	}
}

func TestCompareRelayPriorityTieBreakers(t *testing.T) {
	var low [32]byte
	low[31] = 0x10
	var high [32]byte
	high[31] = 0x20
	if got := compareRelayPriority(consensus.Uint128FromU64(5), 2, low, consensus.Uint128FromU64(4), 2, high); got <= 0 {
		t.Fatalf("higher feerate should win, got %d", got)
	}
	if got := compareRelayPriority(consensus.Uint128FromU64(6), 3, low, consensus.Uint128FromU64(4), 2, high); got <= 0 {
		t.Fatalf("higher absolute fee should win on equal feerate, got %d", got)
	}
	if got := compareRelayPriority(consensus.Uint128FromU64(4), 2, low, consensus.Uint128FromU64(4), 2, high); got <= 0 {
		t.Fatalf("lower txid should win final tie-break, got %d", got)
	}
	if got := compareRelayFeeRate(consensus.Uint128FromU64(0), 0, consensus.Uint128FromU64(1), 1); got != 0 {
		t.Fatalf("invalid sizes should compare equal, got %d", got)
	}
}

// TestCompareRelayFeeRateComparesRatesNotProducts pins distinct sizes on the
// two operands, where a rate comparison and a fee*size product comparison
// disagree: fee 10 over size 1 is rate 10 but product 10, while fee 100 over
// size 100 is rate 1 but product 10000. Every other relay case in this file
// uses equal sizes, where both orientations agree and a doubly crossed
// comparator passes unnoticed.
func TestCompareRelayFeeRateComparesRatesNotProducts(t *testing.T) {
	smallHighRate := consensus.Uint128FromU64(10) // rate 10/1
	largeLowRate := consensus.Uint128FromU64(100) // rate 100/100
	if got := compareRelayFeeRate(smallHighRate, 1, largeLowRate, 100); got != 1 {
		t.Fatalf("higher rate (10/1) must win over larger fee*size (100/100), got %d", got)
	}
	if got := compareRelayFeeRate(largeLowRate, 100, smallHighRate, 1); got != -1 {
		t.Fatalf("lower rate (100/100) must lose to higher rate (10/1), got %d", got)
	}
	// Equal rates, distinct fees and sizes: 6/3 == 4/2, so the rate term is a
	// tie and priority must fall through to the absolute fee.
	if got := compareRelayFeeRate(consensus.Uint128FromU64(6), 3, consensus.Uint128FromU64(4), 2); got != 0 {
		t.Fatalf("equal rates with distinct fees/sizes must tie, got %d", got)
	}
}

// TestMemoryTxPoolEvictsByRateNotProduct drives the same discrimination
// through the live Put/findWorstLocked eviction path: a full pool must keep
// the higher-RATE entry, not the one with the larger fee*size product.
func TestMemoryTxPoolEvictsByRateNotProduct(t *testing.T) {
	pool := NewMemoryTxPoolWithLimit(1)
	var bulky [32]byte
	bulky[0] = 0x51
	var dense [32]byte
	dense[0] = 0x52

	// fee 100 over size 100 → rate 1, product 10000.
	if !pool.Put(bulky, []byte{0x01}, consensus.Uint128FromU64(100), 100) {
		t.Fatal("first Put should succeed")
	}
	// fee 10 over size 1 → rate 10, product 10. Higher rate must evict.
	if !pool.Put(dense, []byte{0x02}, consensus.Uint128FromU64(10), 1) {
		t.Fatal("higher-rate candidate should evict the lower-rate entry")
	}
	if pool.Has(bulky) {
		t.Fatal("lower-rate entry should have been evicted")
	}
	if !pool.Has(dense) {
		t.Fatal("higher-rate entry should be retained")
	}
	// The reverse direction: the lower-rate bulky entry must not displace it.
	if pool.Put(bulky, []byte{0x01}, consensus.Uint128FromU64(100), 100) {
		t.Fatal("lower-rate candidate should be rejected against a higher-rate pool")
	}
	if !pool.Has(dense) || pool.Has(bulky) {
		t.Fatal("pool should still hold only the higher-rate entry")
	}
}

// TestCanonicalMempoolTxPoolRelayAdmissionPreservesProducerResult proves the
// adapter classifies NOTHING itself: for every candidate whose announced txid
// matches its canonical bytes — including bytes that do not parse at all, which
// carry no identity to match — the adapter's result is field-for-field the
// producer's own.
func TestCanonicalMempoolTxPoolRelayAdmissionPreservesProducerResult(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "unparseable bytes reach the producer", raw: []byte{0xFF, 0x00, 0x13, 0x37}},
		{name: "minimal canonical tx", raw: minimalValidTxBytes(t)},
		{name: "distinct canonical tx", raw: distinctTxBytes(t, 7)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mempool, err := node.NewMempool(node.NewChainState(), nil, [32]byte{})
			if err != nil {
				t.Fatalf("NewMempool: %v", err)
			}
			// A rejected candidate leaves no state behind, so the producer's own
			// call and the adapter's call observe the identical mempool.
			direct := mempool.AddRemoteTxForRelay(tc.raw, nil)
			if direct.Err == nil {
				t.Fatalf("fixture admitted; this comparison needs a rejected candidate")
			}
			announced, err := canonicalTxID(tc.raw)
			if err != nil {
				announced = [32]byte{}
			}

			got := NewCanonicalMempoolTxPool(mempool).AddRemoteTxForRelay(announced, tc.raw, nil)
			if got.Disposition != direct.Disposition {
				t.Fatalf("disposition=%v, want the producer's %v", got.Disposition, direct.Disposition)
			}
			if got.TxID != direct.TxID || got.WTxID != direct.WTxID {
				t.Fatalf("identity=(%x,%x), want the producer's (%x,%x)", got.TxID, got.WTxID, direct.TxID, direct.WTxID)
			}
			if got.HasAdmissionContext != direct.HasAdmissionContext || got.AdmissionContext != direct.AdmissionContext {
				t.Fatalf("context=(%v,%+v), want the producer's (%v,%+v)", got.HasAdmissionContext, got.AdmissionContext, direct.HasAdmissionContext, direct.AdmissionContext)
			}
			if got.Err == nil || got.Err.Error() != direct.Err.Error() {
				t.Fatalf("err=%v, want the producer's %v", got.Err, direct.Err)
			}
			if got.Disposition == node.RelayAdmissionInternal {
				t.Fatal("the adapter must not reclassify a delegated candidate as INTERNAL")
			}
		})
	}
}

// TestCanonicalMempoolTxPoolRelayAdmissionRetainsAdmittedCandidate proves the
// adapter's SUCCESS pass-through: a candidate that really admits comes back
// RETAINED, with the producer's own identities and no error.
func TestCanonicalMempoolTxPoolRelayAdmissionRetainsAdmittedCandidate(t *testing.T) {
	chainState := node.NewChainState()
	raw, txid, utxos := signedCanonicalP2PTxWithoutSeeding(t, 1)
	for op, entry := range utxos {
		chainState.Utxos[op] = entry
	}
	mempool, err := node.NewMempool(chainState, nil, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}

	got := NewCanonicalMempoolTxPool(mempool).AddRemoteTxForRelay(txid, raw, nil)
	if got.Disposition != node.RelayAdmissionRetained {
		t.Fatalf("disposition=%v, want RETAINED (err=%v)", got.Disposition, got.Err)
	}
	if got.Err != nil {
		t.Fatalf("err=%v, want nil", got.Err)
	}
	if got.TxID != txid {
		t.Fatalf("TxID=%x, want the canonical %x", got.TxID, txid)
	}
	if got.WTxID == ([32]byte{}) {
		t.Fatal("WTxID is zero for an admitted candidate")
	}
	if got.HasAdmissionContext {
		t.Fatal("a nil expected context must never authorize caching")
	}
	if !mempool.Contains(txid) {
		t.Fatal("RETAINED was published for a candidate that is not resident")
	}
}

// TestCanonicalMempoolTxPoolRelayAdmissionIdentityMismatchIsInternal pins the
// adapter's OWN contract: an announced txid that is not the txid of the supplied
// canonical bytes is an adapter contract violation, and the mempool is never
// reached.
func TestCanonicalMempoolTxPoolRelayAdmissionIdentityMismatchIsInternal(t *testing.T) {
	mempool, err := node.NewMempool(node.NewChainState(), nil, [32]byte{})
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	raw := distinctTxBytes(t, 11)
	canonical, canonicalWTxID, ok := canonicalRelayIdentity(raw)
	if !ok {
		t.Fatal("canonicalRelayIdentity: the fixture must parse canonically")
	}
	if canonicalWTxID == ([32]byte{}) {
		t.Fatal("the fixture's wtxid must be non-zero for this row to be meaningful")
	}
	var announced [32]byte
	announced[0] = ^canonical[0]

	got := NewCanonicalMempoolTxPool(mempool).AddRemoteTxForRelay(announced, raw, nil)
	if got.Disposition != node.RelayAdmissionInternal {
		t.Fatalf("disposition=%v, want INTERNAL", got.Disposition)
	}
	if got.TxID != canonical {
		t.Fatalf("TxID=%x, want the canonical %x", got.TxID, canonical)
	}
	// The branch is entered only because the bytes parsed canonically, so the
	// published identity must be WHOLE: a zero wtxid here would contradict the
	// RelayAdmissionResult contract that zero means "never parsed canonically".
	if got.WTxID != canonicalWTxID {
		t.Fatalf("WTxID=%x, want the parsed %x", got.WTxID, canonicalWTxID)
	}
	var admitErr *node.TxAdmitError
	if !errors.As(got.Err, &admitErr) {
		t.Fatalf("err=%v (%T), want a *node.TxAdmitError", got.Err, got.Err)
	}
	if got.HasAdmissionContext {
		t.Fatal("an adapter contract violation must never authorize caching")
	}
	if mempool.AdmissionCounts() != (node.MempoolAdmissionCounts{}) {
		t.Fatalf("the mempool was reached despite the identity mismatch: %+v", mempool.AdmissionCounts())
	}
}

// TestCanonicalMempoolTxPoolRelayAdmissionNilSafeAndOffTheGenericInterface pins
// the nil-receiver contract shared with the adapter's other methods, and that
// the relay-admission method did NOT widen the generic TxPool contract.
func TestCanonicalMempoolTxPoolRelayAdmissionNilSafeAndOffTheGenericInterface(t *testing.T) {
	var nilAdapter *CanonicalMempoolTxPool
	for name, adapter := range map[string]*CanonicalMempoolTxPool{
		"nil adapter":        nilAdapter,
		"nil-backed adapter": NewCanonicalMempoolTxPool(nil),
	} {
		got := adapter.AddRemoteTxForRelay([32]byte{}, []byte{0x01}, nil)
		if got.Disposition != node.RelayAdmissionUnavailable {
			t.Fatalf("%s: disposition=%v, want UNAVAILABLE", name, got.Disposition)
		}
		// The adapter's own exits carry the same typed error every producer
		// result carries, so a consumer's errors.As always resolves.
		var admitErr *node.TxAdmitError
		if !errors.As(got.Err, &admitErr) {
			t.Fatalf("%s: err=%v (%T), want a *node.TxAdmitError", name, got.Err, got.Err)
		}
		if admitErr.Kind != node.TxAdmitUnavailable {
			t.Fatalf("%s: kind=%q, want %q", name, admitErr.Kind, node.TxAdmitUnavailable)
		}
		if got.HasAdmissionContext || got.TxID != ([32]byte{}) {
			t.Fatalf("%s: published identity or context: %+v", name, got)
		}
	}

	var generic TxPool = NewMemoryTxPool()
	if _, widened := generic.(interface {
		AddRemoteTxForRelay([32]byte, []byte, *node.PendingOutpointAdmissionContext) node.RelayAdmissionResult
	}); widened {
		t.Fatal("the generic TxPool surface was widened with relay admission")
	}
}
