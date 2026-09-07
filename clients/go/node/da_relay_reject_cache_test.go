package node

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type daRejectCacheView struct {
	context  PendingOutpointAdmissionContext
	adopted  bool
	entries  map[[32]byte]struct{}
	fifo     [][32]byte
	capacity int
	next     int
}

func snapshotDARejectCache(cache *daRejectCache) daRejectCacheView {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	var entries map[[32]byte]struct{}
	if cache.entries != nil {
		entries = make(map[[32]byte]struct{}, len(cache.entries))
		for key := range cache.entries {
			entries[key] = struct{}{}
		}
	}
	return daRejectCacheView{
		context:  cache.context,
		adopted:  cache.adopted,
		entries:  entries,
		fifo:     append([][32]byte(nil), cache.fifo...),
		capacity: cap(cache.fifo),
		next:     cache.next,
	}
}

func daRejectContext(t *testing.T, fixture *daNonReplayFixture) PendingOutpointAdmissionContext {
	t.Helper()
	context, ok := fixture.mp.pendingOutpoints.AdmissionContext()
	if !ok {
		t.Fatal("pending-outpoint admission context unavailable")
	}
	return context
}

func invalidDAWitness(t *testing.T, tx daNonReplayTx) daNonReplayTx {
	t.Helper()
	raw := corruptFirstWitnessSignature(t, append([]byte(nil), tx.raw...))
	_, txid, wtxid, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) || txid != tx.txid || wtxid == tx.wtxid {
		t.Fatalf("invalid witness identity=(%x,%x,%d,%v), want same txid and distinct wtxid", txid, wtxid, consumed, err)
	}
	tx.raw, tx.wtxid = raw, wtxid
	return tx
}

func requireDARejectSignature(t *testing.T, got DAAdmissionResult, err error) {
	t.Helper()
	requirePublicDAFailure(t, got, err, TxAdmitRejected, "TX_ERR_SIG_INVALID: CORE_P2PK signature invalid", RelayAdmissionStableTerminalReject)
}

func daRejectKey(value uint64) [32]byte {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:8], value)
	return key
}

func TestDARejectCachePublicAdmission(t *testing.T) {
	t.Run("exact wtxid suppresses only the repeated stable rejection", func(t *testing.T) {
		fixture := newDANonReplayFixture(t, 1)
		valid := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x11}, payload: []byte("exact rejection")})
		invalid := invalidDAWitness(t, valid)
		original := append([]byte(nil), invalid.raw...)
		relayBefore, ownerBefore := daRelayStateSnapshot(fixture.relay), cloneDAAdmissionOwner(fixture.mp.pendingOutpoints)

		got, err := fixture.relay.AdmitDA(invalid.raw, publicPeer(t, "first"))
		requireDARejectSignature(t, got, err)
		if fixture.mp.sigCache.Misses() != 1 {
			t.Fatalf("first signature-cache misses=%d, want 1", fixture.mp.sigCache.Misses())
		}
		first := snapshotDARejectCache(&fixture.relay.rejectCache)
		if !first.adopted || first.context != daRejectContext(t, fixture) || len(first.entries) != 1 || len(first.fifo) != 1 {
			t.Fatalf("first cache=%+v", first)
		}
		invalid.raw[0] ^= 0xff
		got, err = fixture.relay.AdmitDA(original, publicPeer(t, "repeat"))
		requirePublicDAFailure(t, got, err, TxAdmitUnavailable, "DA repeated stable rejection suppressed", RelayAdmissionUnavailable)
		if fixture.mp.sigCache.Misses() != 1 || !reflect.DeepEqual(snapshotDARejectCache(&fixture.relay.rejectCache), first) {
			t.Fatalf("repeat reached signature cache or refreshed rejection: misses=%d", fixture.mp.sigCache.Misses())
		}
		requireDANonReplayUnchanged(t, fixture.relay, fixture.mp.pendingOutpoints, relayBefore, ownerBefore)
	})

	t.Run("same txid valid alternate wtxid remains admissible", func(t *testing.T) {
		fixture := newDANonReplayFixture(t, 1)
		valid := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x12}, payload: []byte("alternate witness")})
		invalid := invalidDAWitness(t, valid)
		if invalid.txid != valid.txid || invalid.wtxid == valid.wtxid {
			t.Fatal("fixture did not independently establish same txid and distinct wtxid")
		}
		got, err := fixture.relay.AdmitDA(invalid.raw, publicPeer(t, "negative"))
		requireDARejectSignature(t, got, err)
		got, err = fixture.relay.AdmitDA(valid.raw, publicPeer(t, "valid"))
		requirePublicDAResult(t, got, err, DAAdmissionResult{DAID: valid.spec.daID, Disposition: DAAdmissionRetained})
		if cache := snapshotDARejectCache(&fixture.relay.rejectCache); len(cache.entries) != 1 || len(cache.fifo) != 1 {
			t.Fatalf("alternate witness cache=%+v", cache)
		}
	})

	t.Run("commit uses the same exact-wtxid suppression path", func(t *testing.T) {
		fixture := newDANonReplayFixture(t, 1)
		valid := fixture.signed(daNonReplayTxSpec{kind: 0x01, daID: [32]byte{0x15}, chunkCount: 2, commitment: [32]byte{0x51}, commitmentOutputs: 1})
		invalid := invalidDAWitness(t, valid)
		got, err := fixture.relay.AdmitDA(invalid.raw, publicPeer(t, "commit-first"))
		requireDARejectSignature(t, got, err)
		got, err = fixture.relay.AdmitDA(invalid.raw, publicPeer(t, "commit-repeat"))
		requirePublicDAFailure(t, got, err, TxAdmitUnavailable, "DA repeated stable rejection suppressed", RelayAdmissionUnavailable)
	})

	t.Run("fresh generation misses and A-to-B-to-A never revives a row", func(t *testing.T) {
		fixture := newDANonReplayFixture(t, 1)
		invalid := invalidDAWitness(t, fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x13}, payload: []byte("generation")}))
		got, err := fixture.relay.AdmitDA(invalid.raw, publicPeer(t, "generation-a"))
		requireDARejectSignature(t, got, err)
		before := daRejectContext(t, fixture)
		fixture.state.admissionMu.Lock()
		owner := fixture.mp.pendingOutpoints
		if _, err = owner.beginTransition(); err == nil {
			tipB := before.StableTip
			tipB.Height++
			tipB.Hash[0] ^= 0xff
			err = owner.commitStableTip(tipB)
		}
		if err == nil {
			_, err = owner.beginTransition()
		}
		if err == nil {
			err = owner.commitStableTip(before.StableTip)
		}
		fixture.state.admissionMu.Unlock()
		if err != nil {
			t.Fatalf("A-to-B-to-A transition: %v", err)
		}
		after := daRejectContext(t, fixture)
		if after.StableTip != before.StableTip || after.Generation != before.Generation+2 {
			t.Fatalf("A-to-B-to-A context=%+v, want stable tip A and generation %d", after, before.Generation+2)
		}
		got, err = fixture.relay.AdmitDA(invalid.raw, publicPeer(t, "generation-new"))
		requireDARejectSignature(t, got, err)
		cache := snapshotDARejectCache(&fixture.relay.rejectCache)
		if fixture.mp.sigCache.Misses() != 2 || cache.context != after || len(cache.entries) != 1 {
			t.Fatalf("post-transition misses=%d cache=%+v", fixture.mp.sigCache.Misses(), cache)
		}
	})

	t.Run("unstable guard bypasses cache and peerless provenance never consults it", func(t *testing.T) {
		fixture := newDANonReplayFixture(t, 1)
		invalid := invalidDAWitness(t, fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x14}, payload: []byte("provenance")}))
		if _, err := fixture.mp.pendingOutpoints.beginTransition(); err != nil {
			t.Fatal(err)
		}
		got, err := fixture.relay.AdmitDA(invalid.raw, publicPeer(t, "unstable"))
		requirePublicDAFailure(t, got, err, TxAdmitUnavailable, "pending-outpoint owner admission context unavailable", RelayAdmissionUnavailable)
		if cache := snapshotDARejectCache(&fixture.relay.rejectCache); cache.adopted || len(cache.entries) != 0 {
			t.Fatalf("unstable access cache=%+v", cache)
		}
		fixture.mp.pendingOutpoints.endTransitionAborted()
		got, err = fixture.relay.AdmitDA(invalid.raw, publicPeer(t, "seed"))
		requireDARejectSignature(t, got, err)
		seeded := snapshotDARejectCache(&fixture.relay.rejectCache)
		for _, provenance := range []DAProvenance{LocalDAProvenance(), DetachedReorgDAProvenance()} {
			got, err = fixture.relay.AdmitDA(invalid.raw, provenance)
			requireDARejectSignature(t, got, err)
			if !reflect.DeepEqual(snapshotDARejectCache(&fixture.relay.rejectCache), seeded) {
				t.Fatalf("peerless provenance changed cache: %+v", provenance)
			}
		}
		replacement, err := newDARelayState(fixture.mp, fixture.relay.caps)
		if err != nil {
			t.Fatal(err)
		}
		got, err = replacement.AdmitDA(invalid.raw, publicPeer(t, "replacement"))
		requireDARejectSignature(t, got, err)

		fixture.relay.mu.Lock()
		projected := fixture.relay.cloneForAtomicBatchLocked()
		if clone := snapshotDARejectCache(&projected.rejectCache); clone.adopted || len(clone.entries) != 0 {
			fixture.relay.mu.Unlock()
			t.Fatalf("retained image copied rejection cache: %+v", clone)
		}
		fixture.relay.publishAtomicBatchLocked(projected)
		fixture.relay.mu.Unlock()
		if !reflect.DeepEqual(snapshotDARejectCache(&fixture.relay.rejectCache), seeded) {
			t.Fatal("retained image publication replaced the live rejection cache")
		}
	})
}

func TestDARejectCachePrecedence(t *testing.T) {
	t.Run("retained owner and own-chunk results precede a seeded hit", func(t *testing.T) {
		fixture := newDANonReplayFixture(t, 2)
		badChunk := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x21}, payload: []byte("bad chunk"), literalChunkHash: true, chunkHash: [32]byte{0xff}})
		context := daRejectContext(t, fixture)
		fixture.relay.rejectCache.insert(context, badChunk.wtxid)
		seeded := snapshotDARejectCache(&fixture.relay.rejectCache)
		got, err := fixture.relay.AdmitDA(badChunk.raw, publicPeer(t, "own-chunk"))
		requirePublicDAFailure(t, got, err, TxAdmitRejected, "DA chunk payload hash mismatch", RelayAdmissionStableTerminalReject)
		if !reflect.DeepEqual(snapshotDARejectCache(&fixture.relay.rejectCache), seeded) {
			t.Fatal("own-chunk rejection refreshed cache")
		}

		fixture.mutateRelay(func(relay *DARelayState) { relay.sets = nil })
		got, err = fixture.relay.AdmitDA(badChunk.raw, publicPeer(t, "owner-unavailable"))
		requirePublicDAFailure(t, got, err, TxAdmitUnavailable, "DA relay owner maps unavailable", RelayAdmissionUnavailable)
		if !reflect.DeepEqual(snapshotDARejectCache(&fixture.relay.rejectCache), seeded) {
			t.Fatal("owner-unavailable result changed cache")
		}
	})

	t.Run("integrity-valid exact replay and retained corruption precede a seeded hit", func(t *testing.T) {
		fixture := newDANonReplayFixture(t, 2)
		tx := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x22}, payload: []byte("exact")})
		got, err := fixture.relay.AdmitDA(tx.raw, publicPeer(t, "retain"))
		requirePublicDAResult(t, got, err, DAAdmissionResult{DAID: tx.spec.daID, Disposition: DAAdmissionRetained})
		fixture.relay.rejectCache.insert(daRejectContext(t, fixture), tx.wtxid)
		seeded := snapshotDARejectCache(&fixture.relay.rejectCache)
		got, err = fixture.relay.AdmitDA(tx.raw, publicPeer(t, "exact"))
		requirePublicDAResult(t, got, err, DAAdmissionResult{DAID: tx.spec.daID, Disposition: DAAdmissionDuplicate})
		if !reflect.DeepEqual(snapshotDARejectCache(&fixture.relay.rejectCache), seeded) {
			t.Fatal("exact replay consulted cache")
		}

		corrupt := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x23}, payload: []byte("corrupt")})
		fixture.mutateRelay(func(relay *DARelayState) {
			relay.locators[corrupt.txid] = daRelayLocator{daID: [32]byte{0xee}, kind: daRelayLocatorChunk}
		})
		fixture.relay.rejectCache.insert(daRejectContext(t, fixture), corrupt.wtxid)
		seeded = snapshotDARejectCache(&fixture.relay.rejectCache)
		got, err = fixture.relay.AdmitDA(corrupt.raw, publicPeer(t, "corrupt"))
		requirePublicDAFailure(t, got, err, TxAdmitRejected, errDARelayImageIncompatible.Error(), RelayAdmissionInternal)
		if !reflect.DeepEqual(snapshotDARejectCache(&fixture.relay.rejectCache), seeded) {
			t.Fatal("retained corruption consulted cache")
		}
	})

	t.Run("retryable and later outcomes never insert", func(t *testing.T) {
		t.Run("missing dependency", func(t *testing.T) {
			fixture := newDANonReplayFixture(t, 1)
			tx := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x24}, payload: []byte("missing")})
			delete(fixture.state.Utxos, tx.inputs[0])
			for range 2 {
				got, err := fixture.relay.AdmitDA(tx.raw, publicPeer(t, "missing"))
				if got != (DAAdmissionResult{}) || err == nil || relayDispositionOf(err) != RelayAdmissionMissingDependency {
					t.Fatalf("missing dependency=(%+v,%v) disposition=%v", got, err, relayDispositionOf(err))
				}
			}
			cache := snapshotDARejectCache(&fixture.relay.rejectCache)
			if !cache.adopted || len(cache.entries) != 0 || cache.fifo != nil {
				t.Fatalf("missing dependency cache=%+v", cache)
			}
		})

		t.Run("MTP unavailable and local backend internal", func(t *testing.T) {
			for _, row := range []struct {
				name        string
				disposition RelayAdmissionDisposition
				mutate      func(*daNonReplayFixture)
			}{
				{"MTP unavailable", RelayAdmissionUnavailable, func(f *daNonReplayFixture) { f.mp.blockStore = &BlockStore{} }},
				{"local backend internal", RelayAdmissionInternal, func(f *daNonReplayFixture) { f.mp.policy.SuiteRegistry = unboundAlgSuiteRegistry() }},
			} {
				fixture := newDANonReplayFixture(t, 1)
				tx := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x25, byte(len(row.name))}, payload: []byte(row.name)})
				row.mutate(fixture)
				var first string
				for range 2 {
					got, err := fixture.relay.AdmitDA(tx.raw, publicPeer(t, row.name))
					if got != (DAAdmissionResult{}) || err == nil || relayDispositionOf(err) != row.disposition || first != "" && err.Error() != first {
						t.Fatalf("%s=(%+v,%v) disposition=%v first=%q", row.name, got, err, relayDispositionOf(err), first)
					}
					first = err.Error()
				}
				if cache := snapshotDARejectCache(&fixture.relay.rejectCache); len(cache.entries) != 0 {
					t.Fatalf("%s cache=%+v", row.name, cache)
				}
			}
		})

		t.Run("render and capacity", func(t *testing.T) {
			fixture := newDANonReplayFixture(t, 2)
			render := fixture.signed(daNonReplayTxSpec{kind: 0x01, daID: [32]byte{0x25}, chunkCount: 2})
			relayBefore, ownerBefore := daRelayStateSnapshot(fixture.relay), cloneDAAdmissionOwner(fixture.mp.pendingOutpoints)
			got, err := fixture.relay.AdmitDA(render.raw, publicPeer(t, "render"))
			if got != (DAAdmissionResult{}) || err != errDARelayMemberIncomplete { //nolint:errorlint // Exact direct renderer sentinel identity is contract-owned.
				t.Fatalf("render result=(%+v,%v)", got, err)
			}
			requireDANonReplayUnchanged(t, fixture.relay, fixture.mp.pendingOutpoints, relayBefore, ownerBefore)
			capacity := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x26}, payload: []byte("capacity")})
			fixture.relay.caps.orphanPoolBytes = 1
			relayBefore, ownerBefore = daRelayStateSnapshot(fixture.relay), cloneDAAdmissionOwner(fixture.mp.pendingOutpoints)
			got, err = fixture.relay.AdmitDA(capacity.raw, publicPeer(t, "capacity"))
			if got != (DAAdmissionResult{}) || err != errDARelayOrphanPoolCapExceeded { //nolint:errorlint // Exact direct DA sentinel identity is contract-owned.
				t.Fatalf("capacity result=(%+v,%v)", got, err)
			}
			requireDANonReplayUnchanged(t, fixture.relay, fixture.mp.pendingOutpoints, relayBefore, ownerBefore)
			if cache := snapshotDARejectCache(&fixture.relay.rejectCache); len(cache.entries) != 0 {
				t.Fatalf("later outcome cache=%+v", cache)
			}
		})

		t.Run("success and exact duplicate", func(t *testing.T) {
			fixture := newDANonReplayFixture(t, 1)
			tx := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x27}, payload: []byte("success")})
			provenance, err := NewPeerDAProvenance("boundary", "boundary")
			if err != nil {
				t.Fatal(err)
			}
			got, err := fixture.relay.AdmitDA(tx.raw, provenance)
			requirePublicDAResult(t, got, err, DAAdmissionResult{DAID: tx.spec.daID, Disposition: DAAdmissionRetained})
			fixture.requireSingleRetained(t, tx, daRelayStateOrphanChunks)
			relayBefore, ownerBefore := daRelayStateSnapshot(fixture.relay), cloneDAAdmissionOwner(fixture.mp.pendingOutpoints)
			got, err = fixture.relay.AdmitDA(tx.raw, publicPeer(t, "duplicate"))
			requirePublicDAResult(t, got, err, DAAdmissionResult{DAID: tx.spec.daID, Disposition: DAAdmissionDuplicate})
			requireDANonReplayUnchanged(t, fixture.relay, fixture.mp.pendingOutpoints, relayBefore, ownerBefore)
			cache := snapshotDARejectCache(&fixture.relay.rejectCache)
			if !cache.adopted || len(cache.entries) != 0 || cache.fifo != nil {
				t.Fatalf("successful path cache=%+v", cache)
			}
		})

		t.Run("owner conflict, sequence exhaustion and competing commit", func(t *testing.T) {
			fixture := newDANonReplayFixture(t, 1)
			first := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x29}, payload: []byte("first")})
			fixture.next = 0
			conflict := fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x2a}, payload: []byte("conflict")})
			got, err := fixture.relay.AdmitDA(first.raw, publicPeer(t, "first-owner"))
			requirePublicDAResult(t, got, err, DAAdmissionResult{DAID: first.spec.daID, Disposition: DAAdmissionRetained})
			relayBefore, ownerBefore := daRelayStateSnapshot(fixture.relay), cloneDAAdmissionOwner(fixture.mp.pendingOutpoints)
			got, err = fixture.relay.AdmitDA(conflict.raw, publicPeer(t, "owner-conflict"))
			requirePublicDAFailure(t, got, err, TxAdmitConflict, "")
			requireDANonReplayUnchanged(t, fixture.relay, fixture.mp.pendingOutpoints, relayBefore, ownerBefore)

			sequence := newDANonReplayFixture(t, 1)
			sequence.relay.nextReceivedTime = ^uint64(0)
			tx := sequence.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x2b}, payload: []byte("sequence")})
			relayBefore, ownerBefore = daRelayStateSnapshot(sequence.relay), cloneDAAdmissionOwner(sequence.mp.pendingOutpoints)
			got, err = sequence.relay.AdmitDA(tx.raw, publicPeer(t, "sequence"))
			if got != (DAAdmissionResult{}) || err != errDARelayArithmeticOverflow { //nolint:errorlint // Exact direct DA sentinel identity is contract-owned.
				t.Fatalf("sequence result=(%+v,%v)", got, err)
			}
			requireDANonReplayUnchanged(t, sequence.relay, sequence.mp.pendingOutpoints, relayBefore, ownerBefore)

			competing := newDANonReplayFixture(t, 2)
			resident := competing.signed(daNonReplayTxSpec{kind: 0x01, daID: [32]byte{0x2c}, chunkCount: 2, commitment: [32]byte{0x55}, commitmentOutputs: 1})
			candidate := competing.signed(daNonReplayTxSpec{kind: 0x01, daID: resident.spec.daID, chunkCount: 2, commitment: [32]byte{0x55}, commitmentOutputs: 1})
			got, err = competing.relay.AdmitDA(resident.raw, publicPeer(t, "resident"))
			requirePublicDAResult(t, got, err, DAAdmissionResult{DAID: resident.spec.daID, Disposition: DAAdmissionRetained})
			relayBefore, ownerBefore = daRelayStateSnapshot(competing.relay), cloneDAAdmissionOwner(competing.mp.pendingOutpoints)
			got, err = competing.relay.AdmitDA(candidate.raw, publicPeer(t, "competing"))
			requirePublicDAResult(t, got, err, DAAdmissionResult{DAID: resident.spec.daID, Disposition: DAAdmissionDuplicate, SameDAIDCommitConflict: true})
			requireDANonReplayUnchanged(t, competing.relay, competing.mp.pendingOutpoints, relayBefore, ownerBefore)
			for name, cache := range map[string]*daRejectCache{"conflict": &fixture.relay.rejectCache, "sequence": &sequence.relay.rejectCache, "competing": &competing.relay.rejectCache} {
				if len(snapshotDARejectCache(cache).entries) != 0 {
					t.Fatalf("%s inserted a rejection", name)
				}
			}
		})
	})

	t.Run("untrusted and deployment-provider profiles bypass without a provider query", func(t *testing.T) {
		for index, rotation := range []consensus.RotationProvider{&daRejectTestRotation{}, &daRejectDeploymentRotation{}} {
			fixture := newDANonReplayFixture(t, 1)
			fixture.mp.mu.Lock()
			fixture.mp.policy.RotationProvider = rotation
			fixture.mp.mu.Unlock()
			invalid := invalidDAWitness(t, fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x28, byte(index)}, payload: []byte("profile")}))
			fixture.relay.rejectCache.insert(daRejectContext(t, fixture), invalid.wtxid)
			seeded := snapshotDARejectCache(&fixture.relay.rejectCache)
			for range 2 {
				got, err := fixture.relay.AdmitDA(invalid.raw, publicPeer(t, "profile"))
				requireDARejectSignature(t, got, err)
				if !reflect.DeepEqual(snapshotDARejectCache(&fixture.relay.rejectCache), seeded) {
					t.Fatal("profile bypass consulted or changed a seeded matching row")
				}
			}
			spendCalls, deploymentCalls := 0, 0
			switch rotation := rotation.(type) {
			case *daRejectTestRotation:
				spendCalls = rotation.spendCalls
			case *daRejectDeploymentRotation:
				spendCalls, deploymentCalls = rotation.spendCalls, rotation.deploymentCalls
			}
			if spendCalls != 2 || deploymentCalls != 0 {
				t.Fatalf("provider calls spend=%d deployment=%d", spendCalls, deploymentCalls)
			}
		}
	})
}

type daRejectTestRotation struct {
	consensus.DefaultRotationProvider
	spendCalls int
}

func (rotation *daRejectTestRotation) NativeSpendSuites(height uint64) *consensus.NativeSuiteSet {
	rotation.spendCalls++
	return rotation.DefaultRotationProvider.NativeSpendSuites(height)
}

type daRejectDeploymentRotation struct {
	daRejectTestRotation
	deploymentCalls int
}

func (rotation *daRejectDeploymentRotation) PublishedSimplicityDeployments() ([]consensus.SimplicityDeploymentDescriptor, [32]byte, bool, error) {
	rotation.deploymentCalls++
	return nil, [32]byte{}, true, nil
}

func TestDARejectCacheFIFO(t *testing.T) {
	const expectedCapacity = 50_000
	if daRejectCacheCapacity != expectedCapacity {
		t.Fatalf("cache capacity=%d, want normative literal %d", daRejectCacheCapacity, expectedCapacity)
	}
	cacheType, rawType, errorType := reflect.TypeOf(daRejectCache{}), reflect.TypeOf([]byte(nil)), reflect.TypeOf((*error)(nil)).Elem()
	for index := 0; index < cacheType.NumField(); index++ {
		fieldType := cacheType.Field(index).Type
		if fieldType == rawType || fieldType == errorType || fieldType.Implements(errorType) {
			t.Fatalf("cache retains forbidden field %s %v", cacheType.Field(index).Name, fieldType)
		}
	}
	context := PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 7, Hash: [32]byte{0x31}}, Generation: 9}
	cache := &daRejectCache{}
	if cache.contains(context, daRejectKey(1)) {
		t.Fatal("empty cache hit")
	}
	empty := snapshotDARejectCache(cache)
	if !empty.adopted || empty.context != context || empty.entries != nil || empty.fifo != nil {
		t.Fatalf("first lookup did not adopt context lazily: %+v", empty)
	}
	for value := uint64(1); value <= expectedCapacity; value++ {
		cache.insert(context, daRejectKey(value))
	}
	cache.insert(context, daRejectKey(1))
	if !cache.contains(context, daRejectKey(1)) {
		t.Fatal("resident oldest key missed")
	}
	cache.insert(context, daRejectKey(expectedCapacity+1))
	full := snapshotDARejectCache(cache)
	if len(full.entries) != expectedCapacity || len(full.fifo) != expectedCapacity || full.capacity != expectedCapacity || full.next != 1 {
		t.Fatalf("bounded FIFO shape entries=%d fifo=%d cap=%d next=%d", len(full.entries), len(full.fifo), full.capacity, full.next)
	}
	if _, ok := full.entries[daRejectKey(1)]; ok {
		t.Fatal("hit or duplicate refreshed the oldest key")
	}
	if _, ok := full.entries[daRejectKey(2)]; !ok {
		t.Fatal("FIFO evicted more than the oldest key")
	}
	if _, ok := full.entries[daRejectKey(expectedCapacity+1)]; !ok {
		t.Fatal("FIFO omitted the new key")
	}

	for _, row := range []struct {
		name   string
		mutate func(*PendingOutpointAdmissionContext)
	}{
		{"has-tip", func(value *PendingOutpointAdmissionContext) { value.StableTip.HasTip = false }},
		{"height", func(value *PendingOutpointAdmissionContext) { value.StableTip.Height++ }},
		{"hash", func(value *PendingOutpointAdmissionContext) { value.StableTip.Hash[1]++ }},
		{"generation", func(value *PendingOutpointAdmissionContext) { value.Generation++ }},
	} {
		changed, isolated := context, &daRejectCache{}
		row.mutate(&changed)
		isolated.insert(context, daRejectKey(2))
		if isolated.contains(changed, daRejectKey(2)) {
			t.Fatalf("%s-only context change retained an old row", row.name)
		}
		cleared := snapshotDARejectCache(isolated)
		if cleared.context != changed || cleared.entries != nil || cleared.fifo != nil || cleared.next != 0 {
			t.Fatalf("%s reconciliation=%+v", row.name, cleared)
		}
	}

	for disposition := RelayAdmissionDisposition(0); disposition <= RelayAdmissionCancelled; disposition++ {
		err := selectRelayDisposition(txAdmitRejected("same text"), disposition)
		if got, want := daRejectCacheInsertable(err), disposition == RelayAdmissionStableTerminalReject; got != want {
			t.Fatalf("disposition %d insertable=%v want=%v", disposition, got, want)
		}
	}
	for _, disposition := range []RelayAdmissionDisposition{255} {
		if daRejectCacheInsertable(selectRelayDisposition(txAdmitRejected("same text"), disposition)) {
			t.Fatalf("invalid disposition %d was insertable", disposition)
		}
	}
	if daRejectCacheInsertable(nil) || daRejectCacheInsertable(txAdmitRejected("STABLE_TERMINAL_REJECT")) {
		t.Fatal("nil or error text selected cache eligibility")
	}
	stable := selectRelayDisposition(txAdmitRejected("opaque"), RelayAdmissionStableTerminalReject)
	if !daRejectCacheInsertable(fmt.Errorf("wrapped: %w", stable)) {
		t.Fatal("wrapped originating stable disposition lost eligibility")
	}
	registry := reorgTestSuiteRegistry(0x02)
	descriptor := consensus.CryptoRotationDescriptor{Name: "cache", OldSuiteID: consensus.SUITE_ID_ML_DSA_87, NewSuiteID: 0x02, CreateHeight: 200, SpendHeight: 300}
	for name, policy := range map[string]MempoolConfig{
		"nil":               {},
		"default value":     {RotationProvider: consensus.DefaultRotationProvider{}},
		"default pointer":   {RotationProvider: &consensus.DefaultRotationProvider{}},
		"canonical default": {RotationProvider: consensus.DefaultRotationProvider{}, SuiteRegistry: consensus.DefaultSuiteRegistry()},
		"descriptor value":  {RotationProvider: consensus.DescriptorRotationProvider{Descriptor: descriptor}, SuiteRegistry: registry},
	} {
		if !daRejectCacheEligible(policy) {
			t.Fatalf("permitted %s profile bypassed cache", name)
		}
	}
	if daRejectCacheEligible(MempoolConfig{RotationProvider: &daRejectTestRotation{}}) || daRejectCacheEligible(MempoolConfig{RotationProvider: &daRejectDeploymentRotation{}}) {
		t.Fatal("untrusted or deployment-provider profile became eligible")
	}
}

func TestDARejectCacheConcurrency(t *testing.T) {
	const sameKeyWorkers = 8
	fixture := newDANonReplayFixture(t, 1)
	invalid := invalidDAWitness(t, fixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x41}, payload: []byte("concurrent miss")}))
	owned, parsed, txid, wtxid, inputs, err := parseDAAdmissionCandidate(invalid.raw)
	if err != nil {
		t.Fatal(err)
	}
	holds := make([]*daAdmissionHold, sameKeyWorkers)
	for index := range holds {
		holds[index], err = fixture.mp.acquireDAAdmissionHold(fixture.mp.pendingOutpoints, inputs)
		if err != nil {
			t.Fatal(err)
		}
	}
	blockHash := [32]byte{0x44}
	canonical := make([]string, fixture.state.Height+1)
	for index := range canonical {
		canonical[index] = fmt.Sprintf("%x", blockHash)
	}
	fixture.mp.blockStore = &BlockStore{headersDir: t.TempDir(), index: blockStoreIndexDisk{Canonical: canonical}}
	previousRead := readFileByPathFn
	t.Cleanup(func() { readFileByPathFn = previousRead })
	entered, release := make(chan struct{}, sameKeyWorkers), make(chan struct{})
	var reads atomic.Int64
	readFileByPathFn = func(string, int64) ([]byte, error) {
		if reads.Add(1) <= sameKeyWorkers {
			entered <- struct{}{}
			<-release
		}
		return make([]byte, consensus.BLOCK_HEADER_BYTES), nil
	}
	start := make(chan struct{})
	results := make(chan error, sameKeyWorkers)
	var workers sync.WaitGroup
	for _, hold := range holds {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, callErr := hold.validateDACandidate(owned, parsed, txid, wtxid, inputs, &fixture.relay.rejectCache)
			results <- callErr
		}()
	}
	close(start)
	watchdog := time.NewTimer(5 * time.Second)
	defer watchdog.Stop()
	for range sameKeyWorkers {
		select {
		case <-entered:
		case <-watchdog.C:
			close(release)
			workers.Wait()
			t.Fatal("cache-aware validations serialized before ordinary validation")
		}
	}
	close(release)
	workers.Wait()
	for range sameKeyWorkers {
		requireDARejectSignature(t, DAAdmissionResult{}, <-results)
	}
	if got := snapshotDARejectCache(&fixture.relay.rejectCache); len(got.entries) != 1 || len(got.fifo) != 1 || got.context != daRejectContext(t, fixture) || fixture.mp.sigCache.Misses() != sameKeyWorkers {
		t.Fatalf("cache-aware same-key misses=%d cache=%+v", fixture.mp.sigCache.Misses(), got)
	}

	context := PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 8, Hash: [32]byte{0x41}}, Generation: 3}
	cache := &daRejectCache{}
	for value := uint64(1); value <= daRejectCacheCapacity-100; value++ {
		cache.insert(context, daRejectKey(value))
	}
	start = make(chan struct{})
	for value := uint64(daRejectCacheCapacity - 99); value <= daRejectCacheCapacity+100; value++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			cache.insert(context, daRejectKey(value))
		}()
	}
	close(start)
	workers.Wait()
	if got := snapshotDARejectCache(cache); len(got.entries) != daRejectCacheCapacity || len(got.fifo) != daRejectCacheCapacity || got.context != context {
		t.Fatalf("concurrent capacity/context=%+v", got)
	}

	guardFixture := newDANonReplayFixture(t, 1)
	valid := guardFixture.signed(daNonReplayTxSpec{kind: 0x02, daID: [32]byte{0x42}, payload: []byte("guard")})
	owned, parsed, txid, wtxid, inputs, err = parseDAAdmissionCandidate(valid.raw)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := guardFixture.mp.acquireDAAdmissionHold(guardFixture.mp.pendingOutpoints, inputs)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := hold.validateDACandidate(owned, parsed, txid, wtxid, inputs, &guardFixture.relay.rejectCache)
	if err != nil {
		t.Fatal(err)
	}
	parentAcquired := guardFixture.state.admissionMu.TryLock()
	if parentAcquired {
		guardFixture.state.admissionMu.Unlock()
	}
	attempted, proceed, done := make(chan bool, 1), make(chan struct{}), make(chan error, 1)
	go func() {
		acquired := guardFixture.state.admissionMu.TryLock()
		if acquired {
			guardFixture.state.admissionMu.Unlock()
		}
		attempted <- acquired
		<-proceed
		if !guardFixture.state.admissionMu.TryLock() {
			done <- fmt.Errorf("transition guard remained held after admission release")
			return
		}
		_, transitionErr := guardFixture.mp.pendingOutpoints.beginTransition()
		if transitionErr == nil {
			transitionErr = guardFixture.mp.pendingOutpoints.commitStableTip(pendingOutpointTipOf(guardFixture.state))
		}
		guardFixture.state.admissionMu.Unlock()
		done <- transitionErr
	}()
	workerAcquired, attemptTimedOut := false, false
	select {
	case workerAcquired = <-attempted:
	case <-time.After(5 * time.Second):
		attemptTimedOut = true
	}
	if !parentAcquired && !workerAcquired {
		admission.Close()
	}
	close(proceed)
	transitionErr, completionTimedOut := error(nil), false
	select {
	case transitionErr = <-done:
	case <-time.After(5 * time.Second):
		completionTimedOut = true
	}
	if attemptTimedOut || completionTimedOut {
		t.Fatalf("transition synchronization timeout: attempt=%v completion=%v", attemptTimedOut, completionTimedOut)
	}
	if parentAcquired || workerAcquired {
		t.Fatalf("successful cache-aware validation released the chain guard: parent=%v worker=%v", parentAcquired, workerAcquired)
	}
	if transitionErr != nil {
		t.Fatal(transitionErr)
	}
	invalid = invalidDAWitness(t, valid)
	got, err := guardFixture.relay.AdmitDA(invalid.raw, publicPeer(t, "post-transition"))
	requireDARejectSignature(t, got, err)
	after := snapshotDARejectCache(&guardFixture.relay.rejectCache)
	if after.context.Generation == admission.context.Generation || len(after.entries) != 1 {
		t.Fatalf("post-transition cache=%+v old=%+v", after, admission.context)
	}
}

var (
	_ consensus.RotationProvider             = (*daRejectTestRotation)(nil)
	_ consensus.RotationProvider             = (*daRejectDeploymentRotation)(nil)
	_ consensus.SimplicityDeploymentProvider = (*daRejectDeploymentRotation)(nil)
)
