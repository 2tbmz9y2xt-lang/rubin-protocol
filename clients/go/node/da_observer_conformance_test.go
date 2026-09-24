//go:build rubin_da_observer

package node

import (
	"bytes"
	"crypto/sha3"
	"maps"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestDAObserverConformanceSurface(t *testing.T) {
	if DAObserverCompleteSetMaxCount() != 65536 {
		t.Fatalf("COMPLETE_SET count bound=%d", DAObserverCompleteSetMaxCount())
	}
	if got := DAObserverReadOwnerCounts(nil); got != (DAObserverOwnerCounts{}) {
		t.Fatalf("nil owner counts=%+v", got)
	}
	o := newPendingOutpointOwner(PendingOutpointTip{})
	o.reserveCalls, o.reservationsAcquired, o.finalizations, o.candidateReleases = 11, 12, 13, 14
	if got := DAObserverReadOwnerCounts(o); got != (DAObserverOwnerCounts{11, 12, 13, 14}) {
		t.Fatalf("owner counts=%+v", got)
	}
	stamped := selectRelayDisposition(txAdmitUnavailable("x"), RelayAdmissionCapacity)
	if DAObserverRelayDisposition(stamped) != RelayAdmissionCapacity || DAObserverRelayDisposition(nil) != relayDispositionOf(nil) {
		t.Fatal("relay disposition differs from relayDispositionOf")
	}

	f := newDANonReplayFixture(t, 4)
	DAObserverSetAdmitObserver(nil, func(DAObserverAdmitCall) {}) // a nil relay is a no-op
	var calls []DAObserverAdmitCall
	DAObserverSetAdmitObserver(f.relay, func(call DAObserverAdmitCall) { calls = append(calls, call) })
	for i, row := range []struct {
		provenance DAProvenance
		want       DAObserverProvenance
	}{
		{publicPeer(t, "p"), DAObserverProvenance{"PEER", "peer-p", "quota-p"}},
		{LocalDAProvenance(), DAObserverProvenance{Kind: "LOCAL"}},
		{DetachedReorgDAProvenance(), DAObserverProvenance{Kind: "DETACHED_REORG"}},
		{DAProvenance{}, DAObserverProvenance{Kind: "INVALID"}},
	} {
		calls = nil
		raw := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{0x40, byte(i)}, payload: []byte{byte(i)}}).raw
		result, err := f.relay.AdmitDA(raw, row.provenance)
		if len(calls) != 1 || calls[0] != (DAObserverAdmitCall{row.want, result, err}) {
			t.Fatalf("row %d observed %+v, want one {%+v %+v %v}", i, calls, row.want, result, err)
		}
	}
	calls = nil
	DAObserverSetAdmitObserver(f.relay, nil)
	f.relay.AdmitDA(nil, LocalDAProvenance())
	if len(calls) != 0 {
		t.Fatal("uninstalled observer was called")
	}
}

// daObserverImageFixture retains one State A, B and C record: A {0xA1} is a
// PEER orphan chunk, B {0xB1} a LOCAL staged commit, C {0xC1} a complete set.
func daObserverImageFixture(t *testing.T) (*daNonReplayFixture, map[[32]byte][]daNonReplayTx) {
	f := newDANonReplayFixture(t, 6)
	payload := []byte("image payload")
	txs := map[[32]byte][]daNonReplayTx{
		{0xA1}: {f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{0xA1}, payload: []byte("a")})},
		{0xB1}: {f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{0xB1}, chunkCount: 2, commitment: [32]byte{9}, commitmentOutputs: 1})},
		{0xC1}: {
			f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{0xC1}, chunkCount: 1, commitment: sha3.Sum256(payload), commitmentOutputs: 1}),
			f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{0xC1}, payload: payload}),
		},
	}
	for _, id := range [][32]byte{{0xA1}, {0xB1}, {0xC1}} {
		provenance := LocalDAProvenance()
		if id == [32]byte{0xA1} {
			provenance = publicPeer(t, "image")
		}
		for _, tx := range txs[id] {
			if _, err := f.relay.AdmitDA(tx.raw, provenance); err != nil {
				t.Fatalf("admit %x: %v", id, err)
			}
		}
	}
	return f, txs
}

// daObserverSyntheticImage builds live state in which every copied field has a
// distinct nonzero value, plus each Kind/Domain/State fallback, and the image
// the contract requires for it. A field sourced from its zero value or from a
// same-typed sibling therefore changes the image.
func daObserverSyntheticImage() (*DARelayState, DAObserverStateImage) {
	id := func(b byte) [32]byte { return [32]byte{b} }
	op := func(b byte, vout uint32) []consensus.Outpoint { return []consensus.Outpoint{{Txid: id(b), Vout: vout}} }
	o := newPendingOutpointOwner(PendingOutpointTip{})
	for _, c := range []*pendingOutpointClaim{
		{token: PendingOutpointToken{o, 3}, domain: PendingOutpointStandardMempool, txid: id(0x31), inputs: op(0x41, 5), generation: 7},
		{token: PendingOutpointToken{o, 9}, domain: PendingOutpointDA, txid: id(0x32), inputs: op(0x42, 6), generation: 8, finalized: true},
		{token: PendingOutpointToken{o, 4}, txid: id(0x33), inputs: op(0x41, 2), generation: 10},
	} {
		o.byToken[c.token] = c
		o.byOutpoint[c.inputs[0]] = pendingOutpointRow{token: c.token, txid: c.txid}
	}
	m1 := &daRelayMemberIdentity{id(0x71), id(0x72), consensus.Uint128{Lo: 141, Hi: 142}, op(0x73, 143), PendingOutpointToken{o, 144}, DAProvenance{daProvenancePeer, "pp", "qq"}}
	m2 := &daRelayMemberIdentity{id(0x74), id(0x75), consensus.Uint128{Lo: 145}, op(0x76, 146), PendingOutpointToken{o, 147}, DetachedReorgDAProvenance()}
	s := &DARelayState{
		mempool: &Mempool{pendingOutpoints: o}, nextReceivedTime: 101, stagedBytes: 102, completeBytes: 103, completeCount: 104,
		orphanBytes: 105, orphanCommitOverheadBytes: 106, pinnedPayloadBytes: 107, records: 108,
		orphanBytesByPeerQuotaKey: map[string]uint64{"k2": 112, "k1": 111}, orphanBytesByDAID: map[[32]byte]uint64{id(0x52): 114, id(0x51): 113},
		locators: map[[32]byte]daRelayLocator{id(0x81): {id(0x61), daRelayLocatorCommit, 0}, id(0x82): {id(0x61), daRelayLocatorChunk, 5}, id(0x83): {id(0x60), 7, 9}},
		sets: map[[32]byte]daRelaySetRecord{
			id(0x5E): {daID: id(0x5E)}, id(0x5F): {daID: id(0x5F), state: daRelayStateStagedCommit}, id(0x60): {daID: id(0x60), state: 9},
			id(0x61): {
				daID: id(0x61), state: daRelayStateCompleteSet, revision: 121, receivedTime: 122, payloadBytes: 123, wireBytes: 124, ttlBlocksRemaining: 125,
				completeIntrinsic: daCompleteCapacitySet{id(0x62), consensus.Uint128{Lo: 126, Hi: 127}, 128, 129, 130},
				commit:            daRelayCommit{id(0x63), id(0x64), "cq", m1, 131, 132, []byte{0xC1}},
				chunks: map[uint16]daRelayChunk{
					5: {id(0x65), id(0x66), "q5", m2, 5, []byte{0xD5}, 133, []byte{0xE5}, true},
					2: {daID: id(0x67), chunkHash: id(0x68), peerQuotaKey: "q2", chunkIndex: 2, wireBytes: 134, txBytes: []byte{0xE2}},
				},
				replaceableChunks: map[uint16]bool{7: true, 3: false},
			},
		},
	}
	return s, DAObserverStateImage{
		Records: []DAObserverRecord{{DAID: id(0x5E), State: "ORPHAN_CHUNKS"}, {DAID: id(0x5F), State: "STAGED_COMMIT"}, {DAID: id(0x60), State: "INVALID"}, {
			DAID: id(0x61), State: "COMPLETE_SET", Revision: 121, ReceivedTime: 122, PayloadBytes: 123, WireBytes: 124, TTLBlocksRemaining: 125,
			CompleteIntrinsic: DAObserverCapacitySet{id(0x62), consensus.Uint128{Lo: 126, Hi: 127}, 128, 129, 130},
			Commit:            DAObserverCommit{id(0x63), id(0x64), "cq", &DAObserverMember{id(0x71), id(0x72), consensus.Uint128{Lo: 141, Hi: 142}, op(0x73, 143), 144, DAObserverProvenance{"PEER", "pp", "qq"}}, 131, 132, []byte{0xC1}},
			Chunks: []DAObserverChunk{
				{DAID: id(0x67), ChunkHash: id(0x68), PeerQuotaKey: "q2", ChunkIndex: 2, WireBytes: 134, TxBytes: []byte{0xE2}},
				{id(0x65), id(0x66), "q5", &DAObserverMember{id(0x74), id(0x75), consensus.Uint128{Lo: 145}, op(0x76, 146), 147, DAObserverProvenance{Kind: "DETACHED_REORG"}}, 5, []byte{0xD5}, 133, []byte{0xE5}, true},
			},
			ReplaceableChunks: []DAObserverReplaceable{{3, false}, {7, true}},
		}},
		Locators:         []DAObserverLocator{{id(0x81), id(0x61), "COMMIT", 0}, {id(0x82), id(0x61), "CHUNK", 5}, {id(0x83), id(0x60), "INVALID", 9}},
		Claims:           []DAObserverClaim{{3, "STANDARD", id(0x31), op(0x41, 5), false, 7}, {4, "INVALID", id(0x33), op(0x41, 2), false, 10}, {9, "DA", id(0x32), op(0x42, 6), true, 8}},
		OutpointRows:     []DAObserverOutpointRow{{op(0x41, 2)[0], 4, id(0x33)}, {op(0x41, 5)[0], 3, id(0x31)}, {op(0x42, 6)[0], 9, id(0x32)}},
		NextReceivedTime: 101, StagedBytes: 102, CompleteBytes: 103, CompleteCount: 104, OrphanBytes: 105, OrphanCommitOverheadBytes: 106, PinnedPayloadBytes: 107, RecordRevisionHighWater: 108,
		OrphanBytesByPeerQuotaKey: []DAObserverKeyBytes{{"k1", 111}, {"k2", 112}},
		OrphanBytesByDAID:         []DAObserverIDBytes{{id(0x51), 113}, {id(0x52), 114}},
	}
}

func TestDAObserverConformanceStateImage(t *testing.T) {
	s, want := daObserverSyntheticImage()
	image, err := DAObserverReadStateImage(s)
	if err != nil || !reflect.DeepEqual(image, want) {
		t.Fatalf("image (err=%v):\n got %+v\nwant %+v", err, image, want)
	}
	flip := func(b []byte) {
		if len(b) != 0 {
			b[0] ^= 0xff
		}
	}
	for _, r := range image.Records {
		flip(r.Commit.TxBytes)
		members := []*DAObserverMember{r.Commit.Member}
		for _, chunk := range r.Chunks {
			flip(chunk.TxBytes)
			flip(chunk.Payload)
			members = append(members, chunk.Member)
		}
		for _, m := range members {
			if m != nil {
				m.Inputs[0].Vout++
			}
		}
	}
	for _, c := range image.Claims {
		c.Inputs[0].Vout++
	}
	if again, _ := DAObserverReadStateImage(s); !reflect.DeepEqual(again, want) {
		t.Fatal("mutating an image changed live state")
	}

	// Admitted State A, B and C records reach the image with their retained bytes.
	f, txs := daObserverImageFixture(t)
	image, err = DAObserverReadStateImage(f.relay)
	if err != nil || len(image.Records) != 3 {
		t.Fatalf("admitted image=%+v err=%v", image, err)
	}
	for i, r := range image.Records {
		var raws [][]byte
		if r.Commit.TxBytes != nil {
			raws = append(raws, r.Commit.TxBytes)
		}
		for _, chunk := range r.Chunks {
			raws = append(raws, chunk.TxBytes)
		}
		if r.State != []string{"ORPHAN_CHUNKS", "STAGED_COMMIT", "COMPLETE_SET"}[i] || !slices.EqualFunc(raws, txs[r.DAID], func(raw []byte, tx daNonReplayTx) bool { return bytes.Equal(raw, tx.raw) }) {
			t.Fatalf("admitted record %x=%+v", r.DAID, r)
		}
	}

	for name, relay := range map[string]*DARelayState{
		"nil relay": nil, "nil mempool": {sets: s.sets, locators: s.locators}, "nil owner": {mempool: &Mempool{}, sets: s.sets, locators: s.locators},
		"nil sets": {mempool: f.mp, locators: s.locators}, "nil locators": {mempool: f.mp, sets: s.sets},
	} {
		if got, err := DAObserverReadStateImage(relay); err == nil || !reflect.DeepEqual(got, DAObserverStateImage{}) {
			t.Fatalf("%s: image=%+v err=%v", name, got, err)
		}
	}
}

func TestDAObserverConformanceInjectors(t *testing.T) {
	if err := DAObserverInjectRetainedFault(nil, [32]byte{1}, DAObserverFaultLocatorDangling); err == nil {
		t.Fatal("nil relay injection succeeded")
	}
	for _, row := range []struct {
		name  string
		fault DAObserverRetainedFault
		want  RelayAdmissionDisposition
	}{
		{"owner unavailable", DAObserverFaultOwnerUnavailable, RelayAdmissionUnavailable},
		{"locator dangling", DAObserverFaultLocatorDangling, RelayAdmissionInternal},
		{"retained raw malformed", DAObserverFaultRetainedRawMalformed, RelayAdmissionInternal},
		{"admission wtxid mismatch", DAObserverFaultAdmissionWTxIDMismatch, RelayAdmissionInternal},
	} {
		for target, name := range []string{"commit", "chunk"} {
			t.Run(row.name+" on "+name, func(t *testing.T) {
				f := newDANonReplayFixture(t, 2)
				commit := f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{0xD1}, chunkCount: 2, commitment: [32]byte{9}, commitmentOutputs: 1})
				chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{0xD1}, payload: []byte("fault")})
				for _, tx := range []daNonReplayTx{commit, chunk} {
					if _, err := f.relay.AdmitDA(tx.raw, LocalDAProvenance()); err != nil {
						t.Fatal(err)
					}
				}
				before := daRelayStateSnapshot(f.relay)
				if err := DAObserverInjectRetainedFault(f.relay, [32]byte{0xEE}, row.fault); err == nil {
					t.Fatal("unlocated injection succeeded")
				}
				if got := daRelayStateSnapshot(f.relay); !reflect.DeepEqual(got, before) { //nolint:govet // Complete private state-image equality is the assertion.
					t.Fatal("unlocated injection changed state")
				}
				for _, tx := range []daNonReplayTx{commit, chunk} {
					if result, err := f.relay.AdmitDA(tx.raw, LocalDAProvenance()); err != nil || result.Disposition != DAAdmissionDuplicate {
						t.Fatalf("before injection replay=(%+v,%v)", result, err)
					}
				}
				located := []daNonReplayTx{commit, chunk}[target]
				if err := DAObserverInjectRetainedFault(f.relay, located.txid, row.fault); err != nil {
					t.Fatal(err)
				}
				if result, err := f.relay.AdmitDA(located.raw, LocalDAProvenance()); err == nil || DAObserverRelayDisposition(err) != row.want {
					t.Fatalf("after %s replay=(%+v,%v), want disposition %d", row.name, result, err, row.want)
				}
			})
		}
	}
	t.Run("owner transition", func(t *testing.T) {
		f := newDANonReplayFixture(t, 2)
		chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{0xD2}, payload: []byte("transition")})
		if end, err := DAObserverBeginOwnerTransition(nil); err == nil || end != nil {
			t.Fatal("nil owner transition reported success")
		}
		end, err := DAObserverBeginOwnerTransition(f.mp.pendingOutpoints)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := f.relay.AdmitDA(chunk.raw, LocalDAProvenance()); DAObserverRelayDisposition(err) != RelayAdmissionUnavailable {
			t.Fatalf("during transition=(%+v,%v)", result, err)
		}
		end()
		result, err := f.relay.AdmitDA(chunk.raw, LocalDAProvenance())
		requirePublicDAResult(t, result, err, DAAdmissionResult{DAID: [32]byte{0xD2}, Disposition: DAAdmissionRetained})
	})
}

func TestDAObserverConformanceConcurrentAndReentrant(t *testing.T) {
	const admissions = 8
	f := newDANonReplayFixture(t, admissions+1)
	raws := make([][]byte, admissions)
	for i := range raws {
		raws[i] = f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{0x30, byte(i)}, payload: []byte{byte(i)}}).raw
	}
	o := f.mp.pendingOutpoints
	var mu sync.Mutex
	seen := map[[32]byte]int{}
	DAObserverSetAdmitObserver(f.relay, func(call DAObserverAdmitCall) {
		// Re-entrant reads from inside the callback must not deadlock.
		if _, err := DAObserverReadStateImage(f.relay); err != nil {
			t.Error(err)
		}
		DAObserverReadOwnerCounts(o)
		mu.Lock()
		seen[call.Result.DAID]++
		mu.Unlock()
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var admitters, readers sync.WaitGroup
		stop := make(chan struct{})
		for range 2 {
			readers.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
						DAObserverReadStateImage(f.relay)
						DAObserverReadOwnerCounts(o)
					}
				}
			})
		}
		for _, raw := range raws {
			admitters.Go(func() {
				if result, err := f.relay.AdmitDA(raw, LocalDAProvenance()); err != nil || result.Disposition != DAAdmissionRetained {
					t.Errorf("concurrent admit=(%+v,%v)", result, err)
				}
			})
		}
		admitters.Wait()
		close(stop)
		readers.Wait()
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("observer or readers deadlocked")
	}
	if len(seen) != admissions || slices.ContainsFunc(slices.Collect(maps.Values(seen)), func(n int) bool { return n != 1 }) {
		t.Fatalf("observations=%v, want each of %d admissions exactly once", seen, admissions)
	}
}
