//go:build rubin_da_observer

package node

import (
	"bytes"
	"cmp"
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
	mustReserve(t, o, [32]byte{1}, consensus.Outpoint{Txid: [32]byte{1}})
	if got := DAObserverReadOwnerCounts(o); got != (DAObserverOwnerCounts{ReserveCalls: 1, ReservationsAcquired: 1}) {
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

// requireDAObserverMember checks an image member against the fixture tx and the live member.
func requireDAObserverMember(t *testing.T, got *DAObserverMember, live *daRelayMemberIdentity, tx daNonReplayTx, kind string) {
	t.Helper()
	if got == nil || live == nil || got.TxID != tx.txid || got.WTxID != tx.wtxid || got.Fee != tx.spec.fee || !slices.Equal(got.Inputs, tx.inputs) ||
		got.TokenSeq != live.token.seq || got.Provenance != (DAObserverProvenance{kind, live.provenance.peerIdentity, live.provenance.quotaIdentity}) {
		t.Fatalf("member=%+v live=%+v tx=%x", got, live, tx.txid)
	}
}

func TestDAObserverConformanceStateImage(t *testing.T) {
	f, txs := daObserverImageFixture(t)
	s, o := f.relay, f.mp.pendingOutpoints
	image, err := DAObserverReadStateImage(s)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(image.Records, []string{"ORPHAN_CHUNKS", "STAGED_COMMIT", "COMPLETE_SET"}, func(r DAObserverRecord, state string) bool { return r.State == state }) {
		t.Fatalf("records=%+v", image.Records)
	}
	for _, r := range image.Records {
		live, tx, kind := s.sets[r.DAID], txs[r.DAID], "LOCAL"
		if r.DAID == [32]byte{0xA1} {
			kind = "PEER"
		}
		c := live.completeIntrinsic
		if r.Revision != live.revision || r.ReceivedTime != live.receivedTime || r.PayloadBytes != live.payloadBytes || r.WireBytes != live.wireBytes || r.TTLBlocksRemaining != live.ttlBlocksRemaining ||
			r.CompleteIntrinsic != (DAObserverCapacitySet{c.id, c.fee, c.totalBytes, c.payloadBytes, c.receivedSequence}) || len(r.ReplaceableChunks) != len(live.replaceableChunks) {
			t.Fatalf("record %x header=%+v live=%+v", r.DAID, r, live)
		}
		commit, chunks := r.Commit, r.Chunks
		if tx[0].spec.kind == 1 {
			if commit.DAID != live.commit.daID || commit.PayloadCommitment != tx[0].spec.commitment || commit.ChunkCount != tx[0].spec.chunkCount || commit.PeerQuotaKey != live.commit.peerQuotaKey || commit.WireBytes != live.commit.wireBytes || !bytes.Equal(commit.TxBytes, tx[0].raw) {
				t.Fatalf("record %x commit=%+v", r.DAID, commit)
			}
			requireDAObserverMember(t, commit.Member, live.commit.member, tx[0], "LOCAL")
			tx = tx[1:]
		} else if commit.Member != nil || commit.TxBytes != nil {
			t.Fatalf("record %x has an empty commit slot image %+v", r.DAID, commit)
		}
		if len(chunks) != len(tx) || len(live.chunks) != len(tx) {
			t.Fatalf("record %x chunks=%d want %d", r.DAID, len(chunks), len(tx))
		}
		for i, chunk := range chunks {
			l := live.chunks[chunk.ChunkIndex]
			if chunk.DAID != l.daID || chunk.ChunkHash != sha3.Sum256(tx[i].spec.payload) || chunk.PeerQuotaKey != l.peerQuotaKey || chunk.ChunkIndex != tx[i].spec.chunkIndex ||
				!bytes.Equal(chunk.Payload, l.payload) || (chunk.Payload == nil) != (l.payload == nil) || chunk.WireBytes != l.wireBytes || !bytes.Equal(chunk.TxBytes, tx[i].raw) || chunk.HashChecked != l.hashChecked {
				t.Fatalf("record %x chunk=%+v live=%+v", r.DAID, chunk, l)
			}
			requireDAObserverMember(t, chunk.Member, l.member, tx[i], kind)
		}
	}
	if (image.NextReceivedTime != s.nextReceivedTime || image.StagedBytes != s.stagedBytes || image.CompleteBytes != s.completeBytes || image.CompleteCount != s.completeCount) ||
		(image.OrphanBytes != s.orphanBytes || image.OrphanCommitOverheadBytes != s.orphanCommitOverheadBytes || image.PinnedPayloadBytes != s.pinnedPayloadBytes || image.RecordRevisionHighWater != s.records) || image.CompleteCount != 1 || image.OrphanBytes == 0 {
		t.Fatalf("image scalars=%+v", image)
	}
	if len(image.Locators) != len(s.locators) || !slices.IsSortedFunc(image.Locators, func(a, b DAObserverLocator) int { return bytes.Compare(a.TxID[:], b.TxID[:]) }) {
		t.Fatalf("locators=%+v", image.Locators)
	}
	for _, l := range image.Locators {
		live := s.locators[l.TxID]
		if l.DAID != live.daID || l.ChunkIndex != live.chunkIndex || l.Kind != map[daRelayLocatorKind]string{daRelayLocatorCommit: "COMMIT", daRelayLocatorChunk: "CHUNK"}[live.kind] {
			t.Fatalf("locator=%+v live=%+v", l, live)
		}
	}
	if len(image.Claims) != len(o.byToken) || len(image.Claims) != 4 || !slices.IsSortedFunc(image.Claims, func(a, b DAObserverClaim) int { return cmp.Compare(a.TokenSeq, b.TokenSeq) }) {
		t.Fatalf("claims=%+v", image.Claims)
	}
	for _, c := range image.Claims {
		live := o.byToken[PendingOutpointToken{owner: o, seq: c.TokenSeq}]
		if live == nil || c.Domain != "DA" || c.TxID != live.txid || !slices.Equal(c.Inputs, live.inputs) || c.Finalized != live.finalized || c.Generation != live.generation {
			t.Fatalf("claim=%+v live=%+v", c, live)
		}
	}
	if len(image.OutpointRows) != len(o.byOutpoint) || !slices.IsSortedFunc(image.OutpointRows, func(a, b DAObserverOutpointRow) int { return compareDAObserverOutpoint(a.Outpoint, b.Outpoint) }) {
		t.Fatalf("outpoint rows=%+v", image.OutpointRows)
	}
	for _, row := range image.OutpointRows {
		if live := o.byOutpoint[row.Outpoint]; row.TokenSeq != live.token.seq || row.TxID != live.txid {
			t.Fatalf("outpoint row=%+v live=%+v", row, live)
		}
	}
	peer := map[string]uint64{}
	for _, row := range image.OrphanBytesByPeerQuotaKey {
		peer[row.Key] = row.Bytes
	}
	daid := map[[32]byte]uint64{}
	for _, row := range image.OrphanBytesByDAID {
		daid[row.DAID] = row.Bytes
	}
	if !maps.Equal(peer, s.orphanBytesByPeerQuotaKey) || !maps.Equal(daid, s.orphanBytesByDAID) || len(peer) == 0 {
		t.Fatalf("orphan charges peer=%v daid=%v", peer, daid)
	}

	second, _ := DAObserverReadStateImage(s)
	liveBefore, ownerBefore := daRelayStateSnapshot(s), cloneDAAdmissionOwner(o)
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
	requireDANonReplayUnchanged(t, s, o, liveBefore, ownerBefore)
	if third, _ := DAObserverReadStateImage(s); !reflect.DeepEqual(third, second) {
		t.Fatal("mutating an image changed a later read")
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
		t.Run(row.name, func(t *testing.T) {
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
			if err := DAObserverInjectRetainedFault(f.relay, chunk.txid, row.fault); err != nil {
				t.Fatal(err)
			}
			if result, err := f.relay.AdmitDA(chunk.raw, LocalDAProvenance()); err == nil || DAObserverRelayDisposition(err) != row.want {
				t.Fatalf("after %s replay=(%+v,%v), want disposition %d", row.name, result, err, row.want)
			}
		})
	}
	t.Run("owner transition", func(t *testing.T) {
		f := newDANonReplayFixture(t, 2)
		chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{0xD2}, payload: []byte("transition")})
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
