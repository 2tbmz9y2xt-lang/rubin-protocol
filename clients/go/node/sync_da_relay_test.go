package node

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// TestCanonicalDASetIdentitiesFromParsedBlock pins I: the exact identities are
// derived from the block's OWN parse and its aligned txid/wtxid arrays, in
// block/transaction order, with chunks strictly ascending — and only for sets
// the existing completeness rule calls complete.
func TestCanonicalDASetIdentitiesFromParsedBlock(t *testing.T) {
	head, tail := []byte("head"), []byte("tail")
	first, second := daExtractionTestID(0x21), daExtractionTestID(0x22)
	block := daExtractionBlockBytes(t,
		daExtractionChunkTxBytes(t, second, 0, 11, head),
		daExtractionCommitTxBytes(t, first, 12, head, tail),
		daExtractionChunkTxBytes(t, first, 1, 13, tail),
		daExtractionCommitTxBytes(t, second, 14, head),
		daExtractionChunkTxBytes(t, first, 0, 15, head),
	)
	parsed, err := consensus.ParseBlockBytes(block)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	identities, err := canonicalDASetIdentitiesFromParsedBlock(parsed)
	if err != nil {
		t.Fatalf("canonicalDASetIdentitiesFromParsedBlock: %v", err)
	}
	// second's first member (its chunk) precedes first's, so second leads.
	if len(identities) != 2 || identities[0].daID != second || identities[1].daID != first {
		t.Fatalf("identities=%+v, want block/transaction order [second, first]", identities)
	}
	// Every part comes from the parsed arrays at that member's own index.
	want := canonicalDASetIdentity{
		daID:   first,
		commit: canonicalDATxIdentity{txid: parsed.Txids[2], wtxid: parsed.Wtxids[2]},
		chunks: []canonicalDAChunkIdentity{
			{canonicalDATxIdentity: canonicalDATxIdentity{txid: parsed.Txids[5], wtxid: parsed.Wtxids[5]}, index: 0},
			{canonicalDATxIdentity: canonicalDATxIdentity{txid: parsed.Txids[3], wtxid: parsed.Wtxids[3]}, index: 1},
		},
	}
	if !reflect.DeepEqual(identities[1], want) {
		t.Fatalf("identity=%+v, want %+v", identities[1], want)
	}

	// An incomplete set and a two-commit set contribute nothing, by the same
	// completeness rule A1 uses.
	for name, txs := range map[string][][]byte{
		"missing chunk":     {daExtractionCommitTxBytes(t, first, 21, head, tail), daExtractionChunkTxBytes(t, first, 0, 22, head)},
		"duplicate commit":  {daExtractionCommitTxBytes(t, first, 23, head), daExtractionCommitTxBytes(t, first, 24, head), daExtractionChunkTxBytes(t, first, 0, 25, head)},
		"chunk without set": {daExtractionChunkTxBytes(t, first, 0, 26, head)},
	} {
		incomplete, err := consensus.ParseBlockBytes(daExtractionBlockBytes(t, txs...))
		if err != nil {
			t.Fatalf("%s: ParseBlockBytes: %v", name, err)
		}
		got, err := canonicalDASetIdentitiesFromParsedBlock(incomplete)
		if err != nil || len(got) != 0 {
			t.Fatalf("%s: identities=%+v err=%v, want none", name, got, err)
		}
	}
}

// TestCanonicalDASetIdentityEqualIsExact pins that equality is total over
// da_id, the commit's txid AND wtxid, and the ordered chunk list. Dropping any
// part would make a reusable da_id, or a witness-different resident, look like
// an inclusion.
func TestCanonicalDASetIdentityEqualIsExact(t *testing.T) {
	base := canonicalDASetIdentity{
		daID:   daRelayTestID(0x31),
		commit: canonicalDATxIdentity{txid: [32]byte{1}, wtxid: [32]byte{2}},
		chunks: []canonicalDAChunkIdentity{
			{canonicalDATxIdentity: canonicalDATxIdentity{txid: [32]byte{3}, wtxid: [32]byte{4}}, index: 0},
		},
	}
	same := base
	same.chunks = append([]canonicalDAChunkIdentity(nil), base.chunks...)
	if !canonicalDASetIdentityEqual(base, same) {
		t.Fatal("an identical identity did not compare equal")
	}
	for name, mutate := range map[string]func(*canonicalDASetIdentity){
		"da_id":          func(id *canonicalDASetIdentity) { id.daID[0] ^= 0xff },
		"commit txid":    func(id *canonicalDASetIdentity) { id.commit.txid[0] ^= 0xff },
		"commit wtxid":   func(id *canonicalDASetIdentity) { id.commit.wtxid[0] ^= 0xff },
		"chunk txid":     func(id *canonicalDASetIdentity) { id.chunks[0].txid[0] ^= 0xff },
		"chunk wtxid":    func(id *canonicalDASetIdentity) { id.chunks[0].wtxid[0] ^= 0xff },
		"chunk index":    func(id *canonicalDASetIdentity) { id.chunks[0].index++ },
		"one more chunk": func(id *canonicalDASetIdentity) { id.chunks = append(id.chunks, id.chunks[0]) },
		"no chunks":      func(id *canonicalDASetIdentity) { id.chunks = nil },
	} {
		other := base
		other.chunks = append([]canonicalDAChunkIdentity(nil), base.chunks...)
		mutate(&other)
		if canonicalDASetIdentityEqual(base, other) {
			t.Fatalf("a differing %s still compared equal", name)
		}
	}
}

// canonicalDATestSet is one retained DA set whose members are real signed
// transactions against the fixture's chain, so the transition can both parse
// them and decide their chain validity for real.
type canonicalDATestSet struct {
	daID     [32]byte
	commit   []byte
	chunks   [][]byte
	payloads [][]byte
}

// daSet builds and retains one complete DA set, spending ops[0] for the commit
// and ops[i+1] for chunk i.
func (f *canonicalMOFixture) daSet(t *testing.T, relay *DARelayState, daID [32]byte, ops []consensus.Outpoint, nonce uint64) canonicalDATestSet {
	t.Helper()
	set := canonicalDATestSet{daID: daID}
	hasher := sha3.New256()
	for i := 1; i < len(ops); i++ {
		payload := []byte{daID[0], byte(i)}
		set.payloads = append(set.payloads, payload)
		_, _ = hasher.Write(payload)
		set.chunks = append(set.chunks, f.daChunkTx(t, ops[i], daID, uint16(i-1), nonce+uint64(i), payload))
	}
	var commitment [32]byte
	copy(commitment[:], hasher.Sum(nil))
	set.commit = f.daCommitTx(t, ops[0], daID, uint16(len(set.chunks)), nonce)
	if err := relay.StageCommit("peer-commit", DARelayCommit{
		DAID: daID, PayloadCommitment: commitment, ChunkCount: uint16(len(set.chunks)),
		WireBytes: uint64(len(set.commit)), TxBytes: set.commit,
	}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
	for i, chunkTx := range set.chunks {
		if err := relay.StageChunk("peer-chunk", DARelayChunk{
			DAID: daID, ChunkHash: sha3.Sum256(set.payloads[i]), ChunkIndex: uint16(i), Payload: set.payloads[i],
			WireBytes: uint64(len(chunkTx)), TxBytes: chunkTx,
		}); err != nil {
			t.Fatalf("StageChunk(%d): %v", i, err)
		}
	}
	return set
}

// daCommitTx is the signed DA commit shape mustBuildSignedDaCommitTxWithChunkCount
// builds, with the set's own da_id bound into its core — which the shared helper
// leaves zero and a retained record's role check will not accept.
func (f *canonicalMOFixture) daCommitTx(t *testing.T, op consensus.Outpoint, daID [32]byte, chunkCount uint16, nonce uint64) []byte {
	t.Helper()
	tx := &consensus.Tx{
		Version: 1, TxKind: 0x01, TxNonce: nonce,
		Inputs:       []consensus.TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout}},
		Outputs:      []consensus.TxOutput{{Value: 100_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...)}},
		DaPayload:    []byte("manifest"),
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: chunkCount, BatchNumber: 1},
	}
	mustCanonicalMO(t, "SignTransaction(da commit)", consensus.SignTransaction(tx, f.engine.chainState.Utxos, devnetGenesisChainID, f.signer))
	return mustMarshalTxForNodeTest(t, tx)
}

func (f *canonicalMOFixture) daChunkTx(t *testing.T, op consensus.Outpoint, daID [32]byte, index uint16, nonce uint64, payload []byte) []byte {
	t.Helper()
	tx := &consensus.Tx{
		Version: 1, TxKind: 0x02, TxNonce: nonce,
		Inputs:      []consensus.TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout}},
		Outputs:     []consensus.TxOutput{{Value: 100_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...)}},
		DaPayload:   append([]byte(nil), payload...),
		DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: sha3.Sum256(payload)},
	}
	mustCanonicalMO(t, "SignTransaction(da chunk)", consensus.SignTransaction(tx, f.engine.chainState.Utxos, devnetGenesisChainID, f.signer))
	return mustMarshalTxForNodeTest(t, tx)
}

// canonicalDATestChain is the captured C1 context these unit rows validate
// against: the fixture's own live chain image, the shared rotation cache, and no
// pool-local policy at all.
func (f *canonicalMOFixture) canonicalDATestChain(t *testing.T) canonicalFinalChainContext {
	t.Helper()
	final := cloneChainState(f.engine.chainState)
	view := final.view()
	nextHeight, _, err := nextBlockContextFromFields(view.hasTip, view.height, view.tipHash)
	mustCanonicalMO(t, "nextBlockContextFromFields", err)
	return canonicalFinalChainContext{
		final:      final,
		rotation:   newCanonicalMempoolRotationCache(nil),
		policy:     MempoolConfig{},
		chainID:    devnetGenesisChainID,
		nextHeight: nextHeight,
	}
}

// identitiesOf renders the exact identities a block carrying these transactions
// would contribute to I.
func identitiesOf(t *testing.T, txs ...[]byte) []canonicalDASetIdentity {
	t.Helper()
	parsed, err := consensus.ParseBlockBytes(daExtractionBlockBytes(t, txs...))
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	identities, err := canonicalDASetIdentitiesFromParsedBlock(parsed)
	if err != nil {
		t.Fatalf("canonicalDASetIdentitiesFromParsedBlock: %v", err)
	}
	return identities
}

func mustPrepareCanonicalDAImage(t *testing.T, relay *DARelayState, included []canonicalDASetIdentity, chain canonicalFinalChainContext) *preparedCanonicalDAImage {
	t.Helper()
	image, err := prepareCanonicalDAImage(relay, included, chain)
	if err != nil {
		t.Fatalf("prepareCanonicalDAImage: %v", err)
	}
	return image
}

// TestCanonicalDAImageExactInclusionSelection pins that ONLY an exact identity
// match removes a resident, that it removes it once, and that every near-miss —
// a different wtxid under the same txid, a different chunk identity, a shorter
// chunk list, or no match at all — is a no-op.
func TestCanonicalDAImageExactInclusionSelection(t *testing.T) {
	f := newCanonicalMOFixture(t, 3, MempoolConfig{})
	relay := f.engine.DARelayState()
	daID := daRelayTestID(0x41)
	set := f.daSet(t, relay, daID, f.ops[:3], 700)
	chain := f.canonicalDATestChain(t)
	exact := identitiesOf(t, append([][]byte{set.commit}, set.chunks...)...)
	if len(exact) != 1 {
		t.Fatalf("block identities=%d, want the one staged set", len(exact))
	}
	other := f.daChunkTx(t, f.ops[1], daID, 0, 999, []byte("different-witness"))

	for _, tc := range []struct {
		name     string
		included []canonicalDASetIdentity
		removed  bool
	}{
		{name: "no inclusion at all is a no-op", included: nil},
		{name: "exact identity removes the resident", included: exact, removed: true},
		{name: "duplicate exact occurrences remove it once", included: append(append([]canonicalDASetIdentity(nil), exact...), exact...), removed: true},
		{name: "same da_id with a different chunk identity remains", included: identitiesOf(t, set.commit, other)},
		{name: "same members with a mutated commit wtxid remains", included: mutatedIdentities(exact, func(id *canonicalDASetIdentity) { id.commit.wtxid[0] ^= 0xff })},
		{name: "same members with a mutated commit txid remains", included: mutatedIdentities(exact, func(id *canonicalDASetIdentity) { id.commit.txid[0] ^= 0xff })},
		{name: "a shorter chunk list remains", included: mutatedIdentities(exact, func(id *canonicalDASetIdentity) { id.chunks = id.chunks[:1] })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := mustPrepareCanonicalDAImage(t, relay, tc.included, chain)
			_, present := image.projected.sets[daID]
			if present == tc.removed {
				t.Fatalf("resident present=%v, want removed=%v", present, tc.removed)
			}
			// The live image is untouched until publication, whatever the plan says.
			if _, live := relay.sets[daID]; !live {
				t.Fatal("preparation mutated the live retained-DA image")
			}
		})
	}
}

// TestCanonicalDAImageRemovesEveryIncludedIdentity is A6's "many": ONE plan
// carrying three DISTINCT exact identities removes all three residents and only
// those. Every record here is chain-valid, so no validity arm can supply a
// removal, and the fourth resident excludes "the plan is non-empty, drop all".
func TestCanonicalDAImageRemovesEveryIncludedIdentity(t *testing.T) {
	f := newCanonicalMOFixture(t, 8, MempoolConfig{})
	relay := f.engine.DARelayState()
	ids := [][32]byte{daRelayTestID(0x44), daRelayTestID(0x45), daRelayTestID(0x46), daRelayTestID(0x47)}
	var carried [][]byte
	for i, daID := range ids {
		set := f.daSet(t, relay, daID, f.ops[2*i:2*i+2], 720+uint64(i)*10)
		if i < 3 {
			carried = append(carried, set.commit, set.chunks[0])
		}
	}
	included := identitiesOf(t, carried...)
	if len(included) != 3 {
		t.Fatalf("block identities=%d, want the three distinct included sets", len(included))
	}
	image := mustPrepareCanonicalDAImage(t, relay, included, f.canonicalDATestChain(t))
	if _, kept := image.projected.sets[ids[3]]; !kept || len(image.projected.sets) != 1 {
		t.Fatalf("projected residents=%d uncarried set kept=%v, want the three included ones gone and only it left", len(image.projected.sets), kept)
	}
}

func mutatedIdentities(identities []canonicalDASetIdentity, mutate func(*canonicalDASetIdentity)) []canonicalDASetIdentity {
	out := make([]canonicalDASetIdentity, len(identities))
	for i := range identities {
		out[i] = identities[i]
		out[i].chunks = append([]canonicalDAChunkIdentity(nil), identities[i].chunks...)
		mutate(&out[i])
	}
	return out
}

// TestCanonicalDAImageFinalChainValidity pins the validity half of D1: a record
// whose every member is chain-valid stays even though the standard mempool holds
// no record for it at all, one final-invalid member removes the WHOLE record,
// and corrupt retained state takes the terminal lane instead — including when an
// earlier member of the same record was merely invalid.
func TestCanonicalDAImageFinalChainValidity(t *testing.T) {
	t.Run("every member valid keeps the record without consulting M1", func(t *testing.T) {
		f := newCanonicalMOFixture(t, 3, MempoolConfig{})
		relay := f.engine.DARelayState()
		daID := daRelayTestID(0x51)
		f.daSet(t, relay, daID, f.ops[:3], 800)
		if len(f.mp.txs) != 0 {
			t.Fatal("the standard mempool must hold no record for these members")
		}
		image := mustPrepareCanonicalDAImage(t, relay, nil, f.canonicalDATestChain(t))
		if _, present := image.projected.sets[daID]; !present {
			t.Fatal("a fully chain-valid record was removed while absent from M1")
		}
	})

	// D1 scans ALL of S0.DA, not just its complete sets. Survival alone would NOT
	// prove that — a scan that skipped incomplete records keeps them too — so the
	// row also drives the same record to final-invalid and requires its removal.
	t.Run("an incomplete record is scanned like any other", func(t *testing.T) {
		f := newCanonicalMOFixture(t, 2, MempoolConfig{})
		relay, daID, payload := f.engine.DARelayState(), daRelayTestID(0x55), []byte{0x55}
		chunkTx := f.daChunkTx(t, f.ops[1], daID, 0, 870, payload)
		mustCanonicalMO(t, "StageChunk", relay.StageChunk("peer-orphan", DARelayChunk{
			DAID: daID, ChunkHash: sha3.Sum256(payload), Payload: payload,
			WireBytes: uint64(len(chunkTx)), TxBytes: chunkTx,
		}))
		if got := relay.sets[daID].state; got != daRelayStateOrphanChunks {
			t.Fatalf("fixture record state=%v, want an INCOMPLETE record", got)
		}
		chain := f.canonicalDATestChain(t)
		if _, present := mustPrepareCanonicalDAImage(t, relay, nil, chain).projected.sets[daID]; !present {
			t.Fatal("an incomplete chain-valid record was dropped")
		}
		chain.final.mu.Lock()
		delete(chain.final.Utxos, f.ops[1])
		chain.final.mu.Unlock()
		if _, present := mustPrepareCanonicalDAImage(t, relay, nil, chain).projected.sets[daID]; present {
			t.Fatal("an incomplete final-invalid record survived: the scan skips incomplete records")
		}
	})

	// The first terminal record in ASCENDING RAW da_id order wins, whatever the
	// map's iteration order happens to be on this run.
	t.Run("the lowest raw da_id terminal record wins", func(t *testing.T) {
		f := newCanonicalMOFixture(t, 3, MempoolConfig{})
		relay := f.engine.DARelayState()
		low, high := daRelayTestID(0x01), daRelayTestID(0xfe)
		f.daSet(t, relay, low, f.ops[:2], 880)
		f.daSet(t, relay, high, f.ops[1:3], 890)
		for _, daID := range [][32]byte{low, high} {
			record := relay.sets[daID].cloneForStateMutation()
			record.commit.chunkCount = 9 // contradicts the retained commit tx
			relay.sets[daID] = record
		}
		_, err := prepareCanonicalDAImage(relay, nil, f.canonicalDATestChain(t))
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%x", low)) {
			t.Fatalf("err=%v, want the lowest raw da_id record's terminal evidence", err)
		}
		if strings.Contains(err.Error(), fmt.Sprintf("%x", high)) {
			t.Fatalf("err=%v names the later record", err)
		}
	})

	t.Run("one final-invalid member removes the whole record", func(t *testing.T) {
		f := newCanonicalMOFixture(t, 3, MempoolConfig{})
		relay := f.engine.DARelayState()
		daID := daRelayTestID(0x52)
		f.daSet(t, relay, daID, f.ops[:3], 810)
		chain := f.canonicalDATestChain(t)
		// The LAST member's input leaves C1: only that member becomes invalid.
		chain.final.mu.Lock()
		delete(chain.final.Utxos, f.ops[2])
		chain.final.mu.Unlock()
		image := mustPrepareCanonicalDAImage(t, relay, nil, chain)
		if _, present := image.projected.sets[daID]; present {
			t.Fatal("a record with a final-invalid member survived")
		}
	})

	for _, tc := range []struct {
		name    string
		corrupt func(record *daRelaySetRecord)
	}{
		{"commit bytes are gone", func(r *daRelaySetRecord) { r.commit.txBytes = nil }},
		{"commit bytes do not parse", func(r *daRelaySetRecord) { r.commit.txBytes = []byte{0xff, 0xfe} }},
		{"commit bytes have trailing bytes", func(r *daRelaySetRecord) { r.commit.txBytes = append(append([]byte(nil), r.commit.txBytes...), 0x00) }},
		{"a chunk is stored at the wrong index", func(r *daRelaySetRecord) {
			chunk := r.chunks[0]
			delete(r.chunks, 0)
			chunk.chunkIndex = 1
			r.chunks[1] = chunk
		}},
		{"the commit declares another chunk count", func(r *daRelaySetRecord) { r.commit.chunkCount = 7 }},
		{"the commit slot holds a chunk transaction", func(r *daRelaySetRecord) { r.commit.txBytes = r.chunks[0].txBytes }},
		{"a chunk slot holds the commit transaction", func(r *daRelaySetRecord) {
			chunk := r.chunks[0]
			chunk.txBytes = r.commit.txBytes
			r.chunks[0] = chunk
		}},
		// H2: the LAST member of the three, reached only by a walk that does not
		// stop at the first valid one.
		{"the last member's bytes do not parse", func(r *daRelaySetRecord) {
			chunk := r.chunks[1]
			chunk.txBytes = []byte{0xff, 0xfe}
			r.chunks[1] = chunk
		}},
	} {
		t.Run("terminal: "+tc.name, func(t *testing.T) {
			f := newCanonicalMOFixture(t, 3, MempoolConfig{})
			relay := f.engine.DARelayState()
			daID := daRelayTestID(0x53)
			f.daSet(t, relay, daID, f.ops[:3], 820)
			chain := f.canonicalDATestChain(t)
			// Every member is ALSO made chain-invalid, so a preparation that
			// preferred the removal decision would silently pass this row.
			chain.final.mu.Lock()
			for _, op := range f.ops[:3] {
				delete(chain.final.Utxos, op)
			}
			chain.final.mu.Unlock()
			before := daRelayStateSnapshot(relay)
			record := relay.sets[daID].cloneForStateMutation()
			tc.corrupt(&record)
			relay.sets[daID] = record

			_, err := prepareCanonicalDAImage(relay, nil, chain)
			var terminal *canonicalDATerminalError
			if !errors.As(err, &terminal) {
				t.Fatalf("err=%v, want the retained-DA terminal class", err)
			}
			if !isCanonicalTransitionTerminalError(err) {
				t.Fatal("the retained-DA terminal class does not take the terminal closeout")
			}
			if !strings.HasPrefix(err.Error(), "canonical retained-DA invariant: ") {
				t.Fatalf("terminal record=%q, want the retained-DA class named first", err.Error())
			}
			if errors.Is(err, errCanonicalPlanMetadataCap) || errors.Is(err, errCanonicalIndexMoved) {
				t.Fatalf("terminal invariant was reported as a resource or stale-plan class: %v", err)
			}
			// Nothing but the deliberate corruption moved.
			relay.sets[daID] = before.sets[daID]
			if got := daRelayStateSnapshot(relay); !reflect.DeepEqual(got, before) {
				t.Fatal("a terminal preparation mutated the live retained-DA image")
			}
		})
	}
}

// TestRetaggedCanonicalDATerminalRelabelsOnlyTheTerminal pins the D-side
// relabel: a terminal the SHARED M/O validator raises for a retained DA member
// is reported as the retained-DA class naming that member, while the canonical
// precommit PLAN error EPD-6 shares is passed through untouched.
func TestRetaggedCanonicalDATerminalRelabelsOnlyTheTerminal(t *testing.T) {
	got := retaggedCanonicalDATerminal(terminalCanonicalMempoolError(errors.New("detail")), "chunk 1")
	var da *canonicalDATerminalError
	if !errors.As(got, &da) || got.Error() != "canonical retained-DA invariant: retained DA chunk 1: detail" {
		t.Fatalf("retag=%v, want the retained-DA class naming the member", got)
	}
	plan := localCanonicalMempoolPlanError(errors.New("provider"))
	if retaggedCanonicalDATerminal(plan, "commit") != plan || retaggedCanonicalDATerminal(nil, "commit") != nil {
		t.Fatal("a plan abort or a nil result was reclassified")
	}
}

// TestCanonicalDAImageIsDeterministicAndSharesRetainedBytes pins that two
// preparations of the same state agree exactly, and that the prepared image
// clones maps while SHARING the immutable retained transaction bytes rather than
// duplicating retained payload.
func TestCanonicalDAImageIsDeterministicAndSharesRetainedBytes(t *testing.T) {
	f := newCanonicalMOFixture(t, 3, MempoolConfig{})
	relay := f.engine.DARelayState()
	kept, dropped := daRelayTestID(0x61), daRelayTestID(0x62)
	f.daSet(t, relay, kept, f.ops[:2], 900)
	f.daSet(t, relay, dropped, f.ops[1:3], 910)
	chain := f.canonicalDATestChain(t)
	chain.final.mu.Lock()
	delete(chain.final.Utxos, f.ops[2])
	chain.final.mu.Unlock()

	first := mustPrepareCanonicalDAImage(t, relay, nil, chain)
	second := mustPrepareCanonicalDAImage(t, relay, nil, chain)
	if !reflect.DeepEqual(daRelayStateSnapshot(first.projected), daRelayStateSnapshot(second.projected)) {
		t.Fatal("two preparations of the same state produced different images")
	}
	if _, present := first.projected.sets[dropped]; present {
		t.Fatal("the invalid record survived preparation")
	}
	live, projected := relay.sets[kept], first.projected.sets[kept]
	if len(live.commit.txBytes) == 0 || len(projected.commit.txBytes) == 0 {
		t.Fatal("the surviving record lost its retained commit bytes: sharing cannot be observed")
	}
	if &live.commit.txBytes[0] != &projected.commit.txBytes[0] {
		t.Fatal("the prepared image copied retained commit bytes instead of sharing them")
	}
	if reflect.ValueOf(live.chunks).Pointer() != reflect.ValueOf(projected.chunks).Pointer() {
		t.Fatal("the prepared image copied a surviving record's chunk map")
	}
	if reflect.ValueOf(relay.sets).Pointer() == reflect.ValueOf(first.projected.sets).Pointer() {
		t.Fatal("the prepared image shares the live set map instead of cloning it")
	}
}

// TestCanonicalDAImagePublishesOnlyForNew pins the truth axis of publication:
// truth NEW publishes the prepared image — latched or not — while OLD and
// UNKNOWN publish no D image at all and leave the live retained state exactly as
// the transition found it.
func TestCanonicalDAImagePublishesOnlyForNew(t *testing.T) {
	for _, tc := range []struct {
		name      string
		truth     canonicalCommitTruth
		latched   bool
		published bool
	}{
		{name: "ordinary NEW publishes", truth: canonicalTruthNew, published: true},
		{name: "terminal NEW publishes the same image", truth: canonicalTruthNew, latched: true, published: true},
		{name: "terminal OLD publishes nothing", truth: canonicalTruthOld, latched: true},
		{name: "open OLD publishes nothing", truth: canonicalTruthOld},
		{name: "UNKNOWN publishes nothing", truth: canonicalTruthUnknown, latched: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCanonicalMOFixture(t, 3, MempoolConfig{})
			relay := f.engine.DARelayState()
			daID := daRelayTestID(0x71)
			f.daSet(t, relay, daID, f.ops[:3], 1000)
			chain := f.canonicalDATestChain(t)
			chain.final.mu.Lock()
			delete(chain.final.Utxos, f.ops[0])
			chain.final.mu.Unlock()

			tr, err := f.engine.beginCanonicalTransition(&diagnosticBatch{})
			mustCanonicalMO(t, "beginCanonicalTransition", err)
			if tr.daRelay != relay {
				t.Fatal("the transition captured a different retained-DA pointer than the engine's")
			}
			image := mustPrepareCanonicalDAImage(t, tr.daRelay, nil, chain)
			if _, present := image.projected.sets[daID]; present {
				t.Fatal("the prepared image kept a record it could not validate")
			}
			var fault *storagePersistenceFault
			if tc.latched {
				fault = &storagePersistenceFault{cause: errors.New("test terminal")}
			}
			plan := &canonicalTransitionPlan{final: cloneChainState(f.engine.chainState)}
			tr.publishCanonicalTransition(plan, canonicalFenceImage{da: image}, tc.truth, fault, "")

			_, live := relay.sets[daID]
			if live == tc.published {
				t.Fatalf("record still retained=%v, want published=%v", live, tc.published)
			}
		})
	}
}

// TestCanonicalDAWritersCannotInterleaveWithTheTransition is the barrier
// schedule for all six surviving production writers: each one launched while the
// admission WRITE guard is held blocks until the guard is released, so no writer
// can land between a D preparation and its publication. It is the deterministic
// negative for removing any single fence.
func TestCanonicalDAWritersCannotInterleaveWithTheTransition(t *testing.T) {
	f := newCanonicalMOFixture(t, 1, MempoolConfig{})
	relay := f.engine.DARelayState()
	daID := daRelayTestID(0x81)
	payload := []byte("fenced")
	// An ordered slice, not a map: subtest order is part of what a rerun has to
	// reproduce.
	writers := []struct {
		name string
		run  func()
	}{
		{"StageCommit", func() {
			_ = relay.StageCommit("fence-peer", DARelayCommit{DAID: daID, PayloadCommitment: sha3.Sum256(payload), ChunkCount: 1, WireBytes: 8})
		}},
		{"StageChunk", func() {
			_ = relay.StageChunk("fence-peer", DARelayChunk{DAID: daRelayTestID(0x82), ChunkHash: sha3.Sum256(payload), Payload: payload, WireBytes: 8})
		}},
		{"AdvanceOrphanTTL", func() { _ = relay.AdvanceOrphanTTL() }},
		{"ReleasePeerQuotaKey", func() { _ = relay.ReleasePeerQuotaKey("fence-peer") }},
		{"PlanPrefetch", func() { relay.PlanPrefetch(daID, []string{"fence-peer"}, time.Unix(1, 0)) }},
		{"ReleasePrefetchPlan", func() { relay.ReleasePrefetchPlan(DARelayPrefetchPlan{DAID: daID, PeerKey: "fence-peer"}) }},
	}
	for _, writer := range writers {
		t.Run(writer.name, func(t *testing.T) {
			done := make(chan struct{})
			f.engine.chainState.admissionMu.Lock()
			go func() { defer close(done); writer.run() }()
			// The BLOCK is proven from the writer's own parked stack, not inferred
			// from elapsed time: a writer that had merely not been scheduled yet
			// would never satisfy this barrier, and a writer that took no fence at
			// all would reach done instead.
			awaitCanonicalMOAdmissionRLock(t, writer.name, 1)
			select {
			case <-done:
				f.engine.chainState.admissionMu.Unlock()
				t.Fatal("the writer ran while the admission write guard was held")
			default:
			}
			f.engine.chainState.admissionMu.Unlock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the writer never proceeded after the guard was released")
			}
		})
	}
}

// TestCanonicalDAWritersObserveTheCompletePublishedImage is the freshness
// schedule: the guard is held CONTINUOUSLY from preparation through
// publication, every writer is launched mid-hold, and the published image is
// exactly the prepared one — no writer's update was lost and no reader could see
// a tuple no writer produced.
func TestCanonicalDAWritersObserveTheCompletePublishedImage(t *testing.T) {
	f := newCanonicalMOFixture(t, 3, MempoolConfig{})
	relay := f.engine.DARelayState()
	daID := daRelayTestID(0x91)
	f.daSet(t, relay, daID, f.ops[:3], 1100)
	chain := f.canonicalDATestChain(t)
	chain.final.mu.Lock()
	delete(chain.final.Utxos, f.ops[0])
	chain.final.mu.Unlock()

	tr, err := f.engine.beginCanonicalTransition(&diagnosticBatch{})
	mustCanonicalMO(t, "beginCanonicalTransition", err)
	var writers sync.WaitGroup
	for i := 0; i < 6; i++ {
		writers.Add(1)
		go func(seed byte) {
			defer writers.Done()
			payload := []byte{seed}
			_ = relay.StageChunk("racing-peer", DARelayChunk{DAID: daRelayTestID(0xa0 + seed), ChunkHash: sha3.Sum256(payload), Payload: payload, WireBytes: 8})
		}(byte(i))
	}
	// Every writer is PROVEN parked at admissionMu.RLock before the preparation
	// runs. Without this the six goroutines might not have reached the fence at
	// all, and "no writer landed inside the prepared image" would hold vacuously.
	awaitCanonicalMOAdmissionRLock(t, "StageChunk", 6)
	image := mustPrepareCanonicalDAImage(t, tr.daRelay, nil, chain)
	prepared := daRelayStateSnapshot(image.projected)
	plan := &canonicalTransitionPlan{final: cloneChainState(f.engine.chainState)}
	tr.publishCanonicalTransition(plan, canonicalFenceImage{da: image}, canonicalTruthNew, nil, "")
	// Drain BEFORE the published snapshot, so the comparison below is against the
	// image every released writer has already finished writing into.
	writers.Wait()
	published := daRelayStateSnapshot(relay)
	if _, ok := published.sets[daID]; ok {
		t.Fatal("the published image kept the record the preparation removed")
	}
	if !reflect.DeepEqual(prepared.sets[daID], published.sets[daID]) {
		t.Fatal("a writer landed between preparation and publication")
	}
	// Every fenced writer ran AFTER publication, so each of its records is in
	// the live image and none of them was in the prepared one.
	for i := 0; i < 6; i++ {
		racing := daRelayTestID(0xa0 + byte(i))
		if _, ok := relay.sets[racing]; !ok {
			t.Fatalf("racing writer %d never landed after the guard was released", i)
		}
		if _, ok := prepared.sets[racing]; ok {
			t.Fatalf("racing writer %d landed inside the prepared image", i)
		}
	}
}

// stageRetainedDAMembersOfBlock retains every DA member of these blocks with the
// exact canonical bytes ingest supplies, so the resident carries the identity
// that block contributes to I.
func stageRetainedDAMembersOfBlock(t *testing.T, relay *DARelayState, blocks ...[]byte) {
	t.Helper()
	for _, blockBytes := range blocks {
		parsed, err := consensus.ParseBlockBytes(blockBytes)
		mustCanonicalMO(t, "ParseBlockBytes", err)
		for _, tx := range parsed.Txs {
			raw := mustMarshalTxForNodeTest(t, tx)
			switch tx.TxKind {
			case 0x01:
				var commitment [32]byte
				copy(commitment[:], tx.Outputs[0].CovenantData)
				mustCanonicalMO(t, "StageCommit", relay.StageCommit("da-peer", DARelayCommit{DAID: tx.DaCommitCore.DaID, PayloadCommitment: commitment, ChunkCount: tx.DaCommitCore.ChunkCount, WireBytes: uint64(len(raw)), TxBytes: raw}))
			case 0x02:
				mustCanonicalMO(t, "StageChunk", relay.StageChunk("da-peer", DARelayChunk{DAID: tx.DaChunkCore.DaID, ChunkHash: tx.DaChunkCore.ChunkHash, ChunkIndex: tx.DaChunkCore.ChunkIndex, Payload: tx.DaPayload, WireBytes: uint64(len(raw)), TxBytes: raw}))
			}
		}
	}
}

// TestCanonicalDAImageIsPreparedOnEveryTransitionPath executes A7: the
// preferred-reorg, standalone-disconnect and genesis-bootstrap entries all reach
// the ONE central D prepare/publish seam. Every record is a COMPLETE set, which
// the orphan TTL never walks, and no capacity eviction runs, so only the D
// projection can remove one; the last two rows also carry an EMPTY inclusion
// list, leaving final chain validity as their only cause.
func TestCanonicalDAImageIsPreparedOnEveryTransitionPath(t *testing.T) {
	t.Run("preferred reorg", func(t *testing.T) {
		f := newCanonicalDATestFixture(t)
		// The PRODUCTION configuration (cmd/rubin-node/main.go builds
		// DefaultMempoolConfig), so PolicyRejectSimplicityPreActivation is on and a
		// chain-VALID survivor actually executes the D policy half.
		mp, err := NewMempool(f.engine.chainState, f.store, devnetGenesisChainID)
		mustCanonicalMO(t, "NewMempool", err)
		f.engine.SetMempool(mp)
		relay := f.engine.DARelayState()
		_, err = f.engine.ApplyBlock(f.blockWithDASets(t, daSetSpec{daID: [32]byte{0xa1}, payloads: [][]byte{[]byte("a1")}}), nil)
		mustCanonicalMO(t, "ApplyBlock(A1)", err)
		fork := f.forkFrom(t)
		blockB1 := fork.blockWithDASets(t, daSetSpec{daID: [32]byte{0xb1}, payloads: [][]byte{[]byte("b1")}})
		parsedB1, hashB1 := mustParseReorgBlockForTest(t, blockB1)
		mustCanonicalMO(t, "StoreBlock(B1)", f.store.StoreBlock(hashB1, parsedB1.HeaderBytes, blockB1))
		blockB2 := fork.blockWithDASets(t, daSetSpec{daID: [32]byte{0xb2}, payloads: [][]byte{[]byte("b2")}})
		// Built and never applied: its set is the survivor the branch leaves alone.
		survivor := fork.blockWithDASets(t, daSetSpec{daID: [32]byte{0xb3}, payloads: [][]byte{[]byte("b3")}})
		stageRetainedDAMembersOfBlock(t, relay, blockB1, blockB2, survivor)
		_, err = f.engine.ApplyBlockWithReorg(blockB2, nil)
		mustCanonicalMO(t, "ApplyBlockWithReorg(B2)", err)
		_, b1Held := relay.sets[[32]byte{0xb1}]
		_, b2Held := relay.sets[[32]byte{0xb2}]
		_, survivorHeld := relay.sets[[32]byte{0xb3}]
		if b1Held || b2Held || !survivorHeld {
			t.Fatalf("reorg D disposition: B1 retained=%v B2 retained=%v survivor removed=%v", b1Held, b2Held, !survivorHeld)
		}
	})
	t.Run("standalone disconnect", func(t *testing.T) {
		f := newCanonicalMOFixture(t, 4, MempoolConfig{})
		// The commit spends an output the DISCONNECTED block creates: valid now, final-invalid once it leaves.
		created := consensus.Outpoint{Txid: txID(t, f.raw(t, f.ops[0], 2, false))}
		mustCanonicalMO(t, "ApplyBlock(spend)", f.applySpend(t, f.ops[0], 2))
		relay, dropped, kept := f.engine.DARelayState(), daRelayTestID(0xd1), daRelayTestID(0xd2)
		f.daSet(t, relay, dropped, []consensus.Outpoint{created, f.ops[1]}, 1200)
		f.daSet(t, relay, kept, f.ops[2:4], 1210)
		_, err := f.engine.DisconnectTip()
		mustCanonicalMO(t, "DisconnectTip", err)
		_, invalidHeld := relay.sets[dropped]
		_, validHeld := relay.sets[kept]
		if invalidHeld || !validHeld {
			t.Fatalf("disconnect D disposition: final-invalid retained=%v final-valid removed=%v", invalidHeld, !validHeld)
		}
	})
	t.Run("genesis bootstrap", func(t *testing.T) {
		f := newCanonicalMOFixture(t, 2, MempoolConfig{})
		engine, _, store := newAliasingTestPair(t, devnetGenesisChainID)
		mp, err := NewMempoolWithConfig(engine.chainState, store, devnetGenesisChainID, MempoolConfig{})
		mustCanonicalMO(t, "NewMempoolWithConfig", err)
		engine.SetMempool(mp)
		relay, daID := engine.DARelayState(), daRelayTestID(0xd3)
		// Signed against the other fixture's UTXOs: never valid against genesis C1.
		f.daSet(t, relay, daID, f.ops[:2], 1220)
		mustCanonicalMO(t, "BootstrapCanonicalGenesisIfEmpty", engine.BootstrapCanonicalGenesisIfEmpty())
		if _, present := relay.sets[daID]; present {
			t.Fatal("the bootstrap transition retained a record it never validated against C1")
		}
	})
}

// TestCanonicalDAImageIsSkippedWithoutABoundRelay pins the unbound engine: a
// transition with no retained-DA state prepares and publishes none, and neither
// step panics.
func TestCanonicalDAImageIsSkippedWithoutABoundRelay(t *testing.T) {
	image, err := prepareCanonicalDAImage(nil, nil, canonicalFinalChainContext{})
	if image != nil || err != nil {
		t.Fatalf("image=%v err=%v, want no image and no error", image, err)
	}
	image.publish()
}

// TestCanonicalFenceImageReportsTheMOTerminalOverTheDTerminal is the
// dual-violation row: one transition whose standard image AND retained-DA image
// are both invariant-violating reports the STANDARD terminal, M/O preparation
// completing first. The control proves the D defect is terminal on its own, so
// the row cannot pass on a harmless D half.
func TestCanonicalFenceImageReportsTheMOTerminalOverTheDTerminal(t *testing.T) {
	f := newCanonicalMOFixture(t, 3, MempoolConfig{})
	relay, daID := f.engine.DARelayState(), daRelayTestID(0x57)
	f.daSet(t, relay, daID, f.ops[1:3], 840)
	record := relay.sets[daID].cloneForStateMutation()
	record.commit.chunkCount = 7 // contradicts the retained commit transaction
	relay.sets[daID] = record
	var da *canonicalDATerminalError
	if _, err := prepareCanonicalDAImage(relay, nil, f.canonicalDATestChain(t)); !errors.As(err, &da) {
		t.Fatalf("control: the D defect is not terminal on its own: %v", err)
	}

	txid := f.add(t, f.ops[0], 1)
	f.mp.mu.Lock()
	f.mp.txs[txid].raw[0] ^= 1 // the entry no longer matches its own identity
	f.mp.mu.Unlock()
	index, err := f.store.CanonicalIndexSnapshot()
	mustCanonicalMO(t, "CanonicalIndexSnapshot", err)
	tr, err := f.engine.beginCanonicalTransition(nil)
	mustCanonicalMO(t, "beginCanonicalTransition", err)
	defer tr.abort()
	_, err = f.engine.prepareCanonicalFenceImage(tr, &canonicalTransitionPlan{oldSequence: index, priorTip: chainTipScalarsOf(f.engine.chainState), final: f.engine.chainState})
	_, live := relay.sets[daID]
	if !isCanonicalTransitionTerminalError(err) || canonicalTerminalReason(err) != "canonical mempool invariant" || errors.As(err, &da) || !live {
		t.Fatalf("dual violation err=%v live record retained=%v, want the standard/owner terminal", err, live)
	}
}

// TestCanonicalDAImagePlanAbortPrecedence pins EPD-6 on the D side. A retained
// member whose failure the SHARED classifiers call plan-aborting returns the
// SAME canonical precommit plan error M returns: nothing removed, nothing
// latched, admission reopened. A corrupt member of that record still outranks
// it, because phase 1 parses every member before phase 2 validates any. The
// abort source is an unbound suite registry, whose backend failure read as an
// exclusion instead would have REMOVED the record.
func TestCanonicalDAImagePlanAbortPrecedence(t *testing.T) {
	f := newCanonicalMOFixture(t, 3, MempoolConfig{SuiteRegistry: unboundAlgSuiteRegistry()})
	relay, daID := f.engine.DARelayState(), daRelayTestID(0x58)
	f.daSet(t, relay, daID, f.ops[:3], 850)
	chain := f.canonicalDATestChain(t)
	chain.policy.SuiteRegistry = unboundAlgSuiteRegistry()

	var plan *canonicalMOPlanError
	image, err := prepareCanonicalDAImage(relay, nil, chain)
	if !errors.As(err, &plan) || image != nil || isCanonicalTransitionTerminalError(err) {
		t.Fatalf("plan-aborting member err=%v image=%v, want the shared plan error", err, image)
	}
	if _, live := relay.sets[daID]; !live {
		t.Fatal("a plan abort removed the live record")
	}

	// The same abort through the real fence aborts OPEN, not latched.
	index, indexErr := f.store.CanonicalIndexSnapshot()
	mustCanonicalMO(t, "CanonicalIndexSnapshot", indexErr)
	tr, beginErr := f.engine.beginCanonicalTransition(nil)
	mustCanonicalMO(t, "beginCanonicalTransition", beginErr)
	_, fenceErr := f.engine.prepareCanonicalFenceImage(tr, &canonicalTransitionPlan{oldSequence: index, priorTip: chainTipScalarsOf(f.engine.chainState), final: f.engine.chainState})
	if endErr := tr.end(fenceErr); !errors.As(endErr, &plan) || f.engine.persistenceFaulted() {
		t.Fatalf("fenced plan abort err=%v latch=%v", endErr, f.engine.persistenceFaulted())
	}
	if _, ok := f.mp.PendingOutpointOwner().AdmissionContext(); !ok {
		t.Fatal("a D plan abort left admission closed")
	}

	// One unparseable LAST member: phase 1 returns for the whole record first.
	record, corrupt := relay.sets[daID].cloneForStateMutation(), relay.sets[daID].chunks[1]
	corrupt.txBytes = []byte{0xff, 0xfe}
	record.chunks[1] = corrupt
	relay.sets[daID] = record
	var terminal *canonicalDATerminalError
	if _, err := prepareCanonicalDAImage(relay, nil, chain); !errors.As(err, &terminal) {
		t.Fatalf("err=%v, want the parse-phase terminal to outrank the plan abort", err)
	}
}

// TestCanonicalDAImageAccountingFailureIsTerminal pins the OTHER terminal cause:
// a checked accounting failure while projecting the removal is the same class as
// corrupt member bytes, and it too publishes nothing.
func TestCanonicalDAImageAccountingFailureIsTerminal(t *testing.T) {
	f := newCanonicalMOFixture(t, 3, MempoolConfig{})
	relay := f.engine.DARelayState()
	daID := daRelayTestID(0x54)
	f.daSet(t, relay, daID, f.ops[:3], 830)
	chain := f.canonicalDATestChain(t)
	chain.final.mu.Lock()
	for _, op := range f.ops[:3] {
		delete(chain.final.Utxos, op)
	}
	chain.final.mu.Unlock()
	relay.mu.Lock()
	relay.pinnedPayloadBytes = 0 // the record still declares pinned payload bytes
	relay.mu.Unlock()

	_, err := prepareCanonicalDAImage(relay, nil, chain)
	var terminal *canonicalDATerminalError
	if !errors.As(err, &terminal) {
		t.Fatalf("err=%v, want the retained-DA terminal class", err)
	}
	if _, live := relay.sets[daID]; !live {
		t.Fatal("a terminal accounting failure removed the live record")
	}
}
