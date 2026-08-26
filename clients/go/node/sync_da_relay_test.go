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
	return f.daSetForOwner(t, relay, f.mp.PendingOutpointOwner(), daID, ops, nonce)
}

// daSetForOwner is daSet for a relay bound to a DIFFERENT engine than the one
// whose UTXOs signed these transactions: the claims are issued by the relay's
// OWN owner, which is the only owner its canonical transition will read.
func (f *canonicalMOFixture) daSetForOwner(t *testing.T, relay *DARelayState, owner *PendingOutpointOwner, daID [32]byte, ops []consensus.Outpoint, nonce uint64) canonicalDATestSet {
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
	set.commit = f.daCommitTxCommitting(t, ops[0], daID, uint16(len(set.chunks)), nonce, commitment)
	retainDAMemberForTest(t, relay, owner, set.commit, "peer-commit")
	for _, chunkTx := range set.chunks {
		retainDAMemberForTest(t, relay, owner, chunkTx, "peer-chunk")
	}
	return set
}

// retainDAMemberForTest installs one retained member with its exact identity and
// a REAL finalized owner DA claim, WITHOUT running admission's chain validation.
//
// The D1 removal rule is about members that are not final_chain_valid against
// C1, and AdmitDA cannot produce one by construction: it admits only what the
// live chain accepts. So these rows build the member the way the retained schema
// itself does — the owner's own Reserve/Finalize plus the package-private staging
// entry — and keep the record/locator/claim bijection exact. AdmitDA's own end to
// end behavior is pinned separately in da_relay_owner_test.go.
func retainDAMemberForTest(t *testing.T, relay *DARelayState, owner *PendingOutpointOwner, raw []byte, peer string) {
	t.Helper()
	tx, txid, wtxid, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) {
		t.Fatalf("ParseTx(retained member): consumed=%d err=%v", consumed, err)
	}
	inputs := relayMetadataInputs(tx)
	provenance, err := NewPeerDAProvenance(peer, peer)
	mustCanonicalMO(t, "NewPeerDAProvenance", err)
	identity := daRelayMemberIdentity{
		txid: txid, wtxid: wtxid, retainedBytes: uint64(len(raw)),
		inputs: inputs, token: finalizedDAClaimForTest(t, owner, txid, inputs), provenance: provenance,
	}
	if tx.TxKind == 0x01 {
		commitment, ok := daCommitPayloadCommitment(tx)
		if !ok {
			t.Fatal("retained DA commit fixture carries no payload commitment output")
		}
		mustCanonicalMO(t, "addDACommit", relay.addDACommit(provenance.quotaKey(), daRelayCommit{
			daRelayMemberIdentity: identity, daID: tx.DaCommitCore.DaID, payloadCommitment: commitment,
			chunkCount: tx.DaCommitCore.ChunkCount, wireBytes: uint64(len(raw)), txBytes: raw,
		}))
		return
	}
	mustCanonicalMO(t, "addDAChunk", relay.addDAChunk(provenance.quotaKey(), daRelayChunk{
		daRelayMemberIdentity: identity, daID: tx.DaChunkCore.DaID, chunkHash: tx.DaChunkCore.ChunkHash,
		chunkIndex: tx.DaChunkCore.ChunkIndex, payload: tx.DaPayload, wireBytes: uint64(len(raw)),
		txBytes: raw, hashChecked: true,
	}))
}

// finalizedDAClaimForTest issues one finalized DA-domain claim through the
// owner's own exported primitives.
func finalizedDAClaimForTest(t *testing.T, owner *PendingOutpointOwner, txid [32]byte, inputs []consensus.Outpoint) PendingOutpointToken {
	t.Helper()
	ctx, ok := owner.AdmissionContext()
	if !ok {
		t.Fatal("pending-outpoint owner is unavailable for a retained DA claim")
	}
	token, err := owner.Reserve(ctx, PendingOutpointDA, txid, inputs)
	mustCanonicalMO(t, "Reserve(DA)", err)
	mustCanonicalMO(t, "Finalize(DA)", owner.Finalize(token))
	return token
}

// daCommitTx is the signed DA commit shape mustBuildSignedDaCommitTxWithChunkCount
// builds, with the set's own da_id bound into its core — which the shared helper
// leaves zero and a retained record's role check will not accept.
// daCommitTx is the retained-commit shape WITHOUT a payload-commitment output.
// It stays for the reorg rows that only need a well-formed tx_kind 0x01 body in
// a block; a retained RECORD needs daCommitTxCommitting below, because the
// retained payload commitment is read from the transaction itself.
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

// daCommitTxCommitting is daCommitTx plus the single COV_TYPE_DA_COMMIT output
// carrying the set's payload commitment — the output AdmitDA and the retained
// schema read that commitment from.
func (f *canonicalMOFixture) daCommitTxCommitting(t *testing.T, op consensus.Outpoint, daID [32]byte, chunkCount uint16, nonce uint64, commitment [32]byte) []byte {
	t.Helper()
	tx := &consensus.Tx{
		Version: 1, TxKind: 0x01, TxNonce: nonce,
		Inputs: []consensus.TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout}},
		Outputs: []consensus.TxOutput{
			{Value: 0, CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: append([]byte(nil), commitment[:]...)},
			{Value: 100_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...)},
		},
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
	image, err := prepareCanonicalDAImage(relay, included, chain, nil)
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
		retainDAMemberForTest(t, relay, f.mp.PendingOutpointOwner(), chunkTx, "peer-orphan")
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
		f := newCanonicalMOFixture(t, 4, MempoolConfig{})
		relay := f.engine.DARelayState()
		low, high := daRelayTestID(0x01), daRelayTestID(0xfe)
		f.daSet(t, relay, low, f.ops[:2], 880)
		f.daSet(t, relay, high, f.ops[2:4], 890)
		for _, daID := range [][32]byte{low, high} {
			record := relay.sets[daID].cloneForStateMutation()
			record.commit.chunkCount = 9 // contradicts the retained commit tx
			relay.sets[daID] = record
		}
		_, err := prepareCanonicalDAImage(relay, nil, f.canonicalDATestChain(t), nil)
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

			_, err := prepareCanonicalDAImage(relay, nil, chain, nil)
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
			if got := daRelayStateSnapshot(relay); !reflect.DeepEqual(got, before) { //nolint:govet // deepequalerrors: the snapshot must match byte-for-byte, error values included — identity is the assertion
				t.Fatal("a terminal preparation mutated the live retained-DA image")
			}
		})
	}
}

// TestRetaggedCanonicalDATerminalRelabelsOnlyTheTerminal pins the D-side
// relabel: a terminal the SHARED M/O validator raises for a retained DA member
// is reported as the retained-DA class naming that member, while the canonical
// precommit PLAN error EPD-6 shares is passed through untouched.
//
// It calls the relabel DIRECTLY because no production input reaches it today
// (see retaggedCanonicalDATerminal): this row pins the MECHANISM waiting for the
// shared validator's future terminal, not a live path.
func TestRetaggedCanonicalDATerminalRelabelsOnlyTheTerminal(t *testing.T) {
	got := retaggedCanonicalDATerminal(terminalCanonicalMempoolError(errors.New("detail")), "chunk 1")
	var da *canonicalDATerminalError
	if !errors.As(got, &da) || got.Error() != "canonical retained-DA invariant: retained DA chunk 1: detail" {
		t.Fatalf("retag=%v, want the retained-DA class naming the member", got)
	}
	plan := localCanonicalMempoolPlanError(errors.New("provider"))
	if retaggedCanonicalDATerminal(plan, "commit") != plan || retaggedCanonicalDATerminal(nil, "commit") != nil { //nolint:errorlint // pointer identity is the assertion: retag must return the SAME plan error, not a wrapper
		t.Fatal("a plan abort or a nil result was reclassified")
	}
}

// TestCanonicalDAImageIsDeterministicAndSharesRetainedBytes pins that two
// preparations of the same state agree exactly, and that the prepared image
// clones maps while SHARING the immutable retained transaction bytes rather than
// duplicating retained payload.
func TestCanonicalDAImageIsDeterministicAndSharesRetainedBytes(t *testing.T) {
	f := newCanonicalMOFixture(t, 4, MempoolConfig{})
	relay := f.engine.DARelayState()
	kept, dropped := daRelayTestID(0x61), daRelayTestID(0x62)
	f.daSet(t, relay, kept, f.ops[:2], 900)
	f.daSet(t, relay, dropped, f.ops[2:4], 910)
	chain := f.canonicalDATestChain(t)
	chain.final.mu.Lock()
	delete(chain.final.Utxos, f.ops[2])
	chain.final.mu.Unlock()

	first := mustPrepareCanonicalDAImage(t, relay, nil, chain)
	second := mustPrepareCanonicalDAImage(t, relay, nil, chain)
	if !reflect.DeepEqual(daRelayStateSnapshot(first.projected), daRelayStateSnapshot(second.projected)) { //nolint:govet // deepequalerrors: the snapshot must match byte-for-byte, error values included — identity is the assertion
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
	f := newCanonicalMOFixture(t, 2, MempoolConfig{})
	relay := f.engine.DARelayState()
	daID := daRelayTestID(0x81)
	payload := []byte("fenced")
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 1400, sha3.Sum256(payload))
	chunkTx := f.daChunkTx(t, f.ops[1], daRelayTestID(0x82), 0, 1401, payload)
	fenceProvenance, err := NewPeerDAProvenance("fence-peer", "fence-peer")
	mustCanonicalMO(t, "NewPeerDAProvenance", err)
	// An ordered slice, not a map: subtest order is part of what a rerun has to
	// reproduce.
	writers := []struct {
		name string
		run  func()
	}{
		{"AdmitDA commit", func() { _, _ = relay.AdmitDA(commitTx, fenceProvenance) }},
		{"AdmitDA chunk", func() { _, _ = relay.AdmitDA(chunkTx, fenceProvenance) }},
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
			awaitCanonicalMOAdmissionRLock(t, awaitedFenceCaller(writer.name), 1)
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
	f := newCanonicalMOFixture(t, 9, MempoolConfig{})
	relay := f.engine.DARelayState()
	daID := daRelayTestID(0x91)
	f.daSet(t, relay, daID, f.ops[:3], 1100)
	racing := make([][]byte, 6)
	for i := range racing {
		racing[i] = f.daChunkTx(t, f.ops[3+i], daRelayTestID(0xa0+byte(i)), 0, 1500+uint64(i), []byte{byte(i)})
	}
	racingProvenance, err := NewPeerDAProvenance("racing-peer", "racing-peer")
	mustCanonicalMO(t, "NewPeerDAProvenance", err)
	chain := f.canonicalDATestChain(t)
	chain.final.mu.Lock()
	delete(chain.final.Utxos, f.ops[0])
	chain.final.mu.Unlock()

	tr, err := f.engine.beginCanonicalTransition(&diagnosticBatch{})
	mustCanonicalMO(t, "beginCanonicalTransition", err)
	var writers sync.WaitGroup
	for i := 0; i < 6; i++ {
		writers.Add(1)
		go func(raw []byte) {
			defer writers.Done()
			_, _ = relay.AdmitDA(raw, racingProvenance)
		}(racing[i])
	}
	// Every writer is PROVEN parked at admissionMu.RLock before the preparation
	// runs. Without this the six goroutines might not have reached the fence at
	// all, and "no writer landed inside the prepared image" would hold vacuously.
	awaitCanonicalMOAdmissionRLock(t, "AdmitDA", 6)
	image := mustPrepareCanonicalDAImage(t, tr.daRelay, nil, chain)
	prepared := daRelayStateSnapshot(image.projected)
	plan := &canonicalTransitionPlan{final: cloneChainState(f.engine.chainState)}
	tr.publishCanonicalTransition(plan, canonicalFenceImage{da: image}, canonicalTruthNew, nil, "")
	// Drain BEFORE reading the live image, so every assertion below sees the
	// image each released writer has already finished writing into.
	writers.Wait()
	if _, ok := daRelayStateSnapshot(relay).sets[daID]; ok {
		t.Fatal("the published image kept the record the preparation removed")
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
func stageRetainedDAMembersOfBlock(t *testing.T, relay *DARelayState, owner *PendingOutpointOwner, blocks ...[]byte) {
	t.Helper()
	for _, blockBytes := range blocks {
		parsed, err := consensus.ParseBlockBytes(blockBytes)
		mustCanonicalMO(t, "ParseBlockBytes", err)
		for _, tx := range parsed.Txs {
			raw := mustMarshalTxForNodeTest(t, tx)
			switch tx.TxKind {
			case 0x01, 0x02:
				retainDAMemberForTest(t, relay, owner, raw, "da-peer")
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
		// The fork is taken BEFORE A1, so B1 is A1's SIBLING and applying B2 has to
		// disconnect A1 to connect [B1, B2] — a branch extension would reach the
		// same seam with an empty disconnect suffix and prove nothing about reorgs.
		fork := f.forkFrom(t)
		_, err = f.engine.ApplyBlock(f.blockWithDASets(t, daSetSpec{daID: [32]byte{0xa1}, payloads: [][]byte{[]byte("a1")}}), nil)
		mustCanonicalMO(t, "ApplyBlock(A1)", err)
		blockB1 := fork.blockWithDASets(t, daSetSpec{daID: [32]byte{0xb1}, payloads: [][]byte{[]byte("b1")}})
		parsedB1, hashB1 := mustParseReorgBlockForTest(t, blockB1)
		mustCanonicalMO(t, "StoreBlock(B1)", f.store.StoreBlock(hashB1, parsedB1.HeaderBytes, blockB1))
		blockB2 := fork.blockWithDASets(t, daSetSpec{daID: [32]byte{0xb2}, payloads: [][]byte{[]byte("b2")}})
		// Built and never applied: its set is the survivor the branch leaves alone.
		survivor := fork.blockWithDASets(t, daSetSpec{daID: [32]byte{0xb3}, payloads: [][]byte{[]byte("b3")}})
		stageRetainedDAMembersOfBlock(t, relay, mp.PendingOutpointOwner(), blockB1, blockB2, survivor)
		_, err = f.engine.ApplyBlockWithReorg(blockB2, nil)
		mustCanonicalMO(t, "ApplyBlockWithReorg(B2)", err)
		if depth := f.engine.LastReorgDepth(); depth != 1 {
			t.Fatalf("LastReorgDepth()=%d, want the one disconnected block A1", depth)
		}
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
		// Signed against the OTHER fixture's UTXOs, so the members are never valid
		// against genesis C1 — but claimed on THIS engine's owner, so the record and
		// its claims are the one bijection the transition's claim phase requires.
		f.daSetForOwner(t, relay, mp.PendingOutpointOwner(), daID, f.ops[:2], 1220)
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
	image, err := prepareCanonicalDAImage(nil, nil, canonicalFinalChainContext{}, nil)
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
	if _, err := prepareCanonicalDAImage(relay, nil, f.canonicalDATestChain(t), nil); !errors.As(err, &da) {
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
	image, err := prepareCanonicalDAImage(relay, nil, chain, nil)
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
	if _, err := prepareCanonicalDAImage(relay, nil, chain, nil); !errors.As(err, &terminal) {
		t.Fatalf("err=%v, want the parse-phase terminal to outrank the plan abort", err)
	}
}

// TestCanonicalDAImageCrossRecordPrecedenceIsRecordMajor pins the CROSS-record
// half of the D scan order, which no same-record row can show: the FIRST record
// in ascending raw da_id order wins even when a LATER record carries an
// EARLIER-phase failure. The low record aborts the plan in phase 2 while the
// high record holds an unparseable member phase 1 would have caught, so a scan
// that ran phase 1 over every record before any phase 2 would report the high
// record's terminal instead — a different public error, a different lane, and a
// latch where the contract requires an open abort.
func TestCanonicalDAImageCrossRecordPrecedenceIsRecordMajor(t *testing.T) {
	f := newCanonicalMOFixture(t, 4, MempoolConfig{SuiteRegistry: unboundAlgSuiteRegistry()})
	relay := f.engine.DARelayState()
	low, high := daRelayTestID(0x01), daRelayTestID(0xfe)
	f.daSet(t, relay, low, f.ops[:2], 900)
	f.daSet(t, relay, high, f.ops[2:4], 910)
	record, corrupt := relay.sets[high].cloneForStateMutation(), relay.sets[high].chunks[0]
	corrupt.txBytes = []byte{0xff, 0xfe}
	record.chunks[0] = corrupt
	relay.sets[high] = record
	chain := f.canonicalDATestChain(t)
	chain.policy.SuiteRegistry = unboundAlgSuiteRegistry()

	image, err := prepareCanonicalDAImage(relay, nil, chain, nil)
	var plan *canonicalMOPlanError
	var terminal *canonicalDATerminalError
	if !errors.As(err, &plan) || errors.As(err, &terminal) || image != nil {
		t.Fatalf("err=%v image=%v, want the low-da_id record's plan abort", err, image)
	}
	if _, live := relay.sets[low]; !live {
		t.Fatal("a plan abort removed the live record")
	}
}

// daAccountingFixture stages the two record STATES whose stored aggregates are
// disjoint, so every counter DARelayState carries is nonzero at once and each
// one can be corrupted on its own: a COMPLETE_SET is the only state that
// contributes pinned payload bytes and contributes no orphan accounting at all,
// while an INCOMPLETE staged-commit record is the only state that contributes
// global, per-peer, per-da_id and commit-overhead orphan bytes.
//
// Both records are chain-valid and neither is included, so BOTH SURVIVE the
// projection: the sweep they exercise is the whole-image one, not the removal
// path's own arithmetic.
type daAccountingFixture struct {
	f          *canonicalMOFixture
	relay      *DARelayState
	chain      canonicalFinalChainContext
	complete   [32]byte
	incomplete [32]byte
}

func newDAAccountingFixture(t *testing.T) *daAccountingFixture {
	t.Helper()
	f := newCanonicalMOFixture(t, 4, MempoolConfig{})
	a := &daAccountingFixture{
		f: f, relay: f.engine.DARelayState(),
		complete: daRelayTestID(0x62), incomplete: daRelayTestID(0x63),
	}
	a.f.daSet(t, a.relay, a.complete, f.ops[:2], 1300)
	// chunk_count 2 with only chunk 0 retained: the record stays incomplete, so
	// its members keep their orphan accounting instead of becoming pinned payload.
	commitTx := f.daCommitTxCommitting(t, f.ops[2], a.incomplete, 2, 1310, sha3.Sum256([]byte("partial")))
	retainDAMemberForTest(t, a.relay, f.mp.PendingOutpointOwner(), commitTx, "peer-partial-commit")
	payload := []byte{0x63, 0x00}
	chunkTx := f.daChunkTx(t, f.ops[3], a.incomplete, 0, 1311, payload)
	retainDAMemberForTest(t, a.relay, f.mp.PendingOutpointOwner(), chunkTx, "peer-partial-chunk")
	a.chain = f.canonicalDATestChain(t)
	a.requireEveryAggregateIsExercised(t)
	return a
}

// requireEveryAggregateIsExercised fails the fixture rather than the rows if any
// stored aggregate is zero: a zero counter would let its corruption row pass on a
// sweep that never looks at that field.
func (a *daAccountingFixture) requireEveryAggregateIsExercised(t *testing.T) {
	t.Helper()
	a.relay.mu.Lock()
	defer a.relay.mu.Unlock()
	if a.relay.orphanBytes == 0 || a.relay.orphanCommitOverheadBytes == 0 || a.relay.pinnedPayloadBytes == 0 {
		t.Fatalf("fixture aggregates orphan=%d commit=%d pinned=%d, want every one nonzero", a.relay.orphanBytes, a.relay.orphanCommitOverheadBytes, a.relay.pinnedPayloadBytes)
	}
	if len(a.relay.orphanBytesByPeerQuotaKey) != 2 || len(a.relay.orphanBytesByDAID) != 1 {
		t.Fatalf("fixture peer entries=%d da_id entries=%d, want 2 and 1", len(a.relay.orphanBytesByPeerQuotaKey), len(a.relay.orphanBytesByDAID))
	}
	if a.relay.sets[a.complete].state != daRelayStateCompleteSet || a.relay.sets[a.incomplete].state == daRelayStateCompleteSet {
		t.Fatalf("fixture states complete=%v incomplete=%v", a.relay.sets[a.complete].state, a.relay.sets[a.incomplete].state)
	}
}

// TestCanonicalDAImageSweepsSurvivingRecordAccounting is R3 over the WHOLE
// projected image. The removal path already checks the arithmetic of the records
// it removes; the clone copies every SURVIVING record's stored counters verbatim,
// so only this sweep can catch one that contradicts the records it is supposed to
// summarize. One row per stored aggregate, plus the map key vs record da_id
// agreement, each with the other aggregates left consistent — a sweep narrowed to
// any single counter fails the other rows.
func TestCanonicalDAImageSweepsSurvivingRecordAccounting(t *testing.T) {
	for _, tc := range []struct {
		name      string
		aggregate string
		corrupt   func(*daAccountingFixture)
	}{
		{"pinned payload bytes", "pinned payload bytes", func(a *daAccountingFixture) { a.relay.pinnedPayloadBytes = 0 }},
		{"global orphan bytes", "orphan pool bytes", func(a *daAccountingFixture) { a.relay.orphanBytes++ }},
		{"commit overhead bytes", "orphan commit overhead bytes", func(a *daAccountingFixture) { a.relay.orphanCommitOverheadBytes++ }},
		{"per-peer orphan bytes", `per-peer orphan bytes for "peer-partial-chunk"`, func(a *daAccountingFixture) {
			a.relay.orphanBytesByPeerQuotaKey["peer-partial-chunk"]++
		}},
		{"per-peer entry that no record implies", "per-peer orphan bytes: records imply 2 entries, state holds 3", func(a *daAccountingFixture) {
			a.relay.orphanBytesByPeerQuotaKey["peer-that-owns-nothing"] = 1
		}},
		{"per-da_id orphan bytes", "per-da_id orphan bytes for", func(a *daAccountingFixture) {
			a.relay.orphanBytesByDAID[a.incomplete]++
		}},
		{"per-da_id entry that no record implies", "per-da_id orphan bytes: records imply 1 entries, state holds 2", func(a *daAccountingFixture) {
			a.relay.orphanBytesByDAID[daRelayTestID(0xfe)] = 1
		}},
		// The record is stored under a key that is not its own da_id. Its members
		// still agree with the record's OWN da_id, so phases 1 and 2 pass it and
		// only the sweep's key check can report it; the copy sorts first, so the
		// key check is the deterministic winner.
		{"map key disagrees with the record da_id", "stored under da_id 0100000000", func(a *daAccountingFixture) {
			a.relay.sets[daRelayTestID(0x01)] = a.relay.sets[a.complete]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newDAAccountingFixture(t)
			a.relay.mu.Lock()
			tc.corrupt(a)
			a.relay.mu.Unlock()
			before := daRelayStateSnapshot(a.relay)

			image, err := prepareCanonicalDAImage(a.relay, nil, a.chain, nil)
			var terminal *canonicalDATerminalError
			if !errors.As(err, &terminal) || image != nil {
				t.Fatalf("err=%v image=%v, want the retained-DA terminal class and no image", err, image)
			}
			if !isCanonicalTransitionTerminalError(err) {
				t.Fatal("the sweep's terminal class does not take the terminal closeout")
			}
			if !strings.Contains(err.Error(), tc.aggregate) {
				t.Fatalf("terminal record=%q, want it to name %q", err.Error(), tc.aggregate)
			}
			if got := daRelayStateSnapshot(a.relay); !reflect.DeepEqual(got, before) { //nolint:govet // deepequalerrors: the snapshot must match byte-for-byte, error values included — identity is the assertion
				t.Fatal("a refused preparation mutated the live retained-DA image")
			}
		})
	}
}

// TestCanonicalDAImageSweepAcceptsAndPublishesAConsistentImage is the sweep's
// no-false-positive control: a consistent image still prepares, still publishes,
// and the PUBLISHED live state satisfies the same invariant — so the sweep also
// holds across a real removal, not only over an untouched image.
func TestCanonicalDAImageSweepAcceptsAndPublishesAConsistentImage(t *testing.T) {
	a := newDAAccountingFixture(t)
	set := a.relay.sets[a.complete]
	if len(set.chunks) != 1 {
		t.Fatalf("fixture complete set holds %d chunks, want the single-chunk shape this row builds", len(set.chunks))
	}
	included := identitiesOf(t, set.commit.txBytes, set.chunks[0].txBytes)
	if len(included) != 1 {
		t.Fatalf("block identities=%d, want the one complete staged set", len(included))
	}
	image := mustPrepareCanonicalDAImage(t, a.relay, included, a.chain)
	if _, present := image.projected.sets[a.complete]; present {
		t.Fatal("the included complete set survived the projection")
	}
	if _, present := image.projected.sets[a.incomplete]; !present {
		t.Fatal("the sweep removed the uninvolved incomplete record")
	}
	image.publish()
	a.relay.mu.Lock()
	defer a.relay.mu.Unlock()
	if _, present := a.relay.sets[a.complete]; present {
		t.Fatal("publication did not remove the included complete set")
	}
	if err := a.relay.checkRetainedDAAccountingLocked(); err != nil {
		t.Fatalf("the PUBLISHED live image fails its own accounting invariant: %v", err)
	}
}

// TestCanonicalDAImageScansEveryMemberAfterAnOrdinaryInvalidOne is the
// MIXED-PHASE row inside ONE record: its first member is ordinary-invalid — a
// planned removal that carries no error — and a LATER member raises a canonical
// precommit plan abort. Phase 2 must visit every member, so the plan abort is
// what the preparation returns; a scan that stopped at the first invalid member
// would silently downgrade this record to a removal and answer nil.
func TestCanonicalDAImageScansEveryMemberAfterAnOrdinaryInvalidOne(t *testing.T) {
	f := newCanonicalMOFixture(t, 3, MempoolConfig{SuiteRegistry: unboundAlgSuiteRegistry()})
	relay, daID := f.engine.DARelayState(), daRelayTestID(0x59)
	f.daSet(t, relay, daID, f.ops[:3], 860)
	// The COMMIT is the first member walked, and its input leaves C1: an ordinary
	// invalidity, not a terminal and not an abort.
	invalidateCommitInput := func(chain canonicalFinalChainContext) {
		chain.final.mu.Lock()
		delete(chain.final.Utxos, f.ops[0])
		chain.final.mu.Unlock()
	}

	// Control: with no abort source, the SAME fixture is an ordinary removal, so
	// the row below cannot pass on a commit that was itself aborting.
	control := f.canonicalDATestChain(t)
	invalidateCommitInput(control)
	if _, present := mustPrepareCanonicalDAImage(t, relay, nil, control).projected.sets[daID]; present {
		t.Fatal("control: the first member is not ordinary-invalid — the record survived")
	}

	chain := f.canonicalDATestChain(t)
	chain.policy.SuiteRegistry = unboundAlgSuiteRegistry()
	invalidateCommitInput(chain)
	before := daRelayStateSnapshot(relay)
	image, err := prepareCanonicalDAImage(relay, nil, chain, nil)
	var plan *canonicalMOPlanError
	if !errors.As(err, &plan) || image != nil || isCanonicalTransitionTerminalError(err) {
		t.Fatalf("err=%v image=%v, want the LATER member's plan abort", err, image)
	}
	if got := daRelayStateSnapshot(relay); !reflect.DeepEqual(got, before) { //nolint:govet // deepequalerrors: the snapshot must match byte-for-byte, error values included — identity is the assertion
		t.Fatal("a plan abort mutated the live retained-DA image")
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

	_, err := prepareCanonicalDAImage(relay, nil, chain, nil)
	var terminal *canonicalDATerminalError
	if !errors.As(err, &terminal) {
		t.Fatalf("err=%v, want the retained-DA terminal class", err)
	}
	if _, live := relay.sets[daID]; !live {
		t.Fatal("a terminal accounting failure removed the live record")
	}
}

// awaitedFenceCaller maps a fence-writer row name onto the frame the parked
// goroutine actually carries: an AdmitDA writer parks inside the mempool's
// admission guard, one frame below its own entry.
func awaitedFenceCaller(name string) string {
	if strings.HasPrefix(name, "AdmitDA") {
		return "AdmitDA"
	}
	return name
}
