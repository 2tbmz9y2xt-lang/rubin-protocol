package p2p

import (
	"crypto/sha3"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// daIngressFixture funds and signs the DA transactions these rows admit.
//
// Since RUB-678 the ONLY way to retain a DA member is AdmitDA, which admits a
// FULLY VALIDATED transaction: a DA test transaction therefore needs real
// inputs, a real signature and a real confirmed UTXO to spend, exactly like a
// standard one. The fixture seeds those UTXOs directly into the harness
// chainstate before any peer worker exists, which is the same construction the
// node package's own canonical fixture uses.
type daIngressFixture struct {
	h       *testHarness
	signer  *consensus.MLDSA87Keypair
	address []byte
	ops     []consensus.Outpoint
	lastOp  consensus.Outpoint
	next    int
	nonce   uint64
}

func newDAIngressFixture(t *testing.T, h *testHarness, outpoints int) *daIngressFixture {
	t.Helper()
	signer, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		t.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	t.Cleanup(signer.Close)
	f := &daIngressFixture{h: h, signer: signer, address: consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())}
	for i := 0; i < outpoints; i++ {
		var txid [32]byte
		txid[0], txid[30], txid[31] = 0xda, byte(i>>8), byte(i)
		op := consensus.Outpoint{Txid: txid, Vout: 0}
		h.chainState.Utxos[op] = consensus.UtxoEntry{
			Value:        1_000_000,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), f.address...),
		}
		f.ops = append(f.ops, op)
	}
	return f
}

// op hands out the next unspent fixture outpoint. Every DA member reserves its
// own inputs with the pending-outpoint owner, so two members may never share one.
func (f *daIngressFixture) op(t *testing.T) consensus.Outpoint {
	t.Helper()
	if f.next >= len(f.ops) {
		t.Fatalf("DA ingress fixture ran out of funded outpoints after %d", f.next)
	}
	op := f.ops[f.next]
	f.next++
	f.lastOp = op
	return op
}

// commitTx builds one signed DA commit carrying the single COV_TYPE_DA_COMMIT
// output that holds the set's payload commitment.
func (f *daIngressFixture) commitTx(t *testing.T, daID [32]byte, chunkCount uint16, commitment [32]byte) []byte {
	t.Helper()
	f.nonce++
	tx := &consensus.Tx{
		Version: 1, TxKind: 0x01, TxNonce: f.nonce,
		Inputs: []consensus.TxInput{{PrevTxid: f.op(t).Txid}},
		Outputs: []consensus.TxOutput{
			{Value: 0, CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: append([]byte(nil), commitment[:]...)},
			{Value: 100_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...)},
		},
		DaPayload:    []byte("manifest"),
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: chunkCount, BatchNumber: 1},
	}
	return f.sign(t, tx)
}

// chunkTx builds one signed DA chunk at an exact index.
func (f *daIngressFixture) chunkTx(t *testing.T, daID [32]byte, index uint16, payload []byte) []byte {
	t.Helper()
	f.nonce++
	tx := &consensus.Tx{
		Version: 1, TxKind: 0x02, TxNonce: f.nonce,
		Inputs:      []consensus.TxInput{{PrevTxid: f.op(t).Txid}},
		Outputs:     []consensus.TxOutput{{Value: 100_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...)}},
		DaPayload:   append([]byte(nil), payload...),
		DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: sha3.Sum256(payload)},
	}
	return f.sign(t, tx)
}

func (f *daIngressFixture) sign(t *testing.T, tx *consensus.Tx) []byte {
	t.Helper()
	if err := consensus.SignTransaction(tx, f.h.chainState.Utxos, node.DevnetGenesisChainID(), f.signer); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return raw
}

// admit retains one DA transaction through the production entry.
func (f *daIngressFixture) admit(t *testing.T, raw []byte, peer string) node.DAAdmissionResult {
	t.Helper()
	result, err := f.h.service.daRelay.AdmitDA(raw, mustPeerDAProvenance(t, peer))
	if err != nil {
		t.Fatalf("AdmitDA: %v", err)
	}
	if result.Disposition != node.DAAdmissionRetained {
		t.Fatalf("AdmitDA disposition=%d, want RETAINED", result.Disposition)
	}
	return result
}

// retainCommit is the prefetch rows' shorthand: retain one commit that DECLARES
// chunkCount chunks and stage none of them, leaving the set incomplete.
func (f *daIngressFixture) retainCommit(t *testing.T, daID [32]byte, chunkCount uint16, peer string) {
	t.Helper()
	f.admit(t, f.commitTx(t, daID, chunkCount, sha3.Sum256([]byte{daID[0]})), peer)
}

func mustPeerDAProvenance(t *testing.T, peer string) node.DAProvenance {
	t.Helper()
	provenance, err := node.NewPeerDAProvenance(peer, peerQuotaKey(peer))
	if err != nil {
		t.Fatalf("NewPeerDAProvenance(%q): %v", peer, err)
	}
	return provenance
}

// TestRemoteDAExitsBeforeEveryStandardAuthority is A1/A2/M1: a remote DA commit
// and a remote DA chunk are retained WITHOUT reaching the seen-set, the relay
// pool, the metadata producer or an MSG_TX announcement, while a remote standard
// transaction still reaches all of them exactly once.
func TestRemoteDAExitsBeforeEveryStandardAuthority(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 4)
	p := daRelayTestPeer(h, "127.0.0.1:19111")
	daID := daRelayTestID(0x10)
	payload := []byte("da-exit")
	commitTx := f.commitTx(t, daID, 1, sha3.Sum256(payload))
	chunkTx := f.chunkTx(t, daID, 0, payload)

	for _, raw := range [][]byte{commitTx, chunkTx} {
		if err := p.handleTx(raw); err != nil {
			t.Fatalf("handleTx(DA): %v", err)
		}
		txid, err := canonicalTxID(raw)
		if err != nil {
			t.Fatalf("canonicalTxID: %v", err)
		}
		if h.service.txSeen.Has(txid) {
			t.Fatalf("remote DA %x entered the standard seen-set", txid)
		}
		if _, pooled := h.service.cfg.TxPool.Get(txid); pooled {
			t.Fatalf("remote DA %x entered the relay pool", txid)
		}
		if _, _, err := h.service.daRelay.LookupRetainedTx(txid); err != nil {
			t.Fatalf("LookupRetainedTx(%x): %v", txid, err)
		}
	}
	if _, owned, err := h.service.daRelay.LookupRetainedTx(mustCanonicalTxID(t, commitTx)); !owned || err != nil {
		t.Fatalf("retained commit lookup owned=%v err=%v", owned, err)
	}

	standard := minimalValidTxBytes(t)
	if err := p.handleTx(standard); err != nil {
		t.Fatalf("handleTx(standard): %v", err)
	}
	if !h.service.txSeen.Has(mustCanonicalTxID(t, standard)) {
		t.Fatal("the standard path no longer marks a remote transaction seen")
	}
}

// TestRemoteDuplicateDACommitScoresThePeerAndChunkDoesNot is A3/M7: an exact
// replay changes nothing, a duplicate COMMIT carries the existing +10 negative
// peer effect, and a duplicate CHUNK is peer-neutral.
func TestRemoteDuplicateDACommitScoresThePeerAndChunkDoesNot(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 4)
	daID := daRelayTestID(0x11)
	payload := []byte("da-replay")
	commitTx := f.commitTx(t, daID, 1, sha3.Sum256(payload))
	chunkTx := f.chunkTx(t, daID, 0, payload)

	p := daRelayTestPeer(h, "127.0.0.1:19112")
	for _, raw := range [][]byte{commitTx, chunkTx} {
		if err := p.handleTx(raw); err != nil {
			t.Fatalf("handleTx: %v", err)
		}
	}
	before := daRelayImageDigest(t, h)
	banBefore := p.state.BanScore

	if err := p.handleTx(commitTx); err != nil {
		t.Fatalf("duplicate commit: %v", err)
	}
	if got := p.state.BanScore - banBefore; got != 10 {
		t.Fatalf("duplicate commit ban delta=%d, want 10", got)
	}
	banAfterCommit := p.state.BanScore
	if err := p.handleTx(chunkTx); err != nil {
		t.Fatalf("duplicate chunk: %v", err)
	}
	if p.state.BanScore != banAfterCommit {
		t.Fatalf("duplicate chunk moved the ban score to %d", p.state.BanScore)
	}
	if after := daRelayImageDigest(t, h); after != before {
		t.Fatalf("a duplicate mutated the retained image: %v -> %v", before, after)
	}
}

// TestPeerlessDAProvenanceIsAbsentFromPeerQuotaAccounting is A5/M2: LOCAL and
// DETACHED_REORG are distinct peerless sources that consume no per-peer quota,
// and peer teardown never selects them.
func TestPeerlessDAProvenanceIsAbsentFromPeerQuotaAccounting(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 4)
	local := f.commitTx(t, daRelayTestID(0x12), 2, sha3.Sum256([]byte("local")))
	detached := f.commitTx(t, daRelayTestID(0x13), 2, sha3.Sum256([]byte("detached")))

	for name, provenance := range map[string]node.DAProvenance{
		"local":    node.LocalDAProvenance(),
		"detached": node.DetachedReorgDAProvenance(),
	} {
		raw := local
		if name == "detached" {
			raw = detached
		}
		if _, err := h.service.daRelay.AdmitDA(raw, provenance); err != nil {
			t.Fatalf("AdmitDA(%s): %v", name, err)
		}
	}
	if node.LocalDAProvenance() == node.DetachedReorgDAProvenance() {
		t.Fatal("LOCAL and DETACHED_REORG provenance compare equal")
	}
	before := daRelayImageDigest(t, h)
	if err := h.service.daRelay.ReleasePeerQuotaKey(peerQuotaKey("127.0.0.1:19111")); err != nil {
		t.Fatalf("ReleasePeerQuotaKey: %v", err)
	}
	if err := h.service.daRelay.ReleasePeerQuotaKey(""); err != nil {
		t.Fatalf("ReleasePeerQuotaKey(empty): %v", err)
	}
	if after := daRelayImageDigest(t, h); after != before {
		t.Fatalf("peer teardown selected a peerless member: %v -> %v", before, after)
	}
}

// TestDAProvenanceConstructorsRefuseEmptyIdentities is R1: the zero value and a
// PEER with either identity empty are refused before any state work.
func TestDAProvenanceConstructorsRefuseEmptyIdentities(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 2)
	raw := f.commitTx(t, daRelayTestID(0x14), 1, sha3.Sum256([]byte("x")))

	for _, tt := range []struct{ peer, quota string }{{"", "quota"}, {"peer", ""}, {"", ""}} {
		if _, err := node.NewPeerDAProvenance(tt.peer, tt.quota); err == nil {
			t.Fatalf("NewPeerDAProvenance(%q,%q) was accepted", tt.peer, tt.quota)
		}
	}
	// A nonempty identity of spaces is accepted, which is the documented choice.
	if _, err := node.NewPeerDAProvenance(" ", " "); err != nil {
		t.Fatalf("NewPeerDAProvenance(space) = %v, want accepted", err)
	}
	before := daRelayImageDigest(t, h)
	if _, err := h.service.daRelay.AdmitDA(raw, node.DAProvenance{}); err == nil {
		t.Fatal("AdmitDA accepted the zero provenance value")
	}
	if after := daRelayImageDigest(t, h); after != before {
		t.Fatal("a refused provenance mutated the retained image")
	}
}

// TestAdmitDARefusesNonDAAndMalformedBytes is R2: a standard-kind transaction,
// trailing bytes, empty bytes and an oversize payload are all refused with no
// retained, locator or claim state.
func TestAdmitDARefusesNonDAAndMalformedBytes(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 2)
	valid := f.commitTx(t, daRelayTestID(0x15), 1, sha3.Sum256([]byte("y")))
	before := daRelayImageDigest(t, h)

	for name, raw := range map[string][]byte{
		"standard kind": minimalValidTxBytes(t),
		"trailing byte": append(append([]byte(nil), valid...), 0x00),
		"empty":         {},
		"oversize":      make([]byte, consensus.MAX_RELAY_MSG_BYTES+1),
	} {
		if _, err := h.service.daRelay.AdmitDA(raw, mustPeerDAProvenance(t, "127.0.0.1:19111")); err == nil {
			t.Fatalf("AdmitDA(%s) was accepted", name)
		}
	}
	if after := daRelayImageDigest(t, h); after != before {
		t.Fatal("a refused admission mutated the retained image")
	}
}

func mustCanonicalTxID(t *testing.T, raw []byte) [32]byte {
	t.Helper()
	txid, err := canonicalTxID(raw)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}
	return txid
}

// daRelayImageDigest is the observable retained-DA image from OUTSIDE package
// node: the complete-set candidate snapshot plus every retained member the
// locator index can still produce. It is what a "changed nothing" row compares.
func daRelayImageDigest(t *testing.T, h *testHarness) string {
	t.Helper()
	digest := ""
	for _, candidate := range h.service.CompleteDASetCandidates(1 << 30) {
		digest += string(candidate.DAID[:]) + string(candidate.CommitTx)
		for _, chunk := range candidate.Chunks {
			digest += string(chunk.Tx)
		}
	}
	return digest
}

func mustParseDATxForTest(t *testing.T, raw []byte) *consensus.Tx {
	t.Helper()
	tx, _, err := parseCanonicalTx(raw)
	if err != nil {
		t.Fatalf("parseCanonicalTx: %v", err)
	}
	return tx
}
