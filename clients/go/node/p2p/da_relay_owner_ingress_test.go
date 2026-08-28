package p2p

import (
	"crypto/sha3"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	// built records every signed transaction this fixture produced, so the
	// image digest below can render State A and State B members — which the
	// complete-set snapshot alone cannot see — and an "unchanged" comparison
	// over an incomplete record is never vacuous.
	built [][]byte
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
	f.built = append(f.built, raw)
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
// transaction still reaches all four exactly once.
//
// All four authorities are ASSERTED, none is prose. The producer is the service's
// own TxMetadataFunc, counted through a spy that wraps the harness default; the
// MSG_TX announcement is counted as wire frames written to the ONLY peer
// registered with the service, which is therefore broadcastInventory's whole
// selection set. The standard half is what makes both counters non-vacuous: they must
// MOVE for a standard transaction on the very same peer and service.
func TestRemoteDAExitsBeforeEveryStandardAuthority(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 4)
	p := daRelayTestPeer(h, "127.0.0.1:19111")
	producerCalls := 0
	inner := h.service.cfg.TxMetadataFunc
	h.service.cfg.TxMetadataFunc = func(b []byte) (node.RelayTxMetadata, error) {
		producerCalls++
		return inner(b)
	}
	listener := &recordingConn{}
	announced := &peer{conn: listener, service: h.service, state: nodePeerState("127.0.0.1:19119")}
	h.service.peersMu.Lock()
	h.service.peers[announced.addr()] = announced
	h.service.peersMu.Unlock()

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
		if producerCalls != 0 {
			t.Fatalf("remote DA %x reached the metadata producer %d times", txid, producerCalls)
		}
		if frames := listener.framesWritten(); frames != 0 {
			t.Fatalf("remote DA %x announced %d frames to another peer", txid, frames)
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
	if producerCalls != 1 || listener.framesWritten() != 1 {
		t.Fatalf("standard path producer calls=%d announced frames=%d, want 1 and 1 — the DA assertions above are vacuous otherwise", producerCalls, listener.framesWritten())
	}
}

// frozenD00R3PeerEffect reads ONE case's expected peer_quality_effect from the
// frozen D00-R3 authority, so the peer-effect assertions below are driven by
// the inert expected artifact rather than by this package's own constants.
func frozenD00R3PeerEffect(t *testing.T, caseID string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "conformance", "fixtures", "protocol", "da_admission_expected_v1.json"))
	if err != nil {
		t.Fatalf("read frozen D00-R3 authority: %v", err)
	}
	var artifact struct {
		Cases []struct {
			ID     string `json:"id"`
			Expect struct {
				P2P struct {
					PeerQualityEffect string `json:"peer_quality_effect"`
				} `json:"p2p_envelope"`
			} `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatalf("decode frozen D00-R3 authority: %v", err)
	}
	for _, row := range artifact.Cases {
		if row.ID == caseID {
			if row.Expect.P2P.PeerQualityEffect == "" {
				t.Fatalf("frozen row %s carries no peer effect", caseID)
			}
			return row.Expect.P2P.PeerQualityEffect
		}
	}
	t.Fatalf("frozen row %s is absent from the artifact", caseID)
	return ""
}

// requireFrozenPeerEffect maps caseID's frozen peer_quality_effect onto the ban
// delta this arm applies: UNCHANGED is zero, NEGATIVE_DUPLICATE_COMMIT is the
// existing +10.
func requireFrozenPeerEffect(t *testing.T, caseID string, delta int) {
	t.Helper()
	effect := frozenD00R3PeerEffect(t, caseID)
	want := 0
	if effect == "NEGATIVE_DUPLICATE_COMMIT" {
		want = 10
	}
	if delta != want {
		t.Fatalf("%s: ban delta=%d, frozen effect %q wants %d", caseID, delta, effect, want)
	}
}

// TestRemoteExactReplayIsPeerNeutralAndDistinctCommitIsNot executes the frozen
// D00-R3 peer-effect rows through the REAL remote entry: an exact retained
// commit or chunk replay — REQUESTED (redelivered by the peer the member came
// from) and UNSOLICITED (pushed by a peer that never delivered it; this client
// tracks no requests until RUB-1169, so the entry is deliberately the same and
// the frozen rows expect identical outcomes) — moves no score, drops no
// connection and changes no image; ONLY the fully validated different-txid
// same-da_id commit carries the existing +10, applied from the admission's
// SameDAIDCommitConflict bool and never from tx kind or DUPLICATE alone.
func TestRemoteExactReplayIsPeerNeutralAndDistinctCommitIsNot(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 4)
	daID := daRelayTestID(0x11)
	payload := []byte("da-replay")
	commitTx := f.commitTx(t, daID, 1, sha3.Sum256(payload))
	chunkTx := f.chunkTx(t, daID, 0, payload)

	origin := daRelayTestPeer(h, "127.0.0.1:19112")
	stranger := daRelayTestPeer(h, "127.0.0.1:19118")
	for _, raw := range [][]byte{commitTx, chunkTx} {
		if err := origin.handleTx(raw); err != nil {
			t.Fatalf("handleTx: %v", err)
		}
	}
	before := f.imageDigest(t)
	for _, tt := range []struct {
		caseID string
		peer   *peer
		raw    []byte
	}{
		{"REMOTE_EXACT_REPLAY", origin, commitTx},
		{"REMOTE_EXACT_CHUNK_REPLAY", origin, chunkTx},
		{"REMOTE_EXACT_COMMIT_REPLAY_UNSOLICITED", stranger, commitTx},
		{"REMOTE_EXACT_CHUNK_REPLAY_UNSOLICITED", stranger, chunkTx},
	} {
		banBefore := tt.peer.state.BanScore
		if err := tt.peer.handleTx(tt.raw); err != nil {
			t.Fatalf("%s: handleTx=%v, want the peer-neutral nil", tt.caseID, err)
		}
		requireFrozenPeerEffect(t, tt.caseID, tt.peer.state.BanScore-banBefore)
		if after := f.imageDigest(t); after != before {
			t.Fatalf("%s mutated the retained image", tt.caseID)
		}
	}

	// The distinct same-da_id commit: fully validated, different txid, same set.
	// The baseline is retaken AFTER the build: the digest probes every built
	// transaction, so building one extends the probe set without changing state.
	distinct := f.commitTx(t, daID, 1, sha3.Sum256([]byte("competitor")))
	beforeDistinct := f.imageDigest(t)
	banBefore := stranger.state.BanScore
	if err := stranger.handleTx(distinct); err != nil {
		t.Fatalf("distinct commit below threshold: %v", err)
	}
	requireFrozenPeerEffect(t, "CAP_COMPLETE_DUPLICATE_MEMBER", stranger.state.BanScore-banBefore)
	if after := f.imageDigest(t); after != beforeDistinct {
		t.Fatal("the discarded distinct commit mutated the retained image")
	}
	// The EXISTING threshold handling, not a new one: once the accumulated score
	// reaches the configured threshold the same +10 is reported as a hard error.
	h.service.cfg.PeerRuntimeConfig.BanThreshold = stranger.state.BanScore + 10
	if err := stranger.handleTx(distinct); err == nil {
		t.Fatal("a distinct same-da_id commit at the ban threshold was reported as peer-neutral")
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
	before := f.imageDigest(t)
	if err := h.service.daRelay.ReleasePeerQuotaKey(peerQuotaKey("127.0.0.1:19111")); err != nil {
		t.Fatalf("ReleasePeerQuotaKey: %v", err)
	}
	if err := h.service.daRelay.ReleasePeerQuotaKey(""); err != nil {
		t.Fatalf("ReleasePeerQuotaKey(empty): %v", err)
	}
	if after := f.imageDigest(t); after != before {
		t.Fatalf("peer teardown selected a peerless member: %v -> %v", before, after)
	}
}

// TestAdmitDARefusesNonDAAndMalformedBytes is R2: a standard-kind transaction,
// trailing bytes, empty bytes and an oversize payload are all refused with no
// retained, locator or claim state.
func TestAdmitDARefusesNonDAAndMalformedBytes(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 2)
	valid := f.commitTx(t, daRelayTestID(0x15), 1, sha3.Sum256([]byte("y")))
	// The valid commit IS retained first, so the unchanged comparison below
	// holds a real State B member in view rather than an empty image.
	f.admit(t, valid, "127.0.0.1:19111")
	before := f.imageDigest(t)

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
	if after := f.imageDigest(t); after != before {
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

// imageDigest is the observable retained-DA image from OUTSIDE package node:
// every transaction the fixture ever built is probed through LookupRetainedTx —
// which renders State A, B and C members alike, with their exact bytes — plus
// the complete-set candidate snapshot. An "unchanged" comparison over a State B
// image is therefore NON-VACUOUS: a staged commit or orphan chunk appearing,
// disappearing or changing bytes changes this digest.
func (f *daIngressFixture) imageDigest(t *testing.T) string {
	t.Helper()
	digest := ""
	for _, raw := range f.built {
		txid := mustCanonicalTxID(t, raw)
		snapshot, owned, err := f.h.service.daRelay.LookupRetainedTx(txid)
		digest += fmt.Sprintf("|%x owned=%v internal=%v bytes=%x", txid, owned, err != nil, sha3.Sum256(snapshot.TxBytes))
	}
	for _, candidate := range f.h.service.CompleteDASetCandidates(1 << 30) {
		digest += "|complete " + string(candidate.DAID[:]) + string(candidate.CommitTx)
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

// TestRemoteDAFromAnAddresslessPeerIsRefusedAndRetainsNothing pins the TOTALITY
// of the DA arm's provenance construction. A registered peer cannot reach this
// state — the handshake binds the address and registerPeer already keyed the
// quota lock by it — so this row constructs the peer directly and pins the
// documented choice for the impossible case: a hard error that drops the
// connection, with nothing retained and NO score moved (the shape check already
// passed, so a ban here would punish a peer for the node's own bookkeeping).
func TestRemoteDAFromAnAddresslessPeerIsRefusedAndRetainsNothing(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 2)
	p := daRelayTestPeer(h, "")
	chunkTx := f.chunkTx(t, daRelayTestID(0x18), 0, []byte("addressless"))
	banBefore := p.state.BanScore

	if err := p.handleTx(chunkTx); err == nil {
		t.Fatal("a DA transaction from an addressless peer was accepted")
	}
	if p.state.BanScore != banBefore {
		t.Fatalf("ban score moved to %d, want the peer-neutral %d", p.state.BanScore, banBefore)
	}
	txid := mustCanonicalTxID(t, chunkTx)
	if _, owned, err := h.service.daRelay.LookupRetainedTx(txid); owned || err != nil {
		t.Fatalf("addressless admission retained state: owned=%v err=%v", owned, err)
	}
	if h.service.txSeen.Has(txid) {
		t.Fatal("the refused DA transaction entered the standard seen-set")
	}
}

// TestRemoteDAAdmissionRejectionIsPeerNeutral is R2's peer-consequence half on
// the arm the shape check cannot reach: a WELL-SHAPED DA transaction whose
// admission fails inside BeginDAAdmission — here because the outpoint it spends
// is no longer in the chainstate — is refused with NO score moved and no retained
// state, exactly as the standard path treats its own admission rejections.
func TestRemoteDAAdmissionRejectionIsPeerNeutral(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 2)
	chunkTx := f.chunkTx(t, daRelayTestID(0x19), 0, []byte("unfunded"))
	delete(h.chainState.Utxos, f.lastOp)
	p := daRelayTestPeer(h, "127.0.0.1:19116")
	banBefore := p.state.BanScore

	if err := p.handleTx(chunkTx); err != nil {
		t.Fatalf("handleTx(unfunded DA chunk) = %v, want the peer-neutral nil", err)
	}
	if p.state.BanScore != banBefore {
		t.Fatalf("ban score moved to %d, want the peer-neutral %d", p.state.BanScore, banBefore)
	}
	txid := mustCanonicalTxID(t, chunkTx)
	if _, owned, err := h.service.daRelay.LookupRetainedTx(txid); owned || err != nil {
		t.Fatalf("a rejected admission retained state: owned=%v err=%v", owned, err)
	}
	if h.service.txSeen.Has(txid) {
		t.Fatal("a rejected DA transaction entered the standard seen-set")
	}
}

// TestRemoteDAAdmissionSerializesOnItsPeerQuotaKey is H5 SAME_QUOTA_LIFECYCLE on
// the ADMISSION side: registration, admission and teardown of one quota identity
// all pass through the one key lock, and two different keys still progress
// independently.
//
// The lock is driven exactly as the lifecycle sites drive it — the production
// helper, held across the window under test — so the row proves participation in
// the same lock rather than the existence of some lock. Both halves are bounded
// and report by CHANNEL: a failure is a timeout, never a hung suite.
func TestRemoteDAAdmissionSerializesOnItsPeerQuotaKey(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h, 2)
	daID := daRelayTestID(0x1a)
	held, other := "127.0.0.1:19140", "127.0.0.2:19141"

	// Same key: the admission must not complete while the key is held.
	unlock := h.service.lockPeerQuotaKey(peerQuotaKey(held))
	blocked := admitDAInBackground(t, h, f.commitTx(t, daID, 1, sha3.Sum256([]byte("same-key"))), held)
	select {
	case err := <-blocked:
		unlock()
		t.Fatalf("the admission completed (err=%v) while its own quota key was held", err)
	case <-time.After(200 * time.Millisecond):
	}

	// A DIFFERENT key is not serialized behind it.
	free := admitDAInBackground(t, h, f.commitTx(t, daRelayTestID(0x1b), 1, sha3.Sum256([]byte("other-key"))), other)
	select {
	case err := <-free:
		if err != nil {
			t.Fatalf("the admission on a different quota key failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		unlock()
		t.Fatal("an admission on a DIFFERENT quota key was serialized behind the held one")
	}

	unlock()
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("the released admission failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the admission did not complete after its quota key was released")
	}
}

// TestLatchedEngineLeavesTheDAAdmissionQuotaKeyFree is A12's teardown half: an
// admission waiting at the fence a latched transition never releases must not
// hold the peer-quota key, or unregisterPeer for it never finishes.
func TestLatchedEngineLeavesTheDAAdmissionQuotaKeyFree(t *testing.T) {
	h := latchedDAHarness(t, newTestHarness(t, 4, "127.0.0.1:0", nil))
	f := newDAIngressFixture(t, h, 1)
	addr := "127.0.0.1:19150"
	parked := admitDAInBackground(t, h, f.chunkTx(t, daRelayTestID(0x1c), 0, []byte("latched")), addr)
	select {
	case err := <-parked:
		t.Fatalf("the admission returned (err=%v) instead of waiting at the inherited fence", err)
	case <-time.After(200 * time.Millisecond):
	}
	done := make(chan error, 1)
	go func() { h.service.unregisterPeer(daRelayTestPeer(h, addr)); done <- nil }()
	requireReturned(t, done, "unregisterPeer on the quota key of a waiting latched admission")
}

// admitDAInBackground runs one remote DA admission on its own peer and reports
// the handler result on a channel, so a caller can bound the wait instead of
// blocking the suite. Every t.Fatalf-worthy input is built by the CALLER, on the
// test goroutine.
func admitDAInBackground(t *testing.T, h *testHarness, raw []byte, addr string) <-chan error {
	t.Helper()
	p := daRelayTestPeer(h, addr)
	done := make(chan error, 1)
	go func() { done <- p.handleTx(raw) }()
	return done
}
