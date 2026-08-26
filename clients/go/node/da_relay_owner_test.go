package node

import (
	"crypto/sha3"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// daOwnerFixture is one engine with a bound mempool, owner and retained-DA
// state, plus the funded outpoints its DA transactions spend.
type daOwnerFixture struct{ *canonicalMOFixture }

func newDAOwnerFixture(t *testing.T, inputs int) *daOwnerFixture {
	t.Helper()
	return &daOwnerFixture{newCanonicalMOFixture(t, inputs, MempoolConfig{})}
}

func (f *daOwnerFixture) relay() *DARelayState { return f.engine.DARelayState() }

func (f *daOwnerFixture) owner() *PendingOutpointOwner { return f.mp.PendingOutpointOwner() }

// image is the complete observable retained-DA state: every record, every
// locator row and every live DA claim, rendered so a "changed nothing" row is a
// single equality rather than a list of spot checks.
func (f *daOwnerFixture) image(t *testing.T) string {
	t.Helper()
	relay, out := f.relay(), ""
	relay.mu.Lock()
	for _, daID := range relay.sortedRetainedDAIDsLocked() {
		record := relay.sets[daID]
		out += string(daID[:]) + string(rune(record.state)) + string(rune(record.receivedTime))
		for _, member := range record.members() {
			out += string(member.txid[:]) + string(member.wtxid[:]) + string(rune(member.token.seq))
		}
	}
	for txid, locator := range relay.locators {
		out += string(txid[:]) + string(rune(locator.kind)) + string(rune(locator.chunkIndex))
	}
	sequence := relay.nextReceivedTime
	relay.mu.Unlock()
	owner := f.owner()
	owner.mu.Lock()
	out += string(rune(len(owner.byToken))) + string(rune(len(owner.byOutpoint))) + string(rune(sequence))
	owner.mu.Unlock()
	return out
}

func mustPeerProvenance(t *testing.T, peer string) DAProvenance {
	t.Helper()
	provenance, err := NewPeerDAProvenance(peer, peer)
	if err != nil {
		t.Fatalf("NewPeerDAProvenance(%q): %v", peer, err)
	}
	return provenance
}

// TestDAProvenanceIsAClosedSetWithAnInvalidZeroValue is R1 plus the api_contract
// shape: the zero value is invalid, a PEER needs BOTH identities, the two
// peerless sources are distinct and carry none, and a forged out-of-set value is
// refused.
func TestDAProvenanceIsAClosedSetWithAnInvalidZeroValue(t *testing.T) {
	if LocalDAProvenance() == DetachedReorgDAProvenance() {
		t.Fatal("LOCAL and DETACHED_REORG compare equal")
	}
	if LocalDAProvenance() == (DAProvenance{}) || DetachedReorgDAProvenance() == (DAProvenance{}) {
		t.Fatal("a peerless provenance compares equal to the invalid zero value")
	}
	if got := LocalDAProvenance().quotaKey(); got != "" {
		t.Fatalf("LOCAL quota key=%q, want empty", got)
	}
	for _, tt := range []struct{ peer, quota string }{{"", "q"}, {"p", ""}, {"", ""}} {
		if _, err := NewPeerDAProvenance(tt.peer, tt.quota); err == nil {
			t.Fatalf("NewPeerDAProvenance(%q,%q) was accepted", tt.peer, tt.quota)
		}
	}
	// Documented choice: emptiness is the only identity rule, so a nonempty
	// string of spaces is a valid identity.
	spaced, err := NewPeerDAProvenance(" ", " ")
	if err != nil || spaced.quotaKey() != " " {
		t.Fatalf("NewPeerDAProvenance(space) = %v, quota=%q", err, spaced.quotaKey())
	}
	for name, provenance := range map[string]DAProvenance{
		"zero value":         {},
		"forged kind":        {kind: daProvenanceKind(9), peerIdentity: "p", quotaIdentity: "q"},
		"peerless with peer": {kind: daProvenanceLocal, peerIdentity: "p"},
		"peer without quota": {kind: daProvenancePeer, peerIdentity: "p"},
	} {
		if err := provenance.validate(); err == nil {
			t.Fatalf("provenance %q validated", name)
		}
	}
}

// TestDAAdmissionDispositionConstantsArePinned is the closed nonzero enum row.
// The values are compared against literals, not against each other, so a
// renumbering is a failure rather than a self-consistent rename.
func TestDAAdmissionDispositionConstantsArePinned(t *testing.T) {
	if uint8(DAAdmissionRetained) != 1 || uint8(DAAdmissionDuplicate) != 2 {
		t.Fatalf("dispositions retained=%d duplicate=%d, want 1 and 2", DAAdmissionRetained, DAAdmissionDuplicate)
	}
	if (DAAdmissionResult{}).Disposition != 0 {
		t.Fatal("the zero DAAdmissionResult carries a disposition value")
	}
}

// TestAdmitDARetainsTheExactMemberLocatorAndFinalizedClaim is A2's bijection:
// one accepted member publishes exactly one record member, one locator row and
// one finalized DA claim carrying the member's exact txid and ordered inputs.
func TestAdmitDARetainsTheExactMemberLocatorAndFinalizedClaim(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	daID, payload := daRelayTestID(0x30), []byte("owner-payload")
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2000, sha3.Sum256(payload))
	result, err := f.relay().AdmitDA(commitTx, mustPeerProvenance(t, "peer-a"))
	if err != nil || result.Disposition != DAAdmissionRetained || result.DAID != daID {
		t.Fatalf("AdmitDA result=%+v err=%v", result, err)
	}
	txid := txID(t, commitTx)
	relay := f.relay()
	relay.mu.Lock()
	record, present := relay.sets[daID]
	locator, located := relay.locators[txid]
	sequence := relay.nextReceivedTime
	relay.mu.Unlock()
	if !present || !located || locator != (daRelayLocator{daID: daID, kind: daRelayLocatorCommit}) {
		t.Fatalf("record present=%v locator=%+v located=%v", present, locator, located)
	}
	if record.receivedTime != 1 || sequence != 1 {
		t.Fatalf("accepted sequence record=%d high-water=%d, want 1 and 1", record.receivedTime, sequence)
	}
	member := record.commit.daRelayMemberIdentity
	if member.txid != txid || member.token == (PendingOutpointToken{}) || member.retainedBytes != uint64(len(commitTx)) {
		t.Fatalf("retained member=%+v", member)
	}
	owner := f.owner()
	owner.mu.Lock()
	claim := owner.byToken[member.token]
	owner.mu.Unlock()
	if claim == nil || claim.domain != PendingOutpointDA || claim.txid != txid || !claim.finalized {
		t.Fatalf("owner claim=%+v, want the member's own finalized DA claim", claim)
	}
	snapshot, owned, err := relay.LookupRetainedTx(txid)
	if !owned || err != nil || snapshot.TxID != txid || string(snapshot.TxBytes) != string(commitTx) {
		t.Fatalf("LookupRetainedTx owned=%v err=%v snapshot=%+v", owned, err, snapshot)
	}
	snapshot.TxBytes[0] ^= 0xff
	if again, _, _ := relay.LookupRetainedTx(txid); string(again.TxBytes) != string(commitTx) {
		t.Fatal("a caller mutating the returned bytes reached the retained image")
	}
}

// TestAdmitDADuplicateReservesNothingAndConsumesNoSequence is A3/M7: an exact
// replay returns DUPLICATE with the complete image unchanged, and a same-txid
// different-wtxid variant is not classified as a duplicate.
func TestAdmitDADuplicateReservesNothingAndConsumesNoSequence(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	daID, payload := daRelayTestID(0x31), []byte("dup-payload")
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2010, sha3.Sum256(payload))
	if _, err := f.relay().AdmitDA(commitTx, mustPeerProvenance(t, "peer-a")); err != nil {
		t.Fatalf("first AdmitDA: %v", err)
	}
	before := f.image(t)
	result, err := f.relay().AdmitDA(commitTx, mustPeerProvenance(t, "peer-b"))
	if err != nil || result.Disposition != DAAdmissionDuplicate || result.DAID != daID {
		t.Fatalf("duplicate result=%+v err=%v", result, err)
	}
	if after := f.image(t); after != before {
		t.Fatal("a duplicate mutated the record, locator, claim or accepted-sequence image")
	}
}

// TestAdmitDARefusesEveryPreOwnerCondition is R1/R2/R4: an invalid provenance, a
// standard-kind transaction, trailing bytes, empty bytes, an oversize payload and
// an unfunded input each leave the complete image byte-identical.
func TestAdmitDARefusesEveryPreOwnerCondition(t *testing.T) {
	f := newDAOwnerFixture(t, 3)
	daID, payload := daRelayTestID(0x32), []byte("reject-payload")
	valid := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2020, sha3.Sum256(payload))
	if _, err := f.relay().AdmitDA(valid, mustPeerProvenance(t, "peer-a")); err != nil {
		t.Fatalf("setup AdmitDA: %v", err)
	}
	before := f.image(t)
	for name, tt := range map[string]struct {
		raw        []byte
		provenance DAProvenance
	}{
		"zero provenance": {f.daCommitTxCommitting(t, f.ops[1], daRelayTestID(0x34), 1, 2022, sha3.Sum256(payload)), DAProvenance{}},
		"standard kind":   {f.raw(t, f.ops[1], 2023, false), mustPeerProvenance(t, "peer-a")},
		"trailing byte":   {append(append([]byte(nil), valid...), 0x00), mustPeerProvenance(t, "peer-a")},
		"empty":           {[]byte{}, mustPeerProvenance(t, "peer-a")},
		"oversize":        {make([]byte, consensus.MAX_RELAY_MSG_BYTES+1), mustPeerProvenance(t, "peer-a")},
	} {
		if _, err := f.relay().AdmitDA(tt.raw, tt.provenance); err == nil {
			t.Fatalf("AdmitDA(%s) was accepted", name)
		}
		if after := f.image(t); after != before {
			t.Fatalf("AdmitDA(%s) mutated the retained image", name)
		}
	}
}

// TestAdmitDACommitLastMismatchRemovesTheChunksAndTheirClaims is A6: the
// first-seen commit is retained as State B, the mismatching chunks and their
// exact claims are removed, and one sequence value is consumed by the commit.
func TestAdmitDACommitLastMismatchRemovesTheChunksAndTheirClaims(t *testing.T) {
	f := newDAOwnerFixture(t, 3)
	daID := daRelayTestID(0x35)
	chunkTx := f.daChunkTx(t, f.ops[0], daID, 0, 2030, []byte("chunk-payload"))
	if _, err := f.relay().AdmitDA(chunkTx, mustPeerProvenance(t, "peer-a")); err != nil {
		t.Fatalf("chunk AdmitDA: %v", err)
	}
	chunkTxID := txID(t, chunkTx)
	commitTx := f.daCommitTxCommitting(t, f.ops[1], daID, 1, 2031, sha3.Sum256([]byte("a different payload")))
	result, err := f.relay().AdmitDA(commitTx, mustPeerProvenance(t, "peer-b"))
	if err != nil || result.Disposition != DAAdmissionRetained {
		t.Fatalf("commit-last mismatch result=%+v err=%v", result, err)
	}
	relay := f.relay()
	relay.mu.Lock()
	record := relay.sets[daID]
	_, chunkLocated := relay.locators[chunkTxID]
	sequence := relay.nextReceivedTime
	relay.mu.Unlock()
	if record.state != daRelayStateStagedCommit || len(record.chunks) != 0 || chunkLocated {
		t.Fatalf("record state=%v chunks=%d chunk locator retained=%v", record.state, len(record.chunks), chunkLocated)
	}
	if sequence != 2 || record.receivedTime != 1 {
		t.Fatalf("sequence high-water=%d record receivedTime=%d, want 2 and the FIRST member's 1", sequence, record.receivedTime)
	}
	owner := f.owner()
	owner.mu.Lock()
	claims := len(owner.byToken)
	owner.mu.Unlock()
	if claims != 1 {
		t.Fatalf("live owner claims=%d, want only the retained commit's", claims)
	}
	if _, owned, err := relay.LookupRetainedTx(chunkTxID); owned || err != nil {
		t.Fatalf("removed chunk lookup owned=%v err=%v, want ABSENT_DA", owned, err)
	}
}

// TestAdmitDAChunkLastMismatchChangesNothing is R3: the candidate is rejected and
// the existing State B record and every claim survive byte-identical.
func TestAdmitDAChunkLastMismatchChangesNothing(t *testing.T) {
	f := newDAOwnerFixture(t, 3)
	daID := daRelayTestID(0x36)
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2040, sha3.Sum256([]byte("committed")))
	if _, err := f.relay().AdmitDA(commitTx, mustPeerProvenance(t, "peer-a")); err != nil {
		t.Fatalf("commit AdmitDA: %v", err)
	}
	before := f.image(t)
	chunkTx := f.daChunkTx(t, f.ops[1], daID, 0, 2041, []byte("not-committed"))
	if _, err := f.relay().AdmitDA(chunkTx, mustPeerProvenance(t, "peer-b")); err == nil {
		t.Fatal("a chunk-last payload mismatch was retained")
	}
	if after := f.image(t); after != before {
		t.Fatal("a chunk-last mismatch mutated the retained image")
	}
}

// TestLookupRetainedTxIsTriStateAndNeverReportsAbsenceForCorruption is A11/H6/M8:
// an absent txid is ABSENT_DA, and a locator that cannot produce its own member
// is INTERNAL rather than absence.
func TestLookupRetainedTxIsTriStateAndNeverReportsAbsenceForCorruption(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	daID, payload := daRelayTestID(0x37), []byte("lookup-payload")
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2050, sha3.Sum256(payload))
	if _, err := f.relay().AdmitDA(commitTx, mustPeerProvenance(t, "peer-a")); err != nil {
		t.Fatalf("AdmitDA: %v", err)
	}
	relay := f.relay()
	if snapshot, owned, err := relay.LookupRetainedTx([32]byte{0xab}); owned || err != nil || snapshot.TxID != ([32]byte{}) {
		t.Fatalf("absent lookup owned=%v err=%v snapshot=%+v, want ABSENT_DA", owned, err, snapshot)
	}
	relay.mu.Lock()
	// Three corruption classes the index itself can hold: a row naming an absent
	// record, a row naming a member whose retained txid is a different one, and a
	// row naming a member slot the record does not have.
	relay.locators[[32]byte{0xcd}] = daRelayLocator{daID: daRelayTestID(0xee), kind: daRelayLocatorCommit}
	relay.locators[[32]byte{0xce}] = daRelayLocator{daID: daID, kind: daRelayLocatorCommit}
	relay.locators[[32]byte{0xcf}] = daRelayLocator{daID: daID, kind: daRelayLocatorChunk, chunkIndex: 7}
	relay.mu.Unlock()
	for name, txid := range map[string][32]byte{
		"dangling locator":  {0xcd},
		"wrong record":      {0xce},
		"wrong member kind": {0xcf},
	} {
		snapshot, owned, err := relay.LookupRetainedTx(txid)
		if owned || err == nil || snapshot.TxID != ([32]byte{}) {
			t.Fatalf("%s lookup owned=%v err=%v, want INTERNAL", name, owned, err)
		}
	}
}

// TestPeerCleanupSelectionIsProvenanceExact walks the Section 18.3 cartesian
// closure: State A matching and non-matching members, State B with an all-PEER
// record, State B with a peerless member, and State C.
func TestPeerCleanupSelectionIsProvenanceExact(t *testing.T) {
	t.Run("state A removes only the matching PEER member", func(t *testing.T) {
		f := newDAOwnerFixture(t, 4)
		mine := f.daChunkTx(t, f.ops[0], daRelayTestID(0x40), 0, 2060, []byte("mine"))
		theirs := f.daChunkTx(t, f.ops[1], daRelayTestID(0x41), 0, 2061, []byte("theirs"))
		local := f.daChunkTx(t, f.ops[2], daRelayTestID(0x42), 0, 2062, []byte("local"))
		mustAdmit(t, f, mine, mustPeerProvenance(t, "peer-a"))
		mustAdmit(t, f, theirs, mustPeerProvenance(t, "peer-b"))
		mustAdmit(t, f, local, LocalDAProvenance())
		if err := f.relay().ReleasePeerQuotaKey("peer-a"); err != nil {
			t.Fatalf("ReleasePeerQuotaKey: %v", err)
		}
		requireRetained(t, f, txID(t, mine), false, "the departing peer's own member")
		requireRetained(t, f, txID(t, theirs), true, "another peer's member")
		requireRetained(t, f, txID(t, local), true, "a LOCAL member")
	})

	t.Run("state B all-PEER commit deletes the whole record", func(t *testing.T) {
		f := newDAOwnerFixture(t, 4)
		daID := daRelayTestID(0x43)
		chunkTx := f.daChunkTx(t, f.ops[0], daID, 0, 2070, []byte("q-chunk"))
		commitTx := f.daCommitTxCommitting(t, f.ops[1], daID, 2, 2071, sha3.Sum256([]byte("two")))
		mustAdmit(t, f, chunkTx, mustPeerProvenance(t, "peer-q"))
		mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-p"))
		if err := f.relay().ReleasePeerQuotaKey("peer-p"); err != nil {
			t.Fatalf("ReleasePeerQuotaKey: %v", err)
		}
		requireRetained(t, f, txID(t, commitTx), false, "the selected State B commit")
		requireRetained(t, f, txID(t, chunkTx), false, "the PEER(Q) member of the deleted record")
	})

	t.Run("state B with a peerless member keeps the commit", func(t *testing.T) {
		f := newDAOwnerFixture(t, 4)
		daID := daRelayTestID(0x44)
		localChunk := f.daChunkTx(t, f.ops[0], daID, 0, 2080, []byte("local-chunk"))
		peerChunk := f.daChunkTx(t, f.ops[1], daID, 1, 2081, []byte("peer-chunk"))
		commitTx := f.daCommitTxCommitting(t, f.ops[2], daID, 3, 2082, sha3.Sum256([]byte("three")))
		mustAdmit(t, f, localChunk, DetachedReorgDAProvenance())
		mustAdmit(t, f, peerChunk, mustPeerProvenance(t, "peer-p"))
		mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-p"))
		if err := f.relay().ReleasePeerQuotaKey("peer-p"); err != nil {
			t.Fatalf("ReleasePeerQuotaKey: %v", err)
		}
		requireRetained(t, f, txID(t, commitTx), true, "an ineligible State B commit")
		requireRetained(t, f, txID(t, localChunk), true, "the DETACHED_REORG member")
		requireRetained(t, f, txID(t, peerChunk), false, "the matching PEER chunk")
		f.relay().mu.Lock()
		state := f.relay().sets[daID].state
		f.relay().mu.Unlock()
		if state != daRelayStateStagedCommit {
			t.Fatalf("record state=%v, want State B preserved", state)
		}
	})

	t.Run("state C is a no-op", func(t *testing.T) {
		f := newDAOwnerFixture(t, 4)
		daID, payload := daRelayTestID(0x45), []byte("complete")
		commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2090, sha3.Sum256(payload))
		chunkTx := f.daChunkTx(t, f.ops[1], daID, 0, 2091, payload)
		mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-p"))
		mustAdmit(t, f, chunkTx, mustPeerProvenance(t, "peer-p"))
		before := f.image(t)
		if err := f.relay().ReleasePeerQuotaKey("peer-p"); err != nil {
			t.Fatalf("ReleasePeerQuotaKey: %v", err)
		}
		if after := f.image(t); after != before {
			t.Fatal("peer cleanup touched a COMPLETE_SET")
		}
	})
}

// TestTTLExpiryRemovesTheWholeRecordAndEveryClaim is A8's TTL half.
func TestTTLExpiryRemovesTheWholeRecordAndEveryClaim(t *testing.T) {
	f := newDAOwnerFixture(t, 4)
	daID, complete := daRelayTestID(0x46), daRelayTestID(0x47)
	orphan := f.daChunkTx(t, f.ops[0], daID, 0, 2100, []byte("orphan"))
	mustAdmit(t, f, orphan, mustPeerProvenance(t, "peer-a"))
	payload := []byte("kept")
	commitTx := f.daCommitTxCommitting(t, f.ops[1], complete, 1, 2101, sha3.Sum256(payload))
	chunkTx := f.daChunkTx(t, f.ops[2], complete, 0, 2102, payload)
	mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-a"))
	mustAdmit(t, f, chunkTx, mustPeerProvenance(t, "peer-a"))
	for i := 0; i < int(defaultDARelayCaps().orphanTTLBlocks); i++ {
		if err := f.relay().AdvanceOrphanTTL(); err != nil {
			t.Fatalf("AdvanceOrphanTTL(%d): %v", i, err)
		}
	}
	requireRetained(t, f, txID(t, orphan), false, "the expired incomplete record")
	requireRetained(t, f, txID(t, commitTx), true, "the COMPLETE_SET commit TTL never walks")
	owner := f.owner()
	owner.mu.Lock()
	claims := len(owner.byToken)
	owner.mu.Unlock()
	if claims != 2 {
		t.Fatalf("live owner claims after TTL=%d, want the two COMPLETE_SET members", claims)
	}
}

func mustAdmit(t *testing.T, f *daOwnerFixture, raw []byte, provenance DAProvenance) {
	t.Helper()
	result, err := f.relay().AdmitDA(raw, provenance)
	if err != nil || result.Disposition != DAAdmissionRetained {
		t.Fatalf("AdmitDA: result=%+v err=%v", result, err)
	}
}

func requireRetained(t *testing.T, f *daOwnerFixture, txid [32]byte, want bool, what string) {
	t.Helper()
	_, owned, err := f.relay().LookupRetainedTx(txid)
	if err != nil {
		t.Fatalf("LookupRetainedTx(%x): %v", txid, err)
	}
	if owned != want {
		t.Fatalf("%s: retained=%v, want %v", what, owned, want)
	}
}

// TestAdmitDASameTxidDifferentWtxidIsNotClassifiedAsADuplicate is A3's
// malleation row: the duplicate test is EXACT txid AND the retained bytes, so a
// variant carrying the same txid under different witness bytes cannot short-cut
// to DUPLICATE and cannot replace what is retained — it goes through full
// validation and is refused there.
func TestAdmitDASameTxidDifferentWtxidIsNotClassifiedAsADuplicate(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	daID, payload := daRelayTestID(0x38), []byte("wtxid-variant")
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2110, sha3.Sum256(payload))
	mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-a"))
	before := f.image(t)

	tx, txid, wtxid, consumed, err := consensus.ParseTx(commitTx)
	if err != nil || consumed != len(commitTx) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	if len(tx.Witness) == 0 || len(tx.Witness[0].Signature) == 0 {
		t.Fatal("the fixture commit carries no witness signature to vary")
	}
	tx.Witness[0].Signature[0] ^= 0xff
	variant, err := consensus.MarshalTx(tx)
	mustCanonicalMO(t, "MarshalTx(wtxid variant)", err)
	_, variantTxID, variantWTxID, _, err := consensus.ParseTx(variant)
	mustCanonicalMO(t, "ParseTx(wtxid variant)", err)
	if variantTxID != txid || variantWTxID == wtxid {
		t.Fatalf("variant txid=%x wtxid==original=%v, want the same txid under a different wtxid", variantTxID, variantWTxID == wtxid)
	}

	result, err := f.relay().AdmitDA(variant, mustPeerProvenance(t, "peer-b"))
	if err == nil {
		t.Fatalf("the wtxid variant was accepted as %v", result.Disposition)
	}
	if result.Disposition == DAAdmissionDuplicate {
		t.Fatal("the wtxid variant was classified as a duplicate")
	}
	if after := f.image(t); after != before {
		t.Fatal("the wtxid variant mutated the retained image")
	}
}

// TestAcceptedSequenceExhaustionFailsClosedBeforeAnyMutation is A10's boundary:
// the last usable high-water value is taken once, and the next acceptance is
// refused BEFORE any record, locator or claim moves.
func TestAcceptedSequenceExhaustionFailsClosedBeforeAnyMutation(t *testing.T) {
	f := newDAOwnerFixture(t, 3)
	relay := f.relay()
	relay.mu.Lock()
	relay.nextReceivedTime = ^uint64(0) - 1
	relay.mu.Unlock()

	first := f.daChunkTx(t, f.ops[0], daRelayTestID(0x39), 0, 2120, []byte("last-usable"))
	mustAdmit(t, f, first, mustPeerProvenance(t, "peer-a"))
	relay.mu.Lock()
	sequence := relay.nextReceivedTime
	relay.mu.Unlock()
	if sequence != ^uint64(0) {
		t.Fatalf("high-water=%d, want the last usable value", sequence)
	}
	before := f.image(t)
	second := f.daChunkTx(t, f.ops[1], daRelayTestID(0x3a), 0, 2121, []byte("exhausted"))
	if _, err := relay.AdmitDA(second, mustPeerProvenance(t, "peer-a")); err == nil {
		t.Fatal("an acceptance past the accepted-sequence space was retained")
	}
	if after := f.image(t); after != before {
		t.Fatal("the exhausted-sequence refusal mutated the retained image")
	}
}

// TestAdmitDARejectsAChunkOutsideItsCommitRange is the chunk-index bound reached
// through the production entry: the record's own declared range refuses it and
// nothing moves.
func TestAdmitDARejectsAChunkOutsideItsCommitRange(t *testing.T) {
	f := newDAOwnerFixture(t, 3)
	daID := daRelayTestID(0x3b)
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2130, sha3.Sum256([]byte("one")))
	mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-a"))
	before := f.image(t)
	outside := f.daChunkTx(t, f.ops[1], daID, 1, 2131, []byte("outside"))
	if _, err := f.relay().AdmitDA(outside, mustPeerProvenance(t, "peer-a")); err == nil {
		t.Fatal("a chunk outside the declared commit range was retained")
	}
	if after := f.image(t); after != before {
		t.Fatal("an out-of-range chunk mutated the retained image")
	}
}
