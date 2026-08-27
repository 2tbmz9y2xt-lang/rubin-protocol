package node

import (
	"crypto/sha3"
	"fmt"
	"sort"
	"strings"
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
		out += fmt.Sprintf("|record %x state=%d received=%d", daID, record.state, record.receivedTime)
		for _, member := range record.members() {
			out += fmt.Sprintf("|member txid=%x wtxid=%x token=%d", member.txid, member.wtxid, member.token.seq)
		}
	}
	// Sorted, so the rendering does not depend on map iteration order.
	locators := make([]string, 0, len(relay.locators))
	for txid, locator := range relay.locators {
		locators = append(locators, fmt.Sprintf("|locator %x kind=%d index=%d", txid, locator.kind, locator.chunkIndex))
	}
	sort.Strings(locators)
	out += strings.Join(locators, "")
	sequence := relay.nextReceivedTime
	relay.mu.Unlock()
	owner := f.owner()
	owner.mu.Lock()
	out += fmt.Sprintf("|claims=%d rows=%d sequence=%d", len(owner.byToken), len(owner.byOutpoint), sequence)
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
	// A fourth class the index cannot show: the locator and the member agree,
	// and the RETAINED BYTES no longer are that member.
	record := relay.sets[daID]
	record.commit.txBytes = append([]byte(nil), commitTx...)
	record.commit.txBytes[len(record.commit.txBytes)-1] ^= 0xff
	relay.sets[daID] = record
	relay.mu.Unlock()
	for name, txid := range map[string][32]byte{
		"dangling locator":  {0xcd},
		"wrong record":      {0xce},
		"wrong member kind": {0xcf},
		"corrupted bytes":   txID(t, commitTx),
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

// daChunkTxSpending is daChunkTx over an ORDERED input list, so a row can pin
// WHICH input an owner conflict names.
func (f *canonicalMOFixture) daChunkTxSpending(t *testing.T, ops []consensus.Outpoint, daID [32]byte, index uint16, nonce uint64, payload []byte) []byte {
	t.Helper()
	inputs := make([]consensus.TxInput, 0, len(ops))
	for _, op := range ops {
		inputs = append(inputs, consensus.TxInput{PrevTxid: op.Txid, PrevVout: op.Vout})
	}
	tx := &consensus.Tx{
		Version: 1, TxKind: 0x02, TxNonce: nonce,
		Inputs:      inputs,
		Outputs:     []consensus.TxOutput{{Value: 100_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...)}},
		DaPayload:   append([]byte(nil), payload...),
		DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: sha3.Sum256(payload)},
	}
	mustCanonicalMO(t, "SignTransaction(multi-input da chunk)", consensus.SignTransaction(tx, f.engine.chainState.Utxos, devnetGenesisChainID, f.signer))
	return mustMarshalTxForNodeTest(t, tx)
}

// ownerClaimCount is the live owner's claim population, the "owns no row" side of
// an A4 conflict.
func (f *daOwnerFixture) ownerClaimCount(t *testing.T) (int, int) {
	t.Helper()
	owner := f.owner()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return len(owner.byToken), len(owner.byOutpoint)
}

// TestOwnerConflictOnAConfirmedOutpointHasExactlyOneWinner is A4 EXECUTED
// through AdmitDA: a standard entry and a DA member, and two DA members with
// DIFFERENT da_ids, competing for one confirmed outpoint yield exactly one
// complete owner in EITHER scheduling order. The loser publishes no record, no
// locator and no owner row, and its error names the winner's txid — the claimant
// of the FIRST conflicting input in canonical order, which the last subtest pins
// against a second, later conflicting input.
//
// The conflict decision itself is the owner's (pending_outpoint_owner.go
// reserveDAAdmissionLocked): these rows CALL it and never edit it.
func TestOwnerConflictOnAConfirmedOutpointHasExactlyOneWinner(t *testing.T) {
	t.Run("standard first, the DA candidate loses", func(t *testing.T) {
		f := newDAOwnerFixture(t, 2)
		standard := f.add(t, f.ops[0], 1)
		before := f.image(t)
		beforeClaims, beforeRows := f.ownerClaimCount(t)
		chunkTx := f.daChunkTx(t, f.ops[0], daRelayTestID(0x50), 0, 2140, []byte("da-loses"))
		_, err := f.relay().AdmitDA(chunkTx, mustPeerProvenance(t, "peer-a"))
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%x", standard)) {
			t.Fatalf("DA candidate on a claimed outpoint: err=%v, want a conflict naming %x", err, standard)
		}
		claims, rows := f.ownerClaimCount(t)
		if f.image(t) != before || claims != beforeClaims || rows != beforeRows {
			t.Fatalf("the losing DA candidate published state: claims=%d/%d rows=%d/%d", claims, beforeClaims, rows, beforeRows)
		}
		if _, owned, err := f.relay().LookupRetainedTx(txID(t, chunkTx)); owned || err != nil {
			t.Fatalf("the loser is retained: owned=%v err=%v", owned, err)
		}
	})

	t.Run("DA first, the standard candidate loses", func(t *testing.T) {
		f := newDAOwnerFixture(t, 2)
		chunkTx := f.daChunkTx(t, f.ops[0], daRelayTestID(0x51), 0, 2141, []byte("da-wins"))
		mustAdmit(t, f, chunkTx, mustPeerProvenance(t, "peer-a"))
		before := f.image(t)
		beforeClaims, beforeRows := f.ownerClaimCount(t)
		standardRaw := f.raw(t, f.ops[0], 2142, false)
		if err := f.mp.AddTx(standardRaw); err == nil {
			t.Fatal("a standard transaction was admitted over a live DA claim")
		}
		claims, rows := f.ownerClaimCount(t)
		if f.mp.Contains(txID(t, standardRaw)) || f.image(t) != before || claims != beforeClaims || rows != beforeRows {
			t.Fatalf("the losing standard candidate published state: claims=%d/%d rows=%d/%d", claims, beforeClaims, rows, beforeRows)
		}
		requireRetained(t, f, txID(t, chunkTx), true, "the winning DA member")
	})

	t.Run("DA first, a different-da_id DA candidate loses", func(t *testing.T) {
		f := newDAOwnerFixture(t, 2)
		winner := f.daChunkTx(t, f.ops[0], daRelayTestID(0x52), 0, 2143, []byte("first-set"))
		mustAdmit(t, f, winner, mustPeerProvenance(t, "peer-a"))
		before := f.image(t)
		beforeClaims, beforeRows := f.ownerClaimCount(t)
		loser := f.daChunkTx(t, f.ops[0], daRelayTestID(0x53), 0, 2144, []byte("second-set"))
		_, err := f.relay().AdmitDA(loser, mustPeerProvenance(t, "peer-b"))
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%x", txID(t, winner))) {
			t.Fatalf("second da_id on the same outpoint: err=%v, want a conflict naming %x", err, txID(t, winner))
		}
		claims, rows := f.ownerClaimCount(t)
		if f.image(t) != before || claims != beforeClaims || rows != beforeRows {
			t.Fatalf("the losing DA candidate published state: claims=%d/%d rows=%d/%d", claims, beforeClaims, rows, beforeRows)
		}
		requireRetained(t, f, txID(t, loser), false, "the losing DA member")
	})

	t.Run("the loser names the FIRST conflicting canonical-order input", func(t *testing.T) {
		f := newDAOwnerFixture(t, 2)
		first := f.add(t, f.ops[0], 1)
		second := f.add(t, f.ops[1], 2)
		if first == second {
			t.Fatal("the two standard claimants are the same transaction")
		}
		loser := f.daChunkTxSpending(t, f.ops, daRelayTestID(0x54), 0, 2145, []byte("two-inputs"))
		_, err := f.relay().AdmitDA(loser, mustPeerProvenance(t, "peer-a"))
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%x", first)) || strings.Contains(err.Error(), fmt.Sprintf("%x", second)) {
			t.Fatalf("conflict evidence=%v, want the claimant of input 0 (%x) and not of input 1 (%x)", err, first, second)
		}
	})
}

// corruptRetainedChunkMember rewrites ONE retained chunk member's identity in
// place, which is how these rows manufacture the defective owner evidence a
// healthy admission cannot produce. It returns after the write so the caller can
// take its "unchanged" baseline over the ALREADY corrupted image.
func corruptRetainedChunkMember(t *testing.T, relay *DARelayState, daID [32]byte, index uint16, mutate func(*daRelayMemberIdentity)) {
	t.Helper()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	record, ok := relay.sets[daID]
	if !ok {
		t.Fatalf("no retained record %x to corrupt", daID)
	}
	chunk, ok := record.chunks[index]
	if !ok {
		t.Fatalf("record %x holds no chunk %d", daID, index)
	}
	mutate(&chunk.daRelayMemberIdentity)
	record.chunks[index] = chunk
}

// TestPeerCleanupFailsClosedOnEveryDefectiveVictimToken is H1 and H2 EXECUTED
// through ReleasePeerQuotaKey: a removal batch whose VALID prefix is followed by
// one defective victim leaves the ENTIRE retained image and every owner claim
// byte-identical — no partial exact release, and never a delete by outpoint
// alone. The victim descriptors are built from the members' own token slots
// (appendDAMemberVictims), so a member whose token evidence is stale, foreign,
// wrong-domain, partial, or superseded by a later claim for the same outpoint
// makes the WHOLE batch refusable at DARemoval.BeginCommit, before any
// projection is published.
//
// Each class pins the EXACT owner refusal it must reach, so a later change that
// still fails — but at a different guard, or for a different reason — is a
// failure here rather than a silently reclassified row.
func TestPeerCleanupFailsClosedOnEveryDefectiveVictimToken(t *testing.T) {
	for name, tt := range map[string]struct {
		want    string
		corrupt func(*testing.T, *daOwnerFixture, [32]byte)
	}{
		"foreign owner token": {"invalid DA victim token", func(t *testing.T, f *daOwnerFixture, daID [32]byte) {
			foreign := newDAOwnerFixture(t, 1).owner()
			corruptRetainedChunkMember(t, f.relay(), daID, 1, func(m *daRelayMemberIdentity) {
				m.token = PendingOutpointToken{owner: foreign, seq: 1}
			})
		}},
		"stale token whose claim was released": {"DA victim batch exceeds live claim population", func(t *testing.T, f *daOwnerFixture, daID [32]byte) {
			owner := f.owner()
			f.relay().mu.Lock()
			stale := f.relay().sets[daID].chunks[1].token
			f.relay().mu.Unlock()
			owner.mu.Lock()
			owner.dropClaimLocked(stale)
			owner.mu.Unlock()
		}},
		"ABA: the outpoint reclaimed by a later token": {"DA victim claim mismatch", func(t *testing.T, f *daOwnerFixture, daID [32]byte) {
			owner := f.owner()
			f.relay().mu.Lock()
			victim := f.relay().sets[daID].chunks[1].daRelayMemberIdentity
			f.relay().mu.Unlock()
			owner.mu.Lock()
			owner.dropClaimLocked(victim.token)
			owner.mu.Unlock()
			// The same outpoint under a NEW token: the member still names the
			// retired one, and the live row must survive the refusal.
			if again := finalizedDAClaimForTest(t, owner, victim.txid, victim.inputs); again == victim.token {
				t.Fatal("the reclaimed outpoint reused the retired token")
			}
		}},
		"wrong-domain token": {"DA victim claim mismatch", func(t *testing.T, f *daOwnerFixture, daID [32]byte) {
			standard := f.add(t, f.ops[3], 3)
			entry, _ := residentClaim(t, f.mp, standard)
			corruptRetainedChunkMember(t, f.relay(), daID, 1, func(m *daRelayMemberIdentity) {
				m.token = entry.token
			})
		}},
		"input evidence the claim does not carry": {"DA victim input mismatch", func(t *testing.T, f *daOwnerFixture, daID [32]byte) {
			corruptRetainedChunkMember(t, f.relay(), daID, 1, func(m *daRelayMemberIdentity) {
				m.inputs = []consensus.Outpoint{f.ops[2]}
			})
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDAOwnerFixture(t, 4)
			daID := daRelayTestID(0x55)
			head := f.daChunkTx(t, f.ops[0], daID, 0, 2150, []byte("valid-prefix"))
			tail := f.daChunkTx(t, f.ops[1], daID, 1, 2151, []byte("defective-tail"))
			mustAdmit(t, f, head, mustPeerProvenance(t, "peer-a"))
			mustAdmit(t, f, tail, mustPeerProvenance(t, "peer-a"))
			tt.corrupt(t, f, daID)
			before := f.image(t)
			err := f.relay().ReleasePeerQuotaKey("peer-a")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("removal err=%v, want a refusal containing %q", err, tt.want)
			}
			if after := f.image(t); after != before {
				t.Fatalf("a refused removal mutated the image:\n before=%s\n after =%s", before, after)
			}
			// The VALID prefix member is the "no partial exact release" subject:
			// it is still retained, so nothing was released by outpoint alone.
			requireRetained(t, f, txID(t, head), true, "the valid prefix member")
		})
	}
}

// TestAdmitDAFailureAtEveryFallibleStepPublishesNothingAndReleasesTheGuard is H7
// EXECUTED: at EVERY fallible step before the first mutation — provenance
// validation, BeginDAAdmission, member rendering, staging, and the owner reserve
// inside BeginCommit — AdmitDA publishes no record, locator or claim and resolves
// any admission guard it took exactly once (the provenance step fails before one
// exists, and must therefore leave none held either).
//
// The guard release is proved DIRECTLY, without a schedule that could hang the
// suite: ChainState.admissionMu must be write-lockable after each failure, which
// it is not while an admission guard's read hold survives. A double release would
// not reach the assertion at all — daAdmissionGuard.close panics on a second
// call — so "exactly once" is the conjunction of the two.
func TestAdmitDAFailureAtEveryFallibleStepPublishesNothingAndReleasesTheGuard(t *testing.T) {
	f := newDAOwnerFixture(t, 4)
	daID := daRelayTestID(0x56)
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2160, sha3.Sum256([]byte("one-chunk")))
	mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-a"))
	conflicting := f.add(t, f.ops[3], 3)
	if conflicting == ([32]byte{}) {
		t.Fatal("the conflicting standard entry was not admitted")
	}
	before := f.image(t)
	for _, step := range []struct {
		name       string
		raw        []byte
		provenance DAProvenance
		want       string
	}{
		{"provenance validation", f.daChunkTx(t, f.ops[1], daRelayTestID(0x57), 0, 2161, []byte("p")), DAProvenance{}, "invalid DA provenance"},
		{"BeginDAAdmission", f.daChunkTx(t, f.ops[1], daRelayTestID(0x58), 0, 2162, []byte("q"))[:20], mustPeerProvenance(t, "peer-b"), "TX_ERR_PARSE"},
		{"member rendering", f.daCommitTx(t, f.ops[1], daRelayTestID(0x59), 1, 2163), mustPeerProvenance(t, "peer-b"), "does not carry exactly one 32-byte payload commitment"},
		{"staging", f.daChunkTx(t, f.ops[1], daID, 1, 2164, []byte("out-of-range")), mustPeerProvenance(t, "peer-b"), "da chunk index outside commit"},
		{"owner reserve", f.daChunkTx(t, f.ops[3], daRelayTestID(0x5a), 0, 2165, []byte("conflict")), mustPeerProvenance(t, "peer-b"), "double-spend conflict"},
	} {
		_, err := f.relay().AdmitDA(step.raw, step.provenance)
		if err == nil || !strings.Contains(err.Error(), step.want) {
			t.Fatalf("%s: AdmitDA err=%v, want a refusal containing %q", step.name, err, step.want)
		}
		if after := f.image(t); after != before {
			t.Fatalf("%s leaked state:\n before=%s\n after =%s", step.name, before, after)
		}
		if !f.engine.chainState.admissionMu.TryLock() {
			t.Fatalf("%s left the admission guard held", step.name)
		}
		f.engine.chainState.admissionMu.Unlock()
	}
}

// TestAdmitDARejectsAChunkAtTheDeclaredIndexCeiling is the ENFORCEMENT row for
// the chunk-index bound reached without a commit to narrow it: the absolute
// ceiling is MAX_DA_CHUNK_COUNT and the last usable index is one below it, so a
// candidate AT the ceiling is refused with nothing moved.
func TestAdmitDARejectsAChunkAtTheDeclaredIndexCeiling(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	before := f.image(t)
	ceiling := f.daChunkTx(t, f.ops[0], daRelayTestID(0x5b), uint16(consensus.MAX_DA_CHUNK_COUNT), 2170, []byte("ceiling"))
	// The refusal is named, not merely counted: the canonical parse inside
	// BeginDAAdmission owns this bound and the retained-schema guard mirrors it,
	// so a row that only asserted "some error" could not tell the two apart.
	_, err := f.relay().AdmitDA(ceiling, mustPeerProvenance(t, "peer-a"))
	if err == nil || !strings.Contains(err.Error(), "chunk_index out of range") {
		t.Fatalf("ceiling chunk err=%v, want the canonical chunk_index refusal", err)
	}
	if after := f.image(t); after != before {
		t.Fatal("a ceiling-index chunk mutated the retained image")
	}
	last := f.daChunkTx(t, f.ops[1], daRelayTestID(0x5b), uint16(consensus.MAX_DA_CHUNK_COUNT-1), 2171, []byte("last-usable"))
	mustAdmit(t, f, last, mustPeerProvenance(t, "peer-a"))
}

// TestTokenlessRetainedMemberContributesNoVictim pins appendDAMemberVictims'
// zero-token arm: a member staged through the package-private accounting entry
// owns NO claim, so a removal that selects it must publish its projection with
// an EMPTY victim batch rather than name a zero token the owner would refuse.
// The production admission path never produces such a member — this is the
// test-only staging construction the retained-schema rows drive.
func TestTokenlessRetainedMemberContributesNoVictim(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	daID := daRelayTestID(0x5c)
	raw := f.daChunkTx(t, f.ops[0], daID, 0, 2180, []byte("tokenless"))
	tx, txid, wtxid, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	provenance := mustPeerProvenance(t, "peer-a")
	mustCanonicalMO(t, "addDAChunk", f.relay().addDAChunk(provenance.quotaKey(), daRelayChunk{
		daRelayMemberIdentity: daRelayMemberIdentity{
			txid: txid, wtxid: wtxid, retainedBytes: uint64(len(raw)),
			inputs: relayMetadataInputs(tx), provenance: provenance,
		},
		daID: daID, chunkHash: tx.DaChunkCore.ChunkHash, chunkIndex: 0,
		payload: tx.DaPayload, wireBytes: uint64(len(raw)), txBytes: raw, hashChecked: true,
	}))
	if err := f.relay().ReleasePeerQuotaKey("peer-a"); err != nil {
		t.Fatalf("ReleasePeerQuotaKey over a tokenless member: %v", err)
	}
	requireRetained(t, f, txid, false, "the tokenless member")
}

// TestPeerlessAdmissionChargesNoPeerQuotaKey is the A5/M2 ENFORCEMENT row on the
// PRODUCTION entry: a LOCAL and a DETACHED_REORG admission through AdmitDA leave
// the per-peer accounting map completely EMPTY — not merely absent from the
// empty key — while a PEER admission charges exactly its own quota identity.
func TestPeerlessAdmissionChargesNoPeerQuotaKey(t *testing.T) {
	f := newDAOwnerFixture(t, 3)
	mustAdmit(t, f, f.daChunkTx(t, f.ops[0], daRelayTestID(0x5d), 0, 2190, []byte("local")), LocalDAProvenance())
	mustAdmit(t, f, f.daChunkTx(t, f.ops[1], daRelayTestID(0x5e), 0, 2191, []byte("detached")), DetachedReorgDAProvenance())
	relay := f.relay()
	relay.mu.Lock()
	peerless := len(relay.orphanBytesByPeerQuotaKey)
	relay.mu.Unlock()
	if peerless != 0 {
		t.Fatalf("peerless admissions charged %d per-peer quota keys: %v", peerless, relay.orphanBytesByPeerQuotaKey)
	}
	mustAdmit(t, f, f.daChunkTx(t, f.ops[2], daRelayTestID(0x5f), 0, 2192, []byte("peer")), mustPeerProvenance(t, "peer-a"))
	relay.mu.Lock()
	charged, keys := relay.orphanBytesByPeerQuotaKey["peer-a"], len(relay.orphanBytesByPeerQuotaKey)
	relay.mu.Unlock()
	if keys != 1 || charged == 0 {
		t.Fatalf("per-peer accounting keys=%d peer-a bytes=%d, want exactly the PEER member's own key", keys, charged)
	}
}
