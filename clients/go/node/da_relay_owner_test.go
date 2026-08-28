package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

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

// image renders the retained-DA state a "changed nothing" row proves untouched
// — every record with its state, revision, sequence stamp, TTL and payload
// bytes, every member with its provenance, every locator row, every prefetch
// reservation, all five accounting counters, the revision high-water and every
// live DA claim — as one string equality rather than a list of spot checks.
//
// The set it renders is the set of MUTABLE DARelayState fields plus the owner
// claim population: an oracle narrower than that proves nothing outside itself.
func (f *daOwnerFixture) image(t *testing.T) string {
	t.Helper()
	relay, out := f.relay(), ""
	relay.mu.Lock()
	for _, daID := range relay.sortedRetainedDAIDsLocked() {
		record := relay.sets[daID]
		out += fmt.Sprintf("|record %x state=%d rev=%d received=%d ttl=%d payload=%d", daID, record.state, record.revision, record.receivedTime, record.ttlBlocksRemaining, record.payloadBytes)
		for _, member := range record.members() {
			out += fmt.Sprintf("|member txid=%x wtxid=%x token=%d prov=%+v", member.txid, member.wtxid, member.token.seq, member.provenance)
		}
	}
	// Sorted, so the rendering does not depend on map iteration order.
	locators := make([]string, 0, len(relay.locators))
	for txid, locator := range relay.locators {
		locators = append(locators, fmt.Sprintf("|locator %x kind=%d index=%d", txid, locator.kind, locator.chunkIndex))
	}
	sort.Strings(locators)
	out += strings.Join(locators, "")
	perKey := make([]string, 0, len(relay.orphanBytesByPeerQuotaKey)+len(relay.orphanBytesByDAID))
	for key, charged := range relay.orphanBytesByPeerQuotaKey {
		perKey = append(perKey, fmt.Sprintf("|peer-bytes %q=%d", key, charged))
	}
	for daID, charged := range relay.orphanBytesByDAID {
		perKey = append(perKey, fmt.Sprintf("|da-bytes %x=%d", daID, charged))
	}
	sort.Strings(perKey)
	out += strings.Join(perKey, "")
	reservations := make([]string, 0, len(relay.prefetch.indexes))
	for daID, indexes := range relay.prefetch.indexes {
		for index, peerKey := range indexes {
			reservations = append(reservations, fmt.Sprintf("|prefetch %x/%d=%q", daID, index, peerKey))
		}
	}
	sort.Strings(reservations)
	out += strings.Join(reservations, "")
	out += fmt.Sprintf("|orphan=%d overhead=%d pinned=%d revisions=%d", relay.orphanBytes, relay.orphanCommitOverheadBytes, relay.pinnedPayloadBytes, relay.records)
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

// frozenD00R3Row is one case row of the FROZEN D00-R3 expected authority
// (conformance/fixtures/protocol/da_admission_expected_v1.json). The rows are
// inert expected data: the replay matrix below reads its expected outcomes FROM
// this artifact, so the oracle is the frozen fixture, never this package's own
// code.
type frozenD00R3Row struct {
	ID     string `json:"id"`
	Expect struct {
		Result struct {
			Disposition    string `json:"disposition"`
			SemanticReason string `json:"semantic_reason_id"`
			ErrorCode      string `json:"error_code"`
			Producer       string `json:"producer_disposition"`
		} `json:"result"`
		P2P struct {
			PeerQualityEffect string `json:"peer_quality_effect"`
		} `json:"p2p_envelope"`
	} `json:"expect"`
}

// loadFrozenD00R3Rows loads the frozen artifact's case rows by id, from the
// read-only fixture file this issue may never edit.
func loadFrozenD00R3Rows(t *testing.T) map[string]frozenD00R3Row {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "fixtures", "protocol", "da_admission_expected_v1.json"))
	if err != nil {
		t.Fatalf("read frozen D00-R3 authority: %v", err)
	}
	var artifact struct {
		Cases []frozenD00R3Row `json:"cases"`
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatalf("decode frozen D00-R3 authority: %v", err)
	}
	rows := make(map[string]frozenD00R3Row, len(artifact.Cases))
	for _, row := range artifact.Cases {
		rows[row.ID] = row
	}
	return rows
}

// requireFrozenD00R3Outcome maps one frozen row onto the AdmitDA observation
// and asserts it. The MAPPING is fixed — semantic reasons onto the public
// result/error surface, the frozen peer effect onto the SameDAIDCommitConflict
// bool that alone drives P2P's existing +10 — while every expected VALUE comes
// from the loaded row.
func requireFrozenD00R3Outcome(t *testing.T, row frozenD00R3Row, result DAAdmissionResult, err error) {
	t.Helper()
	if row.ID == "" {
		t.Fatal("frozen D00-R3 row is absent from the artifact")
	}
	want := row.Expect.Result
	switch {
	case want.SemanticReason == "DUPLICATE_CONFLICT":
		if err != nil || result.Disposition != DAAdmissionDuplicate {
			t.Fatalf("%s: result=%+v err=%v, frozen row wants peer-neutral DUPLICATE", row.ID, result, err)
		}
	case want.SemanticReason == "NONE" && strings.HasPrefix(want.Disposition, "RETAINED"):
		if err != nil || result.Disposition != DAAdmissionRetained {
			t.Fatalf("%s: result=%+v err=%v, frozen row wants %s", row.ID, result, err, want.Disposition)
		}
	case want.SemanticReason == "RUNTIME_UNAVAILABLE" || want.SemanticReason == "INTERNAL":
		if err == nil || relayDispositionOf(err).String() != want.Producer {
			t.Fatalf("%s: err=%v disposition=%v, frozen row wants producer %s", row.ID, err, relayDispositionOf(err), want.Producer)
		}
	case want.SemanticReason == "PARSE_OR_POLICY_REJECT":
		requireOwningErrorCode(t, row.ID, err, want.ErrorCode)
	default:
		t.Fatalf("%s: unmapped frozen outcome %+v", row.ID, want)
	}
	if wantConflict := row.Expect.P2P.PeerQualityEffect == "NEGATIVE_DUPLICATE_COMMIT"; result.SameDAIDCommitConflict != wantConflict {
		t.Fatalf("%s: SameDAIDCommitConflict=%v, frozen peer effect is %q", row.ID, result.SameDAIDCommitConflict, row.Expect.P2P.PeerQualityEffect)
	}
}

// requireOwningErrorCode asserts the PINNED public admission surface, which is
// exactly "CODE: detail" (consensus.TxError.Error, carried verbatim by
// validateTransactionWithConsensus): the OWNING code is the first token, so a
// competing code appearing anywhere in the detail — which a substring match
// would happily accept — fails here instead.
func requireOwningErrorCode(t *testing.T, rowID string, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: no error, frozen row wants owning %s", rowID, want)
	}
	got, detail, _ := strings.Cut(err.Error(), ": ")
	if got != want {
		t.Fatalf("%s: owning error code=%q (detail %q), frozen row wants %q", rowID, got, detail, want)
	}
}

// requireAdmissionGuardReleased proves, by EXPLICIT bounded synchronization,
// that no admission read hold survived: a goroutine write-locks and releases
// the guard, and the row fails by timeout — never by hanging the suite — if
// that writer cannot proceed.
func requireAdmissionGuardReleased(t *testing.T, chainState *ChainState, step string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		chainState.admissionMu.Lock()
		chainState.admissionMu.Unlock() //nolint:staticcheck // The empty critical section IS the probe: acquirability proves release.
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s left the admission guard held", step)
	}
}

// resignedDACommitVariant re-signs the SAME parsed commit, producing a VALID
// same-txid candidate whose witness — and therefore wtxid and raw bytes —
// differ (ML-DSA-87 signing is hedged, so two signatures over one digest
// differ with overwhelming probability).
func (f *daOwnerFixture) resignedDACommitVariant(t *testing.T, commitTx []byte) []byte {
	t.Helper()
	tx, txid, wtxid, consumed, err := consensus.ParseTx(commitTx)
	if err != nil || consumed != len(commitTx) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	mustCanonicalMO(t, "SignTransaction(resign)", consensus.SignTransaction(tx, f.engine.chainState.Utxos, devnetGenesisChainID, f.signer))
	variant := mustMarshalTxForNodeTest(t, tx)
	_, variantTxID, variantWTxID, _, err := consensus.ParseTx(variant)
	mustCanonicalMO(t, "ParseTx(resign)", err)
	if variantTxID != txid || variantWTxID == wtxid || bytes.Equal(variant, commitTx) {
		t.Fatalf("resigned variant txid_same=%v wtxid_same=%v bytes_same=%v, want same txid under new witness", variantTxID == txid, variantWTxID == wtxid, bytes.Equal(variant, commitTx))
	}
	return variant
}

// TestAdmitDAD00R3ReplayMatrix executes every A3/H8/H9 replay case against the
// FROZEN D00-R3 authority: the expected disposition, semantic reason, owning
// error code, producer disposition and peer effect of each subtest are READ
// FROM the frozen artifact, and the retained image, accepted sequence, owner
// claims and admission guard are proven untouched wherever the frozen row is
// zero-effect. Requested and unsolicited deliveries are distinguished by peer
// provenance: this admission API carries no request tracking (RUB-1169 owns
// request routing), so the SAME entry serves both, which is exactly the frozen
// expectation — identical zero-effect outcomes for both request classes.
func TestAdmitDAD00R3ReplayMatrix(t *testing.T) {
	rows := loadFrozenD00R3Rows(t)
	requested := func(t *testing.T) DAProvenance { return mustPeerProvenance(t, "peer-origin") }
	unsolicited := func(t *testing.T) DAProvenance { return mustPeerProvenance(t, "peer-unsolicited") }

	// retainCommitFixture retains one commit and returns its exact bytes.
	retainCommitFixture := func(t *testing.T, f *daOwnerFixture, seed byte) []byte {
		t.Helper()
		commitTx := f.daCommitTxCommitting(t, f.ops[0], daRelayTestID(seed), 1, 2200+uint64(seed), sha3.Sum256([]byte{seed}))
		mustAdmit(t, f, commitTx, requested(t))
		return commitTx
	}

	zeroEffectReplay := func(t *testing.T, rowID string, prepare func(*testing.T, *daOwnerFixture) []byte, provenance func(*testing.T) DAProvenance) {
		t.Helper()
		f := newDAOwnerFixture(t, 2)
		raw := prepare(t, f)
		before := f.image(t)
		result, err := f.relay().AdmitDA(raw, provenance(t))
		requireFrozenD00R3Outcome(t, rows[rowID], result, err)
		if after := f.image(t); after != before {
			t.Fatalf("%s mutated the record, locator, claim, accounting or accepted-sequence image", rowID)
		}
		requireAdmissionGuardReleased(t, f.engine.chainState, rowID)
	}

	t.Run("REMOTE_EXACT_REPLAY", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_EXACT_REPLAY", func(t *testing.T, f *daOwnerFixture) []byte {
			return retainCommitFixture(t, f, 0x60)
		}, requested)
	})
	t.Run("REMOTE_EXACT_COMMIT_REPLAY_UNSOLICITED", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_EXACT_COMMIT_REPLAY_UNSOLICITED", func(t *testing.T, f *daOwnerFixture) []byte {
			return retainCommitFixture(t, f, 0x61)
		}, unsolicited)
	})
	t.Run("REMOTE_EXACT_CHUNK_REPLAY", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_EXACT_CHUNK_REPLAY", func(t *testing.T, f *daOwnerFixture) []byte {
			chunkTx := f.daChunkTx(t, f.ops[0], daRelayTestID(0x62), 0, 2262, []byte("chunk-replay"))
			mustAdmit(t, f, chunkTx, requested(t))
			return chunkTx
		}, requested)
	})
	t.Run("REMOTE_EXACT_CHUNK_REPLAY_UNSOLICITED", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_EXACT_CHUNK_REPLAY_UNSOLICITED", func(t *testing.T, f *daOwnerFixture) []byte {
			chunkTx := f.daChunkTx(t, f.ops[0], daRelayTestID(0x63), 0, 2263, []byte("chunk-unsolicited"))
			mustAdmit(t, f, chunkTx, requested(t))
			return chunkTx
		}, unsolicited)
	})
	t.Run("REMOTE_SAME_TXID_NONEXACT_VALID", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_SAME_TXID_NONEXACT_VALID", func(t *testing.T, f *daOwnerFixture) []byte {
			return f.resignedDACommitVariant(t, retainCommitFixture(t, f, 0x64))
		}, unsolicited)
	})
	t.Run("REMOTE_SAME_TXID_NONEXACT_INVALID", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_SAME_TXID_NONEXACT_INVALID", func(t *testing.T, f *daOwnerFixture) []byte {
			commitTx := retainCommitFixture(t, f, 0x65)
			tx, txid, wtxid, consumed, err := consensus.ParseTx(commitTx)
			if err != nil || consumed != len(commitTx) {
				t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
			}
			if len(tx.Witness) == 0 || len(tx.Witness[0].Signature) == 0 {
				t.Fatal("the fixture commit carries no witness signature to corrupt")
			}
			tx.Witness[0].Signature[0] ^= 0xff
			variant := mustMarshalTxForNodeTest(t, tx)
			_, variantTxID, variantWTxID, _, err := consensus.ParseTx(variant)
			mustCanonicalMO(t, "ParseTx(invalid variant)", err)
			if variantTxID != txid || variantWTxID == wtxid {
				t.Fatal("the invalid variant does not carry the same txid under a different wtxid")
			}
			return variant
		}, unsolicited)
	})
	t.Run("REMOTE_REPLAY_EVIDENCE_ABSENT", func(t *testing.T) {
		f := newDAOwnerFixture(t, 2)
		commitTx := f.daCommitTxCommitting(t, f.ops[0], daRelayTestID(0x66), 1, 2266, sha3.Sum256([]byte("absent")))
		claimsBefore, _ := f.ownerClaimCount(t)
		result, err := f.relay().AdmitDA(commitTx, requested(t))
		requireFrozenD00R3Outcome(t, rows["REMOTE_REPLAY_EVIDENCE_ABSENT"], result, err)
		claims, _ := f.ownerClaimCount(t)
		if claims != claimsBefore+1 {
			t.Fatalf("claims=%d, want the resumed ordinary admission to finalize exactly one", claims)
		}
		requireRetained(t, f, txID(t, commitTx), true, "the ABSENT-evidence candidate")
	})
	t.Run("REMOTE_REPLAY_EVIDENCE_UNAVAILABLE", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_REPLAY_EVIDENCE_UNAVAILABLE", func(t *testing.T, f *daOwnerFixture) []byte {
			commitTx := retainCommitFixture(t, f, 0x67)
			owner := f.owner()
			// An exhausted canonical-tip generation is fail-closed and never a
			// stable AdmissionContext (RUBIN_MEMPOOL_POLICY.md Section 6.5).
			owner.mu.Lock()
			owner.generation = ^uint64(0)
			owner.mu.Unlock()
			return commitTx
		}, requested)
	})
	t.Run("REMOTE_REPLAY_EVIDENCE_UNSTABLE", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_REPLAY_EVIDENCE_UNSTABLE", func(t *testing.T, f *daOwnerFixture) []byte {
			commitTx := retainCommitFixture(t, f, 0x68)
			owner := f.owner()
			// The owner's committed stable tip no longer equals the guarded
			// chainstate tip: the guard-stability proof must select UNAVAILABLE.
			owner.mu.Lock()
			owner.stableTip.Hash[0] ^= 0xff
			owner.mu.Unlock()
			return commitTx
		}, requested)
	})
	t.Run("REMOTE_REPLAY_EVIDENCE_DANGLING", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_REPLAY_EVIDENCE_DANGLING", func(t *testing.T, f *daOwnerFixture) []byte {
			commitTx := retainCommitFixture(t, f, 0x69)
			relay := f.relay()
			relay.mu.Lock()
			relay.locators[txID(t, commitTx)] = daRelayLocator{daID: daRelayTestID(0xee), kind: daRelayLocatorCommit}
			relay.mu.Unlock()
			return commitTx
		}, requested)
	})
	t.Run("REMOTE_REPLAY_EVIDENCE_CORRUPT", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_REPLAY_EVIDENCE_CORRUPT", func(t *testing.T, f *daOwnerFixture) []byte {
			commitTx := retainCommitFixture(t, f, 0x6a)
			relay := f.relay()
			relay.mu.Lock()
			record := relay.sets[daRelayTestID(0x6a)]
			record.commit.txBytes = append([]byte(nil), commitTx...)
			record.commit.txBytes[len(record.commit.txBytes)-1] ^= 0xff
			relay.sets[daRelayTestID(0x6a)] = record
			relay.mu.Unlock()
			return commitTx
		}, requested)
	})
	t.Run("REMOTE_REPLAY_EVIDENCE_MISMATCH", func(t *testing.T) {
		zeroEffectReplay(t, "REMOTE_REPLAY_EVIDENCE_MISMATCH", func(t *testing.T, f *daOwnerFixture) []byte {
			commitTx := retainCommitFixture(t, f, 0x6b)
			relay := f.relay()
			relay.mu.Lock()
			record := relay.sets[daRelayTestID(0x6b)]
			record.commit.wtxid[0] ^= 0xff // the stored admission-time wtxid contradicts the retained bytes
			relay.sets[daRelayTestID(0x6b)] = record
			relay.mu.Unlock()
			return commitTx
		}, requested)
	})
	t.Run("REMOTE_REPLAY_D1_REMOVAL_FIRST", func(t *testing.T) {
		f := newDAOwnerFixture(t, 2)
		commitTx := retainCommitFixture(t, f, 0x6c)
		// The REAL canonical D publication path removes the record: the block
		// spends the member's own confirmed input, the member is no longer
		// final-chain-valid, and D1 retires the record with its claim.
		mustCanonicalMO(t, "ApplyBlock(spend)", f.applySpend(t, f.ops[0], 2280))
		requireRetained(t, f, txID(t, commitTx), false, "the D1-removed member")
		result, err := f.relay().AdmitDA(commitTx, requested(t))
		requireFrozenD00R3Outcome(t, rows["REMOTE_REPLAY_D1_REMOVAL_FIRST"], result, err)
		requireRetained(t, f, txID(t, commitTx), false, "the post-D1 candidate")
		requireAdmissionGuardReleased(t, f.engine.chainState, "REMOTE_REPLAY_D1_REMOVAL_FIRST")
	})
	t.Run("REMOTE_REPLAY_D1_SNAPSHOT_FIRST", func(t *testing.T) {
		f := newDAOwnerFixture(t, 2)
		commitTx := retainCommitFixture(t, f, 0x6d)
		claimsBaseline, _ := f.ownerClaimCount(t)
		before := f.image(t)
		result, err := f.relay().AdmitDA(commitTx, requested(t))
		requireFrozenD00R3Outcome(t, rows["REMOTE_REPLAY_D1_SNAPSHOT_FIRST"], result, err)
		if after := f.image(t); after != before {
			t.Fatal("the snapshot-first exact replay mutated the image")
		}
		// Removal is ordered AFTER the completed replay, through the real
		// canonical transition; the replay's result stands and the record,
		// locator and claim leave together.
		mustCanonicalMO(t, "ApplyBlock(spend)", f.applySpend(t, f.ops[0], 2281))
		requireRetained(t, f, txID(t, commitTx), false, "the snapshot-first member after D1")
		if claims, _ := f.ownerClaimCount(t); claims != claimsBaseline-1 {
			t.Fatalf("claims=%d, want the removed member's claim released", claims)
		}
	})
}

// TestAdmitDAConcurrentSameBytesRetainExactlyOnce is the bound-fixture AdmitDA
// concurrency row: two goroutines admit the SAME bytes through the real guard
// and owner, and exactly one retains while the other observes the peer-neutral
// duplicate — in either schedule — leaving one member, one locator and one
// finalized claim.
//
// The overlap is REAL, not hoped for: both goroutines report ready and then wait
// on one released barrier, so the row cannot pass by running them one after the
// other. Both receives are BOUNDED, so a schedule that deadlocks fails this row
// by timeout instead of hanging the suite (the same discipline
// requireAdmissionGuardReleased uses).
func TestAdmitDAConcurrentSameBytesRetainExactlyOnce(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daRelayTestID(0x6e), 1, 2290, sha3.Sum256([]byte("race")))
	provenance := mustPeerProvenance(t, "peer-race")
	type outcome struct {
		result DAAdmissionResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			ready.Done()
			<-start
			result, err := f.relay().AdmitDA(commitTx, provenance)
			outcomes <- outcome{result: result, err: err}
		}()
	}
	ready.Wait()
	close(start)
	retained, duplicate := 0, 0
	for i := 0; i < 2; i++ {
		var got outcome
		select {
		case got = <-outcomes:
		case <-time.After(30 * time.Second):
			t.Fatalf("concurrent AdmitDA %d of 2 never returned", i+1)
		}
		if got.err != nil {
			t.Fatalf("concurrent AdmitDA: %v", got.err)
		}
		switch got.result.Disposition {
		case DAAdmissionRetained:
			retained++
		case DAAdmissionDuplicate:
			duplicate++
			if got.result.SameDAIDCommitConflict {
				t.Fatal("the racing exact duplicate carried the same-da_id conflict bit")
			}
		}
	}
	if retained != 1 || duplicate != 1 {
		t.Fatalf("retained=%d duplicate=%d, want exactly one of each", retained, duplicate)
	}
	requireRetained(t, f, txID(t, commitTx), true, "the raced member")
	if claims, _ := f.ownerClaimCount(t); claims != 1 {
		t.Fatalf("claims=%d, want exactly the raced member's", claims)
	}
}

// TestAdmitDASameDAIDDistinctCommitSetsTheConflictBitOnly is
// CAP_COMPLETE_DUPLICATE_MEMBER's node half, with the frozen fixture as the
// oracle: only the FULLY VALIDATED different-txid same-da_id commit returns
// DUPLICATE with SameDAIDCommitConflict, before any owner reserve and with the
// image byte-identical; the bit never appears on an exact replay.
func TestAdmitDASameDAIDDistinctCommitSetsTheConflictBitOnly(t *testing.T) {
	rows := loadFrozenD00R3Rows(t)
	f := newDAOwnerFixture(t, 3)
	daID := daRelayTestID(0x6f)
	first := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2295, sha3.Sum256([]byte("first-seen")))
	mustAdmit(t, f, first, mustPeerProvenance(t, "peer-a"))
	before := f.image(t)
	beforeClaims, beforeRows := f.ownerClaimCount(t)

	distinct := f.daCommitTxCommitting(t, f.ops[1], daID, 1, 2296, sha3.Sum256([]byte("competitor")))
	result, err := f.relay().AdmitDA(distinct, mustPeerProvenance(t, "peer-b"))
	requireFrozenD00R3Outcome(t, rows["CAP_COMPLETE_DUPLICATE_MEMBER"], result, err)
	if result.DAID != daID {
		t.Fatalf("conflict DAID=%x, want %x", result.DAID, daID)
	}
	claims, ownerRows := f.ownerClaimCount(t)
	if after := f.image(t); after != before || claims != beforeClaims || ownerRows != beforeRows {
		t.Fatal("the discarded competing commit reserved, mutated or consumed state")
	}
	requireRetained(t, f, txID(t, first), true, "the retained first-seen commit")
	requireRetained(t, f, txID(t, distinct), false, "the discarded competing commit")

	replay, err := f.relay().AdmitDA(first, mustPeerProvenance(t, "peer-c"))
	if err != nil || replay.Disposition != DAAdmissionDuplicate || replay.SameDAIDCommitConflict {
		t.Fatalf("exact replay result=%+v err=%v, want peer-neutral DUPLICATE without the conflict bit", replay, err)
	}
}

// TestReplayClassificationValidatesTheObservationBeforeTheExactVerdict is the
// R9/K2 order row: classifyRetainedReplay copies the observation in one
// DARelayState.mu window and then, OFF-lock over that copy, validates integrity
// FIRST and decides exact equality only on an integrity-valid observation — so
// the shortcut and LookupRetainedTx cannot disagree about a corrupt located
// member, and exact fires only where the one_invariant's "integrity-valid exact
// replay" literally holds.
func TestReplayClassificationValidatesTheObservationBeforeTheExactVerdict(t *testing.T) {
	t.Run("re-admission after retirement", func(t *testing.T) {
		// A member retired through the real removal mutation is simply ABSENT to
		// the shortcut: the replay re-enters ordinary admission and is retained
		// again, never a stale DUPLICATE.
		f := newDAOwnerFixture(t, 2)
		daID := daRelayTestID(0x76)
		commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2300, sha3.Sum256([]byte("retire")))
		mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-a"))
		relay := f.relay()
		relay.mu.Lock()
		token := relay.sets[daID].commit.token
		removeErr := relay.removeDASetRecordLocked(relay.sets[daID])
		relay.mu.Unlock()
		mustCanonicalMO(t, "removeDASetRecordLocked", removeErr)
		owner := f.owner()
		owner.mu.Lock()
		owner.dropClaimLocked(token)
		owner.mu.Unlock()
		result, err := relay.AdmitDA(commitTx, mustPeerProvenance(t, "peer-b"))
		if err != nil || result.Disposition != DAAdmissionRetained {
			t.Fatalf("replay after retirement result=%+v err=%v, want ordinary re-retention, never a stale DUPLICATE", result, err)
		}
	})
	t.Run("a byte-exact replay on a state-contradicting record is INTERNAL", func(t *testing.T) {
		// The guarded observation copies the record's STATE, so the off-lock
		// validator can see that a State A (ORPHAN_CHUNKS) record carrying a
		// commit contradicts itself. Without that field the shortcut would call
		// this an integrity-valid exact replay and answer DUPLICATE.
		f := newDAOwnerFixture(t, 2)
		daID := daRelayTestID(0x7d)
		commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2350, sha3.Sum256([]byte("state-a")))
		mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-a"))
		relay := f.relay()
		relay.mu.Lock()
		record := relay.sets[daID]
		record.state = daRelayStateOrphanChunks
		relay.sets[daID] = record
		relay.mu.Unlock()
		before := f.image(t)
		result, err := relay.AdmitDA(commitTx, mustPeerProvenance(t, "peer-b"))
		if err == nil || relayDispositionOf(err) != RelayAdmissionInternal || result != (DAAdmissionResult{}) {
			t.Fatalf("replay over a State A record holding a commit result=%+v err=%v, want the existing INTERNAL", result, err)
		}
		if _, _, lookupErr := relay.LookupRetainedTx(txID(t, commitTx)); lookupErr == nil {
			t.Fatal("LookupRetainedTx accepted the record the shortcut refused")
		}
		if after := f.image(t); after != before {
			t.Fatal("the INTERNAL classification mutated the image")
		}
	})
	t.Run("a byte-exact replay on a mis-keyed record is INTERNAL", func(t *testing.T) {
		f := newDAOwnerFixture(t, 2)
		daID := daRelayTestID(0x77)
		commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2301, sha3.Sum256([]byte("mis-keyed")))
		mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-a"))
		relay := f.relay()
		relay.mu.Lock()
		record := relay.sets[daID]
		record.daID[0] ^= 0xff // the record no longer agrees with its own map key
		relay.sets[daID] = record
		relay.mu.Unlock()
		before := f.image(t)
		result, err := relay.AdmitDA(commitTx, mustPeerProvenance(t, "peer-b"))
		if err == nil || relayDispositionOf(err) != RelayAdmissionInternal || result != (DAAdmissionResult{}) {
			t.Fatalf("byte-exact replay over a mis-keyed record result=%+v err=%v, want the existing INTERNAL", result, err)
		}
		if _, _, lookupErr := relay.LookupRetainedTx(txID(t, commitTx)); lookupErr == nil {
			t.Fatal("LookupRetainedTx accepted the mis-keyed record the shortcut refused")
		}
		if after := f.image(t); after != before {
			t.Fatal("the INTERNAL classification mutated the image")
		}
	})
}

// TestConflictBitRequiresAProvenDifferentTxid is the K3 corrupt-state row: the
// SameDAIDCommitConflict arm re-proves under the final lock that the staged
// commit's txid actually differs from the candidate's. A corrupt index that
// lost the locator row while the SAME commit stays staged is a plain
// peer-neutral duplicate and must not earn the existing negative peer effect.
func TestConflictBitRequiresAProvenDifferentTxid(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	daID := daRelayTestID(0x78)
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2310, sha3.Sum256([]byte("same-txid")))
	mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-a"))
	relay := f.relay()
	relay.mu.Lock()
	delete(relay.locators, txID(t, commitTx))
	relay.mu.Unlock()
	before := f.image(t)
	result, err := relay.AdmitDA(commitTx, mustPeerProvenance(t, "peer-b"))
	if err != nil || result.Disposition != DAAdmissionDuplicate || result.SameDAIDCommitConflict {
		t.Fatalf("same-txid restage over a lost locator row result=%+v err=%v, want DUPLICATE without the conflict bit", result, err)
	}
	if after := f.image(t); after != before {
		t.Fatal("the corrupt-state duplicate mutated the image")
	}
}

// TestCommitDAAdmissionLiveLocatorRecheckFiresDeterministically drives the
// final-lock live-locator DUPLICATE arm WITHOUT a schedule and with no
// production seam: the member is retained first, a second admission for the
// SAME bytes is built through the shared Mempool.BeginDAAdmission lifecycle,
// and commitDAAdmission is called directly, so the recheck fires by
// construction rather than by winning a race.
func TestCommitDAAdmissionLiveLocatorRecheckFiresDeterministically(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	daID := daRelayTestID(0x79)
	chunkTx := f.daChunkTx(t, f.ops[0], daID, 0, 2320, []byte("live-locator"))
	mustAdmit(t, f, chunkTx, mustPeerProvenance(t, "peer-a"))
	before := f.image(t)
	admission, err := f.mp.BeginDAAdmission(chunkTx)
	if err != nil {
		t.Fatalf("BeginDAAdmission: %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			admission.Close()
		}
	}()
	member, err := daRelayAdmissionMemberOf(admission, mustPeerProvenance(t, "peer-b"))
	if err != nil {
		t.Fatalf("daRelayAdmissionMemberOf: %v", err)
	}
	result, err := f.relay().commitDAAdmission(admission, member)
	if err != nil || result.Disposition != DAAdmissionDuplicate || result.SameDAIDCommitConflict || result.DAID != daID {
		t.Fatalf("live-locator recheck result=%+v err=%v, want peer-neutral DUPLICATE", result, err)
	}
	closed = true
	admission.Close()
	if after := f.image(t); after != before {
		t.Fatal("the live-locator duplicate mutated the image")
	}
	requireAdmissionGuardReleased(t, f.engine.chainState, "the direct commitDAAdmission duplicate")
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
	f := newDAOwnerFixture(t, 6)
	daID, payload := daRelayTestID(0x37), []byte("lookup-payload")
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2050, sha3.Sum256(payload))
	if _, err := f.relay().AdmitDA(commitTx, mustPeerProvenance(t, "peer-a")); err != nil {
		t.Fatalf("AdmitDA: %v", err)
	}
	relay := f.relay()
	if snapshot, owned, err := relay.LookupRetainedTx([32]byte{0xab}); owned || err != nil || snapshot.TxID != ([32]byte{}) {
		t.Fatalf("absent lookup owned=%v err=%v snapshot=%+v, want ABSENT_DA", owned, err, snapshot)
	}
	roleDAID := daRelayTestID(0x3c)
	roleCommitTx := f.daCommitTxCommitting(t, f.ops[1], roleDAID, 1, 2051, sha3.Sum256([]byte("role")))
	if _, err := f.relay().AdmitDA(roleCommitTx, mustPeerProvenance(t, "peer-a")); err != nil {
		t.Fatalf("AdmitDA(role fixture): %v", err)
	}
	// The kind and index rows below rewrite the row of a member that IS resolvable
	// at the slot the corrupt row names, which is the only shape that can tell the
	// closed-set rule from the txid check: with an if/else over the kind, each of
	// them resolves happily and the lookup answers owned=true.
	kindDAID := daRelayTestID(0x3d)
	kindChunks := [][]byte{
		f.daChunkTx(t, f.ops[2], kindDAID, 0, 2052, []byte("kind-zero")),
		f.daChunkTx(t, f.ops[3], kindDAID, 1, 2053, []byte("kind-past")),
	}
	for _, raw := range kindChunks {
		mustAdmit(t, f, raw, mustPeerProvenance(t, "peer-a"))
	}
	indexDAID := daRelayTestID(0x3e)
	indexCommitTx := f.daCommitTxCommitting(t, f.ops[4], indexDAID, 1, 2054, sha3.Sum256([]byte("index")))
	mustAdmit(t, f, indexCommitTx, mustPeerProvenance(t, "peer-a"))
	stateDAID := daRelayTestID(0x3f)
	stateCommitTx := f.daCommitTxCommitting(t, f.ops[5], stateDAID, 1, 2055, sha3.Sum256([]byte("state")))
	mustAdmit(t, f, stateCommitTx, mustPeerProvenance(t, "peer-a"))

	relay.mu.Lock()
	// Three corruption classes the index itself can hold: a row naming an absent
	// record, a row naming a member whose retained txid is a different one, and a
	// row naming a member slot the record does not have.
	relay.locators[[32]byte{0xcd}] = daRelayLocator{daID: daRelayTestID(0xee), kind: daRelayLocatorCommit}
	relay.locators[[32]byte{0xce}] = daRelayLocator{daID: daID, kind: daRelayLocatorCommit}
	relay.locators[[32]byte{0xcf}] = daRelayLocator{daID: daID, kind: daRelayLocatorChunk, chunkIndex: 7}
	// The locator KIND is a closed set of exactly {commit, chunk}: the zero value
	// and anything past the last kind must take the same located-inconsistency
	// lane, never resolve as "some chunk". A commit locator carrying a chunk index
	// is the same class of contradiction — a record holds one commit slot and it
	// has no index.
	relay.locators[txID(t, kindChunks[0])] = daRelayLocator{daID: kindDAID, chunkIndex: 0}
	relay.locators[txID(t, kindChunks[1])] = daRelayLocator{daID: kindDAID, kind: daRelayLocatorChunk + 1, chunkIndex: 1}
	relay.locators[txID(t, indexCommitTx)] = daRelayLocator{daID: indexDAID, kind: daRelayLocatorCommit, chunkIndex: 3}
	// A fourth class the index cannot show: the locator and the member agree,
	// and the RETAINED BYTES no longer are that member.
	record := relay.sets[daID]
	record.commit.txBytes = append([]byte(nil), commitTx...)
	record.commit.txBytes[len(record.commit.txBytes)-1] ^= 0xff
	relay.sets[daID] = record
	// A fifth class, on its OWN record so the byte corruption above cannot mask
	// it: bytes, txid and wtxid all agree and the record's ROLE claim does not —
	// the declared chunk count contradicts the retained commit transaction.
	roleRecord := relay.sets[roleDAID]
	roleRecord.commit.chunkCount = 9
	relay.sets[roleDAID] = roleRecord
	// A sixth class, and the one the PAIRWISE state check cannot see: the record
	// STATE is not a member of the closed set at all. Bytes, identity, role and
	// locator all agree, and an out-of-set value is not ORPHAN_CHUNKS, so it
	// satisfies "ORPHAN_CHUNKS iff no commit" and would answer OWNED_DA.
	stateRecord := relay.sets[stateDAID]
	stateRecord.state = daRelaySetState(0xff)
	relay.sets[stateDAID] = stateRecord
	relay.mu.Unlock()
	for name, txid := range map[string][32]byte{
		"dangling locator":             {0xcd},
		"wrong record":                 {0xce},
		"wrong member kind":            {0xcf},
		"zero locator kind":            txID(t, kindChunks[0]),
		"locator kind past the set":    txID(t, kindChunks[1]),
		"commit locator with an index": txID(t, indexCommitTx),
		"corrupted bytes":              txID(t, commitTx),
		"role mismatch":                txID(t, roleCommitTx),
		"record state outside the set": txID(t, stateCommitTx),
	} {
		snapshot, owned, err := relay.LookupRetainedTx(txid)
		if owned || err == nil || snapshot.TxID != ([32]byte{}) {
			t.Fatalf("%s lookup owned=%v err=%v, want INTERNAL", name, owned, err)
		}
		// The read-only INTERNAL is a PLAIN error: a lookup can never fabricate
		// a canonical-transition terminal.
		var terminal *canonicalDATerminalError
		if errors.As(err, &terminal) {
			t.Fatalf("%s lookup leaked the canonical-transition terminal type: %v", name, err)
		}
	}
	// The SAME state, through the OTHER consumer of the same observation: a
	// byte-exact replay against an out-of-set record is INTERNAL, never the
	// peer-neutral DUPLICATE an integrity-valid exact replay earns. The two
	// consumers agree because they share one validator.
	result, err := relay.AdmitDA(stateCommitTx, mustPeerProvenance(t, "peer-a"))
	if err == nil || relayDispositionOf(err) != RelayAdmissionInternal || result != (DAAdmissionResult{}) {
		t.Fatalf("exact replay over an out-of-set record result=%+v err=%v, want INTERNAL", result, err)
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

	t.Run("state C is a no-op and completion cleared member provenance", func(t *testing.T) {
		f := newDAOwnerFixture(t, 4)
		daID, payload := daRelayTestID(0x45), []byte("complete")
		commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2090, sha3.Sum256(payload))
		chunkTx := f.daChunkTx(t, f.ops[1], daID, 0, 2091, payload)
		mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-p"))
		mustAdmit(t, f, chunkTx, mustPeerProvenance(t, "peer-p"))
		relay := f.relay()
		relay.mu.Lock()
		record := relay.sets[daID]
		relay.mu.Unlock()
		if record.state != daRelayStateCompleteSet {
			t.Fatalf("record state=%v, want COMPLETE_SET", record.state)
		}
		// Completion clears ALL member provenance: the frozen D00-R3 authority
		// pins state_c_member_provenance FORBIDDEN.
		for _, member := range record.members() {
			if member.provenance != (DAProvenance{}) {
				t.Fatalf("State C member %x retains provenance %+v", member.txid, member.provenance)
			}
		}
		if record.commit.peerQuotaKey != "" {
			t.Fatalf("State C commit retains peer quota key %q", record.commit.peerQuotaKey)
		}
		before := f.image(t)
		if err := relay.ReleasePeerQuotaKey("peer-p"); err != nil {
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
// validation, the pre-guard canonical parse, candidate validation under the
// held guard, member rendering, staging, and the owner reserve inside
// BeginCommit — AdmitDA publishes no record, locator or claim and resolves any
// admission guard it took exactly once (the provenance and parse steps fail
// before one exists, and must therefore leave none held either).
//
// The guard release is proved by requireAdmissionGuardReleased's explicit
// bounded write-lock schedule, which fails by timeout rather than hanging the
// suite while a leaked read hold survives. A double release cannot happen —
// daAdmissionGuard.close panics on a second call and releaseIfHeld stands down
// once the hold is spent — so "exactly once" is the conjunction of the two.
func TestAdmitDAFailureAtEveryFallibleStepPublishesNothingAndReleasesTheGuard(t *testing.T) {
	f := newDAOwnerFixture(t, 5)
	daID := daRelayTestID(0x56)
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 1, 2160, sha3.Sum256([]byte("one-chunk")))
	mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-a"))
	conflicting := f.add(t, f.ops[3], 3)
	if conflicting == ([32]byte{}) {
		t.Fatal("the conflicting standard entry was not admitted")
	}
	steps := []struct {
		name       string
		raw        []byte
		provenance DAProvenance
		want       string
	}{
		{"provenance validation", f.daChunkTx(t, f.ops[1], daRelayTestID(0x57), 0, 2161, []byte("p")), DAProvenance{}, "invalid DA provenance"},
		{"pre-guard parse", f.daChunkTx(t, f.ops[1], daRelayTestID(0x58), 0, 2162, []byte("q"))[:20], mustPeerProvenance(t, "peer-b"), "TX_ERR_PARSE"},
		{"candidate validation", f.daChunkTx(t, f.ops[4], daRelayTestID(0x5b), 0, 2166, []byte("unfunded")), mustPeerProvenance(t, "peer-b"), "TX_ERR_MISSING_UTXO"},
		{"member rendering", f.daCommitTx(t, f.ops[1], daRelayTestID(0x59), 1, 2163), mustPeerProvenance(t, "peer-b"), "does not carry exactly one 32-byte payload commitment"},
		{"staging", f.daChunkTx(t, f.ops[1], daID, 1, 2164, []byte("out-of-range")), mustPeerProvenance(t, "peer-b"), "da chunk index outside commit"},
		{"owner reserve", f.daChunkTx(t, f.ops[3], daRelayTestID(0x5a), 0, 2165, []byte("conflict")), mustPeerProvenance(t, "peer-b"), "double-spend conflict"},
	}
	// Built AFTER every step raw was signed against the funded set: the
	// candidate-validation step's input leaves the chainstate, so its failure
	// happens under the held guard, on the ordinary validation path.
	f.engine.chainState.mu.Lock()
	delete(f.engine.chainState.Utxos, f.ops[4])
	f.engine.chainState.mu.Unlock()
	before := f.image(t)
	for _, step := range steps {
		_, err := f.relay().AdmitDA(step.raw, step.provenance)
		if err == nil || !strings.Contains(err.Error(), step.want) {
			t.Fatalf("%s: AdmitDA err=%v, want a refusal containing %q", step.name, err, step.want)
		}
		if after := f.image(t); after != before {
			t.Fatalf("%s leaked state:\n before=%s\n after =%s", step.name, before, after)
		}
		requireAdmissionGuardReleased(t, f.engine.chainState, step.name)
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

// TestTokenlessRetainedMemberFailsClosedOnlyWhereAClaimCanExist is H2/M3/A8's
// zero-token arm. Whether a zero token is legitimate is a property of the RELAY,
// not of the member:
//
//   - BOUND relay: every member it retained owes exactly one finalized claim, so
//     a zero token is MISSING token evidence for a claim that exists. Removing
//     the record around it would publish a record-free, locator-free orphan
//     claim, so the removal fails closed before any publication and the image is
//     left byte-identical.
//   - UNBOUND relay: beginRetainedDARemoval returns no guard at all and no claim
//     can exist, so the member is simply removed with an empty victim batch.
func TestTokenlessRetainedMemberFailsClosedOnlyWhereAClaimCanExist(t *testing.T) {
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
	before := f.image(t)
	err = f.relay().ReleasePeerQuotaKey("peer-a")
	if err == nil || !strings.Contains(err.Error(), "carries no owner token") {
		t.Fatalf("bound-relay removal over a tokenless member: err=%v, want the fail-closed refusal", err)
	}
	if after := f.image(t); after != before {
		t.Fatal("the refused removal mutated the retained image")
	}
	requireRetained(t, f, txid, true, "the tokenless member of a BOUND relay")

	t.Run("an unbound relay owns no claim and removes it", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		chunk := daRelayTestChunk(daRelayTestID(0x5d), 0, 11)
		mustAddDAChunk(t, state, "peer-a", chunk)
		if err := state.ReleasePeerQuotaKey("peer-a"); err != nil {
			t.Fatalf("unbound removal over a tokenless member: %v", err)
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		if len(state.sets) != 0 || len(state.locators) != 0 {
			t.Fatalf("unbound removal left sets=%d locators=%d", len(state.sets), len(state.locators))
		}
	})
}

// TestAdmitDAPlansOutsideTheFinalLockAndRefusesARacedPlan is the lock_and_effect
// ordering row: every allocation, locator, record and victim decision is
// COMPLETE before the final DA lock, and the final lock's currency recheck is
// what makes those off-lock decisions authoritative.
//
// Both halves run through the production functions in the production order, made
// deterministic by construction rather than by winning a race: the plan is
// built, a second member of the SAME record is then admitted, and the plan is
// applied. Applying it would install a record that never saw that member, so it
// is refused with the transient UNAVAILABLE and the whole image byte-identical.
//
// The unrelated-record half is the other side of the same property and is
// covered by the fence suite's six concurrent distinct-record writers: those
// plans are NOT invalidated by one another.
func TestAdmitDAPlansOutsideTheFinalLockAndRefusesARacedPlan(t *testing.T) {
	f := newDAOwnerFixture(t, 3)
	relay := f.relay()
	daID := daRelayTestID(0x7a)
	commitTx := f.daCommitTxCommitting(t, f.ops[0], daID, 3, 2330, sha3.Sum256([]byte("planned")))
	mustAdmit(t, f, commitTx, mustPeerProvenance(t, "peer-a"))
	chunkTx := f.daChunkTx(t, f.ops[1], daID, 0, 2331, []byte("planned-chunk"))
	admission, err := f.mp.BeginDAAdmission(chunkTx)
	if err != nil {
		t.Fatalf("BeginDAAdmission: %v", err)
	}
	defer admission.Close()
	member, err := daRelayAdmissionMemberOf(admission, mustPeerProvenance(t, "peer-b"))
	if err != nil {
		t.Fatalf("daRelayAdmissionMemberOf: %v", err)
	}
	beforePlan := f.image(t)
	plan, err := relay.planDAAdmission(member)
	if err != nil || plan.stageErr != nil {
		t.Fatalf("planDAAdmission: err=%v stageErr=%v", err, plan.stageErr)
	}
	// The plan is COMPLETE and the live image is UNTOUCHED: the staged record
	// already holds this member while the live record does not, and relay.mu is
	// free — the Lock below returns — so none of it was decided under the final
	// lock.
	txid := txID(t, chunkTx)
	relay.mu.Lock()
	liveChunks := len(relay.sets[daID].chunks)
	relay.mu.Unlock()
	if staged, ok := plan.staged.record.chunks[0]; !ok || staged.txid != txid || liveChunks != 0 {
		t.Fatalf("staged chunk present=%v live chunks=%d, want the complete plan off-lock and no live effect", ok, liveChunks)
	}
	if after := f.image(t); after != beforePlan {
		t.Fatal("planning published state")
	}
	// Everything the corridor AFTER the owner reserve assigns is already in the
	// plan — the locator rows to retire and install, and the accounting each side
	// contributes — and installDASetRecordLocked takes only this image, so no
	// schedule exists in which it walks a record or builds a map after
	// BeginCommit.
	wantRetire := map[[32]byte]daRelayLocator{txID(t, commitTx): {daID: daID, kind: daRelayLocatorCommit}}
	wantInstall := map[[32]byte]daRelayLocator{
		txID(t, commitTx): {daID: daID, kind: daRelayLocatorCommit},
		txid:              {daID: daID, kind: daRelayLocatorChunk, chunkIndex: 0},
	}
	if !maps.Equal(plan.image.retire, wantRetire) || !maps.Equal(plan.image.install, wantInstall) {
		t.Fatalf("planned locator rows retire=%+v install=%+v, want %+v and %+v", plan.image.retire, plan.image.install, wantRetire, wantInstall)
	}
	if plan.image.newAccounting.orphanBytes <= plan.image.oldAccounting.orphanBytes || plan.image.newAccounting.peerBytes["peer-b"] == 0 {
		t.Fatalf("planned accounting old=%+v new=%+v, want the arriving member already billed off-lock", plan.image.oldAccounting, plan.image.newAccounting)
	}

	// A raced admission into the SAME record: applying the stale plan would
	// install a record value that never saw it.
	raced := f.daChunkTx(t, f.ops[2], daID, 1, 2332, []byte("raced-chunk"))
	mustAdmit(t, f, raced, mustPeerProvenance(t, "peer-c"))
	beforeApply := f.image(t)
	result, err := relay.applyDAAdmissionPlan(admission, member, plan)
	if err == nil || relayDispositionOf(err) != RelayAdmissionUnavailable || result != (DAAdmissionResult{}) {
		t.Fatalf("raced plan result=%+v err=%v, want the transient UNAVAILABLE refusal", result, err)
	}
	if after := f.image(t); after != beforeApply {
		t.Fatalf("the refused stale plan mutated the image:\n before=%s\n after =%s", beforeApply, after)
	}
	requireRetained(t, f, txID(t, raced), true, "the raced member the stale plan would have retired")
	requireRetained(t, f, txid, false, "the refused candidate")
	// The recheck is what makes the PRECOMPUTED image safe: the plan's retire set
	// still names the pre-race record, so a recheck that accepted a stale plan
	// would retire the raced member's locator row along with it.
	if _, owned, err := relay.LookupRetainedTx(txID(t, raced)); !owned || err != nil {
		t.Fatalf("the raced member's locator row after the refusal owned=%v err=%v", owned, err)
	}
}

// TestRecordRevisionExhaustionFailsClosedBeforeAnyMutation is 8.4: the record
// revision stamp is a CHECKED accumulator like every other one in this state. At
// the ceiling the admission fails closed with the whole image byte-identical —
// an unchecked ++ would wrap the stamp to 0, which is exactly the value an ABSENT
// record presents, so the next plan built against a real record would recheck as
// current.
func TestRecordRevisionExhaustionFailsClosedBeforeAnyMutation(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	relay := f.relay()
	daID := daRelayTestID(0x7e)
	mustAdmit(t, f, f.daChunkTx(t, f.ops[0], daID, 0, 2350, []byte("before-ceiling")), mustPeerProvenance(t, "peer-a"))
	relay.mu.Lock()
	relay.records = ^uint64(0)
	relay.mu.Unlock()
	before := f.image(t)

	exhausted := f.daChunkTx(t, f.ops[1], daID, 1, 2351, []byte("at-ceiling"))
	result, err := relay.AdmitDA(exhausted, mustPeerProvenance(t, "peer-b"))
	if !errors.Is(err, errDARelayArithmeticOverflow) || result != (DAAdmissionResult{}) {
		t.Fatalf("admission at the revision ceiling result=%+v err=%v, want the checked-arithmetic refusal", result, err)
	}
	if after := f.image(t); after != before {
		t.Fatalf("the refused admission mutated the image:\n before=%s\n after =%s", before, after)
	}
	requireRetained(t, f, txID(t, exhausted), false, "the candidate refused at the revision ceiling")
	requireAdmissionGuardReleased(t, f.mp.chainState, "revision ceiling")
}

// TestAdmissionMemberRenderingConsumesTheAdmissionsOwnParse is R9's one-parse
// row: the retained member is rendered from the transaction the admission ITSELF
// parsed, never from a second parse of the snapshot bytes. The proof is direct —
// the snapshot's bytes are replaced with bytes that cannot be parsed at all, and
// the rendering still yields this candidate's own locator.
func TestAdmissionMemberRenderingConsumesTheAdmissionsOwnParse(t *testing.T) {
	f := newDAOwnerFixture(t, 2)
	daID := daRelayTestID(0x7c)
	chunkTx := f.daChunkTx(t, f.ops[0], daID, 0, 2340, []byte("one-parse"))
	admission, err := f.mp.BeginDAAdmission(chunkTx)
	if err != nil {
		t.Fatalf("BeginDAAdmission: %v", err)
	}
	defer admission.Close()
	unparseable := []byte{0x00}
	if _, _, _, _, err := consensus.ParseTx(unparseable); err == nil {
		t.Fatal("the substituted bytes parse, so this row would not detect a re-parse")
	}
	// Only the BYTES are substituted: every other snapshot field keeps the value
	// the admission derived, so the rendering fails here only if it parses them.
	admission.snapshot.TxBytes = unparseable
	member, err := daRelayAdmissionMemberOf(admission, mustPeerProvenance(t, "peer-a"))
	if err != nil {
		t.Fatalf("daRelayAdmissionMemberOf over unparseable snapshot bytes: %v", err)
	}
	want := daRelayLocator{daID: daID, kind: daRelayLocatorChunk, chunkIndex: 0}
	if member.locator != want {
		t.Fatalf("rendered locator=%+v, want the carried parse's %+v", member.locator, want)
	}
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
