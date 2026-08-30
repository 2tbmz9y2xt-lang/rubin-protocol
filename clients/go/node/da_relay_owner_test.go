package node

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type daAdmissionCandidateFixture struct {
	admission                                *DAAdmission
	raw, txBytes, payload                    []byte
	txid, wtxid, daID, commitment, chunkHash [32]byte
	fee                                      consensus.Uint128
	inputs                                   []consensus.Outpoint
	chunkCount, chunkIndex                   uint16
	kind                                     uint8
}

func newDAAdmissionCandidateFixture(t *testing.T, kind uint8) daAdmissionCandidateFixture {
	t.Helper()
	signer := mustNodeMLDSA87Keypair(t)
	address := consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())
	state, outpoints := testSpendableChainState(address, []uint64{1_000_000, 1_000_000})
	cfg := DefaultMempoolConfig()
	cfg.PolicyMaxDaBytesPerBlock = consensus.MAX_DA_BYTES_PER_BLOCK
	mp, err := NewMempoolWithConfig(state, nil, devnetGenesisChainID, cfg)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	inputs := []consensus.Outpoint{outpoints[1], outpoints[0]}
	txInputs := make([]consensus.TxInput, len(inputs))
	for i, input := range inputs {
		txInputs[i] = consensus.TxInput{PrevTxid: input.Txid, PrevVout: input.Vout, Sequence: uint32(i + 3)}
	}
	const fee = uint64(456_789)
	daID := [32]byte{0xa1, 0xb2, 0xc3}
	commitment := sha3.Sum256([]byte("RUB-1273 payload commitment"))
	payload := []byte("RUB-1273 chunk payload")
	tx := &consensus.Tx{Version: 1, TxKind: kind, TxNonce: 37, Inputs: txInputs, Locktime: 41}
	fixture := daAdmissionCandidateFixture{fee: consensus.Uint128FromU64(fee), inputs: append([]consensus.Outpoint(nil), inputs...), daID: daID, commitment: commitment, kind: kind}
	switch kind {
	case 0x01:
		fixture.chunkCount = uint16(consensus.MAX_DA_CHUNK_COUNT)
		tx.Outputs = []consensus.TxOutput{
			{CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: append([]byte(nil), commitment[:]...)},
			{Value: 2_000_000 - fee, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), address...)},
		}
		tx.DaPayload = []byte("RUB-1273 manifest")
		tx.DaCommitCore = &consensus.DaCommitCore{DaID: daID, ChunkCount: fixture.chunkCount, BatchNumber: 7}
	case 0x02:
		fixture.chunkIndex = 1
		fixture.payload = append([]byte(nil), payload...)
		fixture.chunkHash = sha3.Sum256(payload)
		tx.Outputs = []consensus.TxOutput{{Value: 2_000_000 - fee, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), address...)}}
		tx.DaPayload = append([]byte(nil), payload...)
		tx.DaChunkCore = &consensus.DaChunkCore{DaID: daID, ChunkIndex: fixture.chunkIndex, ChunkHash: fixture.chunkHash}
	default:
		t.Fatalf("unsupported test kind %#x", kind)
	}
	if err := consensus.SignTransaction(tx, state.Utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	raw := mustMarshalTxForNodeTest(t, tx)
	_, txid, wtxid, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) {
		t.Fatalf("independent ParseTx=(%d,%v), want %d,nil", consumed, err, len(raw))
	}
	fixture.txid, fixture.wtxid = txid, wtxid
	fixture.raw = append([]byte(nil), raw...)
	fixture.txBytes = append([]byte(nil), raw...)
	fixture.admission, err = mp.BeginDAAdmission(fixture.raw)
	if err != nil {
		t.Fatalf("BeginDAAdmission: %v", err)
	}
	return fixture
}

func requireDAAdmissionCandidate(t *testing.T, got daRelayAdmissionCandidate, want daAdmissionCandidateFixture, provenance daProvenance) {
	t.Helper()
	wantLocator := daRelayLocator{daID: want.daID, kind: daRelayLocatorCommit}
	if want.kind == 0x02 {
		wantLocator.kind, wantLocator.chunkIndex = daRelayLocatorChunk, want.chunkIndex
	}
	if got.member.locator != wantLocator || got.member.member.txid != want.txid || got.member.member.wtxid != want.wtxid ||
		got.member.member.fee != want.fee || got.member.member.provenance != provenance || got.member.member.token != (PendingOutpointToken{}) ||
		!slices.Equal(got.member.member.inputs, want.inputs) || !bytes.Equal(got.member.txBytes, want.txBytes) {
		t.Fatalf("candidate identity mismatch: locator=%+v want=%+v txid=%x/%x wtxid=%x/%x fee=%s/%s inputs=%v provenance=%+v", got.member.locator, wantLocator, got.member.member.txid, want.txid, got.member.member.wtxid, want.wtxid, got.member.member.fee.String(), want.fee.String(), slices.Equal(got.member.member.inputs, want.inputs), got.member.member.provenance)
	}
	if err := got.member.validate(); err != nil {
		t.Fatalf("candidate member shape: %v", err)
	}
	if want.kind == 0x01 {
		if len(got.member.payload) != 0 || got.payloadCommitment != want.commitment || got.chunkCount != want.chunkCount || got.chunkHash != ([32]byte{}) {
			t.Fatalf("commit candidate mismatch: payload=%d commitment=%x/%x count=%d/%d hash=%x", len(got.member.payload), got.payloadCommitment, want.commitment, got.chunkCount, want.chunkCount, got.chunkHash)
		}
		return
	}
	if !bytes.Equal(got.member.payload, want.payload) || got.chunkHash != want.chunkHash || got.payloadCommitment != ([32]byte{}) || got.chunkCount != 0 {
		t.Fatalf("chunk candidate mismatch: payload_match=%v hash=%x/%x commitment=%x count=%d", bytes.Equal(got.member.payload, want.payload), got.chunkHash, want.chunkHash, got.payloadCommitment, got.chunkCount)
	}
}

func requireDAAdmissionCandidateError(t *testing.T, admission *DAAdmission, provenance daProvenance, want error) {
	t.Helper()
	got, err := admission.renderDARelayAdmissionCandidate(provenance)
	if !errors.Is(err, want) || err != want || !reflect.DeepEqual(got, daRelayAdmissionCandidate{}) { //nolint:errorlint // Contract requires the existing direct sentinel, not a wrapper.
		t.Fatalf("render err=%v want=%v zero=%v", err, want, reflect.DeepEqual(got, daRelayAdmissionCandidate{}))
	}
}

func mustDAAdmissionCandidate(t *testing.T, admission *DAAdmission, provenance daProvenance) daRelayAdmissionCandidate {
	t.Helper()
	candidate, err := admission.renderDARelayAdmissionCandidate(provenance)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return candidate
}

func daAdmissionOwnerCounts(admission *DAAdmission) (uint64, int, int) {
	owner := admission.guard.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.tokenHighWater, len(owner.byToken), len(owner.byOutpoint)
}

func TestDAAdmissionCandidateClosedDomain(t *testing.T) {
	fixture := newDAAdmissionCandidateFixture(t, 0x01)
	defer fixture.admission.Close()
	for _, tc := range []struct {
		name  string
		value daProvenance
		quota string
	}{
		{"peer", daProvenance{kind: daProvenancePeer, peerIdentity: "peer-1", quotaIdentity: "quota-1"}, "quota-1"},
		{"local", daProvenance{kind: daProvenanceLocal}, ""},
		{"detached", daProvenance{kind: daProvenanceDetachedReorg}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mustDAAdmissionCandidate(t, fixture.admission, tc.value)
			if got.member.member.provenance.quotaKey() != tc.quota {
				t.Fatalf("quota=%q", got.member.member.provenance.quotaKey())
			}
			requireDAAdmissionCandidate(t, got, fixture, tc.value)
		})
	}
	for _, value := range []daProvenance{
		{},
		{kind: daProvenanceKind(99)},
		{kind: daProvenancePeer},
		{kind: daProvenancePeer, peerIdentity: "peer"},
		{kind: daProvenancePeer, quotaIdentity: "quota"},
		{kind: daProvenanceLocal, peerIdentity: "peer"},
		{kind: daProvenanceLocal, quotaIdentity: "quota"},
		{kind: daProvenanceDetachedReorg, peerIdentity: "peer"},
		{kind: daProvenanceDetachedReorg, quotaIdentity: "quota"},
	} {
		requireDAAdmissionCandidateError(t, fixture.admission, value, errDAProvenanceInvalid)
	}
	copy := *fixture.admission
	mustPanic(t, func() { _, _ = copy.renderDARelayAdmissionCandidate(daProvenance{kind: daProvenanceLocal}) })
	var nilAdmission *DAAdmission
	mustPanic(t, func() { _, _ = nilAdmission.renderDARelayAdmissionCandidate(daProvenance{kind: daProvenanceLocal}) })
	resolved := newDAAdmissionCandidateFixture(t, 0x01)
	resolved.admission.guard.state.Store(daAdmissionResolved)
	mustPanic(t, func() {
		_, _ = resolved.admission.renderDARelayAdmissionCandidate(daProvenance{kind: daProvenanceLocal})
	})
	resolved.admission.Close()
	mustPanic(t, func() {
		_, _ = resolved.admission.renderDARelayAdmissionCandidate(daProvenance{kind: daProvenanceLocal})
	})
}

func TestDAAdmissionCandidateRoleMatrix(t *testing.T) {
	provenance := daProvenance{kind: daProvenancePeer, peerIdentity: "peer", quotaIdentity: "quota"}
	for _, kind := range []uint8{0x01, 0x02} {
		fixture := newDAAdmissionCandidateFixture(t, kind)
		got := mustDAAdmissionCandidate(t, fixture.admission, provenance)
		requireDAAdmissionCandidate(t, got, fixture, provenance)
		fixture.admission.Close()
	}
	for _, tc := range []struct {
		name   string
		kind   uint8
		mutate func(*daRelayAdmissionCandidate)
		want   error
	}{
		{"commit payload", 0x01, func(candidate *daRelayAdmissionCandidate) { candidate.member.payload = []byte{1} }, errDARelayMemberIncomplete},
		{"commit index", 0x01, func(candidate *daRelayAdmissionCandidate) { candidate.member.locator.chunkIndex = 1 }, errDARelayMemberIncomplete},
		{"commit chunk hash", 0x01, func(candidate *daRelayAdmissionCandidate) { candidate.chunkHash = [32]byte{1} }, errDARelayMemberIncomplete},
		{"commit zero count", 0x01, func(candidate *daRelayAdmissionCandidate) { candidate.chunkCount = 0 }, errDARelayChunkCountInvalid},
		{"chunk commitment", 0x02, func(candidate *daRelayAdmissionCandidate) { candidate.payloadCommitment = [32]byte{1} }, errDARelayMemberIncomplete},
		{"chunk count", 0x02, func(candidate *daRelayAdmissionCandidate) { candidate.chunkCount = 1 }, errDARelayMemberIncomplete},
		{"chunk oversized payload", 0x02, func(candidate *daRelayAdmissionCandidate) {
			candidate.member.payload = make([]byte, consensus.CHUNK_BYTES+1)
		}, errDARelayChunkPayloadSizeInvalid},
		{"token", 0x01, func(candidate *daRelayAdmissionCandidate) {
			candidate.member.member.token = PendingOutpointToken{seq: 1}
		}, errDARelayMemberIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newDAAdmissionCandidateFixture(t, tc.kind)
			candidate := mustDAAdmissionCandidate(t, fixture.admission, provenance)
			tc.mutate(&candidate)
			if err := candidate.validate(); !errors.Is(err, tc.want) || err != tc.want { //nolint:errorlint // Contract requires the existing direct sentinel, not a wrapper.
				t.Fatalf("candidate validate=%v, want %v", err, tc.want)
			}
			fixture.admission.Close()
		})
	}
	for _, tc := range []struct {
		name   string
		kind   uint8
		mutate func(*daRelayAdmissionCandidate)
	}{
		{"commit count one", 0x01, func(candidate *daRelayAdmissionCandidate) { candidate.chunkCount = 1 }},
		{"commit count maximum", 0x01, func(candidate *daRelayAdmissionCandidate) {
			candidate.chunkCount = uint16(consensus.MAX_DA_CHUNK_COUNT)
		}},
		{"chunk index zero", 0x02, func(candidate *daRelayAdmissionCandidate) { candidate.member.locator.chunkIndex = 0 }},
		{"chunk index maximum", 0x02, func(candidate *daRelayAdmissionCandidate) {
			candidate.member.locator.chunkIndex = uint16(consensus.MAX_DA_CHUNK_COUNT - 1)
		}},
		{"chunk payload one", 0x02, func(candidate *daRelayAdmissionCandidate) { candidate.member.payload = []byte{1} }},
		{"chunk payload maximum", 0x02, func(candidate *daRelayAdmissionCandidate) {
			candidate.member.payload = make([]byte, consensus.CHUNK_BYTES)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newDAAdmissionCandidateFixture(t, tc.kind)
			candidate := mustDAAdmissionCandidate(t, fixture.admission, provenance)
			tc.mutate(&candidate)
			if err := candidate.validate(); err != nil {
				t.Fatalf("boundary candidate: %v", err)
			}
			fixture.admission.Close()
		})
	}
	for _, tc := range []struct {
		name   string
		kind   uint8
		mutate func(*consensus.Tx)
		want   error
	}{
		{"commit nil core", 0x01, func(tx *consensus.Tx) { tx.DaCommitCore = nil }, errDARelayMemberIncomplete},
		{"commit conflicting core", 0x01, func(tx *consensus.Tx) { tx.DaChunkCore = &consensus.DaChunkCore{} }, errDARelayMemberIncomplete},
		{"commit zero count", 0x01, func(tx *consensus.Tx) { tx.DaCommitCore.ChunkCount = 0 }, errDARelayChunkCountInvalid},
		{"commit excessive count", 0x01, func(tx *consensus.Tx) { tx.DaCommitCore.ChunkCount = uint16(consensus.MAX_DA_CHUNK_COUNT + 1) }, errDARelayChunkCountInvalid},
		{"commit missing commitment", 0x01, func(tx *consensus.Tx) { tx.Outputs = tx.Outputs[1:] }, errDARelayMemberIncomplete},
		{"commit multiple commitments", 0x01, func(tx *consensus.Tx) {
			tx.Outputs = append(tx.Outputs, consensus.TxOutput{CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: make([]byte, 32)})
		}, errDARelayMemberIncomplete},
		{"commit short commitment", 0x01, func(tx *consensus.Tx) { tx.Outputs[0].CovenantData = make([]byte, 31) }, errDARelayMemberIncomplete},
		{"commit long commitment", 0x01, func(tx *consensus.Tx) { tx.Outputs[0].CovenantData = make([]byte, 33) }, errDARelayMemberIncomplete},
		{"chunk nil core", 0x02, func(tx *consensus.Tx) { tx.DaChunkCore = nil }, errDARelayMemberIncomplete},
		{"chunk conflicting core", 0x02, func(tx *consensus.Tx) { tx.DaCommitCore = &consensus.DaCommitCore{} }, errDARelayMemberIncomplete},
		{"chunk index out of range", 0x02, func(tx *consensus.Tx) { tx.DaChunkCore.ChunkIndex = uint16(consensus.MAX_DA_CHUNK_COUNT) }, errDARelayChunkIndexOutOfRange},
		{"chunk empty payload", 0x02, func(tx *consensus.Tx) { tx.DaPayload = nil }, errDARelayMemberIncomplete},
		{"chunk oversized payload", 0x02, func(tx *consensus.Tx) { tx.DaPayload = make([]byte, consensus.CHUNK_BYTES+1) }, errDARelayChunkPayloadSizeInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newDAAdmissionCandidateFixture(t, tc.kind)
			tc.mutate(fixture.admission.tx)
			requireDAAdmissionCandidateError(t, fixture.admission, provenance, tc.want)
			fixture.admission.Close()
		})
	}
	t.Run("nil held parse", func(t *testing.T) {
		fixture := newDAAdmissionCandidateFixture(t, 0x01)
		fixture.admission.tx = nil
		requireDAAdmissionCandidateError(t, fixture.admission, provenance, errDARelayMemberIncomplete)
		fixture.admission.Close()
	})
}

func TestDAAdmissionCandidateUsesHeldParse(t *testing.T) {
	fixture := newDAAdmissionCandidateFixture(t, 0x01)
	defer fixture.admission.Close()
	fixture.raw[0] ^= 0xff
	snapshot := fixture.admission.Snapshot()
	snapshot.TxID[0] ^= 0xff
	snapshot.WTxID[0] ^= 0xff
	snapshot.TxBytes[0] ^= 0xff
	snapshot.Inputs[0].Vout++
	got := mustDAAdmissionCandidate(t, fixture.admission, daProvenance{kind: daProvenanceLocal})
	requireDAAdmissionCandidate(t, got, fixture, daProvenance{kind: daProvenanceLocal})
}

func TestDAAdmissionCandidateIsolation(t *testing.T) {
	fixture := newDAAdmissionCandidateFixture(t, 0x02)
	defer fixture.admission.Close()
	provenance := daProvenance{kind: daProvenancePeer, peerIdentity: "peer", quotaIdentity: "quota"}
	first := mustDAAdmissionCandidate(t, fixture.admission, provenance)
	second := mustDAAdmissionCandidate(t, fixture.admission, provenance)
	fixture.raw[0] ^= 0xff
	snapshot := fixture.admission.Snapshot()
	snapshot.TxBytes[0] ^= 0xff
	snapshot.Inputs[0].Vout++
	fixture.admission.snapshot.TxBytes[0] ^= 0xff
	fixture.admission.snapshot.Inputs[0].Vout++
	fixture.admission.tx.DaPayload[0] ^= 0xff
	requireDAAdmissionCandidate(t, first, fixture, provenance)
	requireDAAdmissionCandidate(t, second, fixture, provenance)
	fixture.admission.snapshot.TxBytes[0] ^= 0xff
	fixture.admission.snapshot.Inputs[0].Vout--
	fixture.admission.tx.DaPayload[0] ^= 0xff
	first.member.txBytes[0] ^= 0xff
	first.member.payload[0] ^= 0xff
	first.member.member.inputs[0].Vout++
	requireDAAdmissionCandidate(t, second, fixture, provenance)
	third := mustDAAdmissionCandidate(t, fixture.admission, provenance)
	requireDAAdmissionCandidate(t, third, fixture, provenance)
	firstTxByte, firstPayloadByte, firstVout := first.member.txBytes[0], first.member.payload[0], first.member.member.inputs[0].Vout
	second.member.txBytes[0] ^= 0xff
	second.member.payload[0] ^= 0xff
	second.member.member.inputs[0].Vout++
	if first.member.txBytes[0] != firstTxByte || first.member.payload[0] != firstPayloadByte || first.member.member.inputs[0].Vout != firstVout {
		t.Fatal("second candidate aliases first candidate")
	}
	after := fixture.admission.Snapshot()
	if !bytes.Equal(after.TxBytes, fixture.txBytes) || !slices.Equal(after.Inputs, fixture.inputs) {
		t.Fatal("candidate mutation changed admission")
	}
}

func TestDAAdmissionCandidateErrorOrder(t *testing.T) {
	provenance := daProvenance{kind: daProvenancePeer}
	success := newDAAdmissionCandidateFixture(t, 0x01)
	successHigh, successTokens, successOutpoints := daAdmissionOwnerCounts(success.admission)
	_ = mustDAAdmissionCandidate(t, success.admission, daProvenance{kind: daProvenanceLocal})
	if high, tokens, outpoints := daAdmissionOwnerCounts(success.admission); high != successHigh || tokens != successTokens || outpoints != successOutpoints || success.admission.guard.state.Load() != daAdmissionOpen {
		t.Fatalf("successful render changed owner or lifecycle: high=%d/%d tokens=%d/%d outpoints=%d/%d state=%d", high, successHigh, tokens, successTokens, outpoints, successOutpoints, success.admission.guard.state.Load())
	}
	success.admission.Close()

	fixture := newDAAdmissionCandidateFixture(t, 0x01)
	before := fixture.admission.Snapshot()
	beforeHigh, beforeTokens, beforeOutpoints := daAdmissionOwnerCounts(fixture.admission)
	fixture.admission.tx.DaCommitCore.ChunkCount = 0
	fixture.admission.tx.Outputs = nil
	fixture.admission.tx = nil
	requireDAAdmissionCandidateError(t, fixture.admission, provenance, errDAProvenanceInvalid)
	afterHigh, afterTokens, afterOutpoints := daAdmissionOwnerCounts(fixture.admission)
	if fixture.admission.guard.state.Load() != daAdmissionOpen || afterHigh != beforeHigh || afterTokens != beforeTokens || afterOutpoints != beforeOutpoints {
		t.Fatalf("rejected render changed admission: state=%d owner=%d/%d,%d/%d,%d/%d", fixture.admission.guard.state.Load(), afterHigh, beforeHigh, afterTokens, beforeTokens, afterOutpoints, beforeOutpoints)
	}
	if after := fixture.admission.Snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("rejected render changed snapshot: before=%+v after=%+v", before, after)
	}
	fixture.admission.Close()

	invalidKind := newDAAdmissionCandidateFixture(t, 0x01)
	invalidKind.admission.tx.TxKind = 0x03
	invalidKind.admission.tx.DaCommitCore.ChunkCount = 0
	invalidKind.admission.tx.Outputs = nil
	requireDAAdmissionCandidateError(t, invalidKind.admission, daProvenance{kind: daProvenanceLocal}, errDARelayMemberIncomplete)
	invalidKind.admission.Close()

	closed := newDAAdmissionCandidateFixture(t, 0x01)
	closed.admission.Close()
	mustPanic(t, func() { _, _ = closed.admission.renderDARelayAdmissionCandidate(provenance) })
}
