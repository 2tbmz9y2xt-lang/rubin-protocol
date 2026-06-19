package node

import (
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type testCoreExtProfiles struct {
	activeByExtID map[uint16]bool
}

func (p testCoreExtProfiles) LookupCoreExtProfile(extID uint16, _ uint64) (consensus.CoreExtProfile, bool, error) {
	if p.activeByExtID == nil {
		return consensus.CoreExtProfile{}, false, nil
	}
	active, ok := p.activeByExtID[extID]
	if !ok {
		return consensus.CoreExtProfile{}, false, nil
	}
	return consensus.CoreExtProfile{Active: active}, true, nil
}

type testSimplicityRotation struct {
	activeAt uint64
}

func (r testSimplicityRotation) NativeCreateSuites(uint64) *consensus.NativeSuiteSet {
	return consensus.NewNativeSuiteSet(consensus.SUITE_ID_ML_DSA_87)
}

func (r testSimplicityRotation) NativeSpendSuites(uint64) *consensus.NativeSuiteSet {
	return consensus.NewNativeSuiteSet(consensus.SUITE_ID_ML_DSA_87)
}

func (r testSimplicityRotation) SimplicityActiveAtHeight(height uint64) (bool, error) {
	return height >= r.activeAt, nil
}

func coreExtCovenantData(extID uint16, payload []byte) []byte {
	out := consensus.AppendU16le(nil, extID)
	out = consensus.AppendCompactSize(out, uint64(len(payload)))
	out = append(out, payload...)
	return out
}

func simplicityCovenantDataForNodeTest(programCMR [32]byte, state []byte) []byte {
	out := append([]byte(nil), programCMR[:]...)
	out = consensus.AppendCompactSize(out, uint64(len(state)))
	out = append(out, state...)
	return out
}

func p2pkCovenantDataForNodePolicyTest() []byte {
	out := make([]byte, consensus.MAX_P2PK_COVENANT_DATA)
	out[0] = consensus.SUITE_ID_ML_DSA_87
	return out
}

func txWithOneInputOneOutput(prevTxid [32]byte, prevVout uint32, outValue uint64, outCovType uint16, outCovData []byte, witnesses []consensus.WitnessItem) []byte {
	b := make([]byte, 0, 256+len(outCovData))
	b = consensus.AppendU32le(b, 1)
	b = append(b, 0x00) // tx_kind
	b = consensus.AppendU64le(b, 1)
	b = consensus.AppendCompactSize(b, 1) // input_count
	b = append(b, prevTxid[:]...)
	b = consensus.AppendU32le(b, prevVout)
	b = consensus.AppendCompactSize(b, 0) // script_sig_len
	b = consensus.AppendU32le(b, 0)       // sequence

	b = consensus.AppendCompactSize(b, 1) // output_count
	b = consensus.AppendU64le(b, outValue)
	b = consensus.AppendU16le(b, outCovType)
	b = consensus.AppendCompactSize(b, uint64(len(outCovData)))
	b = append(b, outCovData...)

	b = consensus.AppendU32le(b, 0) // locktime
	b = consensus.AppendCompactSize(b, uint64(len(witnesses)))
	for _, w := range witnesses {
		b = append(b, w.SuiteID)
		b = consensus.AppendCompactSize(b, uint64(len(w.Pubkey)))
		b = append(b, w.Pubkey...)
		b = consensus.AppendCompactSize(b, uint64(len(w.Signature)))
		b = append(b, w.Signature...)
	}
	b = consensus.AppendCompactSize(b, 0) // da_payload_len
	return b
}

func mustParseTx(t *testing.T, raw []byte) *consensus.Tx {
	t.Helper()
	tx, _, _, consumed, err := consensus.ParseTx(raw)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if consumed != len(raw) {
		t.Fatalf("consumed=%d len=%d", consumed, len(raw))
	}
	return tx
}

func TestRejectCoreExtTxPreActivation_RejectsCreateWhenProfileMissing(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x11
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_EXT, coreExtCovenantData(7, nil), nil)
	tx := mustParseTx(t, raw)

	reject, _, err := RejectCoreExtTxPreActivation(tx, nil, 0, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !reject {
		t.Fatalf("expected reject")
	}
}

func TestRejectCoreExtTxPreActivation_AllowsCreateWhenProfileActive(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x12
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_EXT, coreExtCovenantData(7, nil), nil)
	tx := mustParseTx(t, raw)

	profiles := testCoreExtProfiles{activeByExtID: map[uint16]bool{7: true}}
	reject, _, err := RejectCoreExtTxPreActivation(tx, nil, 0, profiles)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject {
		t.Fatalf("expected allow")
	}
}

func TestRejectCoreExtTxPreActivation_RejectsSpendWhenProfileMissing(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x13
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_P2PK, make([]byte, consensus.MAX_P2PK_COVENANT_DATA), []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL}})
	tx := mustParseTx(t, raw)

	utxos := map[consensus.Outpoint]consensus.UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        10,
			CovenantType: consensus.COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(9, nil),
		},
	}
	reject, _, err := RejectCoreExtTxPreActivation(tx, utxos, 0, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !reject {
		t.Fatalf("expected reject")
	}
}

func TestRejectCoreExtTxPreActivation_RejectsSimplicityPreActivation(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x14
	spendUtxos := map[consensus.Outpoint]consensus.UtxoEntry{{Txid: prev, Vout: 0}: {
		Value:        10,
		CovenantType: consensus.COV_TYPE_CORE_SIMPLICITY,
		CovenantData: simplicityCovenantDataForNodeTest([32]byte{0x52}, nil),
	}}
	tests := []struct {
		name    string
		raw     []byte
		utxos   map[consensus.Outpoint]consensus.UtxoEntry
		wantMsg string
	}{
		{"output", txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_SIMPLICITY, simplicityCovenantDataForNodeTest([32]byte{0x51}, nil), nil), nil, "CORE_SIMPLICITY output pre-ACTIVE"},
		{"spend", txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_P2PK, p2pkCovenantDataForNodePolicyTest(), nil), spendUtxos, "CORE_SIMPLICITY spend pre-ACTIVE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reject, reason, err := RejectCoreExtTxPreActivation(mustParseTx(t, tc.raw), tc.utxos, 0, nil)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !reject || reason != tc.wantMsg {
				t.Fatalf("reject=%v reason=%q, want %q", reject, reason, tc.wantMsg)
			}
		})
	}
}

func TestRejectCoreExtTxPreActivation_AllowsSimplicityWhenActive(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x16
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_SIMPLICITY, simplicityCovenantDataForNodeTest([32]byte{0x53}, nil), nil)
	tx := mustParseTx(t, raw)

	reject, reason, err := RejectCoreExtTxPreActivationWithRotation(tx, nil, 10, nil, testSimplicityRotation{activeAt: 10})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject || reason != "" {
		t.Fatalf("reject=%v reason=%q, want allow", reject, reason)
	}
}

func TestRejectCoreExtTxPreActivation_IgnoresSimplicityWitnessWithoutSimplicityCovenant(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x17
	witness := []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SIMPLICITY_ENVELOPE, Signature: []byte{0x01, 0x00, 0x00, consensus.SIGHASH_ALL}}}
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_P2PK, make([]byte, consensus.MAX_P2PK_COVENANT_DATA), witness)
	tx := mustParseTx(t, raw)

	reject, reason, err := RejectCoreExtTxPreActivation(tx, nil, 0, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject || reason != "" {
		t.Fatalf("reject=%v reason=%q, want allow", reject, reason)
	}
}

func TestRejectCoreExtTxOversizedPayload_NilTx(t *testing.T) {
	reject, _, err := RejectCoreExtTxOversizedPayload(nil, 48)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject {
		t.Fatalf("nil tx must not reject")
	}
}

func TestRejectCoreExtTxOversizedPayload_ZeroLimit(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x30
	payload := make([]byte, 100)
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_EXT, coreExtCovenantData(5, payload), nil)
	tx := mustParseTx(t, raw)

	reject, _, err := RejectCoreExtTxOversizedPayload(tx, 0)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject {
		t.Fatalf("zero limit must not reject (policy disabled)")
	}
}

func TestRejectCoreExtTxOversizedPayload_AllowsUnderLimit(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x31
	payload := make([]byte, 32)
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_EXT, coreExtCovenantData(5, payload), nil)
	tx := mustParseTx(t, raw)

	reject, _, err := RejectCoreExtTxOversizedPayload(tx, 48)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject {
		t.Fatalf("payload within limit must not reject")
	}
}

func TestRejectCoreExtTxOversizedPayload_AllowsAtLimit(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x32
	payload := make([]byte, 48)
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_EXT, coreExtCovenantData(5, payload), nil)
	tx := mustParseTx(t, raw)

	reject, _, err := RejectCoreExtTxOversizedPayload(tx, 48)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject {
		t.Fatalf("payload at exact limit must not reject")
	}
}

func TestRejectCoreExtTxOversizedPayload_RejectsOverLimit(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x33
	payload := make([]byte, 49)
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_EXT, coreExtCovenantData(5, payload), nil)
	tx := mustParseTx(t, raw)

	reject, reason, err := RejectCoreExtTxOversizedPayload(tx, 48)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !reject {
		t.Fatalf("payload over limit must reject")
	}
	if reason == "" {
		t.Fatalf("reason must not be empty")
	}
}

func TestRejectCoreExtTxOversizedPayload_IgnoresNonCoreExt(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x34
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_P2PK, make([]byte, consensus.MAX_P2PK_COVENANT_DATA), []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL}})
	tx := mustParseTx(t, raw)

	reject, _, err := RejectCoreExtTxOversizedPayload(tx, 1)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject {
		t.Fatalf("non-CORE_EXT output must not trigger payload check")
	}
}

func TestRejectCoreExtTxOversizedPayload_EmptyPayloadAllowed(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x35
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_EXT, coreExtCovenantData(5, nil), nil)
	tx := mustParseTx(t, raw)

	reject, _, err := RejectCoreExtTxOversizedPayload(tx, 1)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject {
		t.Fatalf("empty payload must not reject")
	}
}

func TestRejectCoreExtTxPreActivation_AllowsSpendWhenProfileActive(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x14
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_P2PK, make([]byte, consensus.MAX_P2PK_COVENANT_DATA), []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL}})
	tx := mustParseTx(t, raw)

	utxos := map[consensus.Outpoint]consensus.UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        10,
			CovenantType: consensus.COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(9, nil),
		},
	}
	profiles := testCoreExtProfiles{activeByExtID: map[uint16]bool{9: true}}
	reject, _, err := RejectCoreExtTxPreActivation(tx, utxos, 0, profiles)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject {
		t.Fatalf("expected allow")
	}
}
