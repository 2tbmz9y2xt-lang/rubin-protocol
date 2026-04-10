package consensus

import (
	"math"
	"testing"
	"unsafe"
)

// helper: build a minimal tx with given witness items.
func txWithWitness(ws []WitnessItem) *Tx {
	return &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
		Witness: ws,
	}
}

func TestTxWeightAtHeight_NativeSuite_UsesRegistryCost(t *testing.T) {
	mlPub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	mlSig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	tx := txWithWitness([]WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: mlPub, Signature: mlSig},
	})

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	weightReg, _, _, err := TxWeightAndStatsAtHeight(tx, 100, rp, reg)
	if err != nil {
		t.Fatal(err)
	}
	weightLegacy, _, _, err := TxWeightAndStats(tx)
	if err != nil {
		t.Fatal(err)
	}

	// With only ML-DSA-87 (native), both should produce same result.
	if weightReg != weightLegacy {
		t.Errorf("registry weight %d != legacy weight %d", weightReg, weightLegacy)
	}
}

func TestTxWeightAtHeight_UnknownSuite_UsesFloor(t *testing.T) {
	unknownPub := make([]byte, 100)
	unknownSig := make([]byte, 200)
	tx := txWithWitness([]WitnessItem{
		{SuiteID: 0xFF, Pubkey: unknownPub, Signature: unknownSig},
	})

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	weightReg, _, _, err := TxWeightAndStatsAtHeight(tx, 100, rp, reg)
	if err != nil {
		t.Fatal(err)
	}
	weightLegacy, _, _, err := TxWeightAndStats(tx)
	if err != nil {
		t.Fatal(err)
	}

	// Both should use VERIFY_COST_UNKNOWN_SUITE for unknown suite.
	if weightReg != weightLegacy {
		t.Errorf("registry weight %d != legacy weight %d (both should use unknown cost)", weightReg, weightLegacy)
	}
}

func TestTxWeightAtHeight_NativeNotInSpendSet_UsesFloor(t *testing.T) {
	// Simulate suite 0x02 that IS registered but NOT in spend suites at this height.
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			SUITE_ID_ML_DSA_87: {
				SuiteID: SUITE_ID_ML_DSA_87, PubkeyLen: ML_DSA_87_PUBKEY_BYTES,
				SigLen: ML_DSA_87_SIG_BYTES, VerifyCost: VERIFY_COST_ML_DSA_87, AlgName: "ML-DSA-87",
			},
			0x02: {
				SuiteID: 0x02, PubkeyLen: 1312, SigLen: 2420,
				VerifyCost: 4, AlgName: "ML-DSA-65",
			},
		},
	}
	// Rotation provider only includes ML-DSA-87 in spend suites (not 0x02).
	rp := DefaultRotationProvider{}

	pub02 := make([]byte, 1312)
	sig02 := make([]byte, 2421) // 2420+1 sighash byte
	tx := txWithWitness([]WitnessItem{
		{SuiteID: 0x02, Pubkey: pub02, Signature: sig02},
	})

	weight, _, _, err := TxWeightAndStatsAtHeight(tx, 100, rp, reg)
	if err != nil {
		t.Fatal(err)
	}

	// Suite 0x02 not in native spend set → uses unknown suite floor cost.
	// Calculate expected: base weight + witness + da + VERIFY_COST_UNKNOWN_SUITE.
	weightWithNative, _, _, _ := func() (uint64, uint64, uint64, error) {
		// Same tx through a provider that includes 0x02.
		rpIncluding := &mockRotationProvider{h2: 0} // 0x02 in spend at height 0+
		return TxWeightAndStatsAtHeight(tx, 100, rpIncluding, reg)
	}()

	// Unknown floor (64) > native cost (4), so weight should be higher.
	if weight <= weightWithNative {
		t.Errorf("unknown-suite weight %d should be > native weight %d", weight, weightWithNative)
	}
	// Verify the difference is exactly (VERIFY_COST_UNKNOWN_SUITE - 4) = 60.
	if weight-weightWithNative != VERIFY_COST_UNKNOWN_SUITE-4 {
		t.Errorf("weight diff = %d, want %d", weight-weightWithNative, VERIFY_COST_UNKNOWN_SUITE-4)
	}
}

func TestTxWeightAtHeight_Sentinel_NoCost(t *testing.T) {
	tx := txWithWitness([]WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: nil, Signature: nil},
	})

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	weight, _, _, err := TxWeightAndStatsAtHeight(tx, 100, rp, reg)
	if err != nil {
		t.Fatal(err)
	}
	weightLegacy, _, _, err := TxWeightAndStats(tx)
	if err != nil {
		t.Fatal(err)
	}

	// Sentinel has zero cost in both paths.
	if weight != weightLegacy {
		t.Errorf("sentinel: registry weight %d != legacy weight %d", weight, weightLegacy)
	}
}

func TestTxWeightAtHeight_NilProviders_FallbackToLegacy(t *testing.T) {
	mlPub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	mlSig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	tx := txWithWitness([]WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: mlPub, Signature: mlSig},
	})

	// nil rotation
	weight1, _, _, err := TxWeightAndStatsAtHeight(tx, 100, nil, DefaultSuiteRegistry())
	if err != nil {
		t.Fatal(err)
	}
	// nil registry
	weight2, _, _, err := TxWeightAndStatsAtHeight(tx, 100, DefaultRotationProvider{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	legacy, _, _, _ := TxWeightAndStats(tx)
	if weight1 != legacy {
		t.Errorf("nil rotation: %d != legacy %d", weight1, legacy)
	}
	if weight2 != legacy {
		t.Errorf("nil registry: %d != legacy %d", weight2, legacy)
	}
}

func TestTxWeightAtHeight_NilTx(t *testing.T) {
	_, _, _, err := TxWeightAndStatsAtHeight(nil, 100, DefaultRotationProvider{}, DefaultSuiteRegistry())
	if err == nil {
		t.Fatal("expected error for nil tx")
	}
}

func TestTxWeightAtHeight_WrongLengths_UsesFloor(t *testing.T) {
	// ML-DSA-87 with wrong pubkey length → should use unknown cost even though
	// suite is native.
	wrongPub := make([]byte, ML_DSA_87_PUBKEY_BYTES+1)
	mlSig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	tx := txWithWitness([]WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: wrongPub, Signature: mlSig},
	})

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}
	weight, _, _, err := TxWeightAndStatsAtHeight(tx, 100, rp, reg)
	if err != nil {
		t.Fatal(err)
	}

	// Legacy treats this as non-ML-DSA (doesn't match length check), so unknownSuiteCount++.
	legacy, _, _, _ := TxWeightAndStats(tx)
	if weight != legacy {
		t.Errorf("wrong-lengths weight %d != legacy %d (both should use unknown floor)", weight, legacy)
	}
}

// fakeByteSlice creates a []byte slice header with the given length but
// minimal backing memory. Only len() is safe — accessing elements beyond
// index 0 is undefined. Used to trigger addU64 overflow paths in weight
// calculation without allocating gigabytes of memory.
func fakeByteSlice(n int) []byte {
	var dummy byte
	return unsafe.Slice(&dummy, n)
}

func TestTxWeightWithRegistry_ScriptSigOverflow(t *testing.T) {
	// Two inputs with ScriptSig length MaxInt each. After accumulating the
	// first input's scriptSig (~2^63), the second addU64(baseSize, len(scriptSig))
	// overflows uint64.
	big := fakeByteSlice(math.MaxInt)
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs: []TxInput{
			{ScriptSig: big},
			{ScriptSig: big},
		},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	_, _, _, err := txWeightAndStatsWithRegistry(tx, 100, rp, reg)
	if err == nil {
		t.Fatal("expected overflow error from huge ScriptSig")
	}
}

func TestTxWeightWithRegistry_CovenantDataOverflow(t *testing.T) {
	// Two outputs with CovenantData length MaxInt each → overflow in output loop.
	big := fakeByteSlice(math.MaxInt)
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{
			{Value: 1000, CovenantType: COV_TYPE_P2PK, CovenantData: big},
			{Value: 2000, CovenantType: COV_TYPE_P2PK, CovenantData: big},
		},
	}

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	_, _, _, err := txWeightAndStatsWithRegistry(tx, 100, rp, reg)
	if err == nil {
		t.Fatal("expected overflow error from huge CovenantData")
	}
}

func TestTxWeightWithRegistry_WitnessOverflow(t *testing.T) {
	// Two witness items with huge pubkey → overflow in witness loop.
	big := fakeByteSlice(math.MaxInt)
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
		Witness: []WitnessItem{
			{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: big, Signature: []byte{0x01}},
			{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: big, Signature: []byte{0x01}},
		},
	}

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	_, _, _, err := txWeightAndStatsWithRegistry(tx, 100, rp, reg)
	if err == nil {
		t.Fatal("expected overflow error from huge witness pubkey")
	}
}

func TestTxWeightWithRegistry_AnchorBytesOverflow(t *testing.T) {
	// Two anchor outputs with huge CovenantData → overflow in anchorBytes accumulation.
	big := fakeByteSlice(math.MaxInt)
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{
			{Value: 1000, CovenantType: COV_TYPE_ANCHOR, CovenantData: big},
			{Value: 2000, CovenantType: COV_TYPE_ANCHOR, CovenantData: big},
		},
	}

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	_, _, _, err := txWeightAndStatsWithRegistry(tx, 100, rp, reg)
	if err == nil {
		t.Fatal("expected overflow error from anchor bytes")
	}
}

func TestTxWeightWithRegistry_BaseWeightMulOverflow(t *testing.T) {
	// Single input with ScriptSig big enough that mulU64(4, baseSize) overflows.
	// After one MaxInt ScriptSig: baseSize ≈ 2^63. mulU64(4, 2^63) = 2^65 > MaxUint64.
	big := fakeByteSlice(math.MaxInt)
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{ScriptSig: big}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	_, _, _, err := txWeightAndStatsWithRegistry(tx, 100, rp, reg)
	if err == nil {
		t.Fatal("expected overflow error from mulU64(WITNESS_DISCOUNT_DIVISOR, baseSize)")
	}
}

func TestTxWeightWithRegistry_SignatureOverflow(t *testing.T) {
	// Two witness items with huge Signature → overflow in witness loop.
	big := fakeByteSlice(math.MaxInt)
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
		Witness: []WitnessItem{
			{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: []byte{0x01}, Signature: big},
			{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: []byte{0x01}, Signature: big},
		},
	}

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	_, _, _, err := txWeightAndStatsWithRegistry(tx, 100, rp, reg)
	if err == nil {
		t.Fatal("expected overflow error from huge witness signature")
	}
}

func TestTxWeightWithRegistry_DaPayloadOverflow(t *testing.T) {
	// DaPayload big enough to overflow daSize computation.
	big := fakeByteSlice(math.MaxInt)
	tx := &Tx{
		Version:   TX_WIRE_VERSION,
		TxKind:    0x01,
		Inputs:    []TxInput{{PrevVout: 0}},
		Outputs:   []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
		DaPayload: big,
	}

	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	_, _, _, err := txWeightAndStatsWithRegistry(tx, 100, rp, reg)
	if err == nil {
		t.Fatal("expected overflow error from huge DaPayload")
	}
}
