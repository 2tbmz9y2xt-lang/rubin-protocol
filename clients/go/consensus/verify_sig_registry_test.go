//go:build cgo

package consensus

import (
	"fmt"
	"testing"
)

func TestVerifySigWithRegistry_NilRegistry_FallsBackToLegacy(t *testing.T) {
	var d [32]byte
	// ML-DSA-87 with wrong lengths → returns (false, nil) via legacy path.
	ok, err := verifySigWithRegistry(SUITE_ID_ML_DSA_87, []byte{0x01}, []byte{0x02}, d, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected false for wrong-length ML-DSA-87")
	}
}

func TestVerifySigWithRegistry_UnknownSuite_ReturnsError(t *testing.T) {
	reg := DefaultSuiteRegistry()
	var d [32]byte
	_, err := verifySigWithRegistry(0xFF, []byte{0x01}, []byte{0x02}, d, reg)
	if err == nil {
		t.Fatal("expected error for unknown suite")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}

func TestVerifySigWithRegistry_KnownSuite_WrongLengths_ReturnsFalse(t *testing.T) {
	reg := DefaultSuiteRegistry()
	var d [32]byte
	// ML-DSA-87 registered but pubkey is 1 byte → length mismatch → (false, nil).
	ok, err := verifySigWithRegistry(SUITE_ID_ML_DSA_87, []byte{0x01}, []byte{0x02}, d, reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected false for wrong-length pubkey")
	}
}

func TestVerifySigWithRegistry_KnownSuite_CorrectLengths_CallsOpenSSL(t *testing.T) {
	reg := DefaultSuiteRegistry()

	// Mock the OpenSSL function to capture the algorithm name.
	var capturedAlg string
	origFn := opensslVerifySigOneShotFn
	defer func() { opensslVerifySigOneShotFn = origFn }()
	opensslVerifySigOneShotFn = func(alg string, pub, sig, msg []byte) (bool, error) {
		capturedAlg = alg
		return true, nil
	}

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	sig := make([]byte, ML_DSA_87_SIG_BYTES)
	var d [32]byte

	ok, err := verifySigWithRegistry(SUITE_ID_ML_DSA_87, pub, sig, d, reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true from mocked verify")
	}
	if capturedAlg != "ML-DSA-87" {
		t.Fatalf("alg=%q, want %q", capturedAlg, "ML-DSA-87")
	}
}

func TestVerifySigWithRegistry_CustomSuite_UsesRegistryAlg(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x02: {
				SuiteID:    0x02,
				PubkeyLen:  1312,
				SigLen:     2420,
				VerifyCost: 4,
				OpenSSLAlg: "ML-DSA-65",
			},
		},
	}

	var capturedAlg string
	origFn := opensslVerifySigOneShotFn
	defer func() { opensslVerifySigOneShotFn = origFn }()
	opensslVerifySigOneShotFn = func(alg string, pub, sig, msg []byte) (bool, error) {
		capturedAlg = alg
		return true, nil
	}

	pub := make([]byte, 1312)
	sig := make([]byte, 2420)
	var d [32]byte

	ok, err := verifySigWithRegistry(0x02, pub, sig, d, reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true from mocked verify")
	}
	if capturedAlg != "ML-DSA-65" {
		t.Fatalf("alg=%q, want %q", capturedAlg, "ML-DSA-65")
	}
}

func TestValidateP2PKSpendAtHeight_NilProviders_FallsBackToLegacy(t *testing.T) {
	// With nil rotation/registry, should fallback to legacy path.
	// Legacy rejects non-ML-DSA-87 suite.
	w := WitnessItem{SuiteID: 0xFF, Pubkey: []byte{0x01}, Signature: []byte{0x02}}
	entry := UtxoEntry{}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateP2PKSpendAtHeight(entry, w, tx, 0, 1000, [32]byte{}, 100, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for unsupported suite in legacy path")
	}
}

func TestValidateP2PKSpendAtHeight_SuiteNotInSpendSet_RejectsError(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	// Suite 0xFF not in default spend set.
	w := WitnessItem{SuiteID: 0xFF, Pubkey: []byte{0x01}, Signature: []byte{0x02}}
	entry := UtxoEntry{}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateP2PKSpendAtHeight(entry, w, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg)
	if err == nil {
		t.Fatal("expected error for suite not in spend set")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}

func TestValidateP2PKSpendAtHeight_WrongLengths_Rejects(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	// ML-DSA-87 with wrong pubkey length.
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: []byte{0x01}, Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}
	entry := UtxoEntry{}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateP2PKSpendAtHeight(entry, w, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg)
	if err == nil {
		t.Fatal("expected error for wrong lengths")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_NONCANONICAL)
	}
}

func TestValidateThresholdSigSpendAtHeight_NilProviders_FallsBack(t *testing.T) {
	keys := [][32]byte{{}}
	ws := []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}
	tx := &Tx{Version: TX_WIRE_VERSION}

	// Sentinel with nil providers → legacy path → threshold not met.
	err := validateThresholdSigSpendAtHeight(keys, 1, ws, tx, 0, 1000, [32]byte{}, 100, nil, nil, nil, "TEST")
	if err == nil {
		t.Fatal("expected threshold-not-met error")
	}
}

func TestValidateThresholdSigSpendAtHeight_SentinelPassthrough(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	keys := [][32]byte{{}, {}}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL},
		{SuiteID: SUITE_ID_SENTINEL},
	}
	tx := &Tx{Version: TX_WIRE_VERSION}

	// Two sentinels, threshold=0 → should pass.
	err := validateThresholdSigSpendAtHeight(keys, 0, ws, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg, "TEST")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateThresholdSigSpendAtHeight_NonNativeSuiteRejects(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	keys := [][32]byte{{}}
	ws := []WitnessItem{
		{SuiteID: 0xFF, Pubkey: []byte{0x01}, Signature: []byte{0x02}},
	}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateThresholdSigSpendAtHeight(keys, 1, ws, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg, "TEST")
	if err == nil {
		t.Fatal("expected error for non-native suite")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}

func TestValidateThresholdSigSpendAtHeight_SlotMismatch(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	keys := [][32]byte{{}, {}}
	ws := []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateThresholdSigSpendAtHeight(keys, 1, ws, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg, "TEST")
	if err == nil {
		t.Fatal("expected error for slot mismatch")
	}
}

func TestVerifySigWithRegistry_ConsensusInitError_ReturnsError(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	reg := DefaultSuiteRegistry()

	// Mock consensus init to fail.
	opensslConsensusInitFn = func() error {
		return fmt.Errorf("init failed")
	}

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	sig := make([]byte, ML_DSA_87_SIG_BYTES)
	var d [32]byte

	_, err := verifySigWithRegistry(SUITE_ID_ML_DSA_87, pub, sig, d, reg)
	if err == nil {
		t.Fatal("expected error from failed consensus init")
	}
}

func TestVerifySigWithRegistry_OpenSSLError_ReturnsError(t *testing.T) {
	reg := DefaultSuiteRegistry()

	origFn := opensslVerifySigOneShotFn
	defer func() { opensslVerifySigOneShotFn = origFn }()
	opensslVerifySigOneShotFn = func(alg string, pub, sig, msg []byte) (bool, error) {
		return false, fmt.Errorf("openssl internal error")
	}

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	sig := make([]byte, ML_DSA_87_SIG_BYTES)
	var d [32]byte

	_, err := verifySigWithRegistry(SUITE_ID_ML_DSA_87, pub, sig, d, reg)
	if err == nil {
		t.Fatal("expected error from OpenSSL failure")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestVerifySigWithRegistry_VerifyReturnsFalse(t *testing.T) {
	reg := DefaultSuiteRegistry()

	origFn := opensslVerifySigOneShotFn
	defer func() { opensslVerifySigOneShotFn = origFn }()
	opensslVerifySigOneShotFn = func(alg string, pub, sig, msg []byte) (bool, error) {
		return false, nil // invalid signature
	}

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	sig := make([]byte, ML_DSA_87_SIG_BYTES)
	var d [32]byte

	ok, err := verifySigWithRegistry(SUITE_ID_ML_DSA_87, pub, sig, d, reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected false for invalid signature")
	}
}

// buildP2PKTestData creates test fixtures for P2PK spend with a mocked
// OpenSSL verify function. Returns entry, witness, tx, and a cleanup function.
func buildP2PKTestData(t *testing.T, suiteID uint8, pubLen, sigLen int) (UtxoEntry, WitnessItem, *Tx, func()) {
	t.Helper()
	pub := make([]byte, pubLen)
	pub[0] = 0x42 // non-zero to avoid trivial hash collision
	keyID := sha3_256(pub)

	// Build covenant data: [suiteID] ++ keyID (33 bytes = MAX_P2PK_COVENANT_DATA)
	covData := make([]byte, MAX_P2PK_COVENANT_DATA)
	covData[0] = suiteID
	copy(covData[1:33], keyID[:])

	entry := UtxoEntry{
		CovenantType: COV_TYPE_P2PK,
		CovenantData: covData,
	}

	// Signature: cryptoSig ++ sighashType byte (SIGHASH_ALL = 0x01)
	sigWithSighash := make([]byte, sigLen+1)
	sigWithSighash[sigLen] = 0x01 // SIGHASH_ALL

	w := WitnessItem{SuiteID: suiteID, Pubkey: pub, Signature: sigWithSighash}

	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}

	origFn := opensslVerifySigOneShotFn
	opensslVerifySigOneShotFn = func(alg string, p, s, msg []byte) (bool, error) {
		return true, nil
	}
	cleanup := func() { opensslVerifySigOneShotFn = origFn }

	return entry, w, tx, cleanup
}

func TestValidateP2PKSpendAtHeight_ValidSig_Success(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	entry, w, tx, cleanup := buildP2PKTestData(t, SUITE_ID_ML_DSA_87, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	defer cleanup()

	err := validateP2PKSpendAtHeight(entry, w, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateP2PKSpendAtHeight_BadCovenantData_Rejects(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	entry, w, tx, cleanup := buildP2PKTestData(t, SUITE_ID_ML_DSA_87, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	defer cleanup()

	// Corrupt covenant data.
	entry.CovenantData = []byte{0x00}

	err := validateP2PKSpendAtHeight(entry, w, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg)
	if err == nil {
		t.Fatal("expected error for bad covenant data")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestValidateP2PKSpendAtHeight_SuiteNotRegistered_Rejects(t *testing.T) {
	// Suite 0x02 in spend set but NOT in registry.
	rp := &mockRotationProvider{h2: 0}
	reg := DefaultSuiteRegistry() // only ML-DSA-87

	pub := make([]byte, 1312)
	sig := make([]byte, 2421) // 2420 + 1 sighash byte
	sig[2420] = 0x01
	w := WitnessItem{SuiteID: 0x02, Pubkey: pub, Signature: sig}
	entry := UtxoEntry{}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateP2PKSpendAtHeight(entry, w, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg)
	if err == nil {
		t.Fatal("expected error for suite not registered")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}

func TestValidateP2PKSpendAtHeight_KeyBindingMismatch_Rejects(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	entry, w, tx, cleanup := buildP2PKTestData(t, SUITE_ID_ML_DSA_87, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	defer cleanup()

	// Corrupt key ID in covenant data.
	entry.CovenantData[1] ^= 0xFF

	err := validateP2PKSpendAtHeight(entry, w, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg)
	if err == nil {
		t.Fatal("expected error for key binding mismatch")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestValidateThresholdSigSpendAtHeight_ValidSigs_MeetsThreshold(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	origFn := opensslVerifySigOneShotFn
	defer func() { opensslVerifySigOneShotFn = origFn }()
	opensslVerifySigOneShotFn = func(alg string, p, s, msg []byte) (bool, error) {
		return true, nil
	}

	pub1 := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	pub1[0] = 0x01
	key1 := sha3_256(pub1)

	sig1 := make([]byte, ML_DSA_87_SIG_BYTES+1)
	sig1[ML_DSA_87_SIG_BYTES] = 0x01 // SIGHASH_ALL

	keys := [][32]byte{key1, {}}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub1, Signature: sig1},
		{SuiteID: SUITE_ID_SENTINEL},
	}
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}

	// threshold=1, one valid sig + one sentinel → should pass.
	err := validateThresholdSigSpendAtHeight(keys, 1, ws, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg, "TEST")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateThresholdSigSpendAtHeight_ThresholdNotMet(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	keys := [][32]byte{{}, {}}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL},
		{SuiteID: SUITE_ID_SENTINEL},
	}
	tx := &Tx{Version: TX_WIRE_VERSION}

	// threshold=1, two sentinels → threshold not met.
	err := validateThresholdSigSpendAtHeight(keys, 1, ws, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg, "TEST")
	if err == nil {
		t.Fatal("expected threshold-not-met error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestValidateThresholdSigSpendAtHeight_SentinelWithPayload_Rejects(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	keys := [][32]byte{{}}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: []byte{0x01}},
	}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateThresholdSigSpendAtHeight(keys, 0, ws, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg, "TEST")
	if err == nil {
		t.Fatal("expected error for sentinel with pubkey")
	}
}

func TestValidateThresholdSigSpendAtHeight_WrongLengths_Rejects(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	keys := [][32]byte{{}}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: []byte{0x01}, Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)},
	}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateThresholdSigSpendAtHeight(keys, 1, ws, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg, "TEST")
	if err == nil {
		t.Fatal("expected error for wrong lengths")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_NONCANONICAL)
	}
}

func TestValidateThresholdSigSpendAtHeight_NotRegistered_Rejects(t *testing.T) {
	// Suite in spend set but not in registry.
	rp := &mockRotationProvider{h2: 0}
	reg := DefaultSuiteRegistry()

	keys := [][32]byte{{}}
	ws := []WitnessItem{
		{SuiteID: 0x02, Pubkey: make([]byte, 1312), Signature: make([]byte, 2421)},
	}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateThresholdSigSpendAtHeight(keys, 1, ws, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg, "TEST")
	if err == nil {
		t.Fatal("expected error for unregistered suite")
	}
}

func TestVerifyKeyAndSigWithRegistryCache_KeyMismatch(t *testing.T) {
	reg := DefaultSuiteRegistry()

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	sig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	sig[ML_DSA_87_SIG_BYTES] = 0x01
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig}

	// Expected key ID doesn't match pub.
	var wrongKeyID [32]byte
	wrongKeyID[0] = 0xFF

	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}

	err := verifyKeyAndSigWithRegistryCache(w, wrongKeyID, tx, 0, 1000, [32]byte{}, nil, reg, "TEST")
	if err == nil {
		t.Fatal("expected key binding mismatch error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestVerifyKeyAndSigWithRegistryCache_SigInvalid(t *testing.T) {
	reg := DefaultSuiteRegistry()

	origFn := opensslVerifySigOneShotFn
	defer func() { opensslVerifySigOneShotFn = origFn }()
	opensslVerifySigOneShotFn = func(alg string, p, s, msg []byte) (bool, error) {
		return false, nil // invalid sig
	}

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	pub[0] = 0x42
	keyID := sha3_256(pub)

	sig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	sig[ML_DSA_87_SIG_BYTES] = 0x01
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig}

	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}

	err := verifyKeyAndSigWithRegistryCache(w, keyID, tx, 0, 1000, [32]byte{}, nil, reg, "TEST")
	if err == nil {
		t.Fatal("expected sig invalid error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestVerifyKeyAndSigWithRegistryCache_OpenSSLError(t *testing.T) {
	reg := DefaultSuiteRegistry()

	origFn := opensslVerifySigOneShotFn
	defer func() { opensslVerifySigOneShotFn = origFn }()
	opensslVerifySigOneShotFn = func(alg string, p, s, msg []byte) (bool, error) {
		return false, fmt.Errorf("internal error")
	}

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	pub[0] = 0x42
	keyID := sha3_256(pub)

	sig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	sig[ML_DSA_87_SIG_BYTES] = 0x01
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig}

	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}

	err := verifyKeyAndSigWithRegistryCache(w, keyID, tx, 0, 1000, [32]byte{}, nil, reg, "TEST")
	if err == nil {
		t.Fatal("expected openssl error")
	}
}

func TestVerifyKeyAndSigWithRegistryCache_BadSighash(t *testing.T) {
	reg := DefaultSuiteRegistry()

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	pub[0] = 0x42
	keyID := sha3_256(pub)

	// Invalid sighash byte (0x00) → extractSigAndDigest error.
	sig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	sig[ML_DSA_87_SIG_BYTES] = 0x00 // invalid sighash
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig}

	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}

	err := verifyKeyAndSigWithRegistryCache(w, keyID, tx, 0, 1000, [32]byte{}, nil, reg, "TEST")
	if err == nil {
		t.Fatal("expected error for invalid sighash")
	}
}

func TestValidateThresholdSigSpendAtHeight_SigVerifyError(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	pub1 := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	pub1[0] = 0x01
	// Use wrong key ID so verifyKeyAndSig returns key binding mismatch.
	var wrongKey [32]byte
	wrongKey[0] = 0xFF

	sig1 := make([]byte, ML_DSA_87_SIG_BYTES+1)
	sig1[ML_DSA_87_SIG_BYTES] = 0x01

	keys := [][32]byte{wrongKey}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub1, Signature: sig1},
	}
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}

	err := validateThresholdSigSpendAtHeight(keys, 1, ws, tx, 0, 1000, [32]byte{}, 100, nil, rp, reg, "TEST")
	if err == nil {
		t.Fatal("expected error from key binding mismatch")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestVerifyKeyAndSigWithRegistryCache_Success(t *testing.T) {
	reg := DefaultSuiteRegistry()

	origFn := opensslVerifySigOneShotFn
	defer func() { opensslVerifySigOneShotFn = origFn }()
	opensslVerifySigOneShotFn = func(alg string, p, s, msg []byte) (bool, error) {
		return true, nil
	}

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	pub[0] = 0x42
	keyID := sha3_256(pub)

	sig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	sig[ML_DSA_87_SIG_BYTES] = 0x01
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig}

	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}

	err := verifyKeyAndSigWithRegistryCache(w, keyID, tx, 0, 1000, [32]byte{}, nil, reg, "TEST")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
