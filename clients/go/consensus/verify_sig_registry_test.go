//go:build cgo

package consensus

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func canonicalDefaultRuntimeSuiteParams() SuiteParams {
	params, ok := DefaultSuiteRegistry().Lookup(SUITE_ID_ML_DSA_87)
	if !ok {
		panic("default runtime registry missing ML-DSA-87")
	}
	return params
}

func assertDefaultRuntimeRegistryDriftError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected default runtime registry drift error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
	if got, want := err.Error(), fmt.Sprintf("%s: verify_sig: default runtime registry drift", TX_ERR_SIG_ALG_INVALID); got != want {
		t.Fatalf("err=%q, want %q", got, want)
	}
}

func TestVerifySigWithRegistry_NilRegistry_UsesDefaultLiveRegistry(t *testing.T) {
	var d [32]byte
	// ML-DSA-87 with wrong lengths still routes through the canonical default
	// live registry and returns (false, nil) without a transport error.
	ok, err := verifySigWithRegistry(SUITE_ID_ML_DSA_87, []byte{0x01}, []byte{0x02}, d, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected false for wrong-length ML-DSA-87")
	}
}

func TestVerifySigWithRegistry_NilRegistry_MatchesExplicitDefaultLiveRegistry(t *testing.T) {
	reg := DefaultSuiteRegistry()
	var captured []string
	origFn := opensslVerifySigOneShotFn
	defer func() { opensslVerifySigOneShotFn = origFn }()
	opensslVerifySigOneShotFn = func(alg string, pub, sig, msg []byte) (bool, error) {
		captured = append(captured, alg)
		return true, nil
	}

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	sig := make([]byte, ML_DSA_87_SIG_BYTES)
	var d [32]byte

	ok, err := verifySigWithRegistry(SUITE_ID_ML_DSA_87, pub, sig, d, nil)
	if err != nil {
		t.Fatalf("nil registry verify: %v", err)
	}
	if !ok {
		t.Fatal("nil registry must verify canonical default live registry")
	}

	ok, err = verifySigWithRegistry(SUITE_ID_ML_DSA_87, pub, sig, d, reg)
	if err != nil {
		t.Fatalf("explicit registry verify: %v", err)
	}
	if !ok {
		t.Fatal("explicit registry must verify canonical default live registry")
	}

	if len(captured) != 2 {
		t.Fatalf("captured=%d calls, want 2", len(captured))
	}
	wantAlg := canonicalDefaultRuntimeSuiteParams().AlgName
	for i, got := range captured {
		if got != wantAlg {
			t.Fatalf("call %d alg=%q, want %q", i, got, wantAlg)
		}
	}
}

func TestRuntimeSuiteParamsForVerification_NilRegistryMatchesExplicitDefaultLiveRegistry(t *testing.T) {
	reg := DefaultSuiteRegistry()

	gotNil, err := runtimeSuiteParamsForVerification(SUITE_ID_ML_DSA_87, nil)
	if err != nil {
		t.Fatalf("runtimeSuiteParamsForVerification(nil): %v", err)
	}
	gotExplicit, err := runtimeSuiteParamsForVerification(SUITE_ID_ML_DSA_87, reg)
	if err != nil {
		t.Fatalf("runtimeSuiteParamsForVerification(explicit): %v", err)
	}

	want := canonicalDefaultRuntimeSuiteParams()
	if gotNil != want {
		t.Fatalf("nil params=%+v, want %+v", gotNil, want)
	}
	if gotExplicit != want {
		t.Fatalf("explicit params=%+v, want %+v", gotExplicit, want)
	}
	if gotNil != gotExplicit {
		t.Fatalf("nil params=%+v != explicit params=%+v", gotNil, gotExplicit)
	}
}

func TestRuntimeSuiteParamsForVerification_NilRegistry_DefaultRegistryDriftFailsClosed(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*SuiteParams)
	}{
		{
			name: "alg_name_empty",
			mutate: func(params *SuiteParams) {
				params.AlgName = ""
			},
		},
		{
			name: "alg_name_alias",
			mutate: func(params *SuiteParams) {
				params.AlgName = strings.ToLower(params.AlgName)
			},
		},
		{
			name: "pubkey_len",
			mutate: func(params *SuiteParams) {
				params.PubkeyLen--
			},
		},
		{
			name: "sig_len",
			mutate: func(params *SuiteParams) {
				params.SigLen--
			},
		},
		{
			name: "verify_cost",
			mutate: func(params *SuiteParams) {
				params.VerifyCost--
			},
		},
	}

	orig := defaultRuntimeSuiteRegistryForVerification
	defer func() { defaultRuntimeSuiteRegistryForVerification = orig }()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defaultRuntimeSuiteRegistryForVerification = func() *SuiteRegistry {
				params := canonicalDefaultRuntimeSuiteParams()
				tc.mutate(&params)
				return &SuiteRegistry{
					suites: map[uint8]SuiteParams{
						SUITE_ID_ML_DSA_87: params,
					},
				}
			}

			_, err := runtimeSuiteParamsForVerification(SUITE_ID_ML_DSA_87, nil)
			assertDefaultRuntimeRegistryDriftError(t, err)
		})
	}
}

func TestVerifySigWithRegistry_NilRegistry_DefaultRegistryDriftFailsClosed(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*SuiteParams)
	}{
		{
			name: "alg_name",
			mutate: func(params *SuiteParams) {
				params.AlgName = "ML-DSA-65"
			},
		},
		{
			name: "alg_name_empty",
			mutate: func(params *SuiteParams) {
				params.AlgName = ""
			},
		},
		{
			name: "alg_name_alias",
			mutate: func(params *SuiteParams) {
				params.AlgName = strings.ToLower(params.AlgName)
			},
		},
		{
			name: "pubkey_len",
			mutate: func(params *SuiteParams) {
				params.PubkeyLen--
			},
		},
		{
			name: "sig_len",
			mutate: func(params *SuiteParams) {
				params.SigLen--
			},
		},
	}

	orig := defaultRuntimeSuiteRegistryForVerification
	defer func() { defaultRuntimeSuiteRegistryForVerification = orig }()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defaultRuntimeSuiteRegistryForVerification = func() *SuiteRegistry {
				params := canonicalDefaultRuntimeSuiteParams()
				tc.mutate(&params)
				return &SuiteRegistry{
					suites: map[uint8]SuiteParams{
						SUITE_ID_ML_DSA_87: params,
					},
				}
			}

			var d [32]byte
			_, err := verifySigWithRegistry(SUITE_ID_ML_DSA_87, []byte{0x01}, []byte{0x02}, d, nil)
			assertDefaultRuntimeRegistryDriftError(t, err)
		})
	}
}

func TestVerifySigWithRegistry_NilRegistry_VerifyCostDriftFailsClosed(t *testing.T) {
	params := canonicalDefaultRuntimeSuiteParams()
	if got, want := params.VerifyCost, uint64(VERIFY_COST_ML_DSA_87); got != want {
		t.Fatalf("canonical verify_cost=%d, want %d", got, want)
	}

	orig := defaultRuntimeSuiteRegistryForVerification
	defer func() { defaultRuntimeSuiteRegistryForVerification = orig }()
	defaultRuntimeSuiteRegistryForVerification = func() *SuiteRegistry {
		params := canonicalDefaultRuntimeSuiteParams()
		params.VerifyCost--
		return &SuiteRegistry{
			suites: map[uint8]SuiteParams{
				SUITE_ID_ML_DSA_87: params,
			},
		}
	}

	var d [32]byte
	_, err := verifySigWithRegistry(SUITE_ID_ML_DSA_87, []byte{0x01}, []byte{0x02}, d, nil)
	assertDefaultRuntimeRegistryDriftError(t, err)
}

func TestResolveSuiteVerifierBinding_MatchesCanonicalRuntimeParams(t *testing.T) {
	params := canonicalDefaultRuntimeSuiteParams()
	binding, err := resolveSuiteVerifierBinding(params.AlgName, params.PubkeyLen, params.SigLen)
	if err != nil {
		t.Fatalf("resolveSuiteVerifierBinding: %v", err)
	}
	if binding.kind != suiteVerifierBindingOpenSSLDigest32V1 {
		t.Fatalf("binding.kind=%v, want %v", binding.kind, suiteVerifierBindingOpenSSLDigest32V1)
	}
	if binding.opensslAlg != "ML-DSA-87" {
		t.Fatalf("binding.opensslAlg=%q, want %q", binding.opensslAlg, "ML-DSA-87")
	}
	if binding.pubkeyLen != params.PubkeyLen {
		t.Fatalf("binding.pubkeyLen=%d, want %d", binding.pubkeyLen, params.PubkeyLen)
	}
	if binding.sigLen != params.SigLen {
		t.Fatalf("binding.sigLen=%d, want %d", binding.sigLen, params.SigLen)
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

func TestVerifySigWithRegistry_CustomSuite_ExactV1BindingAllowed(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x02: {
				SuiteID:    0x02,
				PubkeyLen:  ML_DSA_87_PUBKEY_BYTES,
				SigLen:     ML_DSA_87_SIG_BYTES,
				VerifyCost: VERIFY_COST_ML_DSA_87,
				AlgName:    "ML-DSA-87",
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

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	sig := make([]byte, ML_DSA_87_SIG_BYTES)
	var d [32]byte

	ok, err := verifySigWithRegistry(0x02, pub, sig, d, reg)
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

func TestVerifySigWithRegistry_CustomSuite_UnsupportedBindingRejected(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x02: {
				SuiteID:    0x02,
				PubkeyLen:  1312,
				SigLen:     2420,
				VerifyCost: 4,
				AlgName:    "ML-DSA-65",
			},
		},
	}

	pub := make([]byte, 1312)
	sig := make([]byte, 2420)
	var d [32]byte

	_, err := verifySigWithRegistry(0x02, pub, sig, d, reg)
	if err == nil {
		t.Fatal("expected explicit binding rejection")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
	if got := err.Error(); !strings.Contains(got, "suite_id=0x02") {
		t.Fatalf("err=%q, want suite_id context", got)
	}
}

func TestValidateP2PKSpendAtHeight_NilProviders_UseDefaultProviders(t *testing.T) {
	// With nil rotation/registry, consensus uses canonical default providers.
	// The default live registry still rejects non-ML-DSA-87 suites.
	w := WitnessItem{SuiteID: 0xFF, Pubkey: []byte{0x01}, Signature: []byte{0x02}}
	entry := UtxoEntry{}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateP2PKSpendAtHeight(testP2PKSpendCheck(entry, w, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
	}))
	if err == nil {
		t.Fatal("expected error for unsupported suite with default providers")
	}
}

func TestValidateP2PKSpendAtHeight_SuiteNotInSpendSet_RejectsError(t *testing.T) {
	reg := DefaultSuiteRegistry()
	rp := DefaultRotationProvider{}

	// Suite 0xFF not in default spend set.
	w := WitnessItem{SuiteID: 0xFF, Pubkey: []byte{0x01}, Signature: []byte{0x02}}
	entry := UtxoEntry{}
	tx := &Tx{Version: TX_WIRE_VERSION}

	err := validateP2PKSpendAtHeight(testP2PKSpendCheck(entry, w, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
	}))
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

	err := validateP2PKSpendAtHeight(testP2PKSpendCheck(entry, w, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
	}))
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

	// Sentinel with nil providers uses canonical defaults and still enforces threshold.
	err := validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck(keys, 1, ws, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		context:     "TEST",
	}))
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
	err := validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck(keys, 0, ws, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
		context:     "TEST",
	}))
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

	err := validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck(keys, 1, ws, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
		context:     "TEST",
	}))
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

	err := validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck(keys, 1, ws, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
		context:     "TEST",
	}))
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

	err := validateP2PKSpendAtHeight(testP2PKSpendCheck(entry, w, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
	}))
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

	err := validateP2PKSpendAtHeight(testP2PKSpendCheck(entry, w, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
	}))
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

	err := validateP2PKSpendAtHeight(testP2PKSpendCheck(entry, w, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
	}))
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

	err := validateP2PKSpendAtHeight(testP2PKSpendCheck(entry, w, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
	}))
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
	err := validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck(keys, 1, ws, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
		context:     "TEST",
	}))
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
	err := validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck(keys, 1, ws, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
		context:     "TEST",
	}))
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

	err := validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck(keys, 0, ws, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
		context:     "TEST",
	}))
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

	err := validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck(keys, 1, ws, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
		context:     "TEST",
	}))
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

	err := validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck(keys, 1, ws, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
		context:     "TEST",
	}))
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

	err := verifyKeyAndSigWithRegistryCache(w, wrongKeyID, testSpendKeySigContext(testSpendSigEnv{
		tx:         tx,
		inputValue: 1000,
		registry:   reg,
		context:    "TEST",
	}))
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

	err := verifyKeyAndSigWithRegistryCache(w, keyID, testSpendKeySigContext(testSpendSigEnv{
		tx:         tx,
		inputValue: 1000,
		registry:   reg,
		context:    "TEST",
	}))
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

	err := verifyKeyAndSigWithRegistryCache(w, keyID, testSpendKeySigContext(testSpendSigEnv{
		tx:         tx,
		inputValue: 1000,
		registry:   reg,
		context:    "TEST",
	}))
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

	err := verifyKeyAndSigWithRegistryCache(w, keyID, testSpendKeySigContext(testSpendSigEnv{
		tx:         tx,
		inputValue: 1000,
		registry:   reg,
		context:    "TEST",
	}))
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

	err := validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck(keys, 1, ws, testSpendSigEnv{
		tx:          tx,
		inputValue:  1000,
		blockHeight: 100,
		rotation:    rp,
		registry:    reg,
		context:     "TEST",
	}))
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

	err := verifyKeyAndSigWithRegistryCache(w, keyID, testSpendKeySigContext(testSpendSigEnv{
		tx:         tx,
		inputValue: 1000,
		registry:   reg,
		context:    "TEST",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Live positive SigCache (RUB-1121)
// ─────────────────────────────────────────────────────────────────────────────

// liveSigCacheBackend is the counting backend seam for the live-cache tests. It
// is the honest way to prove "a hit skips exactly the backend call and nothing
// else" and "a miss executes it exactly once": every assertion below is against
// the observed call count, never against an argument about control flow.
type liveSigCacheBackend struct {
	calls int
	ok    bool
	err   error
}

func newLiveSigCacheBackend(t *testing.T, ok bool, err error) *liveSigCacheBackend {
	t.Helper()
	backend := &liveSigCacheBackend{ok: ok, err: err}
	orig := opensslVerifySigOneShotFn
	opensslVerifySigOneShotFn = func(_ string, _, _, _ []byte) (bool, error) {
		backend.calls++
		return backend.ok, backend.err
	}
	t.Cleanup(func() { opensslVerifySigOneShotFn = orig })
	return backend
}

// liveSigCacheTuple returns canonical-length ML-DSA-87 witness bytes plus a
// digest, all derived from seed so distinct seeds never alias.
func liveSigCacheTuple(seed byte) (pubkey, sig []byte, digest [32]byte) {
	pubkey = make([]byte, ML_DSA_87_PUBKEY_BYTES)
	pubkey[0] = seed
	sig = make([]byte, ML_DSA_87_SIG_BYTES)
	sig[0] = seed
	digest[0] = seed
	return pubkey, sig, digest
}

// registryWithAlg returns a registry whose ML-DSA-87 suite ID maps to a
// different algorithm identity, i.e. a changed registry mapping behind the same
// suite ID.
func registryWithAlg(alg string) *SuiteRegistry {
	params := canonicalDefaultRuntimeSuiteParams()
	params.AlgName = alg
	return NewSuiteRegistryFromParams([]SuiteParams{params})
}

func TestLiveSigCacheHitSkipsOnlyTheBackendCall(t *testing.T) {
	backend := newLiveSigCacheBackend(t, true, nil)
	cache := NewSigCache(4)
	reg := DefaultSuiteRegistry()
	pub, sig, digest := liveSigCacheTuple(0x11)

	ok, err := verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, pub, sig, digest, reg, cache)
	if err != nil || !ok {
		t.Fatalf("first verify: ok=%v err=%v", ok, err)
	}
	if backend.calls != 1 {
		t.Fatalf("miss must execute the backend exactly once, got %d calls", backend.calls)
	}
	if cache.Len() != 1 || cache.Misses() != 1 || cache.Hits() != 0 {
		t.Fatalf("after miss: len=%d misses=%d hits=%d, want 1/1/0", cache.Len(), cache.Misses(), cache.Hits())
	}

	ok, err = verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, pub, sig, digest, reg, cache)
	if err != nil || !ok {
		t.Fatalf("second verify: ok=%v err=%v", ok, err)
	}
	if backend.calls != 1 {
		t.Fatalf("hit must skip the backend, got %d calls", backend.calls)
	}
	if cache.Hits() != 1 || cache.Len() != 1 {
		t.Fatalf("after hit: hits=%d len=%d, want 1/1", cache.Hits(), cache.Len())
	}

	// A different digest, pubkey, signature, or suite is a different tuple.
	otherPub, otherSig, otherDigest := liveSigCacheTuple(0x22)
	for _, tc := range []struct {
		name   string
		pub    []byte
		sig    []byte
		digest [32]byte
	}{
		{"different_digest", pub, sig, otherDigest},
		{"different_pubkey", otherPub, sig, digest},
		{"different_signature", pub, otherSig, digest},
	} {
		before := backend.calls
		if _, err := verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, tc.pub, tc.sig, tc.digest, reg, cache); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if backend.calls != before+1 {
			t.Fatalf("%s must miss and execute the backend once", tc.name)
		}
	}
}

func TestLiveSigCacheNilCacheIsExactBaseline(t *testing.T) {
	backend := newLiveSigCacheBackend(t, true, nil)
	pub, sig, digest := liveSigCacheTuple(0x33)

	for i := 1; i <= 3; i++ {
		ok, err := verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, pub, sig, digest, DefaultSuiteRegistry(), nil)
		if err != nil || !ok {
			t.Fatalf("run %d: ok=%v err=%v", i, ok, err)
		}
		if backend.calls != i {
			t.Fatalf("nil cache must execute the backend every run: calls=%d, want %d", backend.calls, i)
		}
	}
}

func TestLiveSigCacheNeverInsertsUnsuccessfulResults(t *testing.T) {
	backendErr := errors.New("backend exploded")
	cases := []struct {
		name     string
		ok       bool
		err      error
		registry *SuiteRegistry
		suiteID  uint8
		wantCode ErrorCode
		wantCall bool
	}{
		{name: "invalid_signature", ok: false, registry: DefaultSuiteRegistry(), suiteID: SUITE_ID_ML_DSA_87, wantCall: true},
		{name: "backend_error", ok: false, err: backendErr, registry: DefaultSuiteRegistry(), suiteID: SUITE_ID_ML_DSA_87, wantCode: TX_ERR_SIG_INVALID, wantCall: true},
		{name: "unknown_suite", ok: true, registry: DefaultSuiteRegistry(), suiteID: 0x7e, wantCode: TX_ERR_SIG_ALG_INVALID},
		{name: "registry_mapping_changed", ok: true, registry: registryWithAlg("ML-DSA-44"), suiteID: SUITE_ID_ML_DSA_87, wantCode: TX_ERR_SIG_ALG_INVALID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := newLiveSigCacheBackend(t, tc.ok, tc.err)
			cache := NewSigCache(4)
			pub, sig, digest := liveSigCacheTuple(0x44)

			ok, err := verifySigWithRegistryCache(tc.suiteID, pub, sig, digest, tc.registry, cache)
			if ok {
				t.Fatal("expected a non-accepting result")
			}
			switch {
			case tc.wantCode == "":
				if err != nil {
					t.Fatalf("want (false, nil), got err=%v", err)
				}
			default:
				if got := mustTxErrCode(t, err); got != tc.wantCode {
					t.Fatalf("code=%s, want %s", got, tc.wantCode)
				}
			}
			if tc.wantCall && backend.calls != 1 {
				t.Fatalf("backend calls=%d, want 1", backend.calls)
			}
			if !tc.wantCall && backend.calls != 0 {
				t.Fatalf("backend must not run before the failing check: calls=%d", backend.calls)
			}
			if cache.Len() != 0 {
				t.Fatalf("no unsuccessful result may be inserted: len=%d", cache.Len())
			}
		})
	}
}

// TestLiveSigCacheStaleBindingAndLengthCannotHit pins the two ways a cached
// tuple must NOT be reusable: after the registry mapping behind the suite ID
// changed (resolution now fails closed), and for a non-canonical length whose
// bytes share the cached prefix.
func TestLiveSigCacheStaleBindingAndLengthCannotHit(t *testing.T) {
	backend := newLiveSigCacheBackend(t, true, nil)
	cache := NewSigCache(4)
	pub, sig, digest := liveSigCacheTuple(0x55)

	if _, err := verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, pub, sig, digest, DefaultSuiteRegistry(), cache); err != nil {
		t.Fatalf("seed verify: %v", err)
	}
	if cache.Len() != 1 || backend.calls != 1 {
		t.Fatalf("seed state: len=%d calls=%d, want 1/1", cache.Len(), backend.calls)
	}
	hitsAfterSeed := cache.Hits()

	// Same suite ID, changed registry mapping: fails closed at resolution, so
	// the older binding-keyed entry cannot be reached at all.
	_, err := verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, pub, sig, digest, registryWithAlg("ML-DSA-44"), cache)
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
	if cache.Hits() != hitsAfterSeed {
		t.Fatalf("stale binding produced a hit: hits=%d, want %d", cache.Hits(), hitsAfterSeed)
	}
	if backend.calls != 1 {
		t.Fatalf("resolution failure must not reach the backend: calls=%d", backend.calls)
	}

	// Non-canonical lengths sharing the cached byte prefix: rejected before the
	// cache is CONSULTED AT ALL, so neither the hit nor the miss counter moves
	// and the backend is never reached. The miss counter is the load-bearing
	// assertion: it is what distinguishes "checked lengths, then looked up"
	// from "looked up, then checked lengths".
	missesAfterSeed := cache.Misses()
	for _, tc := range []struct {
		name string
		pub  []byte
		sig  []byte
	}{
		{"short_signature", pub, sig[:len(sig)-1]},
		{"short_pubkey", pub[:len(pub)-1], sig},
		{"long_signature", pub, append(append([]byte(nil), sig...), 0x00)},
	} {
		ok, err := verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, tc.pub, tc.sig, digest, DefaultSuiteRegistry(), cache)
		if ok || err != nil {
			t.Fatalf("%s: ok=%v err=%v, want (false, nil)", tc.name, ok, err)
		}
		if cache.Hits() != hitsAfterSeed || cache.Misses() != missesAfterSeed {
			t.Fatalf("%s consulted the cache: hits=%d misses=%d, want %d/%d",
				tc.name, cache.Hits(), cache.Misses(), hitsAfterSeed, missesAfterSeed)
		}
		if backend.calls != 1 {
			t.Fatalf("%s reached the backend: calls=%d", tc.name, backend.calls)
		}
	}
}

// TestLiveSigCacheSaturationAdmitsNewestVerifiedTuple covers capacity pressure
// on the live path: the newest verified tuple always enters and the oldest
// insertion is the one that has to be re-verified afterwards.
func TestLiveSigCacheSaturationAdmitsNewestVerifiedTuple(t *testing.T) {
	backend := newLiveSigCacheBackend(t, true, nil)
	cache := NewSigCache(1)
	reg := DefaultSuiteRegistry()
	pubA, sigA, dA := liveSigCacheTuple(0x66)
	pubB, sigB, dB := liveSigCacheTuple(0x77)

	if _, err := verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, pubA, sigA, dA, reg, cache); err != nil {
		t.Fatalf("verify A: %v", err)
	}
	if _, err := verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, pubB, sigB, dB, reg, cache); err != nil {
		t.Fatalf("verify B: %v", err)
	}
	if backend.calls != 2 || cache.Len() != 1 {
		t.Fatalf("calls=%d len=%d, want 2/1", backend.calls, cache.Len())
	}

	// B (newest) is resident; A was evicted and must be verified again.
	if _, err := verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, pubB, sigB, dB, reg, cache); err != nil {
		t.Fatalf("verify B again: %v", err)
	}
	if backend.calls != 2 {
		t.Fatalf("newest tuple must hit: calls=%d, want 2", backend.calls)
	}
	if _, err := verifySigWithRegistryCache(SUITE_ID_ML_DSA_87, pubA, sigA, dA, reg, cache); err != nil {
		t.Fatalf("verify A again: %v", err)
	}
	if backend.calls != 3 {
		t.Fatalf("evicted tuple must re-execute the backend: calls=%d, want 3", backend.calls)
	}
}

// TestLiveSigCacheSharedBySequentialSpendPaths proves each supported sequential
// native signature path consumes the SAME caller-owned cache, and that a
// key-binding mismatch neither hits nor inserts even when the signature bytes
// are already cached.
func TestLiveSigCacheSharedBySequentialSpendPaths(t *testing.T) {
	backend := newLiveSigCacheBackend(t, true, nil)
	cache := NewSigCache(16)
	reg := DefaultSuiteRegistry()

	pub, cryptoSig, _ := liveSigCacheTuple(0x88)
	keyID := sha3_256(pub)
	w := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    pub,
		Signature: append(append([]byte(nil), cryptoSig...), SIGHASH_ALL),
	}
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK}},
	}
	sigCtx := func() spendSigContext {
		return spendSigContext{
			tx:         tx,
			inputValue: 1000,
			registry:   reg,
			sigCache:   cache,
			context:    "TEST",
		}
	}

	// P2PK path.
	entry := p2pkEntryForPub(t, SUITE_ID_ML_DSA_87, pub)
	p2pk := p2pkSpendCheck{entry: entry, witness: w, rotation: DefaultRotationProvider{}, sig: sigCtx()}
	if err := validateP2PKSpendAtHeight(p2pk); err != nil {
		t.Fatalf("P2PK first: %v", err)
	}
	if backend.calls != 1 {
		t.Fatalf("P2PK first must execute the backend once: calls=%d", backend.calls)
	}
	if err := validateP2PKSpendAtHeight(p2pk); err != nil {
		t.Fatalf("P2PK repeat: %v", err)
	}
	if backend.calls != 1 {
		t.Fatalf("P2PK repeat must hit: calls=%d", backend.calls)
	}

	// Threshold path (CORE_MULTISIG and CORE_VAULT share it) reuses the same
	// cached tuple: no further backend call.
	threshold := thresholdSigSpendCheck{
		keys:      [][32]byte{keyID},
		threshold: 1,
		witnesses: []WitnessItem{w},
		rotation:  DefaultRotationProvider{},
		sig:       sigCtx(),
	}
	if err := validateThresholdSigSpendAtHeight(threshold); err != nil {
		t.Fatalf("threshold: %v", err)
	}
	if backend.calls != 1 {
		t.Fatalf("threshold path must share the cache: calls=%d", backend.calls)
	}

	// CORE_STEALTH path.
	stealth := coreStealthSpendValidation{
		entry:      UtxoEntry{Value: 1000, CovenantType: COV_TYPE_CORE_STEALTH, CovenantData: stealthCovenantDataForKeyID(keyID)},
		w:          w,
		tx:         tx,
		inputValue: 1000,
		registry:   reg,
		rotation:   DefaultRotationProvider{},
		sigCache:   cache,
	}
	if err := validateCoreStealthSpendAtHeight(stealth); err != nil {
		t.Fatalf("stealth: %v", err)
	}
	if backend.calls != 1 {
		t.Fatalf("stealth path must share the cache: calls=%d", backend.calls)
	}

	// Key-binding mismatch with otherwise cached signature bytes: rejected
	// before verification, no hit, nothing inserted.
	hits, entries := cache.Hits(), cache.Len()
	otherPub, _, _ := liveSigCacheTuple(0x99)
	mismatch := p2pkSpendCheck{
		entry:    p2pkEntryForPub(t, SUITE_ID_ML_DSA_87, otherPub),
		witness:  w,
		rotation: DefaultRotationProvider{},
		sig:      sigCtx(),
	}
	err := validateP2PKSpendAtHeight(mismatch)
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
	if cache.Hits() != hits || cache.Len() != entries || backend.calls != 1 {
		t.Fatalf("key-binding mismatch touched the cache: hits=%d len=%d calls=%d", cache.Hits(), cache.Len(), backend.calls)
	}
}

func TestLiveSigCacheHTLCPathSharesTheOwnerCache(t *testing.T) {
	backend := newLiveSigCacheBackend(t, true, nil)
	cache := NewSigCache(4)

	claimPub, _, claimKeyID, refundKeyID := makeMLKeyMaterial(0xa5)
	preimage := []byte("live-sig-cache-htlc-preimage-ok!")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 100, claimKeyID, refundKeyID)
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	check := htlcSpendCheck{
		entry:       entry,
		pathItem:    WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: claimKeyID[:], Signature: encodeHTLCClaimPayload(preimage)},
		sigItem:     WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: claimPub, Signature: dummyMLSignature(SIGHASH_ALL)},
		tx:          tx,
		inputIndex:  inputIndex,
		inputValue:  inputValue,
		chainID:     chainID,
		blockHeight: 3,
		sigCache:    cache,
	}

	if err := validateHTLCSpendAtHeightWithSigCache(check); err != nil {
		t.Fatalf("HTLC first: %v", err)
	}
	if backend.calls != 1 || cache.Len() != 1 {
		t.Fatalf("HTLC first: calls=%d len=%d, want 1/1", backend.calls, cache.Len())
	}
	if err := validateHTLCSpendAtHeightWithSigCache(check); err != nil {
		t.Fatalf("HTLC repeat: %v", err)
	}
	if backend.calls != 1 || cache.Hits() != 1 {
		t.Fatalf("HTLC repeat must hit: calls=%d hits=%d", backend.calls, cache.Hits())
	}

	// The exported wrapper carries no cache and stays exactly uncached.
	if err := ValidateHTLCSpendAtHeight(check.entry, check.pathItem, check.sigItem, tx, inputIndex, inputValue, chainID, 3, 0, nil, nil, nil); err != nil {
		t.Fatalf("HTLC uncached wrapper: %v", err)
	}
	if backend.calls != 2 {
		t.Fatalf("uncached wrapper must execute the backend: calls=%d, want 2", backend.calls)
	}
}

func TestLiveSigCacheVaultThresholdSiteUsesTheOwnerCache(t *testing.T) {
	backend := newLiveSigCacheBackend(t, true, nil)
	cache := NewSigCache(4)

	pub, cryptoSig, _ := liveSigCacheTuple(0xb6)
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	ctx := &nonCoinbaseApplyContext{
		tx:       tx,
		chainID:  chainID,
		rotation: DefaultRotationProvider{},
		registry: DefaultSuiteRegistry(),
		sigCache: cache,
	}
	ctx.spend.vaultSigKeys = [][32]byte{sha3_256(pub)}
	ctx.spend.vaultSigThreshold = 1
	ctx.spend.vaultSigWitness = []WitnessItem{{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    pub,
		Signature: append(append([]byte(nil), cryptoSig...), SIGHASH_ALL),
	}}
	ctx.spend.vaultSigInputIndex = inputIndex
	ctx.spend.vaultSigInputValue = inputValue

	if err := ctx.validateVaultSpendSignature(); err != nil {
		t.Fatalf("vault first: %v", err)
	}
	if backend.calls != 1 || cache.Len() != 1 {
		t.Fatalf("vault first: calls=%d len=%d, want 1/1", backend.calls, cache.Len())
	}
	if err := ctx.validateVaultSpendSignature(); err != nil {
		t.Fatalf("vault repeat: %v", err)
	}
	if backend.calls != 1 || cache.Hits() != 1 {
		t.Fatalf("vault repeat must hit: calls=%d hits=%d", backend.calls, cache.Hits())
	}
}

// TestCheckParsedTransactionSuiteContextSigCacheSeam drives the exact seam the
// live Mempool uses. It also pins that a caller without a cache — the shape
// every block-validation caller has — never consumes one.
func TestCheckParsedTransactionSuiteContextSigCacheSeam(t *testing.T) {
	backend := newLiveSigCacheBackend(t, true, nil)

	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xc7
	pub, cryptoSig, _ := liveSigCacheTuple(0xc7)
	witness := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    pub,
		Signature: append(append([]byte(nil), cryptoSig...), SIGHASH_ALL),
	}
	txBytes := txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData(), []WitnessItem{witness})
	tx, txid := mustParseTxForUtxo(t, txBytes)
	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: p2pkCovenantDataForPubkey(pub),
		},
	}
	check := func(suite SuiteValidationContext) {
		t.Helper()
		if _, err := CheckParsedTransactionWithOwnedUtxoSetAndSuiteContext(
			txBytes, tx, ParsedTxIDs{TxID: txid}, copyTestUtxoSet(utxos), 0, 0, chainID, suite,
		); err != nil {
			t.Fatalf("CheckParsedTransaction...: %v", err)
		}
	}

	// No cache (block-validation shape): every run executes the backend.
	check(SuiteValidationContext{})
	check(SuiteValidationContext{})
	if backend.calls != 2 {
		t.Fatalf("cacheless seam must verify every run: calls=%d, want 2", backend.calls)
	}

	cache := NewSigCache(4)
	check(SuiteValidationContext{SigCache: cache})
	if backend.calls != 3 || cache.Len() != 1 {
		t.Fatalf("first cached run: calls=%d len=%d, want 3/1", backend.calls, cache.Len())
	}
	check(SuiteValidationContext{SigCache: cache})
	if backend.calls != 3 || cache.Hits() != 1 {
		t.Fatalf("repeat cached run must hit: calls=%d hits=%d", backend.calls, cache.Hits())
	}

	// A cache owned by a different caller shares nothing.
	other := NewSigCache(4)
	check(SuiteValidationContext{SigCache: other})
	if backend.calls != 4 || other.Len() != 1 {
		t.Fatalf("separate owner cache: calls=%d len=%d, want 4/1", backend.calls, other.Len())
	}
}
