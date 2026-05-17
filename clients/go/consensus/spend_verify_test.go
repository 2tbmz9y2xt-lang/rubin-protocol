package consensus

import (
	"testing"
)

func p2pkEntryForPub(t *testing.T, suiteID uint8, pub []byte) UtxoEntry {
	t.Helper()
	keyID := sha3_256(pub)
	cov := make([]byte, MAX_P2PK_COVENANT_DATA)
	cov[0] = suiteID
	copy(cov[1:33], keyID[:])
	return UtxoEntry{
		Value:             1,
		CovenantType:      COV_TYPE_P2PK,
		CovenantData:      cov,
		CreationHeight:    0,
		CreatedByCoinbase: false,
	}
}

type testSpendSigEnv struct {
	tx          *Tx
	inputIndex  uint32
	inputValue  uint64
	chainID     [32]byte
	blockHeight uint64
	cache       *SighashV1PrehashCache
	rotation    RotationProvider
	registry    *SuiteRegistry
	context     string
}

func testThresholdSigSpendCheck(keys [][32]byte, threshold uint8, ws []WitnessItem, env testSpendSigEnv) thresholdSigSpendCheck {
	return thresholdSigSpendCheck{
		keys:        keys,
		threshold:   threshold,
		witnesses:   ws,
		blockHeight: env.blockHeight,
		rotation:    env.rotation,
		sig: spendSigContext{
			tx:         env.tx,
			inputIndex: env.inputIndex,
			inputValue: env.inputValue,
			chainID:    env.chainID,
			cache:      env.cache,
			registry:   env.registry,
			context:    env.context,
		},
	}
}

func testP2PKSpendCheck(entry UtxoEntry, w WitnessItem, env testSpendSigEnv) p2pkSpendCheck {
	return p2pkSpendCheck{
		entry:       entry,
		witness:     w,
		blockHeight: env.blockHeight,
		rotation:    env.rotation,
		sig: spendSigContext{
			tx:         env.tx,
			inputIndex: env.inputIndex,
			inputValue: env.inputValue,
			chainID:    env.chainID,
			cache:      env.cache,
			registry:   env.registry,
		},
	}
}

func testSpendKeySigContext(env testSpendSigEnv) spendSigContext {
	return spendSigContext{
		tx:         env.tx,
		inputIndex: env.inputIndex,
		inputValue: env.inputValue,
		chainID:    env.chainID,
		cache:      env.cache,
		registry:   env.registry,
		context:    env.context,
	}
}

func TestValidateP2PKSpend_OkAndFailureModes(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	pub := kp.PubkeyBytes()
	tx, inputIndex, inputValue, chainID := testSighashContextTx()

	sig := signDigestWithSighashType(t, kp, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)

	entry := p2pkEntryForPub(t, SUITE_ID_ML_DSA_87, pub)
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig}
	if err := validateP2PKSpend(entry, w, tx, inputIndex, inputValue, chainID, 0); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}

	// suite invalid
	wBadSuite := w
	wBadSuite.SuiteID = 0x03
	if err := validateP2PKSpend(entry, wBadSuite, tx, inputIndex, inputValue, chainID, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got %v", err)
	}

	// covenant_data invalid (len)
	entryBad := entry
	entryBad.CovenantData = entryBad.CovenantData[:32]
	if err := validateP2PKSpend(entryBad, w, tx, inputIndex, inputValue, chainID, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got %v", err)
	}

	// key binding mismatch
	entryKeyMismatch := entry
	entryKeyMismatch.CovenantData = append([]byte(nil), entry.CovenantData...)
	entryKeyMismatch.CovenantData[1] ^= 0x01
	if err := validateP2PKSpend(entryKeyMismatch, w, tx, inputIndex, inputValue, chainID, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_INVALID (binding), got %v", err)
	}

	// signature invalid
	wBadSig := w
	wBadSig.Signature = append([]byte(nil), wBadSig.Signature...)
	wBadSig.Signature[0] ^= 0x01
	if err := validateP2PKSpend(entry, wBadSig, tx, inputIndex, inputValue, chainID, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_INVALID (sig), got %v", err)
	}
}

func TestValidateThresholdSigSpend_MismatchAndThresholdLogic(t *testing.T) {
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	env := testSpendSigEnv{tx: tx, inputIndex: inputIndex, inputValue: inputValue, chainID: chainID, context: "ctx"}

	// witness slot assignment mismatch
	if err := validateThresholdSigSpend(testThresholdSigSpendCheck([][32]byte{}, 0, []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}, env)); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected TX_ERR_PARSE, got %v", err)
	}

	// unknown suite id branch (should be unreachable at wire level, but must be deterministic)
	keys := [][32]byte{hashWithPrefix(0x01)}
	ws := []WitnessItem{{SuiteID: 0x03, Pubkey: []byte{0x01}, Signature: []byte{0x02}}}
	if err := validateThresholdSigSpend(testThresholdSigSpendCheck(keys, 1, ws, env)); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got %v", err)
	}

	// sentinel witnesses -> threshold not met
	keys2 := [][32]byte{hashWithPrefix(0x02), hashWithPrefix(0x03)}
	ws2 := []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}, {SuiteID: SUITE_ID_SENTINEL}}
	if err := validateThresholdSigSpend(testThresholdSigSpendCheck(keys2, 1, ws2, env)); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_INVALID (threshold), got %v", err)
	}
}

func TestValidateThresholdSigSpend_SentinelKeylessEnforcement(t *testing.T) {
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	env := testSpendSigEnv{tx: tx, inputIndex: inputIndex, inputValue: inputValue, chainID: chainID, context: "ctx"}
	keys := [][32]byte{hashWithPrefix(0x01)}

	// SENTINEL with non-empty pubkey must be rejected
	ws1 := []WitnessItem{{SuiteID: SUITE_ID_SENTINEL, Pubkey: []byte{0x01}}}
	if err := validateThresholdSigSpend(testThresholdSigSpendCheck(keys, 1, ws1, env)); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected TX_ERR_PARSE for sentinel with pubkey, got %v", err)
	}

	// SENTINEL with non-empty signature must be rejected
	ws2 := []WitnessItem{{SuiteID: SUITE_ID_SENTINEL, Signature: []byte{0x01}}}
	if err := validateThresholdSigSpend(testThresholdSigSpendCheck(keys, 1, ws2, env)); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected TX_ERR_PARSE for sentinel with signature, got %v", err)
	}

	// SENTINEL with both non-empty must be rejected
	ws3 := []WitnessItem{{SuiteID: SUITE_ID_SENTINEL, Pubkey: []byte{0x01}, Signature: []byte{0x02}}}
	if err := validateThresholdSigSpend(testThresholdSigSpendCheck(keys, 1, ws3, env)); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected TX_ERR_PARSE for sentinel with pubkey+sig, got %v", err)
	}
}

func TestValidateThresholdSigSpend_OkWithOneValidAndOneSentinel(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	pub := kp.PubkeyBytes()
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	env := testSpendSigEnv{tx: tx, inputIndex: inputIndex, inputValue: inputValue, chainID: chainID, context: "ctx"}
	sig := signDigestWithSighashType(t, kp, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)

	key0 := sha3_256(pub)
	keys := [][32]byte{key0, hashWithPrefix(0x99)}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig},
		{SuiteID: SUITE_ID_SENTINEL},
	}

	if err := validateThresholdSigSpend(testThresholdSigSpendCheck(keys, 1, ws, env)); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestExtractSigAndDigest_LegacyWrapper(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	sig := signDigestWithSighashType(t, kp, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
	w := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    kp.PubkeyBytes(),
		Signature: sig,
	}

	cryptoSig, digest, err := extractSigAndDigest(w, tx, inputIndex, inputValue, chainID)
	if err != nil {
		t.Fatalf("extractSigAndDigest: %v", err)
	}
	if len(cryptoSig) != len(sig)-1 {
		t.Fatalf("crypto signature length = %d, want %d", len(cryptoSig), len(sig)-1)
	}
	wantDigest, err := SighashV1DigestWithType(tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
	if err != nil {
		t.Fatalf("SighashV1DigestWithType: %v", err)
	}
	if digest != wantDigest {
		t.Fatalf("digest mismatch")
	}
}

func TestVerifyMLDSAKeyAndSig_LegacyWrapper(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	sig := signDigestWithSighashType(t, kp, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
	pub := kp.PubkeyBytes()
	w := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    pub,
		Signature: sig,
	}

	if err := verifyMLDSAKeyAndSig(w, sha3_256(pub), tx, inputIndex, inputValue, chainID, "ctx"); err != nil {
		t.Fatalf("verifyMLDSAKeyAndSig: %v", err)
	}
}
