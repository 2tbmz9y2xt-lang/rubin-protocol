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

func TestValidateP2PKSpend_OkAndFailureModes(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	pub := kp.PubkeyBytes()

	digest := sha3_256([]byte("x"))
	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	entry := p2pkEntryForPub(t, SUITE_ID_ML_DSA_87, pub)
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig}
	if err := validateP2PKSpend(entry, w, digest, 0); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}

	// suite invalid
	wBadSuite := w
	wBadSuite.SuiteID = 0x03
	if err := validateP2PKSpend(entry, wBadSuite, digest, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got %v", err)
	}

	// SLH suite inactive
	wSLH := w
	wSLH.SuiteID = SUITE_ID_SLH_DSA_SHAKE_256F
	if err := validateP2PKSpend(entry, wSLH, digest, SLH_DSA_ACTIVATION_HEIGHT-1); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID (inactive), got %v", err)
	}

	// covenant_data invalid (len)
	entryBad := entry
	entryBad.CovenantData = entryBad.CovenantData[:32]
	if err := validateP2PKSpend(entryBad, w, digest, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got %v", err)
	}

	// key binding mismatch
	entryKeyMismatch := entry
	entryKeyMismatch.CovenantData = append([]byte(nil), entry.CovenantData...)
	entryKeyMismatch.CovenantData[1] ^= 0x01
	if err := validateP2PKSpend(entryKeyMismatch, w, digest, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_INVALID (binding), got %v", err)
	}

	// signature invalid
	wBadSig := w
	wBadSig.Signature = append([]byte(nil), wBadSig.Signature...)
	wBadSig.Signature[0] ^= 0x01
	if err := validateP2PKSpend(entry, wBadSig, digest, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_INVALID (sig), got %v", err)
	}

	// SLH active + bad pubkey length → TX_ERR_SIG_NONCANONICAL
	wSLHBadPub := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: []byte{0x01}, Signature: []byte{0x01}}
	if err := validateP2PKSpend(entry, wSLHBadPub, digest, SLH_DSA_ACTIVATION_HEIGHT); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("expected TX_ERR_SIG_NONCANONICAL (SLH bad pubkey len), got %v", err)
	}

	// SLH active + empty signature → TX_ERR_SIG_NONCANONICAL
	wSLHEmptySig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES), Signature: nil}
	if err := validateP2PKSpend(entry, wSLHEmptySig, digest, SLH_DSA_ACTIVATION_HEIGHT); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("expected TX_ERR_SIG_NONCANONICAL (SLH empty sig), got %v", err)
	}
}

func TestValidateThresholdSigSpend_MismatchAndThresholdLogic(t *testing.T) {
	// witness slot assignment mismatch
	if err := validateThresholdSigSpend([][32]byte{}, 0, []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}, [32]byte{}, 0, "ctx"); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected TX_ERR_PARSE, got %v", err)
	}

	// unknown suite id branch (should be unreachable at wire level, but must be deterministic)
	keys := [][32]byte{hashWithPrefix(0x01)}
	ws := []WitnessItem{{SuiteID: 0x03, Pubkey: []byte{0x01}, Signature: []byte{0x02}}}
	if err := validateThresholdSigSpend(keys, 1, ws, [32]byte{}, 0, "ctx"); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got %v", err)
	}

	// sentinel witnesses -> threshold not met
	keys2 := [][32]byte{hashWithPrefix(0x02), hashWithPrefix(0x03)}
	ws2 := []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}, {SuiteID: SUITE_ID_SENTINEL}}
	if err := validateThresholdSigSpend(keys2, 1, ws2, [32]byte{}, 0, "ctx"); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_INVALID (threshold), got %v", err)
	}
}

func TestValidateThresholdSigSpend_SLHPaths(t *testing.T) {
	keys := [][32]byte{{0x01}}

	// SLH inactive at h-1 → TX_ERR_SIG_ALG_INVALID
	wsInactive := []WitnessItem{{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: []byte{0x01}, Signature: []byte{0x01}}}
	if err := validateThresholdSigSpend(keys, 1, wsInactive, [32]byte{}, SLH_DSA_ACTIVATION_HEIGHT-1, "ctx"); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID (SLH inactive), got %v", err)
	}

	// SLH active + bad pubkey length → TX_ERR_SIG_NONCANONICAL
	wsNoncanon := []WitnessItem{{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: []byte{0x01}, Signature: []byte{0x01}}}
	if err := validateThresholdSigSpend(keys, 1, wsNoncanon, [32]byte{}, SLH_DSA_ACTIVATION_HEIGHT, "ctx"); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("expected TX_ERR_SIG_NONCANONICAL (SLH noncanon), got %v", err)
	}
}

func TestValidateThresholdSigSpend_OkWithOneValidAndOneSentinel(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	pub := kp.PubkeyBytes()
	digest := sha3_256([]byte("y"))

	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	key0 := sha3_256(pub)
	keys := [][32]byte{key0, hashWithPrefix(0x99)}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig},
		{SuiteID: SUITE_ID_SENTINEL},
	}

	if err := validateThresholdSigSpend(keys, 1, ws, digest, 0, "ctx"); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}
