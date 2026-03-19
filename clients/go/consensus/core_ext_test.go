package consensus

import (
	"errors"
	"testing"
)

type staticCoreExtProfiles map[uint16]CoreExtProfile

func (m staticCoreExtProfiles) LookupCoreExtProfile(extID uint16, _ uint64) (CoreExtProfile, bool, error) {
	p, ok := m[extID]
	return p, ok, nil
}

func coreExtCovenantData(extID uint16, payload []byte) []byte {
	out := AppendU16le(nil, extID)
	out = AppendCompactSize(out, uint64(len(payload)))
	out = append(out, payload...)
	return out
}

func TestStaticCoreExtProfileProviderEmptyReturnsNil(t *testing.T) {
	provider, err := NewStaticCoreExtProfileProvider(nil)
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider(nil): %v", err)
	}
	if provider != nil {
		t.Fatalf("expected nil provider for empty deployments")
	}
}

func TestStaticCoreExtProfileProviderRejectsDuplicateExtID(t *testing.T) {
	_, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{
		{ExtID: 7, ActivationHeight: 1},
		{ExtID: 7, ActivationHeight: 2},
	})
	if err == nil {
		t.Fatalf("expected duplicate deployment error")
	}
}

func TestStaticCoreExtProfileProviderRejectsEmptyAllowedSuites(t *testing.T) {
	_, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{
		{ExtID: 7, ActivationHeight: 1, AllowedSuites: nil},
	})
	if err == nil {
		t.Fatalf("expected empty allowed suites error")
	}
}

func TestStaticCoreExtProfileProviderLookupRespectsActivationHeight(t *testing.T) {
	verifyFn := func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) {
		return true, nil
	}
	allowed := map[uint8]struct{}{1: {}, 3: {}}
	provider, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{
		{
			ExtID:            7,
			ActivationHeight: 12,
			AllowedSuites:    allowed,
			VerifySigExtFn:   verifyFn,
			BindingDescriptor: []byte{
				0xa1,
			},
			ExtPayloadSchema: []byte{
				0xb2,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}

	if profile, ok, err := provider.LookupCoreExtProfile(7, 11); err != nil {
		t.Fatalf("LookupCoreExtProfile pre-activation: %v", err)
	} else if ok || profile.Active {
		t.Fatalf("profile must be inactive before activation height")
	}

	profile, ok, err := provider.LookupCoreExtProfile(7, 12)
	if err != nil {
		t.Fatalf("LookupCoreExtProfile active: %v", err)
	}
	if !ok || !profile.Active {
		t.Fatalf("expected active profile at activation height")
	}
	if profile.VerifySigExtFn == nil {
		t.Fatalf("missing verify_sig_ext binding")
	}
	if _, has := profile.AllowedSuites[1]; !has {
		t.Fatalf("missing allowed suite 1")
	}
	if _, has := profile.AllowedSuites[3]; !has {
		t.Fatalf("missing allowed suite 3")
	}
	if len(profile.BindingDescriptor) != 1 || profile.BindingDescriptor[0] != 0xa1 {
		t.Fatalf("missing binding descriptor")
	}
	if len(profile.ExtPayloadSchema) != 1 || profile.ExtPayloadSchema[0] != 0xb2 {
		t.Fatalf("missing ext payload schema")
	}

	delete(profile.AllowedSuites, 1)
	profile.BindingDescriptor[0] = 0xff
	profile.ExtPayloadSchema[0] = 0xee
	profile2, ok, err := provider.LookupCoreExtProfile(7, 12)
	if err != nil {
		t.Fatalf("LookupCoreExtProfile second active lookup: %v", err)
	}
	if !ok {
		t.Fatalf("expected active profile on second lookup")
	}
	if _, has := profile2.AllowedSuites[1]; !has {
		t.Fatalf("provider must clone allowed suites per lookup")
	}
	if len(profile2.BindingDescriptor) != 1 || profile2.BindingDescriptor[0] != 0xa1 {
		t.Fatalf("provider must clone binding descriptor per lookup")
	}
	if len(profile2.ExtPayloadSchema) != 1 || profile2.ExtPayloadSchema[0] != 0xb2 {
		t.Fatalf("provider must clone ext payload schema per lookup")
	}
}

func TestStaticCoreExtProfileProviderNilReceiverAndUnknownExtID(t *testing.T) {
	var provider *StaticCoreExtProfileProvider
	if profile, ok, err := provider.LookupCoreExtProfile(7, 12); err != nil {
		t.Fatalf("LookupCoreExtProfile nil receiver: %v", err)
	} else if ok || profile.Active {
		t.Fatalf("nil provider must behave as inactive")
	}

	provider, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 0,
		AllowedSuites:    map[uint8]struct{}{1: {}},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}
	if profile, ok, err := provider.LookupCoreExtProfile(8, 12); err != nil {
		t.Fatalf("LookupCoreExtProfile unknown ext id: %v", err)
	} else if ok || profile.Active {
		t.Fatalf("unknown ext id must behave as inactive")
	}
}

func TestCoreExtProfileSetAnchorChangesWithPayloadSchema(t *testing.T) {
	chainID := [32]byte{0: 0x42}
	base := CoreExtDeploymentProfile{
		ExtID:             7,
		ActivationHeight:  1,
		AllowedSuites:     map[uint8]struct{}{3: {}},
		VerifySigExtFn:    func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) { return true, nil },
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}
	changed := base
	changed.ExtPayloadSchema = []byte{0xb3}

	baseAnchor, err := CoreExtProfileSetAnchorV1(chainID, []CoreExtDeploymentProfile{base})
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1(base): %v", err)
	}
	changedAnchor, err := CoreExtProfileSetAnchorV1(chainID, []CoreExtDeploymentProfile{changed})
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1(changed): %v", err)
	}
	if baseAnchor == changedAnchor {
		t.Fatalf("expected profile set anchor to change when ext_payload_schema changes")
	}
}

func TestCoreExtProfileSetAnchorChangesWithActivationHeight(t *testing.T) {
	chainID := [32]byte{0: 0x42}
	base := CoreExtDeploymentProfile{
		ExtID:             7,
		ActivationHeight:  1,
		AllowedSuites:     map[uint8]struct{}{3: {}},
		VerifySigExtFn:    func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) { return true, nil },
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}
	changed := base
	changed.ActivationHeight = 2

	baseAnchor, err := CoreExtProfileSetAnchorV1(chainID, []CoreExtDeploymentProfile{base})
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1(base): %v", err)
	}
	changedAnchor, err := CoreExtProfileSetAnchorV1(chainID, []CoreExtDeploymentProfile{changed})
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1(changed): %v", err)
	}
	if baseAnchor == changedAnchor {
		t.Fatalf("expected profile set anchor to change when activation_height changes")
	}
}

func TestCoreExtProfileBytesV1RejectsInvalidProfiles(t *testing.T) {
	t.Run("empty allowed suites", func(t *testing.T) {
		_, err := CoreExtProfileBytesV1(CoreExtDeploymentProfile{
			ExtID:            7,
			ActivationHeight: 1,
			ExtPayloadSchema: []byte{0xb2},
		})
		if err == nil || err.Error() != "core_ext profile ext_id=7 must have non-empty allowed suites" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("native binding rejects descriptor", func(t *testing.T) {
		_, err := CoreExtProfileBytesV1(CoreExtDeploymentProfile{
			ExtID:             7,
			ActivationHeight:  1,
			AllowedSuites:     map[uint8]struct{}{3: {}},
			BindingDescriptor: []byte{0xa1},
			ExtPayloadSchema:  []byte{0xb2},
		})
		if err == nil || err.Error() != "core_ext profile ext_id=7 native-only profile must not carry binding_descriptor" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("verify_sig_ext binding requires descriptor", func(t *testing.T) {
		_, err := CoreExtProfileBytesV1(CoreExtDeploymentProfile{
			ExtID:            7,
			ActivationHeight: 1,
			AllowedSuites:    map[uint8]struct{}{3: {}},
			VerifySigExtFn: func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) {
				return true, nil
			},
			ExtPayloadSchema: []byte{0xb2},
		})
		if err == nil || err.Error() != "core_ext profile ext_id=7 verify_sig_ext profile must carry binding_descriptor" {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestParseTx_UnknownSuiteAcceptedAndCharged(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xaa

	sentinelTxBytes := txWithOneInputOneOutputWithWitness(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData(), []WitnessItem{
		// Use canonical HTLC-refund sentinel form to keep witness byte size identical
		// to the "unknown suite" item below (so weight delta is cost-only).
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: make([]byte, 32), Signature: []byte{0x01}},
	})
	sentinelTx, _, _, _, err := ParseTx(sentinelTxBytes)
	if err != nil {
		t.Fatalf("ParseTx(sentinel): %v", err)
	}
	wSentinel, _, _, err := TxWeightAndStats(sentinelTx)
	if err != nil {
		t.Fatalf("TxWeightAndStats(sentinel): %v", err)
	}

	unknownTxBytes := txWithOneInputOneOutputWithWitness(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData(), []WitnessItem{
		{SuiteID: 0x09, Pubkey: make([]byte, 32), Signature: []byte{0x01}},
	})
	unknownTx, _, _, _, err := ParseTx(unknownTxBytes)
	if err != nil {
		t.Fatalf("ParseTx(unknown): %v", err)
	}
	if got := len(unknownTx.Witness); got != 1 || unknownTx.Witness[0].SuiteID != 0x09 {
		t.Fatalf("witness=%v, want suite_id=0x09", unknownTx.Witness)
	}
	wUnknown, _, _, err := TxWeightAndStats(unknownTx)
	if err != nil {
		t.Fatalf("TxWeightAndStats(unknown): %v", err)
	}
	if wUnknown != wSentinel+VERIFY_COST_UNKNOWN_SUITE {
		t.Fatalf("weight_unknown=%d, want %d", wUnknown, wSentinel+VERIFY_COST_UNKNOWN_SUITE)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_PreActiveAnyoneCanSpend_KeylessSentinelOK(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa1

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(1, nil),
		},
	}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 0, 0, chainID); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdate: %v", err)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_PreActiveAnyoneCanSpend_NonKeylessSentinelOK(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa2

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL, Pubkey: make([]byte, 32), Signature: []byte{0x01}}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(1, nil),
		},
	}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 0, 0, chainID); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdate: %v", err)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_DeterministicCovenantDataParseFirst(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa3

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL, Pubkey: make([]byte, 32), Signature: []byte{0x01}}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: []byte{0x01}, // malformed, must map to TX_ERR_COVENANT_TYPE_INVALID before witness checks
		},
	}
	_, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 0, 0, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_RotatedNativeSuiteUsesRegistryPath(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa4

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	sig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	sig[ML_DSA_87_SIG_BYTES] = 0x01
	tx.Witness = []WitnessItem{{
		SuiteID:   0x02,
		Pubkey:    make([]byte, ML_DSA_87_PUBKEY_BYTES),
		Signature: sig,
	}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, nil),
		},
	}
	profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 0,
		AllowedSuites:    map[uint8]struct{}{0x02: {}},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}
	registry := NewSuiteRegistryFromParams([]SuiteParams{{
		SuiteID:    0x02,
		PubkeyLen:  ML_DSA_87_PUBKEY_BYTES,
		SigLen:     ML_DSA_87_SIG_BYTES,
		VerifyCost: VERIFY_COST_ML_DSA_87,
		OpenSSLAlg: "ML-DSA-87",
	}})
	err = nil
	_, _, err = ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext(
		tx,
		txid,
		utxos,
		0,
		0,
		0,
		chainID,
		profiles,
		&mockRotationProvider{h2: 0},
		registry,
	)
	if err == nil {
		t.Fatalf("expected invalid signature error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_ActiveSuiteRulesAndVerifySig(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa4

	kp := mustMLDSA87Keypair(t)

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x01}),
		},
	}

	profiles := staticCoreExtProfiles{
		7: {
			Active: true,
			AllowedSuites: map[uint8]struct{}{
				SUITE_ID_SENTINEL:  {},
				SUITE_ID_ML_DSA_87: {},
			},
		},
	}

	// Sentinel is explicitly forbidden under ACTIVE.
	_, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}

	// Valid ML-DSA signature succeeds under ACTIVE.
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chainID, kp)}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(valid sig): %v", err)
	}

	// Same-length mutated signature must deterministically reject as TX_ERR_SIG_INVALID.
	bad := tx.Witness[0]
	bad.Signature = append([]byte(nil), bad.Signature...)
	bad.Signature[0] ^= 0x01
	tx.Witness = []WitnessItem{bad}
	_, _, err = ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_VerifySigExtErrorMapsToAlgInvalid(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa5

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: 0x09, Pubkey: []byte{0x01}, Signature: []byte{0x02}}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x01}),
		},
	}

	profiles := staticCoreExtProfiles{
		7: {
			Active: true,
			AllowedSuites: map[uint8]struct{}{
				0x09: {},
			},
			VerifySigExtFn: func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) {
				return false, errors.New("unsupported")
			},
		},
	}

	_, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}

func TestHasSuiteExported(t *testing.T) {
	allowed := map[uint8]struct{}{1: {}, 3: {}}
	if !HasSuiteExported(allowed, 1) {
		t.Fatal("expected suite 1 to be allowed")
	}
	if HasSuiteExported(allowed, 2) {
		t.Fatal("expected suite 2 to not be allowed")
	}
	if HasSuiteExported(nil, 1) {
		t.Fatal("expected nil map to return false")
	}
}
