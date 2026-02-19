package consensus

import (
	"bytes"
	"encoding/binary"
	"testing"

	"rubin.dev/node/crypto"
)

func makeHTLCV2CovenantData(
	t *testing.T,
	p crypto.CryptoProvider,
	claimPub,
	refundPub []byte,
	preimage []byte,
	lockMode byte,
	lockValue uint64,
) []byte {
	t.Helper()

	hash := mustSHA3_256(t, p, preimage)
	claimKeyID := mustSHA3_256(t, p, claimPub)
	refundKeyID := mustSHA3_256(t, p, refundPub)

	covenant := make([]byte, 105)
	copy(covenant[:32], hash[:])
	covenant[32] = lockMode
	binary.LittleEndian.PutUint64(covenant[33:41], lockValue)
	copy(covenant[41:73], claimKeyID[:])
	copy(covenant[73:105], refundKeyID[:])
	return covenant
}

func makeHTLCV2Anchor(t *testing.T, preimage []byte) TxOutput {
	t.Helper()
	if len(preimage) != 32 {
		t.Fatalf("preimage must be 32 bytes, got %d", len(preimage))
	}
	covenantData := make([]byte, 54)
	copy(covenantData, []byte("RUBINv1-htlc-preimage/"))
	copy(covenantData[22:], preimage)
	return TxOutput{
		Value:        0,
		CovenantType: CORE_ANCHOR,
		CovenantData: covenantData,
	}
}

func makeHTLCV2Tx(
	t *testing.T,
	inputScriptSig []byte,
	witnessPub []byte,
	witnessSig []byte,
	outputs ...TxOutput,
) Tx {
	t.Helper()
	return Tx{
		Inputs: []TxInput{
			{PrevTxid: [32]byte{}, PrevVout: 0, ScriptSig: inputScriptSig},
		},
		Witness: WitnessSection{
			Witnesses: []WitnessItem{
				{
					SuiteID:   SUITE_ID_ML_DSA,
					Pubkey:    witnessPub,
					Signature: witnessSig,
				},
			},
		},
		Outputs: outputs,
	}
}

func TestSatisfyLock(t *testing.T) {
	t.Run("height met", func(t *testing.T) {
		if err := satisfyLock(TIMELOCK_MODE_HEIGHT, 10, 10, 0); err != nil {
			t.Fatalf("expected height lock to pass, got %v", err)
		}
	})

	t.Run("height not met", func(t *testing.T) {
		err := satisfyLock(TIMELOCK_MODE_HEIGHT, 10, 9, 0)
		if err == nil || err.Error() != "TX_ERR_TIMELOCK_NOT_MET" {
			t.Fatalf("expected TIMLOCK_NOT_MET, got %v", err)
		}
	})

	t.Run("timestamp met", func(t *testing.T) {
		if err := satisfyLock(TIMELOCK_MODE_TIMESTAMP, 10, 0, 10); err != nil {
			t.Fatalf("expected timestamp lock to pass, got %v", err)
		}
	})

	t.Run("timestamp not met", func(t *testing.T) {
		err := satisfyLock(TIMELOCK_MODE_TIMESTAMP, 10, 0, 9)
		if err == nil || err.Error() != "TX_ERR_TIMELOCK_NOT_MET" {
			t.Fatalf("expected TIMLOCK_NOT_MET, got %v", err)
		}
	})

	t.Run("bad lock mode", func(t *testing.T) {
		err := satisfyLock(0xFF, 10, 0, 0)
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse error, got %v", err)
		}
	})
}

func TestValidateHTLCScriptSigLen(t *testing.T) {
	t.Run("zero ok", func(t *testing.T) {
		if err := validateHTLCScriptSigLen(0); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	t.Run("hash path ok", func(t *testing.T) {
		if err := validateHTLCScriptSigLen(32); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	t.Run("parse", func(t *testing.T) {
		err := validateHTLCScriptSigLen(31)
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse error, got %v", err)
		}
	})
}

func TestCheckWitnessFormat(t *testing.T) {
	validPub := make([]byte, ML_DSA_PUBKEY_BYTES)
	validSig := make([]byte, ML_DSA_SIG_BYTES)
	slhPub := make([]byte, SLH_DSA_PUBKEY_BYTES)
	slhSig := make([]byte, 128)

	t.Run("ml-dsa ok", func(t *testing.T) {
		item := WitnessItem{SuiteID: SUITE_ID_ML_DSA, Pubkey: validPub, Signature: validSig}
		if err := checkWitnessFormat(item, false); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	t.Run("ml-dsa bad pubkey len", func(t *testing.T) {
		item := WitnessItem{SuiteID: SUITE_ID_ML_DSA, Pubkey: validPub[:10], Signature: validSig}
		err := checkWitnessFormat(item, false)
		if err == nil || err.Error() != "TX_ERR_SIG_NONCANONICAL" {
			t.Fatalf("expected sig noncanonical, got %v", err)
		}
	})
	t.Run("ml-dsa bad sig len", func(t *testing.T) {
		item := WitnessItem{SuiteID: SUITE_ID_ML_DSA, Pubkey: validPub, Signature: validSig[:10]}
		err := checkWitnessFormat(item, false)
		if err == nil || err.Error() != "TX_ERR_SIG_NONCANONICAL" {
			t.Fatalf("expected sig noncanonical, got %v", err)
		}
	})
	t.Run("sentinel ok", func(t *testing.T) {
		if err := checkWitnessFormat(WitnessItem{SuiteID: SUITE_ID_SENTINEL}, false); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	t.Run("sentinel parse", func(t *testing.T) {
		item := WitnessItem{
			SuiteID:   SUITE_ID_SENTINEL,
			Pubkey:    []byte{1},
			Signature: []byte{2},
		}
		err := checkWitnessFormat(item, false)
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse error, got %v", err)
		}
	})
	t.Run("slh inactive", func(t *testing.T) {
		item := WitnessItem{SuiteID: SUITE_ID_SLH_DSA, Pubkey: slhPub, Signature: slhSig}
		err := checkWitnessFormat(item, false)
		if err == nil || err.Error() != "TX_ERR_DEPLOYMENT_INACTIVE" {
			t.Fatalf("expected deployment inactive, got %v", err)
		}
	})
	t.Run("slh active ok", func(t *testing.T) {
		item := WitnessItem{SuiteID: SUITE_ID_SLH_DSA, Pubkey: slhPub, Signature: slhSig}
		if err := checkWitnessFormat(item, true); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	t.Run("unknown suite id", func(t *testing.T) {
		item := WitnessItem{SuiteID: byte(0x99), Pubkey: []byte{1}, Signature: []byte{2}}
		err := checkWitnessFormat(item, false)
		if err == nil || err.Error() != "TX_ERR_SIG_ALG_INVALID" {
			t.Fatalf("expected sig alg invalid, got %v", err)
		}
	})
}

func TestValidateOutputCovenantConstraints(t *testing.T) {
	p := applyTxStubProvider{}

	validHTLCv1 := make([]byte, 105)
	validHTLCv2 := make([]byte, 105)
	copy(validHTLCv2, validHTLCv1)
	validKeyA := bytes.Repeat([]byte{0x11}, ML_DSA_PUBKEY_BYTES)
	validKeyB := bytes.Repeat([]byte{0x22}, ML_DSA_PUBKEY_BYTES)
	keyAID := mustSHA3_256(t, p, validKeyA)
	keyBID := mustSHA3_256(t, p, validKeyB)
	copy(validHTLCv1[41:73], keyAID[:])
	copy(validHTLCv1[73:105], keyBID[:])
	copy(validHTLCv2[41:73], keyAID[:])
	copy(validHTLCv2[73:105], keyBID[:])

	t.Run("p2pk ok", func(t *testing.T) {
		if err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_P2PK, CovenantData: make([]byte, 33)}); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	t.Run("p2pk short covenant data parse", func(t *testing.T) {
		err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_P2PK, CovenantData: make([]byte, 32)})
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse error, got %v", err)
		}
	})
	t.Run("htlc_v1 ok", func(t *testing.T) {
		if err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_HTLC_V1, CovenantData: validHTLCv1}); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	t.Run("htlc_v1 short covenant data parse", func(t *testing.T) {
		err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_HTLC_V1, CovenantData: make([]byte, 50)})
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse error, got %v", err)
		}
	})
	t.Run("htlc_v2 ok", func(t *testing.T) {
		if err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_HTLC_V2, CovenantData: validHTLCv2}); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	t.Run("htlc_v2 short covenant data parse", func(t *testing.T) {
		err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_HTLC_V2, CovenantData: make([]byte, 50)})
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse error, got %v", err)
		}
	})
	t.Run("htlc_v2 equal keys", func(t *testing.T) {
		dupKey := make([]byte, 105)
		copy(dupKey, validHTLCv2)
		copy(dupKey[41:73], keyAID[:])
		copy(dupKey[73:105], keyAID[:])
		err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_HTLC_V2, CovenantData: dupKey})
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse error, got %v", err)
		}
	})
}

func TestValidateInputAuthorizationHTLCV2(t *testing.T) {
	p := applyTxStubProvider{}
	claimPub := make([]byte, ML_DSA_PUBKEY_BYTES)
	refundPub := make([]byte, ML_DSA_PUBKEY_BYTES)
	for i := range claimPub {
		claimPub[i] = 0x11
		refundPub[i] = 0x22
	}
	claimSig := make([]byte, ML_DSA_SIG_BYTES)
	refundSig := make([]byte, ML_DSA_SIG_BYTES)
	preimage := bytes.Repeat([]byte{0x77}, 32)
	covenant := makeHTLCV2CovenantData(t, p, claimPub, refundPub, preimage, TIMELOCK_MODE_HEIGHT, 100)
	prevout := TxOutput{Value: 1_000, CovenantType: CORE_HTLC_V2, CovenantData: covenant}

	t.Run("inactive tx is deployment inactive", func(t *testing.T) {
		tx := makeHTLCV2Tx(t, []byte{0x01}, claimPub, claimSig, makeHTLCV2Anchor(t, preimage))
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, prevout.Value, &prevout, 0, 0, 0, false, false)
		if err == nil || err.Error() != "TX_ERR_DEPLOYMENT_INACTIVE" {
			t.Fatalf("expected deployment inactive, got %v", err)
		}
	})

	t.Run("active but non-empty scriptsig parse", func(t *testing.T) {
		tx := makeHTLCV2Tx(t, []byte{0x01}, claimPub, claimSig, makeHTLCV2Anchor(t, preimage))
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, prevout.Value, &prevout, 0, 0, 0, false, true)
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse, got %v", err)
		}
	})

	t.Run("active but sentinel suite id invalid", func(t *testing.T) {
		tx := makeHTLCV2Tx(t, nil, claimPub, claimSig, makeHTLCV2Anchor(t, preimage))
		tx.Witness.Witnesses[0].SuiteID = SUITE_ID_SENTINEL
		tx.Witness.Witnesses[0].Pubkey = nil
		tx.Witness.Witnesses[0].Signature = nil
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, prevout.Value, &prevout, 0, 0, 0, false, true)
		if err == nil || err.Error() != "TX_ERR_SIG_ALG_INVALID" {
			t.Fatalf("expected sig alg invalid, got %v", err)
		}
	})

	t.Run("active claim path with one matching anchor", func(t *testing.T) {
		tx := makeHTLCV2Tx(t, nil, claimPub, claimSig, makeHTLCV2Anchor(t, preimage))
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, prevout.Value, &prevout, 0, 0, 0, false, true)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})

	t.Run("active refund path no anchors", func(t *testing.T) {
		tx := makeHTLCV2Tx(t, nil, refundPub, refundSig)
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, prevout.Value, &prevout, 0, 150, 0, false, true)
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})

	t.Run("active refund timelock not met", func(t *testing.T) {
		tx := makeHTLCV2Tx(t, nil, refundPub, refundSig)
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, prevout.Value, &prevout, 0, 50, 0, false, true)
		if err == nil || err.Error() != "TX_ERR_TIMELOCK_NOT_MET" {
			t.Fatalf("expected timelock not met, got %v", err)
		}
	})

	t.Run("active claim hash mismatch", func(t *testing.T) {
		badPreimage := bytes.Repeat([]byte{0x66}, 32)
		tx := makeHTLCV2Tx(t, nil, claimPub, claimSig, makeHTLCV2Anchor(t, badPreimage))
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, prevout.Value, &prevout, 0, 0, 0, false, true)
		if err == nil || err.Error() != "TX_ERR_SIG_INVALID" {
			t.Fatalf("expected sig invalid, got %v", err)
		}
	})

	t.Run("active refund duplicate anchors parse", func(t *testing.T) {
		tx := makeHTLCV2Tx(t, nil, refundPub, refundSig, makeHTLCV2Anchor(t, preimage), makeHTLCV2Anchor(t, preimage))
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, prevout.Value, &prevout, 0, 150, 0, false, true)
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse, got %v", err)
		}
	})
}
