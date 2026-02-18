package consensus

import (
	"testing"

	"rubin.dev/node/crypto"
)

type applyTxStubProvider struct{}

func (p applyTxStubProvider) SHA3_256(input []byte) [32]byte {
	return crypto.DevStdCryptoProvider{}.SHA3_256(input)
}

func (p applyTxStubProvider) VerifyMLDSA87(_ []byte, _ []byte, _ [32]byte) bool { return true }
func (p applyTxStubProvider) VerifySLHDSASHAKE_256f(_ []byte, _ []byte, _ [32]byte) bool {
	return true
}

func makeP2PKPrevout(t *testing.T, p crypto.CryptoProvider) TxOutput {
	t.Helper()
	pubkey := make([]byte, ML_DSA_PUBKEY_BYTES)
	keyID := p.SHA3_256(pubkey)
	covenantData := append([]byte{SUITE_ID_ML_DSA}, keyID[:]...)
	return TxOutput{
		Value:        1000,
		CovenantType: CORE_P2PK,
		CovenantData: covenantData,
	}
}

func makeP2PKTx(prevout TxOutPoint, prevoutValue uint64) Tx {
	input := TxInput{
		PrevTxid: prevout.TxID,
		PrevVout: prevout.Vout,
	}
	witness := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA,
		Pubkey:    make([]byte, ML_DSA_PUBKEY_BYTES),
		Signature: make([]byte, ML_DSA_SIG_BYTES),
	}
	output := TxOutput{
		Value:        prevoutValue - 10,
		CovenantType: CORE_P2PK,
		CovenantData: []byte{},
	}
	return Tx{
		Version:  1,
		TxNonce:  1,
		Inputs:   []TxInput{input},
		Outputs:  []TxOutput{output},
		Locktime: 0,
		Witness: WitnessSection{
			Witnesses: []WitnessItem{witness},
		},
	}
}

func TestApplyTxOK(t *testing.T) {
	p := applyTxStubProvider{}
	prevout := TxOutPoint{TxID: [32]byte{}, Vout: 0}
	prevoutData := makeP2PKPrevout(t, p)

	tx := makeP2PKTx(prevout, prevoutData.Value)
	// ensure key id is correct for the witness pubkey
	keyID := p.SHA3_256(make([]byte, ML_DSA_PUBKEY_BYTES))
	tx.Witness.Witnesses[0].Pubkey = make([]byte, ML_DSA_PUBKEY_BYTES)
	covenantData := append([]byte{SUITE_ID_ML_DSA}, keyID[:]...)
	for i := range tx.Outputs {
		tx.Outputs[i].CovenantType = CORE_P2PK
		tx.Outputs[i].CovenantData = covenantData
	}
	prevoutData.CovenantData = covenantData

	utxo := map[TxOutPoint]UtxoEntry{
		prevout: {
			Output: prevoutData,
		},
	}
	chainID := [32]byte{}

	if err := ApplyTx(p, chainID, &tx, utxo, 0, 0, false, false); err != nil {
		t.Fatalf("ApplyTx failed: %v", err)
	}
}

func TestApplyTxMissingUTXO(t *testing.T) {
	p := applyTxStubProvider{}
	tx := Tx{
		Version: 1,
		TxNonce: 1,
		Inputs: []TxInput{
			{
				PrevTxid: [32]byte{},
				PrevVout: 0,
			},
		},
		Outputs:  []TxOutput{},
		Locktime: 0,
		Witness: WitnessSection{
			Witnesses: []WitnessItem{
				{SuiteID: SUITE_ID_ML_DSA, Pubkey: make([]byte, ML_DSA_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_SIG_BYTES)},
			},
		},
	}
	if err := ApplyTx(p, [32]byte{}, &tx, map[TxOutPoint]UtxoEntry{}, 0, 0, false, false); err == nil {
		t.Fatal("expected missing utxo error")
	}
}

func TestApplyTxDuplicatePrevout(t *testing.T) {
	p := applyTxStubProvider{}
	prevout := TxOutPoint{TxID: [32]byte{1}, Vout: 0}
	keyID := p.SHA3_256(make([]byte, ML_DSA_PUBKEY_BYTES))
	prevoutData := TxOutput{
		Value:        200,
		CovenantType: CORE_P2PK,
		CovenantData: append([]byte{SUITE_ID_ML_DSA}, keyID[:]...),
	}

	tx := Tx{
		Version: 1,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevout.TxID, PrevVout: prevout.Vout},
			{PrevTxid: prevout.TxID, PrevVout: prevout.Vout},
		},
		Outputs: []TxOutput{{
			Value:        200,
			CovenantType: CORE_P2PK,
			CovenantData: append([]byte{SUITE_ID_ML_DSA}, keyID[:]...),
		}},
		Locktime: 0,
		Witness: WitnessSection{
			Witnesses: []WitnessItem{
				{SuiteID: SUITE_ID_ML_DSA, Pubkey: make([]byte, ML_DSA_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_SIG_BYTES)},
				{SuiteID: SUITE_ID_ML_DSA, Pubkey: make([]byte, ML_DSA_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_SIG_BYTES)},
			},
		},
	}
	utxo := map[TxOutPoint]UtxoEntry{
		prevout: {
			Output: prevoutData,
		},
	}
	if err := ApplyTx(p, [32]byte{}, &tx, utxo, 0, 0, false, false); err == nil {
		t.Fatal("expected duplicate prevout parse error")
	}
}

func TestApplyTxValueConservation(t *testing.T) {
	p := applyTxStubProvider{}
	prevout := TxOutPoint{TxID: [32]byte{2}, Vout: 0}
	keyID := p.SHA3_256(make([]byte, ML_DSA_PUBKEY_BYTES))
	prevoutData := TxOutput{
		Value:        100,
		CovenantType: CORE_P2PK,
		CovenantData: append([]byte{SUITE_ID_ML_DSA}, keyID[:]...),
	}
	tx := Tx{
		Version: 1,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevout.TxID, PrevVout: prevout.Vout}},
		Outputs: []TxOutput{{
			Value:        101,
			CovenantType: CORE_P2PK,
			CovenantData: append([]byte{SUITE_ID_ML_DSA}, keyID[:]...),
		}},
		Locktime: 0,
		Witness: WitnessSection{
			Witnesses: []WitnessItem{
				{SuiteID: SUITE_ID_ML_DSA, Pubkey: make([]byte, ML_DSA_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_SIG_BYTES)},
			},
		},
	}
	utxo := map[TxOutPoint]UtxoEntry{
		prevout: {
			Output: prevoutData,
		},
	}
	if err := ApplyTx(p, [32]byte{}, &tx, utxo, 0, 0, false, false); err == nil {
		t.Fatal("expected value conservation error")
	}
}

func TestApplyTxInputOutputCountMismatch(t *testing.T) {
	p := applyTxStubProvider{}
	tx := Tx{
		Version: 1,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: [32]byte{}, PrevVout: 0},
		},
		Outputs: []TxOutput{{
			Value:        0,
			CovenantType: CORE_P2PK,
			CovenantData: append([]byte{SUITE_ID_ML_DSA}, make([]byte, 32)...),
		}},
		Locktime: 0,
		Witness: WitnessSection{
			Witnesses: []WitnessItem{},
		},
	}
	err := ApplyTx(p, [32]byte{}, &tx, map[TxOutPoint]UtxoEntry{}, 0, 0, false, false)
	if err == nil {
		t.Fatal("expected parse error due witness count mismatch")
	}
}
