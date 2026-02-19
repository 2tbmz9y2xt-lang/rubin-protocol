package consensus

import (
	"encoding/binary"
	"testing"
)

func makeVaultV1Data(t *testing.T, owner, recovery [32]byte, spendDelay uint64, mode byte, lockValue uint64, useExtended bool) []byte {
	t.Helper()
	if useExtended {
		data := make([]byte, 81)
		copy(data[:32], owner[:])
		binary.LittleEndian.PutUint64(data[32:40], spendDelay)
		data[40] = mode
		binary.LittleEndian.PutUint64(data[41:49], lockValue)
		copy(data[49:81], recovery[:])
		return data
	}
	data := make([]byte, 73)
	copy(data[:32], owner[:])
	data[32] = mode
	binary.LittleEndian.PutUint64(data[33:41], lockValue)
	copy(data[41:73], recovery[:])
	return data
}

func makeP2PKSpendTx(prevTxID [32]byte, prevout TxOutput, inputScriptSig []byte, witnessPub, witnessSig []byte, outputs ...TxOutput) Tx {
	return Tx{
		Version:  1,
		TxNonce:  7,
		Inputs:   []TxInput{{PrevTxid: prevTxID, PrevVout: 0, ScriptSig: inputScriptSig}},
		Outputs:  outputs,
		Locktime: 0,
		Witness: WitnessSection{
			Witnesses: []WitnessItem{{
				SuiteID:   SUITE_ID_ML_DSA,
				Pubkey:    witnessPub,
				Signature: witnessSig,
			}},
		},
	}
}

func validP2PKCovenantData(t *testing.T, p []byte) []byte {
	t.Helper()
	id := mustSHA3ForTest(t, applyTxStubProvider{}, p)
	return append([]byte{SUITE_ID_ML_DSA}, id[:]...)
}

func TestValidateOutputCovenantConstraintsExtended(t *testing.T) {
	p := applyTxStubProvider{}

	t.Run("HTLC_V2 claimKey==refundKey -> TX_ERR_PARSE", func(t *testing.T) {
		key := make([]byte, ML_DSA_PUBKEY_BYTES)
		keyID := mustSHA3ForTest(t, p, key)
		data := make([]byte, 105)
		copy(data[41:73], keyID[:])
		copy(data[73:105], keyID[:])
		err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_HTLC_V2, CovenantData: data})
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse, got %v", err)
		}
	})

	t.Run("VAULT_V1 len=73 OK", func(t *testing.T) {
		if err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_VAULT_V1, CovenantData: make([]byte, 73)}); err != nil {
			t.Fatalf("expected OK, got %v", err)
		}
	})

	t.Run("VAULT_V1 len=81 OK", func(t *testing.T) {
		if err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_VAULT_V1, CovenantData: make([]byte, 81)}); err != nil {
			t.Fatalf("expected OK, got %v", err)
		}
	})

	t.Run("VAULT_V1 len=74 parse", func(t *testing.T) {
		err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_VAULT_V1, CovenantData: make([]byte, 74)})
		if err == nil || err.Error() != "TX_ERR_PARSE" {
			t.Fatalf("expected parse, got %v", err)
		}
	})

	t.Run("CORE_RESERVED_FUTURE -> TX_ERR_COVENANT_TYPE_INVALID", func(t *testing.T) {
		err := validateOutputCovenantConstraints(TxOutput{CovenantType: CORE_RESERVED_FUTURE, CovenantData: []byte{}})
		if err == nil || err.Error() != "TX_ERR_COVENANT_TYPE_INVALID" {
			t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got %v", err)
		}
	})

	t.Run("unknown type -> TX_ERR_COVENANT_TYPE_INVALID", func(t *testing.T) {
		err := validateOutputCovenantConstraints(TxOutput{CovenantType: 0x9999, CovenantData: []byte{}})
		if err == nil || err.Error() != "TX_ERR_COVENANT_TYPE_INVALID" {
			t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got %v", err)
		}
	})

	t.Run("CORE_ANCHOR value!=0 -> TX_ERR_COVENANT_TYPE_INVALID", func(t *testing.T) {
		err := validateOutputCovenantConstraints(TxOutput{
			CovenantType: CORE_ANCHOR,
			Value:        1,
			CovenantData: []byte{1, 2, 3},
		})
		if err == nil || err.Error() != "TX_ERR_COVENANT_TYPE_INVALID" {
			t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got %v", err)
		}
	})

	t.Run("CORE_ANCHOR data=[] -> TX_ERR_COVENANT_TYPE_INVALID", func(t *testing.T) {
		err := validateOutputCovenantConstraints(TxOutput{
			CovenantType: CORE_ANCHOR,
			Value:        0,
			CovenantData: []byte{},
		})
		if err == nil || err.Error() != "TX_ERR_COVENANT_TYPE_INVALID" {
			t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got %v", err)
		}
	})
}

func TestValidateInputAuthorizationExtended(t *testing.T) {
	p := applyTxStubProvider{}

	t.Run("CORE_TIMELOCK_V1 height not met -> TX_ERR_TIMELOCK_NOT_MET", func(t *testing.T) {
		var lockVal [8]byte
		binary.LittleEndian.PutUint64(lockVal[:], 10)
		prev := TxOutput{
			CovenantType: CORE_TIMELOCK_V1,
			CovenantData: append([]byte{TIMELOCK_MODE_HEIGHT}, lockVal[:]...),
		}
		tx := Tx{
			Inputs: []TxInput{{
				PrevTxid: [32]byte{1},
				PrevVout: 0,
			}},
			Witness: WitnessSection{
				Witnesses: []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}},
			},
		}
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, 7, &prev, 0, 9, 0, false, false)
		if err == nil || err.Error() != "TX_ERR_TIMELOCK_NOT_MET" {
			t.Fatalf("expected TX_ERR_TIMELOCK_NOT_MET, got %v", err)
		}
	})

	t.Run("CORE_TIMELOCK_V1 timestamp path", func(t *testing.T) {
		var lockVal [8]byte
		binary.LittleEndian.PutUint64(lockVal[:], 55)
		prev := TxOutput{
			CovenantType: CORE_TIMELOCK_V1,
			CovenantData: append([]byte{TIMELOCK_MODE_TIMESTAMP}, lockVal[:]...),
		}
		tx := Tx{
			Inputs: []TxInput{{
				PrevTxid: [32]byte{2},
				PrevVout: 0,
			}},
			Witness: WitnessSection{
				Witnesses: []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}},
			},
		}
		if err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, 7, &prev, 0, 0, 55, false, false); err != nil {
			t.Fatalf("expected lock satisfied, got %v", err)
		}
	})

	t.Run("CORE_VAULT_V1 owner path -> OK", func(t *testing.T) {
		ownerKey := bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x11)
		ownerID := mustSHA3ForTest(t, p, ownerKey)
		recoveryID := mustSHA3ForTest(t, p, bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x22))
		data := makeVaultV1Data(t, ownerID, recoveryID, 0, TIMELOCK_MODE_HEIGHT, 0, false)
		prev := TxOutput{CovenantType: CORE_VAULT_V1, CovenantData: data}
		prevValue := uint64(100)
		tx := makeP2PKSpendTx([32]byte{3}, prev, nil, ownerKey, make([]byte, ML_DSA_SIG_BYTES), TxOutput{Value: prevValue - 1, CovenantType: CORE_P2PK, CovenantData: append([]byte{SUITE_ID_ML_DSA}, ownerID[:]...)})
		if err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, prevValue, &prev, 0, 10, 0, false, false); err != nil {
			t.Fatalf("expected owner path OK, got %v", err)
		}
	})

	t.Run("CORE_VAULT_V1 recovery path + spend delay", func(t *testing.T) {
		ownerKey := bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x11)
		ownerID := mustSHA3ForTest(t, p, ownerKey)
		recoveryKey := bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x22)
		recoveryID := mustSHA3ForTest(t, p, recoveryKey)
		data := makeVaultV1Data(t, ownerID, recoveryID, 100, TIMELOCK_MODE_HEIGHT, 10, true)
		prev := TxOutput{CovenantType: CORE_VAULT_V1, CovenantData: data}
		tx := makeP2PKSpendTx([32]byte{4}, prev, nil, recoveryKey, make([]byte, ML_DSA_SIG_BYTES), TxOutput{Value: 99, CovenantType: CORE_P2PK, CovenantData: append([]byte{SUITE_ID_ML_DSA}, ownerID[:]...)})
		if err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, 100, &prev, 0, 20, 0, false, false); err != nil {
			t.Fatalf("expected recovery path OK, got %v", err)
		}
	})

	t.Run("CORE_VAULT_V1 spend_delay not executed -> TX_ERR_TIMELOCK_NOT_MET", func(t *testing.T) {
		ownerKey := bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x11)
		ownerID := mustSHA3ForTest(t, p, ownerKey)
		recoveryKey := bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x22)
		recoveryID := mustSHA3ForTest(t, p, recoveryKey)
		data := makeVaultV1Data(t, ownerID, recoveryID, 1000, TIMELOCK_MODE_HEIGHT, 0, true)
		prev := TxOutput{CovenantType: CORE_VAULT_V1, CovenantData: data}
		tx := makeP2PKSpendTx([32]byte{5}, prev, nil, ownerKey, make([]byte, ML_DSA_SIG_BYTES), TxOutput{Value: 1, CovenantType: CORE_P2PK, CovenantData: append([]byte{SUITE_ID_ML_DSA}, ownerID[:]...)})
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, 100, &prev, 0, 5, 0, false, false)
		if err == nil || err.Error() != "TX_ERR_TIMELOCK_NOT_MET" {
			t.Fatalf("expected TX_ERR_TIMELOCK_NOT_MET, got %v", err)
		}
	})

	t.Run("CORE_ANCHOR as input -> TX_ERR_MISSING_UTXO", func(t *testing.T) {
		prev := TxOutput{
			CovenantType: CORE_ANCHOR,
			Value:        0,
			CovenantData: []byte{1, 2, 3},
		}
		witnessPub := bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x11)
		tx := makeP2PKSpendTx([32]byte{6}, prev, nil, witnessPub, make([]byte, ML_DSA_SIG_BYTES),
			TxOutput{
				Value:        10,
				CovenantType: CORE_P2PK,
				CovenantData: validP2PKCovenantData(t, witnessPub),
			})
		err := ValidateInputAuthorization(p, [32]byte{}, &tx, 0, 10, &prev, 0, 10, 0, false, false)
		if err == nil || err.Error() != "TX_ERR_MISSING_UTXO" {
			t.Fatalf("expected TX_ERR_MISSING_UTXO, got %v", err)
		}
	})
}

func TestApplyTxExtended(t *testing.T) {
	p := applyTxStubProvider{}

	t.Run("outputSum > inputSum -> TX_ERR_VALUE_CONSERVATION", func(t *testing.T) {
		witnessKey := bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x11)
		witnessID := mustSHA3ForTest(t, p, witnessKey)
		prevout := TxOutPoint{TxID: [32]byte{1}, Vout: 0}
		utxo := map[TxOutPoint]UtxoEntry{
			prevout: {
				Output: TxOutput{
					Value:        100,
					CovenantType: CORE_P2PK,
					CovenantData: append([]byte{SUITE_ID_ML_DSA}, witnessID[:]...),
				},
				CreatedByCoinbase: false,
			},
		}
		tx := Tx{
			Version: 1,
			TxNonce: 10,
			Inputs:  []TxInput{{PrevTxid: prevout.TxID, PrevVout: 0}},
			Outputs: []TxOutput{
				{Value: 90, CovenantType: CORE_P2PK, CovenantData: append([]byte{SUITE_ID_ML_DSA}, witnessID[:]...)},
				{Value: 20, CovenantType: CORE_P2PK, CovenantData: append([]byte{SUITE_ID_ML_DSA}, witnessID[:]...)},
			},
			Locktime: 0,
			Witness: WitnessSection{
				Witnesses: []WitnessItem{{
					SuiteID:   SUITE_ID_ML_DSA,
					Pubkey:    witnessKey,
					Signature: make([]byte, ML_DSA_SIG_BYTES),
				}},
			},
		}
		err := ApplyTx(p, [32]byte{}, &tx, utxo, 10, 0, false, true)
		if err == nil || err.Error() != "TX_ERR_VALUE_CONSERVATION" {
			t.Fatalf("expected TX_ERR_VALUE_CONSERVATION, got %v", err)
		}
	})

	t.Run("missing utxo -> TX_ERR_MISSING_UTXO", func(t *testing.T) {
		witnessPub := bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x22)
		witnessData := validP2PKCovenantData(t, witnessPub)
		tx := Tx{
			Version:  1,
			TxNonce:  11,
			Inputs:   []TxInput{{PrevTxid: [32]byte{2}, PrevVout: 1}},
			Outputs:  []TxOutput{{Value: 0, CovenantType: CORE_P2PK, CovenantData: witnessData}},
			Witness:  WitnessSection{Witnesses: []WitnessItem{{SuiteID: SUITE_ID_ML_DSA, Pubkey: witnessPub, Signature: make([]byte, ML_DSA_SIG_BYTES)}}},
			Locktime: 0,
		}
		err := ApplyTx(p, [32]byte{}, &tx, map[TxOutPoint]UtxoEntry{}, 1, 0, false, true)
		if err == nil || err.Error() != "TX_ERR_MISSING_UTXO" {
			t.Fatalf("expected TX_ERR_MISSING_UTXO, got %v", err)
		}
	})

	t.Run("coinbase maturity not executed -> TX_ERR_COINBASE_IMMATURE", func(t *testing.T) {
		witnessKey := bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x11)
		witnessID := mustSHA3ForTest(t, p, witnessKey)
		prevout := TxOutPoint{TxID: [32]byte{3}, Vout: 0}
		utxo := map[TxOutPoint]UtxoEntry{
			prevout: {
				Output: TxOutput{
					Value:        1000,
					CovenantType: CORE_P2PK,
					CovenantData: append([]byte{SUITE_ID_ML_DSA}, witnessID[:]...),
				},
				CreationHeight:    0,
				CreatedByCoinbase: true,
			},
		}
		tx := makeP2PKSpendTx(prevout.TxID, utxo[prevout].Output, nil, witnessKey, make([]byte, ML_DSA_SIG_BYTES), TxOutput{Value: 900, CovenantType: CORE_P2PK, CovenantData: append([]byte{SUITE_ID_ML_DSA}, witnessID[:]...)})
		tx.Inputs[0].PrevVout = 0
		err := ApplyTx(p, [32]byte{}, &tx, utxo, 50, 0, false, true)
		if err == nil || err.Error() != "TX_ERR_COINBASE_IMMATURE" {
			t.Fatalf("expected TX_ERR_COINBASE_IMMATURE, got %v", err)
		}
	})

	t.Run("ApplyTx: ANCHOR output в не-coinbase tx", func(t *testing.T) {
		witnessKey := bytesRepeat(ML_DSA_PUBKEY_BYTES, 0x11)
		witnessID := mustSHA3ForTest(t, p, witnessKey)
		prevout := TxOutPoint{TxID: [32]byte{4}, Vout: 0}
		utxo := map[TxOutPoint]UtxoEntry{
			prevout: {
				Output: TxOutput{
					Value:        100,
					CovenantType: CORE_P2PK,
					CovenantData: append([]byte{SUITE_ID_ML_DSA}, witnessID[:]...),
				},
			},
		}
		tx := makeP2PKSpendTx(prevout.TxID, utxo[prevout].Output, nil, witnessKey, make([]byte, ML_DSA_SIG_BYTES),
			TxOutput{
				Value:        0,
				CovenantType: CORE_ANCHOR,
				CovenantData: []byte{1, 2, 3, 4},
			},
		)
		err := ApplyTx(p, [32]byte{}, &tx, utxo, 1, 0, false, true)
		if err != nil {
			t.Fatalf("expected anchor in non-coinbase tx to pass validation, got %v", err)
		}
	})
}

func bytesRepeat(size int, b byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = b
	}
	return out
}
