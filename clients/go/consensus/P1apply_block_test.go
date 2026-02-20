package consensus

import (
	"bytes"
	"encoding/binary"
	"testing"

	"rubin.dev/node/crypto"
)

func repeatByte(value byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = value
	}
	return b
}

func mustSHA3ForTest(t *testing.T, p crypto.CryptoProvider, input []byte) [32]byte {
	t.Helper()
	out, err := p.SHA3_256(input)
	if err != nil {
		t.Fatalf("SHA3_256 failed: %v", err)
	}
	return out
}

func makeP2PKOutputForKeyID(keyID [32]byte, value uint64) TxOutput {
	covenantData := make([]byte, 33)
	covenantData[0] = SUITE_ID_ML_DSA
	copy(covenantData[1:], keyID[:])
	return TxOutput{
		Value:        value,
		CovenantType: CORE_P2PK,
		CovenantData: covenantData,
	}
}

func sha3NoErr(p crypto.CryptoProvider, input []byte) [32]byte {
	out, err := p.SHA3_256(input)
	if err != nil {
		panic(err)
	}
	return out
}

func makeApplyCoinbaseTx(height uint64, outputs []TxOutput) Tx {
	if len(outputs) == 0 {
		outputs = []TxOutput{
			{
				Value:        0,
				CovenantType: CORE_P2PK,
				CovenantData: make([]byte, 33),
			},
		}
	}
	return Tx{
		Version: 1,
		TxNonce: 0,
		Inputs: []TxInput{
			{
				PrevTxid:  [32]byte{},
				PrevVout:  TX_COINBASE_PREVOUT_VOUT,
				Sequence:  TX_COINBASE_PREVOUT_VOUT,
				ScriptSig: nil,
			},
		},
		Outputs:  outputs,
		Locktime: uint32(height),
		Witness:  WitnessSection{},
	}
}

func makeHTLCV1RefundCovenant(refundKeyID [32]byte) TxOutput {
	data := make([]byte, 105)
	data[32] = TIMELOCK_MODE_HEIGHT
	binary.LittleEndian.PutUint64(data[33:41], 1)
	copy(data[41:73], make([]byte, 32))
	copy(data[73:105], refundKeyID[:])
	return TxOutput{
		CovenantType: CORE_HTLC_V1,
		Value:        10,
		CovenantData: data,
	}
}

func makeHTLCSpendBundle(
	p crypto.CryptoProvider,
	inputCount int,
	chainHeight uint64,
) (Tx, map[TxOutPoint]UtxoEntry) {
	witnessPub := repeatByte(0x11, ML_DSA_PUBKEY_BYTES)
	refundID := sha3NoErr(p, witnessPub)
	covenant := makeHTLCV1RefundCovenant(refundID)

	utxo := make(map[TxOutPoint]UtxoEntry, inputCount)
	var totalIn uint64
	inputs := make([]TxInput, 0, inputCount)
	witnesses := make([]WitnessItem, 0, inputCount)
	for i := 0; i < inputCount; i++ {
		point := TxOutPoint{
			TxID: [32]byte{byte(i)},
			Vout: 0,
		}
		utxo[point] = UtxoEntry{
			Output:            covenant,
			CreationHeight:    0,
			CreatedByCoinbase: false,
		}
		totalIn += covenant.Value

		inputs = append(inputs, TxInput{
			PrevTxid:  point.TxID,
			PrevVout:  point.Vout,
			ScriptSig: nil,
			Sequence:  1,
		})
		witnesses = append(witnesses, WitnessItem{
			SuiteID:   SUITE_ID_ML_DSA,
			Pubkey:    append([]byte(nil), witnessPub...),
			Signature: make([]byte, ML_DSA_SIG_BYTES),
		})
	}

	return Tx{
		Version: 1,
		TxNonce: 1,
		Inputs:  inputs,
		Outputs: []TxOutput{
			makeP2PKOutputForKeyID(refundID, totalIn-1),
		},
		Locktime: uint32(chainHeight),
		Witness: WitnessSection{
			Witnesses: witnesses,
		},
	}, utxo
}

func makeApplyBlock(height uint64, ancestor BlockHeader, ts uint64, txs []Tx) Block {
	header := BlockHeader{
		Version:       1,
		Timestamp:     ts,
		Target:        ancestor.Target,
		Nonce:         1,
		MerkleRoot:    [32]byte{},
		PrevBlockHash: [32]byte{},
	}
	if height > 0 {
		parentHash, _ := BlockHeaderHash(applyTxStubProvider{}, ancestor)
		header.PrevBlockHash = parentHash
	}
	if len(txs) > 0 {
		ptrs := make([]*Tx, len(txs))
		for i := range txs {
			ptrs[i] = &txs[i]
		}
		header.MerkleRoot, _ = merkleRootTxIDs(applyTxStubProvider{}, ptrs)
	}
	return Block{Header: header, Transactions: txs}
}

func makeParentHeader(target [32]byte, ts uint64) BlockHeader {
	return BlockHeader{
		Version:       1,
		PrevBlockHash: [32]byte{},
		MerkleRoot:    [32]byte{},
		Timestamp:     ts,
		Target:        target,
		Nonce:         7,
	}
}

func TestApplyBlock(t *testing.T) {
	p := applyTxStubProvider{}
	key := mustSHA3ForTest(t, p, repeatByte(0x11, ML_DSA_PUBKEY_BYTES))
	cbOut := makeP2PKOutputForKeyID(key, 0)

	t.Run("минимальный valid block (coinbase только)", func(t *testing.T) {
		parent := makeParentHeader([32]byte{0xff}, 1)
		cb := makeApplyCoinbaseTx(0, []TxOutput{cbOut})
		block := makeApplyBlock(0, parent, 2, []Tx{cb})
		utxo := map[TxOutPoint]UtxoEntry{}
		if err := ApplyBlock(p, [32]byte{}, &block, utxo, BlockValidationContext{Height: 0}); err != nil {
			t.Fatalf("expected valid block, got %v", err)
		}
		if len(utxo) != 1 {
			t.Fatalf("expected 1 utxo, got %d", len(utxo))
		}
	})

	t.Run("merkle root invalid", func(t *testing.T) {
		parent := makeParentHeader([32]byte{0xff}, 10)
		cb := makeApplyCoinbaseTx(1, []TxOutput{cbOut})
		block := makeApplyBlock(1, parent, 11, []Tx{cb})
		block.Header.MerkleRoot[0] ^= 0x01
		err := ApplyBlock(p, [32]byte{}, &block, map[TxOutPoint]UtxoEntry{}, BlockValidationContext{Height: 1, AncestorHeaders: []BlockHeader{parent}})
		if err == nil || err.Error() != BLOCK_ERR_MERKLE_INVALID {
			t.Fatalf("expected BLOCK_ERR_MERKLE_INVALID, got %v", err)
		}
	})

	t.Run("pow invalid", func(t *testing.T) {
		parent := makeParentHeader([32]byte{}, 10)
		cb := makeApplyCoinbaseTx(1, []TxOutput{cbOut})
		block := makeApplyBlock(1, parent, 11, []Tx{cb})
		block.Header.Target = [32]byte{}
		err := ApplyBlock(p, [32]byte{}, &block, map[TxOutPoint]UtxoEntry{}, BlockValidationContext{Height: 1, AncestorHeaders: []BlockHeader{parent}})
		if err == nil || err.Error() != BLOCK_ERR_POW_INVALID {
			t.Fatalf("expected BLOCK_ERR_POW_INVALID, got %v", err)
		}
	})

	t.Run("timestamp old", func(t *testing.T) {
		parent := makeParentHeader([32]byte{0xff}, 10)
		cb := makeApplyCoinbaseTx(1, []TxOutput{cbOut})
		block := makeApplyBlock(1, parent, 10, []Tx{cb})
		err := ApplyBlock(p, [32]byte{}, &block, map[TxOutPoint]UtxoEntry{}, BlockValidationContext{Height: 1, AncestorHeaders: []BlockHeader{parent}})
		if err == nil || err.Error() != BLOCK_ERR_TIMESTAMP_OLD {
			t.Fatalf("expected BLOCK_ERR_TIMESTAMP_OLD, got %v", err)
		}
	})

	t.Run("timestamp future", func(t *testing.T) {
		parent := makeParentHeader([32]byte{0xff}, 100)
		cb := makeApplyCoinbaseTx(1, []TxOutput{cbOut})
		block := makeApplyBlock(1, parent, 100+MAX_FUTURE_DRIFT+1, []Tx{cb})
		err := ApplyBlock(p, [32]byte{}, &block, map[TxOutPoint]UtxoEntry{}, BlockValidationContext{
			Height:          1,
			AncestorHeaders: []BlockHeader{parent},
			LocalTimeSet:    true,
			LocalTime:       100,
		})
		if err == nil || err.Error() != BLOCK_ERR_TIMESTAMP_FUTURE {
			t.Fatalf("expected BLOCK_ERR_TIMESTAMP_FUTURE, got %v", err)
		}
	})

	t.Run("weight exceeded", func(t *testing.T) {
		parent := makeParentHeader([32]byte{0xff}, 10)
		heavyTx, utxo := makeHTLCSpendBundle(p, MAX_TX_INPUTS, 1)
		cb := makeApplyCoinbaseTx(1, []TxOutput{cbOut})
		block := makeApplyBlock(1, parent, 11, []Tx{cb, heavyTx})
		err := ApplyBlock(p, [32]byte{}, &block, utxo, BlockValidationContext{Height: 1, AncestorHeaders: []BlockHeader{parent}})
		if err == nil || err.Error() != TX_ERR_WITNESS_OVERFLOW {
			t.Fatalf("expected TX_ERR_WITNESS_OVERFLOW, got %v", err)
		}
	})

	t.Run("subsidy exceeded", func(t *testing.T) {
		parent := makeParentHeader([32]byte{0xff}, 10)
		cb := makeApplyCoinbaseTx(1, []TxOutput{makeP2PKOutputForKeyID(key, 10_000_000_000_000)})
		block := makeApplyBlock(1, parent, 11, []Tx{cb})
		err := ApplyBlock(p, [32]byte{}, &block, map[TxOutPoint]UtxoEntry{}, BlockValidationContext{Height: 1, AncestorHeaders: []BlockHeader{parent}})
		if err == nil || err.Error() != BLOCK_ERR_SUBSIDY_EXCEEDED {
			t.Fatalf("expected BLOCK_ERR_SUBSIDY_EXCEEDED, got %v", err)
		}
	})

	t.Run("double spend in one block", func(t *testing.T) {
		parent := makeParentHeader([32]byte{0xff}, 10)
		spendKey := repeatByte(0x22, ML_DSA_PUBKEY_BYTES)
		spendKeyID := mustSHA3ForTest(t, p, spendKey)
		point := TxOutPoint{TxID: [32]byte{0x01}, Vout: 0}
		utxo := map[TxOutPoint]UtxoEntry{
			point: {Output: makeP2PKOutputForKeyID(spendKeyID, 20), CreationHeight: 0},
		}
		spend := Tx{
			Version: 1,
			TxNonce: 1,
			Inputs: []TxInput{{
				PrevTxid: point.TxID, PrevVout: point.Vout, Sequence: 1, ScriptSig: nil,
			}},
			Outputs:  []TxOutput{makeP2PKOutputForKeyID(spendKeyID, 10)},
			Locktime: 1,
			Witness: WitnessSection{
				Witnesses: []WitnessItem{{
					SuiteID:   SUITE_ID_ML_DSA,
					Pubkey:    spendKey,
					Signature: make([]byte, ML_DSA_SIG_BYTES),
				}},
			},
		}
		spendCopy := spend
		spendCopy.TxNonce = 2
		cb := makeApplyCoinbaseTx(1, []TxOutput{cbOut})
		block := makeApplyBlock(1, parent, 11, []Tx{cb, spend, spendCopy})
		err := ApplyBlock(p, [32]byte{}, &block, utxo, BlockValidationContext{Height: 1, AncestorHeaders: []BlockHeader{parent}})
		if err == nil || err.Error() != TX_ERR_MISSING_UTXO {
			t.Fatalf("expected TX_ERR_MISSING_UTXO, got %v", err)
		}
	})

	t.Run("utxo updated after apply", func(t *testing.T) {
		parent := makeParentHeader([32]byte{0xff}, 10)
		spendKey := repeatByte(0x33, ML_DSA_PUBKEY_BYTES)
		spendKeyID := mustSHA3ForTest(t, p, spendKey)
		point := TxOutPoint{TxID: [32]byte{0x02}, Vout: 0}
		utxo := map[TxOutPoint]UtxoEntry{
			point: {
				Output:            makeP2PKOutputForKeyID(spendKeyID, 20),
				CreationHeight:    0,
				CreatedByCoinbase: false,
			},
		}
		spend := Tx{
			Version: 1,
			TxNonce: 1,
			Inputs: []TxInput{{
				PrevTxid: point.TxID, PrevVout: point.Vout, Sequence: 1, ScriptSig: nil,
			}},
			Outputs:  []TxOutput{makeP2PKOutputForKeyID(spendKeyID, 10)},
			Locktime: 1,
			Witness: WitnessSection{
				Witnesses: []WitnessItem{{
					SuiteID:   SUITE_ID_ML_DSA,
					Pubkey:    spendKey,
					Signature: make([]byte, ML_DSA_SIG_BYTES),
				}},
			},
		}
		cb := makeApplyCoinbaseTx(1, []TxOutput{cbOut})
		block := makeApplyBlock(1, parent, 11, []Tx{cb, spend})
		if err := ApplyBlock(p, [32]byte{}, &block, utxo, BlockValidationContext{Height: 1, AncestorHeaders: []BlockHeader{parent}}); err != nil {
			t.Fatalf("expected valid block, got %v", err)
		}
		if _, ok := utxo[point]; ok {
			t.Fatalf("expected input utxo to be deleted")
		}
		if len(utxo) != 2 {
			t.Fatalf("expected 2 utxos (coinbase + spend output), got %d", len(utxo))
		}
		spendTxID, err := TxID(p, &spend)
		if err != nil {
			t.Fatalf("tx id calc failed: %v", err)
		}
		found := false
		for u := range utxo {
			if bytes.Equal(u.TxID[:], spendTxID[:]) && u.Vout == 0 {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected spend output with txid %x", spendTxID)
		}
	})
}

func TestValidateCoinbaseTxInputs(t *testing.T) {
	t.Run("txNonce!=0", func(t *testing.T) {
		tx := makeApplyCoinbaseTx(0, nil)
		tx.TxNonce = 1
		err := validateCoinbaseTxInputs(&tx)
		if err == nil || err.Error() != BLOCK_ERR_COINBASE_INVALID {
			t.Fatalf("expected BLOCK_ERR_COINBASE_INVALID, got %v", err)
		}
	})

	t.Run("len(inputs)!=1", func(t *testing.T) {
		tx := makeApplyCoinbaseTx(0, nil)
		tx.Inputs = nil
		err := validateCoinbaseTxInputs(&tx)
		if err == nil || err.Error() != BLOCK_ERR_COINBASE_INVALID {
			t.Fatalf("expected BLOCK_ERR_COINBASE_INVALID, got %v", err)
		}
	})

	t.Run("sequence!=0xFFFFFFFF", func(t *testing.T) {
		tx := makeApplyCoinbaseTx(0, nil)
		tx.Inputs[0].Sequence = 1
		err := validateCoinbaseTxInputs(&tx)
		if err == nil || err.Error() != BLOCK_ERR_COINBASE_INVALID {
			t.Fatalf("expected BLOCK_ERR_COINBASE_INVALID, got %v", err)
		}
	})

	t.Run("prevTxid!=zero", func(t *testing.T) {
		tx := makeApplyCoinbaseTx(0, nil)
		tx.Inputs[0].PrevTxid = [32]byte{1}
		err := validateCoinbaseTxInputs(&tx)
		if err == nil || err.Error() != BLOCK_ERR_COINBASE_INVALID {
			t.Fatalf("expected BLOCK_ERR_COINBASE_INVALID, got %v", err)
		}
	})

	t.Run("scriptSig не пуст", func(t *testing.T) {
		tx := makeApplyCoinbaseTx(0, nil)
		tx.Inputs[0].ScriptSig = []byte{1}
		err := validateCoinbaseTxInputs(&tx)
		if err == nil || err.Error() != BLOCK_ERR_COINBASE_INVALID {
			t.Fatalf("expected BLOCK_ERR_COINBASE_INVALID, got %v", err)
		}
	})

	t.Run("witnesses не пуст", func(t *testing.T) {
		tx := makeApplyCoinbaseTx(0, nil)
		tx.Witness.Witnesses = []WitnessItem{{SuiteID: SUITE_ID_ML_DSA}}
		err := validateCoinbaseTxInputs(&tx)
		if err == nil || err.Error() != BLOCK_ERR_COINBASE_INVALID {
			t.Fatalf("expected BLOCK_ERR_COINBASE_INVALID, got %v", err)
		}
	})
}
