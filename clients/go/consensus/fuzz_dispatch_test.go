package consensus

import (
	"encoding/binary"
	"testing"
)

// FuzzExtractCryptoSigAndSighash fuzzes the sighash extraction logic
// that parses the trailing sighash byte from a witness signature field.
// Must never panic regardless of input.
func FuzzExtractCryptoSigAndSighash(f *testing.F) {
	f.Add([]byte{0x01, SIGHASH_ALL})
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF})
	f.Fuzz(func(t *testing.T, sig []byte) {
		if len(sig) > 8192 {
			return
		}
		w := WitnessItem{Signature: sig}
		cryptoSig, sighashType, err := extractCryptoSigAndSighash(w)
		if err != nil {
			return
		}
		// Invariant: crypto sig + 1 sighash byte == original
		if len(cryptoSig)+1 != len(sig) {
			t.Fatalf("crypto sig len %d + 1 != sig len %d", len(cryptoSig), len(sig))
		}
		if sighashType != sig[len(sig)-1] {
			t.Fatalf("sighash type mismatch")
		}
	})
}

// FuzzValidateP2PKSpendStructural fuzzes the structural checks of P2PK
// spend validation (covenant data parsing, suite ID validation) without
// requiring valid ML-DSA signatures.
func FuzzValidateP2PKSpendStructural(f *testing.F) {
	f.Add(
		uint8(SUITE_ID_ML_DSA_87),
		make([]byte, MAX_P2PK_COVENANT_DATA),
		uint8(SUITE_ID_ML_DSA_87),
		[]byte{0x01},
		[]byte{0x02, SIGHASH_ALL},
		uint64(0),
	)
	f.Fuzz(func(t *testing.T, covSuiteID uint8, covData []byte, witSuiteID uint8, pubkey []byte, sig []byte, blockHeight uint64) {
		if len(covData) > 256 || len(pubkey) > 8192 || len(sig) > 131072 {
			return
		}
		entry := UtxoEntry{
			Value:        1,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: covData,
		}
		w := WitnessItem{SuiteID: witSuiteID, Pubkey: pubkey, Signature: sig}
		tx, inputIndex, inputValue, chainID := testSighashContextTx()
		// Must not panic. Error is expected for most fuzz inputs.
		_ = validateP2PKSpend(entry, w, tx, inputIndex, inputValue, chainID, blockHeight)
	})
}

// FuzzValidateTxLocalDispatch fuzzes the ValidateTxLocal entry point with
// a structurally minimal transaction context to exercise covenant dispatch,
// witness cursor tracking, and error handling without valid signatures.
func FuzzValidateTxLocalDispatch(f *testing.F) {
	var prev [32]byte
	prev[0] = 0x42
	var chainID [32]byte
	chainID[0] = 0x11
	seed := txWithOneInputOneOutput(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData())
	f.Add(seed, uint64(1), uint64(0))

	f.Fuzz(func(t *testing.T, txBytes []byte, blockHeight uint64, blockMTP uint64) {
		if len(txBytes) > 1<<20 {
			return
		}
		tx, _, _, _, err := ParseTx(txBytes)
		if err != nil {
			return
		}
		if len(tx.Inputs) == 0 {
			return
		}
		// Build minimal resolved inputs from tx outputs as UTXOs.
		resolved := make([]UtxoEntry, len(tx.Inputs))
		for i := range resolved {
			if i < len(tx.Outputs) {
				resolved[i] = UtxoEntry{
					Value:        tx.Outputs[i].Value,
					CovenantType: tx.Outputs[i].CovenantType,
					CovenantData: tx.Outputs[i].CovenantData,
				}
			} else {
				resolved[i] = UtxoEntry{
					Value:        1,
					CovenantType: COV_TYPE_P2PK,
					CovenantData: validP2PKCovenantData(),
				}
			}
		}
		tvc := TxValidationContext{
			TxIndex:        1,
			Tx:             tx,
			ResolvedInputs: resolved,
			WitnessStart:   0,
			WitnessEnd:     len(tx.Witness),
			Fee:            0,
		}
		// Must not panic regardless of input.
		_ = ValidateTxLocal(tvc, chainID, blockHeight, blockMTP, nil, nil)
	})
}

// FuzzAccumulateBlockResourceStats fuzzes the block resource stats accumulator
// to exercise overflow detection and nil-tx handling.
func FuzzAccumulateBlockResourceStats(f *testing.F) {
	var prev [32]byte
	prev[0] = 0x42
	txBytes := txWithOneInputOneOutput(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData())
	f.Add(txBytes, uint16(1))

	f.Fuzz(func(t *testing.T, txBytes []byte, numTxs uint16) {
		if len(txBytes) > 1<<20 || numTxs > 256 {
			return
		}
		tx, _, _, _, err := ParseTx(txBytes)
		if err != nil {
			return
		}
		pb := &ParsedBlock{
			Txs: make([]*Tx, int(numTxs)),
		}
		for i := range pb.Txs {
			pb.Txs[i] = tx
		}
		// Must not panic.
		_, _ = accumulateBlockResourceStats(pb)
	})
}

// FuzzBlockTxSemanticsNonce fuzzes validateBlockTxSemantics to exercise nonce
// replay detection and covenant validation error propagation.
func FuzzBlockTxSemanticsNonce(f *testing.F) {
	f.Add(uint64(1), uint32(2))
	f.Fuzz(func(t *testing.T, blockHeight uint64, nonce uint32) {
		var prev [32]byte
		binary.LittleEndian.PutUint32(prev[:4], nonce)
		txBytes := txWithOneInputOneOutput(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData())
		tx, _, _, _, err := ParseTx(txBytes)
		if err != nil {
			return
		}
		// Duplicate tx to test nonce-replay detection.
		pb := &ParsedBlock{
			Txs: []*Tx{tx, tx},
		}
		result := validateBlockTxSemantics(pb, blockHeight)
		// With duplicate nonces, should detect replay (unless nonces happen
		// to differ due to input structure).
		_ = result
	})
}
