package consensus

import (
	"encoding/binary"
	"testing"
)

// FuzzExtractCryptoSigAndSighash fuzzes the sighash extraction logic
// that parses the trailing sighash byte from a witness signature field.
//
// Invariants:
// - len(cryptoSig) + 1 == len(sig) on success
// - sighashType == sig[len(sig)-1] on success
// - Deterministic: same input -> same result
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

		// Determinism check.
		cryptoSig2, sighashType2, err2 := extractCryptoSigAndSighash(w)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic error: %v vs %v", err, err2)
		}
		if err == nil {
			if len(cryptoSig) != len(cryptoSig2) || sighashType != sighashType2 {
				t.Fatalf("non-deterministic result")
			}
		}

		if err != nil {
			return
		}
		// Invariant: crypto sig + 1 sighash byte == original
		if len(cryptoSig)+1 != len(sig) {
			t.Fatalf("crypto sig len %d + 1 != sig len %d", len(cryptoSig), len(sig))
		}
		if sighashType != sig[len(sig)-1] {
			t.Fatalf("sighash type mismatch: got 0x%02x, want 0x%02x", sighashType, sig[len(sig)-1])
		}
	})
}

// FuzzValidateP2PKSpendStructural fuzzes the structural checks of P2PK
// spend validation (covenant data parsing, suite ID validation) without
// requiring valid ML-DSA signatures.
//
// Invariants:
// - Deterministic: same input -> same error/nil result
// - No panic regardless of input
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

		err1 := validateP2PKSpend(entry, w, tx, inputIndex, inputValue, chainID, blockHeight)
		err2 := validateP2PKSpend(entry, w, tx, inputIndex, inputValue, chainID, blockHeight)

		// Determinism: both calls must agree on error/nil.
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic: err1=%v, err2=%v", err1, err2)
		}
	})
}

// FuzzValidateTxLocalDispatch fuzzes the ValidateTxLocal entry point with
// a structurally minimal transaction context to exercise covenant dispatch,
// witness cursor tracking, and error handling without valid signatures.
//
// Invariants:
// - Determinism: same input -> identical TxValidationResult
// - Valid↔Err consistency: Valid==true iff Err==nil
// - TxIndex preserved from TxValidationContext
// - Fee preserved from TxValidationContext
// - SigCount >= 0
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
			Fee:            42,
		}

		r1 := ValidateTxLocal(tvc, chainID, blockHeight, blockMTP, nil, nil)

		// Invariant: Valid ↔ Err consistency.
		if r1.Valid && r1.Err != nil {
			t.Fatalf("Valid==true but Err=%v", r1.Err)
		}
		if !r1.Valid && r1.Err == nil {
			t.Fatalf("Valid==false but Err==nil")
		}

		// Invariant: TxIndex preserved.
		if r1.TxIndex != 1 {
			t.Fatalf("TxIndex not preserved: got %d, want 1", r1.TxIndex)
		}

		// Invariant: Fee preserved from TVC.
		if r1.Fee != 42 {
			t.Fatalf("Fee not preserved: got %d, want 42", r1.Fee)
		}

		// Invariant: SigCount non-negative.
		if r1.SigCount < 0 {
			t.Fatalf("SigCount negative: %d", r1.SigCount)
		}

		// Invariant: Determinism.
		r2 := ValidateTxLocal(tvc, chainID, blockHeight, blockMTP, nil, nil)
		if r1.Valid != r2.Valid {
			t.Fatalf("non-deterministic Valid: %v vs %v", r1.Valid, r2.Valid)
		}
		if (r1.Err == nil) != (r2.Err == nil) {
			t.Fatalf("non-deterministic Err: %v vs %v", r1.Err, r2.Err)
		}
		if r1.SigCount != r2.SigCount {
			t.Fatalf("non-deterministic SigCount: %d vs %d", r1.SigCount, r2.SigCount)
		}
	})
}

// FuzzAccumulateBlockResourceStats fuzzes the block resource stats accumulator
// to exercise overflow detection and nil-tx handling.
//
// Invariants:
// - Determinism: same input -> identical result
// - On success: sumWeight > 0 for non-empty blocks (at least header weight)
// - Error consistency between runs
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

		stats1, err1 := accumulateBlockResourceStats(pb)
		stats2, err2 := accumulateBlockResourceStats(pb)

		// Determinism.
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic error: %v vs %v", err1, err2)
		}

		if err1 != nil {
			return
		}

		// Invariant: successful stats must match between runs.
		if stats1.sumWeight != stats2.sumWeight {
			t.Fatalf("non-deterministic sumWeight: %d vs %d", stats1.sumWeight, stats2.sumWeight)
		}
		if stats1.sumDa != stats2.sumDa {
			t.Fatalf("non-deterministic sumDa: %d vs %d", stats1.sumDa, stats2.sumDa)
		}

		// Invariant: weight monotonicity — N identical txs should produce
		// sumWeight = N * single_tx_weight (or overflow error).
		if numTxs > 0 {
			singlePb := &ParsedBlock{Txs: []*Tx{tx}}
			singleStats, singleErr := accumulateBlockResourceStats(singlePb)
			if singleErr == nil && singleStats.sumWeight > 0 {
				// If single tx weight * numTxs would overflow, we already
				// got an error above. Otherwise check proportionality.
				expected := singleStats.sumWeight * uint64(numTxs)
				if expected/uint64(numTxs) == singleStats.sumWeight {
					// No overflow in multiplication.
					if stats1.sumWeight != expected {
						t.Fatalf("sumWeight %d != expected %d (single=%d * n=%d)",
							stats1.sumWeight, expected, singleStats.sumWeight, numTxs)
					}
				}
			}
		}
	})
}

// FuzzBlockTxSemanticsNonce fuzzes validateBlockTxSemantics to exercise nonce
// replay detection and covenant validation error propagation.
//
// Constructs a block with a valid coinbase + two duplicate non-coinbase txs.
//
// Invariants:
// - Determinism: same input -> same error/nil
// - Duplicate nonces always detected (error must be non-nil)
func FuzzBlockTxSemanticsNonce(f *testing.F) {
	f.Add(uint64(1), uint32(2))
	f.Fuzz(func(t *testing.T, blockHeight uint64, nonce uint32) {
		// Clamp blockHeight to uint32 range for valid coinbase locktime.
		if blockHeight > uint64(^uint32(0)) {
			blockHeight = uint64(^uint32(0))
		}

		var prev [32]byte
		binary.LittleEndian.PutUint32(prev[:4], nonce)
		txBytes := txWithOneInputOneOutput(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData())
		tx, _, _, _, err := ParseTx(txBytes)
		if err != nil {
			return
		}

		// Build valid coinbase: zero prevout, locktime == blockHeight.
		coinbase := &Tx{
			Version: 1,
			TxKind:  0,
			TxNonce: 0,
			Inputs: []TxInput{{
				PrevTxid: [32]byte{},
				PrevVout: ^uint32(0),
			}},
			Outputs: []TxOutput{{
				Value:        50,
				CovenantType: COV_TYPE_P2PK,
				CovenantData: validP2PKCovenantData(),
			}},
			Locktime: uint32(blockHeight),
		}

		// Two duplicate non-coinbase txs: same nonce -> replay.
		pb := &ParsedBlock{
			Txs: []*Tx{coinbase, tx, tx},
		}

		result1 := validateBlockTxSemantics(pb, blockHeight)
		result2 := validateBlockTxSemantics(pb, blockHeight)

		// Determinism.
		if (result1 == nil) != (result2 == nil) {
			t.Fatalf("non-deterministic: %v vs %v", result1, result2)
		}

		// Invariant: duplicate nonces in the same block must always be
		// detected. Two identical txs => same TxNonce => replay error.
		if result1 == nil {
			t.Fatalf("duplicate nonce %d not detected at height %d", tx.TxNonce, blockHeight)
		}
	})
}
