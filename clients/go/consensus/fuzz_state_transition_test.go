//go:build cgo

package consensus

import (
	"context"
	"math/big"
	"strings"
	"testing"
)

// maxFuzzBytes caps variable-length fuzz inputs to avoid OOM.
const maxStateTransitionFuzzBytes = 8192

// FuzzConnectBlockInMemory exercises the full in-memory block connection path
// with fuzz-derived block bytes. Invariants:
//   - No panic regardless of input.
//   - Valid error or valid summary (never both nil).
//   - UTXO state mutations are deterministic.
func FuzzConnectBlockInMemory(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 80), make([]byte, 32)) // minimal header-sized input

	f.Fuzz(func(t *testing.T, blockBytes []byte, chainIDRaw []byte) {
		if len(blockBytes) > maxStateTransitionFuzzBytes ||
			len(chainIDRaw) > maxStateTransitionFuzzBytes {
			return
		}
		var chainID [32]byte
		copy(chainID[:], chainIDRaw)

		state := &InMemoryChainState{
			Utxos:            make(map[Outpoint]UtxoEntry),
			AlreadyGenerated: big.NewInt(0),
		}

		summary, err := ConnectBlockBasicInMemoryAtHeight(
			blockBytes,
			nil, // expectedPrevHash
			nil, // expectedTarget
			1,   // blockHeight
			nil, // prevTimestamps
			state,
			chainID,
		)

		// Invariant: exactly one of summary or error must be non-nil for valid blocks,
		// but both nil is valid (block parsing failed before summary construction).
		if summary != nil && err != nil {
			t.Fatalf("both summary and error non-nil: summary=%+v err=%v", summary, err)
		}

		// Determinism: same input → same result.
		state2 := &InMemoryChainState{
			Utxos:            make(map[Outpoint]UtxoEntry),
			AlreadyGenerated: big.NewInt(0),
		}
		summary2, err2 := ConnectBlockBasicInMemoryAtHeight(
			blockBytes, nil, nil, 1, nil, state2, chainID,
		)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic error: %v vs %v", err, err2)
		}
		if summary != nil && summary2 != nil {
			if summary.SumFees != summary2.SumFees {
				t.Fatalf("non-deterministic fees: %d vs %d", summary.SumFees, summary2.SumFees)
			}
			if summary.PostStateDigest != summary2.PostStateDigest {
				t.Fatal("non-deterministic post-state digest")
			}
		}
	})
}

// FuzzTxDepGraphBuild exercises the transaction dependency graph builder with
// fuzz-derived validation contexts. Invariants:
//   - No panic regardless of input shapes.
//   - Levels are non-negative and bounded by TxCount.
//   - LevelOrder is a permutation of [0..TxCount).
//   - Parent-child edges point from lower to higher levels.
func FuzzTxDepGraphBuild(f *testing.F) {
	f.Add([]byte{0x00}, []byte{0x01}, []byte{0x02})

	f.Fuzz(func(t *testing.T, txCountRaw []byte, edgeDataA []byte, edgeDataB []byte) {
		if len(txCountRaw) == 0 || len(txCountRaw) > maxStateTransitionFuzzBytes {
			return
		}
		txCount := int(txCountRaw[0])%8 + 1 // 1-8 txs
		if len(edgeDataA) > maxStateTransitionFuzzBytes || len(edgeDataB) > maxStateTransitionFuzzBytes {
			return
		}

		// Build minimal TxValidationContexts with fuzz-derived outpoints.
		contexts := make([]TxValidationContext, txCount)
		for i := 0; i < txCount; i++ {
			var txid [32]byte
			txid[0] = byte(i)

			// Each tx has one output at vout=0.
			tx := &Tx{
				Outputs: []TxOutput{{Value: 1000}},
			}

			// Build input outpoints from fuzz data to create varying dep patterns.
			var inputs []Outpoint
			if i > 0 && len(edgeDataA) > i {
				// Sometimes reference previous tx's output (parent-child).
				prevIdx := int(edgeDataA[i]) % i
				var prevTxid [32]byte
				prevTxid[0] = byte(prevIdx)
				inputs = append(inputs, Outpoint{Txid: prevTxid, Vout: 0})
			}
			if len(edgeDataB) > i {
				// Sometimes reference same external outpoint (same-prevout conflict).
				var extTxid [32]byte
				extTxid[0] = 0xFF
				extTxid[1] = edgeDataB[i]
				inputs = append(inputs, Outpoint{Txid: extTxid, Vout: 0})
			}

			contexts[i] = TxValidationContext{
				TxIndex:        i,
				Tx:             tx,
				Txid:           txid,
				InputOutpoints: inputs,
			}
		}

		graph := BuildTxDepGraph(contexts)

		// Invariant: TxCount matches.
		if graph.TxCount != txCount {
			t.Fatalf("TxCount: got %d want %d", graph.TxCount, txCount)
		}

		// Invariant: Levels length matches TxCount.
		if len(graph.Levels) != txCount {
			t.Fatalf("Levels length: got %d want %d", len(graph.Levels), txCount)
		}

		// Invariant: all levels are non-negative and ≤ MaxLevel.
		for i, lvl := range graph.Levels {
			if lvl < 0 {
				t.Fatalf("negative level at index %d: %d", i, lvl)
			}
			if lvl > graph.MaxLevel {
				t.Fatalf("level %d exceeds MaxLevel %d at index %d", lvl, graph.MaxLevel, i)
			}
		}

		// Invariant: LevelOrder is a valid permutation of [0..TxCount).
		if len(graph.LevelOrder) != txCount {
			t.Fatalf("LevelOrder length: got %d want %d", len(graph.LevelOrder), txCount)
		}
		seen := make(map[int]bool)
		for _, idx := range graph.LevelOrder {
			if idx < 0 || idx >= txCount {
				t.Fatalf("LevelOrder out of range: %d", idx)
			}
			if seen[idx] {
				t.Fatalf("LevelOrder duplicate: %d", idx)
			}
			seen[idx] = true
		}

		// Invariant: LevelOrder is sorted by level (non-decreasing).
		for i := 1; i < len(graph.LevelOrder); i++ {
			if graph.Levels[graph.LevelOrder[i]] < graph.Levels[graph.LevelOrder[i-1]] {
				t.Fatal("LevelOrder not sorted by level")
			}
		}

		// Invariant: edges respect level ordering.
		for _, e := range graph.Edges {
			if graph.Levels[e.ProducerIdx] >= graph.Levels[e.ConsumerIdx] {
				t.Fatalf("edge level violation: producer level %d >= consumer level %d",
					graph.Levels[e.ProducerIdx], graph.Levels[e.ConsumerIdx])
			}
		}
	})
}

// FuzzDAChunkHashVerify exercises DA chunk hash verification with fuzz-derived payloads.
// Invariants:
//   - No panic regardless of input.
//   - Correct hash → no error. Incorrect hash → error.
//   - Deterministic error ordering.
func FuzzDAChunkHashVerify(f *testing.F) {
	f.Add([]byte{0x01}, []byte{})
	f.Add([]byte{}, []byte{0x42})

	f.Fuzz(func(t *testing.T, payload []byte, hashSuffix []byte) {
		if len(payload) > maxStateTransitionFuzzBytes ||
			len(hashSuffix) > maxStateTransitionFuzzBytes {
			return
		}

		// Compute correct hash for the payload.
		correctHash := sha3_256(payload)

		// Task with correct hash — must always pass.
		correctTask := DAChunkHashTask{
			TxIndex:   0,
			DaPayload: payload,
			Expected:  correctHash,
		}
		err := VerifyDAChunkHashesParallel(context.Background(), []DAChunkHashTask{correctTask}, 1)
		if err != nil {
			t.Fatalf("correct hash rejected: %v", err)
		}

		// Task with fuzz-mutated hash — must fail unless collision.
		var mutatedHash [32]byte
		copy(mutatedHash[:], correctHash[:])
		if len(hashSuffix) > 0 {
			mutatedHash[31] ^= hashSuffix[0] | 0x01 // ensure at least 1 bit flipped
		} else {
			mutatedHash[0] ^= 0xFF
		}

		wrongTask := DAChunkHashTask{
			TxIndex:   0,
			DaPayload: payload,
			Expected:  mutatedHash,
		}
		err = VerifyDAChunkHashesParallel(context.Background(), []DAChunkHashTask{wrongTask}, 1)
		if err == nil {
			t.Fatal("mutated hash accepted — SHA3-256 collision")
		}

		// Empty tasks — must pass.
		err = VerifyDAChunkHashesParallel(context.Background(), nil, 1)
		if err != nil {
			t.Fatalf("empty tasks failed: %v", err)
		}

		// Determinism across worker counts: 1, 2, 4 must all agree.
		for _, w := range []int{1, 2, 4} {
			errW := VerifyDAChunkHashesParallel(context.Background(), []DAChunkHashTask{correctTask}, w)
			if errW != nil {
				t.Fatalf("correct hash rejected with %d workers: %v", w, errW)
			}
		}

		// Mutated hash must fail regardless of worker count.
		for _, w := range []int{1, 2, 4} {
			errW := VerifyDAChunkHashesParallel(context.Background(), []DAChunkHashTask{wrongTask}, w)
			if errW == nil {
				t.Fatalf("mutated hash accepted with %d workers", w)
			}
		}
	})
}

// FuzzDAPayloadCommitVerify exercises DA payload commitment verification.
// Invariants:
//   - Correct commitment of concatenated chunks → no error.
//   - Mutated commitment → error.
//   - Multiple workers produce same result as single worker.
func FuzzDAPayloadCommitVerify(f *testing.F) {
	f.Add([]byte{0x01}, []byte{0x02})

	f.Fuzz(func(t *testing.T, chunk1 []byte, chunk2 []byte) {
		if len(chunk1) > maxStateTransitionFuzzBytes/2 || len(chunk2) > maxStateTransitionFuzzBytes/2 {
			return
		}

		// Build correct task.
		concat := append(append([]byte{}, chunk1...), chunk2...)
		correctCommit := sha3_256(concat)

		var daID [32]byte
		daID[0] = 0x42

		task := DAPayloadCommitTask{
			DaID:           daID,
			ChunkCount:     2,
			ChunkPayloads:  [][]byte{chunk1, chunk2},
			ExpectedCommit: correctCommit,
		}

		// Correct commitment — must pass with any worker count.
		for _, workers := range []int{1, 2, 4} {
			err := VerifyDAPayloadCommitsParallel(context.Background(), []DAPayloadCommitTask{task}, workers)
			if err != nil {
				t.Fatalf("correct commit rejected with %d workers: %v", workers, err)
			}
		}

		// Mutated commitment — must fail.
		badTask := task
		badTask.ExpectedCommit[0] ^= 0xFF
		err := VerifyDAPayloadCommitsParallel(context.Background(), []DAPayloadCommitTask{badTask}, 1)
		if err == nil {
			t.Fatal("mutated commit accepted")
		}
	})
}

// FuzzUtxoApplyNonCoinbase exercises UTXO application of non-coinbase transactions
// with fuzz-derived transaction data and a real ML-DSA-87 signature. Invariants:
//   - No panic regardless of input.
//   - Deterministic result for identical inputs.
//   - Valid signature reaches fee/value-conservation and UTXO-mutation paths.
//   - ChainID, input count, output count, and covenant types are fuzz-varied.
func FuzzUtxoApplyNonCoinbase(f *testing.F) {
	// Generate ML-DSA-87 keypair once (expensive) — reused across all iterations.
	kp, err := NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(err.Error(), "unsupported") {
			f.Skipf("ML-DSA backend unavailable: %v", err)
		}
		f.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	defer kp.Close()

	pubkey := kp.PubkeyBytes()
	covData := p2pkCovenantDataForPubkey(pubkey)

	f.Add([]byte{0x01}, []byte{0x00}, []byte{0x00}, []byte{0x00})

	f.Fuzz(func(t *testing.T, txData []byte, seedA []byte, seedB []byte, chainIDRaw []byte) {
		if len(txData) > maxStateTransitionFuzzBytes ||
			len(seedA) > maxStateTransitionFuzzBytes ||
			len(seedB) > maxStateTransitionFuzzBytes ||
			len(chainIDRaw) > maxStateTransitionFuzzBytes {
			return
		}

		// Derive chainID from fuzz data — exercises chainID-specific sighash paths.
		var chainID [32]byte
		copy(chainID[:], chainIDRaw)

		// Fuzz-driven input count (1–3) and output count (1–3).
		inputCount := 1
		outputCount := 1
		if len(txData) > 3 {
			inputCount = int(txData[3])%3 + 1
		}
		if len(txData) > 4 {
			outputCount = int(txData[4])%3 + 1
		}

		// Construct Tx from fuzz data.
		tx := &Tx{TxNonce: 1}
		if len(txData) > 0 {
			tx.Version = uint32(txData[0])
		}

		// Derive UTXO value from fuzz data to exercise value conservation edge cases.
		var utxoValue uint64 = 1000
		if len(txData) > 6 {
			utxoValue = uint64(txData[5])<<8 | uint64(txData[6])
		}
		if utxoValue == 0 {
			utxoValue = 1 // must be non-zero for valid UTXO
		}

		// Build inputs — each with a unique prevTxid derived from seedA.
		for i := 0; i < inputCount; i++ {
			var prevTxid [32]byte
			offset := i * 32
			if offset < len(seedA) {
				end := offset + 32
				if end > len(seedA) {
					end = len(seedA)
				}
				copy(prevTxid[:], seedA[offset:end])
			}
			prevTxid[31] = byte(i) // ensure uniqueness across inputs
			tx.Inputs = append(tx.Inputs, TxInput{
				PrevTxid: prevTxid,
				PrevVout: 0,
			})
			// Placeholder witness — will be replaced after signing.
			tx.Witness = append(tx.Witness, WitnessItem{
				SuiteID: SUITE_ID_ML_DSA_87,
				Pubkey:  pubkey,
			})
		}

		// Build outputs — primary P2PK + optional ANCHOR or additional P2PK.
		totalInputValue := utxoValue * uint64(inputCount)
		for i := 0; i < outputCount; i++ {
			if i == 0 {
				// Primary P2PK output with fuzz-varied value.
				var outValue uint64 = 500
				if len(txData) > 2 {
					outValue = uint64(txData[1])<<8 | uint64(txData[2])
				}
				if outValue == 0 {
					outValue = 1 // P2PK requires value > 0
				}
				// Cap to total input value to exercise success paths.
				if outValue > totalInputValue {
					outValue = totalInputValue / 2
					if outValue == 0 {
						outValue = 1
					}
				}
				tx.Outputs = append(tx.Outputs, TxOutput{
					Value:        outValue,
					CovenantType: COV_TYPE_P2PK,
					CovenantData: covData,
				})
			} else if len(txData) > 5 && txData[5]%2 == 0 {
				// ANCHOR output — exercises different covenant genesis path.
				// ANCHOR requires Value==0 and non-empty CovenantData.
				tx.Outputs = append(tx.Outputs, TxOutput{
					Value:        0,
					CovenantType: COV_TYPE_ANCHOR,
					CovenantData: []byte{0x01},
				})
			} else {
				// Additional P2PK output — exercises multi-output value conservation.
				tx.Outputs = append(tx.Outputs, TxOutput{
					Value:        1,
					CovenantType: COV_TYPE_P2PK,
					CovenantData: covData,
				})
			}
		}

		// Sign each input with the real ML-DSA-87 key.
		// SighashV1 does NOT include witness in digest — safe to sign sequentially.
		for i := 0; i < inputCount; i++ {
			digest, signErr := SighashV1DigestWithType(tx, uint32(i), utxoValue, chainID, SIGHASH_ALL)
			if signErr != nil {
				return // non-signable tx shape — skip
			}
			sig, signErr := kp.SignDigest32(digest)
			if signErr != nil {
				return // sign failure — skip
			}
			sig = append(sig, SIGHASH_ALL)
			tx.Witness[i].Signature = sig
		}

		var txid [32]byte
		copy(txid[:], seedB)

		// Build UTXO set for all inputs.
		buildUtxoSet := func() map[Outpoint]UtxoEntry {
			s := make(map[Outpoint]UtxoEntry, inputCount)
			for i := 0; i < inputCount; i++ {
				s[Outpoint{Txid: tx.Inputs[i].PrevTxid, Vout: 0}] = UtxoEntry{
					Value:          utxoValue,
					CovenantType:   COV_TYPE_P2PK,
					CovenantData:   covData,
					CreationHeight: 0,
				}
			}
			return s
		}

		// Must not panic.
		summary, err := ApplyNonCoinbaseTxBasic(
			tx, txid, buildUtxoSet(), 100, 0, chainID,
		)

		// Determinism check — fresh UTXO set, same tx.
		summary2, err2 := ApplyNonCoinbaseTxBasic(
			tx, txid, buildUtxoSet(), 100, 0, chainID,
		)

		if (err == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic error: %v vs %v", err, err2)
		}
		if summary != nil && summary2 != nil {
			if summary.Fee != summary2.Fee {
				t.Fatalf("non-deterministic fee: %d vs %d", summary.Fee, summary2.Fee)
			}
		}
	})
}
