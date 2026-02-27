package consensus

import "testing"

func TestCompactSizeLen_Boundaries(t *testing.T) {
	cases := []struct {
		n    uint64
		want uint64
	}{
		{n: 0, want: 1},
		{n: 252, want: 1},
		{n: 253, want: 3},
		{n: 0xffff, want: 3},
		{n: 0x1_0000, want: 5},
		{n: 0xffff_ffff, want: 5},
		{n: 0x1_0000_0000, want: 9},
	}

	for _, tc := range cases {
		if got := compactSizeLen(tc.n); got != tc.want {
			t.Fatalf("compactSizeLen(%d)=%d, want %d", tc.n, got, tc.want)
		}
	}
}

func TestTxWeightAndStats_Nil(t *testing.T) {
	if _, _, _, err := TxWeightAndStats(nil); err == nil {
		t.Fatalf("expected error")
	}
}

func TestTxWeightAndStats_MLAndSLHCountsAndDAAndAnchor(t *testing.T) {
	mlPub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	mlSig := make([]byte, ML_DSA_87_SIG_BYTES)
	slhPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	slhSig := []byte{0x01}

	tx := &Tx{
		Version: 1,
		TxKind:  0x01,
		TxNonce: 7,
		Inputs: []TxInput{
			{Sequence: 0},
		},
		Outputs: []TxOutput{
			{Value: 0, CovenantType: COV_TYPE_DA_COMMIT, CovenantData: make([]byte, 32)},
			{Value: 0, CovenantType: COV_TYPE_ANCHOR, CovenantData: make([]byte, 32)},
		},
		Locktime: 0,
		DaCommitCore: &DaCommitCore{
			ChunkCount:    1,
			BatchSigSuite: 0,
		},
		Witness: []WitnessItem{
			{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: mlPub, Signature: mlSig},
			{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: slhPub, Signature: slhSig},
		},
		DaPayload: []byte{0x01, 0x02, 0x03},
	}

	weight, daBytes, anchorBytes, err := TxWeightAndStats(tx)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}
	if daBytes != 3 {
		t.Fatalf("daBytes=%d, want 3", daBytes)
	}
	if anchorBytes != 64 {
		t.Fatalf("anchorBytes=%d, want 64", anchorBytes)
	}

	// Expected accounting:
	// - base_size = 318 bytes
	// - witness_size = 7_295 bytes
	// - da_size = 4 bytes (len varint + payload)
	// - sig_cost = 8 (ML) + 64 (SLH) = 72
	// - weight = 4*base_size + witness_size + da_size + sig_cost
	const wantWeight = uint64(8_643)
	if weight != wantWeight {
		t.Fatalf("weight=%d, want %d", weight, wantWeight)
	}
}

func TestTxWeightAndStats_NonCanonicalWitnessLengths_NoSigCost(t *testing.T) {
	mlPub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	mlSig := []byte{0x01} // wrong length for ML-DSA
	slhPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	slhSig := []byte{} // empty => should not contribute sig_cost

	tx := &Tx{
		Version: 1,
		TxKind:  0x01,
		TxNonce: 8,
		Inputs: []TxInput{
			{Sequence: 0},
		},
		Outputs: []TxOutput{
			{Value: 0, CovenantType: COV_TYPE_DA_COMMIT, CovenantData: make([]byte, 32)},
		},
		Locktime: 0,
		DaCommitCore: &DaCommitCore{
			ChunkCount:    1,
			BatchSigSuite: 0,
		},
		Witness: []WitnessItem{
			{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: mlPub, Signature: mlSig},
			{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: slhPub, Signature: slhSig},
		},
		DaPayload: []byte{0x01},
	}

	weight, daBytes, anchorBytes, err := TxWeightAndStats(tx)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}
	if weight == 0 {
		t.Fatalf("weight=0, want > 0")
	}
	if daBytes != 1 {
		t.Fatalf("daBytes=%d, want 1", daBytes)
	}
	if anchorBytes != 32 {
		t.Fatalf("anchorBytes=%d, want 32", anchorBytes)
	}
}

func TestValidateTimestampRules_Variants(t *testing.T) {
	t.Run("no_context_ok", func(t *testing.T) {
		if err := validateTimestampRules(123, 0, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("insufficient_prev_timestamps", func(t *testing.T) {
		err := validateTimestampRules(123, 5, []uint64{1, 2, 3, 4})
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != BLOCK_ERR_PARSE {
			t.Fatalf("code=%s, want %s", got, BLOCK_ERR_PARSE)
		}
	})

	t.Run("timestamp_old", func(t *testing.T) {
		prev := []uint64{11, 20, 13, 14, 15, 16, 17, 18, 19, 12, 10} // median=15
		err := validateTimestampRules(15, 11, prev)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != BLOCK_ERR_TIMESTAMP_OLD {
			t.Fatalf("code=%s, want %s", got, BLOCK_ERR_TIMESTAMP_OLD)
		}
	})

	t.Run("timestamp_future", func(t *testing.T) {
		prev := []uint64{11, 20, 13, 14, 15, 16, 17, 18, 19, 12, 10} // median=15
		err := validateTimestampRules(15+MAX_FUTURE_DRIFT+1, 11, prev)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != BLOCK_ERR_TIMESTAMP_FUTURE {
			t.Fatalf("code=%s, want %s", got, BLOCK_ERR_TIMESTAMP_FUTURE)
		}
	})

	t.Run("upper_bound_overflow_clamped", func(t *testing.T) {
		max := ^uint64(0)
		prev := []uint64{
			max - 1, max - 1, max - 1, max - 1, max - 1, max - 1,
			max - 1, max - 1, max - 1, max - 1, max - 1,
		}
		if err := validateTimestampRules(max, 11, prev); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestValidateBlockBasicWithContextAndFeesAtHeight_PropagatesBasicErrors(t *testing.T) {
	coinbase := coinbaseWithWitnessCommitmentAtHeight(t, 1)
	cbid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	prev := hashWithPrefix(0x44)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 7, [][]byte{coinbase})

	wrongPrev := hashWithPrefix(0x55)
	_, err = ValidateBlockBasicWithContextAndFeesAtHeight(block, &wrongPrev, &target, 1, nil, 0, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_LINKAGE_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_LINKAGE_INVALID)
	}
}

func TestParseBlockBytes_EmptyTxList(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	prev := hashWithPrefix(0x19)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 9, [][]byte{tx})
	block[BLOCK_HEADER_BYTES] = 0x00 // tx_count = 0

	_, err = ParseBlockBytes(block)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_COINBASE_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_COINBASE_INVALID)
	}
}

func TestParseBlockBytes_UnexpectedEOF(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	prev := hashWithPrefix(0x1a)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 10, [][]byte{tx})
	block[BLOCK_HEADER_BYTES] = 0x02 // tx_count = 2, but only 1 tx present

	_, err = ParseBlockBytes(block)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_PARSE)
	}
}
