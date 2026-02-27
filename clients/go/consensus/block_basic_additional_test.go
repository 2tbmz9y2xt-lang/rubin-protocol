package consensus

import (
	"reflect"
	"testing"
	"unsafe"
)

var dummyByteForUnsafeLen byte

func unsafeLenBytes(n int) []byte {
	h := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&dummyByteForUnsafeLen)),
		Len:  n,
		Cap:  n,
	}
	return *(*[]byte)(unsafe.Pointer(&h))
}

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

func TestTxWeightAndStats_TxKind00_DAIgnoredForDaBytes(t *testing.T) {
	tx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  0,
		Inputs:   []TxInput{},
		Outputs:  []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		Locktime: 0,
		Witness:  []WitnessItem{{SuiteID: 0xff, Pubkey: []byte{0x01}, Signature: []byte{0x02}}},
		DaPayload: []byte{
			0x01, 0x02, 0x03,
		},
	}

	_, daBytes, _, err := TxWeightAndStats(tx)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}
	if daBytes != 0 {
		t.Fatalf("daBytes=%d, want 0 for tx_kind=0x00", daBytes)
	}
}

func TestTxWeightAndStats_DACoreMissingErrors(t *testing.T) {
	t.Run("tx_kind_01_missing_commit_core", func(t *testing.T) {
		tx := &Tx{Version: 1, TxKind: 0x01, TxNonce: 1}
		if _, _, _, err := TxWeightAndStats(tx); err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("tx_kind_02_missing_chunk_core", func(t *testing.T) {
		tx := &Tx{Version: 1, TxKind: 0x02, TxNonce: 1}
		if _, _, _, err := TxWeightAndStats(tx); err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("unsupported_tx_kind", func(t *testing.T) {
		tx := &Tx{Version: 1, TxKind: 0x03, TxNonce: 1}
		if _, _, _, err := TxWeightAndStats(tx); err == nil {
			t.Fatalf("expected error")
		}
	})
}

func TestTxWeightAndStats_TxKind02_ChunkCoreOK(t *testing.T) {
	mlPub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	mlSig := make([]byte, ML_DSA_87_SIG_BYTES)

	daID := filled32(0xa1)
	payload := []byte("abc")
	chunkHash := sha3_256(payload)

	tx := &Tx{
		Version: 1,
		TxKind:  0x02,
		TxNonce: 9,
		Inputs: []TxInput{
			{
				PrevTxid:  filled32(0x01),
				PrevVout:  2,
				ScriptSig: []byte{0x99},
				Sequence:  3,
			},
		},
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
		},
		Locktime: 0,
		DaChunkCore: &DaChunkCore{
			DaID:       daID,
			ChunkIndex: 0,
			ChunkHash:  chunkHash,
		},
		Witness:   []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: mlPub, Signature: mlSig}},
		DaPayload: payload,
	}

	_, daBytes, anchorBytes, err := TxWeightAndStats(tx)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}
	if daBytes != uint64(len(payload)) {
		t.Fatalf("daBytes=%d, want %d", daBytes, len(payload))
	}
	if anchorBytes != 0 {
		t.Fatalf("anchorBytes=%d, want 0", anchorBytes)
	}
}

func TestTxWeightAndStats_OverflowScriptSigLen(t *testing.T) {
	maxInt := int(^uint(0) >> 1)

	tx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []TxInput{{ScriptSig: unsafeLenBytes(maxInt)}, {ScriptSig: unsafeLenBytes(maxInt)}},
		Outputs:  nil,
		Locktime: 0,
		Witness:  nil,
		DaPayload: []byte{
			0x01,
		},
	}

	if _, _, _, err := TxWeightAndStats(tx); err == nil {
		t.Fatalf("expected error")
	} else if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestTxWeightAndStats_OverflowCovenantDataLen(t *testing.T) {
	maxInt := int(^uint(0) >> 1)

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 2,
		Inputs:  nil,
		Outputs: []TxOutput{
			{Value: 0, CovenantType: COV_TYPE_P2PK, CovenantData: unsafeLenBytes(maxInt)},
			{Value: 0, CovenantType: COV_TYPE_P2PK, CovenantData: unsafeLenBytes(maxInt)},
		},
		Locktime: 0,
	}

	if _, _, _, err := TxWeightAndStats(tx); err == nil {
		t.Fatalf("expected error")
	} else if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestTxWeightAndStats_OverflowBaseWeightMulU64(t *testing.T) {
	// baseSize = 68 + len(scriptSig) for 1-input, 0-output, tx_kind=0x00.
	// Pick len(scriptSig) such that baseSize > max_u64/4 to force mulU64 overflow.
	baseSizeTarget := (^uint64(0))/4 + 1
	scriptSigLen := int(baseSizeTarget - 68)

	tx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  3,
		Inputs:   []TxInput{{ScriptSig: unsafeLenBytes(scriptSigLen)}},
		Outputs:  nil,
		Locktime: 0,
	}

	if _, _, _, err := TxWeightAndStats(tx); err == nil {
		t.Fatalf("expected error")
	} else if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestTxWeightAndStats_OverflowAddWitnessSize(t *testing.T) {
	// baseSize = 68 + len(scriptSig) for 1-input, 0-output, tx_kind=0x00.
	// Choose baseSize=max_u64/4 so baseWeight=max_u64-3, then witnessSize=4 => overflow.
	baseSizeTarget := (^uint64(0)) / 4
	scriptSigLen := int(baseSizeTarget - 68)

	tx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  4,
		Inputs:   []TxInput{{ScriptSig: unsafeLenBytes(scriptSigLen)}},
		Outputs:  nil,
		Locktime: 0,
		Witness:  []WitnessItem{{SuiteID: 0x00, Pubkey: nil, Signature: nil}},
	}

	if _, _, _, err := TxWeightAndStats(tx); err == nil {
		t.Fatalf("expected error")
	} else if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestTxWeightAndStats_OverflowAddDaSize(t *testing.T) {
	// baseSize=max_u64/4 => baseWeight=max_u64-3. With no witness: weight=max_u64-2.
	// Pick daSize=3 (len=2) so adding daSize overflows.
	baseSizeTarget := (^uint64(0)) / 4
	scriptSigLen := int(baseSizeTarget - 68)

	tx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  5,
		Inputs:   []TxInput{{ScriptSig: unsafeLenBytes(scriptSigLen)}},
		Outputs:  nil,
		Locktime: 0,
		Witness:  nil,
		DaPayload: []byte{
			0x01, 0x02,
		},
	}

	if _, _, _, err := TxWeightAndStats(tx); err == nil {
		t.Fatalf("expected error")
	} else if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
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
