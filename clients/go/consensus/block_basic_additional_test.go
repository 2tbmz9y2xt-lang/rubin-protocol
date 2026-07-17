package consensus

import (
	"testing"
)

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

func TestTxWeightAndStats_MLAndUnknownSuiteCountsAndDAAndAnchor(t *testing.T) {
	mlPub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	mlSig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	unknownPub := make([]byte, 64)
	unknownSig := make([]byte, 49_856+1)

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
			{SuiteID: 0x02, Pubkey: unknownPub, Signature: unknownSig}, // non-native/unknown suite
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
	// - witness_size = 57_154 bytes
	// - da_size = 4 bytes (len varint + payload)
	// - sig_cost = 8 (ML) + 64 (unknown suite) = 72
	// - weight = 4*base_size + witness_size + da_size + sig_cost
	const wantWeight = uint64(58_502)
	if weight != wantWeight {
		t.Fatalf("weight=%d, want %d", weight, wantWeight)
	}
}

func TestTxWeightAndStats_NonCanonicalWitnessLengths_NoSigCost(t *testing.T) {
	mlPub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	mlSig := []byte{0x01} // wrong length for ML-DSA
	unknownPub := make([]byte, 64)
	unknownSig := []byte{0x01} // minimal non-empty signature (satisfies sighash tail rule)

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
			{SuiteID: 0x02, Pubkey: unknownPub, Signature: unknownSig}, // non-native/unknown suite
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

func TestTxWeightAndStats_MalformedNativeWitness_ZeroSigCostIntentional(t *testing.T) {
	malformedPub := make([]byte, ML_DSA_87_PUBKEY_BYTES-1)
	malformedSig := make([]byte, ML_DSA_87_SIG_BYTES+1)

	buildTx := func(suiteID uint8) *Tx {
		return &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 9,
			Inputs: []TxInput{
				{Sequence: 0},
			},
			Outputs: []TxOutput{
				{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
			},
			Locktime: 0,
			Witness: []WitnessItem{
				{SuiteID: suiteID, Pubkey: malformedPub, Signature: malformedSig},
			},
		}
	}

	malformedTx := buildTx(SUITE_ID_ML_DSA_87)
	sentinelTx := buildTx(SUITE_ID_SENTINEL)

	legacyWeight, _, _, err := TxWeightAndStats(malformedTx)
	if err != nil {
		t.Fatalf("TxWeightAndStats(malformed): %v", err)
	}
	sentinelWeight, _, _, err := TxWeightAndStats(sentinelTx)
	if err != nil {
		t.Fatalf("TxWeightAndStats(sentinel): %v", err)
	}
	if legacyWeight == 0 {
		t.Fatalf("legacyWeight=0, want > 0 from witness bytes")
	}
	if legacyWeight != sentinelWeight {
		t.Fatalf("legacyWeight=%d, want sentinelWeight=%d", legacyWeight, sentinelWeight)
	}

	registryWeight, _, _, err := TxWeightAndStatsAtHeight(
		malformedTx,
		0,
		DefaultRotationProvider{},
		DefaultSuiteRegistry(),
	)
	if err != nil {
		t.Fatalf("TxWeightAndStatsAtHeight(malformed): %v", err)
	}
	if registryWeight != sentinelWeight {
		t.Fatalf("registryWeight=%d, want sentinelWeight=%d", registryWeight, sentinelWeight)
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
	mlSig := make([]byte, ML_DSA_87_SIG_BYTES+1)

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

func TestIsCoinbaseTx_Variants(t *testing.T) {
	if isCoinbaseTx(nil) {
		t.Fatalf("nil should not be coinbase")
	}
	if isCoinbaseTx(&Tx{TxKind: 0x01}) {
		t.Fatalf("non-zero TxKind should not be coinbase")
	}
	if isCoinbaseTx(&Tx{}) {
		t.Fatalf("non-zero TxNonce required")
	}
	if isCoinbaseTx(&Tx{Inputs: []TxInput{{}, {}}}) {
		t.Fatalf("len(inputs)!=1 should not be coinbase")
	}
	if isCoinbaseTx(&Tx{Witness: []WitnessItem{{}}}) {
		t.Fatalf("non-empty witness should not be coinbase")
	}
	if isCoinbaseTx(&Tx{DaPayload: []byte{0x01}}) {
		t.Fatalf("non-empty da_payload should not be coinbase")
	}
	if isCoinbaseTx(&Tx{Inputs: []TxInput{{ScriptSig: []byte{0x01}}}}) {
		t.Fatalf("non-empty script_sig should not be coinbase")
	}
	if isCoinbaseTx(&Tx{Inputs: []TxInput{{Sequence: 1}}}) {
		t.Fatalf("non-max sequence should not be coinbase")
	}
}

func TestParseBlockTx_EOF(t *testing.T) {
	b := []byte{0x01}
	off := 1
	_, _, _, _, err := parseBlockTx(b, &off)
	if err == nil {
		t.Fatalf("expected EOF error")
	}
}

func TestIsCoinbaseTxInput(t *testing.T) {
	if !isCoinbaseTxInput(TxInput{PrevVout: ^uint32(0), Sequence: ^uint32(0)}) {
		t.Fatal("valid coinbase input should be detected")
	}
	if isCoinbaseTxInput(TxInput{PrevVout: 0, Sequence: ^uint32(0)}) {
		t.Fatal("non-max prevout should not be coinbase")
	}
	if isCoinbaseTxInput(TxInput{PrevVout: ^uint32(0), ScriptSig: []byte{0x01}, Sequence: ^uint32(0)}) {
		t.Fatal("non-empty script_sig should not be coinbase")
	}
	if isCoinbaseTxInput(TxInput{PrevVout: ^uint32(0), Sequence: 0}) {
		t.Fatal("non-max sequence should not be coinbase")
	}
}

func TestAddDACommitDuplicates(t *testing.T) {
	commits := make(map[[32]byte]daCommitSet)
	daID := filled32(0x01)
	tx := &Tx{DaCommitCore: &DaCommitCore{DaID: daID, ChunkCount: 1}}
	if err := addDACommit(commits, tx); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if err := addDACommit(commits, tx); err == nil {
		t.Fatal("duplicate da_id should error")
	}
}

func TestAddDACommitNilCore(t *testing.T) {
	commits := make(map[[32]byte]daCommitSet)
	if err := addDACommit(commits, &Tx{}); err == nil {
		t.Fatal("nil DaCommitCore should error")
	}
}

func TestAddDAChunkNilCore(t *testing.T) {
	chunks := make(map[[32]byte]map[uint16]*Tx)
	if err := addDAChunk(chunks, &Tx{}); err == nil {
		t.Fatal("nil DaChunkCore should error")
	}
}

func TestAddDAChunkDuplicateIndex(t *testing.T) {
	chunks := make(map[[32]byte]map[uint16]*Tx)
	daID := filled32(0x02)
	payload := []byte("test")
	chunkHash := sha3_256(payload)
	tx := &Tx{DaChunkCore: &DaChunkCore{DaID: daID, ChunkIndex: 0, ChunkHash: chunkHash}, DaPayload: payload}
	if err := addDAChunk(chunks, tx); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	if err := addDAChunk(chunks, tx); err == nil {
		t.Fatal("duplicate chunk index should error")
	}
}

func TestValidateDACommitChunkIntegrity_Edges(t *testing.T) {
	t.Run("empty commit set ok", func(t *testing.T) {
		if err := validateDACommitChunkIntegrity(nil, nil); err != nil {
			t.Fatalf("empty: %v", err)
		}
	})
	t.Run("no chunks for commit", func(t *testing.T) {
		daID := filled32(0x03)
		commits := map[[32]byte]daCommitSet{daID: {chunkCount: 1}}
		if err := validateDACommitChunkIntegrity(commits, nil); err == nil {
			t.Fatal("nil chunks should error")
		}
	})
}

func TestValidateDAPayloadCommitments_MissingOutput(t *testing.T) {
	daID := filled32(0x04)
	payload := []byte("payload")
	chunkHash := sha3_256(payload)
	commits := map[[32]byte]daCommitSet{daID: {tx: &Tx{Outputs: []TxOutput{}}, chunkCount: 1}}
	chunks := map[[32]byte]map[uint16]*Tx{daID: {0: {DaPayload: payload, DaChunkCore: &DaChunkCore{ChunkHash: chunkHash}}}}
	if err := validateDAPayloadCommitments(commits, chunks); err == nil {
		t.Fatal("missing da_commit output should error")
	}
}

func TestComputeTxBaseSize_WithDaCommitCore(t *testing.T) {
	// tx_kind=0x01 adds da_core fields to base size; tx_kind=0x00 ignores
	// da_core fields even when the core pointer is non-nil. Both txs share the
	// same non-DA skeleton — the size delta must exactly match
	// len(daCoreFieldsBytes(...)).
	txWithDA := &Tx{Version: 1, TxKind: 0x01, Inputs: []TxInput{{}}, DaCommitCore: &DaCommitCore{}}
	txKind00 := &Tx{Version: 1, TxKind: 0x00, Inputs: []TxInput{{}}, DaCommitCore: &DaCommitCore{}}

	withSize, _, err := computeTxBaseSize(txWithDA)
	if err != nil {
		t.Fatalf("tx_kind=0x01 with DaCommitCore: %v", err)
	}
	withoutSize, _, err := computeTxBaseSize(txKind00)
	if err != nil {
		t.Fatalf("tx_kind=0x00 baseline: %v", err)
	}

	daCoreBytes, err := daCoreFieldsBytes(txWithDA)
	if err != nil {
		t.Fatalf("daCoreFieldsBytes: %v", err)
	}
	wantDelta := uint64(len(daCoreBytes))

	if withSize != withoutSize+wantDelta {
		t.Fatalf("withDa=%d withoutDa=%d daCoreBytes=%d — delta should be exact", withSize, withoutSize, wantDelta)
	}
}

func TestAddOutputSizes_AnchorBytesEmpty(t *testing.T) {
	base, anchor, err := addOutputSizes(0, nil)
	if err != nil {
		t.Fatalf("empty outputs: %v", err)
	}
	if base != 0 || anchor != 0 {
		t.Fatalf("empty outputs: base=%d anchor=%d", base, anchor)
	}
}

func TestAddInputSizes_Empty(t *testing.T) {
	base, err := addInputSizes(0, nil)
	if err != nil {
		t.Fatalf("empty inputs: %v", err)
	}
	if base != 0 {
		t.Fatalf("empty inputs: base=%d", base)
	}
}

func TestValidateBlockResourceLimits_AllBounds(t *testing.T) {
	if err := validateBlockResourceLimits(&blockTxStats{sumWeight: MAX_BLOCK_WEIGHT + 1}); err == nil {
		t.Fatal("weight exceeded should error")
	}
	if err := validateBlockResourceLimits(&blockTxStats{sumDa: MAX_DA_BYTES_PER_BLOCK + 1}); err == nil {
		t.Fatal("da bytes exceeded should error")
	}
	if err := validateBlockResourceLimits(&blockTxStats{sumAnchor: MAX_ANCHOR_BYTES_PER_BLOCK + 1}); err == nil {
		t.Fatal("anchor bytes exceeded should error")
	}
}

func TestTxWeightComponents_NilTx(t *testing.T) {
	if _, _, _, err := txWeightComponents(nil, nil); err == nil {
		t.Fatal("nil tx should error")
	}
}

func TestComputeTxWitnessSentinel(t *testing.T) {
	tx := &Tx{Witness: []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}}
	witSize, sigCost, err := computeTxWitness(tx, func(w WitnessItem) (uint64, error) { return 1, nil })
	if err != nil {
		t.Fatalf("sentinel: %v", err)
	}
	if sigCost != 0 {
		t.Fatalf("sentinel sigCost=%d want 0", sigCost)
	}
	if witSize == 0 {
		t.Fatal("witnessSize=0")
	}
}

func TestComputeTxDASize_Coinbase(t *testing.T) {
	tx := &Tx{TxKind: 0x00, DaPayload: []byte{1, 2, 3}}
	daSize, daBytes := computeTxDASize(tx)
	if daBytes != 0 {
		t.Fatalf("daBytes for coinbase=%d want 0", daBytes)
	}
	if daSize == 0 {
		t.Fatal("daSize=0")
	}
}

func TestTxWeightAndStatsWithRegistry_NilAndFallback(t *testing.T) {
	if _, _, _, err := txWeightAndStatsWithRegistry(nil, 0, nil, nil); err == nil {
		t.Fatal("nil tx should error")
	}
	tx := &Tx{Version: 1, Inputs: []TxInput{{}}, Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}}}
	w, _, _, err := txWeightAndStatsWithRegistry(tx, 0, nil, nil)
	if err != nil {
		t.Fatalf("fallback to legacy: %v", err)
	}
	if w == 0 {
		t.Fatal("weight=0")
	}
}

func TestMulU64_Zero(t *testing.T) {
	if v, err := mulU64(0, ^uint64(0)); err != nil || v != 0 {
		t.Fatalf("mulU64(0,x)=%d,%v want 0,nil", v, err)
	}
	if v, err := mulU64(^uint64(0), 0); err != nil || v != 0 {
		t.Fatalf("mulU64(x,0)=%d,%v want 0,nil", v, err)
	}
}

func TestValidateParsedBlockBasicNil(t *testing.T) {
	if _, err := validateParsedBlockBasicWithContextAtHeight(nil, nil, nil, 0, nil, nil); err == nil {
		t.Fatal("nil pb should error")
	}
}

func TestAddWitnessItemSizeSentinel(t *testing.T) {
	w := WitnessItem{SuiteID: SUITE_ID_SENTINEL}
	_, sigCost, err := addWitnessItemSize(0, 5, w, func(w WitnessItem) (uint64, error) { return 10, nil })
	if err != nil {
		t.Fatalf("sentinel: %v", err)
	}
	if sigCost != 5 {
		t.Fatalf("sentinel sigCost=%d want 5 (unchanged)", sigCost)
	}
}

func TestAddWitnessItemSizeSigCostError(t *testing.T) {
	w := WitnessItem{SuiteID: 0x01, Pubkey: []byte{0x01}, Signature: []byte{0x02}}
	_, _, err := addWitnessItemSize(0, 0, w, func(w WitnessItem) (uint64, error) { return 0, txerr(TX_ERR_PARSE, "bad sig") })
	if err == nil {
		t.Fatal("sigCostFn error should propagate")
	}
}

func TestValidateDACommitChunkIndexes(t *testing.T) {
	if err := validateDACommitChunkIndexes(map[uint16]*Tx{}, 0); err != nil {
		t.Fatalf("empty chunkCount: %v", err)
	}
	set := map[uint16]*Tx{0: {}, 2: {}}
	if err := validateDACommitChunkIndexes(set, 2); err == nil {
		t.Fatal("missing idx=1 should error")
	}
}

func TestSortedDAIDs_Empty(t *testing.T) {
	if ids := sortedDAIDs(map[[32]byte]struct{}{}); len(ids) != 0 {
		t.Fatalf("empty sortedDAIDs: %v", ids)
	}
}

func TestCollectDACommitsAndChunks_Empty(t *testing.T) {
	commits, chunks, err := collectDACommitsAndChunks(nil)
	if err != nil {
		t.Fatalf("empty txs: %v", err)
	}
	if len(commits) != 0 || len(chunks) != 0 {
		t.Fatalf("empty txs: commits=%d chunks=%d", len(commits), len(chunks))
	}
}

func TestValidateDACommitChunkOrphans_NoCommits(t *testing.T) {
	daID := filled32(0x05)
	payload := []byte("test")
	chunkHash := sha3_256(payload)
	chunks := map[[32]byte]map[uint16]*Tx{daID: {0: {DaPayload: payload, DaChunkCore: &DaChunkCore{ChunkHash: chunkHash}}}}
	if err := validateDACommitChunkOrphans(nil, chunks); err == nil {
		t.Fatal("orphan chunks should error")
	}
}

func TestAddWitnessItemSerialSize_Empty(t *testing.T) {
	witSize, err := addWitnessItemSerialSize(10, WitnessItem{})
	if err != nil {
		t.Fatalf("empty witness: %v", err)
	}
	if witSize <= 10 {
		t.Fatalf("witnessSize=%d should be > 10", witSize)
	}
}

func TestAddDAChunkHashMismatch(t *testing.T) {
	chunks := make(map[[32]byte]map[uint16]*Tx)
	daID := filled32(0x06)
	payload := []byte("test")
	wrongHash := sha3_256([]byte("wrong"))
	tx := &Tx{DaChunkCore: &DaChunkCore{DaID: daID, ChunkIndex: 0, ChunkHash: wrongHash}, DaPayload: payload}
	if err := addDAChunk(chunks, tx); err == nil {
		t.Fatal("chunk hash mismatch should error")
	}
}

func TestValidateDAPayloadCommitments_InvalidCovenantDataLen(t *testing.T) {
	daID := filled32(0x07)
	payload := []byte("payload")
	chunkHash := sha3_256(payload)
	commits := map[[32]byte]daCommitSet{daID: {tx: &Tx{Outputs: []TxOutput{{CovenantType: COV_TYPE_DA_COMMIT, CovenantData: make([]byte, 16)}}}, chunkCount: 1}}
	chunks := map[[32]byte]map[uint16]*Tx{daID: {0: {DaPayload: payload, DaChunkCore: &DaChunkCore{ChunkHash: chunkHash}}}}
	if err := validateDAPayloadCommitments(commits, chunks); err == nil {
		t.Fatal("invalid covenant data length should error")
	}
}

func TestValidateDAPayloadCommitments_PayloadMismatch(t *testing.T) {
	daID := filled32(0x08)
	payload1 := []byte("chunk1")
	payload2 := []byte("chunk2") // different from payload1
	chunkHash1 := sha3_256(payload1)
	chunk0 := &Tx{DaPayload: payload1, DaChunkCore: &DaChunkCore{ChunkHash: chunkHash1}}
	chunk1 := &Tx{DaPayload: payload2, DaChunkCore: &DaChunkCore{ChunkHash: sha3_256(payload2)}}
	concat := append([]byte{}, payload1...)
	concat = append(concat, payload2...)
	expectedCommitment := sha3_256(concat)
	wrongCommitment := sha3_256([]byte("wrong"))
	_ = expectedCommitment // silence unused
	_ = wrongCommitment
	commits := map[[32]byte]daCommitSet{daID: {tx: &Tx{Outputs: []TxOutput{{CovenantType: COV_TYPE_DA_COMMIT, CovenantData: wrongCommitment[:]}}}, chunkCount: 2}}
	chunks := map[[32]byte]map[uint16]*Tx{daID: {0: chunk0, 1: chunk1}}
	if err := validateDAPayloadCommitments(commits, chunks); err == nil {
		t.Fatal("payload commitment mismatch should error")
	}
}

func TestValidateDACommitChunkIntegrity_ChunkCountZero(t *testing.T) {
	daID := filled32(0x09)
	commits := map[[32]byte]daCommitSet{daID: {chunkCount: 0}}
	if err := validateDACommitChunkIntegrity(commits, nil); err == nil {
		t.Fatal("chunkCount=0 should error")
	}
}

func TestValidateDACommitChunkIntegrity_LenMismatch(t *testing.T) {
	daID := filled32(0x0a)
	payload := []byte("test")
	chunkHash := sha3_256(payload)
	commits := map[[32]byte]daCommitSet{daID: {chunkCount: 1}}
	chunks := map[[32]byte]map[uint16]*Tx{daID: {0: {DaPayload: payload, DaChunkCore: &DaChunkCore{ChunkHash: chunkHash}}, 1: {DaPayload: payload, DaChunkCore: &DaChunkCore{ChunkHash: chunkHash}}}}
	if err := validateDACommitChunkIntegrity(commits, chunks); err == nil {
		t.Fatal("len mismatch should error")
	}
}

func TestValidateDAPayloadCommitments_DuplicateOutput(t *testing.T) {
	daID := filled32(0x0b)
	payload := []byte("payload")
	chunkHash := sha3_256(payload)
	commitment := chunkHash
	commits := map[[32]byte]daCommitSet{daID: {tx: &Tx{Outputs: []TxOutput{
		{CovenantType: COV_TYPE_DA_COMMIT, CovenantData: commitment[:]},
		{CovenantType: COV_TYPE_DA_COMMIT, CovenantData: commitment[:]},
	}}, chunkCount: 1}}
	chunks := map[[32]byte]map[uint16]*Tx{daID: {0: {DaPayload: payload, DaChunkCore: &DaChunkCore{ChunkHash: chunkHash}}}}
	if err := validateDAPayloadCommitments(commits, chunks); err == nil {
		t.Fatal("duplicate da_commit output should error")
	}
}

func TestValidateDACommitCompleteness_BatchExceeded(t *testing.T) {
	commits := make(map[[32]byte]daCommitSet)
	for i := 0; i < MAX_DA_BATCHES_PER_BLOCK+1; i++ {
		commits[filled32(byte(i))] = daCommitSet{}
	}
	if err := validateDACommitCompleteness(commits, nil); err == nil {
		t.Fatal("too many batches should error")
	}
}

func TestValidateDACommitChunkIntegrity_ChunkCountExceedsMax(t *testing.T) {
	daID := filled32(0x0c)
	commits := map[[32]byte]daCommitSet{daID: {chunkCount: MAX_DA_CHUNK_COUNT + 1}}
	if err := validateDACommitChunkIntegrity(commits, nil); err == nil {
		t.Fatal("chunk count > MAX should error")
	}
}
