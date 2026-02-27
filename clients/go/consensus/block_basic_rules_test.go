package consensus

import "testing"

func buildBlockBytes(t *testing.T, prevHash [32]byte, merkleRoot [32]byte, target [32]byte, nonce uint64, txs [][]byte) []byte {
	t.Helper()
	if len(txs) == 0 {
		t.Fatalf("txs must not be empty")
	}

	header := make([]byte, 0, BLOCK_HEADER_BYTES)
	header = appendU32le(header, 1) // version
	header = append(header, prevHash[:]...)
	header = append(header, merkleRoot[:]...)
	header = appendU64le(header, 1) // timestamp
	header = append(header, target[:]...)
	header = appendU64le(header, nonce)
	if len(header) != BLOCK_HEADER_BYTES {
		t.Fatalf("header size=%d, want %d", len(header), BLOCK_HEADER_BYTES)
	}

	b := make([]byte, 0, len(header)+32)
	b = append(b, header...)
	b = appendCompactSize(b, uint64(len(txs)))
	for _, tx := range txs {
		b = append(b, tx...)
	}
	return b
}

func txWithOneOutput(value uint64, covenantType uint16, covenantData []byte) []byte {
	return txWithOutputs([]testOutput{
		{value: value, covenantType: covenantType, covenantData: covenantData},
	})
}

type testOutput struct {
	covenantData []byte
	value        uint64
	covenantType uint16
}

func txWithOutputs(outputs []testOutput) []byte {
	sizeHint := 96
	for _, out := range outputs {
		sizeHint += 16 + len(out.covenantData)
	}
	b := make([]byte, 0, sizeHint)
	b = appendU32le(b, 1) // version
	b = append(b, 0x00)   // tx_kind
	b = appendU64le(b, 0) // tx_nonce
	b = appendCompactSize(b, 0)
	b = appendCompactSize(b, uint64(len(outputs)))
	for _, out := range outputs {
		b = appendU64le(b, out.value)
		b = appendU16le(b, out.covenantType)
		b = appendCompactSize(b, uint64(len(out.covenantData)))
		b = append(b, out.covenantData...)
	}
	b = appendU32le(b, 0) // locktime
	b = appendCompactSize(b, 0)
	b = appendCompactSize(b, 0)
	return b
}

func coinbaseTxWithOutputs(locktime uint32, outputs []testOutput) []byte {
	sizeHint := 128
	for _, out := range outputs {
		sizeHint += 16 + len(out.covenantData)
	}
	b := make([]byte, 0, sizeHint)
	b = appendU32le(b, 1) // version
	b = append(b, 0x00)   // tx_kind
	b = appendU64le(b, 0) // tx_nonce
	b = appendCompactSize(b, 1)
	b = append(b, make([]byte, 32)...)
	b = appendU32le(b, ^uint32(0))
	b = appendCompactSize(b, 0) // script_sig_len
	b = appendU32le(b, ^uint32(0))
	b = appendCompactSize(b, uint64(len(outputs)))
	for _, out := range outputs {
		b = appendU64le(b, out.value)
		b = appendU16le(b, out.covenantType)
		b = appendCompactSize(b, uint64(len(out.covenantData)))
		b = append(b, out.covenantData...)
	}
	b = appendU32le(b, locktime)
	b = appendCompactSize(b, 0)
	b = appendCompactSize(b, 0)
	return b
}

func txWithOneInputOneOutputAndWitness(suiteID byte, pubkey []byte, signature []byte) []byte {
	outCov := validP2PKCovenantData()
	b := make([]byte, 0, 160+len(pubkey)+len(signature)+len(outCov))
	b = appendU32le(b, 1) // version
	b = append(b, 0x00)   // tx_kind
	b = appendU64le(b, 1) // tx_nonce
	b = appendCompactSize(b, 1)
	b = append(b, make([]byte, 32)...)
	b = appendU32le(b, 0)
	b = appendCompactSize(b, 0)
	b = appendU32le(b, 0)
	b = appendCompactSize(b, 1)
	b = appendU64le(b, 1)
	b = appendU16le(b, COV_TYPE_P2PK)
	b = appendCompactSize(b, uint64(len(outCov)))
	b = append(b, outCov...)
	b = appendU32le(b, 0)
	b = appendCompactSize(b, 1)
	b = append(b, suiteID)
	b = appendCompactSize(b, uint64(len(pubkey)))
	b = append(b, pubkey...)
	b = appendCompactSize(b, uint64(len(signature)))
	b = append(b, signature...)
	b = appendCompactSize(b, 0)
	return b
}

func coinbaseWithWitnessCommitment(t *testing.T, nonCoinbaseTxs ...[]byte) []byte {
	return coinbaseWithWitnessCommitmentAtHeight(t, 0, nonCoinbaseTxs...)
}

func coinbaseWithWitnessCommitmentAtHeight(t *testing.T, height uint64, nonCoinbaseTxs ...[]byte) []byte {
	t.Helper()

	wtxids := make([][32]byte, 1, 1+len(nonCoinbaseTxs))
	for _, txb := range nonCoinbaseTxs {
		_, _, wtxid, _, err := ParseTx(txb)
		if err != nil {
			t.Fatalf("ParseTx(non-coinbase): %v", err)
		}
		wtxids = append(wtxids, wtxid)
	}

	wroot, err := WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commit := WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
	})
}

func coinbaseWithWitnessCommitmentAndP2PKValue(t *testing.T, value uint64, nonCoinbaseTxs ...[]byte) []byte {
	return coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 0, value, nonCoinbaseTxs...)
}

func coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t *testing.T, height uint64, value uint64, nonCoinbaseTxs ...[]byte) []byte {
	t.Helper()

	wtxids := make([][32]byte, 1, 1+len(nonCoinbaseTxs))
	for _, txb := range nonCoinbaseTxs {
		_, _, wtxid, _, err := ParseTx(txb)
		if err != nil {
			t.Fatalf("ParseTx(non-coinbase): %v", err)
		}
		wtxids = append(wtxids, wtxid)
	}

	wroot, err := WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commit := WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: value, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()},
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
	})
}

func testTxID(t *testing.T, tx []byte) [32]byte {
	t.Helper()
	_, txid, _, _, err := ParseTx(tx)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	return txid
}

func hashWithPrefix(prefix byte) [32]byte {
	var out [32]byte
	out[0] = prefix
	return out
}

func filledHash(fill byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = fill
	}
	return out
}

func expectValidateBlockBasicErr(t *testing.T, block []byte, expectedPrev *[32]byte, expectedTarget *[32]byte, want ErrorCode) {
	t.Helper()
	_, err := ValidateBlockBasic(block, expectedPrev, expectedTarget)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != want {
		t.Fatalf("code=%s, want %s", got, want)
	}
}

func TestValidateBlockBasic_CovenantInvalid(t *testing.T) {
	// CORE_ANCHOR with non-zero value must fail covenant validation.
	tx := coinbaseTxWithOutputs(0, []testOutput{
		{value: 1, covenantType: COV_TYPE_ANCHOR, covenantData: []byte{0x01}},
	})
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0x88)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 21, [][]byte{tx})
	expectValidateBlockBasicErr(t, block, &prev, &target, TX_ERR_COVENANT_TYPE_INVALID)
}

func TestValidateBlockBasic_SubsidyExceeded(t *testing.T) {
	height := uint64(1)
	alreadyGenerated := uint64(0)
	sumFees := uint64(0)

	subsidy := BlockSubsidy(height, alreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+1)
	cbid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0x99)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 55, [][]byte{coinbase})
	_, err = ValidateBlockBasicWithContextAndFeesAtHeight(block, &prev, &target, height, nil, alreadyGenerated, sumFees)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_SUBSIDY_EXCEEDED {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_SUBSIDY_EXCEEDED)
	}
}

func TestValidateBlockBasic_SubsidyWithFeesOK(t *testing.T) {
	height := uint64(1)
	alreadyGenerated := uint64(0)
	sumFees := uint64(5)

	subsidy := BlockSubsidy(height, alreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+sumFees)
	cbid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0x9a)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 56, [][]byte{coinbase})
	if _, err := ValidateBlockBasicWithContextAndFeesAtHeight(block, &prev, &target, height, nil, alreadyGenerated, sumFees); err != nil {
		t.Fatalf("ValidateBlockBasicWithContextAndFeesAtHeight: %v", err)
	}
}

func TestValidateBlockBasic_SubsidyExceeded_CoinbaseSumUsesU128(t *testing.T) {
	height := uint64(1)
	alreadyGenerated := uint64(0)
	sumFees := uint64(0)

	wroot, err := WitnessMerkleRootWtxids([][32]byte{{}})
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commit := WitnessCommitmentHash(wroot)

	coinbase := coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: ^uint64(0), covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()},
		{value: ^uint64(0), covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()},
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
	})
	cbid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0x9b)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 57, [][]byte{coinbase})
	_, err = ValidateBlockBasicWithContextAndFeesAtHeight(block, &prev, &target, height, nil, alreadyGenerated, sumFees)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_SUBSIDY_EXCEEDED {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_SUBSIDY_EXCEEDED)
	}
}

func TestParseBlockBytes_OK(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0x11)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 7, [][]byte{tx})

	pb, err := ParseBlockBytes(block)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	if pb.TxCount != 1 || len(pb.Txs) != 1 || len(pb.Txids) != 1 {
		t.Fatalf("unexpected parsed sizes: tx_count=%d txs=%d txids=%d", pb.TxCount, len(pb.Txs), len(pb.Txids))
	}
}

func TestValidateBlockBasic_OK(t *testing.T) {
	tx := coinbaseWithWitnessCommitment(t)
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0x22)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 9, [][]byte{tx})
	s, err := ValidateBlockBasic(block, &prev, &target)
	if err != nil {
		t.Fatalf("ValidateBlockBasic: %v", err)
	}
	if s.TxCount != 1 {
		t.Fatalf("tx_count=%d, want 1", s.TxCount)
	}
}

func TestValidateBlockBasic_HeaderRuleErrors(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	baseTarget := filledHash(0xff)
	tinyTarget := [32]byte{}
	tinyTarget[31] = 0x01
	zeroTarget := [32]byte{}
	wrongTarget := filledHash(0xee)
	wrongPrev := hashWithPrefix(0x99)

	cases := []struct {
		name           string
		wantErr        ErrorCode
		nonce          uint64
		prev           [32]byte
		blockTarget    [32]byte
		expectedPrev   [32]byte
		expectedTarget [32]byte
		corruptRoot    bool
	}{
		{
			name:           "linkage_mismatch",
			prev:           hashWithPrefix(0x33),
			blockTarget:    baseTarget,
			expectedPrev:   wrongPrev,
			expectedTarget: baseTarget,
			nonce:          11,
			wantErr:        BLOCK_ERR_LINKAGE_INVALID,
		},
		{
			name:           "merkle_mismatch",
			prev:           hashWithPrefix(0x44),
			blockTarget:    baseTarget,
			expectedPrev:   hashWithPrefix(0x44),
			expectedTarget: baseTarget,
			nonce:          13,
			corruptRoot:    true,
			wantErr:        BLOCK_ERR_MERKLE_INVALID,
		},
		{
			name:           "pow_invalid",
			prev:           hashWithPrefix(0x55),
			blockTarget:    tinyTarget,
			expectedPrev:   hashWithPrefix(0x55),
			expectedTarget: tinyTarget,
			nonce:          15,
			wantErr:        BLOCK_ERR_POW_INVALID,
		},
		{
			name:           "target_range_invalid",
			prev:           hashWithPrefix(0x56),
			blockTarget:    zeroTarget,
			expectedPrev:   hashWithPrefix(0x56),
			expectedTarget: zeroTarget,
			nonce:          15,
			wantErr:        BLOCK_ERR_TARGET_INVALID,
		},
		{
			name:           "target_mismatch",
			prev:           hashWithPrefix(0x66),
			blockTarget:    baseTarget,
			expectedPrev:   hashWithPrefix(0x66),
			expectedTarget: wrongTarget,
			nonce:          17,
			wantErr:        BLOCK_ERR_TARGET_INVALID,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rootCase := root
			if tc.corruptRoot {
				rootCase[0] ^= 0xff
			}
			block := buildBlockBytes(t, tc.prev, rootCase, tc.blockTarget, tc.nonce, [][]byte{tx})
			expectValidateBlockBasicErr(t, block, &tc.expectedPrev, &tc.expectedTarget, tc.wantErr)
		})
	}
}

func TestParseBlockBytes_TrailingBytes(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0x77)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 19, [][]byte{tx})
	block = append(block, 0x00)
	_, err = ParseBlockBytes(block)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_PARSE)
	}
}

func TestValidateBlockBasic_NonCoinbaseMustHaveInput(t *testing.T) {
	invalidNonCoinbase := txWithOneOutput(1, COV_TYPE_P2PK, validP2PKCovenantData())
	coinbase := coinbaseWithWitnessCommitment(t, invalidNonCoinbase)

	cbid := testTxID(t, coinbase)
	ncid := testTxID(t, invalidNonCoinbase)
	root, err := MerkleRootTxids([][32]byte{cbid, ncid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0x88)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 23, [][]byte{coinbase, invalidNonCoinbase})

	expectValidateBlockBasicErr(t, block, &prev, &target, TX_ERR_PARSE)
}

func TestValidateBlockBasic_CoinbaseRuleErrors(t *testing.T) {
	target := filledHash(0xff)
	cases := []struct {
		blockFn func(t *testing.T, prev [32]byte, target [32]byte, nonce uint64) []byte
		name    string
		nonce   uint64
		height  uint64
		prev    [32]byte
	}{
		{
			name:   "first_tx_must_be_coinbase",
			prev:   hashWithPrefix(0x8a),
			nonce:  24,
			height: 0,
			blockFn: func(t *testing.T, prev [32]byte, target [32]byte, nonce uint64) []byte {
				tx := txWithOneOutput(0, COV_TYPE_ANCHOR, make([]byte, 32))
				root, err := MerkleRootTxids([][32]byte{testTxID(t, tx)})
				if err != nil {
					t.Fatalf("MerkleRootTxids: %v", err)
				}
				return buildBlockBytes(t, prev, root, target, nonce, [][]byte{tx})
			},
		},
		{
			name:   "coinbase_locktime_mismatch",
			prev:   hashWithPrefix(0x8b),
			nonce:  25,
			height: 7,
			blockFn: func(t *testing.T, prev [32]byte, target [32]byte, nonce uint64) []byte {
				coinbase := coinbaseWithWitnessCommitmentAtHeight(t, 6)
				root, err := MerkleRootTxids([][32]byte{testTxID(t, coinbase)})
				if err != nil {
					t.Fatalf("MerkleRootTxids: %v", err)
				}
				return buildBlockBytes(t, prev, root, target, nonce, [][]byte{coinbase})
			},
		},
		{
			name:   "coinbase_like_only_at_index_zero",
			prev:   hashWithPrefix(0x8c),
			nonce:  26,
			height: 0,
			blockFn: func(t *testing.T, prev [32]byte, target [32]byte, nonce uint64) []byte {
				coinbaseLike := coinbaseTxWithOutputs(0, []testOutput{
					{value: 1, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()},
				})
				coinbase := coinbaseWithWitnessCommitment(t, coinbaseLike)
				root, err := MerkleRootTxids([][32]byte{testTxID(t, coinbase), testTxID(t, coinbaseLike)})
				if err != nil {
					t.Fatalf("MerkleRootTxids: %v", err)
				}
				return buildBlockBytes(t, prev, root, target, nonce, [][]byte{coinbase, coinbaseLike})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block := tc.blockFn(t, tc.prev, target, tc.nonce)
			_, err := ValidateBlockBasicAtHeight(block, &tc.prev, &target, tc.height)
			if err == nil {
				t.Fatalf("expected error")
			}
			if got := mustTxErrCode(t, err); got != BLOCK_ERR_COINBASE_INVALID {
				t.Fatalf("code=%s, want %s", got, BLOCK_ERR_COINBASE_INVALID)
			}
		})
	}
}

func TestValidateBlockBasic_WitnessCommitmentMissing(t *testing.T) {
	tx := coinbaseTxWithOutputs(0, []testOutput{
		{value: 1, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()},
	})
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0x90)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 25, [][]byte{tx})
	expectValidateBlockBasicErr(t, block, &prev, &target, BLOCK_ERR_WITNESS_COMMITMENT)
}

func TestValidateBlockBasic_WitnessCommitmentDuplicate(t *testing.T) {
	cbSingle := coinbaseWithWitnessCommitment(t)
	_, _, wtxid, _, err := ParseTx(cbSingle)
	if err != nil {
		t.Fatalf("ParseTx(cbSingle): %v", err)
	}
	wroot, err := WitnessMerkleRootWtxids([][32]byte{wtxid})
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commit := WitnessCommitmentHash(wroot)
	tx := coinbaseTxWithOutputs(0, []testOutput{
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
	})

	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	prev := hashWithPrefix(0x91)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 27, [][]byte{tx})
	expectValidateBlockBasicErr(t, block, &prev, &target, BLOCK_ERR_WITNESS_COMMITMENT)
}

func TestValidateBlockBasic_SLHInactiveAtHeight(t *testing.T) {
	pub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	sig := []byte{0x01}
	height := uint64(SLH_DSA_ACTIVATION_HEIGHT - 1)
	nonCoinbase := txWithOneInputOneOutputAndWitness(SUITE_ID_SLH_DSA_SHAKE_256F, pub, sig)
	coinbase := coinbaseWithWitnessCommitmentAtHeight(t, height, nonCoinbase)

	cbid := testTxID(t, coinbase)
	ncid := testTxID(t, nonCoinbase)
	root, err := MerkleRootTxids([][32]byte{cbid, ncid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	prev := hashWithPrefix(0xa1)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 29, [][]byte{coinbase, nonCoinbase})

	_, err = ValidateBlockBasicAtHeight(block, &prev, &target, height)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}

func TestValidateBlockBasic_SLHActiveAtHeight(t *testing.T) {
	pub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	sig := []byte{0x01}
	height := uint64(SLH_DSA_ACTIVATION_HEIGHT)
	nonCoinbase := txWithOneInputOneOutputAndWitness(SUITE_ID_SLH_DSA_SHAKE_256F, pub, sig)
	coinbase := coinbaseWithWitnessCommitmentAtHeight(t, height, nonCoinbase)

	cbid := testTxID(t, coinbase)
	ncid := testTxID(t, nonCoinbase)
	root, err := MerkleRootTxids([][32]byte{cbid, ncid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	prev := hashWithPrefix(0xa2)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 31, [][]byte{coinbase, nonCoinbase})

	if _, err := ValidateBlockBasicAtHeight(block, &prev, &target, height); err != nil {
		t.Fatalf("ValidateBlockBasicAtHeight: %v", err)
	}
}

func TestAddU64_Overflow(t *testing.T) {
	if _, err := addU64(^uint64(0), 1); err == nil {
		t.Fatalf("expected overflow error")
	}
}
