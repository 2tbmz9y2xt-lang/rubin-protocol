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
	value        uint64
	covenantType uint16
	covenantData []byte
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
	return txWithOneOutput(0, COV_TYPE_ANCHOR, commit[:])
}

func testTxID(t *testing.T, tx []byte) [32]byte {
	t.Helper()
	_, txid, _, _, err := ParseTx(tx)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	return txid
}

func TestValidateBlockBasic_CovenantInvalid(t *testing.T) {
	// CORE_ANCHOR with non-zero value must fail covenant validation.
	tx := txWithOneOutput(1, COV_TYPE_ANCHOR, []byte{0x01})
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	var prev [32]byte
	prev[0] = 0x88
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	block := buildBlockBytes(t, prev, root, target, 21, [][]byte{tx})
	_, err = ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestParseBlockBytes_OK(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	var prev [32]byte
	prev[0] = 0x11
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
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

	var prev [32]byte
	prev[0] = 0x22
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	block := buildBlockBytes(t, prev, root, target, 9, [][]byte{tx})
	s, err := ValidateBlockBasic(block, &prev, &target)
	if err != nil {
		t.Fatalf("ValidateBlockBasic: %v", err)
	}
	if s.TxCount != 1 {
		t.Fatalf("tx_count=%d, want 1", s.TxCount)
	}
}

func TestValidateBlockBasic_LinkageMismatch(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	var prev [32]byte
	prev[0] = 0x33
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	block := buildBlockBytes(t, prev, root, target, 11, [][]byte{tx})
	var wrongPrev [32]byte
	wrongPrev[0] = 0x99
	_, err = ValidateBlockBasic(block, &wrongPrev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_LINKAGE_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_LINKAGE_INVALID)
	}
}

func TestValidateBlockBasic_MerkleMismatch(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	root[0] ^= 0xff // corrupt

	var prev [32]byte
	prev[0] = 0x44
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	block := buildBlockBytes(t, prev, root, target, 13, [][]byte{tx})
	_, err = ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_MERKLE_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_MERKLE_INVALID)
	}
}

func TestValidateBlockBasic_PowInvalid(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	var prev [32]byte
	prev[0] = 0x55
	var tinyTarget [32]byte
	tinyTarget[31] = 0x01 // positive and valid range, but effectively impossible strict-less
	block := buildBlockBytes(t, prev, root, tinyTarget, 15, [][]byte{tx})
	_, err = ValidateBlockBasic(block, &prev, &tinyTarget)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_POW_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_POW_INVALID)
	}
}

func TestValidateBlockBasic_TargetRangeInvalid(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	var prev [32]byte
	prev[0] = 0x56
	var zeroTarget [32]byte
	block := buildBlockBytes(t, prev, root, zeroTarget, 15, [][]byte{tx})
	_, err = ValidateBlockBasic(block, &prev, &zeroTarget)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_TARGET_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_TARGET_INVALID)
	}
}

func TestValidateBlockBasic_TargetMismatch(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	var prev [32]byte
	prev[0] = 0x66
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	block := buildBlockBytes(t, prev, root, target, 17, [][]byte{tx})
	var wrongTarget [32]byte
	for i := range wrongTarget {
		wrongTarget[i] = 0xee
	}
	_, err = ValidateBlockBasic(block, &prev, &wrongTarget)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_TARGET_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_TARGET_INVALID)
	}
}

func TestParseBlockBytes_TrailingBytes(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	var prev [32]byte
	prev[0] = 0x77
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
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

	var prev [32]byte
	prev[0] = 0x88
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	block := buildBlockBytes(t, prev, root, target, 23, [][]byte{coinbase, invalidNonCoinbase})

	_, err = ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateBlockBasic_WitnessCommitmentMissing(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	var prev [32]byte
	prev[0] = 0x90
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	block := buildBlockBytes(t, prev, root, target, 25, [][]byte{tx})
	_, err = ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_WITNESS_COMMITMENT {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_WITNESS_COMMITMENT)
	}
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
	tx := txWithOutputs([]testOutput{
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
	})

	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	var prev [32]byte
	prev[0] = 0x91
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	block := buildBlockBytes(t, prev, root, target, 27, [][]byte{tx})
	_, err = ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_WITNESS_COMMITMENT {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_WITNESS_COMMITMENT)
	}
}

func TestValidateBlockBasic_SLHInactiveAtHeight(t *testing.T) {
	pub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	sig := []byte{0x01}
	nonCoinbase := txWithOneInputOneOutputAndWitness(SUITE_ID_SLH_DSA_SHAKE_256F, pub, sig)
	coinbase := coinbaseWithWitnessCommitment(t, nonCoinbase)

	cbid := testTxID(t, coinbase)
	ncid := testTxID(t, nonCoinbase)
	root, err := MerkleRootTxids([][32]byte{cbid, ncid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	var prev [32]byte
	prev[0] = 0xa1
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	block := buildBlockBytes(t, prev, root, target, 29, [][]byte{coinbase, nonCoinbase})

	_, err = ValidateBlockBasicAtHeight(block, &prev, &target, SLH_DSA_ACTIVATION_HEIGHT-1)
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
	nonCoinbase := txWithOneInputOneOutputAndWitness(SUITE_ID_SLH_DSA_SHAKE_256F, pub, sig)
	coinbase := coinbaseWithWitnessCommitment(t, nonCoinbase)

	cbid := testTxID(t, coinbase)
	ncid := testTxID(t, nonCoinbase)
	root, err := MerkleRootTxids([][32]byte{cbid, ncid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	var prev [32]byte
	prev[0] = 0xa2
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	block := buildBlockBytes(t, prev, root, target, 31, [][]byte{coinbase, nonCoinbase})

	if _, err := ValidateBlockBasicAtHeight(block, &prev, &target, SLH_DSA_ACTIVATION_HEIGHT); err != nil {
		t.Fatalf("ValidateBlockBasicAtHeight: %v", err)
	}
}
