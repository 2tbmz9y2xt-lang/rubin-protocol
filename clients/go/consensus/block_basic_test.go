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
	b := make([]byte, 0, 128+len(covenantData))
	b = appendU32le(b, 1) // version
	b = append(b, 0x00)   // tx_kind
	b = appendU64le(b, 0) // tx_nonce
	b = appendCompactSize(b, 0)
	b = appendCompactSize(b, 1)
	b = appendU64le(b, value)
	b = appendU16le(b, covenantType)
	b = appendCompactSize(b, uint64(len(covenantData)))
	b = append(b, covenantData...)
	b = appendU32le(b, 0) // locktime
	b = appendCompactSize(b, 0)
	b = appendCompactSize(b, 0)
	return b
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
	tx := minimalTxBytes()
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
	var zeroTarget [32]byte // all zeros => impossible strict-less
	block := buildBlockBytes(t, prev, root, zeroTarget, 15, [][]byte{tx})
	_, err = ValidateBlockBasic(block, &prev, &zeroTarget)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_POW_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_POW_INVALID)
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
