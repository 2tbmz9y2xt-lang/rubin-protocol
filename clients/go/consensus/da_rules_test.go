package consensus

import "testing"

func filled32(v byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = v
	}
	return out
}

func daCommitTxBytes(txNonce uint64, daID [32]byte, chunkCount uint16, payloadCommitment [32]byte) []byte {
	b := make([]byte, 0, 320)
	b = appendU32le(b, 1)
	b = append(b, 0x01)
	b = appendU64le(b, txNonce)
	b = appendCompactSize(b, 1)
	prevTxid := filled32(byte(txNonce))
	b = append(b, prevTxid[:]...)
	b = appendU32le(b, 0)
	b = appendCompactSize(b, 0)
	b = appendU32le(b, 0)
	b = appendCompactSize(b, 1)
	b = appendU64le(b, 0)
	b = appendU16le(b, COV_TYPE_DA_COMMIT)
	b = appendCompactSize(b, 32)
	b = append(b, payloadCommitment[:]...)
	b = appendU32le(b, 0)
	b = append(b, daID[:]...)
	b = appendU16le(b, chunkCount)
	retlDomain := filled32(0x10)
	b = append(b, retlDomain[:]...)
	b = appendU64le(b, 1)
	txDataRoot := filled32(0x11)
	b = append(b, txDataRoot[:]...)
	stateRoot := filled32(0x12)
	b = append(b, stateRoot[:]...)
	withdrawalsRoot := filled32(0x13)
	b = append(b, withdrawalsRoot[:]...)
	b = append(b, 0x00)
	b = appendCompactSize(b, 0)
	b = appendCompactSize(b, 0)
	b = appendCompactSize(b, 0)
	return b
}

func daChunkTxBytes(txNonce uint64, daID [32]byte, chunkIndex uint16, chunkHash [32]byte, payload []byte) []byte {
	b := make([]byte, 0, 192+len(payload))
	b = appendU32le(b, 1)
	b = append(b, 0x02)
	b = appendU64le(b, txNonce)
	b = appendCompactSize(b, 1)
	prevTxid := filled32(byte(txNonce + 0x10))
	b = append(b, prevTxid[:]...)
	b = appendU32le(b, 0)
	b = appendCompactSize(b, 0)
	b = appendU32le(b, 0)
	b = appendCompactSize(b, 0)
	b = appendU32le(b, 0)
	b = append(b, daID[:]...)
	b = appendU16le(b, chunkIndex)
	b = append(b, chunkHash[:]...)
	b = appendCompactSize(b, 0)
	b = appendCompactSize(b, uint64(len(payload)))
	b = append(b, payload...)
	return b
}

func buildDABlockBytes(t *testing.T, daTxs ...[]byte) ([]byte, [32]byte, [32]byte) {
	t.Helper()
	coinbase := coinbaseWithWitnessCommitment(t, daTxs...)
	txs := make([][]byte, 0, len(daTxs)+1)
	txs = append(txs, coinbase)
	txs = append(txs, daTxs...)
	txids := make([][32]byte, 0, len(txs))
	for _, txb := range txs {
		txids = append(txids, testTxID(t, txb))
	}
	root, err := MerkleRootTxids(txids)
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	prev := filled32(0x91)
	target := filled32(0xff)
	return buildBlockBytes(t, prev, root, target, 31, txs), prev, target
}

func TestParseTx_DACommitChunkCountZero(t *testing.T) {
	daID := filled32(0xa1)
	commitment := filled32(0xb2)
	txBytes := daCommitTxBytes(1, daID, 0, commitment)
	_, _, _, _, err := ParseTx(txBytes)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateBlockBasic_DAChunkHashMismatch(t *testing.T) {
	daID := filled32(0xa2)
	payload := []byte("abc")
	payloadCommitment := sha3_256(payload)
	commitTx := daCommitTxBytes(1, daID, 1, payloadCommitment)
	chunkHash := sha3_256(payload)
	chunkHash[0] ^= 0x01
	chunkTx := daChunkTxBytes(2, daID, 0, chunkHash, payload)
	block, prev, target := buildDABlockBytes(t, commitTx, chunkTx)
	_, err := ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_CHUNK_HASH_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_CHUNK_HASH_INVALID)
	}
}

func TestValidateBlockBasic_DAPayloadCommitmentMismatch(t *testing.T) {
	daID := filled32(0xa3)
	payload := []byte("abc")
	payloadCommitment := sha3_256(payload)
	wrongCommitment := payloadCommitment
	wrongCommitment[0] ^= 0x01
	commitTx := daCommitTxBytes(1, daID, 1, wrongCommitment)
	chunkHash := sha3_256(payload)
	chunkTx := daChunkTxBytes(2, daID, 0, chunkHash, payload)
	block, prev, target := buildDABlockBytes(t, commitTx, chunkTx)
	_, err := ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID)
	}
}
