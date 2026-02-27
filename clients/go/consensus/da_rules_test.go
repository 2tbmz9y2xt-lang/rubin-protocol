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
	b = AppendU32le(b, 1)
	b = append(b, 0x01)
	b = AppendU64le(b, txNonce)
	b = AppendCompactSize(b, 1)
	prevTxid := filled32(byte(txNonce))
	b = append(b, prevTxid[:]...)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 1)
	b = AppendU64le(b, 0)
	b = AppendU16le(b, COV_TYPE_DA_COMMIT)
	b = AppendCompactSize(b, 32)
	b = append(b, payloadCommitment[:]...)
	b = AppendU32le(b, 0)
	b = append(b, daID[:]...)
	b = AppendU16le(b, chunkCount)
	retlDomain := filled32(0x10)
	b = append(b, retlDomain[:]...)
	b = AppendU64le(b, 1)
	txDataRoot := filled32(0x11)
	b = append(b, txDataRoot[:]...)
	stateRoot := filled32(0x12)
	b = append(b, stateRoot[:]...)
	withdrawalsRoot := filled32(0x13)
	b = append(b, withdrawalsRoot[:]...)
	b = append(b, 0x00)
	b = AppendCompactSize(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendCompactSize(b, 0)
	return b
}

func daChunkTxBytes(txNonce uint64, daID [32]byte, chunkIndex uint16, chunkHash [32]byte, payload []byte) []byte {
	b := make([]byte, 0, 192+len(payload))
	b = AppendU32le(b, 1)
	b = append(b, 0x02)
	b = AppendU64le(b, txNonce)
	b = AppendCompactSize(b, 1)
	prevTxid := filled32(byte(txNonce + 0x10))
	b = append(b, prevTxid[:]...)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendU32le(b, 0)
	b = append(b, daID[:]...)
	b = AppendU16le(b, chunkIndex)
	b = append(b, chunkHash[:]...)
	b = AppendCompactSize(b, 0)
	b = AppendCompactSize(b, uint64(len(payload)))
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
	tests := []struct {
		name          string
		wantErrorCode ErrorCode
		daSeed        byte
		mutateCommit  bool
		mutateChunk   bool
	}{
		{
			name:          "chunk hash mismatch",
			daSeed:        0xa2,
			mutateCommit:  false,
			mutateChunk:   true,
			wantErrorCode: BLOCK_ERR_DA_CHUNK_HASH_INVALID,
		},
		{
			name:          "payload commitment mismatch",
			daSeed:        0xa3,
			mutateCommit:  true,
			mutateChunk:   false,
			wantErrorCode: BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			daID := filled32(test.daSeed)
			payload := []byte("abc")
			payloadCommitment := sha3_256(payload)
			commitment := payloadCommitment
			if test.mutateCommit {
				commitment[0] ^= 0x01
			}

			chunkHash := sha3_256(payload)
			if test.mutateChunk {
				chunkHash[0] ^= 0x01
			}

			commitTx := daCommitTxBytes(1, daID, 1, commitment)
			chunkTx := daChunkTxBytes(2, daID, 0, chunkHash, payload)
			block, prev, target := buildDABlockBytes(t, commitTx, chunkTx)

			_, err := ValidateBlockBasic(block, &prev, &target)
			if err == nil {
				t.Fatalf("expected error")
			}
			if got := mustTxErrCode(t, err); got != test.wantErrorCode {
				t.Fatalf("code=%s, want %s", got, test.wantErrorCode)
			}
		})
	}
}

func mustParseTx(t *testing.T, txBytes []byte) *Tx {
	t.Helper()
	tx, _, _, _, err := ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	return tx
}

func daCommitTxBytesNoOutputs(txNonce uint64, daID [32]byte, chunkCount uint16) []byte {
	b := make([]byte, 0, 320)
	b = AppendU32le(b, 1)
	b = append(b, 0x01)
	b = AppendU64le(b, txNonce)
	b = AppendCompactSize(b, 1)
	prevTxid := filled32(byte(txNonce))
	b = append(b, prevTxid[:]...)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 0) // output_count
	b = AppendU32le(b, 0)
	b = append(b, daID[:]...)
	b = AppendU16le(b, chunkCount)
	retlDomain := filled32(0x10)
	b = append(b, retlDomain[:]...)
	b = AppendU64le(b, 1)
	txDataRoot := filled32(0x11)
	b = append(b, txDataRoot[:]...)
	stateRoot := filled32(0x12)
	b = append(b, stateRoot[:]...)
	withdrawalsRoot := filled32(0x13)
	b = append(b, withdrawalsRoot[:]...)
	b = append(b, 0x00)
	b = AppendCompactSize(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendCompactSize(b, 0)
	return b
}

func daCommitTxBytesDuplicateOutputs(txNonce uint64, daID [32]byte, chunkCount uint16, payloadCommitment [32]byte) []byte {
	b := make([]byte, 0, 384)
	b = AppendU32le(b, 1)
	b = append(b, 0x01)
	b = AppendU64le(b, txNonce)
	b = AppendCompactSize(b, 1)
	prevTxid := filled32(byte(txNonce))
	b = append(b, prevTxid[:]...)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 2) // output_count
	for i := 0; i < 2; i++ {
		b = AppendU64le(b, 0)
		b = AppendU16le(b, COV_TYPE_DA_COMMIT)
		b = AppendCompactSize(b, 32)
		b = append(b, payloadCommitment[:]...)
	}
	b = AppendU32le(b, 0)
	b = append(b, daID[:]...)
	b = AppendU16le(b, chunkCount)
	retlDomain := filled32(0x10)
	b = append(b, retlDomain[:]...)
	b = AppendU64le(b, 1)
	txDataRoot := filled32(0x11)
	b = append(b, txDataRoot[:]...)
	stateRoot := filled32(0x12)
	b = append(b, stateRoot[:]...)
	withdrawalsRoot := filled32(0x13)
	b = append(b, withdrawalsRoot[:]...)
	b = append(b, 0x00)
	b = AppendCompactSize(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendCompactSize(b, 0)
	return b
}

func TestValidateBlockBasic_DA_DuplicateCommit(t *testing.T) {
	daID := filled32(0xc1)
	commitment := filled32(0xc2)
	commit1 := daCommitTxBytes(1, daID, 1, commitment)
	commit2 := daCommitTxBytes(2, daID, 1, commitment)
	block, prev, target := buildDABlockBytes(t, commit1, commit2)

	_, err := ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_SET_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_SET_INVALID)
	}
}

func TestValidateBlockBasic_DA_ChunksWithoutCommit(t *testing.T) {
	daID := filled32(0xc3)
	payload := []byte("abc")
	chunk := daChunkTxBytes(1, daID, 0, sha3_256(payload), payload)
	block, prev, target := buildDABlockBytes(t, chunk)

	_, err := ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_SET_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_SET_INVALID)
	}
}

func TestValidateBlockBasic_DA_CommitWithoutChunks(t *testing.T) {
	daID := filled32(0xc4)
	commitment := filled32(0xc5)
	commit := daCommitTxBytes(1, daID, 1, commitment)
	block, prev, target := buildDABlockBytes(t, commit)

	_, err := ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_INCOMPLETE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_INCOMPLETE)
	}
}

func TestValidateBlockBasic_DA_ChunkCountMismatch(t *testing.T) {
	daID := filled32(0xc6)
	payload := []byte("abc")
	payloadCommitment := sha3_256(payload)

	commit := daCommitTxBytes(1, daID, 2, payloadCommitment)
	chunk := daChunkTxBytes(2, daID, 0, sha3_256(payload), payload)
	block, prev, target := buildDABlockBytes(t, commit, chunk)

	_, err := ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_INCOMPLETE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_INCOMPLETE)
	}
}

func TestValidateBlockBasic_DA_MissingChunkIndex(t *testing.T) {
	daID := filled32(0xc7)
	p0 := []byte("aaa")
	p2 := []byte("bbb")
	concat := append(append([]byte(nil), p0...), p2...)
	payloadCommitment := sha3_256(concat)

	commit := daCommitTxBytes(1, daID, 2, payloadCommitment)
	chunk0 := daChunkTxBytes(2, daID, 0, sha3_256(p0), p0)
	chunk2 := daChunkTxBytes(3, daID, 2, sha3_256(p2), p2)
	block, prev, target := buildDABlockBytes(t, commit, chunk0, chunk2)

	_, err := ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_INCOMPLETE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_INCOMPLETE)
	}
}

func TestValidateBlockBasic_DA_DuplicateChunkIndex(t *testing.T) {
	daID := filled32(0xc8)
	p0 := []byte("aaa")
	p0b := []byte("bbb")
	payloadCommitment := sha3_256(append(append([]byte(nil), p0...), p0b...))

	commit := daCommitTxBytes(1, daID, 2, payloadCommitment)
	chunk0 := daChunkTxBytes(2, daID, 0, sha3_256(p0), p0)
	chunk0dup := daChunkTxBytes(3, daID, 0, sha3_256(p0b), p0b)
	block, prev, target := buildDABlockBytes(t, commit, chunk0, chunk0dup)

	_, err := ValidateBlockBasic(block, &prev, &target)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_SET_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_SET_INVALID)
	}
}

func TestValidateDASetIntegrity_TooManyCommits(t *testing.T) {
	txs := make([]*Tx, 0, MAX_DA_BATCHES_PER_BLOCK+1)
	for i := 0; i < MAX_DA_BATCHES_PER_BLOCK+1; i++ {
		daID := filled32(byte(i))
		commit := daCommitTxBytes(uint64(i+1), daID, 1, filled32(0x42))
		txs = append(txs, mustParseTx(t, commit))
	}

	err := validateDASetIntegrity(txs)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_BATCH_EXCEEDED {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_BATCH_EXCEEDED)
	}
}

func TestValidateBlockBasic_DA_CommitOutputMissingOrDuplicated(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		daID := filled32(0xc9)
		payload := []byte("abc")

		commit := daCommitTxBytesNoOutputs(1, daID, 1)
		chunk := daChunkTxBytes(2, daID, 0, sha3_256(payload), payload)
		block, prev, target := buildDABlockBytes(t, commit, chunk)

		_, err := ValidateBlockBasic(block, &prev, &target)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID {
			t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID)
		}
	})

	t.Run("duplicated", func(t *testing.T) {
		daID := filled32(0xca)
		payload := []byte("abc")
		payloadCommitment := sha3_256(payload)

		commit := daCommitTxBytesDuplicateOutputs(1, daID, 1, payloadCommitment)
		chunk := daChunkTxBytes(2, daID, 0, sha3_256(payload), payload)
		block, prev, target := buildDABlockBytes(t, commit, chunk)

		_, err := ValidateBlockBasic(block, &prev, &target)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID {
			t.Fatalf("code=%s, want %s", got, BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID)
		}
	})
}
