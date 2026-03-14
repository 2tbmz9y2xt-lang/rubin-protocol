package consensus

import (
	"bytes"
	"testing"
)

func txWithNonceAndOutputs(nonce uint64, outputs []testOutput) []byte {
	sizeHint := 128
	for _, out := range outputs {
		sizeHint += 16 + len(out.covenantData)
	}
	b := make([]byte, 0, sizeHint)
	b = AppendU32le(b, 1)     // version
	b = append(b, 0x00)       // tx_kind
	b = AppendU64le(b, nonce) // tx_nonce
	b = AppendCompactSize(b, 1)
	b = append(b, make([]byte, 32)...)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, uint64(len(outputs)))
	for _, out := range outputs {
		b = AppendU64le(b, out.value)
		b = AppendU16le(b, out.covenantType)
		b = AppendCompactSize(b, uint64(len(out.covenantData)))
		b = append(b, out.covenantData...)
	}
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendCompactSize(b, 0)
	return b
}

func repeatedAnchorOutputs(count int, payloadLen int) []testOutput {
	outputs := make([]testOutput, count)
	for i := range outputs {
		outputs[i] = testOutput{
			value:        0,
			covenantType: COV_TYPE_ANCHOR,
			covenantData: bytes.Repeat([]byte{byte(0x40 + i%127)}, payloadLen),
		}
	}
	return outputs
}

func TestValidateBlockBasic_AnchorBytesPrecedeNonceReplay(t *testing.T) {
	oversizedAnchorTx := txWithNonceAndOutputs(1, repeatedAnchorOutputs(3, 50_000))
	duplicateNonceTx := txWithNonceAndOutputs(1, []testOutput{
		{value: 1, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()},
	})
	coinbase := coinbaseWithWitnessCommitmentAtHeight(t, 1, oversizedAnchorTx, duplicateNonceTx)

	cbid := testTxID(t, coinbase)
	tx1id := testTxID(t, oversizedAnchorTx)
	tx2id := testTxID(t, duplicateNonceTx)
	root, err := MerkleRootTxids([][32]byte{cbid, tx1id, tx2id})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0xa1)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 41, [][]byte{coinbase, oversizedAnchorTx, duplicateNonceTx})

	_, err = ValidateBlockBasicAtHeight(block, &prev, &target, 1)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_ANCHOR_BYTES_EXCEEDED {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_ANCHOR_BYTES_EXCEEDED)
	}
}

func TestValidateBlockBasic_WeightPrecedesNonceReplay(t *testing.T) {
	overweightTx := txWithNonceAndOutputs(1, repeatedAnchorOutputs(1024, 17_000))
	duplicateNonceTx := txWithNonceAndOutputs(1, []testOutput{
		{value: 1, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()},
	})
	coinbase := coinbaseWithWitnessCommitmentAtHeight(t, 1, overweightTx, duplicateNonceTx)

	cbid := testTxID(t, coinbase)
	tx1id := testTxID(t, overweightTx)
	tx2id := testTxID(t, duplicateNonceTx)
	root, err := MerkleRootTxids([][32]byte{cbid, tx1id, tx2id})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0xa2)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 42, [][]byte{coinbase, overweightTx, duplicateNonceTx})

	_, err = ValidateBlockBasicAtHeight(block, &prev, &target, 1)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_WEIGHT_EXCEEDED {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_WEIGHT_EXCEEDED)
	}
}

func TestValidateBlockBasic_AnchorBytesPrecedeCoinbaseStructure(t *testing.T) {
	oversizedAnchorTx := txWithNonceAndOutputs(1, repeatedAnchorOutputs(3, 50_000))
	coinbase := coinbaseWithWitnessCommitmentAtHeight(t, 0, oversizedAnchorTx)

	cbid := testTxID(t, coinbase)
	txid := testTxID(t, oversizedAnchorTx)
	root, err := MerkleRootTxids([][32]byte{cbid, txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0xa3)
	target := filledHash(0xff)
	block := buildBlockBytes(t, prev, root, target, 43, [][]byte{coinbase, oversizedAnchorTx})

	_, err = ValidateBlockBasicAtHeight(block, &prev, &target, 1)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_ANCHOR_BYTES_EXCEEDED {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_ANCHOR_BYTES_EXCEEDED)
	}
}
