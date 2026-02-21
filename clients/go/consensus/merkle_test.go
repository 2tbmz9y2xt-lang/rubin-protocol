package consensus

import "testing"

func TestMerkleRootTxids_Single(t *testing.T) {
	txBytes := minimalTxBytes()
	_, txid, _, _, err := ParseTx(txBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var pre [1 + 32]byte
	pre[0] = 0x00
	copy(pre[1:], txid[:])
	want := sha3_256(pre[:])
	if root != want {
		t.Fatalf("root mismatch")
	}
}

func TestMerkleRootTxids_Two(t *testing.T) {
	tx1 := minimalTxBytes()
	tx2 := append([]byte{}, tx1...)
	// Change locktime LSB (within core) to ensure different txid.
	tx2[4+1+8+1+1+0] = 0x01

	_, txid1, _, _, err := ParseTx(tx1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, txid2, _, _, err := ParseTx(tx2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	root, err := MerkleRootTxids([][32]byte{txid1, txid2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var leafPre [1 + 32]byte
	leafPre[0] = 0x00
	copy(leafPre[1:], txid1[:])
	leaf1 := sha3_256(leafPre[:])
	copy(leafPre[1:], txid2[:])
	leaf2 := sha3_256(leafPre[:])

	var nodePre [1 + 32 + 32]byte
	nodePre[0] = 0x01
	copy(nodePre[1:33], leaf1[:])
	copy(nodePre[33:], leaf2[:])
	want := sha3_256(nodePre[:])

	if root != want {
		t.Fatalf("root mismatch")
	}
}
