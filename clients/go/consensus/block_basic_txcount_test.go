package consensus

import (
	"encoding/binary"
	"testing"
)

// TestParseBlockBytes_HugeTxCountEOF verifies that a declared tx_count
// of MaxUint64 immediately followed by EOF does not panic and returns a
// parse error.  The implementation must not preallocate from the untrusted
// count.
func TestParseBlockBytes_HugeTxCountEOF(t *testing.T) {
	prev := filledHash(0x01)
	root := filledHash(0x02)
	target := filledHash(0xff)
	nonce := uint64(1)

	header := make([]byte, 0, BLOCK_HEADER_BYTES)
	header = AppendU32le(header, 1)
	header = append(header, prev[:]...)
	header = append(header, root[:]...)
	header = AppendU64le(header, 1)
	header = append(header, target[:]...)
	header = AppendU64le(header, nonce)

	b := make([]byte, 0, len(header)+9)
	b = append(b, header...)
	b = append(b, 0xff) // tag for u64 CompactSize
	count := make([]byte, 8)
	binary.LittleEndian.PutUint64(count, ^uint64(0)) // u64_max = 18446744073709551615
	b = append(b, count...)

	_, err := ParseBlockBytes(b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_PARSE)
	}
}

// TestParseBlockBytes_TxCount2Pow32EOF declares count=2^32 and delivers
// exactly one minimal transaction before EOF.  The loop must bail with a
// parse error, not allocate an enormous slice.
func TestParseBlockBytes_TxCount2Pow32EOF(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0xab)
	target := filledHash(0xff)

	// Build block with 2^32 tx_count (requires 0xff tag + u64).
	// Block payload: header + 0xff + (u64=4294967296) + 1 tx + EOF.
	b := make([]byte, 0, BLOCK_HEADER_BYTES+1+8+len(tx))
	header := make([]byte, 0, BLOCK_HEADER_BYTES)
	header = AppendU32le(header, 1)
	header = append(header, prev[:]...)
	header = append(header, root[:]...)
	header = AppendU64le(header, 1)
	header = append(header, target[:]...)
	header = AppendU64le(header, 9)
	b = append(b, header...)
	b = append(b, 0xff) // CompactSize u64 tag
	u64Count := make([]byte, 8)
	binary.LittleEndian.PutUint64(u64Count, uint64(1)<<32) // 4294967296
	b = append(b, u64Count...)
	b = append(b, tx...)

	_, err = ParseBlockBytes(b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_PARSE)
	}
}

// TestParseBlockBytes_TxCountTooSmall verifies that a tx_count smaller
// than the number of actual encoded transactions leaves trailing bytes
// and is rejected.
func TestParseBlockBytes_TxCountTooSmall(t *testing.T) {
	tx := minimalTxBytes()
	txid := testTxID(t, tx)
	root, err := MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := hashWithPrefix(0xac)
	target := filledHash(0xff)
	// Build with 2 identical txs then overwrite count to 1.
	block := buildBlockBytes(t, prev, root, target, 10, [][]byte{tx, tx})
	// Overwrite tx_count to 1 — leaving one tx as trailing bytes.
	block[BLOCK_HEADER_BYTES] = 0x01

	_, err = ParseBlockBytes(block)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_PARSE)
	}
}

// TestParseBlockBytes_MalformedCompactSizeEOF verifies that a malformed
// CompactSize (tag 0xfd but only one trailing byte) does not panic.
func TestParseBlockBytes_MalformedCompactSizeEOF(t *testing.T) {
	prev := filledHash(0x01)
	root := filledHash(0x02)
	target := filledHash(0xff)
	nonce := uint64(1)

	header := make([]byte, 0, BLOCK_HEADER_BYTES)
	header = AppendU32le(header, 1)
	header = append(header, prev[:]...)
	header = append(header, root[:]...)
	header = AppendU64le(header, 1)
	header = append(header, target[:]...)
	header = AppendU64le(header, nonce)

	b := make([]byte, 0, len(header)+2)
	b = append(b, header...)
	b = append(b, 0xfd, 0x01) // tag 0xfd needs 2 bytes; we give 1

	_, err := ParseBlockBytes(b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_PARSE)
	}
}
