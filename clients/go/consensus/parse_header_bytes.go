package consensus

import "fmt"

// ParseBlockHeaderBytes parses a canonical v1.1 BlockHeaderBytes (116 bytes) and
// rejects trailing bytes.
//
// This is intended for P2P `headers` payload parsing, where only headers (not full
// blocks) are transferred.
func ParseBlockHeaderBytes(b []byte) (BlockHeader, error) {
	cur := newCursor(b)
	h, err := ParseBlockHeader(cur)
	if err != nil {
		return BlockHeader{}, err
	}
	if cur.pos != len(b) {
		return BlockHeader{}, fmt.Errorf("BLOCK_ERR_PARSE")
	}
	return h, nil
}
