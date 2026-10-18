package consensus

import (
	"bytes"
	"encoding/binary"
)

// Initial148HeaderBytes is the canonical initial-format header width.
const Initial148HeaderBytes = 148

// Initial148Header is a value-owned initial-format header. Every field value is
// structurally admissible; block validity is a separate consumer responsibility.
type Initial148Header struct {
	Version       uint32
	PrevBlockHash [32]byte
	MerkleRoot    [32]byte
	Timestamp     uint64
	Target        [32]byte
	UtxoRoot      [32]byte
	Nonce         uint64
}

// ParseInitial148HeaderBytes decodes exactly one header without semantic checks.
// The caller must not mutate b concurrently; the returned value retains no b.
func ParseInitial148HeaderBytes(b []byte) (Initial148Header, error) {
	if len(b) != Initial148HeaderBytes {
		return Initial148Header{}, txerr(TX_ERR_PARSE, "block header length mismatch")
	}
	var h Initial148Header
	h.Version = binary.LittleEndian.Uint32(b[0:4])
	copy(h.PrevBlockHash[:], b[4:36])
	copy(h.MerkleRoot[:], b[36:68])
	h.Timestamp = binary.LittleEndian.Uint64(b[68:76])
	copy(h.Target[:], b[76:108])
	copy(h.UtxoRoot[:], b[108:140])
	h.Nonce = binary.LittleEndian.Uint64(b[140:148])
	return h, nil
}

// EncodeInitial148Header serializes h into an independent fixed-size array.
func EncodeInitial148Header(h Initial148Header) [148]byte {
	var b [148]byte
	binary.LittleEndian.PutUint32(b[0:4], h.Version)
	copy(b[4:36], h.PrevBlockHash[:])
	copy(b[36:68], h.MerkleRoot[:])
	binary.LittleEndian.PutUint64(b[68:76], h.Timestamp)
	copy(b[76:108], h.Target[:])
	copy(b[108:140], h.UtxoRoot[:])
	binary.LittleEndian.PutUint64(b[140:148], h.Nonce)
	return b
}

// Initial148BlockHash hashes the complete, exact-length header once.
// The caller must not mutate headerBytes concurrently with the call.
func Initial148BlockHash(headerBytes []byte) ([32]byte, error) {
	if len(headerBytes) != Initial148HeaderBytes {
		return [32]byte{}, txerr(TX_ERR_PARSE, "block hash: invalid header length")
	}
	return sha3_256(headerBytes), nil
}

// Initial148PowCheck checks target range and strict unsigned big-endian PoW.
// A full-header consumer must supply the parsed header's Target and establish all
// other validity conditions. This arithmetic primitive does not compare target
// with the serialized field or derive the expected retarget. The caller must not
// mutate headerBytes or the chain's POW_LIMIT concurrently with the call.
func Initial148PowCheck(headerBytes []byte, target [32]byte) error {
	if len(headerBytes) != Initial148HeaderBytes {
		return txerr(TX_ERR_PARSE, "pow: invalid header length")
	}
	if target == ([32]byte{}) || bytes.Compare(target[:], POW_LIMIT[:]) > 0 {
		return txerr(BLOCK_ERR_TARGET_INVALID, "target out of range")
	}
	h, err := Initial148BlockHash(headerBytes)
	if err != nil {
		return err
	}
	if bytes.Compare(h[:], target[:]) >= 0 {
		return txerr(BLOCK_ERR_POW_INVALID, "pow invalid")
	}
	return nil
}
