package consensus

type BlockHeader struct {
	Version       uint32
	PrevBlockHash [32]byte
	MerkleRoot    [32]byte
	Timestamp     uint64
	Target        [32]byte
	Nonce         uint64
}

const BLOCK_HEADER_BYTES = 116

func ParseBlockHeaderBytes(b []byte) (BlockHeader, error) {
	var h BlockHeader
	off := 0

	version, err := readU32le(b, &off)
	if err != nil {
		return h, err
	}
	prev, err := readBytes(b, &off, 32)
	if err != nil {
		return h, err
	}
	merkle, err := readBytes(b, &off, 32)
	if err != nil {
		return h, err
	}
	ts, err := readU64le(b, &off)
	if err != nil {
		return h, err
	}
	target, err := readBytes(b, &off, 32)
	if err != nil {
		return h, err
	}
	nonce, err := readU64le(b, &off)
	if err != nil {
		return h, err
	}
	if off != BLOCK_HEADER_BYTES {
		return h, txerr(TX_ERR_PARSE, "block header length mismatch")
	}

	h.Version = version
	copy(h.PrevBlockHash[:], prev)
	copy(h.MerkleRoot[:], merkle)
	h.Timestamp = ts
	copy(h.Target[:], target)
	h.Nonce = nonce
	return h, nil
}

func BlockHash(headerBytes []byte) ([32]byte, error) {
	if len(headerBytes) != BLOCK_HEADER_BYTES {
		var zero [32]byte
		return zero, txerr(TX_ERR_PARSE, "block hash: invalid header length")
	}
	return sha3_256(headerBytes), nil
}
