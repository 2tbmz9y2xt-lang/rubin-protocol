package consensus

// EncodeCompactSize encodes n as a Bitcoin-style CompactSize varint and
// returns the encoded bytes.  For append-style usage see AppendCompactSize.
func EncodeCompactSize(n uint64) []byte {
	return AppendCompactSize(nil, n)
}

// DecodeCompactSize decodes one CompactSize value from the front of buf.
// Returns the decoded value and the number of bytes consumed.
// Non-minimal encodings are rejected with TX_ERR_PARSE.
func DecodeCompactSize(buf []byte) (uint64, int, error) {
	off := 0
	v, nbytes, err := readCompactSize(buf, &off)
	return v, nbytes, err
}
