package consensus

import "encoding/binary"

// Target (raw bytes), and Nonce (8-byte little-endian).
func BlockHeaderBytes(header BlockHeader) []byte {
	out := make([]byte, 0, 4+32+32+8+32+8)
	var tmp4 [4]byte
	var tmp8 [8]byte

	binary.LittleEndian.PutUint32(tmp4[:], header.Version)
	out = append(out, tmp4[:]...)
	out = append(out, header.PrevBlockHash[:]...)
	out = append(out, header.MerkleRoot[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], header.Timestamp)
	out = append(out, tmp8[:]...)
	out = append(out, header.Target[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], header.Nonce)
	out = append(out, tmp8[:]...)
	return out
}

// TxOutputBytes serializes a TxOutput into its canonical byte representation.
//
// It encodes Value as 8-byte little-endian, CovenantType as 2-byte little-endian,
// then the length of CovenantData using CompactSize followed by the CovenantData bytes.
// The resulting slice is the concatenation of those fields in that order.
func TxOutputBytes(o TxOutput) []byte {
	out := make([]byte, 0, 8+2+9+len(o.CovenantData))
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], o.Value)
	out = append(out, tmp8[:]...)
	var tmp2 [2]byte
	binary.LittleEndian.PutUint16(tmp2[:], o.CovenantType)
	out = append(out, tmp2[:]...)
	out = append(out, CompactSize(len(o.CovenantData)).Encode()...)
	out = append(out, o.CovenantData...)
	return out
}

// WitnessItemBytes serializes a WitnessItem into its wire format.
// The encoding is: SuiteID (1 byte), Pubkey length encoded as CompactSize, Pubkey bytes,
// Signature length encoded as CompactSize, then Signature bytes.
// The returned slice contains the complete serialized witness item.
func WitnessItemBytes(w WitnessItem) []byte {
	out := make([]byte, 0, 1+9+len(w.Pubkey)+9+len(w.Signature))
	out = append(out, w.SuiteID)
	out = append(out, CompactSize(len(w.Pubkey)).Encode()...)
	out = append(out, w.Pubkey...)
	out = append(out, CompactSize(len(w.Signature)).Encode()...)
	out = append(out, w.Signature...)
	return out
}

// WitnessBytes serializes a witness section into a byte slice.
// It encodes the number of witness items using CompactSize and then appends each witness item serialized by WitnessItemBytes, returning the concatenated bytes.
func WitnessBytes(w WitnessSection) []byte {
	out := make([]byte, 0, 9)
	out = append(out, CompactSize(len(w.Witnesses)).Encode()...)
	for _, item := range w.Witnesses {
		out = append(out, WitnessItemBytes(item)...)
	}
	return out
}

// TxNoWitnessBytes serializes a transaction excluding its witness section into a byte slice.
//
// The serialized layout is:
// - Version (4 bytes, little-endian)
// - TxNonce (8 bytes, little-endian)
// - Inputs count (CompactSize) followed by each input:
//   - PrevTxid (32 bytes)
//   - PrevVout (4 bytes, little-endian)
//   - ScriptSig length (CompactSize) and ScriptSig bytes
//   - Sequence (4 bytes, little-endian)
//
// - Outputs count (CompactSize) followed by each output serialized by TxOutputBytes
// - Locktime (4 bytes, little-endian)
func TxNoWitnessBytes(tx *Tx) []byte {
	out := make([]byte, 0, 4+8)
	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], tx.Version)
	out = append(out, tmp4[:]...)
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], tx.TxNonce)
	out = append(out, tmp8[:]...)

	out = append(out, CompactSize(len(tx.Inputs)).Encode()...)
	for _, in := range tx.Inputs {
		out = append(out, in.PrevTxid[:]...)
		binary.LittleEndian.PutUint32(tmp4[:], in.PrevVout)
		out = append(out, tmp4[:]...)
		out = append(out, CompactSize(len(in.ScriptSig)).Encode()...)
		out = append(out, in.ScriptSig...)
		binary.LittleEndian.PutUint32(tmp4[:], in.Sequence)
		out = append(out, tmp4[:]...)
	}

	out = append(out, CompactSize(len(tx.Outputs)).Encode()...)
	for _, o := range tx.Outputs {
		out = append(out, TxOutputBytes(o)...)
	}

	binary.LittleEndian.PutUint32(tmp4[:], tx.Locktime)
	out = append(out, tmp4[:]...)
	return out
}

// TxBytes serializes tx into its complete binary representation including its witness section.
// The returned slice contains the transaction fields followed by the serialized witness data.
func TxBytes(tx *Tx) []byte {
	out := TxNoWitnessBytes(tx)
	out = append(out, WitnessBytes(tx.Witness)...)
	return out
}

// BlockBytes serializes a Block into its canonical byte representation.
// The result is the concatenation of the serialized block header, the number of transactions encoded as a CompactSize, and each transaction serialized (including witnesses).
func BlockBytes(block *Block) []byte {
	out := make([]byte, 0, 64)
	out = append(out, BlockHeaderBytes(block.Header)...)
	out = append(out, CompactSize(len(block.Transactions)).Encode()...)
	for _, tx := range block.Transactions {
		out = append(out, TxBytes(&tx)...)
	}
	return out
}
