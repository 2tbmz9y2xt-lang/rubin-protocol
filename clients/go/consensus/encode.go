package consensus

import "encoding/binary"

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

func WitnessItemBytes(w WitnessItem) []byte {
	out := make([]byte, 0, 1+9+len(w.Pubkey)+9+len(w.Signature))
	out = append(out, w.SuiteID)
	out = append(out, CompactSize(len(w.Pubkey)).Encode()...)
	out = append(out, w.Pubkey...)
	out = append(out, CompactSize(len(w.Signature)).Encode()...)
	out = append(out, w.Signature...)
	return out
}

func WitnessBytes(w WitnessSection) []byte {
	out := make([]byte, 0, 9)
	out = append(out, CompactSize(len(w.Witnesses)).Encode()...)
	for _, item := range w.Witnesses {
		out = append(out, WitnessItemBytes(item)...)
	}
	return out
}

func daCoreFieldsBytes(tx *Tx) []byte {
	switch tx.TxKind {
	case TX_KIND_STANDARD:
		return nil
	case TX_KIND_DA_COMMIT:
		if tx.DACommit == nil || tx.DAChunk != nil {
			panic("DA core fields: DA_COMMIT kind requires DACommit and forbids DAChunk")
		}
		// Fixed fields plus variable-length signature.
		out := make([]byte, 0, 32+2+32+8+32+32+32+1+9+len(tx.DACommit.BatchSig))
		out = append(out, tx.DACommit.DAID[:]...)
		var tmp2 [2]byte
		binary.LittleEndian.PutUint16(tmp2[:], tx.DACommit.ChunkCount)
		out = append(out, tmp2[:]...)
		out = append(out, tx.DACommit.RETLDomainID[:]...)
		var tmp8 [8]byte
		binary.LittleEndian.PutUint64(tmp8[:], tx.DACommit.BatchNumber)
		out = append(out, tmp8[:]...)
		out = append(out, tx.DACommit.TxDataRoot[:]...)
		out = append(out, tx.DACommit.StateRoot[:]...)
		out = append(out, tx.DACommit.WithdrawalsRoot[:]...)
		out = append(out, byte(tx.DACommit.BatchSigSuite))
		out = append(out, CompactSize(len(tx.DACommit.BatchSig)).Encode()...)
		out = append(out, tx.DACommit.BatchSig...)
		return out
	case TX_KIND_DA_CHUNK:
		if tx.DAChunk == nil || tx.DACommit != nil {
			panic("DA core fields: DA_CHUNK kind requires DAChunk and forbids DACommit")
		}
		out := make([]byte, 0, 32+2+32)
		out = append(out, tx.DAChunk.DAID[:]...)
		var tmp2 [2]byte
		binary.LittleEndian.PutUint16(tmp2[:], tx.DAChunk.ChunkIndex)
		out = append(out, tmp2[:]...)
		out = append(out, tx.DAChunk.ChunkHash[:]...)
		return out
	default:
		panic("unknown tx kind")
	}
}

func TxCoreBytes(tx *Tx) []byte {
	out := make([]byte, 0, 4+1+8)
	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], tx.Version)
	out = append(out, tmp4[:]...)
	out = append(out, byte(tx.TxKind))
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

	out = append(out, daCoreFieldsBytes(tx)...)
	return out
}

func TxBytes(tx *Tx) []byte {
	out := TxCoreBytes(tx)
	out = append(out, WitnessBytes(tx.Witness)...)
	out = append(out, CompactSize(len(tx.DAPayload)).Encode()...)
	out = append(out, tx.DAPayload...)
	return out
}

func BlockBytes(block *Block) []byte {
	out := make([]byte, 0, 64)
	out = append(out, BlockHeaderBytes(block.Header)...)
	out = append(out, CompactSize(len(block.Transactions)).Encode()...)
	for _, tx := range block.Transactions {
		out = append(out, TxBytes(&tx)...)
	}
	return out
}
