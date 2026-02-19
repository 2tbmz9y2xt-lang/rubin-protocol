package store

import (
	"encoding/binary"
	"fmt"

	"rubin.dev/node/consensus"
)

func encodeOutpointKey(p consensus.TxOutPoint) []byte {
	// txid(32) || vout(u32 little-endian)
	out := make([]byte, 32+4)
	copy(out[0:32], p.TxID[:])
	binary.LittleEndian.PutUint32(out[32:36], p.Vout)
	return out
}

func decodeOutpointKey(b []byte) (consensus.TxOutPoint, error) {
	if len(b) != 36 {
		return consensus.TxOutPoint{}, fmt.Errorf("outpoint: expected 36 bytes, got %d", len(b))
	}
	var txid [32]byte
	copy(txid[:], b[0:32])
	vout := binary.LittleEndian.Uint32(b[32:36])
	return consensus.TxOutPoint{TxID: txid, Vout: vout}, nil
}

func encodeUtxoEntry(e consensus.UtxoEntry) ([]byte, error) {
	data := e.Output.CovenantData
	if len(data) > 0xffffffff {
		return nil, fmt.Errorf("utxo: covenant_data too large")
	}
	// value u64le | covenant_type u16le | covenant_data_len u32le | covenant_data | creation_height u64le | created_by_coinbase u8
	out := make([]byte, 8+2+4+len(data)+8+1)
	binary.LittleEndian.PutUint64(out[0:8], e.Output.Value)
	binary.LittleEndian.PutUint16(out[8:10], e.Output.CovenantType)
	binary.LittleEndian.PutUint32(out[10:14], uint32(len(data)))
	copy(out[14:14+len(data)], data)
	off := 14 + len(data)
	binary.LittleEndian.PutUint64(out[off:off+8], e.CreationHeight)
	off += 8
	if e.CreatedByCoinbase {
		out[off] = 1
	}
	return out, nil
}

func decodeUtxoEntry(b []byte) (consensus.UtxoEntry, error) {
	if len(b) < 8+2+4+8+1 {
		return consensus.UtxoEntry{}, fmt.Errorf("utxo: truncated")
	}
	value := binary.LittleEndian.Uint64(b[0:8])
	covType := binary.LittleEndian.Uint16(b[8:10])
	dataLen := int(binary.LittleEndian.Uint32(b[10:14]))
	if dataLen < 0 || 14+dataLen+8+1 != len(b) {
		return consensus.UtxoEntry{}, fmt.Errorf("utxo: bad covenant_data_len")
	}
	data := append([]byte(nil), b[14:14+dataLen]...)
	off := 14 + dataLen
	creationHeight := binary.LittleEndian.Uint64(b[off : off+8])
	off += 8
	createdByCoinbase := b[off] == 1
	return consensus.UtxoEntry{
		Output: consensus.TxOutput{
			Value:        value,
			CovenantType: covType,
			CovenantData: data,
		},
		CreationHeight:    creationHeight,
		CreatedByCoinbase: createdByCoinbase,
	}, nil
}
