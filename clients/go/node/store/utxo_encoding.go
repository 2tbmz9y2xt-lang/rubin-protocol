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
	// Canonical KV encoding aligns with operational/RUBIN_CHAINSTATE_SNAPSHOT_HASH_v1.1.md §4:
	// value u64le | covenant_type u16le | covenant_data_len CompactSize | covenant_data | creation_height u64le | created_by_coinbase u8
	//
	// Note: this is an *engineering* (Phase 1) persistence format, not a consensus wire format.
	covLen := consensus.CompactSize(len(data)).Encode()
	out := make([]byte, 0, 8+2+len(covLen)+len(data)+8+1)
	var tmp8 [8]byte
	var tmp2 [2]byte
	binary.LittleEndian.PutUint64(tmp8[:], e.Output.Value)
	out = append(out, tmp8[:]...)
	binary.LittleEndian.PutUint16(tmp2[:], e.Output.CovenantType)
	out = append(out, tmp2[:]...)
	out = append(out, covLen...)
	out = append(out, data...)
	binary.LittleEndian.PutUint64(tmp8[:], e.CreationHeight)
	out = append(out, tmp8[:]...)
	// created_by_coinbase byte
	out = append(out, 0x00)
	if e.CreatedByCoinbase {
		out[len(out)-1] = 1
	}
	return out, nil
}

func decodeUtxoEntry(b []byte) (consensus.UtxoEntry, error) {
	if len(b) < 8+2+8+1 {
		return consensus.UtxoEntry{}, fmt.Errorf("utxo: truncated")
	}
	off := 0
	value := binary.LittleEndian.Uint64(b[off : off+8])
	off += 8
	covType := binary.LittleEndian.Uint16(b[off : off+2])
	off += 2

	covDataLenCS, n, err := consensus.DecodeCompactSize(b[off:])
	if err != nil {
		return consensus.UtxoEntry{}, fmt.Errorf("utxo: covenant_data_len: %w", err)
	}
	off += n
	dataLen := int(covDataLenCS)
	if dataLen < 0 || off+dataLen+8+1 != len(b) {
		return consensus.UtxoEntry{}, fmt.Errorf("utxo: bad covenant_data_len")
	}
	data := append([]byte(nil), b[off:off+dataLen]...)
	off += dataLen
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
