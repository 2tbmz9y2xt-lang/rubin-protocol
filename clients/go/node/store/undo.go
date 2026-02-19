package store

import (
	"encoding/binary"
	"fmt"

	"rubin.dev/node/consensus"
)

type UndoSpent struct {
	OutPoint      consensus.TxOutPoint
	RestoredEntry consensus.UtxoEntry
}

type UndoRecord struct {
	Spent   []UndoSpent
	Created []consensus.TxOutPoint
}

func encodeUndoRecord(u UndoRecord) ([]byte, error) {
	if len(u.Spent) > 0xffffffff || len(u.Created) > 0xffffffff {
		return nil, fmt.Errorf("undo: too many items")
	}

	// Layout:
	// spent_count u32le
	//   (outpoint_key 36 | utxo_len u32le | utxo_bytes) * spent_count
	// created_count u32le
	//   (outpoint_key 36) * created_count
	out := make([]byte, 0, 4+len(u.Spent)*(36+4+64)+4+len(u.Created)*36)

	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], uint32(len(u.Spent))) // #nosec G115 -- len checked against 0xffffffff above.
	out = append(out, tmp4[:]...)

	for _, s := range u.Spent {
		out = append(out, encodeOutpointKey(s.OutPoint)...)
		utxoBytes, err := encodeUtxoEntry(s.RestoredEntry)
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(tmp4[:], uint32(len(utxoBytes))) // #nosec G115 -- utxo bytes len fits u32; caller encodes bounded utxo entry.
		out = append(out, tmp4[:]...)
		out = append(out, utxoBytes...)
	}

	binary.LittleEndian.PutUint32(tmp4[:], uint32(len(u.Created))) // #nosec G115 -- len checked against 0xffffffff above.
	out = append(out, tmp4[:]...)
	for _, p := range u.Created {
		out = append(out, encodeOutpointKey(p)...)
	}

	return out, nil
}

func decodeUndoRecord(b []byte) (*UndoRecord, error) {
	if len(b) < 4+4 {
		return nil, fmt.Errorf("undo: truncated")
	}
	off := 0
	readU32 := func() (uint32, error) {
		if off+4 > len(b) {
			return 0, fmt.Errorf("undo: truncated u32")
		}
		v := binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
		return v, nil
	}

	spentN, err := readU32()
	if err != nil {
		return nil, err
	}
	spent := make([]UndoSpent, 0, spentN)
	for i := uint32(0); i < spentN; i++ {
		if off+36 > len(b) {
			return nil, fmt.Errorf("undo: truncated outpoint")
		}
		p, err := decodeOutpointKey(b[off : off+36])
		if err != nil {
			return nil, err
		}
		off += 36
		utxoLen, err := readU32()
		if err != nil {
			return nil, err
		}
		if utxoLen > uint32(len(b)-off) { // #nosec G115 -- len(b)-off is non-negative (checked by prior offset bounds); fits u32.
			return nil, fmt.Errorf("undo: truncated utxo bytes")
		}
		utxoBytes := b[off : off+int(utxoLen)]
		off += int(utxoLen)
		e, err := decodeUtxoEntry(utxoBytes)
		if err != nil {
			return nil, err
		}
		spent = append(spent, UndoSpent{OutPoint: p, RestoredEntry: e})
	}

	createdN, err := readU32()
	if err != nil {
		return nil, err
	}
	created := make([]consensus.TxOutPoint, 0, createdN)
	for i := uint32(0); i < createdN; i++ {
		if off+36 > len(b) {
			return nil, fmt.Errorf("undo: truncated created outpoint")
		}
		p, err := decodeOutpointKey(b[off : off+36])
		if err != nil {
			return nil, err
		}
		off += 36
		created = append(created, p)
	}
	if off != len(b) {
		return nil, fmt.Errorf("undo: trailing bytes")
	}
	return &UndoRecord{Spent: spent, Created: created}, nil
}
