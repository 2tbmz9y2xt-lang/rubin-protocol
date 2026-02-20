package p2p

import (
	"encoding/binary"
	"fmt"
)

const (
	MaxInvEntries = 50_000
)

const (
	InvTypeTx            = 1 // MSG_TX
	InvTypeWitnessTx     = 2 // MSG_WITNESS_TX
	InvTypeBlock         = 3 // MSG_BLOCK
	InvTypeFilteredBlock = 4 // MSG_FILTERED_BLOCK
)

type InvVector struct {
	Type uint32
	Hash [32]byte
}

func EncodeInvPayload(vecs []InvVector) ([]byte, error) {
	if len(vecs) > MaxInvEntries {
		return nil, fmt.Errorf("p2p: inv: too many entries")
	}
	out := make([]byte, 0, 9+len(vecs)*(4+32))
	out = append(out, encodeCompactSize(uint64(len(vecs)))...)
	var tmp [4]byte
	for _, v := range vecs {
		binary.LittleEndian.PutUint32(tmp[:], v.Type)
		out = append(out, tmp[:]...)
		out = append(out, v.Hash[:]...)
	}
	return out, nil
}

func DecodeInvPayload(b []byte) ([]InvVector, error) {
	countU64, used, err := readCompactSize(b)
	if err != nil {
		return nil, err
	}
	if countU64 > MaxInvEntries {
		return nil, fmt.Errorf("p2p: inv: count exceeds MaxInvEntries")
	}
	count := int(countU64)
	need := used + count*(4+32)
	if len(b) != need {
		return nil, fmt.Errorf("p2p: inv: length mismatch")
	}
	off := used
	out := make([]InvVector, 0, count)
	for i := 0; i < count; i++ {
		tp := binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
		var h [32]byte
		copy(h[:], b[off:off+32])
		off += 32
		out = append(out, InvVector{Type: tp, Hash: h})
	}
	return out, nil
}
