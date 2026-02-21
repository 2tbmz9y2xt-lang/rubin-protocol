package p2p

import (
	"encoding/binary"
	"fmt"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
)

const (
	CompactBlockShortIDBytes = 6
	compactBlockKeyDomain    = "RUBIN-CMPCT-v1"
)

type SendCmpctPayload struct {
	Announce        uint8
	ShortIDWTXID    uint8 // MUST be 1 in RUBIN
	ProtocolVersion uint32
}

func EncodeSendCmpctPayload(p SendCmpctPayload) ([]byte, error) {
	if p.ShortIDWTXID != 1 {
		return nil, fmt.Errorf("p2p: sendcmpct: shortid_wtxid must be 1")
	}
	out := make([]byte, 0, 6)
	out = append(out, p.Announce)
	out = append(out, p.ShortIDWTXID)
	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], p.ProtocolVersion)
	out = append(out, tmp4[:]...)
	return out, nil
}

func DecodeSendCmpctPayload(b []byte) (*SendCmpctPayload, error) {
	if len(b) != 6 {
		return nil, fmt.Errorf("p2p: sendcmpct: length mismatch")
	}
	p := &SendCmpctPayload{
		Announce:        b[0],
		ShortIDWTXID:    b[1],
		ProtocolVersion: binary.LittleEndian.Uint32(b[2:6]),
	}
	if p.ShortIDWTXID != 1 {
		return nil, fmt.Errorf("p2p: sendcmpct: shortid_wtxid must be 1")
	}
	return p, nil
}

type PrefilledTx struct {
	Index   uint64
	TxBytes []byte // canonical TxBytes (includes witness; includes DA payload in wire v2)
}

type CmpctBlockPayload struct {
	Header    consensus.BlockHeader
	Nonce     uint64
	TxCount   uint64
	ShortIDs  [][CompactBlockShortIDBytes]byte
	Prefilled []PrefilledTx
}

func EncodeCmpctBlockPayload(p CmpctBlockPayload) ([]byte, error) {
	if p.TxCount == 0 {
		return nil, fmt.Errorf("p2p: cmpctblock: tx_count must be >= 1")
	}
	if uint64(len(p.ShortIDs))+uint64(len(p.Prefilled)) != p.TxCount {
		return nil, fmt.Errorf("p2p: cmpctblock: shortid_count+prefilled_count must equal tx_count")
	}

	out := make([]byte, 0, BlockHeaderBytesLen+8+64)
	out = append(out, consensus.BlockHeaderBytes(p.Header)...)
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], p.Nonce)
	out = append(out, tmp8[:]...)
	out = append(out, encodeCompactSize(p.TxCount)...)
	out = append(out, encodeCompactSize(uint64(len(p.ShortIDs)))...)
	for _, sid := range p.ShortIDs {
		out = append(out, sid[:]...)
	}

	out = append(out, encodeCompactSize(uint64(len(p.Prefilled)))...)
	var prevIdx uint64
	for i, pf := range p.Prefilled {
		if pf.Index >= p.TxCount {
			return nil, fmt.Errorf("p2p: cmpctblock: prefilled index out of range")
		}
		if i == 0 {
			out = append(out, encodeCompactSize(pf.Index)...)
		} else {
			if pf.Index <= prevIdx {
				return nil, fmt.Errorf("p2p: cmpctblock: prefilled indices not strictly increasing")
			}
			out = append(out, encodeCompactSize(pf.Index-prevIdx-1)...)
		}
		prevIdx = pf.Index
		// Ensure the bytes are parseable to avoid ambiguous concatenations.
		if _, err := consensus.ParseTxBytes(pf.TxBytes); err != nil {
			return nil, fmt.Errorf("p2p: cmpctblock: invalid prefilled tx_bytes: %w", err)
		}
		out = append(out, pf.TxBytes...)
	}
	return out, nil
}

func DecodeCmpctBlockPayload(b []byte) (*CmpctBlockPayload, error) {
	if len(b) < BlockHeaderBytesLen+8+1 {
		return nil, fmt.Errorf("p2p: cmpctblock: short payload")
	}
	off := 0
	headerBytes := b[off : off+BlockHeaderBytesLen]
	off += BlockHeaderBytesLen
	h, err := consensus.ParseBlockHeaderBytes(headerBytes)
	if err != nil {
		return nil, err
	}
	nonce := binary.LittleEndian.Uint64(b[off : off+8])
	off += 8

	txCount, used, err := readCompactSize(b[off:])
	if err != nil {
		return nil, err
	}
	off += used
	if txCount < 1 {
		return nil, fmt.Errorf("p2p: cmpctblock: tx_count must be >= 1")
	}

	shortidCount, used, err := readCompactSize(b[off:])
	if err != nil {
		return nil, err
	}
	off += used
	if shortidCount > txCount {
		return nil, fmt.Errorf("p2p: cmpctblock: shortid_count exceeds tx_count")
	}
	needSIDs := int(shortidCount) * CompactBlockShortIDBytes
	if len(b) < off+needSIDs {
		return nil, fmt.Errorf("p2p: cmpctblock: shortids truncated")
	}
	shortids := make([][CompactBlockShortIDBytes]byte, 0, int(shortidCount))
	for i := 0; i < int(shortidCount); i++ {
		var sid [CompactBlockShortIDBytes]byte
		copy(sid[:], b[off:off+CompactBlockShortIDBytes])
		shortids = append(shortids, sid)
		off += CompactBlockShortIDBytes
	}

	prefilledCount, used, err := readCompactSize(b[off:])
	if err != nil {
		return nil, err
	}
	off += used
	if prefilledCount > txCount {
		return nil, fmt.Errorf("p2p: cmpctblock: prefilled_count exceeds tx_count")
	}
	if shortidCount+prefilledCount != txCount {
		return nil, fmt.Errorf("p2p: cmpctblock: shortid_count+prefilled_count must equal tx_count")
	}

	prefilled := make([]PrefilledTx, 0, int(prefilledCount))
	var prevIdx uint64
	for i := 0; i < int(prefilledCount); i++ {
		delta, u, err := readCompactSize(b[off:])
		if err != nil {
			return nil, err
		}
		off += u
		var idx uint64
		if i == 0 {
			idx = delta
		} else {
			idx = prevIdx + 1 + delta
		}
		if idx >= txCount {
			return nil, fmt.Errorf("p2p: cmpctblock: prefilled index out of range")
		}
		if i > 0 && idx <= prevIdx {
			return nil, fmt.Errorf("p2p: cmpctblock: prefilled indices not strictly increasing")
		}
		prevIdx = idx

		tx, usedBytes, err := consensus.ParseTxBytesPrefix(b[off:])
		if err != nil {
			return nil, err
		}
		_ = tx // parse validates canonical structure
		txBytes := append([]byte(nil), b[off:off+usedBytes]...)
		off += usedBytes
		prefilled = append(prefilled, PrefilledTx{Index: idx, TxBytes: txBytes})
	}

	if off != len(b) {
		return nil, fmt.Errorf("p2p: cmpctblock: trailing bytes")
	}

	return &CmpctBlockPayload{
		Header:    h,
		Nonce:     nonce,
		TxCount:   txCount,
		ShortIDs:  shortids,
		Prefilled: prefilled,
	}, nil
}

type GetBlockTxnPayload struct {
	BlockHash [32]byte
	Indices   []uint64
}

func EncodeGetBlockTxnPayload(p GetBlockTxnPayload) ([]byte, error) {
	if len(p.Indices) == 0 {
		return nil, fmt.Errorf("p2p: getblocktxn: empty indices")
	}
	out := make([]byte, 0, 32+9+len(p.Indices)*5)
	out = append(out, p.BlockHash[:]...)
	out = append(out, encodeCompactSize(uint64(len(p.Indices)))...)
	var prev uint64
	for i, idx := range p.Indices {
		if i == 0 {
			out = append(out, encodeCompactSize(idx)...)
		} else {
			if idx <= prev {
				return nil, fmt.Errorf("p2p: getblocktxn: indices not strictly increasing")
			}
			out = append(out, encodeCompactSize(idx-prev-1)...)
		}
		prev = idx
	}
	return out, nil
}

func DecodeGetBlockTxnPayload(b []byte) (*GetBlockTxnPayload, error) {
	if len(b) < 32+1 {
		return nil, fmt.Errorf("p2p: getblocktxn: short payload")
	}
	var h [32]byte
	copy(h[:], b[:32])
	off := 32
	n, used, err := readCompactSize(b[off:])
	if err != nil {
		return nil, err
	}
	off += used
	if n == 0 {
		return nil, fmt.Errorf("p2p: getblocktxn: empty indices")
	}
	indices := make([]uint64, 0, int(n))
	var prev uint64
	for i := 0; i < int(n); i++ {
		delta, u, err := readCompactSize(b[off:])
		if err != nil {
			return nil, err
		}
		off += u
		var idx uint64
		if i == 0 {
			idx = delta
		} else {
			idx = prev + 1 + delta
		}
		if i > 0 && idx <= prev {
			return nil, fmt.Errorf("p2p: getblocktxn: indices not strictly increasing")
		}
		prev = idx
		indices = append(indices, idx)
	}
	if off != len(b) {
		return nil, fmt.Errorf("p2p: getblocktxn: trailing bytes")
	}
	return &GetBlockTxnPayload{BlockHash: h, Indices: indices}, nil
}

type BlockTxnPayload struct {
	BlockHash [32]byte
	Txs       [][]byte // each is canonical TxBytes
}

func EncodeBlockTxnPayload(p BlockTxnPayload) ([]byte, error) {
	out := make([]byte, 0, 32+9)
	out = append(out, p.BlockHash[:]...)
	out = append(out, encodeCompactSize(uint64(len(p.Txs)))...)
	for _, txb := range p.Txs {
		if _, err := consensus.ParseTxBytes(txb); err != nil {
			return nil, fmt.Errorf("p2p: blocktxn: invalid tx_bytes: %w", err)
		}
		out = append(out, txb...)
	}
	return out, nil
}

func DecodeBlockTxnPayload(b []byte) (*BlockTxnPayload, error) {
	if len(b) < 32+1 {
		return nil, fmt.Errorf("p2p: blocktxn: short payload")
	}
	var h [32]byte
	copy(h[:], b[:32])
	off := 32
	n, used, err := readCompactSize(b[off:])
	if err != nil {
		return nil, err
	}
	off += used
	txs := make([][]byte, 0, int(n))
	for i := 0; i < int(n); i++ {
		_, usedBytes, err := consensus.ParseTxBytesPrefix(b[off:])
		if err != nil {
			return nil, err
		}
		txb := append([]byte(nil), b[off:off+usedBytes]...)
		off += usedBytes
		txs = append(txs, txb)
	}
	if off != len(b) {
		return nil, fmt.Errorf("p2p: blocktxn: trailing bytes")
	}
	return &BlockTxnPayload{BlockHash: h, Txs: txs}, nil
}

func cmpctKeys(p crypto.CryptoProvider, header consensus.BlockHeader, nonce uint64) (uint64, uint64, error) {
	if p == nil {
		return 0, 0, fmt.Errorf("p2p: cmpct: nil crypto provider")
	}
	hb := consensus.BlockHeaderBytes(header)
	var nonce8 [8]byte
	binary.LittleEndian.PutUint64(nonce8[:], nonce)
	buf := make([]byte, 0, len(compactBlockKeyDomain)+len(hb)+len(nonce8))
	buf = append(buf, []byte(compactBlockKeyDomain)...)
	buf = append(buf, hb...)
	buf = append(buf, nonce8[:]...)
	km, err := p.SHA3_256(buf)
	if err != nil {
		return 0, 0, err
	}
	k0 := binary.LittleEndian.Uint64(km[0:8])
	k1 := binary.LittleEndian.Uint64(km[8:16])
	return k0, k1, nil
}

func ShortID(p crypto.CryptoProvider, header consensus.BlockHeader, nonce uint64, txBytes []byte) ([CompactBlockShortIDBytes]byte, error) {
	k0, k1, err := cmpctKeys(p, header, nonce)
	if err != nil {
		return [CompactBlockShortIDBytes]byte{}, err
	}
	wtxid, err := p.SHA3_256(txBytes)
	if err != nil {
		return [CompactBlockShortIDBytes]byte{}, err
	}
	s64 := siphash24(k0, k1, wtxid[:])
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], s64)
	var out [CompactBlockShortIDBytes]byte
	copy(out[:], tmp8[:CompactBlockShortIDBytes])
	return out, nil
}

func rotl64(x uint64, b uint) uint64 {
	return (x << b) | (x >> (64 - b))
}

func sipround(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = rotl64(v1, 13)
	v1 ^= v0
	v0 = rotl64(v0, 32)

	v2 += v3
	v3 = rotl64(v3, 16)
	v3 ^= v2

	v0 += v3
	v3 = rotl64(v3, 21)
	v3 ^= v0

	v2 += v1
	v1 = rotl64(v1, 17)
	v1 ^= v2
	v2 = rotl64(v2, 32)
	return v0, v1, v2, v3
}

// siphash24 implements SipHash-2-4 for shortid derivation. This is a local
// implementation to avoid extra dependencies; correctness is exercised by
// roundtrip + determinism tests and cross-client interop tests.
func siphash24(k0, k1 uint64, msg []byte) uint64 {
	v0 := uint64(0x736f6d6570736575) ^ k0
	v1 := uint64(0x646f72616e646f6d) ^ k1
	v2 := uint64(0x6c7967656e657261) ^ k0
	v3 := uint64(0x7465646279746573) ^ k1

	off := 0
	for ; off+8 <= len(msg); off += 8 {
		m := binary.LittleEndian.Uint64(msg[off : off+8])
		v3 ^= m
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
		v0 ^= m
	}

	var last uint64 = uint64(len(msg)) << 56
	rem := msg[off:]
	for i := 0; i < len(rem); i++ {
		last |= uint64(rem[i]) << (8 * i)
	}
	v3 ^= last
	v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	v0 ^= last

	v2 ^= 0xff
	for i := 0; i < 4; i++ {
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	}
	return v0 ^ v1 ^ v2 ^ v3
}
