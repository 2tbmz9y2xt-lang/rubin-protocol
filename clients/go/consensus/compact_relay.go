package consensus

import "encoding/binary"

func sipRound(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = (v1 << 13) | (v1 >> (64 - 13))
	v1 ^= v0
	v0 = (v0 << 32) | (v0 >> (64 - 32))

	v2 += v3
	v3 = (v3 << 16) | (v3 >> (64 - 16))
	v3 ^= v2

	v0 += v3
	v3 = (v3 << 21) | (v3 >> (64 - 21))
	v3 ^= v0

	v2 += v1
	v1 = (v1 << 17) | (v1 >> (64 - 17))
	v1 ^= v2
	v2 = (v2 << 32) | (v2 >> (64 - 32))

	return v0, v1, v2, v3
}

func siphash24(msg []byte, k0, k1 uint64) uint64 {
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	i := 0
	for ; i+8 <= len(msg); i += 8 {
		m := binary.LittleEndian.Uint64(msg[i : i+8])
		v3 ^= m
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0 ^= m
	}

	var b uint64 = uint64(len(msg)) << 56
	rem := msg[i:]
	switch len(rem) {
	case 7:
		b |= uint64(rem[6]) << 48
		fallthrough
	case 6:
		b |= uint64(rem[5]) << 40
		fallthrough
	case 5:
		b |= uint64(rem[4]) << 32
		fallthrough
	case 4:
		b |= uint64(rem[3]) << 24
		fallthrough
	case 3:
		b |= uint64(rem[2]) << 16
		fallthrough
	case 2:
		b |= uint64(rem[1]) << 8
		fallthrough
	case 1:
		b |= uint64(rem[0])
	}

	v3 ^= b
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= b

	v2 ^= 0xff
	for range 4 {
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	}

	return v0 ^ v1 ^ v2 ^ v3
}

// CompactShortID computes a 6-byte short ID from WTXID using SipHash-2-4.
// The 64-bit SipHash result is truncated to lower 48 bits (little-endian bytes).
func CompactShortID(wtxid [32]byte, nonce1, nonce2 uint64) [6]byte {
	h := siphash24(wtxid[:], nonce1, nonce2)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], h&0x0000ffffffffffff)
	var out [6]byte
	copy(out[:], b[:6])
	return out
}
