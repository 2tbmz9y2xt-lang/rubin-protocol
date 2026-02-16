package consensus

import (
	"encoding/binary"
	"fmt"
)

// CompactSize implements RUBIN CompactSize encoding per spec/RUBIN_L1_CANONICAL_v1.1.md §3.2.1.
type CompactSize uint64

func (c CompactSize) Encode() []byte {
	n := uint64(c)
	if n < 253 {
		return []byte{byte(n)}
	}
	if n <= 0xffff {
		var b2 [2]byte
		binary.LittleEndian.PutUint16(b2[:], uint16(n))
		return []byte{0xfd, b2[0], b2[1]}
	}
	if n <= 0xffffffff {
		var b4 [4]byte
		binary.LittleEndian.PutUint32(b4[:], uint32(n))
		return []byte{
			0xfe,
			b4[0], b4[1], b4[2], b4[3],
		}
	}
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], n)
	return []byte{
		0xff,
		b8[0], b8[1], b8[2], b8[3],
		b8[4], b8[5], b8[6], b8[7],
	}
}

func DecodeCompactSize(b []byte) (CompactSize, int, error) {
	if len(b) < 1 {
		return 0, 0, fmt.Errorf("compactsize: empty")
	}
	tag := b[0]
	switch {
	case tag < 0xfd:
		return CompactSize(tag), 1, nil
	case tag == 0xfd:
		if len(b) < 3 {
			return 0, 0, fmt.Errorf("compactsize: truncated u16")
		}
		n := uint64(b[1]) | (uint64(b[2]) << 8)
		if n < 253 {
			return 0, 0, fmt.Errorf("compactsize: non-minimal u16")
		}
		return CompactSize(n), 3, nil
	case tag == 0xfe:
		if len(b) < 5 {
			return 0, 0, fmt.Errorf("compactsize: truncated u32")
		}
		n := uint64(b[1]) | (uint64(b[2]) << 8) | (uint64(b[3]) << 16) | (uint64(b[4]) << 24)
		if n < 0x1_0000 {
			return 0, 0, fmt.Errorf("compactsize: non-minimal u32")
		}
		return CompactSize(n), 5, nil
	default: // 0xff
		if len(b) < 9 {
			return 0, 0, fmt.Errorf("compactsize: truncated u64")
		}
		n := uint64(b[1]) |
			(uint64(b[2]) << 8) |
			(uint64(b[3]) << 16) |
			(uint64(b[4]) << 24) |
			(uint64(b[5]) << 32) |
			(uint64(b[6]) << 40) |
			(uint64(b[7]) << 48) |
			(uint64(b[8]) << 56)
		if n < 0x1_0000_0000 {
			return 0, 0, fmt.Errorf("compactsize: non-minimal u64")
		}
		return CompactSize(n), 9, nil
	}
}
