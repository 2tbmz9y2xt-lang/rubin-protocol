package consensus

import (
	"encoding/hex"
	"testing"
)

func TestCompactSizeEncodeDecode(t *testing.T) {
	cases := []struct {
		name string
		val  uint64
		hex  string
	}{
		{"zero", 0, "00"},
		{"max_u8_minimal", 252, "fc"},
		{"u16_boundary", 253, "fdfd00"},
		{"u16_max", 65535, "fdffff"},
		{"u32_boundary", 65536, "fe00000100"},
		{"u32_mid", 0x12345678, "fe78563412"},
		{"u64_boundary", 0x1_0000_0000, "ff0000000001000000"},
		{"u64_high", 0xffff_ffff_ffff_ffff, "ffffffffffffffffff"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := CompactSize(tc.val).Encode()
			if hex.EncodeToString(enc) != tc.hex {
				t.Fatalf("encode mismatch: got %x want %s", enc, tc.hex)
			}
			dec, n, err := DecodeCompactSize(enc)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if n != len(enc) {
				t.Fatalf("decode consumed %d bytes, want %d", n, len(enc))
			}
			if uint64(dec) != tc.val {
				t.Fatalf("decode value mismatch: got %d want %d", dec, tc.val)
			}
		})
	}
}
