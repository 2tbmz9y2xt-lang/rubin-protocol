package consensus

import (
	"bytes"
	"testing"
)

func TestEncodeCompactSize_Roundtrip(t *testing.T) {
	cases := []uint64{
		0, 1, 0xfc, 0xfd, 0xfe, 0xffff,
		0x1_0000, 0xffff_ffff, 0x1_0000_0000,
		0x0123_4567_89ab_cdef,
	}
	for _, v := range cases {
		enc := EncodeCompactSize(v)
		got, n, err := DecodeCompactSize(enc)
		if err != nil {
			t.Fatalf("v=%d: DecodeCompactSize: %v", v, err)
		}
		if got != v {
			t.Fatalf("v=%d: got=%d", v, got)
		}
		if n != len(enc) {
			t.Fatalf("v=%d: consumed=%d want=%d", v, n, len(enc))
		}
	}
}

func TestEncodeCompactSize_MatchesAppend(t *testing.T) {
	values := []uint64{0, 252, 253, 65535, 65536, 0xffff_ffff, 0x1_0000_0000}
	for _, v := range values {
		standalone := EncodeCompactSize(v)
		appended := AppendCompactSize(nil, v)
		if !bytes.Equal(standalone, appended) {
			t.Fatalf("v=%d: mismatch standalone=%x appended=%x", v, standalone, appended)
		}
	}
}

func TestDecodeCompactSize_RejectsNonMinimal(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{name: "fd_for_small", b: []byte{0xfd, 0xfc, 0x00}},
		{name: "fe_for_u16", b: []byte{0xfe, 0xff, 0xff, 0x00, 0x00}},
		{name: "ff_for_u32", b: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := DecodeCompactSize(tc.b)
			if err == nil {
				t.Fatalf("expected error for non-minimal encoding")
			}
		})
	}
}

func TestDecodeCompactSize_RejectsTruncated(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{name: "empty", b: []byte{}},
		{name: "tag_only_fd", b: []byte{0xfd}},
		{name: "tag_only_fe", b: []byte{0xfe}},
		{name: "tag_only_ff", b: []byte{0xff}},
		{name: "fd_one_byte", b: []byte{0xfd, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := DecodeCompactSize(tc.b)
			if err == nil {
				t.Fatalf("expected error for truncated input")
			}
		})
	}
}
