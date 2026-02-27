package consensus

import "testing"

func TestCompactSize_EncodeDecodeRoundtrip_Boundaries(t *testing.T) {
	cases := []uint64{
		0,
		1,
		0xfc,
		0xfd,
		0xfe,
		0xffff,
		0x1_0000,
		0xffff_ffff,
		0x1_0000_0000,
		0x0123_4567_89ab_cdef,
	}
	for _, v := range cases {
		var b []byte
		b = appendCompactSize(b, v)

		off := 0
		got, n, err := readCompactSize(b, &off)
		if err != nil {
			t.Fatalf("v=%d: readCompactSize: %v", v, err)
		}
		if got != v {
			t.Fatalf("v=%d: got=%d", v, got)
		}
		if n != len(b) || off != len(b) {
			t.Fatalf("v=%d: consumed=%d off=%d want=%d", v, n, off, len(b))
		}
	}
}

func TestCompactSize_RejectsNonMinimalEncodings(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{name: "0xfd_for_small", b: []byte{0xfd, 0xfc, 0x00}},                       // 252
		{name: "0xfe_for_u16", b: []byte{0xfe, 0xff, 0xff, 0x00, 0x00}},             // 65535
		{name: "0xff_for_u32", b: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}}, // 0xffffffff
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			off := 0
			_, _, err := readCompactSize(tc.b, &off)
			if err == nil {
				t.Fatalf("expected error")
			}
			if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
				t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
			}
		})
	}
}

func TestCompactSize_TruncatedReturnsError(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{name: "empty", b: []byte{}},
		{name: "tag_only_fd", b: []byte{0xfd}},
		{name: "tag_only_fe", b: []byte{0xfe}},
		{name: "tag_only_ff", b: []byte{0xff}},
		{name: "fd_one_byte", b: []byte{0xfd, 0x00}},
		{name: "fe_three_bytes", b: []byte{0xfe, 0x00, 0x00, 0x00}},
		{name: "ff_seven_bytes", b: []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			off := 0
			_, _, err := readCompactSize(tc.b, &off)
			if err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}
