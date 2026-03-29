package consensus

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

// --- AppendU16le ---

func TestAppendU16le_Zero(t *testing.T) {
	got := AppendU16le(nil, 0)
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2", len(got))
	}
	if binary.LittleEndian.Uint16(got) != 0 {
		t.Fatalf("got %x, want 0000", got)
	}
}

func TestAppendU16le_MaxValue(t *testing.T) {
	got := AppendU16le(nil, math.MaxUint16)
	want := uint16(math.MaxUint16)
	if binary.LittleEndian.Uint16(got) != want {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestAppendU16le_KnownValue(t *testing.T) {
	got := AppendU16le(nil, 0x0102)
	// little-endian: low byte first
	if got[0] != 0x02 || got[1] != 0x01 {
		t.Fatalf("got %x, want [02 01]", got)
	}
}

func TestAppendU16le_AppendsToExisting(t *testing.T) {
	prefix := []byte{0xAA, 0xBB}
	got := AppendU16le(prefix, 0x1234)
	if len(got) != 4 {
		t.Fatalf("len=%d, want 4", len(got))
	}
	if got[0] != 0xAA || got[1] != 0xBB {
		t.Fatalf("prefix corrupted: %x", got[:2])
	}
	if binary.LittleEndian.Uint16(got[2:]) != 0x1234 {
		t.Fatalf("appended value wrong: %x", got[2:])
	}
}

// --- AppendU32le ---

func TestAppendU32le_Zero(t *testing.T) {
	got := AppendU32le(nil, 0)
	if len(got) != 4 {
		t.Fatalf("len=%d, want 4", len(got))
	}
	if binary.LittleEndian.Uint32(got) != 0 {
		t.Fatalf("got %x, want 00000000", got)
	}
}

func TestAppendU32le_MaxValue(t *testing.T) {
	got := AppendU32le(nil, math.MaxUint32)
	if binary.LittleEndian.Uint32(got) != math.MaxUint32 {
		t.Fatalf("got %x", got)
	}
}

func TestAppendU32le_KnownValue(t *testing.T) {
	got := AppendU32le(nil, 0x01020304)
	if got[0] != 0x04 || got[1] != 0x03 || got[2] != 0x02 || got[3] != 0x01 {
		t.Fatalf("got %x, want [04 03 02 01]", got)
	}
}

func TestAppendU32le_AppendsToExisting(t *testing.T) {
	prefix := []byte{0xFF}
	got := AppendU32le(prefix, 42)
	if len(got) != 5 {
		t.Fatalf("len=%d, want 5", len(got))
	}
	if got[0] != 0xFF {
		t.Fatalf("prefix corrupted")
	}
	if binary.LittleEndian.Uint32(got[1:]) != 42 {
		t.Fatalf("value wrong: %x", got[1:])
	}
}

// --- AppendU64le ---

func TestAppendU64le_Zero(t *testing.T) {
	got := AppendU64le(nil, 0)
	if len(got) != 8 {
		t.Fatalf("len=%d, want 8", len(got))
	}
	if binary.LittleEndian.Uint64(got) != 0 {
		t.Fatalf("got %x", got)
	}
}

func TestAppendU64le_MaxValue(t *testing.T) {
	got := AppendU64le(nil, math.MaxUint64)
	if binary.LittleEndian.Uint64(got) != math.MaxUint64 {
		t.Fatalf("got %x", got)
	}
}

func TestAppendU64le_KnownValue(t *testing.T) {
	got := AppendU64le(nil, 0x0102030405060708)
	want := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestAppendU64le_AppendsToExisting(t *testing.T) {
	prefix := []byte{0xDE, 0xAD}
	got := AppendU64le(prefix, 1)
	if len(got) != 10 {
		t.Fatalf("len=%d, want 10", len(got))
	}
	if got[0] != 0xDE || got[1] != 0xAD {
		t.Fatalf("prefix corrupted")
	}
	if binary.LittleEndian.Uint64(got[2:]) != 1 {
		t.Fatalf("value wrong")
	}
}

// --- Chained appends ---

func TestAppendChained_MultipleTypes(t *testing.T) {
	var buf []byte
	buf = AppendU16le(buf, 0x1122)
	buf = AppendU32le(buf, 0x33445566)
	buf = AppendU64le(buf, 0x778899AABBCCDDEE)
	if len(buf) != 2+4+8 {
		t.Fatalf("len=%d, want 14", len(buf))
	}
	if binary.LittleEndian.Uint16(buf[0:2]) != 0x1122 {
		t.Fatal("u16 wrong")
	}
	if binary.LittleEndian.Uint32(buf[2:6]) != 0x33445566 {
		t.Fatal("u32 wrong")
	}
	if binary.LittleEndian.Uint64(buf[6:14]) != 0x778899AABBCCDDEE {
		t.Fatal("u64 wrong")
	}
}

// --- Roundtrip with wire_read ---

func TestAppendU16le_RoundtripWithRead(t *testing.T) {
	for _, v := range []uint16{0, 1, 0x00FF, 0xFF00, math.MaxUint16} {
		buf := AppendU16le(nil, v)
		off := 0
		got, err := readU16le(buf, &off)
		if err != nil {
			t.Fatalf("readU16le(%d): %v", v, err)
		}
		if got != v {
			t.Fatalf("roundtrip u16: wrote %d, read %d", v, got)
		}
	}
}

func TestAppendU32le_RoundtripWithRead(t *testing.T) {
	for _, v := range []uint32{0, 1, 0x00FF00FF, math.MaxUint32} {
		buf := AppendU32le(nil, v)
		off := 0
		got, err := readU32le(buf, &off)
		if err != nil {
			t.Fatalf("readU32le(%d): %v", v, err)
		}
		if got != v {
			t.Fatalf("roundtrip u32: wrote %d, read %d", v, got)
		}
	}
}

func TestAppendU64le_RoundtripWithRead(t *testing.T) {
	for _, v := range []uint64{0, 1, 0x00FF00FF00FF00FF, math.MaxUint64} {
		buf := AppendU64le(nil, v)
		off := 0
		got, err := readU64le(buf, &off)
		if err != nil {
			t.Fatalf("readU64le(%d): %v", v, err)
		}
		if got != v {
			t.Fatalf("roundtrip u64: wrote %d, read %d", v, got)
		}
	}
}
