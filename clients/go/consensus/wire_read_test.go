package consensus

import (
	"math"
	"testing"
)

func TestReadBytes_RejectsInvalidOffsets(t *testing.T) {
	buf := []byte{0x01, 0x02, 0x03}

	for _, off := range []int{-1, len(buf) + 1, int(^uint(0) >> 1)} {

		t.Run("off", func(t *testing.T) {
			_, err := readBytes(buf, &off, 1)
			if err == nil {
				t.Fatalf("expected error for invalid offset=%d", off)
			}
			if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
				t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
			}
		})
	}
}

// Regression: negative offset must be rejected without integer overflow.
func TestReadU8_NegativeOffset(t *testing.T) {
	off := -1
	_, err := readU8([]byte{0x42}, &off)
	if err == nil {
		t.Fatal("expected error for negative offset")
	}
}

func TestReadU16le_NegativeOffset(t *testing.T) {
	off := -1
	_, err := readU16le([]byte{0, 0}, &off)
	if err == nil {
		t.Fatal("expected error for negative offset")
	}
}

func TestReadU32le_NegativeOffset(t *testing.T) {
	off := -1
	_, err := readU32le([]byte{0, 0, 0, 0}, &off)
	if err == nil {
		t.Fatal("expected error for negative offset")
	}
}

func TestReadU64le_NegativeOffset(t *testing.T) {
	off := -1
	_, err := readU64le([]byte{0, 0, 0, 0, 0, 0, 0, 0}, &off)
	if err == nil {
		t.Fatal("expected error for negative offset")
	}
}

// Regression: MaxInt offset must not wrap around on *off+N.
func TestReadU8_OverflowOffset(t *testing.T) {
	off := math.MaxInt
	_, err := readU8([]byte{0x42}, &off)
	if err == nil {
		t.Fatal("expected error for overflow offset")
	}
}

func TestReadU16le_OverflowOffset(t *testing.T) {
	off := math.MaxInt
	_, err := readU16le([]byte{0, 0}, &off)
	if err == nil {
		t.Fatal("expected error for overflow offset")
	}
}

func TestReadU32le_OverflowOffset(t *testing.T) {
	off := math.MaxInt
	_, err := readU32le([]byte{0, 0, 0, 0}, &off)
	if err == nil {
		t.Fatal("expected error for overflow offset")
	}
}

func TestReadU64le_OverflowOffset(t *testing.T) {
	off := math.MaxInt
	_, err := readU64le([]byte{0, 0, 0, 0, 0, 0, 0, 0}, &off)
	if err == nil {
		t.Fatal("expected error for overflow offset")
	}
}

// Happy path: ensure normal reads still work correctly.
func TestReadU8_HappyPath(t *testing.T) {
	off := 0
	v, err := readU8([]byte{0xAB}, &off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 0xAB {
		t.Fatalf("expected 0xAB, got 0x%02x", v)
	}
	if off != 1 {
		t.Fatalf("offset should be 1, got %d", off)
	}
}

func TestReadU16le_HappyPath(t *testing.T) {
	off := 0
	v, err := readU16le([]byte{0x01, 0x02}, &off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 0x0201 {
		t.Fatalf("expected 0x0201, got 0x%04x", v)
	}
	if off != 2 {
		t.Fatalf("offset should be 2, got %d", off)
	}
}

func TestReadU32le_HappyPath(t *testing.T) {
	off := 0
	v, err := readU32le([]byte{0x01, 0x02, 0x03, 0x04}, &off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 0x04030201 {
		t.Fatalf("expected 0x04030201, got 0x%08x", v)
	}
}

func TestReadU64le_HappyPath(t *testing.T) {
	off := 0
	v, err := readU64le([]byte{1, 2, 3, 4, 5, 6, 7, 8}, &off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 0x0807060504030201 {
		t.Fatalf("expected 0x0807060504030201, got 0x%016x", v)
	}
}

func TestReadU8_EOF(t *testing.T) {
	off := 0
	_, err := readU8([]byte{}, &off)
	if err == nil {
		t.Fatal("expected EOF error")
	}
}

func TestReadU16le_EOF(t *testing.T) {
	off := 0
	_, err := readU16le([]byte{0x01}, &off)
	if err == nil {
		t.Fatal("expected EOF error for short buffer")
	}
}
