package consensus

import (
	"encoding/binary"
	"fmt"
)

type cursor struct {
	b   []byte
	pos int
}

// newCursor creates a cursor for reading from b with the initial read position set to 0.
func newCursor(b []byte) *cursor {
	return &cursor{b: b, pos: 0}
}

func (c *cursor) remaining() int {
	if c.pos >= len(c.b) {
		return 0
	}
	return len(c.b) - c.pos
}

func (c *cursor) readExact(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, fmt.Errorf("parse: truncated")
	}
	start := c.pos
	c.pos += n
	return c.b[start:c.pos], nil
}

func (c *cursor) readU8() (byte, error) {
	b, err := c.readExact(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) readU16LE() (uint16, error) {
	b, err := c.readExact(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (c *cursor) readU32LE() (uint32, error) {
	b, err := c.readExact(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (c *cursor) readU64LE() (uint64, error) {
	b, err := c.readExact(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (c *cursor) readCompactSize() (uint64, error) {
	cs, used, err := DecodeCompactSize(c.b[c.pos:])
	if err != nil {
		return 0, err
	}
	c.pos += used
	return uint64(cs), nil
}
