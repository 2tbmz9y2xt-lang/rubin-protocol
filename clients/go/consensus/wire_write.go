package consensus

import "encoding/binary"

// AppendU16le appends v as a 2-byte little-endian value to dst.
func AppendU16le(dst []byte, v uint16) []byte {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], v)
	return append(dst, buf[:]...)
}

// AppendU32le appends v as a 4-byte little-endian value to dst.
func AppendU32le(dst []byte, v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return append(dst, buf[:]...)
}

// AppendU64le appends v as an 8-byte little-endian value to dst.
func AppendU64le(dst []byte, v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return append(dst, buf[:]...)
}
