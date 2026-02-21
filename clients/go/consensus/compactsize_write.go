package consensus

func appendCompactSize(dst []byte, n uint64) []byte {
	switch {
	case n < 0xfd:
		return append(dst, byte(n))
	case n <= 0xffff:
		dst = append(dst, 0xfd)
		return appendU16le(dst, uint16(n))
	case n <= 0xffff_ffff:
		dst = append(dst, 0xfe)
		return appendU32le(dst, uint32(n))
	default:
		dst = append(dst, 0xff)
		return appendU64le(dst, n)
	}
}
