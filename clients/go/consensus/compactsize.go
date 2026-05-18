package consensus

func readCompactSize(b []byte, off *int) (uint64, int, error) {
	start := *off
	tag, err := readU8(b, off)
	if err != nil {
		return 0, 0, err
	}
	v, err := readCompactSizeTagged(tag, b, off)
	if err != nil {
		return 0, 0, err
	}
	return v, *off - start, nil
}

func readCompactSizeTagged(tag byte, b []byte, off *int) (uint64, error) {
	if tag < 0xfd {
		return uint64(tag), nil
	}
	switch tag {
	case 0xfd:
		return readCompactSize16(b, off)
	case 0xfe:
		return readCompactSize32(b, off)
	case 0xff:
		return readCompactSize64(b, off)
	default:
		return 0, txerr(TX_ERR_PARSE, "invalid CompactSize tag")
	}
}

func readCompactSize16(b []byte, off *int) (uint64, error) {
	v, err := readU16le(b, off)
	if err != nil {
		return 0, err
	}
	if v < 0xfd {
		return 0, txerr(TX_ERR_PARSE, "non-minimal CompactSize (0xfd)")
	}
	return uint64(v), nil
}

func readCompactSize32(b []byte, off *int) (uint64, error) {
	v, err := readU32le(b, off)
	if err != nil {
		return 0, err
	}
	if v <= 0xffff {
		return 0, txerr(TX_ERR_PARSE, "non-minimal CompactSize (0xfe)")
	}
	return uint64(v), nil
}

func readCompactSize64(b []byte, off *int) (uint64, error) {
	v, err := readU64le(b, off)
	if err != nil {
		return 0, err
	}
	if v <= 0xffff_ffff {
		return 0, txerr(TX_ERR_PARSE, "non-minimal CompactSize (0xff)")
	}
	return v, nil
}
