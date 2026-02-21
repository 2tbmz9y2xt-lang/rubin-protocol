package consensus

func readCompactSize(b []byte, off *int) (uint64, int, error) {
	start := *off
	tag, err := readU8(b, off)
	if err != nil {
		return 0, 0, err
	}

	switch {
	case tag < 0xfd:
		return uint64(tag), *off - start, nil
	case tag == 0xfd:
		v, err := readU16le(b, off)
		if err != nil {
			return 0, 0, err
		}
		if v < 0xfd {
			return 0, 0, txerr(TX_ERR_PARSE, "non-minimal CompactSize (0xfd)")
		}
		return uint64(v), *off - start, nil
	case tag == 0xfe:
		v, err := readU32le(b, off)
		if err != nil {
			return 0, 0, err
		}
		if v <= 0xffff {
			return 0, 0, txerr(TX_ERR_PARSE, "non-minimal CompactSize (0xfe)")
		}
		return uint64(v), *off - start, nil
	case tag == 0xff:
		v, err := readU64le(b, off)
		if err != nil {
			return 0, 0, err
		}
		if v <= 0xffff_ffff {
			return 0, 0, txerr(TX_ERR_PARSE, "non-minimal CompactSize (0xff)")
		}
		return v, *off - start, nil
	default:
		// unreachable
		return 0, 0, txerr(TX_ERR_PARSE, "invalid CompactSize tag")
	}
}
