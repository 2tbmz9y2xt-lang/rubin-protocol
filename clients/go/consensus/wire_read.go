package consensus

import "encoding/binary"

func readU8(b []byte, off *int) (uint8, error) {
	if *off < 0 || *off >= len(b) {
		return 0, txerr(TX_ERR_PARSE, "unexpected EOF (u8)")
	}
	v := b[*off]
	*off++
	return v, nil
}

func readU16le(b []byte, off *int) (uint16, error) {
	if *off < 0 || *off > len(b) || 2 > len(b)-*off {
		return 0, txerr(TX_ERR_PARSE, "unexpected EOF (u16le)")
	}
	v := binary.LittleEndian.Uint16(b[*off : *off+2])
	*off += 2
	return v, nil
}

func readU32le(b []byte, off *int) (uint32, error) {
	if *off < 0 || *off > len(b) || 4 > len(b)-*off {
		return 0, txerr(TX_ERR_PARSE, "unexpected EOF (u32le)")
	}
	v := binary.LittleEndian.Uint32(b[*off : *off+4])
	*off += 4
	return v, nil
}

func readU64le(b []byte, off *int) (uint64, error) {
	if *off < 0 || *off > len(b) || 8 > len(b)-*off {
		return 0, txerr(TX_ERR_PARSE, "unexpected EOF (u64le)")
	}
	v := binary.LittleEndian.Uint64(b[*off : *off+8])
	*off += 8
	return v, nil
}

func readBytes(b []byte, off *int, n int) ([]byte, error) {
	if n < 0 {
		return nil, txerr(TX_ERR_PARSE, "negative length")
	}
	if *off < 0 || *off > len(b) {
		return nil, txerr(TX_ERR_PARSE, "unexpected EOF (bytes)")
	}
	if n > len(b)-*off {
		return nil, txerr(TX_ERR_PARSE, "unexpected EOF (bytes)")
	}
	v := b[*off : *off+n]
	*off += n
	return v, nil
}
