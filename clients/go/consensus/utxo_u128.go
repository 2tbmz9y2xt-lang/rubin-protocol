package consensus

import "math/bits"

func addU64ToU128WithCode(x u128, v uint64, code ErrorCode) (u128, error) {
	lo, carry := bits.Add64(x.lo, v, 0)
	hi, carry2 := bits.Add64(x.hi, 0, carry)
	if carry2 != 0 {
		return u128{}, txerr(code, "u128 overflow")
	}
	return u128{hi: hi, lo: lo}, nil
}

func cmpU128(a u128, b u128) int {
	if a.hi < b.hi {
		return -1
	}
	if a.hi > b.hi {
		return 1
	}
	if a.lo < b.lo {
		return -1
	}
	if a.lo > b.lo {
		return 1
	}
	return 0
}

func subU128(a u128, b u128) (u128, error) {
	if cmpU128(a, b) < 0 {
		return u128{}, txerr(TX_ERR_PARSE, "u128 underflow")
	}
	lo, borrow := bits.Sub64(a.lo, b.lo, 0)
	hi, borrow2 := bits.Sub64(a.hi, b.hi, borrow)
	if borrow2 != 0 {
		return u128{}, txerr(TX_ERR_PARSE, "u128 underflow")
	}
	return u128{hi: hi, lo: lo}, nil
}
