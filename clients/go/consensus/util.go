package consensus

import (
	"encoding/binary"
	"fmt"
)

// maxIntAsUint64 returns the maximum value representable by the built-in int type, expressed as a uint64.
// The result is platform-dependent (e.g., 2^31-1 on 32-bit systems, 2^63-1 on 64-bit systems).
func maxIntAsUint64() uint64 {
	return uint64(^uint(0) >> 1)
}

// If v is greater than maxIntAsUint64() it returns an error formatted "parse: <name> overflows usize".
func toIntLen(v uint64, name string) (int, error) {
	if v > maxIntAsUint64() {
		return 0, fmt.Errorf("parse: %s overflows usize", name)
	}
	// #nosec G115 -- v is bounded to int by maxIntAsUint64 above.
	return int(v), nil
}

// u32ToInt converts a uint32 to an int if it does not exceed the provided maximum bound.
// It returns an error "parse: <name> invalid bound" when max is negative, and
// "parse: <name> does not fit int" when v is greater than max.
func u32ToInt(v uint32, name string, max int) (int, error) {
	if max < 0 {
		return 0, fmt.Errorf("parse: %s invalid bound", name)
	}
	if uint64(v) > uint64(max) {
		return 0, fmt.Errorf("parse: %s does not fit int", name)
	}
	// #nosec G115 -- v is bounded to max via explicit uint32 comparison above.
	return int(v), nil
}

// addUint64 returns the sum of a and b or an error if the addition would overflow uint64.
// If overflow would occur it returns 0 and an error with message "TX_ERR_PARSE".
func addUint64(a, b uint64) (uint64, error) {
	if b > (^uint64(0) - a) {
		return 0, fmt.Errorf("TX_ERR_PARSE")
	}
	return a + b, nil
}

// subUint64 subtracts b from a and prevents underflow.
// It returns the difference a - b and nil on success. If b is greater than a it
// returns 0 and an error with message "TX_ERR_VALUE_CONSERVATION".
func subUint64(a, b uint64) (uint64, error) {
	if b > a {
		return 0, fmt.Errorf("TX_ERR_VALUE_CONSERVATION")
	}
	return a - b, nil
}

// parseU64LE parses an unsigned 64-bit little-endian integer from v starting at start.
// If fewer than 8 bytes are available at start it returns an error "parse: <name> truncated".
// On success it returns the parsed uint64 and a nil error.
func parseU64LE(v []byte, start int, name string) (uint64, error) {
	if start+8 > len(v) {
		return 0, fmt.Errorf("parse: %s truncated", name)
	}
	var tmp [8]byte
	copy(tmp[:], v[start:start+8])
	return binary.LittleEndian.Uint64(tmp[:]), nil
}

// isZeroOutPoint reports whether the provided TxOutPoint represents the special zero outpoint used for coinbase inputs.
// It returns true if TxID is all zero bytes and Vout equals TX_COINBASE_PREVOUT_VOUT, false otherwise.
func isZeroOutPoint(prevout TxOutPoint) bool {
	return prevout.TxID == ([32]byte{}) && prevout.Vout == TX_COINBASE_PREVOUT_VOUT
}

// isCoinbaseTx reports whether tx is a coinbase transaction for the given blockHeight.
// 
// A transaction is considered coinbase only if all of the following hold:
// - tx is non-nil and has exactly one input,
// - tx.Locktime equals blockHeight,
// - tx.TxNonce is zero,
// - there are no witness items,
// - the single input references the zero outpoint,
// - the input's Sequence equals TX_COINBASE_PREVOUT_VOUT,
// - the input's ScriptSig has length zero.
func isCoinbaseTx(tx *Tx, blockHeight uint64) bool {
	if tx == nil {
		return false
	}
	if len(tx.Inputs) != 1 {
		return false
	}
	if uint64(tx.Locktime) != blockHeight {
		return false
	}
	if tx.TxNonce != 0 {
		return false
	}
	if len(tx.Witness.Witnesses) != 0 {
		return false
	}
	txin := tx.Inputs[0]
	return isZeroOutPoint(TxOutPoint{TxID: txin.PrevTxid, Vout: txin.PrevVout}) &&
		txin.Sequence == TX_COINBASE_PREVOUT_VOUT &&
		len(txin.ScriptSig) == 0
}

// isScriptSigZeroLen checks that the scriptSig length for the named item is zero.
// If scriptSigLen is not zero, it returns an error "parse: <itemName> script_sig must be empty"; otherwise it returns nil.
func isScriptSigZeroLen(itemName string, scriptSigLen int) error {
	if scriptSigLen != 0 {
		return fmt.Errorf("parse: %s script_sig must be empty", itemName)
	}
	return nil
}