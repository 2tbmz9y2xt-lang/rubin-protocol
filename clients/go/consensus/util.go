package consensus

import (
	"encoding/binary"
	"fmt"
)

func maxIntAsUint64() uint64 {
	return uint64(^uint(0) >> 1)
}

func toIntLen(v uint64, name string) (int, error) {
	if v > maxIntAsUint64() {
		return 0, fmt.Errorf("parse: %s overflows usize", name)
	}
	// #nosec G115 -- v is bounded to int by maxIntAsUint64 above.
	return int(v), nil
}

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

func addUint64(a, b uint64) (uint64, error) {
	if b > (^uint64(0) - a) {
		return 0, fmt.Errorf("TX_ERR_PARSE")
	}
	return a + b, nil
}

func subUint64(a, b uint64) (uint64, error) {
	if b > a {
		return 0, fmt.Errorf("TX_ERR_VALUE_CONSERVATION")
	}
	return a - b, nil
}

func parseU64LE(v []byte, start int, name string) (uint64, error) {
	if start+8 > len(v) {
		return 0, fmt.Errorf("parse: %s truncated", name)
	}
	var tmp [8]byte
	copy(tmp[:], v[start:start+8])
	return binary.LittleEndian.Uint64(tmp[:]), nil
}

func isZeroOutPoint(prevout TxOutPoint) bool {
	return prevout.TxID == ([32]byte{}) && prevout.Vout == TX_COINBASE_PREVOUT_VOUT
}

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

func isScriptSigZeroLen(itemName string, scriptSigLen int) error {
	if scriptSigLen != 0 {
		return fmt.Errorf("parse: %s script_sig must be empty", itemName)
	}
	return nil
}
