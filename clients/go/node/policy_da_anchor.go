package node

import (
	"errors"
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// RejectNonCoinbaseAnchorOutputs implements policy-only "CORE_ANCHOR is non-standard outside coinbase".
//
// It returns reject=true if the transaction creates a CORE_ANCHOR output (COV_TYPE_ANCHOR).
// This check is independent from consensus validity and is intended for wallet/mempool/miner policy.
func RejectNonCoinbaseAnchorOutputs(tx *consensus.Tx) (reject bool, reason string, err error) {
	if tx == nil {
		return true, "nil tx", errors.New("nil tx")
	}
	for _, out := range tx.Outputs {
		if out.CovenantType == consensus.COV_TYPE_ANCHOR {
			return true, "non-coinbase CORE_ANCHOR is non-standard (policy)", nil
		}
	}
	return false, "", nil
}

// RejectDaAnchorTxPolicy implements policy-only DA/anchor anti-abuse checks.
//
// Current policy surface (no consensus changes):
//   - Compute da_bytes(tx) using consensus weight accounting (TxWeightAndStats).
//   - If da_bytes(tx) > 0 and daSurchargePerByte > 0, require:
//     fee(tx) >= da_bytes(tx) * daSurchargePerByte
//     Fee is computed from the provided UTXO snapshot without signature verification.
//
// Miner template budget capping is enforced by the caller (needs running sum).
func RejectDaAnchorTxPolicy(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	daSurchargePerByte uint64,
) (reject bool, daBytes uint64, reason string, err error) {
	if tx == nil {
		return true, 0, "nil tx", errors.New("nil tx")
	}
	_, daBytes, _, err = consensus.TxWeightAndStats(tx)
	if err != nil {
		return true, 0, "tx weight/stats error", err
	}
	if daBytes == 0 || daSurchargePerByte == 0 {
		return false, daBytes, "", nil
	}
	minFee, err := mulU64NoOverflow(daBytes, daSurchargePerByte)
	if err != nil {
		return true, daBytes, "min fee overflow", err
	}
	fee, err := computeFeeNoVerify(tx, utxos)
	if err != nil {
		return true, daBytes, "cannot compute fee for DA tx (policy)", err
	}
	if fee < minFee {
		return true, daBytes, fmt.Sprintf("DA fee below policy minimum (fee=%d min_fee=%d)", fee, minFee), nil
	}
	return false, daBytes, "", nil
}

func computeFeeNoVerify(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry) (uint64, error) {
	if tx == nil {
		return 0, errors.New("nil tx")
	}
	if len(tx.Inputs) == 0 {
		return 0, errors.New("missing inputs")
	}
	if utxos == nil {
		return 0, errors.New("nil utxo set")
	}
	var sumIn uint64
	for _, in := range tx.Inputs {
		op := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		entry, ok := utxos[op]
		if !ok {
			return 0, errors.New("missing utxo")
		}
		next := sumIn + entry.Value
		if next < sumIn {
			return 0, errors.New("sum_in overflow")
		}
		sumIn = next
	}
	var sumOut uint64
	for _, out := range tx.Outputs {
		next := sumOut + out.Value
		if next < sumOut {
			return 0, errors.New("sum_out overflow")
		}
		sumOut = next
	}
	if sumOut > sumIn {
		return 0, errors.New("overspend")
	}
	return sumIn - sumOut, nil
}

func mulU64NoOverflow(a uint64, b uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a > ^uint64(0)/b {
		return 0, errors.New("u64 overflow")
	}
	return a * b, nil
}
