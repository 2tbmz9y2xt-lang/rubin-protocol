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

// RejectDaAnchorTxPolicy implements policy-only DA/anchor anti-abuse checks
// aligned with POLICY_MEMPOOL_ADMISSION_GENESIS.md Stage C:
//
//	fee(tx)             = sum_inputs - sum_outputs
//	relay_fee_floor(tx) = weight(tx) * currentMempoolMinFeeRate
//	da_fee_floor(tx)    = da_payload_len(tx) * minDaFeeRate
//	da_surcharge(tx)    = da_payload_len(tx) * daSurchargePerByte
//	da_required_fee(tx) = da_fee_floor(tx) + da_surcharge(tx)
//	required_fee(tx)    = max(relay_fee_floor(tx), da_required_fee(tx))
//	reject if fee(tx) < required_fee(tx)
//
// Arithmetic is checked widening; any overflow rejects fail-closed as a
// policy error. The helper does not change consensus validity. Non-DA
// transactions (da_payload_len == 0) keep the relay-fee floor only.
//
// Inputs:
//   - weight: consensus tx weight; supplied by the caller because callers
//     already compute weight via consensus.TxWeightAndStats.
//   - currentMempoolMinFeeRate: rolling local mempool floor exposed by
//     #1336 (e.g. Mempool.currentMinFeeRateLocked()). Callers without a
//     live mempool may use DefaultMempoolMinFeeRate as the documented
//     default for that rolling state — not a parallel floor invention.
//   - minDaFeeRate: the spec-side DA per-byte floor
//     (POLICY_MEMPOOL_ADMISSION_GENESIS.md Stage C `min_da_fee_rate`,
//     default 1).
//   - daSurchargePerByte: operator-tunable DA per-byte surcharge added on
//     top of the spec-side floor; default 0 disables only the surcharge,
//     not the DA floor.
//
// Miner template budget capping is enforced by the caller (needs running sum).
func RejectDaAnchorTxPolicy(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	weight uint64,
	currentMempoolMinFeeRate uint64,
	minDaFeeRate uint64,
	daSurchargePerByte uint64,
) (reject bool, daBytes uint64, reason string, err error) {
	if tx == nil {
		return true, 0, "nil tx", errors.New("nil tx")
	}
	_, daBytes, _, err = consensus.TxWeightAndStats(tx)
	if err != nil {
		return true, 0, "tx weight/stats error", err
	}
	if daBytes == 0 {
		// Non-DA transaction: this helper only enforces the DA half of
		// the Stage C admission contract. The relay-fee floor for non-DA
		// transactions is enforced by the mempool admission path
		// (validateFeeFloorLocked), so the helper deliberately
		// short-circuits and does not compute fee or apply any
		// DA-specific term to non-DA transactions.
		return false, 0, "", nil
	}
	relayFloor, err := mulU64NoOverflow(weight, currentMempoolMinFeeRate)
	if err != nil {
		return true, daBytes, fmt.Sprintf("relay fee floor overflow (weight=%d current_mempool_min_fee_rate=%d)", weight, currentMempoolMinFeeRate), err
	}
	daFloor, err := mulU64NoOverflow(daBytes, minDaFeeRate)
	if err != nil {
		return true, daBytes, fmt.Sprintf("DA fee floor overflow (da_payload_len=%d min_da_fee_rate=%d)", daBytes, minDaFeeRate), err
	}
	daSurcharge, err := mulU64NoOverflow(daBytes, daSurchargePerByte)
	if err != nil {
		return true, daBytes, fmt.Sprintf("DA surcharge overflow (da_payload_len=%d surcharge_per_byte=%d)", daBytes, daSurchargePerByte), err
	}
	daRequired := daFloor
	if err := addU64NoOverflow(&daRequired, daSurcharge); err != nil {
		return true, daBytes, fmt.Sprintf("DA required fee overflow (da_fee_floor=%d da_surcharge=%d)", daFloor, daSurcharge), err
	}
	required := relayFloor
	if daRequired > required {
		required = daRequired
	}
	if required == 0 {
		// DA tx but every Stage C term is zero (zero weight + zero DA
		// constants). Nothing to enforce; admit without fee compute.
		return false, daBytes, "", nil
	}
	fee, err := computeFeeNoVerify(tx, utxos)
	if err != nil {
		return true, daBytes, "cannot compute fee for DA tx (policy)", err
	}
	if fee < required {
		return true, daBytes, fmt.Sprintf(
			"DA fee below Stage C floor (fee=%d required_fee=%d relay_fee_floor=%d da_fee_floor=%d da_surcharge=%d weight=%d da_payload_len=%d)",
			fee, required, relayFloor, daFloor, daSurcharge, weight, daBytes,
		), nil
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
