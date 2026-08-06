package node

import (
	"errors"
	"fmt"
	"math/bits"

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
// TODO(rust-parity,#1352): Go implements Stage C required_fee =
// max(relay_fee_floor, da_fee_floor + da_surcharge). Rust is still tracked
// as surcharge-only per #1352; do not roll this policy out in any
// multi-client relay/miner deployment until Rust matches this behavior or a
// release gate explicitly prevents mixed-client divergence.
//
// Arithmetic is checked widening; any overflow rejects fail-closed as a
// policy error. The helper does not change consensus validity. For non-DA
// transactions (da_payload_len == 0), this helper applies no DA-specific
// fee policy; relay-fee-floor enforcement remains the caller/mempool's
// responsibility (for example via validateFeeFloorLocked).
//
// Inputs:
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
//
// The helper recomputes both `weight` and `daBytes` from `tx` via
// consensus.TxWeightAndStats. This avoids trusting any caller-supplied
// weight value (a stale or zero weight would otherwise silently
// under-enforce the relay-fee half of the Stage C predicate).
func RejectDaAnchorTxPolicy(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	currentMempoolMinFeeRate uint64,
	minDaFeeRate uint64,
	daSurchargePerByte uint64,
) (reject bool, daBytes uint64, reason string, err error) {
	if tx == nil {
		return true, 0, "nil tx", errors.New("nil tx")
	}
	weight, daBytes, _, err := consensus.TxWeightAndStats(tx)
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
	floor, reason, err := computeDaAnchorRequiredFee(
		weight,
		daBytes,
		currentMempoolMinFeeRate,
		minDaFeeRate,
		daSurchargePerByte,
	)
	if err != nil {
		return true, daBytes, reason, err
	}
	if floor.required.IsZero() {
		// DA tx but every Stage C rate-derived fee term is zero: the
		// relay-floor term is zero and both DA-side terms are zero.
		// Nothing to enforce; admit without fee compute.
		return false, daBytes, "", nil
	}
	fee, err := computeFeeNoVerify(tx, utxos)
	if err != nil {
		return true, daBytes, "cannot compute fee for DA tx (policy)", err
	}
	if fee.Cmp(floor.required) < 0 {
		return true, daBytes, fmt.Sprintf(
			"DA fee below Stage C floor (fee=%s required_fee=%s relay_fee_floor=%s da_fee_floor=%d da_surcharge=%d weight=%d da_payload_len=%d)",
			fee.String(), floor.required.String(), floor.relayFloor.String(), floor.daFloor, floor.daSurcharge, weight, daBytes,
		), nil
	}
	return false, daBytes, "", nil
}

type daAnchorRequiredFee struct {
	relayFloor  consensus.Uint128
	daFloor     uint64
	daSurcharge uint64
	required    consensus.Uint128
}

// mulU64Exact returns the exact 128-bit product of two u64 rate terms. Every
// product bit is retained, so a relay fee floor above u64 is measured exactly
// against the u128 fee instead of rejecting a transaction whose fee genuinely
// clears it. Mirrors the already-exact predicates in mempool_fee_floor.go
// (feeRateBelowFloor) and the consensus-CLI policy model
// (feeBelowRollingFloorPolicy), which never reject on this product.
func mulU64Exact(a uint64, b uint64) consensus.Uint128 {
	hi, lo := bits.Mul64(a, b)
	return consensus.Uint128{Hi: hi, Lo: lo}
}

func computeDaAnchorRequiredFee(
	weight uint64,
	daBytes uint64,
	currentMempoolMinFeeRate uint64,
	minDaFeeRate uint64,
	daSurchargePerByte uint64,
) (daAnchorRequiredFee, string, error) {
	// The relay-floor term is exact and never rejects: weight and the rolling
	// rate are both u64, so their full product fits u128 by construction.
	// The DA-side terms below keep their u64 overflow errors, whose reject
	// reasons are pinned by the shared CV-DA-FEE-FLOOR vector and by both
	// consensus-CLI policy models.
	relayFloor := mulU64Exact(weight, currentMempoolMinFeeRate)
	daFloor, err := mulU64NoOverflow(daBytes, minDaFeeRate)
	if err != nil {
		return daAnchorRequiredFee{}, fmt.Sprintf("DA fee floor overflow (da_payload_len=%d min_da_fee_rate=%d)", daBytes, minDaFeeRate), err
	}
	daSurcharge, err := mulU64NoOverflow(daBytes, daSurchargePerByte)
	if err != nil {
		return daAnchorRequiredFee{}, fmt.Sprintf("DA surcharge overflow (da_payload_len=%d surcharge_per_byte=%d)", daBytes, daSurchargePerByte), err
	}
	required, err := maxDaAnchorRequiredFee(relayFloor, daFloor, daSurcharge)
	if err != nil {
		return daAnchorRequiredFee{}, fmt.Sprintf("DA required fee overflow (da_fee_floor=%d da_surcharge=%d)", daFloor, daSurcharge), err
	}
	return daAnchorRequiredFee{
		relayFloor:  relayFloor,
		daFloor:     daFloor,
		daSurcharge: daSurcharge,
		required:    required,
	}, "", nil
}

func maxDaAnchorRequiredFee(relayFloor consensus.Uint128, daFloor uint64, daSurcharge uint64) (consensus.Uint128, error) {
	daRequired := daFloor
	if err := addU64NoOverflow(&daRequired, daSurcharge); err != nil {
		return consensus.Uint128{}, err
	}
	widened := consensus.Uint128FromU64(daRequired)
	if widened.Cmp(relayFloor) > 0 {
		return widened, nil
	}
	return relayFloor, nil
}

// computeFeeNoVerify derives the policy-side fee as an exact u128, matching
// the consensus derivation's domain. Per-input and per-output values stay
// u64; only their sums and the difference widen, so a DA transaction whose
// fee exceeds u64 is measured against the Stage C floor exactly instead of
// failing an overflow check.
func computeFeeNoVerify(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry) (consensus.Uint128, error) {
	if tx == nil {
		return consensus.Uint128{}, errors.New("nil tx")
	}
	if len(tx.Inputs) == 0 {
		return consensus.Uint128{}, errors.New("missing inputs")
	}
	if utxos == nil {
		return consensus.Uint128{}, errors.New("nil utxo set")
	}
	sumIn, err := sumInputValueNoVerify(tx, utxos)
	if err != nil {
		return consensus.Uint128{}, err
	}
	sumOut, err := sumOutputValueNoVerify(tx)
	if err != nil {
		return consensus.Uint128{}, err
	}
	fee, ok := sumIn.CheckedSub(sumOut)
	if !ok {
		return consensus.Uint128{}, errors.New("overspend")
	}
	return fee, nil
}

func sumInputValueNoVerify(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry) (consensus.Uint128, error) {
	var sumIn consensus.Uint128
	for _, in := range tx.Inputs {
		op := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		entry, ok := utxos[op]
		if !ok {
			return consensus.Uint128{}, errors.New("missing utxo")
		}
		next, ok := sumIn.CheckedAdd(consensus.Uint128FromU64(entry.Value))
		if !ok {
			return consensus.Uint128{}, errors.New("sum_in overflow")
		}
		sumIn = next
	}
	return sumIn, nil
}

func sumOutputValueNoVerify(tx *consensus.Tx) (consensus.Uint128, error) {
	var sumOut consensus.Uint128
	for _, out := range tx.Outputs {
		next, ok := sumOut.CheckedAdd(consensus.Uint128FromU64(out.Value))
		if !ok {
			return consensus.Uint128{}, errors.New("sum_out overflow")
		}
		sumOut = next
	}
	return sumOut, nil
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

func addU64NoOverflow(dst *uint64, value uint64) error {
	if value > ^uint64(0)-*dst {
		return errors.New("u64 overflow")
	}
	*dst += value
	return nil
}
