package node

import (
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// cheapFeeFloorPrecheck fast-rejects below-floor plain P2PK transactions
// before the expensive ML-DSA signature verification, mirroring Rust
// `cheap_fee_floor_precheck` at
// `clients/rust/crates/rubin-node/src/txpool.rs`.
//
// Wave-4 class-closure conservatism: defer when the slow path
// (`ValidateTxCovenantsGenesis` and the per-tx nonce/UTXO checks
// inside `applyNonCoinbaseTxBasic*`) would return Rejected (terminal).
// Without these defers a below-floor tx that ALSO has a structural
// defect would be misclassified as transient Unavailable instead of
// Rejected (terminal), masking the structural error and allowing
// callers to retry forever.
//
// tx_nonce == 0 for non-coinbase: slow path returns
// `txerr(TX_ERR_TX_NONCE_INVALID, "tx_nonce must be >= 1 for
// non-coinbase")` at `clients/go/consensus/connect_block_parallel.go:290`
// and `clients/go/consensus/utxo_basic.go:161`.
func cheapFeeFloorPrecheck(tx *consensus.Tx, snapshot *chainStateAdmissionSnapshot, minFeeRate uint64, nextHeight uint64, rotation consensus.RotationProvider, registry *consensus.SuiteRegistry) error {
	if precheckEarlyDefer(tx) {
		return nil
	}
	inputValue, ok := feePrecheckP2PKInputValue(tx, snapshot.utxos, nextHeight, rotation, registry)
	if !ok {
		return nil
	}
	outputValue, ok := feePrecheckP2PKOutputValue(tx.Outputs, nextHeight, rotation)
	if !ok || outputValue > inputValue {
		return nil
	}
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil || weight == 0 {
		return nil
	}
	fee := inputValue - outputValue
	if feeRateBelowFloor(fee, weight, minFeeRate) {
		return txAdmitUnavailable(fmt.Sprintf("mempool fee below rolling minimum: fee=%d weight=%d min_fee_rate=%d", fee, weight, minFeeRate))
	}
	return nil
}

// precheckEarlyDefer returns true when the tx shape disqualifies it
// from the cheap fast-reject path: non-plain tx_kind, DA-bearing
// payload, or tx_nonce == 0 (slow path returns Rejected
// TX_ERR_TX_NONCE_INVALID at clients/go/consensus/utxo_basic.go:160-162
// — wave-4 class-closure conservatism). Extracted from
// cheapFeeFloorPrecheck to keep cyclomatic complexity within the
// repository's lint budget.
func precheckEarlyDefer(tx *consensus.Tx) bool {
	return tx.TxKind != 0x00 || len(tx.DaPayload) != 0 || tx.TxNonce == 0
}
