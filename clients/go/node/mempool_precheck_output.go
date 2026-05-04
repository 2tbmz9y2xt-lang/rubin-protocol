package node

import (
	"math/bits"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// feePrecheckP2PKOutputValue returns the sum of P2PK output values when
// every output is a CONSENSUS-VALID `COV_TYPE_P2PK` (non-zero value,
// exactly `MAX_P2PK_COVENANT_DATA == 33` byte covenant_data, and a
// suite_id in the active `NativeCreateSuites(nextHeight)` set) and the
// running sum does not overflow `uint64`. Returns `(0, false)` for any
// other shape so the caller defers to the expensive admission path.
//
// Wave-4 class-closure conservatism: each guard mirrors a permanent-
// reject branch in `ValidateTxCovenantsGenesis` at
// `clients/go/consensus/covenant_genesis.go (`ValidateTxCovenantsGenesis`)`. Without them a
// below-floor tx with consensus-invalid P2PK outputs would be
// misclassified as transient Unavailable instead of permanent Rejected.
// Mirrors Rust `fee_precheck_p2pk_output_value` at
// `clients/rust/crates/rubin-node/src/txpool.rs`.
func feePrecheckP2PKOutputValue(outputs []consensus.TxOutput, nextHeight uint64, rotation consensus.RotationProvider) (uint64, bool) {
	if rotation == nil {
		rotation = consensus.DefaultRotationProvider{}
	}
	nativeSuites := rotation.NativeCreateSuites(nextHeight)
	var total uint64
	for _, out := range outputs {
		if out.CovenantType != consensus.COV_TYPE_P2PK {
			return 0, false
		}
		// Wave-4 class-closure conservatism: each guard mirrors a
		// permanent-reject branch in ValidateTxCovenantsGenesis
		// (covenant_genesis.go (`ValidateTxCovenantsGenesis`)).
		if out.Value == 0 {
			return 0, false
		}
		if uint64(len(out.CovenantData)) != consensus.MAX_P2PK_COVENANT_DATA {
			return 0, false
		}
		suiteID := out.CovenantData[0]
		if !nativeSuites.Contains(suiteID) {
			return 0, false
		}
		next, carry := bits.Add64(total, out.Value, 0)
		if carry != 0 {
			return 0, false
		}
		total = next
	}
	return total, true
}
