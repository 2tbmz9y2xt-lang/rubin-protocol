package node

import (
	"errors"
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// validateChainSnapshot validates chain state snapshot and extracts next height
func validateChainSnapshot(snapshot *chainStateAdmissionSnapshot) (uint64, error) {
	if snapshot == nil {
		return 0, txAdmitUnavailable("nil chainstate")
	}
	nextHeight, _, err := nextBlockContextFromFields(snapshot.hasTip, snapshot.height, snapshot.tipHash)
	if err != nil {
		return 0, txAdmitUnavailable(err.Error())
	}
	return nextHeight, nil
}

// buildPolicyInputSnapshotIfNeeded (mempool_precheck.go) replaced the old preparePolicyUtxos; callers use it directly.

// validateTransactionWithConsensus performs consensus validation with configured profiles
func (m *Mempool) validateTransactionWithConsensus(
	txBytes []byte,
	tx *consensus.Tx,
	txid [32]byte,
	wtxid [32]byte,
	snapshot *chainStateAdmissionSnapshot,
	nextHeight uint64,
	blockMTP uint64,
	policy MempoolConfig,
) (*consensus.CheckedTransaction, error) {
	checked, err := consensus.CheckParsedTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		txBytes,
		tx,
		consensus.ParsedTxIDs{TxID: txid, WTxID: wtxid},
		snapshot.utxos,
		nextHeight,
		blockMTP,
		m.chainID,
		consensus.SuiteValidationContext{Rotation: policy.RotationProvider, Registry: policy.SuiteRegistry},
	)
	if err != nil {
		return nil, txAdmitRejected(err.Error())
	}
	return checked, nil
}

// extractTxInputs extracts outpoints from checked transaction
func extractTxInputs(checked *consensus.CheckedTransaction) []consensus.Outpoint {
	inputs := make([]consensus.Outpoint, 0, len(checked.Tx.Inputs))
	for _, in := range checked.Tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	return inputs
}

// applyPolicyAgainstStateDA handles DA fee policy application
func applyPolicyAgainstStateDA(checked *consensus.CheckedTransaction, policy MempoolConfig, utxos map[consensus.Outpoint]consensus.UtxoEntry) error {
	// Stage C DA fee policy: only enter the helper for DA-bearing tx when
	// the DA-side floor is configured (MinDaFeeRate > 0) or a per-byte
	// surcharge applies. Non-DA tx skip the helper entirely on the hot
	// admit path; their relay-floor handling remains in
	// validateFeeFloorLocked.
	//
	// The mempool admit path enforces the rolling relay-fee floor through
	// validateFeeFloorLocked (TxAdmitUnavailable — transient/retryable),
	// so this caller intentionally passes currentMempoolMinFeeRate=0 so
	// max(relay_fee_floor, da_required_fee) collapses to da_required_fee.
	// Without the zero override, a DA tx that pays the DA-side floor but
	// not the rolling relay floor would surface here as TxAdmitRejected
	// ("DA fee below Stage C floor ... relay_fee_floor=...") instead of
	// the symmetric TxAdmitUnavailable that non-DA tx receive from
	// validateFeeFloorLocked. With currentMin=0 the helper enforces only
	// the DA-specific terms and validateFeeFloorLocked owns relay-floor
	// classification uniformly for both DA and non-DA admissions.
	//
	// The miner caller (rejectCandidate) keeps using the live rolling
	// floor because it has no validateFeeFloorLocked equivalent — the
	// miner template needs to skip a tx whenever it fails any floor.
	if checked.DaBytes > 0 && (policy.MinDaFeeRate > 0 || policy.PolicyDaSurchargePerByte > 0) {
		reject, _, reason, err := RejectDaAnchorTxPolicy(
			checked.Tx,
			utxos,
			0,
			policy.MinDaFeeRate,
			policy.PolicyDaSurchargePerByte,
		)
		if err != nil {
			return txAdmitRejected(fmt.Sprintf("%s: %v", reason, err))
		}
		if reject {
			return txAdmitRejected(reason)
		}
	}
	return nil
}

func applyPolicyAgainstStateCoreExtUnsupported(checked *consensus.CheckedTransaction, utxos map[consensus.Outpoint]consensus.UtxoEntry) error {
	if reject, reason := rejectUnsupportedCoreExtNodeRuntime(checked.Tx, utxos); reject {
		return errors.New(reason)
	}
	return nil
}

func applyPolicyAgainstStateSimplicity(checked *consensus.CheckedTransaction, utxos map[consensus.Outpoint]consensus.UtxoEntry, nextHeight uint64, policy MempoolConfig) error {
	if policy.PolicyRejectSimplicityPreActivation {
		reject, reason, err := rejectCoreSimplicityPreActivation(checked.Tx, utxos, nextHeight, policy.RotationProvider)
		if err != nil {
			return err
		}
		if reject {
			return errors.New(reason)
		}
	}
	return nil
}

// applyPolicyAgainstStateAnchor handles non-coinbase anchor output policy application
func applyPolicyAgainstStateAnchor(checked *consensus.CheckedTransaction, policy MempoolConfig) error {
	if policy.PolicyRejectNonCoinbaseAnchorOutputs {
		reject, reason, err := RejectNonCoinbaseAnchorOutputs(checked.Tx)
		if err != nil {
			return err
		}
		if reject {
			return errors.New(reason)
		}
	}
	return nil
}
