package node

import (
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// buildPolicyInputSnapshotIfNeeded returns the immutable pre-validation
// snapshot of only the transaction inputs that policy lanes inspect.
// The snapshot is needed only by policy lanes that read tx inputs from
// utxos (CORE_EXT pre-activation gate, or a DA-bearing tx under any
// non-zero DA-side fee term); non-DA tx with no CORE_EXT gate skip the
// map-copy entirely (returns nil, nil). Built before
// CheckTransaction*WithOwnedUtxoSet because that helper takes
// ownership of the supplied utxo map and removes spent inputs as part
// of validation. Extracted from checkTransactionWithSnapshot to keep
// cyclomatic complexity within the repository's lint budget.
func buildPolicyInputSnapshotIfNeeded(parsedTx *consensus.Tx, snapshot *chainStateAdmissionSnapshot, policy MempoolConfig) (map[consensus.Outpoint]consensus.UtxoEntry, error) {
	needs, err := policyNeedsInputSnapshotForTx(parsedTx, policy)
	if err != nil {
		return nil, txAdmitRejected(err.Error())
	}
	if !needs {
		return nil, nil
	}
	policyUtxos, err := policyInputSnapshot(parsedTx, snapshot.utxos)
	if err != nil {
		return nil, txAdmitRejected(err.Error())
	}
	return policyUtxos, nil
}

// checkTxParseAndContext resolves the chain-context inputs every
// admission needs (next block height + MTP) and parses the candidate
// transaction in canonical-bytes mode. Extracted from
// checkTransactionWithSnapshot to keep cyclomatic complexity within
// the repository's lint budget. Returns the parsed Tx, next-block
// height, next-block MTP, or a typed admission error if any step
// fails (Unavailable for chain-context failure, Rejected for parse
// failure / trailing bytes).
func (m *Mempool) checkTxParseAndContext(txBytes []byte, snapshot *chainStateAdmissionSnapshot) (*consensus.Tx, uint64, uint64, error) {
	if snapshot == nil {
		return nil, 0, 0, txAdmitUnavailable("nil chainstate")
	}
	nextHeight, _, err := nextBlockContextFromFields(snapshot.hasTip, snapshot.height, snapshot.tipHash)
	if err != nil {
		return nil, 0, 0, txAdmitUnavailable(err.Error())
	}
	blockMTP, err := m.nextBlockMTP(nextHeight)
	if err != nil {
		return nil, 0, 0, txAdmitUnavailable(err.Error())
	}
	parsedTx, _, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		return nil, 0, 0, txAdmitRejected(err.Error())
	}
	if consumed != len(txBytes) {
		return nil, 0, 0, txAdmitRejected("trailing bytes after canonical tx")
	}
	return parsedTx, nextHeight, blockMTP, nil
}

// checkTransactionWithSnapshot validates a transaction against a consistent
// owned admission snapshot plus an immutable mempool policy snapshot.
//
// `snappedFloor` is the rolling-relay-floor value snapped ONCE in the
// caller (`addTxWithSource`) before either the precheck or the locked
// admission path runs. The precheck uses this snapped value directly
// (wave-6); the locked admission path enforces
// `max(snappedFloor, m.currentMinFeeRateLocked())` (wave-8) so newer
// HIGHER floors raised by `raiseMinFeeRateAfterEvictionLocked` win,
// while spurious-reject under `decayMinFeeRateAfterConnectedBlockLocked`
// remains the lesser evil (caller can retry against the fresher
// snapshot). Bidirectional race protection biased toward strict.
func (m *Mempool) checkTransactionWithSnapshot(txBytes []byte, snapshot *chainStateAdmissionSnapshot, policy MempoolConfig, snappedFloor uint64) (*consensus.CheckedTransaction, []consensus.Outpoint, error) {
	parsedTx, nextHeight, blockMTP, err := m.checkTxParseAndContext(txBytes, snapshot)
	if err != nil {
		return nil, nil, err
	}
	// Only plain P2PK candidates use the cheap floor reject. Transactions
	// that may hit DA, CORE_ANCHOR, CORE_EXT, or missing-UTXO policy lanes
	// keep the existing validation and policy-error precedence below.
	// Wave-4 (PR #1422): pass nextHeight + policy.RotationProvider so the
	// precheck can defer on consensus-invalid P2PK output shapes
	// (value==0, wrong covenant_data length, suite outside native create
	// set) that ValidateTxCovenantsGenesis would return Rejected
	// (terminal). Without these passes a below-floor + malformed tx
	// would be misclassified as transient Unavailable instead of
	// Rejected (terminal).
	if err := cheapFeeFloorPrecheck(parsedTx, snapshot, snappedFloor, nextHeight, policy.RotationProvider, policy.SuiteRegistry); err != nil {
		return nil, nil, err
	}
	policyUtxos, err := buildPolicyInputSnapshotIfNeeded(parsedTx, snapshot, policy)
	if err != nil {
		return nil, nil, err
	}
	checked, err := consensus.CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		txBytes,
		snapshot.utxos,
		nextHeight,
		blockMTP,
		m.chainID,
		policy.CoreExtProfiles,
		policy.RotationProvider,
		policy.SuiteRegistry,
	)
	if err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}
	if err := m.applyPolicyAgainstState(checked, nextHeight, policyUtxos, policy); err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}
	inputs := make([]consensus.Outpoint, 0, len(checked.Tx.Inputs))
	for _, in := range checked.Tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	return checked, inputs, nil
}
