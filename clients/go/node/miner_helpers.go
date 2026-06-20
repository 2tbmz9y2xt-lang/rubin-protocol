package node

import (
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// rejectCandidateDAPolicy handles DA anti-abuse policy for candidate tx
func (m *Miner) rejectCandidateDAPolicy(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry, policyDaIncluded uint64) (bool, uint64, error) {
	currentMin := m.getCurrentMinFeeRate()
	// Apply minimum floor
	if currentMin < DefaultMempoolMinFeeRate {
		currentMin = DefaultMempoolMinFeeRate
	}

	reject, daBytes, _, err := RejectDaAnchorTxPolicy(
		tx,
		utxos,
		currentMin,
		m.cfg.MinDaFeeRate,
		m.cfg.PolicyDaSurchargePerByte,
	)
	if err != nil {
		return false, policyDaIncluded, err
	}
	if reject {
		return true, policyDaIncluded, nil
	}

	// Update DA byte counter
	nextDaIncluded, ok := updatedPolicyDaBytes(policyDaIncluded, daBytes, m.cfg.PolicyMaxDaBytesPerBlock)
	if !ok {
		return true, policyDaIncluded, nil
	}

	return false, nextDaIncluded, nil
}

// getCurrentMinFeeRate returns the current minimum fee rate for the miner
func (m *Miner) getCurrentMinFeeRate() uint64 {
	if fn := m.cfg.CurrentMempoolMinFeeRateFn; fn != nil {
		return fn()
	}
	return m.cfg.CurrentMempoolMinFeeRate
}

// rejectCandidateAnchorPolicy handles anchor policy for candidate tx
func (m *Miner) rejectCandidateAnchorPolicy(tx *consensus.Tx) (bool, error) {
	if !m.cfg.PolicyRejectNonCoinbaseAnchorOutputs {
		return false, nil
	}

	reject, _, err := RejectNonCoinbaseAnchorOutputs(tx)
	if err != nil {
		return false, err
	}
	return reject, nil
}

// rejectCandidateSimplicityPolicy handles Simplicity activation policy for candidate tx.
func (m *Miner) rejectCandidateSimplicityPolicy(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry, nextHeight uint64) (bool, error) {
	if !m.cfg.PolicyRejectSimplicityPreActivation {
		return false, nil
	}

	var rotation consensus.RotationProvider
	if m.sync != nil {
		rotation = m.sync.cfg.RotationProvider
	}
	reject, _, err := rejectCoreSimplicityPreActivation(tx, utxos, nextHeight, rotation)
	if err != nil {
		return false, err
	}
	return reject, nil
}
