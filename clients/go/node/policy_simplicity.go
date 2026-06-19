package node

import (
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func rejectCoreSimplicityPreActivation(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	height uint64,
	rotation consensus.RotationProvider,
) (reject bool, reason string, err error) {
	if tx == nil {
		return true, "nil tx", fmt.Errorf("nil tx")
	}
	kind := coreSimplicityPolicyKind(tx, utxos)
	if kind == "" {
		return false, "", nil
	}
	active, err := coreSimplicityActive(height, rotation)
	if err != nil {
		return true, "CORE_SIMPLICITY deployment lookup failure",
			fmt.Errorf("CORE_SIMPLICITY deployment lookup failure: %w", err)
	}
	if active {
		return false, "", nil
	}
	if err := validateTxCovenantsGenesisWithActiveSimplicity(tx, height, rotation); err != nil {
		return false, "", err
	}
	return true, fmt.Sprintf("CORE_SIMPLICITY %s pre-ACTIVE", kind), nil
}

func coreSimplicityPolicyKind(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry) string {
	for _, out := range tx.Outputs {
		if out.CovenantType == consensus.COV_TYPE_CORE_SIMPLICITY {
			return "output"
		}
	}
	for _, in := range tx.Inputs {
		op := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		entry, ok := utxos[op]
		if ok && entry.CovenantType == consensus.COV_TYPE_CORE_SIMPLICITY {
			return "spend"
		}
	}
	return ""
}

func coreSimplicityActive(height uint64, rotation consensus.RotationProvider) (bool, error) {
	provider, ok := rotation.(consensus.SimplicityDeploymentProvider)
	if !ok {
		return false, nil
	}
	return provider.SimplicityActiveAtHeight(height)
}

func validateTxCovenantsGenesisWithActiveSimplicity(tx *consensus.Tx, height uint64, rotation consensus.RotationProvider) error {
	if rotation == nil {
		rotation = consensus.DefaultRotationProvider{}
	}
	return consensus.ValidateTxCovenantsGenesis(tx, height, activeSimplicityGenesisRotation{RotationProvider: rotation})
}

type activeSimplicityGenesisRotation struct {
	consensus.RotationProvider
}

func (activeSimplicityGenesisRotation) SimplicityActiveAtHeight(uint64) (bool, error) {
	return true, nil
}
