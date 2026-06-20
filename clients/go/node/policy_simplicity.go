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
	kind := covenantPolicyKind(tx, utxos, consensus.COV_TYPE_CORE_SIMPLICITY)
	if kind == "" {
		return false, "", nil
	}
	active := false
	if provider, ok := rotation.(consensus.SimplicityDeploymentProvider); ok {
		active, err = provider.SimplicityActiveAtHeight(height)
		if err != nil {
			return true, "CORE_SIMPLICITY deployment lookup failure",
				fmt.Errorf("CORE_SIMPLICITY deployment lookup failure: %w", err)
		}
	}
	if active {
		return false, "", nil
	}
	if rotation == nil {
		rotation = consensus.DefaultRotationProvider{}
	}
	if err := consensus.ValidateTxCovenantsGenesis(tx, height, activeSimplicityGenesisRotation{RotationProvider: rotation}); err != nil {
		return false, "", err
	}
	return true, fmt.Sprintf("CORE_SIMPLICITY %s pre-ACTIVE", kind), nil
}

func rejectUnsupportedCoreExtNodeRuntime(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
) (reject bool, reason string) {
	if kind := covenantPolicyKind(tx, utxos, consensus.COV_TYPE_CORE_EXT); kind != "" {
		return true, fmt.Sprintf("CORE_EXT %s unsupported by Go node runtime", kind)
	}
	if utxos == nil && len(tx.Inputs) > 0 {
		return true, "input snapshot unavailable for CORE_EXT unsupported policy"
	}
	return false, ""
}

func covenantPolicyKind(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry, covenantType uint16) string {
	if tx == nil {
		return ""
	}
	for _, out := range tx.Outputs {
		if out.CovenantType == covenantType {
			return "output"
		}
	}
	if utxos == nil {
		return ""
	}
	for _, in := range tx.Inputs {
		op := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		if utxos[op].CovenantType == covenantType {
			return "spend"
		}
	}
	return ""
}

type activeSimplicityGenesisRotation struct {
	consensus.RotationProvider
}

func (activeSimplicityGenesisRotation) SimplicityActiveAtHeight(uint64) (bool, error) {
	return true, nil
}
