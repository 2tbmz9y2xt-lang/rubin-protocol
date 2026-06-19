package node

import (
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func coreExtProfileActive(extID uint16, height uint64, profiles consensus.CoreExtProfileProvider) (bool, error) {
	if profiles == nil {
		return false, nil
	}
	p, ok, err := profiles.LookupCoreExtProfile(extID, height)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	return p.Active, nil
}

func rejectCoreExtCovenantDataPreActivation(
	covenantData []byte,
	height uint64,
	profiles consensus.CoreExtProfileProvider,
	kind string,
) (reject bool, reason string, err error) {
	cd, err := consensus.ParseCoreExtCovenantData(covenantData)
	if err != nil {
		return true, fmt.Sprintf("CORE_EXT %s covenant_data invalid", kind), err
	}
	active, err := coreExtProfileActive(cd.ExtID, height, profiles)
	if err != nil {
		return true, fmt.Sprintf("CORE_EXT profile lookup error ext_id=%d", cd.ExtID), err
	}
	if !active {
		return true, fmt.Sprintf("CORE_EXT %s pre-ACTIVE ext_id=%d", kind, cd.ExtID), nil
	}
	return false, "", nil
}

// RejectCoreExtTxOversizedPayload implements SHOULD-level mempool policy that rejects
// transactions containing CORE_EXT outputs whose ext_payload exceeds maxBytes.
// This is a relay/mempool policy (not consensus), preventing oversized payloads
// from consuming mempool space before the SHOULD→MUST promotion threshold is reached.
func RejectCoreExtTxOversizedPayload(
	tx *consensus.Tx,
	maxBytes int,
) (reject bool, reason string, err error) {
	if tx == nil {
		return false, "", nil
	}
	if maxBytes <= 0 {
		return false, "", nil
	}
	for i, out := range tx.Outputs {
		if out.CovenantType != consensus.COV_TYPE_CORE_EXT {
			continue
		}
		cd, err := consensus.ParseCoreExtCovenantData(out.CovenantData)
		if err != nil {
			// Parse failure is handled by consensus validation; skip here.
			continue
		}
		if len(cd.ExtPayload) > maxBytes {
			return true, fmt.Sprintf(
				"CORE_EXT output %d ext_payload %d bytes exceeds policy limit %d",
				i, len(cd.ExtPayload), maxBytes,
			), nil
		}
	}
	return false, "", nil
}

// RejectCoreExtTxPreActivation enforces non-consensus pre-activation policy
// for CORE_EXT profiles and CORE_SIMPLICITY covenant exposure.
//
// It returns reject=true if tx creates or spends a CORE_EXT output whose profile(ext_id, height)
// is not ACTIVE, or creates/spends a CORE_SIMPLICITY output before Simplicity activation.
// If profiles is nil or lookup misses, the CORE_EXT profile is treated as not ACTIVE;
// lookup errors are returned to the caller.
// This compatibility entrypoint has no Simplicity rotation provider, so CORE_SIMPLICITY
// is treated as pre-ACTIVE. Callers that can provide Simplicity activation state must use
// RejectCoreExtTxPreActivationWithRotation.
//
// This is intended for wallet/mempool/miner admission policy to mitigate pre-activation
// anyone-can-spend exposure. Consensus rules are implemented elsewhere.
func RejectCoreExtTxPreActivation(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	height uint64,
	profiles consensus.CoreExtProfileProvider,
) (reject bool, reason string, err error) {
	return RejectCoreExtTxPreActivationWithRotation(tx, utxos, height, profiles, nil)
}

// RejectCoreExtTxPreActivationWithRotation is the rotation-aware policy entrypoint.
// It allows CORE_SIMPLICITY only when rotation reports Simplicity active at height.
func RejectCoreExtTxPreActivationWithRotation(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	height uint64,
	profiles consensus.CoreExtProfileProvider,
	rotation consensus.RotationProvider,
) (reject bool, reason string, err error) {
	if tx == nil {
		return true, "nil tx", fmt.Errorf("nil tx")
	}

	for _, out := range tx.Outputs {
		if out.CovenantType != consensus.COV_TYPE_CORE_EXT {
			continue
		}
		reject, reason, err := rejectCoreExtCovenantDataPreActivation(out.CovenantData, height, profiles, "output")
		if err != nil || reject {
			return reject, reason, err
		}
	}
	reject, reason, err = rejectCoreExtSpendsPreActivation(tx, utxos, height, profiles)
	if err != nil || reject {
		return reject, reason, err
	}
	return rejectCoreSimplicityPreActivation(tx, utxos, height, rotation)
}

func rejectCoreExtSpendsPreActivation(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	height uint64,
	profiles consensus.CoreExtProfileProvider,
) (reject bool, reason string, err error) {
	if utxos == nil {
		return false, "", nil
	}
	for _, in := range tx.Inputs {
		op := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		entry, ok := utxos[op]
		if !ok || entry.CovenantType != consensus.COV_TYPE_CORE_EXT {
			continue
		}
		reject, reason, err := rejectCoreExtCovenantDataPreActivation(entry.CovenantData, height, profiles, "spend")
		if err != nil || reject {
			return reject, reason, err
		}
	}

	return false, "", nil
}

func rejectCoreSimplicityPreActivation(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	height uint64,
	rotation consensus.RotationProvider,
) (reject bool, reason string, err error) {
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
