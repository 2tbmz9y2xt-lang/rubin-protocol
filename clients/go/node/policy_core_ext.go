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

// RejectCoreExtTxPreActivation implements non-consensus policy guardrails for CORE_EXT.
//
// It returns reject=true if tx creates or spends a CORE_EXT output whose profile(ext_id, height)
// is not ACTIVE. If profiles is nil or lookup fails/misses, the profile is treated as not ACTIVE.
//
// This is intended for wallet/mempool/miner admission policy to mitigate pre-activation
// anyone-can-spend exposure. Consensus rules are implemented elsewhere.
func RejectCoreExtTxPreActivation(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	height uint64,
	profiles consensus.CoreExtProfileProvider,
) (reject bool, reason string, err error) {
	if tx == nil {
		return true, "nil tx", fmt.Errorf("nil tx")
	}

	for _, out := range tx.Outputs {
		if out.CovenantType != consensus.COV_TYPE_CORE_EXT {
			continue
		}
		cd, err := consensus.ParseCoreExtCovenantData(out.CovenantData)
		if err != nil {
			return true, "CORE_EXT output covenant_data invalid", err
		}
		active, err := coreExtProfileActive(cd.ExtID, height, profiles)
		if err != nil {
			return true, fmt.Sprintf("CORE_EXT profile lookup error ext_id=%d", cd.ExtID), err
		}
		if !active {
			return true, fmt.Sprintf("CORE_EXT output pre-ACTIVE ext_id=%d", cd.ExtID), nil
		}
	}

	if utxos == nil {
		return false, "", nil
	}
	for _, in := range tx.Inputs {
		op := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		entry, ok := utxos[op]
		if !ok || entry.CovenantType != consensus.COV_TYPE_CORE_EXT {
			continue
		}
		cd, err := consensus.ParseCoreExtCovenantData(entry.CovenantData)
		if err != nil {
			return true, "CORE_EXT spent UTXO covenant_data invalid", err
		}
		active, err := coreExtProfileActive(cd.ExtID, height, profiles)
		if err != nil {
			return true, fmt.Sprintf("CORE_EXT profile lookup error ext_id=%d", cd.ExtID), err
		}
		if !active {
			return true, fmt.Sprintf("CORE_EXT spend pre-ACTIVE ext_id=%d", cd.ExtID), nil
		}
	}

	return false, "", nil
}
