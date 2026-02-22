package consensus

import "math/bits"

type Outpoint struct {
	Txid [32]byte
	Vout uint32
}

type UtxoEntry struct {
	Value             uint64
	CovenantType      uint16
	CovenantData      []byte
	CreationHeight    uint64
	CreatedByCoinbase bool
}

type UtxoApplySummary struct {
	Fee       uint64
	UtxoCount uint64
}

func ApplyNonCoinbaseTxBasic(tx *Tx, txid [32]byte, utxoSet map[Outpoint]UtxoEntry, height uint64, blockTimestamp uint64) (*UtxoApplySummary, error) {
	if tx == nil {
		return nil, txerr(TX_ERR_PARSE, "nil tx")
	}
	if len(tx.Inputs) == 0 {
		return nil, txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
	}

	if err := ValidateTxCovenantsGenesis(tx); err != nil {
		return nil, err
	}

	work := make(map[Outpoint]UtxoEntry, len(utxoSet))
	for k, v := range utxoSet {
		work[k] = v
	}

	var sumIn u128
	var sumInVault u128
	hasVaultInput := false
	for _, in := range tx.Inputs {
		op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		entry, ok := work[op]
		if !ok {
			return nil, txerr(TX_ERR_MISSING_UTXO, "utxo not found")
		}

		if entry.CovenantType == COV_TYPE_ANCHOR || entry.CovenantType == COV_TYPE_DA_COMMIT {
			return nil, txerr(TX_ERR_MISSING_UTXO, "attempt to spend non-spendable covenant")
		}

		if entry.CreatedByCoinbase && height < entry.CreationHeight+COINBASE_MATURITY {
			return nil, txerr(TX_ERR_COINBASE_IMMATURE, "coinbase immature")
		}

		var err error
		sumIn, err = addU64ToU128(sumIn, entry.Value)
		if err != nil {
			return nil, err
		}
		if entry.CovenantType == COV_TYPE_VAULT {
			hasVaultInput = true
			sumInVault, err = addU64ToU128(sumInVault, entry.Value)
			if err != nil {
				return nil, err
			}
		}

		delete(work, op)
	}

	var sumOut u128
	for i, out := range tx.Outputs {
		var err error
		sumOut, err = addU64ToU128(sumOut, out.Value)
		if err != nil {
			return nil, err
		}

		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			continue
		}

		op := Outpoint{Txid: txid, Vout: uint32(i)}
		work[op] = UtxoEntry{
			Value:             out.Value,
			CovenantType:      out.CovenantType,
			CovenantData:      append([]byte(nil), out.CovenantData...),
			CreationHeight:    height,
			CreatedByCoinbase: false,
		}
	}

	if cmpU128(sumOut, sumIn) > 0 {
		return nil, txerr(TX_ERR_VALUE_CONSERVATION, "sum_out exceeds sum_in")
	}
	if hasVaultInput && cmpU128(sumOut, sumInVault) < 0 {
		return nil, txerr(TX_ERR_VALUE_CONSERVATION, "vault inputs cannot fund miner fee")
	}
	feeU128, err := subU128(sumIn, sumOut)
	if err != nil {
		return nil, err
	}
	fee, err := u128ToU64(feeU128)
	if err != nil {
		return nil, err
	}

	return &UtxoApplySummary{
		Fee:       fee,
		UtxoCount: uint64(len(work)),
	}, nil
}

func checkSpendCovenant(
	covType uint16,
	covData []byte,
) error {
	if covType == COV_TYPE_P2PK {
		return nil
	}
	if covType == COV_TYPE_VAULT {
		v, err := ParseVaultCovenantData(covData)
		if err != nil {
			return err
		}
		_ = v
		return nil
	}
	// HTLC/reserved/unknown are unsupported in basic apply path.
	return txerr(TX_ERR_COVENANT_TYPE_INVALID, "unsupported covenant in basic apply")
}

type u128 struct {
	hi uint64
	lo uint64
}

func addU64ToU128(x u128, v uint64) (u128, error) {
	lo, carry := bits.Add64(x.lo, v, 0)
	hi, carry2 := bits.Add64(x.hi, 0, carry)
	if carry2 != 0 {
		return u128{}, txerr(TX_ERR_PARSE, "u128 overflow")
	}
	return u128{hi: hi, lo: lo}, nil
}

func cmpU128(a u128, b u128) int {
	if a.hi < b.hi {
		return -1
	}
	if a.hi > b.hi {
		return 1
	}
	if a.lo < b.lo {
		return -1
	}
	if a.lo > b.lo {
		return 1
	}
	return 0
}

func subU128(a u128, b u128) (u128, error) {
	if cmpU128(a, b) < 0 {
		return u128{}, txerr(TX_ERR_PARSE, "u128 underflow")
	}
	lo, borrow := bits.Sub64(a.lo, b.lo, 0)
	hi, borrow2 := bits.Sub64(a.hi, b.hi, borrow)
	if borrow2 != 0 {
		return u128{}, txerr(TX_ERR_PARSE, "u128 underflow")
	}
	return u128{hi: hi, lo: lo}, nil
}

func u128ToU64(x u128) (uint64, error) {
	if x.hi != 0 {
		return 0, txerr(TX_ERR_PARSE, "u64 overflow")
	}
	return x.lo, nil
}
