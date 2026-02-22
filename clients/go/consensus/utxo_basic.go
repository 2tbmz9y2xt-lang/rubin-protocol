package consensus

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

	var sumIn uint64
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
		sumIn, err = addU64(sumIn, entry.Value)
		if err != nil {
			return nil, err
		}

		delete(work, op)
	}

	var sumOut uint64
	for i, out := range tx.Outputs {
		var err error
		sumOut, err = addU64(sumOut, out.Value)
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

	if sumOut > sumIn {
		return nil, txerr(TX_ERR_VALUE_CONSERVATION, "sum_out exceeds sum_in")
	}

	return &UtxoApplySummary{
		Fee:       sumIn - sumOut,
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
