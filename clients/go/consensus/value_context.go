package consensus

// Uint128 is the public representation of a consensus u128 value.
// The numeric value is Hi*2^64 + Lo.
type Uint128 struct {
	Lo uint64
	Hi uint64
}

// TxContextBase carries tx-wide value totals used by shared value
// conservation checks.
type TxContextBase struct {
	TotalIn  Uint128
	TotalOut Uint128
	Height   uint64
}

func uint128FromInternal(v u128) Uint128 {
	return Uint128{
		Lo: v.lo,
		Hi: v.hi,
	}
}

func uint128ToInternal(v Uint128) u128 {
	return u128{
		lo: v.Lo,
		hi: v.Hi,
	}
}

func sumTxContextInputValues(resolvedInputs []UtxoEntry, initial u128) (u128, error) {
	total := initial
	for _, entry := range resolvedInputs {
		var err error
		total, err = addU64ToU128(total, entry.Value)
		if err != nil {
			return u128{}, err
		}
	}
	return total, nil
}

func sumTxContextOutputValues(outputs []TxOutput, initial u128) (u128, error) {
	total := initial
	for _, out := range outputs {
		var err error
		total, err = addU64ToU128(total, out.Value)
		if err != nil {
			return u128{}, err
		}
	}
	return total, nil
}

// CheckValueConservationTxWide applies the canonical tx-wide value
// conservation rules against immutable tx totals. The vault floor input is
// ignored unless the transaction spends exactly one CORE_VAULT input.
func CheckValueConservationTxWide(
	base *TxContextBase,
	hasExactOneVaultInput bool,
	vaultInputSum Uint128,
) *TxError {
	if base == nil {
		return &TxError{Code: TX_ERR_PARSE, Msg: "txcontext base missing"}
	}

	totalIn := uint128ToInternal(base.TotalIn)
	totalOut := uint128ToInternal(base.TotalOut)
	if cmpU128(totalOut, totalIn) > 0 {
		return &TxError{Code: TX_ERR_VALUE_CONSERVATION, Msg: "sum_out exceeds sum_in"}
	}

	if hasExactOneVaultInput {
		vaultFloor := uint128ToInternal(vaultInputSum)
		if cmpU128(totalOut, vaultFloor) < 0 {
			return &TxError{Code: TX_ERR_VALUE_CONSERVATION, Msg: "CORE_VAULT value must not fund miner fee"}
		}
	}

	return nil
}
