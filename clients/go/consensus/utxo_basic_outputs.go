package consensus

func (ctx *nonCoinbaseApplyContext) addSpendableOutputs() error {
	for i, out := range ctx.tx.Outputs {
		var err error
		ctx.sumOut, err = addU64ToU128(ctx.sumOut, out.Value)
		if err != nil {
			return err
		}
		if out.CovenantType == COV_TYPE_VAULT {
			ctx.createsVault = true
		}
		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			continue
		}
		op := Outpoint{Txid: ctx.txid, Vout: uint32(i)}
		ctx.work[op] = UtxoEntry{
			Value:             out.Value,
			CovenantType:      out.CovenantType,
			CovenantData:      append([]byte(nil), out.CovenantData...),
			CreationHeight:    ctx.height,
			CreatedByCoinbase: false,
		}
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) finalizeValueAndFee() (uint64, error) {
	valueBase := &TxContextBase{
		TotalIn:  uint128FromInternal(ctx.spend.sumIn),
		TotalOut: uint128FromInternal(ctx.sumOut),
		Height:   ctx.height,
	}
	if ctx.txContext != nil {
		if errTx := requireTxContextBaseMatchesTotals(ctx.txContext.Base, valueBase.TotalIn, valueBase.TotalOut, ctx.height); errTx != nil {
			return 0, errTx
		}
	}
	if errTx := CheckValueConservationTxWide(valueBase, ctx.spend.vaultInputCount == 1, uint128FromInternal(ctx.spend.sumInVault)); errTx != nil {
		return 0, errTx
	}
	feeU128, err := subU128(ctx.spend.sumIn, ctx.sumOut)
	if err != nil {
		return 0, err
	}
	return u128ToU64(feeU128)
}
