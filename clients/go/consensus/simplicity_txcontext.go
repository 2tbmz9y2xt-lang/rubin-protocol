package consensus

type SimplicityTxContextBase struct {
	ChainID     [32]byte
	TotalIn     Uint128
	TotalOut    Uint128
	Height      uint64
	TxNonce     uint64
	Locktime    uint32
	InputCount  uint16
	OutputCount uint16
	TxKind      uint8
}

type SimplicityTxContextIOView struct {
	Value        uint64
	CovenantType uint16
}

type SimplicityTxContextSelfView struct {
	SelfProgramCMR [32]byte
	Digest32       [32]byte
	SelfState      []byte
	SelfValue      uint64
	InputIndex     uint16
	SighashType    uint8
}

type simplicityTxContextSelfSource struct {
	programCMR       [32]byte
	state            []byte
	value            uint64
	isCoreSimplicity bool
}

type SimplicityTxContext struct {
	Base        SimplicityTxContextBase
	inputViews  []SimplicityTxContextIOView
	outputViews []SimplicityTxContextIOView
	selfSources []simplicityTxContextSelfSource
}

func BuildSimplicityTxContext(tx *Tx, resolvedInputs []UtxoEntry, blockHeight uint64, chainID [32]byte) (*SimplicityTxContext, error) {
	if tx == nil {
		return nil, txerr(TX_ERR_PARSE, "nil tx")
	}
	for _, check := range []struct {
		invalid bool
		message string
	}{
		{len(tx.Inputs) != len(resolvedInputs), "simplicity txcontext resolved input count mismatch"},
		{len(tx.Inputs) > MAX_TX_INPUTS, "simplicity txcontext input_count overflow"},
		{len(tx.Outputs) > MAX_TX_OUTPUTS, "simplicity txcontext output_count overflow"},
	} {
		if check.invalid {
			return nil, txerr(TX_ERR_PARSE, check.message)
		}
	}

	totalIn, err := sumTxContextInputValues(resolvedInputs, u128{})
	if err != nil {
		return nil, err
	}
	totalOut, err := sumTxContextOutputValues(tx.Outputs, u128{})
	if err != nil {
		return nil, err
	}

	ctx := &SimplicityTxContext{
		Base: SimplicityTxContextBase{
			ChainID:     chainID,
			Height:      blockHeight,
			TxKind:      tx.TxKind,
			TxNonce:     tx.TxNonce,
			Locktime:    tx.Locktime,
			InputCount:  uint16(len(tx.Inputs)),
			OutputCount: uint16(len(tx.Outputs)),
			TotalIn:     uint128FromInternal(totalIn),
			TotalOut:    uint128FromInternal(totalOut),
		},
		inputViews:  make([]SimplicityTxContextIOView, len(resolvedInputs)),
		outputViews: make([]SimplicityTxContextIOView, len(tx.Outputs)),
		selfSources: make([]simplicityTxContextSelfSource, len(resolvedInputs)),
	}

	hasSimplicityInput, err := populateSimplicityTxContextViews(ctx, tx, resolvedInputs)
	if err != nil {
		return nil, err
	}
	if !hasSimplicityInput {
		return nil, nil
	}
	return ctx, nil
}

func populateSimplicityTxContextViews(ctx *SimplicityTxContext, tx *Tx, resolvedInputs []UtxoEntry) (bool, error) {
	hasSimplicityInput := false
	for i, entry := range resolvedInputs {
		ctx.inputViews[i] = SimplicityTxContextIOView{
			Value:        entry.Value,
			CovenantType: entry.CovenantType,
		}
		if entry.CovenantType != COV_TYPE_CORE_SIMPLICITY {
			continue
		}
		programCMR, state, err := parseCoreSimplicityCovenantData(entry.CovenantData)
		if err != nil {
			return false, err
		}
		ctx.selfSources[i] = simplicityTxContextSelfSource{
			programCMR:       programCMR,
			state:            state,
			value:            entry.Value,
			isCoreSimplicity: true,
		}
		hasSimplicityInput = true
	}

	for i, out := range tx.Outputs {
		ctx.outputViews[i] = SimplicityTxContextIOView{
			Value:        out.Value,
			CovenantType: out.CovenantType,
		}
	}
	return hasSimplicityInput, nil
}

func (c *SimplicityTxContext) InputViews() []SimplicityTxContextIOView {
	return append([]SimplicityTxContextIOView{}, c.inputViews...)
}

func (c *SimplicityTxContext) OutputViews() []SimplicityTxContextIOView {
	return append([]SimplicityTxContextIOView{}, c.outputViews...)
}

func (c *SimplicityTxContext) SelfView(inputIndex uint16, sighashType uint8, digest32 [32]byte) (SimplicityTxContextSelfView, error) {
	if int(inputIndex) >= len(c.selfSources) {
		return SimplicityTxContextSelfView{}, txerr(TX_ERR_PARSE, "simplicity txcontext self input index out of range")
	}
	source := c.selfSources[inputIndex]
	if !source.isCoreSimplicity {
		return SimplicityTxContextSelfView{}, txerr(TX_ERR_COVENANT_TYPE_INVALID, "simplicity txcontext self input is not CORE_SIMPLICITY")
	}
	return SimplicityTxContextSelfView{
		InputIndex:     inputIndex,
		SelfValue:      source.value,
		SelfState:      append([]byte{}, source.state...),
		SelfProgramCMR: source.programCMR,
		SighashType:    sighashType,
		Digest32:       digest32,
	}, nil
}
