package consensus

import "slices"

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

type SimplicityTxContextGroupEntry struct {
	State []byte
	Value uint64
}

type SimplicityTxContextSameCMRView struct {
	ProgramCMR [32]byte
	Inputs     []SimplicityTxContextGroupEntry
	Outputs    []SimplicityTxContextGroupEntry
}

type SimplicityTxContextDAViewKind uint8

const (
	SimplicityTxContextDAViewAbsent SimplicityTxContextDAViewKind = iota
	SimplicityTxContextDAViewCommit
	SimplicityTxContextDAViewChunk
)

type SimplicityTxContextDACommitView struct {
	DaID            [32]byte
	RetlDomainID    [32]byte
	TxDataRoot      [32]byte
	StateRoot       [32]byte
	WithdrawalsRoot [32]byte
	BatchNumber     uint64
	ChunkCount      uint16
}

type SimplicityTxContextDAChunkView struct {
	DaID       [32]byte
	ChunkHash  [32]byte
	ChunkIndex uint16
}

type SimplicityTxContextDAView struct {
	Commit SimplicityTxContextDACommitView
	Chunk  SimplicityTxContextDAChunkView
	Kind   SimplicityTxContextDAViewKind
}

type simplicityTxContextSelfSource struct {
	programCMR       [32]byte
	state            []byte
	value            uint64
	isCoreSimplicity bool
}

type SimplicityTxContext struct {
	Base         SimplicityTxContextBase
	inputViews   []SimplicityTxContextIOView
	outputViews  []SimplicityTxContextIOView
	selfSources  []simplicityTxContextSelfSource
	groupInputs  map[[32]byte][]SimplicityTxContextGroupEntry
	groupOutputs map[[32]byte][]SimplicityTxContextGroupEntry
	daView       SimplicityTxContextDAView
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
	if !slices.ContainsFunc(resolvedInputs, func(entry UtxoEntry) bool {
		return entry.CovenantType == COV_TYPE_CORE_SIMPLICITY
	}) {
		return nil, nil
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

	if err := populateSimplicityTxContextViews(ctx, tx, resolvedInputs); err != nil {
		return nil, err
	}
	ctx.daView, err = buildSimplicityTxContextDAView(tx)
	return ctx, err
}

func populateSimplicityTxContextViews(ctx *SimplicityTxContext, tx *Tx, resolvedInputs []UtxoEntry) error {
	ctx.groupInputs = make(map[[32]byte][]SimplicityTxContextGroupEntry)
	ctx.groupOutputs = make(map[[32]byte][]SimplicityTxContextGroupEntry)

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
			return err
		}
		ctx.selfSources[i] = simplicityTxContextSelfSource{
			programCMR:       programCMR,
			state:            append([]byte{}, state...),
			value:            entry.Value,
			isCoreSimplicity: true,
		}
		ctx.groupInputs[programCMR] = append(ctx.groupInputs[programCMR], SimplicityTxContextGroupEntry{
			Value: entry.Value,
			State: append([]byte{}, state...),
		})
		if len(ctx.groupInputs[programCMR]) > SIMPLICITY_MAX_GROUP_INPUTS {
			return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY same-cmr input group exceeds limit")
		}
	}

	for i, out := range tx.Outputs {
		ctx.outputViews[i] = SimplicityTxContextIOView{
			Value:        out.Value,
			CovenantType: out.CovenantType,
		}
		if out.CovenantType != COV_TYPE_CORE_SIMPLICITY {
			continue
		}
		programCMR, state, err := parseValidatedCoreSimplicityCovenantData(out.Value, out.CovenantData)
		if err != nil {
			return err
		}
		ctx.groupOutputs[programCMR] = append(ctx.groupOutputs[programCMR], SimplicityTxContextGroupEntry{
			Value: out.Value,
			State: append([]byte{}, state...),
		})
	}
	return nil
}

func buildSimplicityTxContextDAView(tx *Tx) (SimplicityTxContextDAView, error) {
	var view SimplicityTxContextDAView
	switch tx.TxKind {
	case 0x00:
		view.Kind = SimplicityTxContextDAViewAbsent
	case 0x01:
		core := tx.DaCommitCore
		if core == nil {
			return SimplicityTxContextDAView{}, txerr(TX_ERR_PARSE, "missing da_commit_core for tx_kind=0x01")
		}
		if invalidDaCommitChunkCount(core.ChunkCount) {
			return SimplicityTxContextDAView{}, txerr(TX_ERR_PARSE, "chunk_count out of range for tx_kind=0x01")
		}
		view.Kind = SimplicityTxContextDAViewCommit
		view.Commit = SimplicityTxContextDACommitView{
			DaID:            core.DaID,
			ChunkCount:      core.ChunkCount,
			RetlDomainID:    core.RetlDomainID,
			BatchNumber:     core.BatchNumber,
			TxDataRoot:      core.TxDataRoot,
			StateRoot:       core.StateRoot,
			WithdrawalsRoot: core.WithdrawalsRoot,
		}
	case 0x02:
		core := tx.DaChunkCore
		if core == nil {
			return SimplicityTxContextDAView{}, txerr(TX_ERR_PARSE, "missing da_chunk_core for tx_kind=0x02")
		}
		if uint64(core.ChunkIndex) >= MAX_DA_CHUNK_COUNT {
			return SimplicityTxContextDAView{}, txerr(TX_ERR_PARSE, "chunk_index out of range for tx_kind=0x02")
		}
		view.Kind = SimplicityTxContextDAViewChunk
		view.Chunk = SimplicityTxContextDAChunkView{
			DaID:       core.DaID,
			ChunkIndex: core.ChunkIndex,
			ChunkHash:  core.ChunkHash,
		}
	default:
		return SimplicityTxContextDAView{}, txerr(TX_ERR_PARSE, "unsupported tx_kind")
	}
	return view, nil
}

func (c *SimplicityTxContext) InputViews() []SimplicityTxContextIOView {
	return append([]SimplicityTxContextIOView{}, c.inputViews...)
}

func (c *SimplicityTxContext) OutputViews() []SimplicityTxContextIOView {
	return append([]SimplicityTxContextIOView{}, c.outputViews...)
}

func (c *SimplicityTxContext) SameCMRView(inputIndex uint16) (SimplicityTxContextSameCMRView, error) {
	source, err := c.selfSource(inputIndex)
	if err != nil {
		return SimplicityTxContextSameCMRView{}, err
	}
	return SimplicityTxContextSameCMRView{
		ProgramCMR: source.programCMR,
		Inputs:     cloneSimplicityGroupEntries(c.groupInputs[source.programCMR]),
		Outputs:    cloneSimplicityGroupEntries(c.groupOutputs[source.programCMR]),
	}, err
}

func (c *SimplicityTxContext) SelfView(inputIndex uint16, sighashType uint8, digest32 [32]byte) (SimplicityTxContextSelfView, error) {
	source, err := c.selfSource(inputIndex)
	if err != nil {
		return SimplicityTxContextSelfView{}, err
	}
	return SimplicityTxContextSelfView{
		InputIndex:     inputIndex,
		SelfValue:      source.value,
		SelfState:      append([]byte{}, source.state...),
		SelfProgramCMR: source.programCMR,
		SighashType:    sighashType,
		Digest32:       digest32,
	}, err
}

func (c *SimplicityTxContext) selfSource(inputIndex uint16) (simplicityTxContextSelfSource, error) {
	if int(inputIndex) >= len(c.selfSources) {
		return simplicityTxContextSelfSource{}, txerr(TX_ERR_PARSE, "simplicity txcontext self input index out of range")
	}
	source := c.selfSources[inputIndex]
	if !source.isCoreSimplicity {
		return simplicityTxContextSelfSource{}, txerr(TX_ERR_COVENANT_TYPE_INVALID, "simplicity txcontext self input is not CORE_SIMPLICITY")
	}
	return source, nil
}

func cloneSimplicityGroupEntries(src []SimplicityTxContextGroupEntry) []SimplicityTxContextGroupEntry {
	out := make([]SimplicityTxContextGroupEntry, len(src))
	for i, entry := range src {
		out[i] = SimplicityTxContextGroupEntry{
			Value: entry.Value,
			State: append([]byte{}, entry.State...),
		}
	}
	return out
}
