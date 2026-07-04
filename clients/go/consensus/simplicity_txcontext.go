package consensus

import (
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"
)

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

type SimplicityTxContextDescriptorHashResult struct {
	Hash    [32]byte
	Present bool
}

type SimplicityTxContextMeter struct {
	cost uint64
}

func (m *SimplicityTxContextMeter) Cost() uint64 {
	return m.cost
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

type simplicityTxContextDescriptorSource struct {
	covenantData []byte
	covenantType uint16
}

type SimplicityTxContext struct {
	Base              SimplicityTxContextBase
	inputViews        []SimplicityTxContextIOView
	outputViews       []SimplicityTxContextIOView
	inputDescriptors  []simplicityTxContextDescriptorSource
	outputDescriptors []simplicityTxContextDescriptorSource
	selfSources       []simplicityTxContextSelfSource
	groupInputs       map[[32]byte][]SimplicityTxContextGroupEntry
	groupOutputs      map[[32]byte][]SimplicityTxContextGroupEntry
	daView            SimplicityTxContextDAView
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
		inputViews:        make([]SimplicityTxContextIOView, len(resolvedInputs)),
		outputViews:       make([]SimplicityTxContextIOView, len(tx.Outputs)),
		inputDescriptors:  make([]simplicityTxContextDescriptorSource, len(resolvedInputs)),
		outputDescriptors: make([]simplicityTxContextDescriptorSource, len(tx.Outputs)),
		selfSources:       make([]simplicityTxContextSelfSource, len(resolvedInputs)),
	}

	if err := populateSimplicityTxContextViews(ctx, tx, resolvedInputs); err != nil {
		return nil, err
	}
	return ctx, nil
}

func populateSimplicityTxContextViews(ctx *SimplicityTxContext, tx *Tx, resolvedInputs []UtxoEntry) error {
	ctx.groupInputs, ctx.groupOutputs = make(map[[32]byte][]SimplicityTxContextGroupEntry), make(map[[32]byte][]SimplicityTxContextGroupEntry)

	if err := populateSimplicityTxContextInputViews(ctx, resolvedInputs); err != nil {
		return err
	}
	if err := populateSimplicityTxContextOutputViews(ctx, tx.Outputs); err != nil {
		return err
	}
	var err error
	ctx.daView, err = buildSimplicityTxContextDAView(tx)
	return err
}

func populateSimplicityTxContextInputViews(ctx *SimplicityTxContext, resolvedInputs []UtxoEntry) error {
	for i, entry := range resolvedInputs {
		ctx.inputViews[i] = SimplicityTxContextIOView{
			Value:        entry.Value,
			CovenantType: entry.CovenantType,
		}
		ctx.inputDescriptors[i] = simplicityTxContextDescriptorSource{
			covenantType: entry.CovenantType,
			covenantData: append([]byte{}, entry.CovenantData...),
		}
		if entry.CovenantType != COV_TYPE_CORE_SIMPLICITY {
			continue
		}
		programCMR, state, err := splitCoreSimplicityCovenantData(entry.CovenantData)
		if err != nil {
			return err
		}
		state = append([]byte{}, state...)
		ctx.selfSources[i] = simplicityTxContextSelfSource{
			programCMR:       programCMR,
			state:            state,
			value:            entry.Value,
			isCoreSimplicity: true,
		}
		ctx.groupInputs[programCMR] = append(ctx.groupInputs[programCMR], SimplicityTxContextGroupEntry{
			Value: entry.Value,
			State: state,
		})
		if len(ctx.groupInputs[programCMR]) > SIMPLICITY_MAX_GROUP_INPUTS {
			return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY same-cmr input group exceeds limit")
		}
	}
	return nil
}

func populateSimplicityTxContextOutputViews(ctx *SimplicityTxContext, outputs []TxOutput) error {
	for i, out := range outputs {
		ctx.outputViews[i] = SimplicityTxContextIOView{
			Value:        out.Value,
			CovenantType: out.CovenantType,
		}
		ctx.outputDescriptors[i] = simplicityTxContextDescriptorSource{
			covenantType: out.CovenantType,
			covenantData: append([]byte{}, out.CovenantData...),
		}
		if out.CovenantType != COV_TYPE_CORE_SIMPLICITY {
			continue
		}
		programCMR, state, err := splitCoreSimplicityCovenantData(out.CovenantData)
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

// splitCoreSimplicityCovenantData performs the §2.4 step-3d byte-copy split of a
// CORE_SIMPLICITY covenant_data snapshot into (program_cmr, state): program_cmr =
// the first 32 bytes; state = the bytes after the CompactSize length prefix, with
// the prefix STRIPPED (matching the Section 3.4 state_bytes definition). The
// snapshot is trusted — for resolved inputs by their creation-time §14 validation,
// for outputs by the step-2 §14 structural validation that precedes step 3d — so the
// split is byte-copies only and MUST NOT re-impose the value>0 / state_len-bound /
// total-length checks (those are creation-time §14 concerns, not step 3d; see
// RUBIN_CONSENSUS_STATE_MACHINE.md §2.4 step 3d "It MUST NOT re-parse covenant_data").
// The spec's "the split cannot fail" holds for those well-formed snapshots; the length
// guards here are a defensive no-panic boundary (validity-path code must return a typed
// error, never panic) for the structurally impossible malformed case, not a re-validation
// of the §14 checks. They do not re-parse.
func splitCoreSimplicityCovenantData(covenantData []byte) ([32]byte, []byte, error) {
	var programCMR [32]byte
	if len(covenantData) < 33 {
		return programCMR, nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY covenant_data too short for step-3d split")
	}
	copy(programCMR[:], covenantData[:32])
	stateStart := 32 + compactSizePrefixLen(covenantData[32])
	if len(covenantData) < stateStart {
		return programCMR, nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY covenant_data too short for step-3d split")
	}
	return programCMR, covenantData[stateStart:], nil
}

// compactSizePrefixLen returns the encoded byte width of a CompactSize length prefix
// from its tag byte (§ CompactSize encoding): 1 for tag < 0xfd, else 3/5/9 for the
// 0xfd/0xfe/0xff wide forms. It reads only the tag to strip the prefix; it does not
// decode or validate the encoded value (that would be a re-parse).
func compactSizePrefixLen(tag byte) int {
	switch tag {
	case 0xff:
		return 9
	case 0xfe:
		return 5
	case 0xfd:
		return 3
	default:
		return 1
	}
}

func buildSimplicityTxContextDAView(tx *Tx) (SimplicityTxContextDAView, error) {
	var view SimplicityTxContextDAView
	switch tx.TxKind {
	case 0x00:
		view.Kind = SimplicityTxContextDAViewAbsent
	case 0x01:
		core := tx.DaCommitCore
		if err := validateSimplicityTxContextDACommitCore(core); err != nil {
			return SimplicityTxContextDAView{}, err
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

func validateSimplicityTxContextDACommitCore(core *DaCommitCore) error {
	switch {
	case core == nil, invalidDaCommitChunkCount(core.ChunkCount), len(core.BatchSig) > MAX_DA_MANIFEST_BYTES_PER_TX:
		return txerr(TX_ERR_PARSE, "invalid da_commit_core for tx_kind=0x01")
	}
	return nil
}

func (c *SimplicityTxContext) InputViews() []SimplicityTxContextIOView {
	return append([]SimplicityTxContextIOView{}, c.inputViews...)
}

func (c *SimplicityTxContext) OutputViews() []SimplicityTxContextIOView {
	return append([]SimplicityTxContextIOView{}, c.outputViews...)
}

func (c *SimplicityTxContext) InputDescriptorHash(inputIndex uint16, meter *SimplicityTxContextMeter) (SimplicityTxContextDescriptorHashResult, error) {
	return c.descriptorHash(c.inputDescriptors, inputIndex, meter)
}

func (c *SimplicityTxContext) OutputDescriptorHash(outputIndex uint16, meter *SimplicityTxContextMeter) (SimplicityTxContextDescriptorHashResult, error) {
	return c.descriptorHash(c.outputDescriptors, outputIndex, meter)
}

// InputDescriptorHashCost returns the metered access cost of the input descriptor
// hash at inputIndex WITHOUT materializing the hash — the cost-only path for
// EvalHost.IntrinsicCost (the descriptor_hash cost depends only on the descriptor
// length, never on the hash value). An out-of-range index is the Either-miss cost.
// It charges no meter and never runs sha3_256.
func (c *SimplicityTxContext) InputDescriptorHashCost(inputIndex uint16) (uint64, error) {
	return descriptorHashCost(c.inputDescriptors, inputIndex)
}

// OutputDescriptorHashCost is the output-side cost-only accessor (see InputDescriptorHashCost).
func (c *SimplicityTxContext) OutputDescriptorHashCost(outputIndex uint16) (uint64, error) {
	return descriptorHashCost(c.outputDescriptors, outputIndex)
}

func descriptorHashCost(sources []simplicityTxContextDescriptorSource, index uint16) (uint64, error) {
	if int(index) >= len(sources) {
		return simplicity.IntrinsicMissCost, nil
	}
	return simplicity.DescriptorHashAccessCost(descriptorSourceLen(sources[index]))
}

func (c *SimplicityTxContext) descriptorHash(sources []simplicityTxContextDescriptorSource, index uint16, meter *SimplicityTxContextMeter) (SimplicityTxContextDescriptorHashResult, error) {
	if meter == nil {
		return SimplicityTxContextDescriptorHashResult{}, txerr(TX_ERR_PARSE, "nil simplicity txcontext meter")
	}
	if int(index) >= len(sources) {
		if err := meter.charge(simplicity.IntrinsicMissCost); err != nil {
			return SimplicityTxContextDescriptorHashResult{}, err
		}
		return SimplicityTxContextDescriptorHashResult{}, nil
	}
	source := sources[index]
	cost, err := simplicity.DescriptorHashAccessCost(descriptorSourceLen(source))
	if err != nil {
		meter.cost = simplicity.MaxExecCost
		return SimplicityTxContextDescriptorHashResult{}, err
	}
	if err := meter.charge(cost); err != nil {
		return SimplicityTxContextDescriptorHashResult{}, err
	}
	desc := OutputDescriptorBytes(source.covenantType, source.covenantData)
	return SimplicityTxContextDescriptorHashResult{Hash: sha3_256(desc), Present: true}, nil
}

func descriptorSourceLen(source simplicityTxContextDescriptorSource) uint64 {
	dataLen := uint64(len(source.covenantData))
	return 2 + compactSizeLen(dataLen) + dataLen
}

func (m *SimplicityTxContextMeter) charge(cost uint64) error {
	if m == nil {
		return txerr(TX_ERR_PARSE, "nil simplicity txcontext meter")
	}
	next, err := simplicity.ChargeCost(m.cost, cost)
	m.cost = next
	return err
}

func (c *SimplicityTxContext) SameCMRView(inputIndex uint16) (SimplicityTxContextSameCMRView, error) {
	if int(inputIndex) >= len(c.selfSources) {
		return SimplicityTxContextSameCMRView{}, txerr(TX_ERR_PARSE, "simplicity txcontext self input index out of range")
	}
	source := c.selfSources[inputIndex]
	if !source.isCoreSimplicity {
		return SimplicityTxContextSameCMRView{}, txerr(TX_ERR_COVENANT_TYPE_INVALID, "simplicity txcontext self input is not CORE_SIMPLICITY")
	}
	return SimplicityTxContextSameCMRView{
		ProgramCMR: source.programCMR,
		Inputs:     cloneSimplicityGroupEntries(c.groupInputs[source.programCMR]),
		Outputs:    cloneSimplicityGroupEntries(c.groupOutputs[source.programCMR]),
	}, nil
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
