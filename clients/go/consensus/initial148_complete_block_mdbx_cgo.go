//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"errors"
	"math"
	"math/bits"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// initial148CompleteBlockInputV1 is the immutable dormant complete-block input.
// Raw, PublishedGenesis, ParentTimestamps, Rotation, Registry and CapRegistry
// stay unmodified until run returns. Rotation is a frozen *boundSpendSurface or
// *boundSpendSurfaceWithDeployment bound at Height. It carries no expected root
// and no validity receipt.
type initial148CompleteBlockInputV1 struct {
	Raw                    []byte
	Height                 uint64
	ParentHash             [32]byte
	ExpectedTarget         [32]byte
	ChainID                [32]byte
	DatabaseID             [32]byte
	ParentTimestamps       []uint64
	AlreadyGenerated       Uint128
	Generation             uint64
	Parent                 mdbx.TreeEndpointV1
	Endpoint               mdbx.TreeEndpointV1
	CanonicalBeforePresent bool
	OwnerBeforePresent     bool
	CapRegistry            *validatedLogicalStateCapRegistry
	Registry               *SuiteRegistry
	Rotation               RotationProvider
	PublishedGenesis       []byte
	FirstGenesisDemand     uint64
}

// initial148CompleteBlockResultV1 is delivered by validate only after the fresh
// derived root equals the header utxo_root. It stays valid only inside run.
type initial148CompleteBlockResultV1 struct {
	summary    BlockBasicSummary
	transition *connectBlockInputViewResult
	effect     blockTreeEffectV1
}

// initial148CompleteBlockOutcomeV1 records entry into validate, the selected
// validation error (nil only after equality) and the raw required-read
// projection. required.derived means D completed, never block validity.
type initial148CompleteBlockOutcomeV1 struct {
	attempted     bool
	validationErr error
	required      initial148RootReadOutcomeV1
}

type initial148CompleteRunV1 func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error

// initial148CompleteBlockFrameV1 owns validation under full W and retains only
// Raw/result/source ownership under M after successful required/root completion.
type initial148CompleteBlockFrameV1 struct {
	input    initial148CompleteBlockInputV1
	account  *mdbx.OperationAccount
	outcome  initial148CompleteBlockOutcomeV1
	source   blockTreeSourceV1
	result   *initial148CompleteBlockResultV1
	workers  int
	parallel bool
	active   bool
	reduce   func() error
}

// withInitial148CompleteBlockV1 is the dormant sequential complete initial148
// entry. Local refusals before W return attempted=false and never invoke run.
func withInitial148CompleteBlockV1(account *mdbx.OperationAccount, input initial148CompleteBlockInputV1, run initial148CompleteRunV1) (initial148CompleteBlockOutcomeV1, error) {
	return withInitial148CompleteBlockBodyV1(account, input, run, false, 0)
}

// withInitial148ReplayCompleteBlockV1 admits delayed immutable input inside
// the sole replay callback. Gross replay funding covers both W and retained M.
func withInitial148ReplayCompleteBlockV1(account *mdbx.OperationAccount, run func(func(*mdbx.Reader, initial148CompleteBlockInputV1) (*initial148CompleteBlockResultV1, error)) error) (initial148CompleteBlockOutcomeV1, error) {
	if account == nil || run == nil {
		return initial148CompleteBlockOutcomeV1{}, localLogicalStateFailure("invalid complete initial148 request")
	}
	f := &initial148CompleteBlockFrameV1{account: account, reduce: func() error { return nil }}
	used := false
	err := f.runV1(func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
		err := run(func(reader *mdbx.Reader, input initial148CompleteBlockInputV1) (*initial148CompleteBlockResultV1, error) {
			if !f.active || used {
				return nil, localLogicalStateFailure("complete initial148 validate is not available")
			}
			used = true
			_, admission := initial148CompleteAdmitV1(account, input, func(func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error { return nil })
			if admission != nil {
				f.outcome.validationErr = admission
				return nil, admission
			}
			f.input = input
			return validate(reader)
		})
		if err != nil {
			return err
		}
		return f.outcome.validationErr
	})
	if err == nil {
		err = f.outcome.validationErr
	}
	return f.outcome, err
}

// withInitial148CompleteBlockParallelV1 is the queued entry; workers <= 0 uses
// the NewSigCheckQueue default (GOMAXPROCS).
func withInitial148CompleteBlockParallelV1(account *mdbx.OperationAccount, input initial148CompleteBlockInputV1, workers int, run initial148CompleteRunV1) (initial148CompleteBlockOutcomeV1, error) {
	return withInitial148CompleteBlockBodyV1(account, input, run, true, workers)
}

func withInitial148CompleteBlockBodyV1(account *mdbx.OperationAccount, input initial148CompleteBlockInputV1, run initial148CompleteRunV1, parallel bool, workers int) (initial148CompleteBlockOutcomeV1, error) {
	w, err := initial148CompleteAdmitV1(account, input, run)
	if err != nil {
		return initial148CompleteBlockOutcomeV1{}, err
	}
	frame := &initial148CompleteBlockFrameV1{input: input, account: account, workers: workers, parallel: parallel}
	err = account.WithPhaseReservationV1(w, initial148RetainedTariffV1(uint64(len(input.Raw))), func(release func() error) error {
		frame.reduce = release
		return frame.runV1(run)
	})
	if err == nil && frame.outcome.validationErr != nil {
		err = frame.outcome.validationErr
	}
	return frame.outcome, err
}

// initial148CompleteAdmitV1 applies the local refusals in their fixed order and
// returns the W tariff.
func initial148CompleteAdmitV1(account *mdbx.OperationAccount, input initial148CompleteBlockInputV1, run initial148CompleteRunV1) (uint64, error) {
	if !initial148CompleteOwnersV1(account, input, run) {
		return 0, localLogicalStateFailure("invalid complete initial148 request")
	}
	if len(input.Raw) > initial148BlockMaxBytes {
		return 0, ErrInitial148BlockCapacity
	}
	if !initial148CompleteIdentityV1(input) || !initial148CompleteHeightContextV1(input) {
		return 0, localLogicalStateFailure("invalid complete initial148 context")
	}
	if !initial148CompleteTargetContextV1(input) {
		return 0, ErrBlockSteps1To12Context
	}
	w, ok := initial148CompleteTariffV1(input)
	if !ok {
		return 0, localLogicalStateFailure("complete initial148 reservation exceeds integer domain")
	}
	return w, nil
}

func initial148CompleteOwnersV1(account *mdbx.OperationAccount, input initial148CompleteBlockInputV1, run initial148CompleteRunV1) bool {
	return account != nil && run != nil && input.CapRegistry != nil && input.Registry != nil && initial148FrozenRotationV1(input.Rotation, input.Height)
}

func initial148FrozenRotationV1(rotation RotationProvider, height uint64) bool {
	switch bound := rotation.(type) {
	case *boundSpendSurface:
		return initial148FrozenSurfaceV1(bound, height)
	case *boundSpendSurfaceWithDeployment:
		return bound != nil && bound.have && initial148FrozenSurfaceV1(bound.boundSpendSurface, height)
	}
	return false
}

func initial148FrozenSurfaceV1(bound *boundSpendSurface, height uint64) bool {
	return bound != nil && bound.height == height && bound.haveCreate && bound.haveSpend
}

func initial148CompleteIdentityV1(input initial148CompleteBlockInputV1) bool {
	if input.Height > math.MaxUint32 || input.DatabaseID == ([32]byte{}) || input.Generation == 0 {
		return false
	}
	endpoint := input.Endpoint.Kind == mdbx.TreeEndpointAppliedV1 && input.Endpoint.Height == input.Height
	return endpoint && initial148RequiredParentV1(input.Height, input.Parent) && input.Parent.BlockHash == input.ParentHash
}

func initial148CompleteHeightContextV1(input initial148CompleteBlockInputV1) bool {
	if input.Height != 0 {
		return input.PublishedGenesis == nil
	}
	return len(input.ParentTimestamps) == 0 && input.AlreadyGenerated == (Uint128{}) && len(input.Raw) != 0 && bytes.Equal(input.PublishedGenesis, input.Raw)
}

func initial148CompleteTargetContextV1(input initial148CompleteBlockInputV1) bool {
	if input.Height != 0 {
		return blockStepsContextValid(input.ExpectedTarget, input.Height, input.ParentTimestamps)
	}
	return input.ExpectedTarget != ([32]byte{}) && bytes.Compare(input.ExpectedTarget[:], POW_LIMIT[:]) <= 0
}

// initial148CompleteTariffV1 reserves the RUB-1907 W' census: Raw, distinct
// genesis backing, frozen configuration and the larger connect/cap phase.
func initial148CompleteTariffV1(input initial148CompleteBlockInputV1) (uint64, bool) {
	m, ok := initial148MinimumWitnessV1(input.Registry)
	if !ok {
		return 0, false
	}
	total, ok := initial148CompleteBodyTariffV1(uint64(len(input.Raw)), m)
	if !ok {
		return 0, false
	}
	r, a := initial148RegistryCountsV1(input.Registry)
	terms := [...][2]uint64{
		{16384, initial148DescriptorCountV1(input.Rotation)},
		{128, uint64(len(input.CapRegistry.rows))},
		{1024, r},
		{2, a},
		{8, uint64(len(input.ParentTimestamps))},
		{1, initial148DistinctGenesisBytesV1(input.Raw, input.PublishedGenesis)},
	}
	total, ok = initial148TariffSumV1(total, terms[:])
	return total, ok && total <= math.MaxInt64
}

// initial148TariffSumV1 checks every product and sum before it enters W'.
func initial148TariffSumV1(total uint64, terms [][2]uint64) (uint64, bool) {
	for _, term := range terms {
		hi, product := bits.Mul64(term[0], term[1])
		sum, carry := bits.Add64(total, product, 0)
		if hi != 0 || carry != 0 {
			return 0, false
		}
		total = sum
	}
	return total, true
}

// initial148CompleteBodyTariffV1 is the pure (Raw bytes, minimum witness) W'
// recipe before configuration and distinct published-genesis backing. Zero m
// means that no registered suite can produce a signature task.
func initial148CompleteBodyTariffV1(n, m uint64) (uint64, bool) {
	if n > 68_000_157 {
		return 0, false
	}
	var b, w, s uint64
	if n > 149 {
		w = n - 149
		b = min(17_000_000, w, (68_000_157-n)/3)
	}
	if m != 0 {
		s = w / m
	}
	terms := [...][2]uint64{{131_072, min(1_024, b/41)}, {1, 4_194_304}, {6, b}, {1, w}, {512, s}}
	connect, ok := initial148TariffSumV1(0, terms[:])
	if !ok {
		return 0, false
	}
	// b <= 17,000,000, so 16*b and 16,777,216+n cannot overflow.
	phase := [...][2]uint64{{1, max(connect, 16*b)}}
	return initial148TariffSumV1(16_777_216+n, phase[:])
}

// initial148RetainedTariffV1 covers Raw, compact result ownership and fixed
// current-transaction metadata after required/root/queue work has completed.
// Admission has already bounded n, so every operation here fits uint64.
func initial148RetainedTariffV1(n uint64) uint64 {
	var b uint64
	if n > 149 {
		b = min(17_000_000, n-149, (68_000_157-n)/3)
	}
	return 16_777_216 + n + 6*b
}

// initial148MinimumWitnessV1 counts the suite byte, both CompactSizes and
// SigLen+1. Negative lengths admit no task; zero means no eligible suite.
func initial148MinimumWitnessV1(registry *SuiteRegistry) (uint64, bool) {
	var minimum uint64
	for _, params := range registry.suites {
		if params.PubkeyLen < 0 || params.SigLen < 0 {
			continue
		}
		// Nonnegative int lengths are at most MaxInt64; widen before +1.
		pub, sig := uint64(params.PubkeyLen), uint64(params.SigLen)+1
		terms := [...][2]uint64{{1, pub}, {1, sig}, {1, compactSizeLen(pub)}, {1, compactSizeLen(sig)}}
		size, ok := initial148TariffSumV1(1, terms[:])
		if !ok {
			return 0, false
		}
		if minimum == 0 || size < minimum {
			minimum = size
		}
	}
	return minimum, true
}

func initial148RegistryCountsV1(registry *SuiteRegistry) (uint64, uint64) {
	var names uint64
	for _, params := range registry.suites {
		names += uint64(len(params.AlgName))
	}
	return uint64(len(registry.suites)), names
}

func initial148DescriptorCountV1(rotation RotationProvider) uint64 {
	if bound, ok := rotation.(*boundSpendSurfaceWithDeployment); ok {
		return uint64(len(bound.descriptors))
	}
	return 0
}

func initial148DistinctGenesisBytesV1(raw, published []byte) uint64 {
	if len(published) == 0 || (len(raw) == len(published) && &raw[0] == &published[0]) {
		return 0
	}
	return uint64(len(published))
}

// runV1 holds full W through required/root/queue validation, then M through
// writer/readback and the run tail. Failed validation retains W. Every
// frame-owned datum is released after return, error, panic or Goexit.
func (f *initial148CompleteBlockFrameV1) runV1(run initial148CompleteRunV1) error {
	f.active = true
	defer f.releaseV1()
	if err := run(f.validateV1); err != nil {
		return err
	}
	if !f.outcome.attempted {
		return localLogicalStateFailure("complete initial148 run returned without validation")
	}
	return nil
}

func (f *initial148CompleteBlockFrameV1) releaseV1() {
	f.active = false
	if f.result != nil && f.result.transition != nil && f.result.transition.spentInputs != nil {
		f.result.transition.spentInputs.discard()
	}
	if f.result != nil {
		*f.result = initial148CompleteBlockResultV1{}
	}
	f.result, f.source = nil, blockTreeSourceV1{}
	f.input = initial148CompleteBlockInputV1{}
	f.reduce = nil
}

// validateV1 is usable once, only while run is active.
func (f *initial148CompleteBlockFrameV1) validateV1(reader *mdbx.Reader) (*initial148CompleteBlockResultV1, error) {
	if !f.active || f.outcome.attempted {
		return nil, localLogicalStateFailure("complete initial148 validate is not available")
	}
	f.outcome.attempted = true
	result, err := f.validateBodyV1(reader)
	if err != nil {
		f.outcome.validationErr = err
		return nil, err
	}
	f.result = result
	if err := f.retireValidationV1(); err != nil {
		f.outcome.validationErr = err
		return nil, err
	}
	return result, nil
}

// retireValidationV1 drops only references with no consumer after requiredV1
// returned successfully. Raw, result/spent/current and scalar source identity
// remain live under M through the enclosing writer/readback and run tail.
func (f *initial148CompleteBlockFrameV1) retireValidationV1() error {
	f.input.CapRegistry, f.input.Registry, f.input.Rotation = nil, nil, nil
	f.input.PublishedGenesis, f.input.ParentTimestamps = nil, nil
	return f.reduce()
}

func (f *initial148CompleteBlockFrameV1) validateBodyV1(reader *mdbx.Reader) (*initial148CompleteBlockResultV1, error) {
	summary, header, err := initial148CompleteStepsV1(f.input)
	if err != nil {
		return nil, err
	}
	if summary.BlockHash != f.input.Endpoint.BlockHash {
		return nil, localLogicalStateFailure("complete initial148 endpoint hash differs")
	}
	generated := initial148PendingGeneratedV1(f.input)
	effect, err := prepareBlockTreeEffectV1(&f.source, reader, f.account, f.treeRequestV1(summary.BlockHash, &generated))
	if err != nil {
		return nil, err
	}
	result := &initial148CompleteBlockResultV1{summary: summary, effect: effect}
	err = f.requiredV1(reader, header.UtxoRoot, generated, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// initial148CompleteStepsV1 runs Section 25 steps 1-12. Height 0 composes the
// same height-free owners and omits linkage and timestamp checks.
func initial148CompleteStepsV1(input initial148CompleteBlockInputV1) (BlockBasicSummary, Initial148Header, error) {
	var summary BlockBasicSummary
	var err error
	if input.Height == 0 {
		summary, err = initial148GenesisStepsV1(input.Raw, input.ExpectedTarget)
	} else {
		summary, err = ValidateInitial148BlockSteps1To12(input.Raw, input.ParentHash, input.ExpectedTarget, input.Height, input.ParentTimestamps)
	}
	if err != nil {
		return BlockBasicSummary{}, Initial148Header{}, err
	}
	header, err := ParseInitial148HeaderBytes(input.Raw[:Initial148HeaderBytes])
	return summary, header, err
}

func initial148GenesisStepsV1(raw []byte, expectedTarget [32]byte) (BlockBasicSummary, error) {
	p, err := initial148FirstPass(raw)
	if err != nil {
		return BlockBasicSummary{}, err
	}
	if err := initial148GenesisHeaderV1(raw, &p, expectedTarget); err != nil {
		return BlockBasicSummary{}, err
	}
	if err := blockStepsResources(&p); err != nil {
		return BlockBasicSummary{}, err
	}
	if err := blockStepsDA(raw, &p); err != nil {
		return BlockBasicSummary{}, err
	}
	hash, err := Initial148BlockHash(raw[:Initial148HeaderBytes])
	if err != nil {
		return BlockBasicSummary{}, err
	}
	return BlockBasicSummary{TxCount: p.count, SumWeight: p.stats.sumWeight, SumDa: p.stats.sumDa, BlockHash: hash}, nil
}

func initial148GenesisHeaderV1(raw []byte, p *blockStepsPass, expectedTarget [32]byte) error {
	if err := Initial148PowCheck(raw[:Initial148HeaderBytes], p.header.Target); err != nil {
		return err
	}
	if p.header.Target != expectedTarget {
		return txerr(BLOCK_ERR_TARGET_INVALID, "target mismatch")
	}
	return blockStepsCommitments(p.header, p.first, p.txRoot, p.witnessRoot)
}

// initial148PendingGeneratedV1 precomputes already_generated(h+1) for the source
// BlockMeta. A pending overflow is not exposed here: finish returns it before
// cap or D, and the prepared source is then never delivered.
func initial148PendingGeneratedV1(input initial148CompleteBlockInputV1) Uint128 {
	next, err := checkedAdvanceAlreadyGenerated(input.Height, input.AlreadyGenerated, input.AlreadyGenerated.Big())
	if err != nil {
		return input.AlreadyGenerated
	}
	return next
}

func (f *initial148CompleteBlockFrameV1) treeRequestV1(block [32]byte, generated *Uint128) blockTreeRequestV1 {
	in := f.input
	return blockTreeRequestV1{
		DatabaseID: in.DatabaseID, Generation: in.Generation, Block: block, Height: in.Height,
		HeaderBytes: Initial148HeaderBytes, BodyKind: 1, Raw: in.Raw, Generated: generated,
		Direction: mdbx.TreeForwardV1, Kind: mdbx.TreeKindDirectApplyV1, Undo: mdbx.UndoTransientV1,
		Endpoint: in.Endpoint, CanonicalBeforePresent: in.CanonicalBeforePresent, OwnerBeforePresent: in.OwnerBeforePresent,
	}
}

// requiredV1 runs the candidate, cap and fresh D inside one R/D scope. The
// callback's selected error is the validation result; a later sticky read
// joined by the producer never replaces an earlier selected error.
func (f *initial148CompleteBlockFrameV1) requiredV1(reader *mdbx.Reader, headerRoot [32]byte, generated Uint128, result *initial148CompleteBlockResultV1) error {
	request := initial148RequiredRequestV1{Source: f.source, Primitive: result.effect.Primitive, Parent: f.input.Parent}
	var selected, first error
	scopeErr := withInitial148RequiredStateV1(reader, f.account, request, func(view logicalStateView, derive func() initial148RootReadOutcomeV1) error {
		selected = f.candidateV1(view, derive, headerRoot, generated, result)
		if scope, ok := view.(*initial148RequiredScopeV1); ok {
			first = scope.first
		}
		return selected
	})
	if selected == nil {
		return scopeErr
	}
	f.recordReadFailureV1(first, selected)
	return selected
}

// recordReadFailureV1 preserves the producer's raw first cause and observation
// only when the selected error is that R failure, not an earlier result.
func (f *initial148CompleteBlockFrameV1) recordReadFailureV1(first, selected error) {
	if f.outcome.required.derived || f.outcome.required.cause != nil {
		return
	}
	if initial148SelectedReadV1(selected, first) {
		f.outcome.required = initial148RequiredOutcomeV1(first)
	}
}

// initial148SelectedReadV1 reports whether the selected error is the scope's
// first R failure itself or one of its application wrappers (the input-view
// read error or a logicalStateFailure), which carry that cause without Unwrap.
func initial148SelectedReadV1(selected, first error) bool {
	if first == nil {
		return false
	}
	var read *blockInputViewReadError
	if errors.As(selected, &read) {
		selected = read.failure
	}
	var failure *logicalStateFailure
	return errors.Is(selected, first) || errors.As(selected, &failure) && any(failure.cause) == any(first)
}

// candidateV1 owns the transition's spent source from connect until the root
// condition succeeds; every exit before that disposes of it here.
func (f *initial148CompleteBlockFrameV1) candidateV1(view logicalStateView, derive func() initial148RootReadOutcomeV1, headerRoot [32]byte, generated Uint128, result *initial148CompleteBlockResultV1) error {
	transition, err := f.connectV1(view)
	if err != nil {
		return err
	}
	result.transition = transition
	handedOff := false
	defer func() {
		if !handedOff && transition.spentInputs != nil {
			transition.spentInputs.discard()
		}
	}()
	if transition.alreadyGeneratedN1 != generated {
		return localLogicalStateFailure("complete initial148 generated scalar differs")
	}
	if err := f.capV1(view, transition); err != nil {
		return err
	}
	if err := f.deriveRootV1(derive, headerRoot); err != nil {
		return err
	}
	handedOff = true
	return nil
}

func (f *initial148CompleteBlockFrameV1) connectV1(view logicalStateView) (*connectBlockInputViewResult, error) {
	in := f.input
	header, _, off, count, err := initial148Frame(in.Raw)
	if err != nil {
		return nil, err
	}
	if err := validateInputViewPlacement(in.Raw, off, count); err != nil {
		return nil, err
	}
	blockMTP, err := inMemoryConnectBlockMTP(in.Height, in.ParentTimestamps, header.Timestamp)
	if err != nil {
		return nil, err
	}
	work := newBlockInputViewConnectWork(connectBlockBasicInMemorySuiteContext{
		BlockBytes: in.Raw, BlockHeight: in.Height, PrevTimestamps: in.ParentTimestamps,
		ChainID: in.ChainID, Rotation: in.Rotation, Registry: in.Registry,
	}, view, off, count, blockMTP)
	if !f.parallel {
		return work.connect(in.AlreadyGenerated)
	}
	return connectBlockInputViewQueued(work, NewSigCheckQueue(f.workers).WithRegistry(in.Registry), in.AlreadyGenerated)
}

// capV1 derives the exact totals in both activation states and applies cap then
// growth; the plan is consumed here and never escapes.
func (f *initial148CompleteBlockFrameV1) capV1(view logicalStateView, transition *connectBlockInputViewResult) error {
	_, err := evaluateLogicalStateCap(nil, *f.input.CapRegistry, f.input.ChainID, f.input.Height, view, replayStepTouched(transition), struct{}{})
	return err
}

// compareRootV1 consumes derived and cause before the 32 root bytes.
func (f *initial148CompleteBlockFrameV1) compareRootV1(required initial148RootReadOutcomeV1, headerRoot [32]byte) error {
	f.outcome.required = required
	if !required.derived {
		if required.cause == nil {
			return localLogicalStateFailure("complete initial148 derive returned no result")
		}
		return required.cause
	}
	if required.cause != nil {
		return localLogicalStateFailure("complete initial148 derive returned an inconsistent result")
	}
	if required.root != headerRoot {
		return txerr(BLOCK_ERR_UTXO_ROOT_MISMATCH, "utxo_root mismatch")
	}
	return nil
}

// deriveRootV1 holds the optional first-genesis engine demand only during D.
func (f *initial148CompleteBlockFrameV1) deriveRootV1(derive func() initial148RootReadOutcomeV1, headerRoot [32]byte) error {
	if f.input.FirstGenesisDemand == 0 {
		return f.compareRootV1(derive(), headerRoot)
	}
	return f.account.WithReservation(f.input.FirstGenesisDemand, func() error {
		return f.compareRootV1(derive(), headerRoot)
	})
}
