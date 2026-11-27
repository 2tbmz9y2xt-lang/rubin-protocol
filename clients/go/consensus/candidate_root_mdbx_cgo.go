//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"math"
	"reflect"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// CandidateRootCapRow is one chain's logical state cap activation.
type CandidateRootCapRow struct {
	ChainID          [32]byte
	ActivationHeight uint64
}

// CandidateRootCapRegistry holds the validated ordered activation rows.
type CandidateRootCapRegistry struct {
	registry validatedLogicalStateCapRegistry
}

// NewCandidateRootCapRegistry validates the supplied order and copies the rows.
func NewCandidateRootCapRegistry(rows []CandidateRootCapRow) (*CandidateRootCapRegistry, error) {
	raw := make([]logicalStateCapRegistryRow, len(rows))
	for i := range rows {
		raw[i] = logicalStateCapRegistryRow{chainID: rows[i].ChainID[:], activationHeight: rows[i].ActivationHeight}
	}
	registry, err := validateLogicalStateCapRegistry(raw)
	if err != nil {
		return nil, err
	}
	return &CandidateRootCapRegistry{registry: registry}, nil
}

// CandidateRootRotation owns one height's resolved rotation and deployment result.
type CandidateRootRotation struct {
	rotation RotationProvider
}

// FreezeCandidateRootRotation copies the provider's context before candidate validation.
func FreezeCandidateRootRotation(height uint64, provider RotationProvider) (*CandidateRootRotation, error) {
	if height == 0 || height > math.MaxUint32 || !candidateProviderPresent(provider) {
		return nil, localLogicalStateFailure("invalid candidate rotation context")
	}
	surface := &boundSpendSurface{
		height: height, haveCreate: true, haveSpend: true,
		create: provider.NativeCreateSuites(height).Clone(), spend: provider.NativeSpendSuites(height).Clone(),
	}
	if surface.create.Len() == 0 || surface.spend.Len() == 0 {
		return nil, localLogicalStateFailure("unresolved candidate suite context")
	}
	rotation := RotationProvider(surface)
	if deployment, ok := provider.(SimplicityDeploymentProvider); ok {
		descriptors, anchor, present, err := deployment.PublishedSimplicityDeployments()
		rotation = &boundSpendSurfaceWithDeployment{
			boundSpendSurface: surface, have: true,
			descriptors: append([]SimplicityDeploymentDescriptor(nil), descriptors...), setAnchor: anchor, ok: present, err: err,
		}
	}
	return &CandidateRootRotation{rotation: rotation}, nil
}

// candidateProviderPresent rejects a missing provider before any provider call.
func candidateProviderPresent(provider RotationProvider) bool {
	if provider == nil {
		return false
	}
	value := reflect.ValueOf(provider)
	kind := value.Kind()
	nilable := kind == reflect.Chan || kind == reflect.Func || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice
	return !nilable || !value.IsNil()
}

// CandidateRootInput borrows the final immutable body and selected parent context.
type CandidateRootInput struct {
	Raw              []byte
	Selection        mdbx.CandidateRootParentV1
	ExpectedTarget   [32]byte
	ParentTimestamps []uint64
	AlreadyGenerated Uint128
	ChainID          [32]byte
	CapRegistry      *CandidateRootCapRegistry
	Registry         *SuiteRegistry
	Rotation         *CandidateRootRotation
}

// CandidateRootFailureKind classifies candidate logical state failures.
type CandidateRootFailureKind = logicalStateFailureKind

const (
	CandidateRootFailureUnavailable    = logicalStateFailureUnavailable
	CandidateRootFailureStoreIntegrity = logicalStateFailureStoreIntegrity
	CandidateRootFailureLocalInvariant = logicalStateFailureLocalInvariant
)

// InspectCandidateRootFailure reports the class and original cause of a direct logical state failure.
func InspectCandidateRootFailure(err error) (CandidateRootFailureKind, error, bool) {
	failure, ok := err.(*logicalStateFailure)
	if !ok || failure == nil {
		return 0, nil, false
	}
	return failure.kind, failure.cause, true
}

// DeriveCandidateUTXORootV1 derives the exact poststate root in the active View.
// On error the returned root is zero. The enclosing View also reports its own outcome.
func DeriveCandidateUTXORootV1(reader *mdbx.Reader, owner *mdbx.OperationReservationOwner, input CandidateRootInput) ([32]byte, error) {
	if !input.registriesV1() {
		return [32]byte{}, localLogicalStateFailure("invalid candidate validation context")
	}
	if len(input.Raw) > initial148BlockMaxBytes {
		return [32]byte{}, ErrInitial148BlockCapacity
	}
	var result initial148RootReadOutcomeV1
	err := owner.WithCandidateRootV1(reader, input.Selection, input.Raw, func(scope *mdbx.CandidateRootScopeV1) error {
		var err error
		result, err = input.fundAndDeriveV1(reader, scope)
		return err
	})
	if err != nil {
		return [32]byte{}, err
	}
	if !result.derived || result.cause != nil || result.hasObservation {
		return [32]byte{}, localLogicalStateFailure("candidate root result is inconsistent")
	}
	return result.root, nil
}

// registriesV1 admits initialized registries and one height-frozen rotation.
func (in *CandidateRootInput) registriesV1() bool {
	if in.CapRegistry == nil || in.CapRegistry.registry.rows == nil || in.Registry == nil || in.Registry.suites == nil || in.Rotation == nil {
		return false
	}
	height, rotation := in.Selection.Height, in.Rotation.rotation
	if !initial148FrozenRotationV1(rotation, height) {
		return false
	}
	return in.hasFrozenSuitesV1(rotation.NativeCreateSuites(height)) && in.hasFrozenSuitesV1(rotation.NativeSpendSuites(height))
}

// hasFrozenSuitesV1 requires the supplied registry to resolve the frozen suite set.
func (in *CandidateRootInput) hasFrozenSuitesV1(set *NativeSuiteSet) bool {
	if set == nil || set.suites == nil {
		return false
	}
	for suite := range set.suites {
		params, ok := in.Registry.Lookup(suite)
		if !ok || params.PubkeyLen <= 0 || params.SigLen <= 0 {
			return false
		}
	}
	return true
}

// fundAndDeriveV1 validates the window before admitting the full validation tariff.
func (in *CandidateRootInput) fundAndDeriveV1(reader *mdbx.Reader, scope *mdbx.CandidateRootScopeV1) (initial148RootReadOutcomeV1, error) {
	if !blockStepsContextValid(in.ExpectedTarget, in.Selection.Height, in.ParentTimestamps) {
		return initial148RootReadOutcomeV1{}, ErrBlockSteps1To12Context
	}
	w, ok := initial148ValidationTariffV1(in.Raw, in.Registry, &in.CapRegistry.registry, in.Rotation.rotation, in.ParentTimestamps)
	if !ok {
		// Saturation is above the scope ceiling and selects the owner's capacity refusal.
		w = math.MaxUint64
	}
	var out initial148RootReadOutcomeV1
	err := scope.WithCandidateValidationV1(w, func(retire func() error) error {
		var err error
		out, err = in.deriveFundedV1(reader, scope, retire)
		return err
	})
	return out, err
}

// deriveFundedV1 preserves prefix, placement, CURRENT, state law and root order.
func (in *CandidateRootInput) deriveFundedV1(reader *mdbx.Reader, scope *mdbx.CandidateRootScopeV1, retire func() error) (initial148RootReadOutcomeV1, error) {
	p := in.Selection
	if err := validateCandidateBlockSteps(in.Raw, p.Parent.BlockHash, in.ExpectedTarget, in.ParentTimestamps); err != nil {
		return initial148RootReadOutcomeV1{}, err
	}
	frame, err := initial148ConnectFrameV1(in.connectContextV1())
	if err != nil {
		return initial148RootReadOutcomeV1{}, err
	}
	if err := scope.QualifyCurrentV1(); err != nil {
		return initial148RootReadOutcomeV1{}, err
	}
	meta, err := candidateTreeCensusV1(scope, in.Raw, p.Height)
	if err != nil {
		return initial148RootReadOutcomeV1{}, err
	}
	return withCandidateRequiredV1(reader, scope, p, in.Raw, meta, retire, func(view logicalStateView) (Uint128, error) {
		defer in.retireValidationV1()
		return in.applyStateLawV1(frame, view)
	})
}

// connectContextV1 lends the frozen validation inputs to the shared transition.
func (in *CandidateRootInput) connectContextV1() connectBlockBasicInMemorySuiteContext {
	return connectBlockBasicInMemorySuiteContext{
		BlockBytes: in.Raw, BlockHeight: in.Selection.Height, PrevTimestamps: in.ParentTimestamps,
		ChainID: in.ChainID, Rotation: in.Rotation.rotation, Registry: in.Registry,
	}
}

// applyStateLawV1 checks actual generation, cap and growth and disposes the transition.
func (in *CandidateRootInput) applyStateLawV1(frame initial148ConnectFrame, view logicalStateView) (Uint128, error) {
	work := frame.workV1(in.connectContextV1(), view)
	transition, err := work.connect(in.AlreadyGenerated)
	if err != nil {
		return Uint128{}, err
	}
	defer transition.spentInputs.discard()
	generated := transition.alreadyGeneratedN1
	if generated != initial148ExpectedGeneratedV1(in.Selection.Height, in.AlreadyGenerated) {
		return Uint128{}, localLogicalStateFailure("candidate generated scalar differs")
	}
	if err := initial148CheckCapV1(&in.CapRegistry.registry, in.ChainID, in.Selection.Height, view, transition); err != nil {
		return Uint128{}, err
	}
	return generated, nil
}

// retireValidationV1 drops the provider, registry and timestamp references after cap and growth.
func (in *CandidateRootInput) retireValidationV1() {
	in.CapRegistry, in.Registry, in.Rotation = nil, nil, nil
	in.ParentTimestamps = nil
}
