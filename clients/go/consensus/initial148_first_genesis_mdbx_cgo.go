//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

const (
	initial148FirstGenesisSourceBytesV1 uint64 = 139_146_042
	initial148FirstGenesisDeriveBytesV1 uint64 = 421_677
)

// Initial148FirstGenesisOutcomeV1 preserves the raw native tuple and its logical
// result. It carries no state or summary; NEW is observed through strict readback.
type Initial148FirstGenesisOutcomeV1 struct {
	Result string
	Truth  mdbx.CommitTruth
	Stage  mdbx.UpdateStage
	Err    error
}

// ConnectPublishedInitial148GenesisMDBX is dormant, with no production caller.
// It requires NONE/STABLE and two FULL_HISTORY PRE_GENESIS roles, changes only
// CURRENT, and projects the native tuple by the first-genesis outcome table.
// databaseID and generation are the opening owner's expected context, never
// authority. All input bytes remain borrowed and immutable through return.
func ConnectPublishedInitial148GenesisMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, candidate, published []byte, chainID, genesisHash, databaseID [32]byte, generation uint64) Initial148FirstGenesisOutcomeV1 {
	call := initial148FirstGenesisCallV1{out: Initial148FirstGenesisOutcomeV1{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite}}
	call.out.Result, call.out.Err = initial148FirstGenesisInputCheckV1(store, reservations, candidate, published, chainID, genesisHash, databaseID, generation)
	if call.out.Err != nil {
		return call.out
	}
	call.input = initial148FirstGenesisInputV1(candidate, published, chainID, genesisHash, databaseID, generation)
	err := reservations.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		call.account = account
		_, runErr := withInitial148CompleteBlockV1(account, call.input, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
			call.validate = validate
			return account.WithReservation(initial148FirstGenesisSourceBytesV1, func() error {
				call.out.Truth, call.out.Stage, _, call.out.Err = store.UpdateTreeV1(account, call.planV1)
				return call.out.Err
			})
		})
		return runErr
	})
	if err != nil && call.out.Err == nil {
		call.out.Err = err
	}
	return initial148FirstGenesisProjectV1(call.out, call.entered, call.complete)
}

// initial148FirstGenesisInputCheckV1 preserves D4 before every reservation or Store call.
func initial148FirstGenesisInputCheckV1(store *mdbx.Store, owner *mdbx.OperationReservationOwner, raw, published []byte, chainID, hash, database [32]byte, generation uint64) (string, error) {
	if store == nil {
		return genesisMDBXInvariant, errors.New("nil genesis Store")
	}
	if !initial148FirstGenesisShapeV1(published, chainID, hash) {
		return genesisMDBXInvariant, errors.New("invalid published genesis context")
	}
	if !bytes.Equal(raw, published) {
		return "CONSENSUS_INVALID", txerr(BLOCK_ERR_LINKAGE_INVALID, "block does not match published genesis")
	}
	if !initial148FirstGenesisOwnerV1(owner) {
		return genesisMDBXInvariant, errors.New("invalid genesis reservation owner")
	}
	if err := replayEntryContext148(PublishedGenesisContextV1{ChainID: chainID, GenesisHash: hash, Published: published}); err != nil {
		return genesisMDBXInvariant, err
	}
	if !initial148FirstGenesisExpectedV1(database, generation) {
		return genesisMDBXInvariant, errors.New("invalid first genesis expected context")
	}
	return "", nil
}

// initial148FirstGenesisShapeV1 is the complete-only D4 context shape.
func initial148FirstGenesisShapeV1(published []byte, chainID, hash [32]byte) bool {
	return len(published) == 298 && chainID != ([32]byte{}) && hash != ([32]byte{})
}

// initial148FirstGenesisOwnerV1 rejects an uninitialized reservation owner at D4.
func initial148FirstGenesisOwnerV1(owner *mdbx.OperationReservationOwner) bool {
	return owner != nil && *owner != (mdbx.OperationReservationOwner{})
}

// initial148FirstGenesisExpectedV1 admits only explicit nonzero opening context.
func initial148FirstGenesisExpectedV1(database [32]byte, generation uint64) bool {
	return database != ([32]byte{}) && generation != 0
}

// This package-private configuration is created once, then borrowed read-only.
// Both rotation caches are populated before publication; no call can mutate it.
var initial148FirstGenesisDefaultsV1 = func() initial148CompleteBlockInputV1 {
	// Concrete calls expose the default suite set's package-initialization dependency.
	inner := DefaultRotationProvider{}
	rotation := &boundSpendSurface{inner: inner, height: 0, haveCreate: true, haveSpend: true, create: inner.NativeCreateSuites(0), spend: inner.NativeSpendSuites(0)}
	capRegistry, _ := validateLogicalStateCapRegistry(nil) // No fallible row in the empty normative registry.
	return initial148CompleteBlockInputV1{CapRegistry: &capRegistry, Registry: DefaultSuiteRegistry(), Rotation: rotation}
}()

// initial148FirstGenesisInputV1 borrows the frozen default height-zero owners.
func initial148FirstGenesisInputV1(raw, published []byte, chainID, hash, database [32]byte, generation uint64) initial148CompleteBlockInputV1 {
	input := initial148FirstGenesisDefaultsV1
	input.Raw, input.PublishedGenesis = raw, published
	input.ChainID, input.DatabaseID, input.Generation = chainID, database, generation
	for i := range input.ExpectedTarget {
		input.ExpectedTarget[i] = 0xff
	}
	input.Endpoint = mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, BlockHash: hash, CumulativeChainwork: [40]byte{39: 1}}
	input.FirstGenesisDemand = initial148FirstGenesisDeriveBytesV1
	return input
}

type initial148FirstGenesisCallV1 struct {
	input    initial148CompleteBlockInputV1
	account  *mdbx.OperationAccount
	validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)
	out      Initial148FirstGenesisOutcomeV1
	entered  bool
	complete bool
}

// planV1 reads actual authority first, validates without committing, then creates
// the separately typed first-genesis primitive over the same immutable block.
func (c *initial148FirstGenesisCallV1) planV1(reader *mdbx.Reader) (mdbx.TreeOperationV1, error) {
	c.entered = true
	authority, err := c.prestateV1(reader)
	if err != nil {
		return mdbx.TreeOperationV1{}, err
	}
	pair, bodyKind, err := c.pairV1(reader, authority)
	if err != nil {
		return mdbx.TreeOperationV1{}, err
	}
	validated, err := c.validate(reader)
	if err != nil {
		return mdbx.TreeOperationV1{}, err
	}
	request := blockTreeRequestV1{
		DatabaseID: c.input.DatabaseID, Generation: authority.Authority.ActiveGenerationID, Block: c.input.Endpoint.BlockHash,
		HeaderBytes: Initial148HeaderBytes, BodyKind: bodyKind, Raw: c.input.Raw, Generated: &validated.transition.alreadyGeneratedN1,
		Direction: mdbx.TreeForwardV1, Kind: mdbx.TreeKindFirstGenesisV1, Undo: mdbx.UndoWriteOrReuseV1, Endpoint: c.input.Endpoint,
	}
	if bodyKind == 2 {
		request.Raw = nil
	}
	source := new(blockTreeSourceV1)
	effect, err := prepareBlockTreeEffectV1(source, reader, c.account, request)
	if err != nil {
		return mdbx.TreeOperationV1{}, err
	}
	pair.Mutations = append(pair.Mutations, effect.Index[:]...)
	initial148FirstGenesisSortV1(&pair)
	c.complete = true
	return mdbx.TreeOperationV1{Pair: pair, Primitives: []mdbx.TreePrimitiveV1{effect.Primitive}}, nil
}

// prestateV1 orders actual authority and role checks before expected-context comparison.
func (c *initial148FirstGenesisCallV1) prestateV1(reader *mdbx.Reader) (mdbx.TreeAuthorityV1, error) {
	a, present, err := reader.ReadTreeAuthorityV1()
	if err != nil {
		return a, err
	}
	if !present {
		return a, initial148FirstGenesisIntegrityV1("absent first genesis authority")
	}
	if a.Authority.Phase != mdbx.StoragePhaseNoneV1 || a.Authority.Lifecycle != mdbx.StorageLifecycleStableV1 {
		return a, c.staleV1()
	}
	current, err := c.bindingsV1(reader, a)
	if err != nil {
		return a, err
	}
	if current.DatabaseID != c.input.DatabaseID || a.Authority.ActiveGenerationID != c.input.Generation {
		return a, c.staleV1()
	}
	return a, nil
}

// bindingsV1 finishes both binding reads before either role's identity checks.
func (c *initial148FirstGenesisCallV1) bindingsV1(reader *mdbx.Reader, a mdbx.TreeAuthorityV1) (mdbx.RootBindingV1, error) {
	current, err := initial148FirstGenesisBindingV1(reader, a.Authority.ActiveGenerationID)
	if err != nil {
		return current, err
	}
	lag, err := initial148FirstGenesisBindingV1(reader, a.LagGenerationID)
	if err != nil {
		return current, err
	}
	return current, c.rolesV1(current, lag)
}

// initial148FirstGenesisBindingV1 retains the Store-bound accessor error or names absence.
func initial148FirstGenesisBindingV1(reader *mdbx.Reader, generation uint64) (mdbx.RootBindingV1, error) {
	binding, present, err := reader.ReadTreeRootBindingV1(generation)
	if err != nil {
		return binding, err
	}
	if !present {
		return binding, initial148FirstGenesisIntegrityV1("absent first genesis binding")
	}
	return binding, nil
}

// rolesV1 gives immutable identity damage priority over changed endpoint or assurance.
func (c *initial148FirstGenesisCallV1) rolesV1(current, lag mdbx.RootBindingV1) error {
	for _, binding := range [...]mdbx.RootBindingV1{current, lag} {
		if binding.ChainID != c.input.ChainID || binding.GenesisHash != c.input.Endpoint.BlockHash {
			return initial148FirstGenesisIntegrityV1("first genesis binding identity differs")
		}
	}
	for _, binding := range [...]mdbx.RootBindingV1{current, lag} {
		if binding.Endpoint.Kind != mdbx.TreeEndpointPreGenesisV1 || binding.Assurance.Kind != mdbx.TreeAssuranceFullHistoryV1 {
			return c.staleV1()
		}
	}
	return nil
}

// staleV1 records the callback refusal without changing the native error projection.
func (c *initial148FirstGenesisCallV1) staleV1() error {
	c.out.Result = "STALE_LOCAL_PLAN"
	return errors.New("first genesis prestate changed")
}

// initial148FirstGenesisIntegrityV1 preserves a positive canonical integrity cause.
func initial148FirstGenesisIntegrityV1(message string) error {
	return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New(message)}
}

// pairV1 qualifies only the finite first-genesis point rows. No parent or
// generation-prefix scan can define the height-zero state.
func (c *initial148FirstGenesisCallV1) pairV1(reader *mdbx.Reader, a mdbx.TreeAuthorityV1) (mdbx.TreePairV1, uint8, error) {
	dbis := mdbx.TreeSchemaV1DBIs()
	lagCounter := binary.BigEndian.AppendUint64([]byte{0x10}, a.LagGenerationID)
	value, present, err := reader.Get(dbis[0], lagCounter)
	if err != nil {
		return mdbx.TreePairV1{}, 0, err
	}
	if !present || !bytes.Equal(value, mdbx.LogicalCounterValue(0, 0)) {
		return mdbx.TreePairV1{}, 0, initial148FirstGenesisIntegrityV1("first genesis LAG counter differs")
	}
	if err := c.indicesAbsentV1(reader, a.Authority.ActiveGenerationID); err != nil {
		return mdbx.TreePairV1{}, 0, err
	}
	pair := mdbx.TreePairV1{Consulted: []mdbx.ConsultedRow{
		{DBI: dbis[0], Key: []byte{0}},
		{DBI: dbis[0], Key: []byte{1}},
		{DBI: dbis[0], Key: []byte{2}},
		{DBI: dbis[0], Key: lagCounter},
		{DBI: dbis[0], Key: binary.BigEndian.AppendUint64([]byte{0x11}, a.LagGenerationID)},
	}}
	if _, err := c.artifactV1(reader, &pair, 3, c.input.Raw[:Initial148HeaderBytes]); err != nil {
		return pair, 0, err
	}
	bodyPresent, err := c.artifactV1(reader, &pair, 4, c.input.Raw)
	if bodyPresent {
		return pair, 2, err
	}
	return pair, 1, err
}

// indicesAbsentV1 checks the two height-zero CURRENT ownership targets without a scan.
func (c *initial148FirstGenesisCallV1) indicesAbsentV1(reader *mdbx.Reader, generation uint64) error {
	canonical, _ := mdbx.HeightKey(generation, 0)
	owner, _ := mdbx.CanonicalOwnerKey(generation, c.input.Endpoint.BlockHash)
	for _, row := range [...]mdbx.ConsultedRow{{DBI: mdbx.TreeSchemaV1DBIs()[2], Key: canonical}, {DBI: mdbx.TreeSchemaV1DBIs()[7], Key: owner}} {
		_, present, err := reader.Get(row.DBI, row.Key)
		if err != nil {
			return err
		}
		if present {
			return initial148FirstGenesisIntegrityV1("first genesis index already present")
		}
	}
	return nil
}

// artifactV1 distinguishes absent, identical and differing hash-global data before use.
func (c *initial148FirstGenesisCallV1) artifactV1(reader *mdbx.Reader, pair *mdbx.TreePairV1, rank int, expected []byte) (bool, error) {
	dbi, key := mdbx.TreeSchemaV1DBIs()[rank], bytes.Clone(c.input.Endpoint.BlockHash[:])
	value, present, err := reader.Get(dbi, key)
	if err != nil {
		return false, err
	}
	if !present {
		pair.Mutations = append(pair.Mutations, mdbx.Mutation{DBI: dbi, Key: key, AfterKind: mdbx.AfterLiteral, Literal: expected})
		return false, nil
	}
	if len(value) != len(expected) || !bytes.Equal(value, expected) {
		return true, initial148FirstGenesisIntegrityV1("first genesis artifact differs")
	}
	pair.Consulted = append(pair.Consulted, mdbx.ConsultedRow{DBI: dbi, Key: key})
	return true, nil
}

// initial148FirstGenesisSortV1 orders each disjoint Pair domain by native rank and key.
func initial148FirstGenesisSortV1(pair *mdbx.TreePairV1) {
	slices.SortFunc(pair.Mutations, func(a, b mdbx.Mutation) int {
		if a.DBI.Rank != b.DBI.Rank {
			return int(a.DBI.Rank) - int(b.DBI.Rank)
		}
		return bytes.Compare(a.Key, b.Key)
	})
	slices.SortFunc(pair.Consulted, func(a, b mdbx.ConsultedRow) int {
		if a.DBI.Rank != b.DBI.Rank {
			return int(a.DBI.Rank) - int(b.DBI.Rank)
		}
		return bytes.Compare(a.Key, b.Key)
	})
}

// initial148FirstGenesisProjectV1 adds the format-3 capacity and changed-plan cells to D8.
func initial148FirstGenesisProjectV1(out Initial148FirstGenesisOutcomeV1, entered, complete bool) Initial148FirstGenesisOutcomeV1 {
	raw := GenesisMDBXOutcome{Truth: out.Truth, Stage: out.Stage, Err: out.Err}
	if genesisMDBXCached(raw, entered) {
		out.Result = ""
		return out
	}
	if !initial148FirstGenesisTupleV1(out, entered, complete) {
		out.Result = genesisMDBXInvariant
		return out
	}
	if out.Stage == mdbx.UpdateStageCommitMayHaveCrossed {
		out.Result = genesisMDBXCrossed(out.Truth, out.Err)
		return out
	}
	if mdbx.IsOperationReservationCapacity(out.Err) {
		out.Result = "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"
		return out
	}
	if initial148FirstGenesisMismatchV1(out.Err, complete) {
		out.Result = "STALE_LOCAL_PLAN"
		return out
	}
	out.Result = genesisMDBXUncrossed(out.Err, out.Result, out.Stage)
	return out
}

// initial148FirstGenesisTupleV1 rejects inconsistent stage, truth, cause or plan evidence.
func initial148FirstGenesisTupleV1(out Initial148FirstGenesisOutcomeV1, entered, complete bool) bool {
	if !initial148FirstGenesisDomainV1(out) {
		return false
	}
	if genesisMDBXNilError(out.Err) {
		return false
	}
	if out.Stage == mdbx.UpdateStageCommitMayHaveCrossed {
		return entered && complete && (out.Truth == mdbx.CommitTruthNew || out.Err != nil)
	}
	return out.Truth == mdbx.CommitTruthOld && out.Err != nil
}

// initial148FirstGenesisDomainV1 closes the raw native stage/truth domains for projection.
func initial148FirstGenesisDomainV1(out Initial148FirstGenesisOutcomeV1) bool {
	return out.Truth >= mdbx.CommitTruthOld && out.Truth <= mdbx.CommitTruthUnknown && out.Stage >= mdbx.UpdateStagePrewrite && out.Stage <= mdbx.UpdateStageCommitMayHaveCrossed
}

// initial148FirstGenesisMismatchV1 qualifies StateMismatch only after a complete plan.
func initial148FirstGenesisMismatchV1(err error, complete bool) bool {
	var engine *mdbx.EngineError
	return complete && errors.As(err, &engine) && engine != nil && engine.Class == mdbx.EngineStateMismatch
}
