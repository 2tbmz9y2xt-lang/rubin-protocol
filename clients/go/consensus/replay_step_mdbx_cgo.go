//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"math/bits"
	"slices"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// ReplayStepContextV1 is the immutable historical consensus context of a dormant replay owner.
type ReplayStepContextV1 struct {
	Genesis  PublishedGenesisContextV1
	Rotation RotationProvider
	Registry *SuiteRegistry
}

// ReplayStepOwnerV1 shares one PATH owner and mathematical supply memo across handle copies.
type ReplayStepOwnerV1 struct {
	path  *replayPathOwner
	state *replayStepState
}

type replayStepState struct {
	context   ReplayStepContextV1
	preflight error
	height    uint64
	generated Uint128
	memo      bool
	database  [32]byte
}

type ReplayStepNeedKindV1 uint8

const (
	ReplayStepNeedHeaderV1     ReplayStepNeedKindV1 = 1
	ReplayStepNeedBlockBytesV1 ReplayStepNeedKindV1 = 2
)

type ReplayStepNeedV1 struct {
	Kind   ReplayStepNeedKindV1
	Height uint64
	Hash   [32]byte
}

// ReplayStepOutcomeV1 exposes the native tuple and this invocation's logical result; it publishes no state.
type ReplayStepOutcomeV1 struct {
	Result, Decision, CanonicalTruth string
	Truth                            mdbx.CommitTruth
	Stage                            mdbx.UpdateStage
	Err                              error
	Needed                           *ReplayStepNeedV1
	// The following fields describe only the explicit148 route. Legacy calls
	// leave NativeCalled false, Index -1, and every other new field zero.
	NativeCalled   bool
	Index          int
	Role           string
	Height         uint64
	Block          [32]byte
	Cause          error
	Observation    mdbx.TreeObservationV1
	HasObservation bool
}

func NewReplayStepOwnerV1(context ReplayStepContextV1, view ReplayHeaderCandidateViewV1, retentionLimit uint64) *ReplayStepOwnerV1 {
	s := &replayStepState{}
	if !replayEntryContextShape(context.Genesis) {
		s.preflight = errors.New("invalid published genesis context")
	} else {
		context.Genesis.Published = bytes.Clone(context.Genesis.Published)
		s.context, s.preflight = context, replayEntryContext(context.Genesis)
	}
	return &ReplayStepOwnerV1{path: newReplayPathOwner(view, retentionLimit), state: s}
}

// NewReplayStepOwner148V1 fixes the grammar and opening database identity of
// the dormant tree STEP, sharing the existing path lock, slot and supply memo.
func NewReplayStepOwner148V1(context ReplayStepContextV1, view ReplayHeaderCandidateView148V1, retentionLimit uint64, databaseID [32]byte) *ReplayStepOwnerV1 {
	s := &replayStepState{database: databaseID}
	if !replayEntryContextShape148(context.Genesis) || databaseID == ([32]byte{}) {
		s.preflight = errors.New("invalid published genesis or opening database context")
	} else {
		context.Genesis.Published = bytes.Clone(context.Genesis.Published)
		s.context, s.preflight = context, replayEntryContext148(context.Genesis)
	}
	return &ReplayStepOwnerV1{path: &replayPathOwner{initial148: true, view148: view, limit: retentionLimit}, state: s}
}

func (o *ReplayStepOwnerV1) DiscardV1() bool {
	return o != nil && o.path != nil && o.path.discard()
}

func (o *ReplayStepOwnerV1) StepReplayMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, supplied []byte) ReplayStepOutcomeV1 {
	return replayStepRun(o, store, reservations, supplied).out
}

type replayStepObservation struct {
	decision        string
	h               uint64
	x               [32]byte
	incoming, cause error
	failure         *logicalStateFailure
}

// Only finalized scalars and original error references survive the native operation.
type replayStepInvocation struct {
	out         ReplayStepOutcomeV1
	observation replayStepObservation
}

func replayStepRun(o *ReplayStepOwnerV1, store *mdbx.Store, reservations *mdbx.OperationReservationOwner, supplied []byte) *replayStepInvocation {
	i := &replayStepInvocation{out: ReplayStepOutcomeV1{CanonicalTruth: "OLD", Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite, Index: -1}}
	switch {
	case o == nil, o.path == nil, o.state == nil:
		i.out.Result, i.out.Err = selectedSideInvariant, errors.New("invalid replay step owner")
		return i
	}
	o.path.mu.Lock()
	defer o.path.mu.Unlock()
	defer o.path.finishLocked()
	if o.state.preflight != nil {
		i.out.Result, i.out.Err = selectedSideInvariant, o.state.preflight
		if o.path.initial148 {
			i.out.Cause, i.out.Err = i.out.Err, nil
		}
		return i
	}
	if o.path.initial148 {
		return replayStepRun148V1(o, store, reservations, supplied, i)
	}
	return replayStepRunLegacyV1(o, store, reservations, supplied, i)
}

// replayStepRunLegacyV1 retains the legacy reservation and batch application.
func replayStepRunLegacyV1(o *ReplayStepOwnerV1, store *mdbx.Store, reservations *mdbx.OperationReservationOwner, supplied []byte, i *replayStepInvocation) *replayStepInvocation {
	if store == nil {
		i.out.Truth, i.out.Stage, i.out.Err = store.Update(nil)
		i.out.CanonicalTruth = ""
		return i
	}
	c := &replayStepCall{owner: o, invocation: i, entry: replayEntryCall{sentinel: errors.New("replay step decision")}}
	ran := false
	err := reservations.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		ran = true
		i.out.Truth, i.out.Stage, i.out.Err = store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
			input := supplied
			supplied = nil
			return c.plan(r, input)
		})
		c.project()
		return nil
	})
	if ran {
		return i
	}
	if reservations == nil || *reservations == (mdbx.OperationReservationOwner{}) {
		i.out.Err, i.out.CanonicalTruth = err, ""
		return i
	}
	// For a proven nonzero owner and nonnil callback, reserve's sole refusal is its capacity sentinel.
	c.denied = true
	i.out.Truth, i.out.Stage, i.out.Err = store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) { return c.plan(r, nil) })
	c.project()
	return i
}

// replayStepRun148V1 keeps the complete frame outside the one native pair call.
func replayStepRun148V1(o *ReplayStepOwnerV1, store *mdbx.Store, reservations *mdbx.OperationReservationOwner, supplied []byte, invocation *replayStepInvocation) *replayStepInvocation {
	c := &replayStepCall{owner: o, invocation: invocation, entry: replayEntryCall{sentinel: errors.New("replay step decision")}}
	err := reservations.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		defer o.path.finishLocked()
		defer c.release148V1()
		c.account = account
		complete, runErr := withInitial148ReplayCompleteBlockV1(account, func(validate func(*mdbx.Reader, initial148CompleteBlockInputV1) (*initial148CompleteBlockResultV1, error)) error {
			c.validate148 = validate
			invocation.out.NativeCalled = true
			out := applyReplayPairV1(store, account, func(reader *mdbx.Reader) (replayPairRequestV1, *initial148CompleteBlockResultV1, replayPairRowsV1, error) {
				input := supplied
				supplied = nil
				return c.prepare148V1(reader, input)
			}, c.lagInputs148V1)
			invocation.out.Truth, invocation.out.Stage, invocation.out.Index, invocation.out.Err, invocation.out.Role = out.Truth, out.Stage, out.Index, out.Err, out.Role
			return out.Err
		})
		c.complete148 = complete
		c.project148V1(runErr)
		return nil
	})
	if err != nil {
		invocation.out.Cause, invocation.out.Result = err, selectedSideInvariant
	}
	return invocation
}

// release148V1 retires caller backing after native and complete-frame cleanup.
func (c *replayStepCall) release148V1() {
	c.reader, c.body, c.old, c.timestamps, c.consulted = nil, nil, nil, nil, nil
	c.own, c.tree = replayPathOwn{}, mdbx.TreeAuthorityV1{}
	c.validate148, c.account = nil, nil
}

// prepare148V1 recognizes complete authority before the single gross precheck.
func (c *replayStepCall) prepare148V1(reader *mdbx.Reader, supplied []byte) (request replayPairRequestV1, result *initial148CompleteBlockResultV1, rows replayPairRowsV1, err error) {
	c.entered, c.reader = true, reader
	defer func() { c.select148V1(err) }()
	if err = c.authority148V1(reader); err != nil {
		return
	}
	if err = c.sources(supplied); err != nil {
		return
	}
	var input initial148CompleteBlockInputV1
	input, err = c.boundInput148V1()
	if err != nil {
		return
	}
	c.entry.step = "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)"
	result, err = c.validate148(reader, input)
	if err != nil {
		err = c.consensus(err)
		return
	}
	c.count = result.summary.TxCount
	rows, err = c.rows148V1(result)
	if err != nil {
		return
	}
	request = replayPairRequestV1{Authority: c.tree, Database: c.owner.state.database, Height: c.h, Endpoint: input.Endpoint, LagParent: c.parentEndpoint, Raw: c.body}
	c.owner.state.height, c.owner.state.generated = c.h+1, result.transition.alreadyGeneratedN1
	c.entry.step, c.entry.planned = "", true
	return
}

// authority148V1 derives the finite height/window/path worklist before funding.
func (c *replayStepCall) authority148V1(reader *mdbx.Reader) error {
	envelope, present, err := reader.ReadTreeAuthorityV1()
	if err != nil {
		return err
	}
	c.tree, c.a = envelope, envelope.Authority
	phase := present && c.a.Phase == mdbx.StoragePhaseReplayV1 && c.a.Lifecycle == mdbx.StorageLifecycleRecoveryRequiredV1
	if !phase || c.tree.SourceKind != mdbx.TreeSourceGenesisReplayV1 || !replayPathApplicable(c.a) {
		_, err := c.decide("", "not applicable")
		return err
	}
	if c.a.Replay.Cursor.Kind == mdbx.ReplayCursorAppliedV1 {
		c.h = c.a.Replay.Cursor.Height + 1
	}
	c.bodyBound, c.undoBound = c.promises148V1()
	c.windowCount = replayStepWindowV1(c.h)
	return c.account.PrecheckV1(400000000)
}

func replayStepWindowV1(height uint64) uint64 {
	if height != 0 && height%WINDOW_SIZE == 0 {
		return WINDOW_SIZE
	}
	return min(height, 11)
}

func (c *replayStepCall) boundInput148V1() (initial148CompleteBlockInputV1, error) {
	if err := ValidateInitial148BlockBodyCommitments(c.body); err != nil {
		return initial148CompleteBlockInputV1{}, c.unbound()
	}
	return c.input148V1()
}

// select148V1 retains the original first source or validation result by identity.
func (c *replayStepCall) select148V1(err error) {
	if err == nil || any(err) == any(c.entry.sentinel) || c.invocation.observation.incoming != nil {
		return
	}
	h, x := c.h, c.x
	if x == ([32]byte{}) {
		h, x = c.own.h, c.own.x
	}
	c.invocation.observation = replayStepObservation{h: h, x: x, incoming: err}
}

// undo148V1 projects the validated original-order source without consuming
// its map or cursor; only the later LAG input frame owns that consumption.
func (c *replayStepCall) undo148V1(result *initial148CompleteBlockResultV1) ([]mdbx.Mutation, error) {
	spent := result.transition.spentInputs
	count := canonicalUndoCount(spent)
	if c.count > math.MaxUint32 || count < 0 || count > math.MaxUint32 {
		return nil, localLogicalStateFailure("validated replay undo count differs")
	}
	var generated [16]byte
	binary.BigEndian.PutUint64(generated[:8], c.owner.state.generated.Hi)
	binary.BigEndian.PutUint64(generated[8:], c.owner.state.generated.Lo)
	rows := make([]mdbx.Mutation, 1, count+1)
	rows[0] = mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[5], Key: mdbx.UndoManifestKey(c.x), AfterKind: mdbx.AfterLiteral, Literal: mdbx.UndoManifestValue(c.h, generated, uint32(c.count), uint32(count))}
	if spent == nil {
		return rows, nil
	}
	rows, err := c.undoEntries148V1(spent, rows)
	if err != nil {
		return nil, err
	}
	if len(rows) != count+1 {
		return nil, localLogicalStateFailure("validated replay undo count differs")
	}
	return rows, nil
}

// undoEntries148V1 reads validated transactions in original order without
// changing the spent source's map, cursor or retained backing.
func (c *replayStepCall) undoEntries148V1(spent *blockSpentInputSource, rows []mdbx.Mutation) ([]mdbx.Mutation, error) {
	offset := spent.offset
	for ordinal := spent.nextTx; ordinal < spent.count; ordinal++ {
		if ordinal > math.MaxUint32 {
			return nil, localLogicalStateFailure("validated replay undo framing differs")
		}
		tx, _, _, _, err := parseBlockTx(c.body, &offset)
		if err != nil {
			return nil, localLogicalStateFailure("validated replay undo framing differs")
		}
		for index, input := range tx.Inputs {
			op := Outpoint{Txid: input.PrevTxid, Vout: input.PrevVout}
			if spent.spent[op] == 0 {
				continue
			}
			key, _ := mdbx.UTXOKey(c.a.Replay.TargetGenerationID, op.Txid, op.Vout)
			rows = append(rows, mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[5], Key: mdbx.UndoEntryKey(c.x, op.Txid, uint32(ordinal), uint32(index), op.Vout), AfterKind: mdbx.AfterOldValueRef, RefDBI: mdbx.SchemaV2DBIs()[1], RefKey: key})
		}
	}
	return rows, nil
}

// compare148V1 finishes hash-global comparisons before old-active ownership.
func (c *replayStepCall) compare148V1(result *initial148CompleteBlockResultV1) (bool, error) {
	if c.headerMismatch {
		return false, selectedSideDefect("replay body and header differ")
	}
	if c.stored {
		raw, present, err := c.source(mdbx.SchemaV2DBIs()[4], c.x[:], selectedSideCanonical)
		if err != nil {
			return false, err
		}
		if !present || !bytes.Equal(raw, c.body) {
			return false, selectedSideDefect("replay stored body differs")
		}
	}
	undo, err := c.undo148V1(result)
	if err != nil {
		return false, err
	}
	c.entry.step = selectedSideCanonical
	present, err := canonicalUndoFamilyEqualV1(c.reader, &c.x, undo)
	if err == nil {
		c.entry.step = ""
	}
	return present, err
}

// promises148V1 uses the final pair's L_body, independently of B_target.
func (c *replayStepCall) promises148V1() (uint64, uint64) {
	_, undo := replayStepPromises(c.a.Replay)
	if c.a.Replay.TargetProfile == mdbx.StorageProfileArchiveV1 || c.a.Replay.Target.TipHeight < 15120 {
		return 0, undo
	}
	return 720*((c.a.Replay.Target.TipHeight-15120)/720) + 1, undo
}

// rows148V1 owns comparisons, the one shared old-active result, and the
// complete envelope. Pair separately owns its two role-index effects.
func (c *replayStepCall) rows148V1(result *initial148CompleteBlockResultV1) (replayPairRowsV1, error) {
	undoPresent, err := c.compare148V1(result)
	if err != nil {
		return replayPairRowsV1{}, err
	}
	b, u := c.bodyBound, c.undoBound
	deleteOld := false
	if c.stored && c.h < b || undoPresent && c.h < u {
		deleteOld, err = c.oldActive()
		if err != nil {
			return replayPairRowsV1{}, err
		}
	}
	return c.artifactRows148V1(b, u, undoPresent, deleteOld)
}

// artifactRows148V1 translates the already compared/promise-owned families;
// it performs no second old-active lookup or earlier target-membership read.
func (c *replayStepCall) artifactRows148V1(b, u uint64, undoPresent, deleteOld bool) (replayPairRowsV1, error) {
	rows := replayPairRowsV1{BodyKind: 3, Undo: mdbx.UndoTransientV1}
	if c.h >= b {
		rows.BodyKind = 1
	}
	if c.stored {
		rows.BodyKind = 2
	}
	rows.Undo = replayStepUndo148V1(c.h >= u, undoPresent, deleteOld)
	rows.Pair.Mutations = c.headerExtra()
	if c.stored {
		mutations, err := c.bodyEffects(rows.Pair.Mutations, b, deleteOld)
		if err != nil {
			return replayPairRowsV1{}, err
		}
		rows.Pair.Mutations = mutations
	}
	return c.pair148V1(rows)
}

func replayStepUndo148V1(promised, present, deleteOld bool) mdbx.TreeUndoEffectV1 {
	if promised {
		return mdbx.UndoWriteOrReuseV1
	}
	if !present {
		return mdbx.UndoTransientV1
	}
	if deleteOld {
		return mdbx.UndoCompareDeleteV1
	}
	return mdbx.UndoCompareV1
}

// membership148V1 observes both independent new-height row presences without
// treating staging rows as evidence about the committed OLD prefix.
func (c *replayStepCall) membership148V1(generation uint64) (bool, bool, error) {
	key, _ := mdbx.HeightKey(generation, c.h)
	entry, present, err := c.source(mdbx.SchemaV2DBIs()[2], key, replayEntryRecovery)
	if err != nil {
		return false, false, err
	}
	if present && !bytes.Equal(entry, mdbx.ChainValue(c.x, c.parent, c.work)) {
		return false, false, selectedSideDefect("replay target staging entry differs")
	}
	key, _ = mdbx.CanonicalOwnerKey(generation, c.x)
	owner, owned, err := c.source(mdbx.SchemaV2DBIs()[7], key, replayEntryRecovery)
	if err != nil {
		return false, false, err
	}
	if owned && !bytes.Equal(owner, mdbx.CanonicalOwnerValue(c.h)) {
		return false, false, selectedSideDefect("replay target staging owner differs")
	}
	return present, owned, nil
}

// pair148V1 preserves the full qualified envelope and predeclares finite LAG
// OLD equality keys without reading their health before the reached LAG stage.
func (c *replayStepCall) pair148V1(rows replayPairRowsV1) (replayPairRowsV1, error) {
	var err error
	rows.CurrentCanonical, rows.CurrentOwner, err = c.membership148V1(c.a.Replay.TargetGenerationID)
	if err != nil {
		return replayPairRowsV1{}, err
	}
	if replayPairAppliesV1(c.a.Replay.Target.TipHeight, c.h) {
		rows.LagCanonical, rows.LagOwner, err = c.membership148V1(c.tree.TargetLagGenerationID)
		if err != nil {
			return replayPairRowsV1{}, err
		}
		if c.h > 0 {
			key, _ := mdbx.HeightKey(c.tree.TargetLagGenerationID, c.h-1)
			owner, _ := mdbx.CanonicalOwnerKey(c.tree.TargetLagGenerationID, c.parent)
			c.consulted = append(c.consulted, mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[2], Key: key}, mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[7], Key: owner})
		}
	}
	next, replay := c.tree, *c.a.Replay
	replay.Cursor = mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: c.h, BlockHash: c.x}
	next.Authority.Replay = &replay
	encoded, err := next.Encode()
	if err != nil {
		return replayPairRowsV1{}, err
	}
	rows.Pair.Mutations = append(rows.Pair.Mutations, mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: encoded})
	slices.SortFunc(rows.Pair.Mutations, replayPairMutationCompareV1)
	rows.Pair.Consulted, rows.Pair.ContextConsulted = c.finiteRemainder(rows.Pair.Mutations), c.context
	return rows, nil
}

// lagEvidence148V1 uses only the already qualified CURRENT context/header and
// decoded exclusive role identities, before the producing LAG Get can expire r.
func (c *replayStepCall) lagEvidence148V1() bool {
	_, bound := replayHeaderBind148(c.parentHeader[:], c.parent)
	return bound && c.parentEndpoint.Kind == mdbx.TreeEndpointAppliedV1 && c.parentEndpoint.Height == c.h-1 && c.parentEndpoint.BlockHash == c.parent && c.parent == c.a.Replay.Cursor.BlockHash
}

// replayStepLagWidth148V1 is used only on the direct recorded Get of a frozen
// required LAG key; neither wrapped errors nor backend integrity match it.
func replayStepLagWidth148V1(err error) bool {
	engine, ok := any(err).(*mdbx.EngineError)
	if !ok || engine == nil {
		return false
	}
	got := replayTreeRefusal{engine.Class, engine.Operation, engine.Code, engine.Diagnostic, engine.ReopenRequired}
	want := replayTreeRefusal{mdbx.EngineIntegrity, "get", -30796, "invalid tree native representation", false}
	return got == want && engine.Cause != nil && engine.TreeObservation == nil
}

func (c *replayStepCall) lagGet148V1(dbi mdbx.DBI, key []byte, qualified bool) ([]byte, bool, error) {
	value, present, err := c.source(dbi, key, replayEntryRecovery)
	if err != nil && qualified && replayStepLagWidth148V1(err) {
		return nil, false, c.observe("target local", err, nil)
	}
	return value, present, err
}

func (c *replayStepCall) lagDamage148V1(qualified bool, message string) error {
	cause := selectedSideDefect(message)
	if qualified {
		return c.observe("target local", cause, nil)
	}
	return cause
}

// lagParent148V1 never completes localization with a later header read. Every
// Get error returns before any further use of the expired callback Reader.
func (c *replayStepCall) lagParent148V1() error {
	if c.h == 0 {
		return nil
	}
	qualified := c.lagEvidence148V1()
	key, _ := mdbx.HeightKey(c.tree.TargetLagGenerationID, c.h-1)
	expected := mdbx.ChainValue(c.parent, [32]byte(c.parentHeader[4:36]), c.parentEndpoint.CumulativeChainwork)
	entry, present, err := c.lagGet148V1(mdbx.SchemaV2DBIs()[2], key, qualified)
	if err != nil {
		return err
	}
	if !present || !bytes.Equal(entry, expected) {
		return c.lagDamage148V1(qualified, "required replay LAG parent differs")
	}
	owner, _ := mdbx.CanonicalOwnerKey(c.tree.TargetLagGenerationID, c.parent)
	entry, present, err = c.lagGet148V1(mdbx.SchemaV2DBIs()[7], owner, qualified)
	if err != nil {
		return err
	}
	if !present || !bytes.Equal(entry, mdbx.CanonicalOwnerValue(c.h-1)) {
		return c.lagDamage148V1(qualified, "required replay LAG reciprocal owner differs")
	}
	return nil
}

// lagInputs148V1 runs after the pair's CURRENT F2 and separate LAG/F3 sources.
// Key-only backing and D retire before native writing; spent is consumed once.
func (c *replayStepCall) lagInputs148V1(_ *mdbx.Reader, result *initial148CompleteBlockResultV1, use func([]mdbx.TreeOutpointV1) error) (err error) {
	defer func() { c.select148V1(err) }()
	if err := c.lagParent148V1(); err != nil {
		return err
	}
	spent := result.transition.spentInputs
	count := canonicalUndoCount(spent)
	if count < 0 {
		return localLogicalStateFailure("validated replay undo count differs")
	}
	return c.account.WithReservation(36*uint64(count), func() error {
		keys := make([]mdbx.TreeOutpointV1, 0, count)
		if spent != nil {
			for item, have := spent.next(); have; item, have = spent.next() {
				key, _ := mdbx.UTXOKey(c.tree.TargetLagGenerationID, item.outpoint.Txid, item.outpoint.Vout)
				_, present, err := c.source(mdbx.SchemaV2DBIs()[1], key, replayEntryRecovery)
				if err != nil {
					return err
				}
				if !present {
					return c.lagDamage148V1(c.lagEvidence148V1(), "required replay LAG input absent")
				}
				keys = append(keys, mdbx.TreeOutpointV1{Txid: item.outpoint.Txid, Vout: item.outpoint.Vout})
			}
		}
		slices.SortFunc(keys, func(a, b mdbx.TreeOutpointV1) int {
			return cmp.Or(bytes.Compare(a.Txid[:], b.Txid[:]), cmp.Compare(a.Vout, b.Vout))
		})
		c.entry.step = replayEntryRecovery
		err := use(keys)
		if err == nil {
			c.entry.step = ""
		}
		return err
	})
}

// input148V1 binds the existing spend surface at this height. The two false
// flags are NOT_OBSERVED validation-only Index fields, never commit evidence.
func (c *replayStepCall) input148V1() (initial148CompleteBlockInputV1, error) {
	context := c.owner.state.context
	rotation := bindSpendSurface(context.Rotation, c.h)
	rotation.NativeCreateSuites(c.h)
	rotation.NativeSpendSuites(c.h)
	registry := context.Registry
	if registry == nil {
		registry = DefaultSuiteRegistry()
	}
	input := initial148CompleteBlockInputV1{
		Raw: c.body, Height: c.h, ParentHash: c.parent, ExpectedTarget: c.target,
		ChainID: context.Genesis.ChainID, DatabaseID: c.owner.state.database,
		ParentTimestamps: c.timestamps, AlreadyGenerated: c.owner.state.supply(c.h),
		Generation: c.a.Replay.TargetGenerationID, Parent: c.parentEndpoint,
		Endpoint:               mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: c.h, BlockHash: c.x, CumulativeChainwork: c.work},
		CanonicalBeforePresent: false, OwnerBeforePresent: false,
		CapRegistry: initial148FirstGenesisDefaultsV1.CapRegistry, Registry: registry, Rotation: rotation,
	}
	if c.h == 0 {
		if err := c.publication148V1(); err != nil {
			return initial148CompleteBlockInputV1{}, err
		}
		input.PublishedGenesis, input.FirstGenesisDemand = c.body, initial148FirstGenesisDeriveBytesV1
	}
	return input, nil
}

// publication148V1 qualifies the same reached Raw against both configured
// identities and the current publication shape, without another body backing.
func (c *replayStepCall) publication148V1() error {
	context := c.owner.state.context.Genesis
	if context.Published == nil {
		context.Published = c.body
	}
	if err := replayEntryContext148(context); err != nil {
		return c.unbound()
	}
	if !bytes.Equal(context.Published, c.body) {
		return c.unbound()
	}
	return nil
}

// selectedOnly148V1 permits a qualified local projection only while the raw
// product contains that exact result and the invocation sentinel alone.
func (c *replayStepCall) selectedOnly148V1(selected error) bool {
	for _, part := range genesisMDBXCauses(c.invocation.out.Err) {
		if any(part) != any(selected) && any(part) != any(c.entry.sentinel) {
			return false
		}
	}
	return true
}

// selectedCause148V1 chooses the original selection, falling back to the
// first actual native cause distinct from the invocation sentinel.
func (c *replayStepCall) selectedCause148V1() error {
	if selected := c.invocation.observation.incoming; selected != nil {
		return selected
	}
	for _, part := range genesisMDBXCauses(c.invocation.out.Err) {
		if any(part) != any(c.entry.sentinel) {
			return part
		}
	}
	return nil
}

// diagnostic148V1 keeps selected source identity separate from the raw native
// product, and copies only a diagnostic actually attached to that selection.
func (c *replayStepCall) diagnostic148V1() {
	out, selected := &c.invocation.out, c.selectedCause148V1()
	out.Cause = selected
	out.Height, out.Block = c.invocation.observation.h, c.invocation.observation.x
	if selected != nil && out.Block == ([32]byte{}) {
		out.Height, out.Block = c.h, c.x
	}
	required := c.complete148.required
	if initial148SelectedReadV1(selected, required.cause) {
		out.Cause, out.Observation, out.HasObservation = required.cause, required.observation, required.hasObservation
		return
	}
	if engine, ok := any(selected).(*mdbx.EngineError); ok && engine != nil && engine.TreeObservation != nil {
		out.Observation, out.HasObservation = *engine.TreeObservation, true
	}
}

// local148V1 admits only target-owned original evidence supplied by the native
// owner, or the explicitly qualified source-stage target-local selection.
func (c *replayStepCall) local148V1() bool {
	out := &c.invocation.out
	if !c.selectedOnly148V1(out.Cause) {
		return false
	}
	return c.entry.decision == "target local" || c.requiredLocal148V1() || c.observedLocal148V1()
}

// requiredLocal148V1 recognizes the existing required-scope's selected
// logical representation result, including absent CURRENT counters without
// a native observation. Unmatched native integrity retains its own route.
func (c *replayStepCall) requiredLocal148V1() bool {
	failure, ok := any(c.invocation.out.Cause).(*logicalStateFailure)
	if !ok || failure == nil {
		return false
	}
	return c.h > 0 && c.parentEndpoint.Kind == mdbx.TreeEndpointAppliedV1 && failure.kind == logicalStateFailureStoreIntegrity && any(c.complete148.required.cause) == any(failure)
}

func (c *replayStepCall) observedLocal148V1() bool {
	out := &c.invocation.out
	o := out.Observation
	owned := o.Generation == c.a.Replay.TargetGenerationID || o.Generation == c.tree.TargetLagGenerationID
	return out.HasObservation && owned && o.DatabaseID == c.owner.state.database && o.OriginalImage && o.OriginalReference
}

// project148V1 never clears or replaces the captured Truth/Stage/Index/Err.
// Private replay progress does not establish ordinary canonical publication.
func (c *replayStepCall) project148V1(runErr error) {
	out := &c.invocation.out
	out.CanonicalTruth, out.Decision = "OLD", c.entry.decision
	c.diagnostic148V1()
	if !out.NativeCalled {
		out.Cause, out.Result = runErr, selectedSideInvariant
		return
	}
	if out.Stage == mdbx.UpdateStageCommitMayHaveCrossed {
		out.Result = replayEntryCrossed(ReplayEntryOutcomeV1{Truth: out.Truth, Stage: out.Stage, Err: out.Err}, &c.entry).Result
		return
	}
	call := c.entry
	call.planned = replayTreeSnapshotOnly(out.Err)
	out.Result = replayStepCauses(out.Err, &call)
	if c.entered && c.a.Replay != nil && c.local148V1() {
		out.Result, out.Decision = replayEntryRecovery, "target local"
	}
	if out.Stage == mdbx.UpdateStageWriteStartedDefinitelyPrecommit {
		out.Result = replayEntryPrecommit(out.Result)
	}
	if out.Result == replayEntryRecovery {
		out.Needed = c.needed
	}
}

type replayStepCall struct {
	owner                             *ReplayStepOwnerV1
	invocation                        *replayStepInvocation
	entry                             replayEntryCall
	entered, denied, carrierInvalid   bool
	reader                            *mdbx.Reader
	a                                 mdbx.StorageAuthorityV1
	old                               *mdbx.AuthorityPointV1
	own                               replayPathOwn
	body                              []byte
	stored, headerMismatch            bool
	x, parent, target                 [32]byte
	work                              [40]byte
	timestamps                        []uint64
	context                           *mdbx.CanonicalContextWindowV1
	consulted                         []mdbx.ConsultedRow
	view                              *replayStepView
	h, count                          uint64
	needed                            *ReplayStepNeedV1
	tree                              mdbx.TreeAuthorityV1
	account                           *mdbx.OperationAccount
	validate148                       func(*mdbx.Reader, initial148CompleteBlockInputV1) (*initial148CompleteBlockResultV1, error)
	complete148                       initial148CompleteBlockOutcomeV1
	parentEndpoint                    mdbx.TreeEndpointV1
	parentHeader                      [148]byte
	bodyBound, undoBound, windowCount uint64
}

func (c *replayStepCall) decide(result, decision string) (mdbx.Batch, error) {
	c.entry.result, c.entry.decision = result, decision
	return mdbx.Batch{}, c.entry.sentinel
}

func (c *replayStepCall) plan(r *mdbx.Reader, supplied []byte) (mdbx.Batch, error) {
	c.entered, c.reader = true, r
	a, err := r.ReadStorageAuthorityV1()
	if err != nil {
		return mdbx.Batch{}, err
	}
	c.a = a
	if a.Phase != mdbx.StoragePhaseReplayV1 || !replayPathApplicable(a) {
		return c.decide("", "not applicable")
	}
	if c.denied {
		return c.decide(selectedSideCapacity, "")
	}
	if err := c.sources(supplied); err != nil {
		return mdbx.Batch{}, err
	}
	if err := c.qualify(); err != nil {
		return mdbx.Batch{}, err
	}
	return c.stateBatch()
}

func (c *replayStepCall) sources(supplied []byte) error {
	c.entry.step = selectedSideCanonical
	old, err := c.reader.CanonicalTipV1(uint64(c.a.ActiveGenerationID))
	if err != nil {
		return err
	}
	c.entry.step, c.old = "", old
	limit := blockSteps1To12MaxBytes + c.owner.path.headerBytesV1() - BLOCK_HEADER_BYTES
	if len(supplied) <= limit {
		supplied = bytes.Clone(supplied)
	} else {
		supplied = nil
	}
	own, err := c.owner.path.ownLocked(c.reader, c.a, old, c.owner.state.context.Genesis, supplied)
	c.own, c.entry.step = own, own.resource
	if err != nil {
		if own.missing {
			c.needed = &ReplayStepNeedV1{Kind: ReplayStepNeedHeaderV1, Height: own.missingHeight, Hash: own.missingHash}
		}
		return err
	}
	c.h, c.x = own.h, own.x
	if own.activeEntry != nil {
		key, _ := mdbx.HeightKey(uint64(c.a.ActiveGenerationID), c.h)
		c.consulted = append(c.consulted, mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[2], Key: key})
	}
	if err := c.targetContext(); err != nil {
		return err
	}
	return c.bodySource(supplied)
}

func (c *replayStepCall) bodySource(supplied []byte) error {
	raw, present, err := c.source(mdbx.SchemaV2DBIs()[4], c.x[:], replayEntryRecovery)
	if err != nil {
		return err
	}
	c.body, c.stored = raw, present
	if !present {
		c.body = supplied
	}
	n := c.owner.path.headerBytesV1()
	if len(c.body) < n || !c.owner.path.bindsV1(c.body[:min(len(c.body), n)], c.x) {
		return c.unbound()
	}
	if c.stored && c.own.headerSource == replayPathSupplied {
		c.headerMismatch = !bytes.Equal(c.body[:n], c.own.header)
		// Comparison is the original supplied source's last consumer. Keep its origin, not its backing.
		c.own.header = nil
	}
	return nil
}

func (c *replayStepCall) unbound() error {
	if c.stored {
		return selectedSideDefect("stored replay body does not bind the target")
	}
	c.needed = &ReplayStepNeedV1{Kind: ReplayStepNeedBlockBytesV1, Height: c.h, Hash: c.x}
	return replayRecoveryRefusal(replayEntryRecovery, "replay block bytes unavailable or unbound")
}

func (c *replayStepCall) targetContext() error {
	if c.h == 0 {
		return c.genesisTargetV1()
	}
	count := min(c.h, uint64(11))
	if c.h%WINDOW_SIZE == 0 {
		count = WINDOW_SIZE
	}
	if c.owner.path.initial148 {
		count = c.windowCount
	}
	c.context = &mdbx.CanonicalContextWindowV1{Generation: uint64(c.a.Replay.TargetGenerationID), FirstHeight: c.h - count, Count: uint32(count)}
	c.timestamps = make([]uint64, 0, count)
	var previous []byte
	for h := c.h - count; h < c.h; h++ {
		entry, header, err := c.contextPair(c.context.Generation, h, previous)
		if err != nil {
			return err
		}
		previous = entry
		c.timestamps = append(c.timestamps, header.Timestamp)
		c.target = header.Target
	}
	if err := c.contextTarget(previous); err != nil {
		return err
	}
	c.timestamps = c.timestamps[len(c.timestamps)-int(min(c.h, 11)):]
	return nil
}

func (c *replayStepCall) genesisTargetV1() error {
	if c.owner.path.initial148 {
		header, _ := ParseInitial148HeaderBytes(c.own.header)
		work, err := WorkFromTarget(header.Target)
		if err != nil {
			return selectedSideDefect("replay header work invalid")
		}
		c.target, c.work = header.Target, replayEntryWork(work)
		return nil
	}
	for i := range c.target {
		c.target[i] = 255
	}
	c.work[39] = 1
	return nil
}

func (c *replayStepCall) contextTarget(previous []byte) error {
	c.parent = [32]byte(previous[:32])
	if c.parent != c.a.Replay.Cursor.BlockHash {
		return selectedSideDefect("target context does not reach the replay cursor")
	}
	target, err := ReplayExpectedTargetV1(c.h, c.target, c.timestamps)
	if err != nil {
		return selectedSideDefect("target context target schedule invalid")
	}
	c.target = target
	work, err := WorkFromTarget([32]byte(c.own.header[76:108]))
	if err != nil {
		return selectedSideDefect("replay header work invalid")
	}
	work.Add(work, new(big.Int).SetBytes(previous[64:104]))
	if !replayEntryWorkOK(work) {
		return selectedSideDefect("replay cumulative work invalid")
	}
	c.work = replayEntryWork(work)
	return nil
}

func (c *replayStepCall) contextPair(g, h uint64, previous []byte) ([]byte, BlockHeader, error) {
	entry, err := c.contextEntryV1(g, h)
	if err != nil {
		return nil, BlockHeader{}, err
	}
	raw, present, err := c.source(mdbx.SchemaV2DBIs()[3], entry[:32], replayEntryRecovery)
	if err != nil {
		return nil, BlockHeader{}, err
	}
	if !present || !c.owner.path.bindsV1(raw, [32]byte(entry[:32])) {
		return nil, BlockHeader{}, selectedSideDefect("target context named header absent or misnamed")
	}
	header, _ := (&replayQualifier{wide: c.owner.path.initial148}).parse(raw)
	err = c.contextLink(h, entry, header, previous)
	if err == nil && c.owner.path.initial148 && h == c.h-1 {
		copy(c.parentHeader[:], raw)
		c.parentEndpoint = mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: h, BlockHash: [32]byte(entry[:32]), CumulativeChainwork: [40]byte(entry[64:104])}
	}
	return entry, header, err
}

func (c *replayStepCall) contextEntryV1(g, h uint64) ([]byte, error) {
	key, _ := mdbx.HeightKey(g, h)
	entry, present, err := c.source(mdbx.SchemaV2DBIs()[2], key, replayEntryRecovery)
	if err != nil {
		return nil, err
	}
	if !present || len(entry) != 104 {
		if c.owner.path.initial148 {
			return nil, c.observe("target local", selectedSideDefect("target context entry missing or invalid"), nil)
		}
		return nil, selectedSideDefect("target context entry missing or invalid")
	}
	if !c.owner.path.initial148 && !archiveSelectedSideWork(entry[64:104]) {
		return nil, selectedSideDefect("target context entry missing or invalid")
	}
	return entry, nil
}

func (c *replayStepCall) contextLink(h uint64, entry []byte, header BlockHeader, previous []byte) error {
	work, err := WorkFromTarget(header.Target)
	if err != nil {
		return selectedSideDefect("target context header work invalid")
	}
	bad := header.PrevBlockHash != [32]byte(entry[32:64]) || !archiveSelectedSideWork(entry[64:104])
	if previous != nil {
		work.Add(work, new(big.Int).SetBytes(previous[64:104]))
		switch {
		case bad, header.PrevBlockHash != [32]byte(previous[:32]), work.Cmp(new(big.Int).SetBytes(entry[64:104])) != 0:
			bad = true
		}
	}
	if h == 0 {
		switch {
		case bad, [32]byte(entry[:32]) != c.owner.state.context.Genesis.GenesisHash, work.Cmp(new(big.Int).SetBytes(entry[64:104])) != 0:
			bad = true
		}
	}
	if bad {
		failure := &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("target context parent or work contradiction")}
		return c.observe("target local", failure, failure)
	}
	return nil
}

func (c *replayStepCall) qualify() error {
	if c.h == 0 {
		if err := ValidateBlockBodyCommitments(c.body); err != nil {
			return c.unbound()
		}
		return nil
	}
	summary, err := ValidateBlockSteps1To12(c.body, c.parent, c.target, c.h, c.timestamps)
	switch any(err) {
	case ErrBlockSteps1To12Capacity, ErrBlockSteps1To12Context:
		return replayRecoveryRefusal(selectedSideInvariant, "replay qualification context or capacity invariant")
	}
	if binding := ValidateBlockBodyCommitments(c.body); binding != nil {
		return c.unbound()
	}
	if err != nil {
		return c.consensus(err)
	}
	c.count = summary.TxCount
	return nil
}

func (c *replayStepCall) consensus(err error) error {
	e, ok := any(err).(*TxError)
	if !ok || e == nil {
		return err
	}
	return c.observe("consensus invalid", err, nil)
}

func (c *replayStepCall) observe(decision string, incoming error, failure *logicalStateFailure) error {
	o := replayStepObservation{decision: decision, h: c.h, x: c.x, incoming: incoming, failure: failure}
	if failure != nil {
		o.cause = failure.cause
	}
	c.invocation.observation = o
	c.entry.result, c.entry.decision = "", decision
	return c.entry.sentinel
}

func (s *replayStepState) supply(h uint64) Uint128 {
	if !s.memo || s.height > h {
		s.height, s.generated, s.memo = 0, Uint128{}, true
	}
	ag := s.generated.Big()
	for s.height < h {
		ag.Add(ag, new(big.Int).SetUint64(BlockSubsidyBig(s.height, ag)))
		s.height++
	}
	s.generated = uint128FromBigInt(ag)
	return s.generated
}

func (c *replayStepCall) stateBatch() (mdbx.Batch, error) {
	c.view = &replayStepView{base: newLogicalMDBXStateView(c.reader, uint64(c.a.Replay.TargetGenerationID), c.h)}
	c.owner.state.supply(c.h)
	result, err := c.connect()
	if err != nil {
		return mdbx.Batch{}, err
	}
	if result.spentInputs != nil {
		defer result.spentInputs.discard()
	}
	c.entry.step = replayEntryRecovery
	touched := replayStepTouched(result)
	result.createdUtxos = nil
	c.view.epoch, c.view.witness = true, false
	plan, failure := buildLogicalStatePlan(c.h, c.view, touched, newLogicalMDBXMetadata(c.view.base, nil))
	if failure != nil {
		return mdbx.Batch{}, c.logicalFailureWithOuter(failure, failure)
	}
	if err := checkLogicalStateCapAndGrowth(plan.Parent.bytes, plan.Result.bytes, false); err != nil {
		return mdbx.Batch{}, c.consensus(err)
	}
	batch, failure := logicalMDBXPlanToBatch(plan)
	if failure != nil {
		return mdbx.Batch{}, c.logicalFailureWithOuter(failure, failure)
	}
	return c.completeBatch(batch, result)
}

func (c *replayStepCall) connect() (*connectBlockInputViewResult, error) {
	if c.h == 0 {
		return c.genesis()
	}
	c.entry.step = "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)"
	context := c.owner.state.context
	input := connectBlockBasicInMemorySuiteContext{BlockBytes: c.body, ExpectedPrevHash: &c.parent, ExpectedTarget: &c.target, BlockHeight: c.h, PrevTimestamps: c.timestamps, ChainID: context.Genesis.ChainID, Rotation: context.Rotation, Registry: context.Registry}
	result, err := connectBlockBasicWithInputView(input, c.view, c.owner.state.generated)
	if err == nil {
		return result, nil
	}
	if carrier, ok := any(err).(*blockInputViewReadError); ok {
		if !c.carrierMatches(carrier) {
			c.carrierInvalid = true
			return nil, err
		}
		return nil, c.logicalFailureWithOuter(carrier.failure, carrier)
	}
	return nil, c.consensus(err)
}

func (c *replayStepCall) genesis() (*connectBlockInputViewResult, error) {
	var out GenesisMDBXOutcome
	parsed, err := genesisMDBXValidate(c.body, c.owner.state.context.Genesis.ChainID, &out)
	if err != nil {
		return nil, c.consensus(err)
	}
	c.count = uint64(len(parsed.Txs))
	c.entry.step = replayEntryRecovery
	prefix := binary.BigEndian.AppendUint64(nil, uint64(c.a.Replay.TargetGenerationID))
	if err := genesisMDBXEmptyUTXO(c.reader, prefix); err != nil {
		return nil, err
	}
	if err := genesisMDBXZeroCounter(c.view.Counters()); err != nil {
		return nil, err
	}
	return &connectBlockInputViewResult{createdUtxos: out.State.Utxos}, nil
}

func replayStepTouched(result *connectBlockInputViewResult) []logicalTouchedState {
	n := len(result.createdUtxos)
	if result.spentInputs != nil {
		n += len(result.spentInputs.spent)
	}
	touched := make([]logicalTouchedState, 0, n)
	for op, entry := range result.createdUtxos {
		touched = append(touched, logicalTouchedState{Outpoint: op, FinalPresent: true, Final: entry})
	}
	if result.spentInputs != nil {
		for op, length := range result.spentInputs.spent {
			if length != 0 {
				touched = append(touched, logicalTouchedState{Outpoint: op})
			}
		}
	}
	return touched
}

type replayStepView struct {
	base           *logicalMDBXStateView
	epoch, witness bool
	parent         logicalStatePlanWork
	failedOp       Outpoint
	failedKind     logicalStateRowReadKind
	failedCause    error
}

func (v *replayStepView) Counters() logicalStateCounterRead {
	read := v.base.Counters()
	if v.epoch && read.kind == logicalStateCountersPresent {
		v.witness = logicalStateCountersMalformed(read, v.base.height, true)
		v.parent = logicalStatePlanWork{parent: read.counters}
	}
	if v.epoch && read.kind == logicalStateCountersStoreIntegrity {
		v.witness = any(read.cause) == any(errLogicalMDBXAbsentCounter)
	}
	return read
}

func (v *replayStepView) Lookup(op Outpoint) logicalStateRowRead {
	read := v.base.Lookup(op)
	v.failedOp, v.failedKind, v.failedCause = op, read.kind, read.cause
	if v.epoch && read.kind == logicalStateRowPresent {
		length := logicalStateEntryLength(read.entry)
		v.witness = logicalStateParentFailure(&v.parent, length, true) != nil
		if !v.witness {
			v.parent.oldCount++
			v.parent.oldBytes += length
		}
	}
	if read.kind == logicalStateRowStoreIntegrity {
		_, observed := v.base.rows[op]
		v.witness = !observed && read.cause != nil && replayStepPositiveCause(read.cause)
	}
	return read
}

func replayStepPositiveCause(cause error) bool {
	_, native := any(cause).(*mdbx.EngineError)
	return !native && !genesisMDBXNilError(cause)
}

func replayStepCarrierShape(e *blockInputViewReadError) bool {
	switch {
	case e == nil, e.failure == nil:
		return false
	case e.failure.cause == nil, genesisMDBXNilError(e.failure.cause), e.txIndex < 1, e.inputIndex < 0, e.inputIndex >= 1024, e.failure.kind < logicalStateFailureUnavailable, e.failure.kind > logicalStateFailureLocalInvariant:
		return false
	}
	return true
}

func (c *replayStepCall) carrierMatches(e *blockInputViewReadError) bool {
	if !replayStepCarrierShape(e) {
		return false
	}
	if e.txIndex < 0 {
		return false
	}
	return uint64(e.txIndex) < c.count && e.outpoint == c.view.failedOp && any(e.failure.cause) == any(c.view.failedCause) && c.view.failedKind == logicalStateRowReadKind(e.failure.kind)+logicalStateRowUnavailable-1
}

func (c *replayStepCall) logicalFailureWithOuter(failure *logicalStateFailure, outer error) error {
	targetLocal := failure != nil && failure.kind == logicalStateFailureStoreIntegrity && failure.cause != nil && c.a.Replay.Cursor.Kind == mdbx.ReplayCursorAppliedV1 && c.view.witness && replayStepPositiveCause(failure.cause)
	if targetLocal {
		return c.observe("target local", outer, failure)
	}
	return outer
}

func (c *replayStepCall) completeBatch(batch mdbx.Batch, result *connectBlockInputViewResult) (mdbx.Batch, error) {
	undo, err := canonicalUndoFamilyV1(uint64(c.a.Replay.TargetGenerationID), c.h, c.count, &c.x, &c.owner.state.generated, batch.Mutations, c.view.base.rows, result.spentInputs)
	// The shared owner terminally discarded the original compact source before returning.
	result.spentInputs = nil
	if err != nil {
		return mdbx.Batch{}, err
	}
	extras, err := c.artifacts(undo)
	if err != nil {
		return mdbx.Batch{}, err
	}
	extras, err = c.indexExtras(extras)
	if err != nil {
		return mdbx.Batch{}, err
	}
	mutations, failure := replayStepCompose(batch.Mutations, extras, c.view.base)
	if failure != nil {
		return mdbx.Batch{}, failure
	}
	batch.Mutations, batch.ContextConsulted = mutations, c.context
	batch.LargeConsulted = []mdbx.LargeImageSelectorV1{{Kind: mdbx.LargeImageBlockBodyV1, Hash: c.x}, {Kind: mdbx.LargeImageUndoFamilyV1, Hash: c.x}}
	batch.Consulted, err = c.remainder(batch.Mutations)
	c.view, c.body, c.own, c.old, c.timestamps = nil, nil, replayPathOwn{}, nil, nil
	if err != nil {
		return mdbx.Batch{}, err
	}
	c.entry.step, c.entry.planned = "", true
	return batch, nil
}

func (c *replayStepCall) artifacts(undo []mdbx.Mutation) ([]mdbx.Mutation, error) {
	extras := c.headerExtra()
	b, u := replayStepPromises(c.a.Replay)
	if c.headerMismatch {
		return nil, selectedSideDefect("replay body and header differ")
	}
	c.entry.step = replayEntryRecovery
	undoOld, err := canonicalUndoFamilyEqualV1(c.reader, &c.x, undo)
	if err != nil {
		return nil, err
	}
	c.entry.step = ""
	deleteOld := false
	switch {
	case c.stored && c.h < b, undoOld && c.h < u:
		deleteOld, err = c.oldActive()
		if err != nil {
			return nil, err
		}
	}
	extras, err = c.bodyEffects(extras, b, deleteOld)
	if err != nil {
		return nil, err
	}
	return replayStepUndoEffects(extras, undo, undoOld, c.h < u, deleteOld), nil
}

func replayStepUndoEffects(extras, undo []mdbx.Mutation, present, below, deleteOld bool) []mdbx.Mutation {
	switch {
	case !present && !below:
		return append(extras, undo...)
	case present && below && deleteOld:
		for _, row := range undo {
			extras = append(extras, mdbx.Mutation{DBI: row.DBI, Key: row.Key, BeforePresent: true, AfterKind: mdbx.AfterAbsent})
		}
	}
	return extras
}

func (c *replayStepCall) headerExtra() []mdbx.Mutation {
	dbis := mdbx.SchemaV2DBIs()
	if c.own.headerSource == replayPathStored {
		c.consulted = append(c.consulted, mdbx.ConsultedRow{DBI: dbis[3], Key: c.x[:]})
		return nil
	}
	header := c.own.header
	if c.stored && c.own.headerSource == replayPathSupplied {
		header = c.body[:c.owner.path.headerBytesV1()]
	}
	return []mdbx.Mutation{{DBI: dbis[3], Key: c.x[:], AfterKind: mdbx.AfterLiteral, Literal: header}}
}

func (c *replayStepCall) bodyEffects(extras []mdbx.Mutation, b uint64, deleteOld bool) ([]mdbx.Mutation, error) {
	dbis := mdbx.SchemaV2DBIs()
	if !c.stored && c.h >= b {
		literal, err := mdbx.HashBoundValue(c.x, c.body, true)
		if err != nil {
			return nil, err
		}
		extras = append(extras, mdbx.Mutation{DBI: dbis[4], Key: c.x[:], AfterKind: mdbx.AfterLiteral, Literal: literal})
		if c.own.headerSource == replayPathSupplied {
			// SAME admitted header bytes were consumed above; header and body now share the one final literal.
			extras[0].Literal = literal[:116:116]
			c.own.header = nil
		}
	}
	if c.stored && c.h < b && deleteOld {
		extras = append(extras, mdbx.Mutation{DBI: dbis[4], Key: c.x[:], BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	}
	return extras, nil
}

func replayStepPromises(rp *mdbx.ReplayV1) (uint64, uint64) {
	tip, b, u := rp.Target.TipHeight, uint64(0), uint64(0)
	if rp.TargetProfile == mdbx.StorageProfilePrunedV1 && tip >= 15120 {
		b = tip - 15119
	}
	if tip >= 1440 {
		u = tip - 1439
	}
	return b, u
}

func (c *replayStepCall) indexExtras(extras []mdbx.Mutation) ([]mdbx.Mutation, error) {
	dbis, g := mdbx.SchemaV2DBIs(), uint64(c.a.Replay.TargetGenerationID)
	key, _ := mdbx.HeightKey(g, c.h)
	entry := mdbx.ChainValue(c.x, c.parent, c.work)
	old, present, err := c.read(dbis[2], key, replayEntryRecovery)
	if err != nil {
		return nil, err
	}
	if present && !bytes.Equal(old, entry) {
		return nil, selectedSideDefect("replay target staging entry differs")
	}
	owner, _ := mdbx.CanonicalOwnerKey(g, c.x)
	oldOwner, ownerPresent, err := c.read(dbis[7], owner, replayEntryRecovery)
	if err != nil {
		return nil, err
	}
	if ownerPresent && !bytes.Equal(oldOwner, mdbx.CanonicalOwnerValue(c.h)) {
		return nil, selectedSideDefect("replay target staging owner differs")
	}
	extras = append(extras, mdbx.Mutation{DBI: dbis[2], Key: key, BeforePresent: present, AfterKind: mdbx.AfterLiteral, Literal: entry}, mdbx.Mutation{DBI: dbis[7], Key: owner, BeforePresent: ownerPresent, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(c.h)})
	c.a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: c.h, BlockHash: c.x}
	value, err := c.a.Encode()
	if err != nil {
		return nil, err
	}
	return append(extras, mdbx.Mutation{DBI: dbis[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: value}), nil
}

func (c *replayStepCall) source(dbi mdbx.DBI, key []byte, step string) ([]byte, bool, error) {
	c.entry.step = step
	value, present, err := c.reader.Get(dbi, key)
	if err == nil {
		c.entry.step = ""
	}
	return value, present, err
}

func (c *replayStepCall) read(dbi mdbx.DBI, key []byte, step string) ([]byte, bool, error) {
	value, present, err := c.source(dbi, key, step)
	if err == nil {
		c.consulted = append(c.consulted, mdbx.ConsultedRow{DBI: dbi, Key: key})
	}
	return value, present, err
}

func (c *replayStepCall) oldActive() (bool, error) {
	if c.old == nil || c.h > c.old.Height {
		return true, nil
	}
	c.entry.step = selectedSideCanonical
	g := uint64(c.a.ActiveGenerationID)
	owner, err := c.reader.CanonicalOwnerV1(g, c.x)
	if err != nil {
		return false, err
	}
	c.consulted = append(c.consulted, owner.Rows...)
	entry := owner.Entry
	switch {
	case !owner.Owned, owner.Height != c.h:
		key, _ := mdbx.HeightKey(g, c.h)
		if c.own.activeEntry != nil {
			entry = c.own.activeEntry
		} else {
			entry, _, err = c.read(mdbx.SchemaV2DBIs()[2], key, selectedSideCanonical)
			if err != nil {
				return false, err
			}
		}
	}
	if err := c.oldActiveHealth(g, entry); err != nil {
		return false, err
	}
	c.entry.step = ""
	return [32]byte(entry[:32]) != c.x, nil
}

func (c *replayStepCall) oldActiveHealth(g uint64, entry []byte) error {
	if len(entry) != 104 || !archiveSelectedSideWork(entry[64:104]) {
		return selectedSideDefect("old active entry absent or invalid")
	}
	raw, err := c.oldActiveHeader(entry)
	if err != nil {
		return err
	}
	work, err := WorkFromTarget([32]byte(raw[76:108]))
	if err != nil {
		return selectedSideDefect("old active header work invalid")
	}
	if c.h == 0 {
		if [32]byte(entry[:32]) != c.owner.state.context.Genesis.GenesisHash || work.Cmp(new(big.Int).SetBytes(entry[64:104])) != 0 {
			return selectedSideDefect("old active genesis inconsistent")
		}
		return nil
	}
	return c.oldActiveWork(g, entry, work)
}

func (c *replayStepCall) oldActiveHeader(entry []byte) ([]byte, error) {
	x := [32]byte(entry[:32])
	raw := c.own.header
	if x != c.x || c.own.headerSource != replayPathStored {
		var err error
		raw, _, err = c.read(mdbx.SchemaV2DBIs()[3], entry[:32], selectedSideCanonical)
		if err != nil {
			return nil, err
		}
	}
	if !c.owner.path.bindsV1(raw, x) || [32]byte(raw[4:36]) != [32]byte(entry[32:64]) {
		return nil, selectedSideDefect("old active header absent or inconsistent")
	}
	return raw, nil
}

func (c *replayStepCall) oldActiveWork(g uint64, entry []byte, work *big.Int) error {
	key, _ := mdbx.HeightKey(g, c.h-1)
	previous, _, err := c.read(mdbx.SchemaV2DBIs()[2], key, selectedSideCanonical)
	if err != nil {
		return err
	}
	if len(previous) != 104 || !archiveSelectedSideWork(previous[64:104]) || [32]byte(previous[:32]) != [32]byte(entry[32:64]) {
		return selectedSideDefect("old active predecessor inconsistent")
	}
	work.Add(work, new(big.Int).SetBytes(previous[64:104]))
	if work.Cmp(new(big.Int).SetBytes(entry[64:104])) != 0 {
		return selectedSideDefect("old active cumulative work inconsistent")
	}
	return nil
}

func replayStepCompose(logical, extras []mdbx.Mutation, view *logicalMDBXStateView) ([]mdbx.Mutation, *logicalStateFailure) {
	for _, extra := range extras {
		if failure := logicalMDBXExtraPolicy(extra, view, logical); failure != nil {
			return nil, failure
		}
	}
	mutations := append(logical, extras...)
	sort.Slice(mutations, func(i, j int) bool { return logicalMDBXBefore(mutations[i], mutations[j]) })
	for i := 1; i < len(mutations); i++ {
		if !logicalMDBXBefore(mutations[i-1], mutations[i]) {
			return nil, localLogicalStateFailure("duplicate replay mutation target")
		}
	}
	return mutations, nil
}

func replayStepTarget(rows []mdbx.Mutation, dbi mdbx.DBI, key []byte) int {
	i := sort.Search(len(rows), func(i int) bool { return !logicalMDBXBefore(rows[i], mdbx.Mutation{DBI: dbi, Key: key}) })
	if i < len(rows) && rows[i].DBI == dbi && bytes.Equal(rows[i].Key, key) {
		return i
	}
	return -1
}

func (c *replayStepCall) remainder(mutations []mdbx.Mutation) ([]mdbx.ConsultedRow, error) {
	count, knownBytes, err := c.stateRemainder(mutations)
	if err != nil {
		return nil, err
	}
	finite := c.finiteRemainder(mutations)
	total, carry := bits.Add64(count, uint64(len(finite)), 0)
	if carry != 0 || total > 16384 || knownBytes > mdbx.MaxOperationDataBytes {
		return nil, replayRecoveryRefusal(selectedSideCapacity, "replay consulted remainder exceeds bound")
	}
	rows := make([]mdbx.ConsultedRow, len(finite), int(total))
	copy(rows, finite)
	for op := range c.view.base.rows {
		key, _ := mdbx.UTXOKey(c.view.base.imageID, op.Txid, op.Vout)
		if replayStepTarget(mutations, mdbx.SchemaV2DBIs()[1], key) < 0 {
			rows = append(rows, mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[1], Key: key})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return logicalMDBXBefore(mdbx.Mutation{DBI: rows[i].DBI, Key: rows[i].Key}, mdbx.Mutation{DBI: rows[j].DBI, Key: rows[j].Key})
	})
	return rows, nil
}

func (c *replayStepCall) stateRemainder(mutations []mdbx.Mutation) (uint64, uint64, error) {
	var count, knownBytes uint64
	var scratch [44]byte
	binary.BigEndian.PutUint64(scratch[:8], c.view.base.imageID)
	for op, row := range c.view.base.rows {
		copy(scratch[8:40], op.Txid[:])
		binary.BigEndian.PutUint32(scratch[40:], op.Vout)
		key := scratch[:]
		if replayStepTarget(mutations, mdbx.SchemaV2DBIs()[1], key) < 0 {
			var carry uint64
			count, carry = bits.Add64(count, 1, 0)
			if carry != 0 {
				return 0, 0, localLogicalStateFailure("replay remainder count overflow")
			}
			if row.present {
				if row.entryBytes < 36 {
					return 0, 0, localLogicalStateFailure("replay remainder row length invalid")
				}
				knownBytes, carry = bits.Add64(knownBytes, row.entryBytes-36, 0)
				if carry != 0 {
					return 0, 0, localLogicalStateFailure("replay remainder bytes overflow")
				}
			}
		}
	}
	return count, knownBytes, nil
}

func (c *replayStepCall) finiteRemainder(mutations []mdbx.Mutation) []mdbx.ConsultedRow {
	sort.Slice(c.consulted, func(i, j int) bool {
		return logicalMDBXBefore(mdbx.Mutation{DBI: c.consulted[i].DBI, Key: c.consulted[i].Key}, mdbx.Mutation{DBI: c.consulted[j].DBI, Key: c.consulted[j].Key})
	})
	finite := c.consulted[:0]
	for _, row := range c.consulted {
		if replayStepTarget(mutations, row.DBI, row.Key) < 0 && (len(finite) == 0 || finite[len(finite)-1].DBI != row.DBI || !bytes.Equal(finite[len(finite)-1].Key, row.Key)) {
			finite = append(finite, row)
		}
	}
	return finite
}

func (c *replayStepCall) project() {
	out := &c.invocation.out
	out.CanonicalTruth = "OLD"
	if !c.entered {
		out.Result = replayStepCauses(out.Err, &replayEntryCall{})
		return
	}
	if out.Stage == mdbx.UpdateStageCommitMayHaveCrossed {
		entry := replayEntryCrossed(ReplayEntryOutcomeV1{Truth: out.Truth, Stage: out.Stage, Err: out.Err}, &c.entry)
		out.CanonicalTruth, out.Result = entry.CanonicalTruth, entry.Result
	} else {
		switch {
		case out.Truth != mdbx.CommitTruthOld, out.Stage != mdbx.UpdateStagePrewrite, any(out.Err) != any(c.entry.sentinel):
			out.Result = replayStepCauses(out.Err, &c.entry)
			if c.carrierInvalid {
				out.Result = selectedSideInvariant
			}
			if out.Stage == mdbx.UpdateStageWriteStartedDefinitelyPrecommit {
				out.Result = replayEntryPrecommit(out.Result)
			}
		default:
			out.Result, out.Decision, out.Err = c.entry.result, c.entry.decision, nil
		}
	}
	if out.Result == replayEntryRecovery {
		out.Needed = c.needed
	}
}

func replayStepCauses(err error, call *replayEntryCall) string {
	result := ""
	for _, part := range genesisMDBXCauses(err) {
		next := replayStepPart(part, call)
		if next == selectedSideIntegrity || next == selectedSideInvariant {
			return next
		}
		if result == "" {
			result = next
		}
	}
	return result
}

func replayStepPart(part error, call *replayEntryCall) string {
	if mdbx.IsOperationReservationCapacity(part) {
		return selectedSideCapacity
	}
	switch e := any(part).(type) {
	case *selectedSideFailure, *mdbx.EngineError:
		return replayEntryPart(part, call)
	case *blockInputViewReadError:
		if !replayStepCarrierShape(e) {
			return selectedSideInvariant
		}
		return replayStepLogicalPart(e.failure, "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)")
	case *logicalStateFailure:
		return replayStepLogicalPart(e, call.step)
	case interface{ Unwrap() error }:
		return replayStepCauses(e.Unwrap(), call)
	}
	return replayEntryPart(part, call)
}

func replayStepLogicalPart(failure *logicalStateFailure, step string) string {
	if failure == nil || failure.cause == nil || genesisMDBXNilError(failure.cause) {
		return selectedSideInvariant
	}
	if failure.kind == logicalStateFailureUnavailable {
		return replayEntryCauses(failure.cause, &replayEntryCall{step: step})
	}
	return genesisMDBXLogicalResult(failure, step)
}
