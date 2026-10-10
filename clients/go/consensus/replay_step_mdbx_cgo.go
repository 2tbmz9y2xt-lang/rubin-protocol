//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"math/bits"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// ReplayStepContextV1 is the immutable historical consensus context of a dormant replay owner.
type ReplayStepContextV1 struct {
	Genesis PublishedGenesisContextV1
	Rotation RotationProvider
	Registry *SuiteRegistry
}

// ReplayStepOwnerV1 shares one PATH owner and mathematical supply memo across handle copies.
type ReplayStepOwnerV1 struct {
	path *replayPathOwner
	state *replayStepState
}

type replayStepState struct {
	context ReplayStepContextV1
	preflight error
	height uint64
	generated Uint128
	memo bool
}

type ReplayStepNeedKindV1 uint8

const (
	ReplayStepNeedHeaderV1 ReplayStepNeedKindV1 = 1
	ReplayStepNeedBlockBytesV1 ReplayStepNeedKindV1 = 2
)

type ReplayStepNeedV1 struct {
	Kind ReplayStepNeedKindV1
	Height uint64
	Hash [32]byte
}

// ReplayStepOutcomeV1 exposes the native tuple and this invocation's logical result; it publishes no state.
type ReplayStepOutcomeV1 struct {
	Result, Decision, CanonicalTruth string
	Truth mdbx.CommitTruth
	Stage mdbx.UpdateStage
	Err error
	Needed *ReplayStepNeedV1
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

func (o *ReplayStepOwnerV1) DiscardV1() bool {
	return o != nil && o.path != nil && o.path.discard()
}

func (o *ReplayStepOwnerV1) StepReplayMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, supplied []byte) ReplayStepOutcomeV1 {
	return replayStepRun(o, store, reservations, supplied).out
}

type replayStepObservation struct {
	decision string
	h uint64
	x [32]byte
	incoming error
	failure *logicalStateFailure
	cause error
}

// Only finalized scalars and original error references survive the native operation.
type replayStepInvocation struct {
	out ReplayStepOutcomeV1
	observation replayStepObservation
}

func replayStepRun(o *ReplayStepOwnerV1, store *mdbx.Store, reservations *mdbx.OperationReservationOwner, supplied []byte) *replayStepInvocation {
	i := &replayStepInvocation{out: ReplayStepOutcomeV1{CanonicalTruth: "OLD", Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite}}
	if o == nil || o.path == nil || o.state == nil {
		i.out.Result, i.out.Err = selectedSideInvariant, errors.New("invalid replay step owner")
		return i
	}
	o.path.mu.Lock()
	defer o.path.mu.Unlock()
	defer o.path.finishLocked()
	if o.state.preflight != nil {
		i.out.Result, i.out.Err = selectedSideInvariant, o.state.preflight
		return i
	}
	if store == nil {
		i.out.Truth, i.out.Stage, i.out.Err = store.Update(nil)
		i.out.CanonicalTruth = ""
		return i
	}
	c := &replayStepCall{owner: o, invocation: i, sentinel: errors.New("replay step decision")}
	c.entry.sentinel = c.sentinel
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

type replayStepCall struct {
	owner *ReplayStepOwnerV1
	invocation *replayStepInvocation
	sentinel error
	entry replayEntryCall
	entered, denied bool
	carrierInvalid bool
	reader *mdbx.Reader
	a mdbx.StorageAuthorityV1
	old *mdbx.AuthorityPointV1
	own replayPathOwn
	body []byte
	stored bool
	headerMismatch bool
	h uint64
	x, parent, target [32]byte
	work [40]byte
	timestamps []uint64
	context *mdbx.CanonicalContextWindowV1
	consulted []mdbx.ConsultedRow
	view *replayStepView
	count uint64
	generated Uint128
	needed *ReplayStepNeedV1
}

func (c *replayStepCall) decide(result, decision string) (mdbx.Batch, error) {
	c.entry.result, c.entry.decision = result, decision
	return mdbx.Batch{}, c.sentinel
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
	supplied = nil
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
	if len(supplied) <= blockSteps1To12MaxBytes {
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
	c.entry.step = replayEntryRecovery
	raw, present, err := c.reader.Get(mdbx.SchemaV2DBIs()[4], c.x[:])
	if err != nil {
		return err
	}
	c.entry.step = ""
	c.body, c.stored = raw, present
	if !present {
		c.body = supplied
	}
	if len(c.body) < BLOCK_HEADER_BYTES || !replayPathBinds(c.body[:min(len(c.body), BLOCK_HEADER_BYTES)], c.x) {
		return c.unbound()
	}
	if c.stored && c.own.headerSource == replayPathSupplied {
		c.headerMismatch = !bytes.Equal(c.body[:116], c.own.header)
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
		for i := range c.target {
			c.target[i] = 255
		}
		c.work[39] = 1
		return nil
	}
	count := min(c.h, uint64(11))
	if c.h%WINDOW_SIZE == 0 {
		count = WINDOW_SIZE
	}
	g := uint64(c.a.Replay.TargetGenerationID)
	c.context = &mdbx.CanonicalContextWindowV1{Generation: g, FirstHeight: c.h-count, Count: uint32(count)}
	c.timestamps = make([]uint64, 0, count)
	var previous []byte
	for h := c.h-count; h < c.h; h++ {
		entry, header, err := c.contextPair(g, h, previous)
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
	key, _ := mdbx.HeightKey(g, h)
	c.entry.step = replayEntryRecovery
	entry, present, err := c.reader.Get(mdbx.SchemaV2DBIs()[2], key)
	if err != nil {
		return nil, BlockHeader{}, err
	}
	c.entry.step = ""
	if !present || len(entry) != 104 || !archiveSelectedSideWork(entry[64:104]) {
		return nil, BlockHeader{}, selectedSideDefect("target context entry missing or invalid")
	}
	c.entry.step = replayEntryRecovery
	raw, present, err := c.reader.Get(mdbx.SchemaV2DBIs()[3], entry[:32])
	if err != nil {
		return nil, BlockHeader{}, err
	}
	c.entry.step = ""
	if !present || !replayPathBinds(raw, [32]byte(entry[:32])) {
		return nil, BlockHeader{}, selectedSideDefect("target context named header absent or misnamed")
	}
	header, _ := ParseBlockHeaderBytes(raw)
	if err := c.contextLink(h, entry, header, previous); err != nil {
		return nil, BlockHeader{}, err
	}
	return entry, header, nil
}

func (c *replayStepCall) contextLink(h uint64, entry []byte, header BlockHeader, previous []byte) error {
	work, err := WorkFromTarget(header.Target)
	if err != nil {
		return selectedSideDefect("target context header work invalid")
	}
	bad := header.PrevBlockHash != [32]byte(entry[32:64])
	if previous != nil {
		bad = bad || header.PrevBlockHash != [32]byte(previous[:32])
		work.Add(work, new(big.Int).SetBytes(previous[64:104]))
		bad = bad || work.Cmp(new(big.Int).SetBytes(entry[64:104])) != 0
	}
	if h == 0 {
		bad = bad || [32]byte(entry[:32]) != c.owner.state.context.Genesis.GenesisHash || work.Cmp(new(big.Int).SetBytes(entry[64:104])) != 0
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
	if err == nil {
		c.count = summary.TxCount
		return nil
	}
	if err == ErrBlockSteps1To12Capacity || err == ErrBlockSteps1To12Context {
		return replayRecoveryRefusal(selectedSideInvariant, "replay qualification context or capacity invariant")
	}
	if binding := ValidateBlockBodyCommitments(c.body); binding != nil {
		return c.unbound()
	}
	return c.consensus(err)
}

func (c *replayStepCall) consensus(err error) error {
	e, ok := err.(*TxError)
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
	_, err := c.decide("", decision)
	return err
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
	c.generated = c.owner.state.supply(c.h)
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
	touched = nil
	if failure != nil {
		return mdbx.Batch{}, c.logicalFailureWithOuter(failure, failure)
	}
	batch, failure := logicalMDBXPlanToBatch(plan)
	plan = logicalStatePlan[logicalMDBXMetadata]{}
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
	result, err := connectBlockBasicWithInputView(input, c.view, c.generated)
	if err == nil {
		return result, nil
	}
	if carrier, ok := err.(*blockInputViewReadError); ok {
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
	base *logicalMDBXStateView
	epoch, witness bool
	parent logicalStatePlanWork
	failedOp Outpoint
	failedKind logicalStateRowReadKind
	failedCause error
}

func (v *replayStepView) Counters() logicalStateCounterRead {
	read := v.base.Counters()
	if v.epoch && read.kind == logicalStateCountersPresent {
		v.witness = logicalStateCountersMalformed(read, v.base.height, true)
		v.parent = logicalStatePlanWork{parent: read.counters}
	}
	if v.epoch && read.kind == logicalStateCountersStoreIntegrity {
		v.witness = read.cause == errLogicalMDBXAbsentCounter
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
	_, native := cause.(*mdbx.EngineError)
	return !native && !genesisMDBXNilError(cause)
}

func replayStepCarrierShape(e *blockInputViewReadError) bool {
	if e == nil || e.failure == nil {
		return false
	}
	return e.failure.cause != nil && !genesisMDBXNilError(e.failure.cause) && e.txIndex >= 1 && e.inputIndex >= 0 && e.inputIndex < 1024 && e.failure.kind >= logicalStateFailureUnavailable && e.failure.kind <= logicalStateFailureLocalInvariant
}

func (c *replayStepCall) carrierMatches(e *blockInputViewReadError) bool {
	if !replayStepCarrierShape(e) || uint64(e.txIndex) >= c.count {
		return false
	}
	v := c.view
	return e.outpoint == v.failedOp && e.failure.cause == v.failedCause && v.failedKind == logicalStateRowReadKind(e.failure.kind)+logicalStateRowUnavailable-1
}

func (c *replayStepCall) logicalFailureWithOuter(failure *logicalStateFailure, outer error) error {
	if failure == nil || failure.kind != logicalStateFailureStoreIntegrity || failure.cause == nil {
		return outer
	}
	if c.a.Replay.Cursor.Kind == mdbx.ReplayCursorAppliedV1 && c.view.witness && replayStepPositiveCause(failure.cause) {
		return c.observe("target local", outer, failure)
	}
	return outer
}

func (c *replayStepCall) completeBatch(batch mdbx.Batch, result *connectBlockInputViewResult) (mdbx.Batch, error) {
	undo, err := canonicalUndoFamilyV1(uint64(c.a.Replay.TargetGenerationID), c.h, c.count, &c.x, &c.generated, batch.Mutations, c.view.base.rows, result.spentInputs)
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
	bodyOld := c.stored
	c.entry.step = replayEntryRecovery
	undoOld, err := canonicalUndoFamilyEqualV1(c.reader, &c.x, undo)
	if err != nil {
		return nil, err
	}
	c.entry.step = ""
	deleteOld := false
	if bodyOld && c.h < b || undoOld && c.h < u {
		deleteOld, err = c.oldActive()
		if err != nil {
			return nil, err
		}
	}
	extras, err = c.bodyEffects(extras, b, deleteOld)
	if err != nil {
		return nil, err
	}
	if !undoOld && c.h >= u {
		extras = append(extras, undo...)
	}
	if undoOld && c.h < u && deleteOld {
		for _, row := range undo {
			extras = append(extras, mdbx.Mutation{DBI: row.DBI, Key: row.Key, BeforePresent: true, AfterKind: mdbx.AfterAbsent})
		}
	}
	return extras, nil
}

func (c *replayStepCall) headerExtra() []mdbx.Mutation {
	dbis := mdbx.SchemaV2DBIs()
	if c.own.headerSource == replayPathStored {
		c.consulted = append(c.consulted, mdbx.ConsultedRow{DBI: dbis[3], Key: c.x[:]})
		return nil
	}
	header := c.own.header
	if c.stored && c.own.headerSource == replayPathSupplied {
		header = c.body[:116]
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
	tip := rp.Target.TipHeight
	var b, u uint64
	if rp.TargetProfile == mdbx.StorageProfilePrunedV1 && tip >= 15120 {
		b = tip-15119
	}
	if tip >= 1440 {
		u = tip-1439
	}
	return b, u
}

func (c *replayStepCall) indexExtras(extras []mdbx.Mutation) ([]mdbx.Mutation, error) {
	dbis, g := mdbx.SchemaV2DBIs(), uint64(c.a.Replay.TargetGenerationID)
	key, _ := mdbx.HeightKey(g, c.h)
	entry := mdbx.ChainValue(c.x, c.parent, c.work)
	c.entry.step = replayEntryRecovery
	old, present, err := c.read(dbis[2], key)
	if err != nil {
		return nil, err
	}
	c.entry.step = ""
	if present && !bytes.Equal(old, entry) {
		return nil, selectedSideDefect("replay target staging entry differs")
	}
	owner, _ := mdbx.CanonicalOwnerKey(g, c.x)
	c.entry.step = replayEntryRecovery
	oldOwner, ownerPresent, err := c.read(dbis[7], owner)
	if err != nil {
		return nil, err
	}
	c.entry.step = ""
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

func (c *replayStepCall) read(dbi mdbx.DBI, key []byte) ([]byte, bool, error) {
	value, present, err := c.reader.Get(dbi, key)
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
	if !owner.Owned || owner.Height != c.h {
		key, _ := mdbx.HeightKey(g, c.h)
		if c.own.activeEntry != nil {
			entry = c.own.activeEntry
		} else {
			entry, _, err = c.read(dbisRank(2), key)
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

func dbisRank(rank uint8) mdbx.DBI { return mdbx.SchemaV2DBIs()[rank] }

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
		raw, _, err = c.read(dbisRank(3), entry[:32])
		if err != nil {
			return nil, err
		}
	}
	if !replayPathBinds(raw, x) || [32]byte(raw[4:36]) != [32]byte(entry[32:64]) {
		return nil, selectedSideDefect("old active header absent or inconsistent")
	}
	return raw, nil
}

func (c *replayStepCall) oldActiveWork(g uint64, entry []byte, work *big.Int) error {
	key, _ := mdbx.HeightKey(g, c.h-1)
	previous, _, err := c.read(dbisRank(2), key)
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
	rows := make([]mdbx.ConsultedRow, len(finite), int(count)+len(finite))
	copy(rows, finite)
	for op := range c.view.base.rows {
		key, _ := mdbx.UTXOKey(c.view.base.imageID, op.Txid, op.Vout)
		if replayStepTarget(mutations, dbisRank(1), key) < 0 {
			rows = append(rows, mdbx.ConsultedRow{DBI: dbisRank(1), Key: key})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return logicalMDBXBefore(mdbx.Mutation{DBI: rows[i].DBI, Key: rows[i].Key}, mdbx.Mutation{DBI: rows[j].DBI, Key: rows[j].Key}) })
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
		if replayStepTarget(mutations, dbisRank(1), key) < 0 {
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
	sort.Slice(c.consulted, func(i, j int) bool { return logicalMDBXBefore(mdbx.Mutation{DBI: c.consulted[i].DBI, Key: c.consulted[i].Key}, mdbx.Mutation{DBI: c.consulted[j].DBI, Key: c.consulted[j].Key}) })
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
	if out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && out.Err == c.sentinel {
		out.Result, out.Decision, out.Err = c.entry.result, c.entry.decision, nil
	} else if out.Stage == mdbx.UpdateStageCommitMayHaveCrossed {
		entry := replayEntryCrossed(ReplayEntryOutcomeV1{Truth: out.Truth, Stage: out.Stage, Err: out.Err}, &c.entry)
		out.CanonicalTruth, out.Result = entry.CanonicalTruth, entry.Result
	} else {
		out.Result = replayStepCauses(out.Err, &c.entry)
		if c.carrierInvalid {
			out.Result = selectedSideInvariant
		}
		if out.Stage == mdbx.UpdateStageWriteStartedDefinitelyPrecommit {
			out.Result = replayEntryPrecommit(out.Result)
		}
	}
	if out.Result == replayEntryRecovery && c.needed != nil {
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
	switch e := part.(type) {
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
