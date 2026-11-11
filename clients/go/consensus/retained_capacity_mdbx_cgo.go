//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"math"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// RetainedAccountingV1 is the dormant retained-accounting owner of ordinary
// direct operations (RUBIN_COMPACT_BLOCKS.md Section 10). It caches only a
// fully completed pre tuple bound to an exact reusable mutation binding.
// It is noncopyable during use and is not safe for concurrent use.
type RetainedAccountingV1 struct {
	limits   LimitsV1
	binding  mdbx.MutationBindingV1
	exactRet uint64
	valid    bool
	complete [2]retainedCompleteV1
	active   *DirectRetainedProofV1
}

type retainedUndoProjectionV1 struct {
	block               [32]byte
	oldCharge           uint64
	oldOwned, postOwned bool
}

// DirectRetainedProofV1 is one owned direct attempt: the exact borrowed
// operation, its captured roles and scalars and the sole undo projection.
type DirectRetainedProofV1 struct {
	owner                                *RetainedAccountingV1
	self                                 *DirectRetainedProofV1
	binding                              mdbx.MutationBindingV1
	op                                   *mdbx.TreeOperationV1
	roles                                [2]retainedRoleV1
	pre, remove, add, post               uint64
	complete                             [2]retainedCompleteV1
	undo                                 retainedUndoProjectionV1
	prepared, entered, accepted, applied bool
}

var (
	errRetainedPlanAPIV1     error = localLogicalStateFailure("invalid retained direct plan")
	errRetainedShapeAPIV1    error = localLogicalStateFailure("invalid retained direct shape")
	errRetainedPendingV1     error = localLogicalStateFailure("retained direct finite delta is unavailable")
	errRetainedProofAPIV1    error = localLogicalStateFailure("invalid retained direct proof")
	errRetainedReportAPIV1   error = localLogicalStateFailure("invalid retained direct report")
	errRetainedApplyAPIV1    error = localLogicalStateFailure("invalid retained direct application")
	errRetainedProofCapacity       = retainedFailureV1("storage_capacity", errRetainedArithmetic)
)

// NewRetainedAccountingV1 copies limits and performs no native work.
func NewRetainedAccountingV1(limits LimitsV1) *RetainedAccountingV1 {
	return &RetainedAccountingV1{limits: limits}
}

// InvalidateV1 retires the cache, its facts and any active attempt.
func (a *RetainedAccountingV1) InvalidateV1() {
	if a == nil {
		return
	}
	a.binding, a.exactRet, a.valid, a.complete, a.active = mdbx.MutationBindingV1{}, 0, false, [2]retainedCompleteV1{}, nil
}

// PlanDirectMDBX refuses invalid initial controls with no new attempt and no
// Reader work, then owns exactly one attempt that stays active with
// prepared=false on every later refusal.
func (a *RetainedAccountingV1) PlanDirectMDBX(dst *DirectRetainedProofV1, old *mdbx.Reader, account *mdbx.OperationAccount, op *mdbx.TreeOperationV1) error {
	if err := a.initialV1(dst, old, account, op); err != nil {
		return err
	}
	*dst = DirectRetainedProofV1{owner: a, self: dst, op: op}
	a.active = dst
	if err := retainedOpBindingV1(op); err != nil {
		return err
	}
	return account.WithReservation(retainedPlanFrameV1, func() error {
		return dst.planV1(old, account)
	})
}

// retainedPlanFrameV1 is the OLD frame 2313928 plus the planned frame 2166472.
const retainedPlanFrameV1 uint64 = 4480400

// planV1 runs initializer, planned decode and relation, then the pre tuple,
// and clears the read context before the frame exits.
func (p *DirectRetainedProofV1) planV1(old *mdbx.Reader, account *mdbx.OperationAccount) error {
	var read retainedReadV1
	defer func() { read = retainedReadV1{} }()
	if err := prepareRetainedReadV1(&read, old, account, retainedLateV1(p.op)); err != nil {
		return err
	}
	planned := &read.authority
	if err := retainedPlannedV1(&read, p.op, &planned); err != nil {
		return err
	}
	if err := retainedRelationV1(&read, p.op); err != nil {
		return err
	}
	if err := p.owner.preV1(p, &read); err != nil {
		return err
	}
	if err := retainedRoleRelationV1(&read, p.op); err != nil {
		return err
	}
	if err := p.undoChargeV1(&read); err != nil {
		return err
	}
	return errRetainedPendingV1
}

// undoChargeV1 captures the sole primitive's actual OLD physical family
// charge through the producer's header-independent raw family read.
func (p *DirectRetainedProofV1) undoChargeV1(read *retainedReadV1) error {
	prim := &p.op.Primitives[0]
	w := retainedWalkV1{read: read}
	if err := w.undoV1(retainedArtifactV1{hash: prim.Block, height: prim.Height}); err != nil {
		return err
	}
	p.undo.block, p.undo.oldCharge = prim.Block, w.pre.exactRet
	return nil
}

// retainedLateV1 returns a private copy of a qualified slot hash or nil.
func retainedLateV1(op *mdbx.TreeOperationV1) *[32]byte {
	if op.HeaderSlot == nil {
		return nil
	}
	hash := op.HeaderSlot.Hash
	return &hash
}

// retainedPlannedV1 decodes the proposed authority once or keeps OLD by
// pointer; the planned authority keeps the direct grammar and generations.
func retainedPlannedV1(read *retainedReadV1, op *mdbx.TreeOperationV1, planned **mdbx.TreeAuthorityV1) error {
	m, ok := retainedAuthorityMutationV1(op)
	if !ok {
		return nil
	}
	if m.AfterKind != mdbx.AfterLiteral || !m.BeforePresent {
		return errRetainedShapeAPIV1
	}
	decoded, err := mdbx.DecodeTreeAuthorityV1(m.Literal)
	if err != nil || !retainedAuthorityV1(decoded) {
		return errRetainedShapeAPIV1
	}
	o, n := read.authority, decoded
	if n.Authority.ActiveGenerationID != o.Authority.ActiveGenerationID || n.LagGenerationID != o.LagGenerationID {
		return errRetainedShapeAPIV1
	}
	*planned = &decoded
	return nil
}

func retainedAuthorityMutationV1(op *mdbx.TreeOperationV1) (*mdbx.Mutation, bool) {
	meta := mdbx.TreeSchemaV1DBIs()[0]
	for i := range op.Pair.Mutations {
		m := &op.Pair.Mutations[i]
		if m.DBI == meta && len(m.Key) == 1 && m.Key[0] == 2 {
			return m, true
		}
	}
	return nil, false
}

// retainedRelationV1 binds the sole primitive to the OLD CURRENT generation.
func retainedRelationV1(read *retainedReadV1, op *mdbx.TreeOperationV1) error {
	p := &op.Primitives[0]
	c := p.Coverage
	if p.Generation != read.authority.Authority.ActiveGenerationID || c.Generation != p.Generation {
		return errRetainedShapeAPIV1
	}
	if c.Block != p.Block || c.Height != p.Height || p.Undo != mdbx.UndoWriteOrReuseV1 && p.Undo != mdbx.UndoTransientV1 {
		return errRetainedShapeAPIV1
	}
	return nil
}

// retainedRoleRelationV1 binds the sole primitive to the fresh CURRENT role:
// its coverage database is the role origin and its height is the role's next
// height j (DIRECT 3759, h=H_old+1). It runs once the role data exists.
func retainedRoleRelationV1(read *retainedReadV1, op *mdbx.TreeOperationV1) error {
	p := &op.Primitives[0]
	if p.Coverage.DatabaseID != read.origin.database || p.Height != read.roles[0].j {
		return errRetainedShapeAPIV1
	}
	return nil
}

// preV1 reuses a matching completed pre tuple with fresh roles and no cold
// visit; otherwise it drops the cache and reconstructs once.
func (a *RetainedAccountingV1) preV1(p *DirectRetainedProofV1, read *retainedReadV1) error {
	p.binding = read.binding
	if a.valid && a.binding.EqualForReuse(read.binding) && retainedFactsMatchV1(read, a.complete) {
		if err := readRetainedRolesV1(read); err != nil {
			return err
		}
		p.pre, p.complete, p.roles = a.exactRet, a.complete, read.roles
		return nil
	}
	a.binding, a.exactRet, a.valid, a.complete = mdbx.MutationBindingV1{}, 0, false, [2]retainedCompleteV1{}
	pre, err := readDirectRetainedMDBXV1(read)
	if err != nil {
		return err
	}
	p.pre, p.complete, p.roles = pre.exactRet, pre.complete, read.roles
	if pre.binding.EqualForReuse(pre.binding) {
		a.binding, a.exactRet, a.valid, a.complete = pre.binding, pre.exactRet, true, pre.complete
	}
	return nil
}

// retainedFactsMatchV1 compares cached fact generations with fresh OLD spans.
func retainedFactsMatchV1(read *retainedReadV1, cached [2]retainedCompleteV1) bool {
	var fresh [2]uint64
	at := 0
	for _, span := range retainedSpansV1(read.authority.Authority) {
		if span.Kind != mdbx.CleanupSpanGenerationV1 {
			continue
		}
		if at == len(fresh) {
			return false
		}
		fresh[at], at = span.GenerationID, at+1
	}
	return fresh == [2]uint64{cached[0].generation, cached[1].generation}
}

// initialV1 checks the initial controls in contract order.
func (a *RetainedAccountingV1) initialV1(dst *DirectRetainedProofV1, old *mdbx.Reader, account *mdbx.OperationAccount, op *mdbx.TreeOperationV1) error {
	if retainedPlanNilV1(a, dst, old, account, op) {
		return errRetainedPlanAPIV1
	}
	if a.active != nil || *dst != (DirectRetainedProofV1{}) {
		return errRetainedPlanAPIV1
	}
	if op.Proof != nil || op.Pair.EntryInventory != nil {
		return errRetainedPlanAPIV1
	}
	return retainedDirectCountV1(op)
}

func retainedPlanNilV1(a *RetainedAccountingV1, dst *DirectRetainedProofV1, old *mdbx.Reader, account *mdbx.OperationAccount, op *mdbx.TreeOperationV1) bool {
	return a == nil || dst == nil || old == nil || account == nil || op == nil
}

// retainedDirectCountV1 admits exactly one primitive and no LAG kind.
func retainedDirectCountV1(op *mdbx.TreeOperationV1) error {
	if len(op.Primitives) != 1 {
		return errRetainedPlanAPIV1
	}
	if kind := op.Primitives[0].Kind; kind == mdbx.TreeKindLagForwardV1 || kind == mdbx.TreeKindLagReverseV1 {
		return errRetainedPlanAPIV1
	}
	return nil
}

// retainedOpBindingV1 runs the op-only binding refusals before any frame.
func retainedOpBindingV1(op *mdbx.TreeOperationV1) error {
	p := &op.Primitives[0]
	if p.Source == nil || p.Coverage == nil {
		return errRetainedShapeAPIV1
	}
	if p.Direction != mdbx.TreeForwardV1 || p.Kind != mdbx.TreeKindDirectApplyV1 {
		return errRetainedShapeAPIV1
	}
	if !retainedCoverageShapeV1(p.Coverage) {
		return errRetainedShapeAPIV1
	}
	return retainedHeaderSlotV1(op)
}

// retainedCoverageShapeV1 admits HeaderBytes 148 and a stored BodyKind 2
// without a current-body literal, or a current BodyKind 1 literal.
func retainedCoverageShapeV1(c *mdbx.TreeSourceCoverageV1) bool {
	if c.HeaderBytes != 148 {
		return false
	}
	switch c.BodyKind {
	case 1:
		return len(c.CurrentBody) != 0
	case 2:
		return c.CurrentBody == nil
	}
	return false
}

// retainedHeaderSlotV1 qualifies an optional slot; a nil slot is admitted.
func retainedHeaderSlotV1(op *mdbx.TreeOperationV1) error {
	slot, p := op.HeaderSlot, &op.Primitives[0]
	if slot == nil {
		return nil
	}
	if slot.Hash != p.Block || slot.Hash != p.Coverage.Block || p.Coverage.BodyKind != 2 {
		return errRetainedShapeAPIV1
	}
	return nil
}

// Proof reduces the native report against the captured finite delta. It makes
// no Store, Reader or account call, allocates nothing and returns only
// preinitialized errors.
func (p *DirectRetainedProofV1) Proof(report *mdbx.TreeDeltaReportV1) error {
	if !p.callableV1() {
		return errRetainedProofAPIV1
	}
	p.entered = true
	if report == nil || !p.reportShapeV1(report) {
		return errRetainedReportAPIV1
	}
	post, ok := p.postV1(report)
	if !ok {
		return errRetainedProofCapacity
	}
	limits := p.owner.limits
	if post > math.MaxUint64-limits.R() || post+limits.R() > limits.LRet() {
		return errRetainedProofCapacity
	}
	p.post, p.accepted = post, true
	return nil
}

// callableV1 admits only the owner's active prepared attempt, once.
func (p *DirectRetainedProofV1) callableV1() bool {
	if p == nil || p.self != p || p.owner == nil || p.owner.active != p {
		return false
	}
	return p.prepared && !p.entered && !p.applied
}

// reportShapeV1 admits only the direct report domain of the contract table.
func (p *DirectRetainedProofV1) reportShapeV1(r *mdbx.TreeDeltaReportV1) bool {
	c, old := r.Current, p.roles[0]
	if !c.Present || c.Generation != old.generation || c.BytesBefore != old.s || c.CountBefore != old.n {
		return false
	}
	if r.Lag != (mdbx.TreeRoleDeltaV1{}) || len(r.Undo) != 1 {
		return false
	}
	return validLogicalStateResidualEnvelope(c.BytesAfter, c.CountAfter) && retainedUndoShapeV1(r.Undo[0])
}

// retainedUndoShapeV1 bounds the sole record by the per-block envelope.
func retainedUndoShapeV1(u mdbx.TreeUndoChargeV1) bool {
	switch u.Effect {
	case mdbx.TreeUndoFamilyNoneV1:
		return u.Entries == 0 && u.Bytes == 0
	case mdbx.TreeUndoFamilyWrittenV1, mdbx.TreeUndoFamilyKeptV1, mdbx.TreeUndoFamilyDeletedV1:
		if u.Entries == 0 {
			return u.Bytes == 0
		}
		return u.Entries <= 414634 && u.Bytes >= 56*u.Entries && u.Bytes <= 65596*u.Entries
	}
	return false
}

// postV1 replaces the CURRENT role and the touched family, then applies E once.
func (p *DirectRetainedProofV1) postV1(r *mdbx.TreeDeltaReportV1) (uint64, bool) {
	c, old := r.Current, p.roles[0]
	if c.IndexRemoved > old.j || old.j-c.IndexRemoved > math.MaxUint64-c.IndexAdded {
		return 0, false
	}
	oldTerm, ok1 := retainedRoleTermV1(old.s, old.n, old.j)
	newTerm, ok2 := retainedRoleTermV1(c.BytesAfter, c.CountAfter, old.j-c.IndexRemoved+c.IndexAdded)
	oldUndo, postUndo := p.undoTermsV1(r.Undo[0])
	v, ok3 := retainedSubV1(p.pre, oldTerm, p.remove, oldUndo)
	v, ok4 := retainedAddV1(v, newTerm, p.add, postUndo)
	return v, ok1 && ok2 && ok3 && ok4
}

func retainedRoleTermV1(s, n, j uint64) (uint64, bool) {
	tree, err := RetainedTreeChargeV1(n)
	if err != nil || j > math.MaxUint64/RetainedIndexChargeV1 {
		return 0, false
	}
	return retainedAddV1(s, tree, RetainedIndexChargeV1*j)
}

// undoTermsV1 settles the sole touched family from the captured projection.
func (p *DirectRetainedProofV1) undoTermsV1(u mdbx.TreeUndoChargeV1) (uint64, uint64) {
	physical := p.undo.oldCharge
	switch u.Effect {
	case mdbx.TreeUndoFamilyNoneV1:
	case mdbx.TreeUndoFamilyDeletedV1:
		physical = 0
	case mdbx.TreeUndoFamilyWrittenV1, mdbx.TreeUndoFamilyKeptV1:
		physical = u.Bytes
	}
	var before, after uint64
	if p.undo.oldOwned {
		before = p.undo.oldCharge
	}
	if p.undo.postOwned {
		after = physical
	}
	return before, after
}

func retainedSubV1(v uint64, values ...uint64) (uint64, bool) {
	for _, n := range values {
		if n > v {
			return 0, false
		}
		v -= n
	}
	return v, true
}

func retainedAddV1(v uint64, values ...uint64) (uint64, bool) {
	for _, n := range values {
		if n > math.MaxUint64-v {
			return 0, false
		}
		v += n
	}
	return v, true
}

// ApplyDirectMDBX consumes the owned active attempt once. Only the exact
// accepted NEW/nil/CommitMayHaveCrossed/-1 tuple advances the cache; every
// other valid tuple invalidates unless a trusted clean callback refusal
// preserves a completed same-binding pre tuple. Misuse is a local API failure
// and invalidates. It makes no Reader, account or native call.
func (a *RetainedAccountingV1) ApplyDirectMDBX(p *DirectRetainedProofV1, truth mdbx.CommitTruth, stage mdbx.UpdateStage, index int, nativeErr error, cleanCallbackRefusal bool) error {
	if a == nil {
		return errRetainedApplyAPIV1
	}
	if !a.ownsV1(p) || !retainedTupleDomainV1(truth, stage, index) {
		a.InvalidateV1()
		return errRetainedApplyAPIV1
	}
	a.active, p.applied = nil, true
	if nativeErr == nil {
		return a.successV1(p, truth, stage, index)
	}
	if !retainedCleanRefusalV1(p, truth, stage, index, cleanCallbackRefusal) || !a.valid || !a.binding.EqualForReuse(p.binding) {
		a.InvalidateV1()
	}
	return nil
}

func (a *RetainedAccountingV1) ownsV1(p *DirectRetainedProofV1) bool {
	return p != nil && p.self == p && p.owner == a && a.active == p && !p.applied
}

func retainedTupleDomainV1(truth mdbx.CommitTruth, stage mdbx.UpdateStage, index int) bool {
	truthOK := truth >= mdbx.CommitTruthOld && truth <= mdbx.CommitTruthUnknown
	stageOK := stage >= mdbx.UpdateStagePrewrite && stage <= mdbx.UpdateStageCommitMayHaveCrossed
	return truthOK && stageOK && index >= -1 && index <= 0
}

func retainedCleanRefusalV1(p *DirectRetainedProofV1, truth mdbx.CommitTruth, stage mdbx.UpdateStage, index int, clean bool) bool {
	return clean && !p.entered && truth == mdbx.CommitTruthOld && stage == mdbx.UpdateStagePrewrite && index == -1
}

// successV1 advances the cache only for the exact accepted normal success.
func (a *RetainedAccountingV1) successV1(p *DirectRetainedProofV1, truth mdbx.CommitTruth, stage mdbx.UpdateStage, index int) error {
	exact := truth == mdbx.CommitTruthNew && stage == mdbx.UpdateStageCommitMayHaveCrossed && index == -1
	if !exact || !p.prepared || !p.entered || !p.accepted {
		a.InvalidateV1()
		return errRetainedApplyAPIV1
	}
	next, ok := p.binding.AfterOneCommitAttemptV1()
	if !ok {
		a.InvalidateV1()
		return nil
	}
	a.binding, a.exactRet, a.valid, a.complete = next, p.post, true, p.complete
	return nil
}
