//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"math"
	"slices"

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
	errRetainedFiniteAPIV1   error = localLogicalStateFailure("unsupported retained direct finite effect")
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

// retainedFiniteV1 is the finite local context: the read pointer, the single
// planned authority value, the post endpoints and the borrowed op and proof.
type retainedFiniteV1 struct {
	read    *retainedReadV1
	planned mdbx.TreeAuthorityV1
	post    [2]mdbx.TreeEndpointV1
	op      *mdbx.TreeOperationV1
	proof   *DirectRetainedProofV1
}

// planV1 runs initializer, planned decode and relation, the pre tuple, the
// role relations and the finite delta, and clears every context before the
// frame exits. prepared is set only after the complete finite capture.
func (p *DirectRetainedProofV1) planV1(old *mdbx.Reader, account *mdbx.OperationAccount) error {
	var read retainedReadV1
	f := retainedFiniteV1{read: &read, op: p.op, proof: p}
	defer func() { read, f = retainedReadV1{}, retainedFiniteV1{} }()
	if err := prepareRetainedReadV1(&read, old, account, retainedLateV1(p.op)); err != nil {
		return err
	}
	if err := f.plannedV1(); err != nil {
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
	if err := f.deltaV1(); err != nil {
		return err
	}
	p.prepared = true
	return nil
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

// plannedV1 decodes the proposed authority once into this context's single
// planned value, or copies nothing when the Pair keeps OLD. The planned value
// must keep the direct grammar and generations.
func (f *retainedFiniteV1) plannedV1() error {
	m, ok := retainedAuthorityMutationV1(f.op)
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
	o := &f.read.authority
	if decoded.Authority.ActiveGenerationID != o.Authority.ActiveGenerationID || decoded.LagGenerationID != o.LagGenerationID {
		return errRetainedShapeAPIV1
	}
	f.planned = decoded
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
	if p.Generation != read.authority.Authority.ActiveGenerationID || c.Generation != p.Generation ||
		c.Block != p.Block || c.Height != p.Height || p.Undo != mdbx.UndoWriteOrReuseV1 && p.Undo != mdbx.UndoTransientV1 {
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
	if retainedPlanNilV1(a, dst, old, account, op) || a.active != nil || *dst != (DirectRetainedProofV1{}) ||
		op.Proof != nil || op.Pair.EntryInventory != nil {
		return errRetainedPlanAPIV1
	}
	return retainedDirectCountV1(op)
}

func retainedPlanNilV1(a *RetainedAccountingV1, dst *DirectRetainedProofV1, old *mdbx.Reader, account *mdbx.OperationAccount, op *mdbx.TreeOperationV1) bool {
	return a == nil || dst == nil || old == nil || account == nil || op == nil
}

// retainedDirectCountV1 admits exactly one primitive and no LAG kind.
func retainedDirectCountV1(op *mdbx.TreeOperationV1) error {
	if len(op.Primitives) != 1 || op.Primitives[0].Kind == mdbx.TreeKindLagForwardV1 || op.Primitives[0].Kind == mdbx.TreeKindLagReverseV1 {
		return errRetainedPlanAPIV1
	}
	return nil
}

// retainedOpBindingV1 runs the op-only binding refusals before any frame.
func retainedOpBindingV1(op *mdbx.TreeOperationV1) error {
	p := &op.Primitives[0]
	if p.Source == nil || p.Coverage == nil || p.Direction != mdbx.TreeForwardV1 || p.Kind != mdbx.TreeKindDirectApplyV1 ||
		p.Undo < 1 || p.Undo > 6 || !retainedCoverageShapeV1(op) {
		return errRetainedShapeAPIV1
	}
	return retainedHeaderSlotV1(op)
}

// retainedCoverageShapeV1 admits HeaderBytes 148 and a stored BodyKind 2
// without a current-body literal in Coverage or the Pair, or a current
// BodyKind 1 literal.
func retainedCoverageShapeV1(op *mdbx.TreeOperationV1) bool {
	c := op.Primitives[0].Coverage
	if c.HeaderBytes != 148 {
		return false
	}
	switch c.BodyKind {
	case 1:
		return len(c.CurrentBody) != 0
	case 2:
		return c.CurrentBody == nil && !retainedBodyLiteralV1(op)
	}
	return false
}

// retainedBodyLiteralV1 reports a Pair body literal at x.
func retainedBodyLiteralV1(op *mdbx.TreeOperationV1) bool {
	x := op.Primitives[0].Block
	for i := range op.Pair.Mutations {
		m := &op.Pair.Mutations[i]
		if m.DBI.Rank == 4 && m.AfterKind == mdbx.AfterLiteral && bytes.Equal(m.Key, x[:]) {
			return true
		}
	}
	return false
}

// retainedHeaderSlotV1 qualifies an optional slot; a nil slot is admitted.
func retainedHeaderSlotV1(op *mdbx.TreeOperationV1) error {
	slot, p := op.HeaderSlot, &op.Primitives[0]
	if slot != nil && (slot.Hash != p.Block || slot.Hash != p.Coverage.Block || p.Coverage.BodyKind != 2) {
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
	return p != nil && p.self == p && p.owner != nil && p.owner.active == p && p.prepared && !p.entered && !p.applied
}

// reportShapeV1 admits only the direct report domain of the contract table.
func (p *DirectRetainedProofV1) reportShapeV1(r *mdbx.TreeDeltaReportV1) bool {
	c, old := r.Current, p.roles[0]
	return c.Present && c.Generation == old.generation && c.BytesBefore == old.s && c.CountBefore == old.n &&
		r.Lag == (mdbx.TreeRoleDeltaV1{}) && len(r.Undo) == 1 &&
		validLogicalStateResidualEnvelope(c.BytesAfter, c.CountAfter) && retainedUndoShapeV1(r.Undo[0])
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
	if !a.ownsV1(p) || !retainedTupleDomainV1(truth, stage, index, nativeErr != nil) {
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

func retainedTupleDomainV1(truth mdbx.CommitTruth, stage mdbx.UpdateStage, index int, failed bool) bool {
	truthOK := truth >= mdbx.CommitTruthOld && truth <= mdbx.CommitTruthUnknown
	stageOK := stage >= mdbx.UpdateStagePrewrite && stage <= mdbx.UpdateStageCommitMayHaveCrossed
	return truthOK && stageOK && index >= -1 && index <= 0 && (!failed || retainedFailureTupleV1(truth, stage, index))
}

// retainedFailureTupleV1 is the native failure union (internal/mdbx
// mdbx_cgo.go updateNativeOutcome.valid, tree_compose_cgo.go index): before
// the commit may have crossed the truth is OLD; a primitive index is a
// precommit writer abort.
func retainedFailureTupleV1(truth mdbx.CommitTruth, stage mdbx.UpdateStage, index int) bool {
	if stage == mdbx.UpdateStageCommitMayHaveCrossed {
		return index == -1
	}
	return truth == mdbx.CommitTruthOld
}

func retainedCleanRefusalV1(p *DirectRetainedProofV1, truth mdbx.CommitTruth, stage mdbx.UpdateStage, index int, clean bool) bool {
	return clean && !p.entered && truth == mdbx.CommitTruthOld && stage == mdbx.UpdateStagePrewrite && index == -1
}

// successV1 advances the cache only for the exact accepted normal success.
// Another nil-error tuple is impossible and a local API failure; the exact
// tuple without this attempt's accepted Proof is the missing/foreign proof
// row: applied, invalidated, nil.
func (a *RetainedAccountingV1) successV1(p *DirectRetainedProofV1, truth mdbx.CommitTruth, stage mdbx.UpdateStage, index int) error {
	if truth != mdbx.CommitTruthNew || stage != mdbx.UpdateStageCommitMayHaveCrossed || index != -1 {
		a.InvalidateV1()
		return errRetainedApplyAPIV1
	}
	next, ok := p.binding.AfterOneCommitAttemptV1()
	if !ok || !p.prepared || !p.entered || !p.accepted {
		a.InvalidateV1()
		return nil
	}
	a.binding, a.exactRet, a.valid, a.complete = next, p.post, true, p.complete
	return nil
}

// deltaV1 captures the complete finite delta: x, every other Pair header or
// body identity and, under a W/L transfer, every OLD selected row, each
// settled once between its OLD and planned union.
func (f *retainedFiniteV1) deltaV1() error {
	x, err := f.pairV1()
	if err != nil {
		return err
	}
	f.post = [2]mdbx.TreeEndpointV1{f.op.Primitives[0].Endpoint, f.read.endpoints[1]}
	transfer, err := f.promiseV1()
	if err != nil {
		return err
	}
	if err := f.settleXV1(x); err != nil {
		return err
	}
	if err := f.pairRowsV1(x.hash); err != nil {
		return err
	}
	if transfer {
		return f.transferV1(x.hash)
	}
	return nil
}

// changedV1 reports whether the Pair carries a planned authority value.
func (f *retainedFiniteV1) changedV1() bool {
	_, ok := retainedAuthorityMutationV1(f.op)
	return ok
}

// pairV1 classifies every Pair mutation and returns x's planned canonical
// identity from its CURRENT index insert.
func (f *retainedFiniteV1) pairV1() (retainedArtifactV1, error) {
	prim := &f.op.Primitives[0]
	x := retainedArtifactV1{hash: prim.Block, height: prim.Height, generation: f.read.roles[0].generation}
	found := false
	for i := range f.op.Pair.Mutations {
		m := &f.op.Pair.Mutations[i]
		ok, index := f.mutationV1(m)
		if !ok {
			return x, errRetainedFiniteAPIV1
		}
		if index {
			x.parent, found = [32]byte(m.Literal[32:64]), true
		}
	}
	if !found {
		return x, errRetainedFiniteAPIV1
	}
	return x, nil
}

// mutationV1 admits one mutation of the direct CURRENT domain and reports
// whether it is x's CURRENT canonical index insert. Every other row is an
// unknown effect: a state, x-keyed undo, tree-node or CURRENT counter/root
// row, which native admission refuses for every covered direct op, and every
// other namespace, generation or SideLink effect.
func (f *retainedFiniteV1) mutationV1(m *mdbx.Mutation) (bool, bool) {
	switch m.DBI.Rank {
	case 0:
		return len(m.Key) == 1 && m.Key[0] == 2, false
	case 2:
		ok := f.indexV1(m)
		return ok, ok
	case 7:
		key, _ := mdbx.CanonicalOwnerKey(f.read.roles[0].generation, f.op.Primitives[0].Block)
		return retainedInsertV1(m) && bytes.Equal(m.Key, key), false
	case 3, 4:
		return f.artifactRowV1(m), false
	case 6:
		return f.wLinkV1(m), false
	}
	return false, false
}

// wLinkV1 admits only the deletion of the cleared side's SideLink at x's
// height; restV1 requires it exactly for a W row x (MP 1480-1483, 2559-2561).
func (f *retainedFiniteV1) wLinkV1(m *mdbx.Mutation) bool {
	s := f.read.authority.Authority.SelectedSide
	if s == nil || !f.changedV1() || f.planned.Authority.SelectedSide != nil {
		return false
	}
	key, _ := mdbx.HeightKey(s.GenerationID, f.op.Primitives[0].Height)
	return m.BeforePresent && m.AfterKind == mdbx.AfterAbsent && bytes.Equal(m.Key, key)
}

func retainedInsertV1(m *mdbx.Mutation) bool {
	return !m.BeforePresent && m.AfterKind == mdbx.AfterLiteral
}

func (f *retainedFiniteV1) indexV1(m *mdbx.Mutation) bool {
	x := &f.op.Primitives[0]
	key, _ := mdbx.HeightKey(f.read.roles[0].generation, x.Height)
	return retainedInsertV1(m) && bytes.Equal(m.Key, key) && len(m.Literal) == 104 && [32]byte(m.Literal[:32]) == x.Block
}

// artifactRowV1 admits x's nil-slot header insert and BodyKind 1 body
// literal, and a deletion of another identity's header or body row.
func (f *retainedFiniteV1) artifactRowV1(m *mdbx.Mutation) bool {
	x := &f.op.Primitives[0]
	if !bytes.Equal(m.Key, x.Block[:]) {
		return len(m.Key) == 32 && m.BeforePresent && m.AfterKind == mdbx.AfterAbsent
	}
	if m.DBI.Rank == 3 {
		return retainedInsertV1(m) && f.op.HeaderSlot == nil
	}
	return retainedInsertV1(m) && x.Coverage.BodyKind == 1
}

// deletedV1 returns the kind bits whose row the Pair deletes for hash.
func (f *retainedFiniteV1) deletedV1(hash [32]byte, upto int) uint8 {
	var bits uint8
	for i := range f.op.Pair.Mutations[:upto] {
		m := &f.op.Pair.Mutations[i]
		if (m.DBI.Rank == 3 || m.DBI.Rank == 4) && m.AfterKind == mdbx.AfterAbsent && bytes.Equal(m.Key, hash[:]) {
			bits |= m.DBI.Rank - 2
		}
	}
	return bits
}

// obsoleteV1 returns every kind bit when an obsolete generation projects
// hash in OLD: a healthy header names its parent, then the producer's earlier
// membership rule takes a positive own forward with that parent despite a
// FALSE fact and excludes it only under a TRUE fact (FALSE is branch_data).
// A header read error takes OLD's canonical header duty, as projectedV1 does.
func (f *retainedFiniteV1) obsoleteV1(old retainedArtifactV1) (uint8, error) {
	header, present, err := f.read.headerV1(old.hash)
	if err != nil {
		return 0, retainedSourceV1(err, old.required&1 != 0)
	}
	k := retainedArtifactV1{hash: old.hash, generation: f.read.roles[0].generation}
	if !present || len(header) != 148 || !retainedHeaderV1(header, retainedArtifactV1{hash: old.hash}) {
		return 0, nil
	}
	k.parent = [32]byte(header[4:36])
	w := retainedWalkV1{read: f.read, pre: retainedPreImageV1{complete: f.proof.complete}}
	found, err := w.earlierV1(min(retainedCountV1(f.read.authority.Authority, mdbx.CleanupSpanGenerationV1), 2), k)
	if err != nil || !found {
		return 0, err
	}
	return 7, nil
}

// unionsV1 settles the OLD and planned unions from their seeds and adds the
// obsolete projection, which owns every kind. Obsolete namespaces are
// untouched and the Pair changes no header but a deleted one and x's, whose
// planned keep owns every kind, so the planned image keeps OLD's projection
// unless the Pair deletes the header it needs (MP 1717, 2550-2557).
func (f *retainedFiniteV1) unionsV1(old, planned retainedArtifactV1, deleted uint8) (retainedArtifactV1, retainedArtifactV1, error) {
	old, err := f.read.unionV1(old)
	if err != nil {
		return old, planned, err
	}
	planned, err = f.plannedOwnersV1(planned)
	if err != nil {
		return old, planned, err
	}
	ob, err := f.obsoleteV1(old)
	old.bits |= ob
	if deleted&1 == 0 {
		planned.bits |= ob
	}
	return old, planned, err
}

// exchangeV1 runs use while read.authority holds the single planned value and
// restores OLD on every return, error, panic or Goexit.
func (f *retainedFiniteV1) exchangeV1(use func() error) error {
	f.read.authority, f.planned = f.planned, f.read.authority
	defer func() { f.read.authority, f.planned = f.planned, f.read.authority }()
	return use()
}

// keepV1 applies the producer's keep windows of read.authority to a canonical
// point at height h: header always, body and undo by their windows.
func (read *retainedReadV1) keepV1(k retainedArtifactV1) retainedArtifactV1 {
	a := read.authority.Authority
	k.bits, k.required = 1, 1
	if k.height >= read.bodyFirstV1() || retainedOwedV1(a, k.height, mdbx.CleanupSpanBlocksV1) {
		k.bits, k.required = k.bits|2, k.required|2
	}
	if k.height >= a.U || retainedOwedV1(a, k.height, mdbx.CleanupSpanUndoV1) {
		k.bits, k.required = k.bits|4, k.required|4
	}
	return k
}

// unionV1 adds the optional owners of k.hash in read.authority order; it
// stops once header and body, the only optional kinds, are owned.
func (read *retainedReadV1) unionV1(k retainedArtifactV1) (retainedArtifactV1, error) {
	for at := uint64(0); k.bits&3 != 3 && at < 1440; at++ {
		item, present, err := read.optionalAtV1(at)
		if err != nil || !present {
			return k, err
		}
		if item.hash == k.hash {
			k = retainedMergeV1(k, item)
		}
	}
	return k, nil
}

func retainedMergeV1(k, item retainedArtifactV1) retainedArtifactV1 {
	if k.bits == 0 {
		return item
	}
	k.bits |= item.bits
	k.selected = k.selected || item.selected
	return k
}

// plannedOwnersV1 settles the planned union of an identity: its canonical
// point under the planned keep and its planned optional owners.
func (f *retainedFiniteV1) plannedOwnersV1(k retainedArtifactV1) (retainedArtifactV1, error) {
	if !f.changedV1() {
		return f.read.plannedUnionV1(k)
	}
	err := f.exchangeV1(func() error {
		var err error
		k, err = f.read.plannedUnionV1(k)
		return err
	})
	return k, err
}

// plannedUnionV1 applies read.authority's keep to a canonical point, then
// adds its optional owners.
func (read *retainedReadV1) plannedUnionV1(k retainedArtifactV1) (retainedArtifactV1, error) {
	if k.required&1 != 0 {
		k = read.keepV1(k)
	}
	return read.unionV1(k)
}

// settleXV1 settles x: canonical header term once, E header/body by union,
// and the sole undo projection.
func (f *retainedFiniteV1) settleXV1(x retainedArtifactV1) error {
	x.required = 1
	old, planned, err := f.unionsV1(retainedArtifactV1{hash: x.hash}, x, 0)
	if err != nil {
		return err
	}
	if err := retainedSumV1(&f.proof.add, RetainedHeaderChargeV1); err != nil {
		return err
	}
	if err := f.chargeV1(old, planned, 1, 0); err != nil {
		return err
	}
	if err := f.bodyXV1(old, planned); err != nil {
		return err
	}
	if err := f.proof.undoChargeV1(f.read); err != nil {
		return err
	}
	f.proof.undo.oldOwned, f.proof.undo.postOwned = old.bits&4 != 0, planned.bits&4 != 0
	return nil
}

// bodyXV1 settles x's body: a BodyKind 1 literal never rewrites an owned
// body; a stored body follows the union.
func (f *retainedFiniteV1) bodyXV1(old, planned retainedArtifactV1) error {
	c := f.op.Primitives[0].Coverage
	if c.BodyKind != 1 {
		return f.chargeV1(old, planned, 2, 0)
	}
	if old.bits&2 != 0 {
		return errRetainedFiniteAPIV1
	}
	if planned.bits&2 != 0 {
		return retainedSumV1(&f.proof.add, uint64(len(c.CurrentBody)))
	}
	return nil
}

// settleV1 settles one non-x identity from its one OLD canonical observation.
func (f *retainedFiniteV1) settleV1(hash [32]byte, deleted uint8) error {
	k, err := f.read.canonicalOwnerV1(hash)
	if err != nil {
		return err
	}
	old, planned, err := f.unionsV1(k, k, deleted)
	if err != nil {
		return err
	}
	for _, bit := range [3]uint8{1, 2, 4} {
		if err := f.chargeV1(old, planned, bit, deleted); err != nil {
			return err
		}
	}
	return nil
}

// retainedEOwnedV1 excludes the canonical header, charged by the header term.
func retainedEOwnedV1(k retainedArtifactV1, bit uint8) bool {
	return k.bits&bit != 0 && (bit != 1 || k.required&1 == 0)
}

// chargeV1 removes or adds one kind's actual OLD bytes when its E ownership
// changes; a deleted row may not stay owned.
func (f *retainedFiniteV1) chargeV1(old, planned retainedArtifactV1, bit, deleted uint8) error {
	o, p := retainedEOwnedV1(old, bit), retainedEOwnedV1(planned, bit)
	if deleted&bit != 0 && planned.bits&bit != 0 {
		return errRetainedFiniteAPIV1
	}
	if o == p {
		return nil
	}
	item := planned
	if o {
		item = old
	}
	item.bits, item.required = bit, item.required&bit
	w := retainedWalkV1{read: f.read}
	if err := w.artifactsV1(item); err != nil {
		return err
	}
	if o {
		return retainedSumV1(&f.proof.remove, w.pre.exactRet)
	}
	return retainedSumV1(&f.proof.add, w.pre.exactRet)
}

// pairRowsV1 settles each other identity whose header or body row the Pair
// deletes, once per hash.
func (f *retainedFiniteV1) pairRowsV1(x [32]byte) error {
	for i := range f.op.Pair.Mutations {
		m := &f.op.Pair.Mutations[i]
		if m.DBI.Rank != 3 && m.DBI.Rank != 4 || bytes.Equal(m.Key, x[:]) {
			continue
		}
		hash := [32]byte(m.Key)
		if f.deletedV1(hash, i) != 0 {
			continue
		}
		if err := f.settleV1(hash, f.deletedV1(hash, len(f.op.Pair.Mutations))); err != nil {
			return err
		}
	}
	return nil
}

// transferV1 settles each OLD selected row once, other than x and the
// identities the Pair rows settle.
func (f *retainedFiniteV1) transferV1(x [32]byte) error {
	for at := uint64(0); at < uint64(f.read.authority.Authority.SelectedSide.RowCount); at++ {
		item, _, err := f.read.optionalAtV1(at)
		if err != nil {
			return err
		}
		if item.hash == x || f.deletedV1(item.hash, len(f.op.Pair.Mutations)) != 0 {
			continue
		}
		seen, err := f.read.indexOfV1(item.hash, at)
		if err == nil && !seen {
			err = f.settleV1(item.hash, 0)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (read *retainedReadV1) indexOfV1(hash [32]byte, limit uint64) (bool, error) {
	for at := uint64(0); at < limit; at++ {
		item, present, err := read.optionalAtV1(at)
		if err != nil || !present {
			return false, err
		}
		if item.hash == hash {
			return true, nil
		}
	}
	return false, nil
}

// promiseV1 admits only the descriptor changes of a direct op: unchanged
// profile, next generation, excluded branch, BLOCKS and GENERATION spans,
// nonregressing B (MP 1288-1290; L_body, not B, decides BLOCKS), a U increase
// U0->U1 that creates or extends exactly UNDO(CURRENT,U0,U1-1,U0), and the
// optional plan; it reports a W/L transfer.
func (f *retainedFiniteV1) promiseV1() (bool, error) {
	if !f.changedV1() {
		return false, nil
	}
	if !retainedPromiseFixedV1(&f.read.authority.Authority, &f.planned.Authority) {
		return false, errRetainedFiniteAPIV1
	}
	for _, kind := range [3]mdbx.CleanupSpanKindV1{mdbx.CleanupSpanBlocksV1, mdbx.CleanupSpanGenerationV1, mdbx.CleanupSpanUndoV1} {
		if !f.spansV1(kind) {
			return false, errRetainedFiniteAPIV1
		}
	}
	return f.optionalPlanV1()
}

func retainedPromiseFixedV1(o, p *mdbx.StorageAuthorityV1) bool {
	same := o.ActiveProfile == p.ActiveProfile && o.NextGenerationID == p.NextGenerationID && p.B >= o.B && p.U >= o.U
	return same && retainedExcludedSameV1(o.ExcludedInvalidBranch, p.ExcludedInvalidBranch)
}

// retainedExcludedSameV1 requires an unchanged excluded_invalid_branch slot:
// it is never automatically cleared or overwritten (MP 1855-1857), and any
// other change is an effect this owner does not support.
func retainedExcludedSameV1(x, y *mdbx.InvalidBranchV1) bool {
	return x == y || x != nil && y != nil && x.FirstInvalidHeight == y.FirstInvalidHeight && x.FirstInvalidBlockHash == y.FirstInvalidBlockHash && bytes.Equal(x.ExactConsensusError, y.ExactConsensusError)
}

// optionalPlanV1 admits unchanged optional descriptors, or the W/L transfer
// of a live selected side (MP 3018-3058): side cleared, detached suffix
// unchanged and L appended as, or merged into, the side generation's SIDE
// span, whose SideLinks keep their association (MP 1473-1478, 2672-2674).
// From the rolling-prepared OLD shape (MP 1422-1426) L merges into the pending
// SIDE with first and next kept (MP 2539-2541); a W row breaks the adjacency.
func (f *retainedFiniteV1) optionalPlanV1() (bool, error) {
	o, p := f.read.authority.Authority, f.planned.Authority
	if !retainedDetachedEqualV1(o.DetachedSuffix, p.DetachedSuffix) {
		return false, errRetainedFiniteAPIV1
	}
	if o.SelectedSide == nil || p.SelectedSide != nil {
		return false, f.sideSpansV1(retainedSelectedEqualV1(o.SelectedSide, p.SelectedSide), mdbx.CleanupSpanV1{})
	}
	l, err := f.restV1()
	if err != nil {
		return false, err
	}
	if n := retainedCountV1(o, mdbx.CleanupSpanSideV1); n != 0 {
		if !retainedExtendedV1(o, p, l, n, retainedCountV1(p, mdbx.CleanupSpanSideV1)) {
			return false, errRetainedFiniteAPIV1
		}
		return true, nil
	}
	return true, f.sideSpansV1(true, l)
}

// restV1 returns the SIDE span owing L: the selected rows except a W row x
// at the first side height. A W row elsewhere, or a W row without its
// SideLink deletion or that deletion without a W row, is refused.
func (f *retainedFiniteV1) restV1() (mdbx.CleanupSpanV1, error) {
	s, prim := f.read.authority.Authority.SelectedSide, &f.op.Primitives[0]
	l := mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: s.GenerationID, FirstHeight: selectedSideFirst(s), LastHeight: s.TipHeight}
	if s.RowCount != 0 && prim.Height >= l.FirstHeight && prim.Height <= l.LastHeight {
		w, err := f.wV1(prim.Height - l.FirstHeight)
		if err != nil {
			return l, err
		}
		l.FirstHeight += w
	}
	l.NextHeight = l.FirstHeight
	if (l.FirstHeight != selectedSideFirst(s)) != slices.ContainsFunc(f.op.Pair.Mutations, func(m mdbx.Mutation) bool { return m.DBI.Rank == 6 }) {
		return l, errRetainedFiniteAPIV1
	}
	return l, nil
}

// wV1 returns 1 when the selected row at index at is x, the W row, which
// must be the first side row; else 0.
func (f *retainedFiniteV1) wV1(at uint64) (uint64, error) {
	item, _, err := f.read.optionalAtV1(at)
	if err != nil || item.hash != f.op.Primitives[0].Block {
		return 0, err
	}
	if at != 0 {
		return 0, errRetainedFiniteAPIV1
	}
	return 1, nil
}

// sideSpansV1 requires the planned SIDE spans to equal OLD, plus l appended
// when it owes a nonempty L; same is false for an unsupported change.
func (f *retainedFiniteV1) sideSpansV1(same bool, l mdbx.CleanupSpanV1) error {
	o, p := f.read.authority.Authority, f.planned.Authority
	no, np := retainedCountV1(o, mdbx.CleanupSpanSideV1), retainedCountV1(p, mdbx.CleanupSpanSideV1)
	want := no
	if l.Kind == mdbx.CleanupSpanSideV1 && l.FirstHeight <= l.LastHeight {
		want, same = no+1, same && retainedNthV1(p, mdbx.CleanupSpanSideV1, no) == l
	}
	if !same || np != want || !retainedPrefixV1(o, p, mdbx.CleanupSpanSideV1, no) {
		return errRetainedFiniteAPIV1
	}
	return nil
}

func retainedSelectedEqualV1(o, p *mdbx.SelectedSideV1) bool {
	return o == p || o != nil && p != nil && *o == *p
}

func retainedDetachedEqualV1(o, p *mdbx.DetachedSuffixV1) bool {
	return o == p || o != nil && p != nil && o.Cursor == p.Cursor && o.EntryCount == p.EntryCount && o.LogicalBytes == p.LogicalBytes && slices.Equal(o.Entries, p.Entries)
}

// spansV1 compares one kind's descriptors in place; UNDO admits only the
// span a U increase U0->U1 creates or extends.
func (f *retainedFiniteV1) spansV1(kind mdbx.CleanupSpanKindV1) bool {
	o, p := f.read.authority.Authority, f.planned.Authority
	no, np := retainedCountV1(o, kind), retainedCountV1(p, kind)
	if kind != mdbx.CleanupSpanUndoV1 || o.U == p.U {
		return no == np && retainedPrefixV1(o, p, kind, no)
	}
	u := mdbx.CleanupSpanV1{Kind: kind, GenerationID: f.read.roles[0].generation, FirstHeight: o.U, NextHeight: o.U, LastHeight: p.U - 1}
	if np == no+1 {
		last := retainedNthV1(p, kind, no)
		return last == u && retainedPrefixV1(o, p, kind, no)
	}
	return retainedExtendedV1(o, p, u, no, np)
}

// retainedExtendedV1 admits the last OLD span of u's kind extended to adjacent u.
func retainedExtendedV1(o, p mdbx.StorageAuthorityV1, u mdbx.CleanupSpanV1, no, np int) bool {
	if no == 0 || np != no || !retainedPrefixV1(o, p, u.Kind, no-1) {
		return false
	}
	e := retainedNthV1(o, u.Kind, no-1)
	t := retainedNthV1(p, u.Kind, no-1)
	ok := e.LastHeight+1 == u.FirstHeight && e.GenerationID == u.GenerationID
	e.LastHeight = u.LastHeight
	return ok && e == t
}

func retainedCountV1(a mdbx.StorageAuthorityV1, kind mdbx.CleanupSpanKindV1) int {
	n := 0
	for _, s := range retainedSpansV1(a) {
		if s.Kind == kind {
			n++
		}
	}
	return n
}

// retainedNthV1 returns the i-th descriptor of kind without copying spans.
func retainedNthV1(a mdbx.StorageAuthorityV1, kind mdbx.CleanupSpanKindV1, i int) mdbx.CleanupSpanV1 {
	for _, s := range retainedSpansV1(a) {
		if s.Kind != kind {
			continue
		}
		if i == 0 {
			return s
		}
		i--
	}
	return mdbx.CleanupSpanV1{}
}

func retainedPrefixV1(o, p mdbx.StorageAuthorityV1, kind mdbx.CleanupSpanKindV1, n int) bool {
	for i := 0; i < n; i++ {
		a := retainedNthV1(o, kind, i)
		b := retainedNthV1(p, kind, i)
		if a != b {
			return false
		}
	}
	return true
}

// retainedSumV1 adds n to the proof's add or remove scalar with checked arithmetic.
func retainedSumV1(dst *uint64, n uint64) error {
	v, ok := retainedAddV1(*dst, n)
	if !ok {
		return errRetainedProofCapacity
	}
	*dst = v
	return nil
}
