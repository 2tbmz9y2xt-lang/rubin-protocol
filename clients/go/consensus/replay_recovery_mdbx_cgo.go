//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Dormant Reader-scoped recovery planners and the pre-activation recomputation (RUBIN_MEMPOOL_POLICY.md Sections
// 6.4.1.5 and 6.4.1.8). No production caller. Each runs inside its caller's Store.Update callback, writes nothing,
// reserves nothing and returns one plan, report, refusal or error; a plan takes effect only when the caller returns it.

const (
	// replayRecoveryMinBytes is M, the identity, walk and plan terms of the entry lane (RE L27-36): 3,550,822.
	replayRecoveryMinBytes = replayEntryIdentityBytes + replayEntryWalkBytes + replayEntryPlanBytes
	// replayRecoveryIntentBytes is the intent planner's charge: three authority buffers, fixed bookkeeping and the clear
	// planner's checked transfer sublimit (the archiveSelectedSideCharge precedent without its identity envelope and
	// Consulted union arrays).
	replayRecoveryIntentBytes = 3*mdbx.MaxMetadataBytes + 131_072 + selectedSideTransferBytes
)

// The intent planner's charge fits the full lane; a violation does not compile.
const _ = mdbx.MaxOperationDataBytes - replayRecoveryIntentBytes

// ReplayRecoveryPlanV1 is one Reader-scoped plan: the complete Batch and, on an error, ReadResource: the read class
// in flight for a Reader, Store or native failure; empty for a plan, an authority read failure and a decided refusal,
// except that every error of the direct entry's identity page carries LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)
// and every error of the selected-side clear planner carries that planner's own ReadResource. The empty plan is a zero
// Batch with a nil error; Store.Update refuses it as an invalid Batch, so the caller decides that outcome itself.
type ReplayRecoveryPlanV1 struct {
	Batch        mdbx.Batch
	ReadResource string
}

// ReplayRecomputationReportV1 is the closed pre-activation report domain; zero is no report.
type ReplayRecomputationReportV1 uint8

const (
	ReplayRecomputationNotApplicableV1 ReplayRecomputationReportV1 = iota + 1
	ReplayRecomputationRefusedV1
	ReplayRecomputationTargetLocalV1
	ReplayRecomputationStaleV1
	ReplayRecomputationPlanChangeV1
	ReplayRecomputationActivationEligibleV1
)

// ReplayRecomputationV1 is the recomputation result. Result is LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact|
// storage_capacity) for REFUSED, STALE_LOCAL_PLAN for STALE and empty otherwise; Evidence is non-zero exactly for
// TARGET_LOCAL (the canonical-v1 row of the first target-local defect); Release is non-nil exactly for STALE,
// PLAN_CHANGE and ACTIVATION_ELIGIBLE and the caller runs it exactly once after its own commit; on an error only
// ReadResource is set.
type ReplayRecomputationV1 struct {
	Report       ReplayRecomputationReportV1
	Result       string
	Evidence     mdbx.ConsultedRow
	Release      func()
	ReadResource string
	reader       *mdbx.Reader
	authority    mdbx.StorageAuthorityV1
	activeTip    uint64
}

// replayInvLimit is invLimit(lane) = floor((lane - M) * 116 / 244) for M <= lane <= LANE_MAX; zero is the full lane.
func replayInvLimit(lane uint64) uint64 {
	if lane == 0 {
		lane = mdbx.MaxOperationDataBytes
	}
	return (lane - replayRecoveryMinBytes) * 116 / (116 + replayEntryDerivedBytes)
}

func replayRecoveryRefusal(result, message string) error {
	return &selectedSideFailure{result: result, cause: errors.New(message)}
}

// PlanRecoveryIntentMDBX plans the recovery intent (MP 2495-2503, 1553-1571): RECOVERY_REQUIRED with pending = the
// active profile, through the selected-side clear when a side is selected; no ReplayV1, target, generation or counter.
// Any authority other than PRUNE_GC/STABLE or NONE/STABLE with a selected side is the empty plan.
func PlanRecoveryIntentMDBX(reader *mdbx.Reader) (ReplayRecoveryPlanV1, error) {
	a, err := reader.ReadStorageAuthorityV1()
	if err != nil {
		return ReplayRecoveryPlanV1{}, err
	}
	if !replayRecoveryIntentDomain(a) {
		return ReplayRecoveryPlanV1{}, nil
	}
	if a.SelectedSide != nil {
		return replayRecoveryIntentSide(reader)
	}
	return replayRecoveryIntentOnly(a)
}

func replayRecoveryIntentDomain(a mdbx.StorageAuthorityV1) bool {
	if a.Lifecycle != mdbx.StorageLifecycleStableV1 {
		return false
	}
	return a.Phase == mdbx.StoragePhasePruneGCV1 || a.Phase == mdbx.StoragePhaseNoneV1 && a.SelectedSide != nil
}

// replayRecoveryIntentSide keeps the clear planner's Batch and Consulted and changes only its authority literal.
func replayRecoveryIntentSide(reader *mdbx.Reader) (ReplayRecoveryPlanV1, error) {
	plan, err := PlanSelectedSideClearMDBX(reader)
	if err != nil {
		return ReplayRecoveryPlanV1{ReadResource: plan.ReadResource}, err
	}
	cleared, err := mdbx.DecodeStorageAuthorityV1(plan.Batch.Mutations[0].Literal)
	if err != nil {
		return ReplayRecoveryPlanV1{}, selectedSideIllegal()
	}
	literal, err := replayRecoveryIntentLiteral(cleared)
	if err != nil {
		return ReplayRecoveryPlanV1{}, err
	}
	plan.Batch.Mutations[0].Literal = literal
	return ReplayRecoveryPlanV1{Batch: plan.Batch}, nil
}

// replayRecoveryIntentOnly is the one-mutation intent without a selected side; Consulted is empty.
func replayRecoveryIntentOnly(a mdbx.StorageAuthorityV1) (ReplayRecoveryPlanV1, error) {
	literal, err := replayRecoveryIntentLiteral(a)
	if err != nil {
		return ReplayRecoveryPlanV1{}, err
	}
	return ReplayRecoveryPlanV1{Batch: replayRecoveryAuthorityBatch(literal, nil)}, nil
}

func replayRecoveryIntentLiteral(a mdbx.StorageAuthorityV1) ([]byte, error) {
	profile := a.ActiveProfile
	a.Lifecycle, a.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &profile
	return selectedSideEncode(a)
}

func replayRecoveryAuthorityBatch(literal []byte, consulted []mdbx.ConsultedRow) mdbx.Batch {
	meta := mdbx.SchemaV2DBIs()[0]
	return mdbx.Batch{
		Mutations: []mdbx.Mutation{{DBI: meta, Key: []byte{0x02}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: literal}},
		Consulted: consulted,
	}
}

// PlanDirectReplayEntryMDBX plans the direct header-qualified replay-target entry on NONE/STABLE with no selected side
// and a positive-height active identity (MP 1704-1706, 2618-2639) through the merged inventory, walk, selection,
// protection and entry plan with the inventory share invLimit(limit). The release is non-nil exactly when ProtectV1
// returned one; the caller runs it exactly once after its Update.
func (o *ReplayEntryOwnerV1) PlanDirectReplayEntryMDBX(reader *mdbx.Reader, limit uint64) (ReplayRecoveryPlanV1, func(), error) {
	a, proceed, plan, err := o.directEntryGates(reader, limit)
	if !proceed {
		return plan, nil, err
	}
	call := &replayEntryCall{owner: o, sentinel: errors.New("direct replay entry decision"), lane: limit}
	plan, err = replayRecoveryDirect(call, reader, a)
	return plan, call.release, err
}

// directEntryGates is (h1)-(h6): context, LANE_MAX, authority, domain, minimum share and the step-1 identity page;
// proceed is true only for NONE/STABLE with no selected side and an H>0 identity.
func (o *ReplayEntryOwnerV1) directEntryGates(reader *mdbx.Reader, limit uint64) (mdbx.StorageAuthorityV1, bool, ReplayRecoveryPlanV1, error) {
	a, done, err := o.replayRecoveryGates(reader, limit)
	switch {
	case done:
		return a, false, ReplayRecoveryPlanV1{}, err
	case a.Phase != mdbx.StoragePhaseNoneV1 || a.Lifecycle != mdbx.StorageLifecycleStableV1 || a.SelectedSide != nil:
		return a, false, ReplayRecoveryPlanV1{}, nil
	case limit < replayRecoveryMinBytes:
		return a, false, ReplayRecoveryPlanV1{}, replayRecoveryRefusal(selectedSideCapacity, "replay entry share below the minimum")
	}
	identity, site, err := replayEntryIdentity(reader, a.ActiveGenerationID)
	return a, err == nil && identity == 2, ReplayRecoveryPlanV1{ReadResource: site}, err
}

// replayRecoveryDirect is (h7)-(h12) through the merged qualifyAndPlan; a decided outcome becomes its refusal.
func replayRecoveryDirect(call *replayEntryCall, reader *mdbx.Reader, a mdbx.StorageAuthorityV1) (ReplayRecoveryPlanV1, error) {
	batch, err := call.qualifyAndPlan(reader, a, 'b')
	switch {
	case errors.Is(err, call.sentinel):
		return ReplayRecoveryPlanV1{}, replayRecoveryRefusal(call.result, "direct replay entry refused")
	case err != nil:
		return ReplayRecoveryPlanV1{ReadResource: call.step}, err
	}
	return ReplayRecoveryPlanV1{Batch: batch}, nil
}

// replayRecoveryGates is the context check, the LANE_MAX check and the authority read, in that order; done is a
// failed gate whose error is returned.
func (o *ReplayEntryOwnerV1) replayRecoveryGates(reader *mdbx.Reader, limit uint64) (mdbx.StorageAuthorityV1, bool, error) {
	if err := replayEntryContext(o.genesis); err != nil {
		return mdbx.StorageAuthorityV1{}, true, replayRecoveryRefusal(selectedSideInvariant, err.Error())
	}
	if limit > mdbx.MaxOperationDataBytes {
		return mdbx.StorageAuthorityV1{}, true, replayRecoveryRefusal(selectedSideInvariant, "replay share above LANE_MAX")
	}
	a, err := reader.ReadStorageAuthorityV1()
	return a, err != nil, err
}

// PlanReplayTargetConversionMDBX plans the target-to-GENERATION plan change (MP 2508-2512) for a PLAN_CHANGE report
// returned by RecomputeReplayTargetMDBX on this same Reader; any other report is the empty Batch and nil. It reads
// nothing: PRUNE_GC/RECOVERY_REQUIRED, pending = ReplayV1.target_profile, ReplayV1 cleared and CleanupV1 exactly
// {GENERATION(target_generation_id)}; no row is deleted, no counter written and no target index row touched.
func PlanReplayTargetConversionMDBX(reader *mdbx.Reader, report ReplayRecomputationV1) (mdbx.Batch, error) {
	if report.Report != ReplayRecomputationPlanChangeV1 || report.reader == nil || report.reader != reader {
		return mdbx.Batch{}, nil
	}
	a := report.authority
	a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: a.Replay.TargetGenerationID}}}
	profile := a.Replay.TargetProfile
	a.Phase, a.Lifecycle, a.PendingTargetProfile, a.Replay = mdbx.StoragePhasePruneGCV1, mdbx.StorageLifecycleRecoveryRequiredV1, &profile, nil
	literal, err := selectedSideEncode(a)
	if err != nil {
		return mdbx.Batch{}, err
	}
	return replayRecoveryAuthorityBatch(literal, replayEntryConsulted(a.ActiveGenerationID, report.activeTip)), nil
}

// replayTargetLocal is a target-local defect of the target generation's canonical-v1 row at height.
type replayTargetLocal struct{ height uint64 }

func (e *replayTargetLocal) Error() string { return "replay target-local defect" }

// replayRecompute is one recomputation's callback state; step is the in-flight read class.
type replayRecompute struct {
	owner      *ReplayEntryOwnerV1
	reader     *mdbx.Reader
	a          mdbx.StorageAuthorityV1
	rp         mdbx.ReplayV1
	q          *replayQualifier
	step       string
	activeTip  uint64
	activeHash [32]byte
	activeWork big.Int
	activeBad  uint64
	activeN    uint64 // the active walk's end count: H+1, 1 for an established Fork F anchor, 0 for an anchor-less empty index
}

// RecomputeReplayTargetMDBX is the pre-activation recomputation (MP 2789-2803, 2873-2916) at REPLAY with the cursor
// APPLIED at the target height: the active index walk, then the target index stream through the cursor, then
// stitching and selection over the complete candidate set, then the fresh-best-tip and published-comparand
// classification and one ProtectV1. It writes nothing and returns no Batch; any other authority is NOT_APPLICABLE.
func (o *ReplayEntryOwnerV1) RecomputeReplayTargetMDBX(reader *mdbx.Reader, limit uint64) (ReplayRecomputationV1, error) {
	a, done, err := o.replayRecoveryGates(reader, limit)
	switch {
	case done:
		return ReplayRecomputationV1{}, err
	case !replayRecomputeDomain(a):
		return ReplayRecomputationV1{Report: ReplayRecomputationNotApplicableV1}, nil
	}
	r := &replayRecompute{owner: o, reader: reader, a: a, rp: *a.Replay}
	inv, refused, err := r.prepare(limit)
	if err != nil || refused != "" {
		return ReplayRecomputationV1{Report: replayRecomputeRefused(refused), Result: refused}, err
	}
	return r.recompute(inv)
}

func replayRecomputeDomain(a mdbx.StorageAuthorityV1) bool {
	if a.Phase != mdbx.StoragePhaseReplayV1 || a.Replay == nil {
		return false
	}
	cursor := a.Replay.Cursor
	return cursor.Kind == mdbx.ReplayCursorAppliedV1 && cursor.Height == a.Replay.Target.TipHeight
}

func replayRecomputeRefused(result string) ReplayRecomputationReportV1 {
	if result == "" {
		return 0
	}
	return ReplayRecomputationRefusedV1
}

// prepare is (f5)-(f7): the target identity against the context, the minimum share and the inventory status.
func (r *replayRecompute) prepare(limit uint64) (HeaderCandidateInventoryV1, string, error) {
	target, g := r.rp.Target, r.owner.genesis
	switch {
	case target.ChainID != g.ChainID || target.GenesisHash != g.GenesisHash:
		return HeaderCandidateInventoryV1{}, "", selectedSideDefect("replay target identity differs from the context")
	case limit < replayRecoveryMinBytes:
		return HeaderCandidateInventoryV1{}, selectedSideCapacity, nil
	}
	inv, result := replayEntryInventory(r.owner.view, replayInvLimit(limit))
	if result == selectedSideInvariant {
		return inv, "", replayRecoveryRefusal(result, "header candidate inventory producer violation")
	}
	return inv, result, nil
}

// recompute is (f8)-(f13): both streams, then classification, then protection for PLAN_CHANGE/ACTIVATION_ELIGIBLE.
func (r *replayRecompute) recompute(inv HeaderCandidateInventoryV1) (ReplayRecomputationV1, error) {
	r.q = newReplayQualifier(r.owner.genesis, inv, r.a.ExcludedInvalidBranch)
	r.q.atC = r.rp.Target.TipHeight
	tip, err := r.q.walk(r.reader, uint64(r.a.ActiveGenerationID), &r.step)
	if err != nil {
		return ReplayRecomputationV1{ReadResource: r.step}, err
	}
	r.snapshot(tip)
	var local *replayTargetLocal
	if err := r.targetStream(); errors.As(err, &local) {
		key, _ := mdbx.HeightKey(uint64(r.rp.TargetGenerationID), local.height)
		return ReplayRecomputationV1{Report: ReplayRecomputationTargetLocalV1, Evidence: mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[2], Key: key}}, nil
	} else if err != nil {
		return ReplayRecomputationV1{ReadResource: r.step}, err
	}
	report := r.classify()
	if report == ReplayRecomputationRefusedV1 {
		return ReplayRecomputationV1{Report: report, Result: replayEntryRecovery}, nil
	}
	return r.protect(inv.Version, report)
}

// snapshot keeps the active stream's end state, which selection and the comparand read after the target stream.
func (r *replayRecompute) snapshot(tip uint64) {
	r.activeTip, r.activeHash, r.activeBad, r.activeN = tip, r.q.hash, r.q.badFrom, r.q.count
	r.activeWork.Set(&r.q.work)
}

// targetStream is (f9): the target generation's canonical index ascending, T1-T7 per row, then End and the tip attach.
func (r *replayRecompute) targetStream() error {
	q := r.q
	q.hash, q.target, q.count, q.badFrom = [32]byte{}, [32]byte{}, 0, math.MaxUint64
	q.work.SetInt64(0)
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], uint64(r.rp.TargetGenerationID))
	var after []byte
	for {
		r.step = replayEntryRecovery
		page, err := r.reader.PrefixPage(mdbx.SchemaV2DBIs()[2], prefix[:], after, replayEntryPageRows, uint64(replayEntryPageRows)*120)
		if err != nil {
			return err
		}
		r.step = ""
		if err := r.targetRows(page.Rows); err != nil {
			return err
		}
		if page.Stop == mdbx.PrefixPageExhausted || len(page.Rows) == 0 {
			break
		}
		after = page.Rows[len(page.Rows)-1].Key
	}
	return r.targetEnd()
}

func (r *replayRecompute) targetRows(rows []mdbx.PrefixRow) error {
	for _, row := range rows {
		if err := r.targetRow(row); err != nil {
			return err
		}
	}
	return nil
}

// targetEnd is the End row, the received branches on T and T's own candidacy with the target chain's eligibility.
func (r *replayRecompute) targetEnd() error {
	q, target := r.q, r.rp.Target
	if q.count != target.TipHeight+1 {
		return selectedSideDefect("replay target index ends below the cursor")
	}
	q.attach(q.hash, [32]byte{})
	q.consider(target.TipHash, target.TipHeight, target.CumulativeChainwork, q.badFrom <= target.TipHeight)
	q.hash, q.count, q.badFrom = r.activeHash, r.activeN, r.activeBad
	q.work.Set(&r.activeWork)
	return nil
}

// targetRow is T1-T7 for one target index row; the first positive observation ends the recomputation.
func (r *replayRecompute) targetRow(row mdbx.PrefixRow) error {
	q := r.q
	h := binary.BigEndian.Uint64(row.Key[8:])
	hash, parent := [32]byte(row.Value[:32]), [32]byte(row.Value[32:64])
	if err := r.targetTuple(h, hash); err != nil {
		return err
	}
	if h != q.count {
		return &replayTargetLocal{height: q.count}
	}
	header, raw, err := r.targetHeader(hash)
	if err != nil {
		return err
	}
	if parent != header.PrevBlockHash || h > 0 && parent != q.hash {
		return &replayTargetLocal{height: h}
	}
	work, err := r.targetWork(h, header, row.Value[64:104])
	if err != nil {
		return err
	}
	return r.targetAdvance(h, hash, raw, header, work)
}

// targetTuple is T1 (a row above the cursor) and T2 (the genesis and tip identities).
func (r *replayRecompute) targetTuple(h uint64, hash [32]byte) error {
	target := r.rp.Target
	switch {
	case h > target.TipHeight:
		return selectedSideDefect("replay target index row above the cursor")
	case h == 0 && hash != r.owner.genesis.GenesisHash, h == target.TipHeight && hash != target.TipHash:
		return selectedSideDefect("replay target index identity mismatch")
	}
	return nil
}

// targetHeader is T4: a transient read is the error; absent, unparsable or misnamed bytes are nonlocalizable.
func (r *replayRecompute) targetHeader(hash [32]byte) (BlockHeader, []byte, error) {
	r.step = replayEntryRecovery
	raw, present, err := r.reader.Get(mdbx.SchemaV2DBIs()[3], hash[:])
	if err != nil {
		return BlockHeader{}, nil, err
	}
	r.step = ""
	header, parseErr := ParseBlockHeaderBytes(raw)
	blockHash, hashErr := BlockHash(raw)
	if !present || parseErr != nil || hashErr != nil || blockHash != hash {
		return header, nil, selectedSideDefect("replay target header absent or misnamed")
	}
	return header, raw, nil
}

// targetWork is T6: the block work, the tuple chainwork at c first, then the stored work domain and value.
func (r *replayRecompute) targetWork(h uint64, header BlockHeader, stored []byte) (*big.Int, error) {
	work, err := r.targetComputed(h, header)
	if err != nil {
		return nil, err
	}
	if !archiveSelectedSideWork(stored) || work.BitLen() > 320 || replayEntryWork(work) != [40]byte(stored) {
		return nil, &replayTargetLocal{height: h}
	}
	return work, nil
}

// targetComputed is computed(h); a zero-target header is target-local only strictly between 0 and c.
func (r *replayRecompute) targetComputed(h uint64, header BlockHeader) (*big.Int, error) {
	c := r.rp.Target.TipHeight
	blockWork, err := r.q.blockWork(header.Target)
	switch {
	case err != nil && (h == 0 || h == c):
		return nil, selectedSideDefect("replay target header target zero")
	case err != nil:
		return nil, &replayTargetLocal{height: h}
	}
	work := new(big.Int).Add(blockWork, &r.q.work)
	if h == 0 {
		work.Set(blockWork)
	}
	if h == c && !replayRecomputeTupleWork(work, r.rp.Target) {
		return nil, selectedSideDefect("replay target tuple chainwork mismatch")
	}
	return work, nil
}

// replayRecomputeTupleWork is computed(c) equal to the tuple's cumulative_chainwork (a value above 320 bits differs).
func replayRecomputeTupleWork(work *big.Int, target mdbx.RecoveryTargetV1) bool {
	return work.BitLen() <= 320 && replayEntryWork(work) == target.CumulativeChainwork
}

// targetAdvance is T7 (D10 and the exclusion decide eligibility, never a defect), the attach of received branches on
// the previous entry, E3 target identities and listed target-identity tips counted once across both indexes.
func (r *replayRecompute) targetAdvance(h uint64, hash [32]byte, raw []byte, header BlockHeader, work *big.Int) error {
	q := r.q
	if h > 0 {
		q.attach(q.hash, hash)
	}
	if !q.canonicalOK(h, raw, header) || q.isExcluded(hash) {
		q.badFrom = min(q.badFrom, h)
	}
	q.hash, q.target, q.count = hash, header.Target, h+1
	q.work.Set(work)
	q.ring[h%WINDOW_SIZE] = header.Timestamp
	encoded := replayEntryWork(work)
	if i := q.find(hash); i >= 0 {
		q.nodes[i].flags |= replayNodeE3 | replayNodeReached
		q.nodes[i].height, q.nodes[i].work = h, encoded
	}
	listed, err := r.targetTip(h, hash)
	if listed {
		q.consider(hash, h, encoded, q.badFrom <= h)
	}
	return err
}

// targetTip reports whether hash is a listed tip; an unsupplied one is counted for E1 unless the active index or the
// Fork F anchor already counted it (the same hash at the same height).
func (r *replayRecompute) targetTip(h uint64, hash [32]byte) (bool, error) {
	q := r.q
	if _, listed := slices.BinarySearchFunc(q.tips, hash, replayHashCompare); !listed || q.find(hash) >= 0 {
		return listed, nil
	}
	shared, err := r.activeHas(h, hash)
	if err == nil && !shared {
		q.canonTips++
	}
	return err == nil, err
}

// activeHas reports whether the active index (or the Fork F anchor at an empty index, only when the walk established
// and counted it) holds hash at height h.
// Postconditions: it reads at most one active canonical-v1 row through the caller's Reader in the same transaction,
// adds no Consulted row, and holds one transient owned copy of that row's value (Reader.Get, at most 104 bytes),
// dropped on return and never retained; it fits the 512-byte identity term the recomputation does not spend on an
// identity page beside its 240-byte chain state (capacity_boundary). A read failure is returned unchanged with the
// in-flight class recovery_artifact.
func (r *replayRecompute) activeHas(h uint64, hash [32]byte) (bool, error) {
	switch {
	case r.q.indexEmpty:
		return r.activeN == 1 && h == 0 && hash == r.activeHash, nil
	case h > r.activeTip:
		return false, nil
	}
	key, _ := mdbx.HeightKey(uint64(r.a.ActiveGenerationID), h)
	r.step = replayEntryRecovery
	value, present, err := r.reader.Get(mdbx.SchemaV2DBIs()[2], key)
	if err != nil {
		return false, err
	}
	r.step = ""
	return present && len(value) >= 32 && [32]byte(value[:32]) == hash, nil
}

// classify is (f10)-(f12): stitching and selection, then the fresh best tip F and the published OLD comparand P.
func (r *replayRecompute) classify() ReplayRecomputationReportV1 {
	q := r.q
	if _, ok, result := q.selectTarget(); result != "" || !ok {
		return ReplayRecomputationRefusedV1
	}
	if !r.descends(q.best) {
		return ReplayRecomputationPlanChangeV1
	}
	if p := r.comparand(); p.ok && replayRecomputeOutranks(p, r.rp.Target) {
		return ReplayRecomputationPlanChangeV1
	}
	return ReplayRecomputationActivationEligibleV1
}

// replayRecomputeOutranks is CAN23 between P and T: greater chainwork, then the lexicographically smaller tip hash.
func replayRecomputeOutranks(p replayCandidate, t mdbx.RecoveryTargetV1) bool {
	c := bytes.Compare(p.work[:], t.CumulativeChainwork[:])
	return c > 0 || c == 0 && bytes.Compare(p.hash[:], t.TipHash[:]) < 0
}

// comparand is P: the published prefix tip markBad recorded, else the eligible active canonical tip, else none.
func (r *replayRecompute) comparand() replayCandidate {
	switch {
	case r.q.comparand.ok:
		return r.q.comparand
	case r.activeBad == math.MaxUint64 && !r.q.indexEmpty:
		return replayCandidate{ok: true, hash: r.activeHash, height: r.activeTip, work: replayEntryWork(&r.activeWork)}
	}
	return replayCandidate{}
}

// descends is hash linkage of F's header ancestry to T through received headers, the active index or the target index.
func (r *replayRecompute) descends(f replayCandidate) bool {
	if f.hash == r.rp.Target.TipHash {
		return true
	}
	if i := r.q.find(f.hash); i >= 0 && r.q.nodes[i].flags&replayNodeE3 == 0 {
		return r.receivedDescends(i)
	}
	return r.identityDescends(f.height)
}

// identityDescends: an index identity other than T descends from T only above c on an active index through T.
func (r *replayRecompute) identityDescends(h uint64) bool {
	return h > r.rp.Target.TipHeight && r.q.hasAtC && r.q.hashAtC == r.rp.Target.TipHash
}

// receivedDescends climbs received parents to the attach point, then decides on the identity it attaches to.
func (r *replayRecompute) receivedDescends(i int) bool {
	q, tip := r.q, r.rp.Target.TipHash
	for {
		if q.nodes[i].hash == tip {
			return true
		}
		p := q.receivedParent(i)
		if p < 0 {
			break
		}
		i = p
	}
	return q.parentOf(i) == tip || r.identityDescends(q.nodes[i].height-1)
}

// protect is (f13): ProtectV1 exactly once with the inventory Version; STALE replaces the classified report.
func (r *replayRecompute) protect(version uint64, report ReplayRecomputationReportV1) (ReplayRecomputationV1, error) {
	current, release := r.owner.view.ProtectV1(version)
	if release == nil {
		return ReplayRecomputationV1{}, replayRecoveryRefusal(selectedSideInvariant, "header candidate view returned no release")
	}
	out := ReplayRecomputationV1{Report: report, Release: release, reader: r.reader, authority: r.a, activeTip: r.activeTip}
	if !current {
		out.Report, out.Result = ReplayRecomputationStaleV1, replayEntryStale
	}
	return out, nil
}
