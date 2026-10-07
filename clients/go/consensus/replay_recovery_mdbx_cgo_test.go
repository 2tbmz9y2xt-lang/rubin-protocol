//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

const replayRecoveryM uint64 = 3_550_822 // capacity_boundary M, from the contract text

var errRecoverySentinel = errors.New("recovery test sentinel")

// recoveryTarget is a seeded target generation 2: hashes[h] and headers[h] for h = 0..c.
type recoveryTarget struct {
	headers [][116]byte
	hashes  [][32]byte
}

// targetFrom is the active prefix 0..k followed by n target-only headers forked at k.
func (w *replayWorld) targetFrom(k, n int) recoveryTarget {
	headers, hashes := w.fork(k, n, 1) // the skew keeps the target-only headers off the active chain
	return recoveryTarget{headers: append(append([][116]byte{}, w.headers[:k+1]...), headers...), hashes: append(append([][32]byte{}, w.hashes[:k+1]...), hashes...)}
}

// seedTarget writes the target index rows 0..len-1 of generation 2 (work = height+1), their owner rows and every
// header absent from the active chain; edit may rewrite or drop (nil) a row value.
func (w *replayWorld) seedTarget(tg recoveryTarget, edit func(h uint64, value []byte) []byte) {
	var rows []mdbx.Mutation
	for h := range tg.hashes {
		parent := [32]byte{}
		if h > 0 {
			parent = tg.hashes[h-1]
		}
		value := mdbx.ChainValue(tg.hashes[h], parent, sideWorldWork(uint64(h)+1))
		if edit != nil {
			value = edit(uint64(h), value)
		}
		if value != nil {
			rows = append(rows,
				mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(2, uint64(h))), AfterKind: mdbx.AfterLiteral, Literal: value},
				mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(2, [32]byte(value[:32]))), AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(uint64(h))})
		}
		if !recoveryHas(w.hashes, tg.hashes[h]) {
			rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(tg.hashes[h][:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(tg.headers[h][:])})
		}
	}
	w.apply(rows...)
}

func recoveryHas(hashes [][32]byte, hash [32]byte) bool {
	for _, h := range hashes {
		if h == hash {
			return true
		}
	}
	return false
}

// replayAt seeds REPLAY/RECOVERY_REQUIRED at APPLIED(c, T) with target ARCHIVE, g_t = 2 and next = 3.
func (w *replayWorld) replayAt(tg recoveryTarget) {
	c := uint64(len(tg.hashes) - 1)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Phase, a.Lifecycle, a.NextGenerationID, a.PendingTargetProfile = mdbx.StoragePhaseReplayV1, mdbx.StorageLifecycleRecoveryRequiredV1, 3, nil
		a.Replay = &mdbx.ReplayV1{
			TargetProfile:      mdbx.StorageProfileArchiveV1,
			TargetGenerationID: 2,
			Target:             mdbx.RecoveryTargetV1{ChainID: w.genesis.ChainID, GenesisHash: w.genesis.GenesisHash, TipHash: tg.hashes[c], TipHeight: c, CumulativeChainwork: sideWorldWork(c + 1)},
			Cursor:             mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: c, BlockHash: tg.hashes[c]},
		}
	})
}

// recoveryWorld is active 0..4 of generation 1 and the target 0..3 + 4..6 of generation 2 at APPLIED(6).
func recoveryWorld(t *testing.T, edit func(h uint64, value []byte) []byte) (*replayWorld, recoveryTarget) {
	w := newReplayWorld(t, 4)
	tg := w.targetFrom(3, 3)
	w.seedTarget(tg, edit)
	w.replayAt(tg)
	return w, tg
}

// recompute runs the recomputation (and the conversion on its report) in one Update; commit returns the conversion.
func (w *replayWorld) recompute(view *replayView, limit uint64, commit bool) (ReplayRecomputationV1, mdbx.Batch, error, error) {
	var rep ReplayRecomputationV1
	var conv mdbx.Batch
	var err error
	owner := NewReplayEntryOwnerV1(view, w.genesis)
	if view == nil {
		owner = NewReplayEntryOwnerV1(nil, w.genesis)
	}
	_, _, uerr := w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		rep, err = owner.RecomputeReplayTargetMDBX(r, limit)
		var cerr error
		conv, cerr = PlanReplayTargetConversionMDBX(r, rep)
		if commit && cerr == nil {
			return conv, nil
		}
		return mdbx.Batch{}, errRecoverySentinel
	})
	return rep, conv, err, uerr
}

func recoveryClass(err error, step string) string {
	return replayEntryCauses(err, &replayEntryCall{step: step})
}

func recoveryReport(t *testing.T, w *replayWorld, view *replayView, want ReplayRecomputationReportV1, label string) ReplayRecomputationV1 {
	t.Helper()
	image := w.image()
	rep, _, err, _ := w.recompute(view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err == nil && rep.Report == want, "%s: report %d err %v want %d", label, rep.Report, err, want)
	replaySameImage(t, image, w.image(), label)
	if rep.Release != nil {
		rep.Release()
	}
	return rep
}

func recoveryIntegrity(t *testing.T, w *replayWorld, view *replayView, label string) {
	t.Helper()
	rep, _, err, _ := w.recompute(view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, rep.ReadResource) == selectedSideIntegrity && rep.Report == 0 && rep.Release == nil,
		"%s: %+v %v", label, rep, err)
	logicalMDBXAssert(t, len(view.versions) == 0, "%s: ProtectV1 calls %d", label, len(view.versions))
}

// A11, A12, A21, A22: PLAN_CHANGE and its committed conversion, ACTIVATION_ELIGIBLE without the branch; the view
// returns a distinct Version on every call and ProtectV1 receives the Version of the same call's inventory.
func TestReplayRecomputePlanChangeConversion(t *testing.T) {
	w, _ := recoveryWorld(t, nil)
	headers, hashes := w.fork(2, 7, 3) // tip height 9, work 10 > T's 7, forks below c
	view := &replayView{inv: replayComplete([][32]byte{hashes[6]}, headers), distinct: true}
	image := w.image()
	rep, _, err, _ := w.recompute(view, mdbx.MaxOperationDataBytes, false) // A21: read-only
	logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationPlanChangeV1 && rep.Result == "" && rep.Evidence.Key == nil && rep.Release != nil, "A21: %+v %v", rep, err)
	logicalMDBXAssert(t, view.calls == 1 && len(view.versions) == 1 && view.versions[0] == view.issued[0] && view.releases == 0, "A21/A22 view: %+v", view)
	rep.Release()
	logicalMDBXAssert(t, view.releases == 1, "A21 release runs %d", view.releases)
	replaySameImage(t, image, w.image(), "A21")
	before := w.authority()
	rep, conv, err, uerr := w.recompute(view, mdbx.MaxOperationDataBytes, true)
	// The batch shape is asserted before the commit outcome, so a wrong Consulted row fails here and not as a refused Update.
	logicalMDBXAssert(t, len(conv.Mutations) == 1 && len(conv.ObsoleteDeletes) == 0 && len(conv.Consulted) == 4, "A11 batch: %+v", conv)
	for i, h := range []uint64{0, 1, 4, 5} {
		logicalMDBXAssert(t, conv.Consulted[i].DBI == logicalMDBXDBIs[2] && bytes.Equal(conv.Consulted[i].Key, logicalMDBXMust(mdbx.HeightKey(1, h))), "A11 consulted %d", i)
	}
	logicalMDBXAssert(t, err == nil && uerr == nil && rep.Report == ReplayRecomputationPlanChangeV1 && rep.Result == "" && reflect.DeepEqual(rep.Evidence, mdbx.ConsultedRow{}) && rep.Release != nil, "A11: %+v %v %v", rep, err, uerr)
	logicalMDBXAssert(t, view.calls == 2 && len(view.versions) == 2 && view.issued[0] != view.issued[1] && view.versions[1] == view.issued[1] && view.limits[1] == 71_815_566, "A11/A22 view: %+v", view)
	want := before
	archive := mdbx.StorageProfileArchiveV1
	want.Phase, want.Lifecycle, want.PendingTargetProfile, want.Replay = mdbx.StoragePhasePruneGCV1, mdbx.StorageLifecycleRecoveryRequiredV1, &archive, nil
	want.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 2}}}
	got := w.authority()
	logicalMDBXAssert(t, reflect.DeepEqual(got, want) && got.NextGenerationID == 3 && got.ActiveGenerationID == 1, "A11 authority: %+v want %+v", got, want)
	after := w.image()
	logicalMDBXAssert(t, len(after) == len(image), "A11 image rows %d %d", len(after), len(image))
	for i := range after {
		same := bytes.Equal(after[i].Key, image[i].Key) && bytes.Equal(after[i].Value, image[i].Value)
		logicalMDBXAssert(t, same || bytes.Equal(after[i].Key, []byte{0, 2}), "A11 row %x changed", after[i].Key)
	}
	logicalMDBXAssert(t, view.releases == 1, "A11: the release ran inside Update (%d runs)", view.releases)
	rep.Release()
	logicalMDBXAssert(t, view.releases == 2, "A11: release runs %d", view.releases)
	// A12: the same world without the branch.
	w2, _ := recoveryWorld(t, nil)
	view2 := &replayView{inv: replayComplete(nil, nil), distinct: true}
	rep2 := recoveryReport(t, w2, view2, ReplayRecomputationActivationEligibleV1, "A12")
	logicalMDBXAssert(t, rep2.Result == "" && reflect.DeepEqual(rep2.Evidence, mdbx.ConsultedRow{}) && view2.calls == 1 && len(view2.versions) == 1 && view2.versions[0] == view2.issued[0] && view2.releases == 1, "A12/A22: %+v %+v", rep2, view2)
}

// recoveryConversionEmpty runs the recomputation and then the conversion planner on its report in one callback and
// asserts the report value and that the conversion returns the empty Batch and nil.
func recoveryConversionEmpty(t *testing.T, w *replayWorld, view *replayView, limit uint64, want ReplayRecomputationReportV1, label string) {
	t.Helper()
	var rep ReplayRecomputationV1
	var batch mdbx.Batch
	var rerr, cerr error
	_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		rep, rerr = NewReplayEntryOwnerV1(view, w.genesis).RecomputeReplayTargetMDBX(r, limit)
		batch, cerr = PlanReplayTargetConversionMDBX(r, rep)
		return mdbx.Batch{}, errRecoverySentinel
	})
	logicalMDBXAssert(t, rerr == nil && rep.Report == want && cerr == nil && reflect.ValueOf(batch).IsZero(), "%s: report %d %v conversion %+v %v", label, rep.Report, rerr, batch, cerr)
	zero := want == ReplayRecomputationNotApplicableV1 || limit < replayRecoveryM // H29: NOT_APPLICABLE and (f6)
	logicalMDBXAssert(t, view.calls <= 1 && len(view.versions) <= 1 && (!zero || view.calls+len(view.versions) == 0), "%s H29 view: %+v", label, view)
	if rep.Release != nil {
		rep.Release()
	}
}

// R20, R20b: the conversion planner returns the empty Batch and nil on every report other than a PLAN_CHANGE report
// returned on the same Reader.
func TestReplayRecomputeConversionRefusals(t *testing.T) {
	below, tg := recoveryWorld(t, nil)
	below.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: 5, BlockHash: tg.hashes[5]}
	})
	recoveryConversionEmpty(t, below, recoveryEmpty(), mdbx.MaxOperationDataBytes, ReplayRecomputationNotApplicableV1, "R20 NOT_APPLICABLE")
	w, _ := recoveryWorld(t, nil)
	recoveryConversionEmpty(t, w, &replayView{inv: HeaderCandidateInventoryV1{Status: HeaderCandidateIncompleteV1}}, mdbx.MaxOperationDataBytes, ReplayRecomputationRefusedV1, "R20 REFUSED recovery_artifact")
	recoveryConversionEmpty(t, w, recoveryEmpty(), replayRecoveryM-1, ReplayRecomputationRefusedV1, "R20 REFUSED storage_capacity")
	gap, _ := recoveryWorld(t, func(h uint64, v []byte) []byte {
		if h == 3 {
			return nil
		}
		return v
	})
	recoveryConversionEmpty(t, gap, recoveryEmpty(), mdbx.MaxOperationDataBytes, ReplayRecomputationTargetLocalV1, "R20 TARGET_LOCAL")
	recoveryConversionEmpty(t, w, &replayView{inv: replayComplete(nil, nil), stale: true}, mdbx.MaxOperationDataBytes, ReplayRecomputationStaleV1, "R20 STALE")
	recoveryConversionEmpty(t, w, recoveryEmpty(), mdbx.MaxOperationDataBytes, ReplayRecomputationActivationEligibleV1, "R20 ACTIVATION_ELIGIBLE")
	_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		for _, report := range []ReplayRecomputationV1{{}, {Report: ReplayRecomputationPlanChangeV1}} {
			b, err := PlanReplayTargetConversionMDBX(r, report)
			logicalMDBXAssert(t, err == nil && reflect.ValueOf(b).IsZero(), "R20b: %+v %v", b, err)
		}
		return mdbx.Batch{}, errRecoverySentinel
	})
	// R20b: a PLAN_CHANGE report from an earlier callback.
	headers, hashes := w.fork(2, 7, 3)
	view := recoveryTips([][32]byte{hashes[6]}, headers)
	var earlier ReplayRecomputationV1
	_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		earlier, _ = NewReplayEntryOwnerV1(view, w.genesis).RecomputeReplayTargetMDBX(r, mdbx.MaxOperationDataBytes)
		return mdbx.Batch{}, errRecoverySentinel
	})
	logicalMDBXAssert(t, earlier.Report == ReplayRecomputationPlanChangeV1, "R20b premise %+v", earlier)
	earlier.Release()
	_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		b, err := PlanReplayTargetConversionMDBX(r, earlier)
		logicalMDBXAssert(t, err == nil && reflect.ValueOf(b).IsZero(), "R20b earlier: %+v %v", b, err)
		return mdbx.Batch{}, errRecoverySentinel
	})
}

// A15, R28, R35, R55: domain, capacity and target identity refusals with zero view calls.
func TestReplayRecomputeGates(t *testing.T) {
	w, tg := recoveryWorld(t, nil)
	view := &replayView{inv: replayComplete(nil, nil)}
	rep, _, err, _ := w.recompute(view, replayRecoveryM-1, false)
	logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationRefusedV1 && rep.Result == selectedSideCapacity && view.calls == 0 && len(view.versions) == 0, "R35: %+v %v", rep, err)
	rep, _, err, _ = w.recompute(view, mdbx.MaxOperationDataBytes+1, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, rep.ReadResource) == selectedSideInvariant && view.calls == 0 && len(view.versions) == 0, "R34: %+v %v", rep, err)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.ChainID[0] ^= 1 })
	rep, _, err, _ = w.recompute(view, replayRecoveryM-1, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, rep.ReadResource) == selectedSideIntegrity && view.calls == 0 && len(view.versions) == 0, "R55/R61: %+v %v", rep, err)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Replay.Target.ChainID[0] ^= 1
		a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorPreGenesisV1}
	})
	rep, _, err, _ = w.recompute(view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationNotApplicableV1 && rep.Release == nil && view.calls == 0 && len(view.versions) == 0, "A15: %+v %v", rep, err)
	w2 := pendingWorld(t, 4)
	rep, _, err, _ = w2.recompute(view, replayRecoveryM-1, false)
	logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationNotApplicableV1 && view.calls == 0 && len(view.versions) == 0, "R28/R35: %+v %v", rep, err)
	_ = tg
}

// R29, R29b, R31: inventory status and protection outcomes.
func TestReplayRecomputeViewOutcomes(t *testing.T) {
	w, _ := recoveryWorld(t, nil)
	for _, c := range []struct {
		status HeaderCandidateStatusV1
		result string
	}{{HeaderCandidateIncompleteV1, replayEntryRecovery}, {HeaderCandidateCapacityRefusedV1, selectedSideCapacity}} {
		view := &replayView{inv: HeaderCandidateInventoryV1{Status: c.status}}
		rep, _, err, _ := w.recompute(view, mdbx.MaxOperationDataBytes, false)
		logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationRefusedV1 && rep.Result == c.result && len(view.versions) == 0, "R29: %+v", rep)
	}
	rep, _, err, _ := w.recompute(nil, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationRefusedV1 && rep.Result == replayEntryRecovery, "R29 nil view: %+v", rep)
	stale := &replayView{inv: replayComplete(nil, nil), stale: true}
	rep, _, err, _ = w.recompute(stale, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationStaleV1 && rep.Result == replayEntryStale && rep.Release != nil, "R31: %+v", rep)
	rep.Release()
	logicalMDBXAssert(t, stale.releases == 1, "R31 release")
	for _, current := range []bool{true, false} {
		nilRel := &replayView{inv: replayComplete(nil, nil), nilRelease: true, stale: !current}
		rep, _, err, _ = w.recompute(nilRel, mdbx.MaxOperationDataBytes, false)
		logicalMDBXAssert(t, err != nil && recoveryClass(err, rep.ReadResource) == selectedSideInvariant && rep.Release == nil && rep.Report == 0 && len(nilRel.versions) == 1,
			"R29c nil release current=%v: %+v %v", current, rep, err)
	}
}

// A23, A21b, A21d: rebuild, a descendant of T, an outranking branch forking at a target-only entry.
func TestReplayRecomputeDescent(t *testing.T) {
	w := newReplayWorld(t, 5)
	tg := recoveryTarget{headers: w.headers, hashes: w.hashes}
	w.seedTarget(tg, nil)
	w.replayAt(tg)
	recoveryReport(t, w, &replayView{inv: replayComplete(nil, nil)}, ReplayRecomputationActivationEligibleV1, "A23")

	w2, tg2 := recoveryWorld(t, nil)
	up, upHashes := replayChain(t, tg2.hashes[6], binary64(tg2.headers[6]), 2)
	recoveryReport(t, w2, &replayView{inv: replayComplete([][32]byte{upHashes[1]}, up)}, ReplayRecomputationActivationEligibleV1, "A21b")
	side, sideHashes := replayChain(t, tg2.hashes[5], binary64(tg2.headers[5])+1, 3)
	recoveryReport(t, w2, &replayView{inv: replayComplete([][32]byte{sideHashes[2]}, side)}, ReplayRecomputationPlanChangeV1, "A21d")
	less, lessHashes := w2.fork(2, 2, 3) // tip height 4, work 5 < 7
	recoveryReport(t, w2, &replayView{inv: replayComplete([][32]byte{lessHashes[1]}, less)}, ReplayRecomputationActivationEligibleV1, "A26")
}

func binary64(h [116]byte) uint64 {
	return uint64(h[68]) | uint64(h[69])<<8 | uint64(h[70])<<16 | uint64(h[71])<<24 | uint64(h[72])<<32 | uint64(h[73])<<40 | uint64(h[74])<<48 | uint64(h[75])<<56
}

// A30, A31, A33, A34: target-local defects with Evidence and no protection.
func TestReplayRecomputeTargetLocal(t *testing.T) {
	cases := []struct {
		label string
		at    uint64
		edit  func(h uint64, v []byte) []byte
	}{
		{"A30 gap", 3, func(h uint64, v []byte) []byte {
			if h == 3 {
				return nil
			}
			return v
		}},
		{"A31 parent vs header", 2, func(h uint64, v []byte) []byte {
			if h == 2 {
				v[40] ^= 1
			}
			return v
		}},
		{"A33 work zero", 2, func(h uint64, v []byte) []byte {
			if h == 2 {
				copy(v[64:104], make([]byte, 40))
			}
			return v
		}},
		{"A34 work differs", 2, func(h uint64, v []byte) []byte {
			if h == 2 {
				w := sideWorldWork(9)
				copy(v[64:104], w[:])
			}
			return v
		}},
		{"A35 work at c", 6, func(h uint64, v []byte) []byte {
			if h == 6 {
				w := sideWorldWork(9)
				copy(v[64:104], w[:])
			}
			return v
		}},
	}
	for _, c := range cases {
		w, _ := recoveryWorld(t, c.edit)
		view := &replayView{inv: replayComplete(nil, nil)}
		rep := recoveryReport(t, w, view, ReplayRecomputationTargetLocalV1, c.label)
		key := logicalMDBXMust(mdbx.HeightKey(2, c.at))
		logicalMDBXAssert(t, rep.Evidence.DBI == logicalMDBXDBIs[2] && bytes.Equal(rep.Evidence.Key, key) && rep.Result == "" && rep.Release == nil && len(view.versions) == 0 && view.calls == 1,
			"%s: evidence %x", c.label, rep.Evidence.Key)
	}
}

// A32, A38, R52: the T5 link to the previous accepted row, a T5 defect before a T2 defect at c, an absent target-only
// header.
func TestReplayRecomputeTargetLinks(t *testing.T) {
	// A32: the height-2 entry names a header whose PrevBlockHash is x, and its stored parent is x too, so only the
	// link to the accepted height-1 hash disagrees.
	w := newReplayWorld(t, 4)
	tg := w.targetFrom(3, 3)
	x := [32]byte{0x77}
	tg.headers[2], tg.hashes[2] = replayHeader(t, x, POW_LIMIT, binary64(tg.headers[2]))
	logicalMDBXAssert(t, tg.hashes[2] != w.hashes[2] && x != tg.hashes[1], "A32 premise")
	w.seedTarget(tg, func(h uint64, v []byte) []byte {
		if h == 2 {
			copy(v[32:64], x[:])
		}
		return v
	})
	w.replayAt(tg)
	view := recoveryEmpty()
	rep := recoveryReport(t, w, view, ReplayRecomputationTargetLocalV1, "A32")
	logicalMDBXAssert(t, rep.Evidence.DBI == logicalMDBXDBIs[2] && bytes.Equal(rep.Evidence.Key, logicalMDBXMust(mdbx.HeightKey(2, 2))) && rep.Release == nil && len(view.versions) == 0,
		"A32: evidence %x", rep.Evidence.Key)
	// A38 first world: a T5 defect at height 2 and a T2 defect at c.
	w, _ = recoveryWorld(t, func(h uint64, v []byte) []byte {
		switch h {
		case 2:
			v[40] ^= 1
		case 6:
			v[0] ^= 1
		}
		return v
	})
	rep = recoveryReport(t, w, recoveryEmpty(), ReplayRecomputationTargetLocalV1, "A38 T5 before T2 at c")
	logicalMDBXAssert(t, rep.Evidence.DBI == logicalMDBXDBIs[2] && bytes.Equal(rep.Evidence.Key, logicalMDBXMust(mdbx.HeightKey(2, 2))), "A38 evidence %x", rep.Evidence.Key)
	// R52: a target-only entry whose header row is absent.
	w, tg = recoveryWorld(t, nil)
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(tg.hashes[5][:]), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	recoveryIntegrity(t, w, recoveryEmpty(), "R52 header absent")
}

// H29: the recomputation's InventoryV1 limit argument is invLimit(limit).
func TestReplayRecomputeInventoryLimit(t *testing.T) {
	for _, c := range []struct{ limit, inv uint64 }{{replayRecoveryM, 0}, {replayRecoveryM + 244, 116}, {mdbx.MaxOperationDataBytes, 71_815_566}} {
		w, _ := recoveryWorld(t, nil)
		view := recoveryEmpty()
		rep, _, err, _ := w.recompute(view, c.limit, false)
		logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationActivationEligibleV1 && view.calls == 1 && view.limits[0] == c.inv && len(view.versions) == 1,
			"H29 %d: %+v %v %v", c.limit, rep, err, view.limits)
		rep.Release()
	}
}

// R48, R50, R51, R54: nonlocalizable target defects.
func TestReplayRecomputeTargetIntegrity(t *testing.T) {
	w, tg := recoveryWorld(t, nil)
	extra, extraHashes := replayChain(t, tg.hashes[6], binary64(tg.headers[6]), 1)
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(2, 7)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(extraHashes[0], tg.hashes[6], sideWorldWork(8))},
		mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(2, extraHashes[0])), AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(7)},
		mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(extraHashes[0][:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(extra[0][:])})
	recoveryIntegrity(t, w, &replayView{inv: replayComplete(nil, nil)}, "R48")
	w2, _ := recoveryWorld(t, func(h uint64, v []byte) []byte {
		if h == 6 {
			return nil
		}
		return v
	})
	w2.setAuthority(func(a *mdbx.StorageAuthorityV1) {}) // the tuple stays at 6
	recoveryIntegrity(t, w2, &replayView{inv: replayComplete(nil, nil)}, "R51")
	w3, _ := recoveryWorld(t, nil)
	w3.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.CumulativeChainwork = sideWorldWork(8) })
	recoveryIntegrity(t, w3, &replayView{inv: replayComplete(nil, nil)}, "R54")
}

// A17, A17b, R45: the recovery intent without a selected side.
func TestPlanRecoveryIntent(t *testing.T) {
	w := newReplayWorld(t, 4)
	plan := recoveryIntent(t, w)
	logicalMDBXAssert(t, reflect.ValueOf(plan).IsZero(), "R45 NONE/STABLE: %+v", plan)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Phase, a.B, a.U = mdbx.StoragePhasePruneGCV1, 10, 13_690
		a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanBlocksV1, GenerationID: 1, FirstHeight: 1, LastHeight: 3, NextHeight: 2}}}
	})
	before := w.authority()
	plan = recoveryIntent(t, w)
	logicalMDBXAssert(t, len(plan.Batch.Mutations) == 1 && len(plan.Batch.Consulted) == 0 && plan.ReadResource == "", "A17: %+v", plan)
	_, _, err := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return plan.Batch, nil })
	want := before
	pruned := mdbx.StorageProfilePrunedV1
	want.Lifecycle, want.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &pruned
	logicalMDBXAssert(t, err == nil && reflect.DeepEqual(w.authority(), want), "A17 commit: %v %+v", err, w.authority())
	plan = recoveryIntent(t, w)
	logicalMDBXAssert(t, reflect.ValueOf(plan).IsZero(), "R45 PRUNE_GC/RECOVERY_REQUIRED: %+v", plan)
	// R45: NONE/RECOVERY_REQUIRED, REPLAY and ORDINARY_APPLY each return the empty plan with ReadResource empty.
	replay, _ := recoveryWorld(t, nil)
	ordinary := newReplayWorld(t, 4)
	ordinary.setAuthority(recoveryOrdinaryApply)
	for _, c := range []struct {
		label string
		w     *replayWorld
	}{{"NONE/RECOVERY_REQUIRED", pendingWorld(t, 4)}, {"REPLAY", replay}, {"ORDINARY_APPLY/RECOVERY_REQUIRED", ordinary}} {
		image := c.w.image()
		plan = recoveryIntent(t, c.w)
		logicalMDBXAssert(t, reflect.ValueOf(plan).IsZero(), "R45 %s: %+v", c.label, plan)
		replaySameImage(t, image, c.w.image(), "R45 "+c.label)
	}
}

func recoveryIntent(t *testing.T, w *replayWorld) ReplayRecoveryPlanV1 {
	t.Helper()
	var plan ReplayRecoveryPlanV1
	var err error
	_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		plan, err = PlanRecoveryIntentMDBX(r)
		return mdbx.Batch{}, errRecoverySentinel
	})
	logicalMDBXAssert(t, err == nil, "intent: %v", err)
	return plan
}

// A20, A20b, A20c, R13-class domain rows, R38, R39: the direct entry planner.
func TestPlanDirectReplayEntry(t *testing.T) {
	w := newReplayWorld(t, 5)
	headers, hashes := w.fork(3, 4, 0) // tip height 7, work 8
	view := &replayView{inv: replayComplete([][32]byte{hashes[3]}, headers)}
	before := w.snapshot()
	pre := w.image()
	plan, release, err := recoveryDirect(w, view, mdbx.MaxOperationDataBytes, true)
	logicalMDBXAssert(t, err == nil && release != nil && plan.ReadResource == "" && view.calls == 1 && view.limits[0] == 71_815_566 && len(view.versions) == 1, "A20: %+v %v %+v", plan, err, view)
	logicalMDBXAssert(t, view.releases == 0, "A20: the release ran inside Update")
	release()
	logicalMDBXAssert(t, view.releases == 1, "A20: release runs %d", view.releases)
	want, encoded, counterKey := replayExpected(t, w, before, mdbx.StorageProfilePrunedV1, hashes[3], 7, 8)
	got := w.authority()
	logicalMDBXAssert(t, reflect.DeepEqual(got, want) && got.PendingTargetProfile == nil && got.NextGenerationID == 3, "A20 authority: %+v want %+v", got, want)
	recoveryEntryImage(t, pre, w.image(), encoded, counterKey)
	logicalMDBXAssert(t, len(plan.Batch.Mutations) == 2 && len(plan.Batch.Consulted) == 4, "A20 batch rows: %+v", plan.Batch)
	for i, h := range []uint64{0, 1, 5, 6} {
		logicalMDBXAssert(t, plan.Batch.Consulted[i].DBI == logicalMDBXDBIs[2] && bytes.Equal(plan.Batch.Consulted[i].Key, logicalMDBXMust(mdbx.HeightKey(1, h))), "A20 consulted %d", i)
	}
	for _, c := range []struct{ limit, inv uint64 }{{replayRecoveryM, 0}, {replayRecoveryM + 244, 116}} {
		w2 := newReplayWorld(t, 5)
		v2 := &replayView{inv: replayComplete(nil, nil)}
		plan, release, err = recoveryDirect(w2, v2, c.limit, false)
		logicalMDBXAssert(t, err == nil && release != nil && len(plan.Batch.Mutations) == 2 && v2.limits[0] == c.inv, "A20b/c %d: %+v %v %v", c.limit, plan, err, v2.limits)
		release()
		planned, derr := mdbx.DecodeStorageAuthorityV1(plan.Batch.Mutations[0].Literal)
		logicalMDBXAssert(t, derr == nil && planned.Replay != nil && planned.Replay.Target.TipHash == w2.hashes[5] && planned.Replay.Target.TipHeight == 5,
			"A20b/c %d: the target is not the active canonical tip at H = 5: %+v %v", c.limit, planned.Replay, derr)
	}
	w3 := newReplayWorld(t, 5)
	v3 := &replayView{inv: replayComplete(nil, nil)}
	plan, release, err = recoveryDirect(w3, v3, replayRecoveryM-1, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, plan.ReadResource) == selectedSideCapacity && release == nil && v3.calls == 0 && len(v3.versions) == 0, "R37-class: %v", err)
	plan, release, err = recoveryDirect(w3, v3, mdbx.MaxOperationDataBytes+1, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, plan.ReadResource) == selectedSideInvariant && release == nil && v3.calls == 0 && len(v3.versions) == 0, "R38: %v", err)
	for _, tip := range []int{-1, 0} {
		w4 := newReplayWorld(t, tip)
		plan, release, err = recoveryDirect(w4, v3, mdbx.MaxOperationDataBytes, false)
		logicalMDBXAssert(t, err == nil && release == nil && len(plan.Batch.Mutations) == 0 && v3.calls == 0 && len(v3.versions) == 0, "R39 %d: %+v %v", tip, plan, err)
	}
	replay, _ := recoveryWorld(t, nil)
	for _, c := range []struct {
		label string
		w     *replayWorld
	}{{"NONE/RECOVERY_REQUIRED", pendingWorld(t, 5)}, {"REPLAY", replay}} {
		for _, limit := range []uint64{mdbx.MaxOperationDataBytes, replayRecoveryM - 1} {
			plan, release, err = recoveryDirect(c.w, v3, limit, false)
			logicalMDBXAssert(t, err == nil && release == nil && reflect.ValueOf(plan).IsZero() && v3.calls == 0 && len(v3.versions) == 0, "R40 %s %d: %+v %v", c.label, limit, plan, err)
		}
	}
	stale := &replayView{inv: replayComplete(nil, nil), stale: true}
	plan, release, err = recoveryDirect(newReplayWorld(t, 5), stale, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, plan.ReadResource) == replayEntryStale && release != nil, "R42: %v", err)
	release()
}

// recoveryEntryImage asserts that a committed (h) plan changed the pre-image only in the authority row (the encoded
// literal), the new meta 0x10 target counter row (LogicalCounterValue(0,0), written absent) and the meta entry count.
func recoveryEntryImage(t *testing.T, pre, post []mdbx.PrefixRow, encoded, counterKey []byte) {
	t.Helper()
	rows := map[string][]byte{}
	for _, row := range pre {
		rows[string(row.Key)] = row.Value
	}
	counter := string(append([]byte{0}, counterKey...))
	_, existed := rows[counter]
	logicalMDBXAssert(t, !existed, "A20: the counter row was present before the commit")
	counts := bytes.Clone(rows[string([]byte{0xff})])
	binary.BigEndian.PutUint64(counts[:8], binary.BigEndian.Uint64(counts[:8])+1)
	rows[string([]byte{0xff})], rows[string([]byte{0, 2})], rows[counter] = counts, encoded, mdbx.LogicalCounterValue(0, 0)
	same := len(post) == len(rows)
	for _, row := range post {
		value, ok := rows[string(row.Key)]
		same = same && ok && bytes.Equal(value, row.Value)
	}
	logicalMDBXAssert(t, same, "A20 mutation set: %d rows after, %d expected", len(post), len(rows))
}

func recoveryDirect(w *replayWorld, view *replayView, limit uint64, commit bool) (ReplayRecoveryPlanV1, func(), error) {
	var plan ReplayRecoveryPlanV1
	var release func()
	var err error
	_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		plan, release, err = NewReplayEntryOwnerV1(view, w.genesis).PlanDirectReplayEntryMDBX(r, limit)
		if commit && err == nil {
			return plan.Batch, nil
		}
		return mdbx.Batch{}, errRecoverySentinel
	})
	return plan, release, err
}

// H27, H28: exported shape pins; the four signatures take no target tuple, flag, candidate subset or cursor.
func TestReplayRecoveryExportedShape(t *testing.T) {
	plan := reflect.TypeFor[ReplayRecoveryPlanV1]()
	logicalMDBXAssert(t, plan.NumField() == 2 && plan.Field(0).Name == "Batch" && plan.Field(0).Type == reflect.TypeFor[mdbx.Batch]() &&
		plan.Field(1).Name == "ReadResource" && plan.Field(1).Type == reflect.TypeFor[string](), "ReplayRecoveryPlanV1 %v", plan)
	rec := reflect.TypeFor[ReplayRecomputationV1]()
	var exported []string
	for i := range rec.NumField() {
		if rec.Field(i).IsExported() {
			exported = append(exported, rec.Field(i).Name+" "+rec.Field(i).Type.String())
		}
	}
	logicalMDBXAssert(t, reflect.DeepEqual(exported, []string{"Report consensus.ReplayRecomputationReportV1", "Result string", "Evidence mdbx.ConsultedRow", "Release func()", "ReadResource string"}), "fields %v", exported)
	logicalMDBXAssert(t, ReplayRecomputationNotApplicableV1 == 1 && ReplayRecomputationRefusedV1 == 2 && ReplayRecomputationTargetLocalV1 == 3 &&
		ReplayRecomputationStaleV1 == 4 && ReplayRecomputationPlanChangeV1 == 5 && ReplayRecomputationActivationEligibleV1 == 6, "report constants")
	logicalMDBXAssert(t, reflect.TypeOf(PlanRecoveryIntentMDBX).String() == "func(*mdbx.Reader) (consensus.ReplayRecoveryPlanV1, error)" &&
		reflect.TypeOf(PlanReplayTargetConversionMDBX).String() == "func(*mdbx.Reader, consensus.ReplayRecomputationV1) (mdbx.Batch, error)" &&
		reflect.TypeOf((*ReplayEntryOwnerV1).PlanDirectReplayEntryMDBX).String() == "func(*consensus.ReplayEntryOwnerV1, *mdbx.Reader, uint64) (consensus.ReplayRecoveryPlanV1, func(), error)" &&
		reflect.TypeOf((*ReplayEntryOwnerV1).RecomputeReplayTargetMDBX).String() == "func(*consensus.ReplayEntryOwnerV1, *mdbx.Reader, uint64) (consensus.ReplayRecomputationV1, error)", "H27/H28 signatures")
	logicalMDBXAssert(t, replayRecoveryMinBytes == replayRecoveryM && replayRecoveryIntentBytes == 11_665_408 && replayInvLimit(mdbx.MaxOperationDataBytes) == 71_815_566, "capacity constants")
}

func recoveryEmpty() *replayView { return &replayView{inv: replayComplete(nil, nil)} }

// rebuildWorld is active 0..tip of generation 1 with the target index replicating 0..c (T = the active entry at c).
func rebuildWorld(t *testing.T, tip, c int) *replayWorld {
	w := newReplayWorld(t, tip)
	tg := recoveryTarget{headers: w.headers[:c+1], hashes: w.hashes[:c+1]}
	w.seedTarget(tg, nil)
	w.replayAt(tg)
	return w
}

// A27, A27b, A27d: the published OLD comparand P is compared with T whether or not it descends from T.
func TestReplayRecomputeComparand(t *testing.T) {
	recoveryReport(t, rebuildWorld(t, 7, 5), recoveryEmpty(), ReplayRecomputationPlanChangeV1, "A27 P strictly descends from T")
	// The D10 world fails CAN22 at height 6 only; T = the active entry at c, so the mark is at c+1 for c = 5 and at
	// c+3 for c = 3.
	headers := replayD10Headers(t)
	d10Rebuild := func(c int) *replayWorld {
		w := defectWorld(t, headers, replayKeep)
		w.seedReplay(recoveryTarget{headers: w.headers[:c+1], hashes: w.hashes[:c+1]})
		return w
	}
	recoveryReport(t, d10Rebuild(5), recoveryEmpty(), ReplayRecomputationActivationEligibleV1, "A27b D10 at c+1: P = T")
	recoveryReport(t, d10Rebuild(3), recoveryEmpty(), ReplayRecomputationPlanChangeV1, "A27d D10 at c+3: P at c+2")
	// The same dispositions with the mark seeded through the exclusion.
	w := rebuildWorld(t, 8, 5)
	replayExclude(w, 6)
	recoveryReport(t, w, recoveryEmpty(), ReplayRecomputationActivationEligibleV1, "A27b exclusion P = T")
	w = rebuildWorld(t, 8, 5)
	replayExclude(w, 8)
	recoveryReport(t, w, recoveryEmpty(), ReplayRecomputationPlanChangeV1, "A27d exclusion P at c+2")
}

// A24, A25: a received tip with T's chainwork wins only with the lexicographically smaller hash.
func TestReplayRecomputeTie(t *testing.T) {
	w, tg := recoveryWorld(t, nil)
	found := map[bool]bool{}
	for skew := uint64(3); len(found) < 2 && skew < 200; skew++ {
		headers, hashes := w.fork(2, 4, skew) // tip height 6, work 7 = T's
		smaller := bytes.Compare(hashes[3][:], tg.hashes[6][:]) < 0
		if found[smaller] {
			continue
		}
		found[smaller] = true
		want := ReplayRecomputationActivationEligibleV1
		if smaller {
			want = ReplayRecomputationPlanChangeV1
		}
		recoveryReport(t, w, &replayView{inv: replayComplete([][32]byte{hashes[3]}, headers)}, want, "A24/A25")
	}
	logicalMDBXAssert(t, len(found) == 2, "tie premise: %v", found)
}

// A29: a listed shared-prefix identity tip, and a target-only identity tip, without headers, each count once.
func TestReplayRecomputeSingleCount(t *testing.T) {
	w, tg := recoveryWorld(t, nil)
	recoveryReport(t, w, &replayView{inv: replayComplete([][32]byte{tg.hashes[2]}, nil)}, ReplayRecomputationActivationEligibleV1, "A29 shared")
	recoveryReport(t, w, &replayView{inv: replayComplete([][32]byte{tg.hashes[5]}, nil)}, ReplayRecomputationActivationEligibleV1, "A29 target-only")
	// The target-only entry at 4 shares its height with the active tip but not its hash: counted once, by the target.
	recoveryReport(t, w, &replayView{inv: replayComplete([][32]byte{tg.hashes[4]}, nil)}, ReplayRecomputationActivationEligibleV1, "A29 target-only at an active height")
	orphan, _ := replayHeader(t, [32]byte{9}, POW_LIMIT, 1)
	for label, view := range map[string]*replayView{"R30 E1": recoveryTips([][32]byte{{7}}, nil), "R30 E2": recoveryTips(nil, [][116]byte{orphan})} {
		rep := recoveryReport(t, w, view, ReplayRecomputationRefusedV1, label)
		logicalMDBXAssert(t, rep.Result == replayEntryRecovery && rep.Release == nil && len(view.versions) == 0, "%s: %+v", label, rep)
	}
}

// genesisTargetWorld is an empty active index (PRE_GENESIS) with the target index 0..c from the published genesis.
func genesisTargetWorld(t *testing.T, c int) (*replayWorld, recoveryTarget) {
	w := newReplayWorld(t, -1)
	headers, hashes := replayChain(t, w.genesis.GenesisHash, w.lastTime, c)
	tg := recoveryTarget{headers: append([][116]byte{w.headers[0]}, headers...), hashes: append([][32]byte{w.genesis.GenesisHash}, hashes...)}
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(w.genesis.GenesisHash[:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(w.headers[0][:])})
	w.seedTarget(tg, nil)
	w.replayAt(tg)
	return w, tg
}

// A39, A39b, A39c: an empty active index has no comparand; the anchor and the target genesis entry count once.
func TestReplayRecomputeEmptyActive(t *testing.T) {
	w, _ := genesisTargetWorld(t, 4)
	recoveryReport(t, w, recoveryEmpty(), ReplayRecomputationActivationEligibleV1, "A39")
	recoveryReport(t, w, &replayView{inv: replayComplete([][32]byte{w.genesis.GenesisHash}, nil)}, ReplayRecomputationActivationEligibleV1, "A39c")
	// A39c identity-only: no anchor is established, so the accepted target genesis entry counts the tip once.
	w.genesis = replayIdentityOnly()
	recoveryReport(t, w, &replayView{inv: replayComplete([][32]byte{w.genesis.GenesisHash}, nil)}, ReplayRecomputationActivationEligibleV1, "A39c identity-only")
	w.genesis = replayGenesis()
	headers, hashes := replayChain(t, w.genesis.GenesisHash, w.lastTime+7, 6)
	view := &replayView{inv: replayComplete([][32]byte{hashes[5]}, headers)}
	rep, conv, err, _ := w.recompute(view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationPlanChangeV1 && len(conv.Consulted) == 2 &&
		conv.Consulted[0].DBI == logicalMDBXDBIs[2] && conv.Consulted[1].DBI == logicalMDBXDBIs[2] &&
		bytes.Equal(conv.Consulted[0].Key, logicalMDBXMust(mdbx.HeightKey(1, 0))) && bytes.Equal(conv.Consulted[1].Key, logicalMDBXMust(mdbx.HeightKey(1, 1))), "A39b: %+v %+v %v", rep, conv, err)
	rep.Release()
}

// A21c, A21e: received copies of target-only entries are target identities; a header-qualified received chain is
// never compared.
func TestReplayRecomputeReceivedIdentities(t *testing.T) {
	w, tg := recoveryWorld(t, nil)
	up, upHashes := replayChain(t, tg.hashes[6], binary64(tg.headers[6]), 3)
	copies := append(append([][116]byte{}, tg.headers[4:7]...), up...)
	recoveryReport(t, w, &replayView{inv: replayComplete([][32]byte{upHashes[2]}, copies)}, ReplayRecomputationActivationEligibleV1, "A21c")
	// A21c: copies of target entries 5..6 whose parent 4 is target-only and unsupplied are reached only as target
	// identities (not unattached lowest headers, E2); the listed supplied copy of T is not counted for E1.
	upper := append(append([][116]byte{}, tg.headers[5:7]...), up...)
	recoveryReport(t, w, recoveryTips([][32]byte{upHashes[2], tg.hashes[6]}, upper), ReplayRecomputationActivationEligibleV1, "A21c copies above a target-only parent")
	x, xHashes := w.fork(2, 6, 5) // tip height 8, work 9: between T's 7 and U's 10
	both := append(append([][116]byte{}, up...), x...)
	view := recoveryTips([][32]byte{upHashes[2], xHashes[5]}, both)
	recoveryReport(t, w, view, ReplayRecomputationActivationEligibleV1, "A21e")
	logicalMDBXAssert(t, view.calls == 1 && len(view.versions) == 1 && view.versions[0] == 7, "A21e: ProtectV1 calls %v", view.versions)
}

// R47, R50, R52, R57, A38: first-observation order of the active stream, T1-T7 and End.
func TestReplayRecomputeOrder(t *testing.T) {
	gap := func(h uint64, v []byte) []byte {
		if h == 3 {
			return nil
		}
		return v
	}
	w, _ := recoveryWorld(t, gap)
	value := mdbx.ChainValue(w.hashes[2], w.hashes[1], [40]byte{})
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(1, 2)), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: value},
		mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, w.hashes[2])), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(2)})
	recoveryIntegrity(t, w, recoveryEmpty(), "R47 active before target")
	w, _ = recoveryWorld(t, func(h uint64, v []byte) []byte {
		if h >= 3 && h <= 5 {
			return nil
		}
		if h == 6 {
			copy(v[:32], v[32:64])
		}
		return v
	})
	recoveryIntegrity(t, w, recoveryEmpty(), "R50 T2 before T3")
	// R57: the height-0 row names a self-authenticating header X other than genesis whose PrevBlockHash differs from
	// the stored zero parent, so T5 alone would give TARGET_LOCAL and only T2 first gives integrity.
	x, xHash := replayHeader(t, [32]byte{5}, POW_LIMIT, 1)
	w, _ = recoveryWorld(t, func(h uint64, v []byte) []byte {
		if h == 0 {
			copy(v[:32], xHash[:])
		}
		return v
	})
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(xHash[:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(x[:])})
	recoveryIntegrity(t, w, recoveryEmpty(), "R57 T2 before T5")
	w, tg := recoveryWorld(t, func(h uint64, v []byte) []byte {
		if h == 5 {
			v[40] ^= 1
		}
		return v
	})
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(tg.hashes[5][:]), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	recoveryIntegrity(t, w, recoveryEmpty(), "R52 T4 before T5")
	w, _ = recoveryWorld(t, func(h uint64, v []byte) []byte {
		switch h {
		case 2:
			v[40] ^= 1
		case 6:
			return nil
		}
		return v
	})
	rep := recoveryReport(t, w, recoveryEmpty(), ReplayRecomputationTargetLocalV1, "A38 rows before End")
	logicalMDBXAssert(t, rep.Evidence.DBI == logicalMDBXDBIs[2] && bytes.Equal(rep.Evidence.Key, logicalMDBXMust(mdbx.HeightKey(2, 2))), "A38 evidence %x", rep.Evidence.Key)
}

// A19, R46: the intent with a selected side is the clear planner's Batch with only the authority literal changed.
func TestPlanRecoveryIntentSide(t *testing.T) {
	w := newSideWorld(t, sideFullSpec)
	var clear SelectedSidePlanV1
	var intent ReplayRecoveryPlanV1
	var cerr, ierr error
	_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) { // A19: the reference in a separate sentinel Update
		clear, cerr = PlanSelectedSideClearMDBX(r)
		return mdbx.Batch{}, errRecoverySentinel
	})
	_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		intent, ierr = PlanRecoveryIntentMDBX(r)
		return mdbx.Batch{}, errRecoverySentinel
	})
	logicalMDBXAssert(t, cerr == nil && ierr == nil && intent.ReadResource == "" && intent.ReadResource == clear.ReadResource && len(intent.Batch.Mutations) == len(clear.Batch.Mutations) &&
		reflect.DeepEqual(intent.Batch.Consulted, clear.Batch.Consulted) && reflect.DeepEqual(intent.Batch.Mutations[1:], clear.Batch.Mutations[1:]), "A19 batch: %+v", intent)
	want, err := mdbx.DecodeStorageAuthorityV1(clear.Batch.Mutations[0].Literal)
	logicalMDBXAssert(t, err == nil, "A19 decode: %v", err)
	profile := want.ActiveProfile
	want.Lifecycle, want.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &profile
	got, err := mdbx.DecodeStorageAuthorityV1(intent.Batch.Mutations[0].Literal)
	logicalMDBXAssert(t, err == nil && reflect.DeepEqual(got, want) && got.SelectedSide == nil && got.Phase == mdbx.StoragePhasePruneGCV1, "A19 literal: %+v want %+v", got, want)
	_, _, err = w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return intent.Batch, nil })
	logicalMDBXAssert(t, err == nil, "A19 commit: %v", err)
	// A19: leaving row 3 names canonical block 0, a kept reference; leaving row 2 is named by nothing else.
	w = newSideWorld(t, sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 1, override: map[uint64]uint64{3: 0}})
	unkept, kept := w.sideAt[2], w.canonical[0]
	_ = w.store.View(func(r *mdbx.Reader) error {
		_, before, berr := r.Get(logicalMDBXDBIs[3], unkept[:])
		_, isLeaving := w.sideAt[3]
		logicalMDBXAssert(t, berr == nil && before && !isLeaving, "A19 pre-state: %v", before)
		return nil
	})
	_, _, err = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		p, perr := PlanRecoveryIntentMDBX(r)
		if perr != nil {
			return mdbx.Batch{}, perr
		}
		return p.Batch, nil
	})
	logicalMDBXAssert(t, err == nil, "A19 kept commit: %v", err)
	_ = w.store.View(func(r *mdbx.Reader) error {
		_, gone, gerr := r.Get(logicalMDBXDBIs[3], unkept[:])
		_, here, herr := r.Get(logicalMDBXDBIs[3], kept[:])
		logicalMDBXAssert(t, gerr == nil && herr == nil && !gone && here, "A19 headers: unkept %v kept %v", gone, here)
		return nil
	})
	// Each world serves one planner: the clear planner's integrity error disarms its Store.
	w = newSideWorld(t, sideFullSpec)
	w.removeLink(3)
	_ = w.store.View(func(r *mdbx.Reader) error { clear, cerr = PlanSelectedSideClearMDBX(r); return nil })
	w = newSideWorld(t, sideFullSpec)
	w.removeLink(3)
	intent, ierr = ReplayRecoveryPlanV1{}, nil
	_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		intent, ierr = PlanRecoveryIntentMDBX(r)
		return mdbx.Batch{}, errRecoverySentinel
	})
	logicalMDBXAssert(t, ierr != nil && ierr.Error() == cerr.Error() && intent.ReadResource == clear.ReadResource && intent.Batch.Mutations == nil, "R46: %+v %v / %v", intent, ierr, cerr)
}

// H26: ProtectV1 occurs once, in protect; a release value only as its := left side, its nil comparison and the
// Release field value, and as the merged call's release field in the (h) return; no defer or go statement.
func TestReplayRecoveryProtectPlacement(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "replay_recovery_mdbx_cgo.go", nil, 0)
	logicalMDBXAssert(t, err == nil, "parse: %v", err)
	got := map[string]int{}
	order := map[string]token.Pos{} // the first classify and protect calls, by calling function
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			ast.Inspect(decl, func(n ast.Node) bool { // no package-level declaration names a release or ProtectV1
				if x, ok := n.(*ast.Ident); ok && (x.Name == "ProtectV1" || x.Name == "release") {
					got["package "+x.Name]++
				}
				return true
			})
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "classify" || sel.Sel.Name == "protect") {
					if _, seen := order[fn.Name.Name+" "+sel.Sel.Name]; !seen {
						order[fn.Name.Name+" "+sel.Sel.Name] = call.Pos()
					}
					got[fn.Name.Name+" calls "+sel.Sel.Name]++
				}
			}
			return true
		})
		ast.Inspect(fn, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if x.Name == "ProtectV1" || x.Name == "release" {
					got[fn.Name.Name+" "+x.Name]++
				}
			case *ast.DeferStmt, *ast.GoStmt:
				got[fn.Name.Name+" defer/go"]++
			}
			return true
		})
	}
	want := map[string]int{"protect ProtectV1": 1, "protect release": 3, "PlanDirectReplayEntryMDBX release": 1, "recompute calls classify": 1, "recompute calls protect": 1}
	logicalMDBXAssert(t, reflect.DeepEqual(got, want), "placement census: %v", got)
	logicalMDBXAssert(t, order["recompute classify"] < order["recompute protect"], "protect is called before the selection step: %v", order)
}

// targetFork is the active prefix 0..k followed by n target-only headers forked at k (timestamps shifted by skew); the
// target-only header at index old (old >= 0) repeats the genesis timestamp, so CAN22 fails there while D1-D9 pass.
func (w *replayWorld) targetFork(k, n int, skew uint64, old int) recoveryTarget {
	w.t.Helper()
	ts := binary.LittleEndian.Uint64(w.headers[k][68:76]) + skew
	tg := recoveryTarget{headers: append([][116]byte{}, w.headers[:k+1]...), hashes: append([][32]byte{}, w.hashes[:k+1]...)}
	for i := range n {
		ts += 2 * TARGET_BLOCK_INTERVAL
		stamp := ts
		if i == old {
			stamp = binary.LittleEndian.Uint64(w.headers[0][68:76])
		}
		header, hash := replayHeader(w.t, tg.hashes[len(tg.hashes)-1], POW_LIMIT, stamp)
		tg.headers, tg.hashes = append(tg.headers, header), append(tg.hashes, hash)
	}
	return tg
}

func (w *replayWorld) seedReplay(tg recoveryTarget) recoveryTarget {
	w.seedTarget(tg, nil)
	w.replayAt(tg)
	return tg
}

// zeroTargetHeader is a header whose all-zero target yields no work (CAN23 work = floor(2^256/target)).
func zeroTargetHeader(parent [32]byte, ts uint64) ([116]byte, [32]byte) {
	var h [116]byte
	binary.LittleEndian.PutUint32(h[:4], 1)
	copy(h[4:36], parent[:])
	binary.LittleEndian.PutUint64(h[68:76], ts)
	hash, _ := BlockHash(h[:])
	return h, hash
}

func recoveryTips(tips [][32]byte, headers [][116]byte) *replayView {
	return &replayView{inv: replayComplete(tips, headers)}
}

// A28, A27c, A28c, A28d, A28b (structural-only dispositions): an outranking non-descendant and the compared comparand.
func TestReplayRecomputeStructural(t *testing.T) {
	setup := func(tip, exclude int) (*replayWorld, recoveryTarget) {
		w := newReplayWorld(t, tip)
		tg := w.seedReplay(w.targetFrom(3, 3)) // c = 6, work 7
		if exclude > 0 {
			replayExclude(w, uint64(exclude))
		}
		return w, tg
	}
	w, tg := setup(8, 0) // active tip 8, work 9, not on T's path
	recoveryReport(t, w, recoveryEmpty(), ReplayRecomputationPlanChangeV1, "A28")
	b, bh := replayChain(t, tg.hashes[6], binary64(tg.headers[6]), 4) // B descends from T, work 11 > P's 9
	recoveryReport(t, w, recoveryTips([][32]byte{bh[3]}, b), ReplayRecomputationPlanChangeV1, "A27c")
	w, tg = setup(10, 9) // P = active 8, work 9 > 7, not listed
	view := recoveryEmpty()
	recoveryReport(t, w, view, ReplayRecomputationPlanChangeV1, "A28c unlisted")
	logicalMDBXAssert(t, len(view.versions) == 1 && view.versions[0] == 7 && view.releases == 1, "A28c protect: %+v", view)
	recoveryReport(t, w, recoveryTips([][32]byte{w.hashes[8]}, nil), ReplayRecomputationPlanChangeV1, "A28c listed")
	b, bh = replayChain(t, tg.hashes[6], binary64(tg.headers[6]), 5) // work 12 > X's 9
	recoveryReport(t, w, recoveryTips([][32]byte{bh[4]}, b), ReplayRecomputationPlanChangeV1, "A28d")
	w, _ = setup(10, 10)
	recoveryReport(t, w, recoveryTips([][32]byte{w.hashes[8]}, nil), ReplayRecomputationPlanChangeV1, "A28b")
	w = rebuildWorld(t, 10, 5)
	replayExclude(w, 10)
	recoveryReport(t, w, recoveryTips([][32]byte{w.hashes[8]}, nil), ReplayRecomputationPlanChangeV1, "A28b T below j")
}

// A41, A42, R33, R32: the comparand is the published prefix tip, never the ineligible published tip; an eligible
// candidate below T still changes the plan; with no eligible candidate the recomputation refuses.
func TestReplayRecomputePrefixComparand(t *testing.T) {
	headers := replayD10Headers(t) // published tip 10 (work 11) ineligible from 6; P = 5, work 6
	d10 := func() *replayWorld { return defectWorld(t, headers, replayKeep) }
	w := d10()
	w.seedReplay(w.targetFork(3, 3, 1, -1)) // T at 6, work 7 > P's 6 < published tip's 11
	recoveryReport(t, w, recoveryEmpty(), ReplayRecomputationActivationEligibleV1, "A41")
	base := d10()
	found := map[bool]bool{}
	for skew := uint64(1); len(found) < 2 && skew < 200; skew++ {
		tg := base.targetFork(3, 2, skew, -1) // T at 5, work 6 = P's
		larger := bytes.Compare(base.hashes[5][:], tg.hashes[5][:]) > 0
		if found[larger] {
			continue
		}
		found[larger] = true
		w = d10()
		w.seedReplay(tg)
		b, bh := replayChain(t, tg.hashes[5], binary64(tg.headers[5]), 2) // B descends from T, work 8
		want := ReplayRecomputationPlanChangeV1
		if larger {
			want = ReplayRecomputationActivationEligibleV1
		}
		recoveryReport(t, w, recoveryTips([][32]byte{bh[1]}, b), want, "A42")
	}
	logicalMDBXAssert(t, len(found) == 2, "A42 premise: %v", found)
	w = newReplayWorld(t, 4)
	w.seedReplay(w.targetFork(3, 3, 1, 0)) // T ineligible from 4; the active tip 4 (work 5 < 7) is eligible
	recoveryReport(t, w, recoveryEmpty(), ReplayRecomputationPlanChangeV1, "R33")
	w = d10()
	w.seedReplay(w.targetFork(3, 5, 1, 0)) // T at 8 ineligible; the only eligible candidate is the unlisted P
	recoveryReport(t, w, recoveryEmpty(), ReplayRecomputationPlanChangeV1, "R33 P only")
	w = newReplayWorld(t, 4) // R33 through the exclusion: the excluded hash is the target-only entry at 4
	tg := w.seedReplay(w.targetFrom(3, 3))
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 4, FirstInvalidBlockHash: tg.hashes[4], ExactConsensusError: []byte("BLOCK_ERR_POW_INVALID")}
	})
	recoveryReport(t, w, recoveryEmpty(), ReplayRecomputationPlanChangeV1, "R33 excluded target-only entry")
	// R33 with an empty active index: T is ineligible from height 3 (CAN22), so a listed target identity is the only
	// candidate; it is eligible at 2 (PLAN_CHANGE) and ineligible at 3 (REFUSED).
	w = newReplayWorld(t, -1)
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(w.genesis.GenesisHash[:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(w.headers[0][:])})
	tg = w.seedReplay(w.targetFork(0, 4, 1, 2))
	recoveryReport(t, w, recoveryTips([][32]byte{tg.hashes[2]}, nil), ReplayRecomputationPlanChangeV1, "R33 listed target identity")
	recoveryReport(t, w, recoveryTips([][32]byte{tg.hashes[3]}, nil), ReplayRecomputationRefusedV1, "R32 listed ineligible target identity")
	w = newReplayWorld(t, -1)
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(w.genesis.GenesisHash[:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(w.headers[0][:])})
	w.seedReplay(w.targetFork(0, 4, 1, 0))
	view := recoveryEmpty()
	rep := recoveryReport(t, w, view, ReplayRecomputationRefusedV1, "R32")
	logicalMDBXAssert(t, rep.Result == replayEntryRecovery && len(view.versions) == 0 && rep.Release == nil, "R32: %+v", rep)
}

// A30b, A33b, A36, A37, R49, R53b, R54b, R54c, R58, R59: further target-stream classes and their order.
func TestReplayRecomputeTargetClasses(t *testing.T) {
	local := func(w *replayWorld, view *replayView, at uint64, label string) {
		t.Helper()
		rep := recoveryReport(t, w, view, ReplayRecomputationTargetLocalV1, label)
		logicalMDBXAssert(t, rep.Evidence.DBI == logicalMDBXDBIs[2] && bytes.Equal(rep.Evidence.Key, logicalMDBXMust(mdbx.HeightKey(2, at))) &&
			rep.Release == nil && len(view.versions) == 0, "%s: %+v", label, rep)
	}
	at := func(height uint64, edit func(v []byte)) func(uint64, []byte) []byte {
		return func(h uint64, v []byte) []byte {
			if h == height {
				if edit == nil {
					return nil
				}
				edit(v)
			}
			return v
		}
	}
	w, tg := recoveryWorld(t, at(3, nil))
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(tg.hashes[4][:]), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	local(w, recoveryEmpty(), 3, "A30b T3 before T4")
	w, _ = recoveryWorld(t, at(2, func(v []byte) {
		clear(v[64:104])
		v[64+3], v[64+39] = 1, 1 // 2^288 + 1
	}))
	local(w, recoveryEmpty(), 2, "A33b work above 2^288")
	w, _ = recoveryWorld(t, at(0, func(v []byte) { v[40] ^= 1 }))
	local(w, recoveryEmpty(), 0, "A37 parent at 0")
	w = newReplayWorld(t, 4)
	tg = w.targetFrom(3, 3)
	tg.headers[5], tg.hashes[5] = zeroTargetHeader(tg.hashes[4], binary64(tg.headers[5]))
	tg.headers[6], tg.hashes[6] = replayHeader(t, tg.hashes[5], POW_LIMIT, binary64(tg.headers[6]))
	w.seedReplay(tg)
	local(w, recoveryEmpty(), 5, "A36 zero-target target-only header")
	w = newReplayWorld(t, 4)
	tg = w.targetFrom(3, 3)
	tg.headers[6], tg.hashes[6] = zeroTargetHeader(tg.hashes[5], binary64(tg.headers[6]))
	w.seedReplay(tg)
	recoveryIntegrity(t, w, recoveryEmpty(), "R53b zero-target header at c")
	// R53b at 0 (structural-only): the context GenesisHash names a zero-target header and the active index is empty.
	w = newReplayWorld(t, -1)
	gh, ghash := zeroTargetHeader([32]byte{}, w.lastTime)
	w.genesis.GenesisHash, w.genesis.Published = ghash, nil // an identity-only context (RE L125-127)
	zh, zhashes := replayChain(t, ghash, w.lastTime, 4)
	zt := recoveryTarget{headers: append([][116]byte{gh}, zh...), hashes: append([][32]byte{ghash}, zhashes...)}
	w.seedTarget(zt, nil)
	w.replayAt(zt)
	recoveryIntegrity(t, w, recoveryEmpty(), "R53b zero-target header at 0")
	other, otherHash := replayHeader(t, [32]byte{1}, POW_LIMIT, 1)
	w, _ = recoveryWorld(t, at(0, func(v []byte) { copy(v[:32], otherHash[:]) }))
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(otherHash[:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(other[:])})
	recoveryIntegrity(t, w, recoveryEmpty(), "R49 height 0 not GenesisHash")
	for _, c := range []struct {
		label string
		edit  func(v []byte)
	}{{"R54 stored work at c differs too", func(v []byte) { w := sideWorldWork(9); copy(v[64:104], w[:]) }}, {"R54b stored work at c out of domain", func(v []byte) { clear(v[64:104]) }}} {
		w, _ = recoveryWorld(t, at(6, c.edit))
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.CumulativeChainwork = sideWorldWork(8) })
		recoveryIntegrity(t, w, recoveryEmpty(), c.label)
	}
	orphan, _ := replayHeader(t, [32]byte{9}, POW_LIMIT, 1)
	w, _ = recoveryWorld(t, at(6, func(v []byte) { v[0] ^= 1 }))
	recoveryIntegrity(t, w, recoveryTips(nil, [][116]byte{orphan}), "R58 E2 with T2 at c")
	w, _ = recoveryWorld(t, at(2, func(v []byte) { v[40] ^= 1 }))
	local(w, recoveryTips(nil, [][116]byte{orphan}), 2, "R59 E2 with T5")
}

// R28b, R28c, R36, R60: domain before (f5), every non-domain authority, the context check, (f5) before the inventory.
func TestReplayRecomputeDomainRows(t *testing.T) {
	w, tg := recoveryWorld(t, nil)
	view := recoveryEmpty()
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: 5, BlockHash: tg.hashes[5]}
	})
	for _, label := range []string{"R28b cursor below tip", "R28b with a foreign ChainID"} {
		rep, _, err, _ := w.recompute(view, mdbx.MaxOperationDataBytes, false)
		logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationNotApplicableV1 && rep.Release == nil && view.calls == 0 && len(view.versions) == 0, "%s: %+v %v", label, rep, err)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.ChainID[0] ^= 1 })
	}
	w2 := newReplayWorld(t, 4)
	cleanup := &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanBlocksV1, GenerationID: 1, FirstHeight: 1, LastHeight: 3, NextHeight: 2}}}
	pruned := mdbx.StorageProfilePrunedV1
	for _, s := range []struct {
		label string
		edit  func(a *mdbx.StorageAuthorityV1)
	}{
		{"NONE/STABLE", func(*mdbx.StorageAuthorityV1) {}},
		{"PRUNE_GC/STABLE", func(a *mdbx.StorageAuthorityV1) {
			a.Phase, a.Cleanup, a.B, a.U = mdbx.StoragePhasePruneGCV1, cleanup, 10, 13_690
		}},
		{"PRUNE_GC/RECOVERY_REQUIRED", func(a *mdbx.StorageAuthorityV1) {
			a.Phase, a.Cleanup, a.B, a.U = mdbx.StoragePhasePruneGCV1, cleanup, 10, 13_690
			a.Lifecycle, a.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &pruned
		}},
		{"ORDINARY_APPLY/RECOVERY_REQUIRED", recoveryOrdinaryApply},
	} {
		w2.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.Phase, a.Lifecycle, a.Cleanup, a.PendingTargetProfile, a.B, a.U = mdbx.StoragePhaseNoneV1, mdbx.StorageLifecycleStableV1, nil, nil, 0, 0
			a.Ordinary = nil
			s.edit(a)
		})
		rep, _, err, _ := w2.recompute(view, mdbx.MaxOperationDataBytes, false)
		logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationNotApplicableV1 && view.calls == 0 && len(view.versions) == 0, "R28c %s: %+v %v", s.label, rep, err)
	}
	bad := *w
	bad.genesis.ChainID = [32]byte{}
	w3, _ := recoveryWorld(t, nil)
	bad.store = w3.store
	rep, _, err, _ := bad.recompute(view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, rep.ReadResource) == selectedSideInvariant && rep.ReadResource == "" && view.calls == 0 && len(view.versions) == 0, "R36 (f): %+v %v", rep, err)
	plan, release, err := recoveryDirect(&bad, view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, plan.ReadResource) == selectedSideInvariant && release == nil && view.calls == 0 && len(view.versions) == 0, "R36 (h): %+v %v", plan, err)
	w3.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.GenesisHash[0] ^= 1 })
	incomplete := &replayView{inv: HeaderCandidateInventoryV1{Status: HeaderCandidateIncompleteV1}}
	rep, _, err, _ = w3.recompute(incomplete, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, rep.ReadResource) == selectedSideIntegrity && incomplete.calls == 0 && len(incomplete.versions) == 0, "R60 / R55 GenesisHash: %+v %v", rep, err)
}

// recoveryOrdinaryApply sets a legal ORDINARY_APPLY/RECOVERY_REQUIRED authority over a newReplayWorld(t, 4) authority.
func recoveryOrdinaryApply(a *mdbx.StorageAuthorityV1) {
	oldPoint, newPoint := mdbx.AuthorityPointV1{Height: 5, BlockHash: [32]byte{0x51}}, mdbx.AuthorityPointV1{Height: 5, BlockHash: [32]byte{0x52}}
	a.Phase, a.Lifecycle, a.NextGenerationID = mdbx.StoragePhaseOrdinaryApplyV1, mdbx.StorageLifecycleRecoveryRequiredV1, 3
	a.Ordinary = &mdbx.OrdinaryApplyV1{
		Stage: mdbx.OrdinaryStageDisconnectV1, Target: newPoint, OldSuffix: []mdbx.AuthorityPointV1{oldPoint}, NewSuffix: []mdbx.AuthorityPointV1{newPoint},
		CapturedSelectedSide: &mdbx.SelectedSideV1{GenerationID: 2, F: 4, TipHeight: 5, TipHash: newPoint.BlockHash, CumulativeChainwork: sideWorldWork(1), RowCount: 1, LogicalBytes: 1},
	}
}

// R13, R27, R41, R41b, R42b, R43, R43b: the direct entry planner's domain and decided refusals.
func TestPlanDirectReplayEntryRefusals(t *testing.T) {
	sw := newSideWorld(t, sideFullSpec)
	view := recoveryEmpty()
	var plan ReplayRecoveryPlanV1
	var release func()
	var err error
	_, _, _ = sw.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		plan, release, err = NewReplayEntryOwnerV1(view, replayGenesis()).PlanDirectReplayEntryMDBX(r, mdbx.MaxOperationDataBytes)
		return mdbx.Batch{}, errRecoverySentinel
	})
	logicalMDBXAssert(t, err == nil && release == nil && len(plan.Batch.Mutations) == 0 && view.calls == 0 && len(view.versions) == 0, "R13: %+v %v", plan, err)
	w := newReplayWorld(t, 4)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Phase, a.B, a.U = mdbx.StoragePhasePruneGCV1, 10, 13_690
		a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanBlocksV1, GenerationID: 1, FirstHeight: 1, LastHeight: 3, NextHeight: 2}}}
	})
	plan, release, err = recoveryDirect(w, view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err == nil && release == nil && len(plan.Batch.Mutations) == 0 && view.calls == 0 && len(view.versions) == 0, "R27 (h): %+v %v", plan, err)
	intent := recoveryIntent(t, w)
	logicalMDBXAssert(t, len(intent.Batch.Mutations) == 1 && len(intent.Batch.Consulted) == 0 && intent.ReadResource == "", "R27 (g): %+v", intent)
	r27, derr := mdbx.DecodeStorageAuthorityV1(intent.Batch.Mutations[0].Literal)
	r27want := w.authority()
	r27profile := r27want.ActiveProfile
	r27want.Lifecycle, r27want.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &r27profile
	logicalMDBXAssert(t, derr == nil && reflect.DeepEqual(r27, r27want), "R27 (g) is not A17's plan: %+v %v", r27, derr)
	refused := func(w *replayWorld, v *replayView, result, label string) {
		t.Helper()
		plan, release, err := recoveryDirect(w, v, mdbx.MaxOperationDataBytes, false)
		logicalMDBXAssert(t, err != nil && recoveryClass(err, plan.ReadResource) == result && release == nil && len(v.versions) == 0 && len(plan.Batch.Mutations) == 0, "%s: %+v %v", label, plan, err)
	}
	refused(newReplayWorld(t, 5), &replayView{inv: HeaderCandidateInventoryV1{Status: HeaderCandidateIncompleteV1}}, replayEntryRecovery, "R41 Incomplete")
	refused(newReplayWorld(t, 5), &replayView{inv: HeaderCandidateInventoryV1{Status: HeaderCandidateCapacityRefusedV1}}, selectedSideCapacity, "R41 CapacityRefused")
	w = newReplayWorld(t, 5)
	replayExclude(w, 1)
	refused(w, recoveryEmpty(), replayEntryRecovery, "R41 no eligible positive-height target")
	defect := func() *replayWorld {
		w := newReplayWorld(t, 5)
		w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(1, 2)), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(w.hashes[2], w.hashes[1], [40]byte{})},
			mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, w.hashes[2])), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(2)})
		return w
	}
	refused(defect(), &replayView{inv: HeaderCandidateInventoryV1{Status: HeaderCandidateIncompleteV1}}, replayEntryRecovery, "R41 Incomplete with a D1-D9 defect")
	v := recoveryEmpty()
	plan, release, err = recoveryDirect(defect(), v, mdbx.MaxOperationDataBytes, false)
	// R41b: a decided D1/D3-D9 refusal above height 0 is returned with the step cleared (RE L651-664, L677-716).
	logicalMDBXAssert(t, err != nil && plan.ReadResource == "" && recoveryClass(err, plan.ReadResource) == selectedSideIntegrity && release == nil && len(v.versions) == 0 && len(plan.Batch.Mutations) == 0, "R41b: %+v %v", plan, err)
	exhausted := func() *replayWorld {
		w := newReplayWorld(t, 5)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.NextGenerationID = math.MaxUint64 })
		return w
	}
	plan, release, err = recoveryDirect(exhausted(), recoveryEmpty(), mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, plan.ReadResource) == selectedSideInvariant && release != nil && len(plan.Batch.Mutations) == 0, "R43: %+v %v", plan, err)
	release()
	plan, release, err = recoveryDirect(exhausted(), &replayView{inv: replayComplete(nil, nil), stale: true}, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, plan.ReadResource) == replayEntryStale && release != nil, "R42 exhausted: %+v %v", plan, err)
	release()
	nilRel := &replayView{inv: replayComplete(nil, nil), nilRelease: true, stale: true}
	plan, release, err = recoveryDirect(newReplayWorld(t, 5), nilRel, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, plan.ReadResource) == selectedSideInvariant && release == nil && len(plan.Batch.Mutations) == 0, "R43b: %+v %v", plan, err)
}

// A17b, A18, A40: pending is the active profile; the detached suffix stays; an empty plan is refused by Store.Update.
func TestPlanRecoveryIntentFields(t *testing.T) {
	cleanup := &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanBlocksV1, GenerationID: 1, FirstHeight: 1, LastHeight: 3, NextHeight: 2}}}
	for _, c := range []struct {
		label string
		edit  func(a *mdbx.StorageAuthorityV1)
	}{
		{"A17b archive", func(a *mdbx.StorageAuthorityV1) {
			a.ActiveProfile, a.B, a.U, a.NextGenerationID = mdbx.StorageProfileArchiveV1, 0, 0, 3
			a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 2}}}
		}},
		{"A18 detached suffix", func(a *mdbx.StorageAuthorityV1) {
			a.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: []mdbx.DetachedSuffixEntryV1{{Height: 4, Hash: [32]byte{4}, BlockBytesLen: 300}}, Cursor: mdbx.AuthorityPointV1{Height: 4, BlockHash: [32]byte{4}}, EntryCount: 1, LogicalBytes: 300}
			a.B, a.U = 10, 13_690
		}},
	} {
		w := newReplayWorld(t, 4)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.Phase, a.Cleanup = mdbx.StoragePhasePruneGCV1, cleanup
			c.edit(a)
		})
		before := w.authority()
		plan := recoveryIntent(t, w)
		_, _, err := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return plan.Batch, nil })
		want := before
		profile := before.ActiveProfile
		want.Lifecycle, want.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &profile
		got := w.authority()
		logicalMDBXAssert(t, err == nil && len(plan.Batch.Mutations) == 1 && len(plan.Batch.Consulted) == 0 && reflect.DeepEqual(got, want) && got.Replay == nil, "%s: %v %+v want %+v", c.label, err, got, want)
	}
	w := newReplayWorld(t, 4)
	image := w.image()
	_, _, err := w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		plan, perr := PlanRecoveryIntentMDBX(r) // NONE/STABLE without a side: the empty plan
		logicalMDBXAssert(t, perr == nil && len(plan.Batch.Mutations) == 0, "A40 premise")
		return plan.Batch, nil
	})
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, errors.As(err, &engine) && engine.Class == mdbx.EngineInvalidInput, "A40: %v", err)
	replaySameImage(t, image, w.image(), "A40")
}

// A19b: a selected side under PRUNE_GC/STABLE with a BLOCKS span: the clear planner's SIDE span follows BLOCKS.
func TestPlanRecoveryIntentSideAfterBlocks(t *testing.T) {
	w := newSideWorld(t, sideFullSpec)
	blocks := mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanBlocksV1, GenerationID: 1, FirstHeight: 0, LastHeight: 0, NextHeight: 0}
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Phase, a.Cleanup, a.B, a.U = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{blocks}}, 10, 13_690
	})
	var intent ReplayRecoveryPlanV1
	var err error
	_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		intent, err = PlanRecoveryIntentMDBX(r)
		return mdbx.Batch{}, errRecoverySentinel
	})
	logicalMDBXAssert(t, err == nil && len(intent.Batch.Mutations) > 0, "A19b: %+v %v", intent, err)
	got, err := mdbx.DecodeStorageAuthorityV1(intent.Batch.Mutations[0].Literal)
	logicalMDBXAssert(t, err == nil && got.SelectedSide == nil && got.Phase == mdbx.StoragePhasePruneGCV1 && got.Lifecycle == mdbx.StorageLifecycleRecoveryRequiredV1 &&
		got.PendingTargetProfile != nil && *got.PendingTargetProfile == got.ActiveProfile && len(got.Cleanup.Spans) == 2 && got.Cleanup.Spans[0] == blocks &&
		got.Cleanup.Spans[1].Kind == mdbx.CleanupSpanSideV1, "A19b literal: %+v %v", got, err)
}

// R29, R29c: an Incomplete inventory refuses before the active walk observes a D1-D9 defect; a producer violation
// (a Complete inventory whose Bytes differ from its listing) is the TERMINAL_LOCAL_INVARIANT(evidence) error.
func TestReplayRecomputeInventoryOrder(t *testing.T) {
	w, _ := recoveryWorld(t, nil)
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(1, 2)), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(w.hashes[2], w.hashes[1], [40]byte{})},
		mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, w.hashes[2])), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(2)})
	view := &replayView{inv: HeaderCandidateInventoryV1{Status: HeaderCandidateIncompleteV1}}
	rep, _, err, _ := w.recompute(view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err == nil && rep.Report == ReplayRecomputationRefusedV1 && rep.Result == replayEntryRecovery && len(view.versions) == 0, "R29 Incomplete with a D1-D9 defect: %+v %v", rep, err)
	w2, _ := recoveryWorld(t, nil)
	bad := replayComplete([][32]byte{{7}}, nil)
	bad.Bytes++
	view = &replayView{inv: bad}
	rep, _, err, _ = w2.recompute(view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, rep.ReadResource) == selectedSideInvariant && rep.Report == 0 && len(view.versions) == 0, "R29c CC-7: %+v %v", rep, err)
	// R29c: every other producer violation the merged check rejects (RE L310-328).
	over := replayComplete([][32]byte{{1}, {2}, {3}, {4}}, nil)
	partial := replayComplete([][32]byte{{7}}, nil)
	partial.Status = HeaderCandidateIncompleteV1
	refusedBytes := partial
	refusedBytes.Status = HeaderCandidateCapacityRefusedV1
	for _, c := range []struct {
		label string
		inv   HeaderCandidateInventoryV1
		limit uint64
	}{
		{"Bytes above the limit", over, replayRecoveryM + 244},
		{"Incomplete with nonzero Bytes", partial, mdbx.MaxOperationDataBytes},
		{"CapacityRefused with nonzero Bytes", refusedBytes, mdbx.MaxOperationDataBytes},
		{"unknown Status", HeaderCandidateInventoryV1{Status: 9}, mdbx.MaxOperationDataBytes},
	} {
		w3, _ := recoveryWorld(t, nil)
		view = &replayView{inv: c.inv}
		rep, _, err, _ = w3.recompute(view, c.limit, false)
		logicalMDBXAssert(t, err != nil && recoveryClass(err, rep.ReadResource) == selectedSideInvariant && rep.Report == 0 && view.calls == 1 && len(view.versions) == 0, "R29c %s: %+v %v", c.label, rep, err)
	}
}

// A16: the converted GENERATION(2) span drains through CleanupGenerationMDBX to NONE/RECOVERY_REQUIRED with pending
// ARCHIVE; the merged entry then allocates target_generation_id 3 with next 4, never 2.
func TestReplayRecomputeConversionDrainThenEntry(t *testing.T) {
	w, _ := recoveryWorld(t, nil)
	// Header-only seeds: the pruned promises B = 10, U = 13,690 lie above every active height, so the drain checks the
	// shared prefix's owned headers and needs no stored body or undo (CG keeps: body at h >= B, undo at h >= U).
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.B, a.U = 10, 13_690 })
	headers, hashes := w.fork(2, 7, 3)
	view := &replayView{inv: replayComplete([][32]byte{hashes[6]}, headers)}
	rep, _, err, uerr := w.recompute(view, mdbx.MaxOperationDataBytes, true)
	logicalMDBXAssert(t, err == nil && uerr == nil && rep.Report == ReplayRecomputationPlanChangeV1, "A16 conversion: %+v %v %v", rep, err, uerr)
	rep.Release()
	for i := 0; ; i++ {
		a := w.authority()
		if a.Phase != mdbx.StoragePhasePruneGCV1 {
			break
		}
		logicalMDBXAssert(t, i < 64, "A16: drain did not finish: %+v", a.Cleanup)
		out := CleanupGenerationMDBX(w.store, w.owner, 1, 1440)
		logicalMDBXAssert(t, out.Err == nil && out.Truth == mdbx.CommitTruthNew, "A16 drain %d: %+v", i, out)
	}
	a := w.authority()
	logicalMDBXAssert(t, a.Phase == mdbx.StoragePhaseNoneV1 && a.Lifecycle == mdbx.StorageLifecycleRecoveryRequiredV1 && a.PendingTargetProfile != nil &&
		*a.PendingTargetProfile == mdbx.StorageProfileArchiveV1 && a.Cleanup == nil && a.NextGenerationID == 3, "A16 drained: %+v", a)
	_ = w.store.View(func(r *mdbx.Reader) error {
		prefix, _ := mdbx.HeightKey(2, 0)
		page, perr := r.PrefixPage(mdbx.SchemaV2DBIs()[2], prefix[:8], nil, 16, 1<<20)
		logicalMDBXAssert(t, perr == nil && len(page.Rows) == 0, "A16: generation 2 index left: %+v %v", page, perr)
		return nil
	})
	out := w.enter(recoveryEmpty(), w.genesis)
	a = w.authority()
	logicalMDBXAssert(t, out.Err == nil && a.Phase == mdbx.StoragePhaseReplayV1 && a.Replay != nil && a.Replay.TargetGenerationID == 3 && a.NextGenerationID == 4 &&
		a.Replay.TargetProfile == mdbx.StorageProfileArchiveV1, "A16 entry: %+v %+v", out, a.Replay)
}
