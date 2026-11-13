//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// rtNew is a format-3 store; a non-zero envelope is seeded with both active roles' 16-byte zero counters and empty
// PRE_GENESIS FULL_HISTORY bindings (the btNew precedent); extra rows are seeded in the same Pair.
func rtNew(t *testing.T, envelope mdbx.TreeAuthorityV1, extra ...mdbx.Mutation) *btWorld {
	t.Helper()
	w := &btWorld{path: filepath.Join(t.TempDir(), "tree"), cfg: mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}}
	var err error
	w.s, err = mdbx.CreateTreeV1(w.path, w.cfg, [32]byte{7})
	logicalMDBXAssert(t, err == nil, "CreateTreeV1: %v", err)
	w.owner, err = mdbx.NewOperationReservationOwner(805306368)
	logicalMDBXAssert(t, err == nil, "reservation owner: %v", err)
	t.Cleanup(func() { _ = w.s.Close() })
	rows := extra
	if envelope.Authority.Version != 0 {
		root, rerr := (mdbx.RootBindingV1{DatabaseID: [32]byte{7}, CommitmentVersion: 1, RootDigest: sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")), Assurance: mdbx.TreeAssuranceV1{Kind: 1}}).Encode()
		literal, eerr := envelope.Encode()
		logicalMDBXAssert(t, rerr == nil && eerr == nil, "seed encode: %v %v", rerr, eerr)
		rows = append(rows, btMutation(0, []byte{2}, literal))
		for _, g := range []uint64{envelope.Authority.ActiveGenerationID, envelope.LagGenerationID} {
			rows = append(rows, btMutation(0, btMeta(0x10, g), make([]byte, 16)), btMutation(0, btMeta(0x11, g), root))
		}
	}
	if len(rows) != 0 {
		w.pair(t, rows...)
	}
	return w
}

// rtStable is NONE/STABLE with active 1, lag 2 and next 5.
func rtStable() mdbx.TreeAuthorityV1 {
	return mdbx.TreeAuthorityV1{Authority: mdbx.StorageAuthorityV1{Version: 1, ActiveProfile: mdbx.StorageProfilePrunedV1, ActiveGenerationID: 1, NextGenerationID: 5, Phase: mdbx.StoragePhaseNoneV1, Lifecycle: mdbx.StorageLifecycleStableV1}, LagGenerationID: 2}
}

// rtPrune is PRUNE_GC/STABLE with one GENERATION(3) span.
func rtPrune() mdbx.TreeAuthorityV1 {
	e := rtStable()
	e.Authority.Phase, e.Authority.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 3}}}
	return e
}

type rtCommit struct {
	plan    ReplayRecoveryPlanV1
	planErr error
	truth   mdbx.CommitTruth
	stage   mdbx.UpdateStage
	index   int
	err     error
}

// rtIntent plans the intent inside UpdateTreeV1's callback and hands the Batch to replayTreeOperation.
func rtIntent(t *testing.T, w *btWorld) rtCommit {
	t.Helper()
	var c rtCommit
	err := w.owner.WithOperation(mdbx.LaneOperation, func(a *mdbx.OperationAccount) error {
		c.truth, c.stage, c.index, c.err = w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
			c.plan, c.planErr = PlanRecoveryIntentMDBX(r)
			if c.planErr != nil {
				return mdbx.TreeOperationV1{}, c.planErr
			}
			return replayTreeOperation(c.plan.Batch)
		})
		return nil
	})
	logicalMDBXAssert(t, err == nil, "intent account: %v", err)
	return c
}

func rtEnvelope(t *testing.T, w *btWorld) mdbx.TreeAuthorityV1 {
	t.Helper()
	var envelope mdbx.TreeAuthorityV1
	err := w.s.View(func(r *mdbx.Reader) error {
		var present bool
		var rerr error
		envelope, present, rerr = r.ReadTreeAuthorityV1()
		logicalMDBXAssert(t, rerr == nil && present, "envelope read: %t %v", present, rerr)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "envelope view: %v", err)
	return envelope
}

// rtImage is every family's entry count plus the meta control, envelope, counter and binding rows of generations 1-6.
func rtImage(t *testing.T, w *btWorld) [][]byte {
	t.Helper()
	inspection, err := w.s.Inspect()
	logicalMDBXAssert(t, err == nil, "inspect: %v", err)
	counts := []byte{}
	for _, d := range inspection.DBIs {
		counts = binary.BigEndian.AppendUint64(counts, d.Entries)
	}
	image := [][]byte{counts}
	err = w.s.View(func(r *mdbx.Reader) error {
		keys := [][]byte{{0}, {1}, {2}, {3}}
		for g := uint64(1); g <= 6; g++ {
			keys = append(keys, btMeta(0x10, g), btMeta(0x11, g))
		}
		for _, key := range keys {
			value, present, gerr := r.Get(mdbx.TreeSchemaV1DBIs()[0], key)
			logicalMDBXAssert(t, gerr == nil, "image get %x: %v", key, gerr)
			image = append(image, append([]byte{boolByte(present)}, value...))
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "image view: %v", err)
	return image
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// rtLegal is X1: version byte 1, decodable, every role nonzero, pairwise distinct and below next_generation_id.
func rtLegal(t *testing.T, literal []byte, label string) mdbx.TreeAuthorityV1 {
	t.Helper()
	decoded, err := mdbx.DecodeTreeAuthorityV1(literal)
	logicalMDBXAssert(t, err == nil && len(literal) > 0 && literal[0] == 1, "%s X1 decode: %v", label, err)
	a := decoded.Authority
	roles := []uint64{a.ActiveGenerationID, decoded.LagGenerationID}
	if a.Replay != nil {
		roles = append(roles, a.Replay.TargetGenerationID, decoded.TargetLagGenerationID)
	}
	for i, role := range roles {
		logicalMDBXAssert(t, role != 0 && role < a.NextGenerationID, "%s X1 role %d = %d next %d", label, i, role, a.NextGenerationID)
		for _, earlier := range roles[:i] {
			logicalMDBXAssert(t, earlier != role, "%s X1 roles repeat %d", label, role)
		}
	}
	return decoded
}

// F2: only the exact tree-Reader refusal selects the envelope; it leaves the Reader active.
func TestReplayTreeReaderRefusal(t *testing.T) {
	w := rtNew(t, rtStable())
	var refusal error
	err := w.s.View(func(r *mdbx.Reader) error {
		_, refusal = r.ReadStorageAuthorityV1()
		_, present, rerr := r.ReadTreeAuthorityV1()
		logicalMDBXAssert(t, present && rerr == nil, "F2: the refusal disarmed the Reader: %v", rerr)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "F2 view: %v", err)
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, errors.As(refusal, &engine) && engine.Class == mdbx.EngineInvalidInput && engine.Operation == "get" && engine.Code == 22 &&
		engine.Diagnostic == "tree Reader requires tree authority accessor" && engine.Cause == nil && !engine.ReopenRequired && engine.TreeObservation == nil, "F2 pinned refusal: %#v", refusal)
	logicalMDBXAssert(t, replayTreeRefused(refusal, replayTreeReaderRefusal), "F2: the exact refusal is not selected")
	variants := map[string]error{"nil": nil, "wrapped": fmt.Errorf("w: %w", refusal), "joined": errors.Join(refusal), "typed nil": (*mdbx.EngineError)(nil), "other": errors.New("tree Reader requires tree authority accessor")}
	for label, edit := range map[string]func(e *mdbx.EngineError){
		"class": func(e *mdbx.EngineError) { e.Class = mdbx.EngineStateMismatch }, "operation": func(e *mdbx.EngineError) { e.Operation = "update" },
		"code": func(e *mdbx.EngineError) { e.Code = -30779 }, "diagnostic": func(e *mdbx.EngineError) { e.Diagnostic = "Reader is not active" },
		"cause": func(e *mdbx.EngineError) { e.Cause = errors.New("c") }, "reopen": func(e *mdbx.EngineError) { e.ReopenRequired = true },
		"observation": func(e *mdbx.EngineError) { e.TreeObservation = &mdbx.TreeObservationV1{} },
	} {
		copied := *engine
		edit(&copied)
		variants[label] = &copied
	}
	for label, variant := range variants {
		logicalMDBXAssert(t, !replayTreeRefused(variant, replayTreeReaderRefusal), "F2 %s selected the tree route", label)
	}
}

// K, P1: the pair-only conversion keeps the Batch's own rows; any other domain is refused before admission.
func TestReplayTreeOperation(t *testing.T) {
	b := replayRecoveryAuthorityBatch([]byte{1}, []mdbx.ConsultedRow{{DBI: mdbx.TreeSchemaV1DBIs()[0], Key: []byte{3}}})
	op, err := replayTreeOperation(b)
	logicalMDBXAssert(t, err == nil && op.Primitives == nil && op.Proof == nil && op.HeaderSlot == nil && op.Pair.EntryInventory == nil &&
		&op.Pair.Mutations[0] == &b.Mutations[0] && &op.Pair.Consulted[0] == &b.Consulted[0] && len(op.Pair.Mutations) == 1 && len(op.Pair.Consulted) == 1, "K: %+v %v", op, err)
	for label, edit := range map[string]func(b *mdbx.Batch){
		"Reverse":           func(b *mdbx.Batch) { b.Reverse = true },
		"ContextConsulted":  func(b *mdbx.Batch) { b.ContextConsulted = &mdbx.CanonicalContextWindowV1{} },
		"LargeConsulted":    func(b *mdbx.Batch) { b.LargeConsulted = make([]mdbx.LargeImageSelectorV1, 1) },
		"ObsoleteDeletes":   func(b *mdbx.Batch) { b.ObsoleteDeletes = make([]mdbx.ObsoleteRowV1, 1) },
		"ObsoleteConsulted": func(b *mdbx.Batch) { b.ObsoleteConsulted = make([]mdbx.ObsoletePageWitnessV1, 1) },
	} {
		w := rtNew(t, rtPrune())
		image := rtImage(t, w)
		var refused error
		err := w.owner.WithOperation(mdbx.LaneOperation, func(a *mdbx.OperationAccount) error {
			truth, stage, index, uerr := w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
				plan, perr := PlanRecoveryIntentMDBX(r)
				logicalMDBXAssert(t, perr == nil && len(plan.Batch.Mutations) == 1, "P1 %s premise: %v", label, perr)
				edit(&plan.Batch)
				var kop mdbx.TreeOperationV1
				kop, refused = replayTreeOperation(plan.Batch)
				logicalMDBXAssert(t, reflect.ValueOf(kop).IsZero(), "P1 %s: a refused conversion built an operation", label)
				return kop, refused
			})
			logicalMDBXAssert(t, refused != nil && errors.Is(uerr, refused) && truth == mdbx.CommitTruthOld && stage == mdbx.UpdateStagePrewrite && index == -1,
				"P1 %s: %d/%d/%d %v", label, truth, stage, index, uerr)
			return nil
		})
		logicalMDBXAssert(t, err == nil && recoveryClass(refused, "") == selectedSideInvariant, "P1 %s class: %v %v", label, err, refused)
		logicalMDBXAssert(t, reflect.DeepEqual(image, rtImage(t, w)), "P1 %s: image changed", label)
	}
}

// I1, I2, X1: the format-3 intent commits RECOVERY_REQUIRED with pending = the active profile and changes nothing else.
func TestReplayTreeIntent(t *testing.T) {
	detached := rtPrune()
	detached.Authority.B, detached.Authority.U = 10, 13_690
	detached.Authority.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: []mdbx.DetachedSuffixEntryV1{{Height: 4, Hash: [32]byte{4}, BlockBytesLen: 300}}, Cursor: mdbx.AuthorityPointV1{Height: 4, BlockHash: [32]byte{4}}, EntryCount: 1, LogicalBytes: 300}
	archive := rtPrune()
	archive.Authority.ActiveProfile = mdbx.StorageProfileArchiveV1
	for label, before := range map[string]mdbx.TreeAuthorityV1{"I1": rtPrune(), "I1 archive": archive, "I2": detached} {
		w := rtNew(t, before)
		image := rtImage(t, w)
		c := rtIntent(t, w)
		logicalMDBXAssert(t, c.planErr == nil && c.err == nil && c.truth == mdbx.CommitTruthNew && c.index == -1, "%s commit: %d/%d/%d %v %v", label, c.truth, c.stage, c.index, c.planErr, c.err)
		logicalMDBXAssert(t, c.plan.ReadResource == "" && len(c.plan.Batch.Mutations) == 1 && len(c.plan.Batch.Consulted) == 0, "%s plan: %+v", label, c.plan)
		m := c.plan.Batch.Mutations[0]
		logicalMDBXAssert(t, m.DBI == mdbx.TreeSchemaV1DBIs()[0] && bytes.Equal(m.Key, []byte{2}) && m.AfterKind == mdbx.AfterLiteral && m.BeforePresent, "%s mutation: %+v", label, m)
		want := before
		profile := before.Authority.ActiveProfile
		want.Authority.Lifecycle, want.Authority.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &profile
		decoded := rtLegal(t, m.Literal, label)
		got := rtEnvelope(t, w)
		logicalMDBXAssert(t, reflect.DeepEqual(got, want) && reflect.DeepEqual(decoded, want), "%s readback: %+v want %+v", label, got, want)
		logicalMDBXAssert(t, got.TargetLagGenerationID == 0 && got.SourceKind == mdbx.TreeSourceNoneV1 && reflect.ValueOf(got.Progress).IsZero() && got.Authority.Replay == nil, "%s source fields: %+v", label, got)
		after := rtImage(t, w)
		logicalMDBXAssert(t, len(after) == len(image), "%s image shape", label)
		for i := range image {
			logicalMDBXAssert(t, i == 3 || bytes.Equal(image[i], after[i]), "%s: row %d other than the envelope changed", label, i)
		}
	}
}

// Domain, P2, D4: outside PRUNE_GC/STABLE and on proved exact-empty absence the intent is the empty plan; the empty
// plan handed to replayTreeOperation is refused by UpdateTreeV1 admission with nothing written.
func TestReplayTreeIntentEmpty(t *testing.T) {
	pendingNone := rtStable()
	profile := mdbx.StorageProfilePrunedV1
	pendingNone.Authority.Lifecycle, pendingNone.Authority.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &profile
	pendingPrune := rtPrune()
	pendingPrune.Authority.Lifecycle, pendingPrune.Authority.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &profile
	for label, envelope := range map[string]mdbx.TreeAuthorityV1{"NONE/STABLE": rtStable(), "NONE/RECOVERY_REQUIRED": pendingNone, "PRUNE_GC/RECOVERY_REQUIRED": pendingPrune, "D4 exact-empty": {}} {
		w := rtNew(t, envelope)
		image := rtImage(t, w)
		c := rtIntent(t, w)
		var engine *mdbx.EngineError
		logicalMDBXAssert(t, c.planErr == nil && reflect.ValueOf(c.plan).IsZero(), "%s plan: %+v %v", label, c.plan, c.planErr)
		logicalMDBXAssert(t, errors.As(c.err, &engine) && engine.Class == mdbx.EngineInvalidInput && engine.Diagnostic == "invalid Update Batch" && c.truth == mdbx.CommitTruthOld && c.stage == mdbx.UpdateStagePrewrite,
			"%s P2: %d/%d %v", label, c.truth, c.stage, c.err)
		logicalMDBXAssert(t, reflect.DeepEqual(image, rtImage(t, w)), "%s: image changed", label)
	}
}

// D2: a non-empty absence is TERMINAL_STORE_INTEGRITY(canonical) with ReadResource empty, refused at PREWRITE before
// any write (the latched Store refuses every later read; D1 needs a raw seed the Pair grammar refuses and is
// TestReplayTreeFixtureIntentUndecodable).
func TestReplayTreeIntentNonEmptyAbsence(t *testing.T) {
	w := rtNew(t, mdbx.TreeAuthorityV1{}, btMutation(0, btMeta(0x10, 1), make([]byte, 16)))
	c := rtIntent(t, w)
	logicalMDBXAssert(t, c.planErr != nil && errors.Is(c.err, c.planErr) && reflect.ValueOf(c.plan).IsZero() && recoveryClass(c.planErr, c.plan.ReadResource) == selectedSideIntegrity && c.truth == mdbx.CommitTruthOld,
		"D2: %+v %v %v", c.plan, c.planErr, c.err)
	logicalMDBXAssert(t, c.stage == mdbx.UpdateStagePrewrite && c.index == -1, "D2: the refusal reached stage %d", c.stage)
}

// rtReplayEnvelope is REPLAY/RECOVERY_REQUIRED GENESIS_REPLAY with active 1, lag 3, target 2 (target profile ARCHIVE,
// the active profile PRUNED), target lag 4 and next 5 over authority a (q148Replay).
func rtReplayEnvelope(a mdbx.StorageAuthorityV1) mdbx.TreeAuthorityV1 {
	a.Version, a.ActiveProfile, a.NextGenerationID, a.Lifecycle = 1, mdbx.StorageProfilePrunedV1, 5, mdbx.StorageLifecycleRecoveryRequiredV1
	a.Replay.TargetProfile = mdbx.StorageProfileArchiveV1
	return mdbx.TreeAuthorityV1{Authority: a, LagGenerationID: 3, TargetLagGenerationID: 4, SourceKind: mdbx.TreeSourceGenesisReplayV1}
}

// rtReplayWorld is q148Recomputation's world (active tip 2, target index of generation 2 with tip 4) whose envelope is
// rewritten to rtReplayEnvelope, with counter and binding rows for generations 3 and 4.
func rtReplayWorld(t *testing.T) (*q148World, mdbx.TreeAuthorityV1, *q148View) {
	t.Helper()
	w, s, tg := q148Recomputation(t, 2)
	heavy := s.clone(2)
	heavy.extend(t, 3, 4*TARGET_BLOCK_INTERVAL, false)
	envelope := rtReplayEnvelope(q148Replay(w, tg, 4, t))
	literal, err := envelope.Encode()
	logicalMDBXAssert(t, err == nil, "REPLAY envelope: %v", err)
	root := rtImageRow(t, w.btWorld, btMeta(0x11, 1))
	rows := []mdbx.Mutation{btMutation(0, []byte{2}, literal)}
	rows[0].BeforePresent = true
	for _, g := range []uint64{3, 4} {
		rows = append(rows, btMutation(0, btMeta(0x10, g), make([]byte, 16)), btMutation(0, btMeta(0x11, g), root))
	}
	w.pair(t, rows...)
	return w, envelope, &q148View{inv: q148Complete([][32]byte{heavy.tip()}, heavy.headers[3:])}
}

func rtImageRow(t *testing.T, w *btWorld, key []byte) []byte {
	t.Helper()
	var value []byte
	err := w.s.View(func(r *mdbx.Reader) error {
		v, present, gerr := r.Get(mdbx.TreeSchemaV1DBIs()[0], key)
		logicalMDBXAssert(t, gerr == nil && present, "row %x: %t %v", key, present, gerr)
		value = bytes.Clone(v)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "row view: %v", err)
	return value
}

type rtRecomputed struct {
	report  ReplayRecomputationV1
	recErr  error
	batch   mdbx.Batch
	convErr error
	direct  ReplayRecomputationV1
	rtCommit
}

// rtRecompute runs RecomputeReplayTargetMDBX and PlanReplayTargetConversionMDBX inside UpdateTreeV1's callback and
// hands the Batch to replayTreeOperation; with direct it also runs Q6 on the read authority under the same Reader.
// Every Release runs after the commit call.
func rtRecompute(t *testing.T, w *btWorld, owner *ReplayEntryOwnerV1, direct bool) rtRecomputed {
	t.Helper()
	var c rtRecomputed
	err := w.owner.WithOperation(mdbx.LaneOperation, func(a *mdbx.OperationAccount) error {
		c.truth, c.stage, c.index, c.err = w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
			c.report, c.recErr = owner.RecomputeReplayTargetMDBX(r, mdbx.MaxOperationDataBytes)
			if c.recErr != nil {
				return mdbx.TreeOperationV1{}, c.recErr
			}
			if direct {
				c.direct, _ = owner.recompute148(r, c.report.envelope.Authority, mdbx.MaxOperationDataBytes)
			}
			c.batch, c.convErr = PlanReplayTargetConversionMDBX(r, c.report)
			return replayTreeOperation(c.batch)
		})
		return nil
	})
	logicalMDBXAssert(t, err == nil, "recompute account: %v", err)
	for _, release := range []func(){c.report.Release, c.direct.Release} {
		if release != nil {
			release()
		}
	}
	return c
}

// rtConverted is the C plan's envelope from the aliases: PRUNE_GC/RECOVERY_REQUIRED, pending = the target profile,
// ReplayV1 none, CleanupV1 [GENERATION(lo), GENERATION(hi)], target lag, source kind and progress none.
func rtConverted(before mdbx.TreeAuthorityV1, lo, hi uint64) mdbx.TreeAuthorityV1 {
	want := before
	profile := before.Authority.Replay.TargetProfile
	want.Authority.Phase, want.Authority.Lifecycle, want.Authority.PendingTargetProfile, want.Authority.Replay = mdbx.StoragePhasePruneGCV1, mdbx.StorageLifecycleRecoveryRequiredV1, &profile, nil
	want.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: lo}, {Kind: mdbx.CleanupSpanGenerationV1, GenerationID: hi}}}
	want.TargetLagGenerationID, want.SourceKind, want.Progress = 0, mdbx.TreeSourceNoneV1, mdbx.TreeProgressV1{}
	return want
}

// rtConsulted is the active generation-1 index rows at heights 0, 1, tip and tip+1 for an active tip of 2.
func rtConsulted(t *testing.T) []mdbx.ConsultedRow {
	t.Helper()
	var rows []mdbx.ConsultedRow
	for _, h := range []uint64{0, 1, 2, 3} {
		key, err := mdbx.HeightKey(1, h)
		logicalMDBXAssert(t, err == nil, "height key: %v", err)
		rows = append(rows, mdbx.ConsultedRow{DBI: mdbx.TreeSchemaV1DBIs()[2], Key: key})
	}
	return rows
}

// Y1, C1, H2, X1: on a tree Reader RecomputeReplayTargetMDBX returns Q6's report for the envelope's authority with the
// read envelope; its PLAN_CHANGE converts both target generations into ascending GENERATION spans and nothing else.
func TestReplayTreeConversion(t *testing.T) {
	w, before, view := rtReplayWorld(t)
	image := rtImage(t, w.btWorld)
	c := rtRecompute(t, w.btWorld, NewReplayEntryOwnerV1(view, w.g), true)
	logicalMDBXAssert(t, c.recErr == nil && c.convErr == nil && c.report.Report == ReplayRecomputationPlanChangeV1 && c.report.activeTip == 2, "Y1 report: %+v %v %v", c.report, c.recErr, c.convErr)
	logicalMDBXAssert(t, reflect.DeepEqual(c.report.envelope, before) && reflect.DeepEqual(c.report.authority, before.Authority), "Y1 envelope: %+v", c.report.envelope)
	logicalMDBXAssert(t, c.direct.Report == c.report.Report && c.direct.Result == c.report.Result && c.direct.activeTip == c.report.activeTip && c.direct.reader == c.report.reader &&
		reflect.DeepEqual(c.direct.authority, c.report.authority) && c.direct.ReadResource == c.report.ReadResource && c.direct.Evidence.Key == nil && c.report.Evidence.Key == nil, "Y1: not Q6's report: %+v %+v", c.direct, c.report)
	logicalMDBXAssert(t, c.err == nil && c.truth == mdbx.CommitTruthNew && c.index == -1, "C1 commit: %d/%d/%d %v", c.truth, c.stage, c.index, c.err)
	logicalMDBXAssert(t, len(c.batch.Mutations) == 1 && reflect.DeepEqual(c.batch.Consulted, rtConsulted(t)), "C1 plan: %+v", c.batch)
	m := c.batch.Mutations[0]
	logicalMDBXAssert(t, m.DBI == mdbx.TreeSchemaV1DBIs()[0] && bytes.Equal(m.Key, []byte{2}) && m.AfterKind == mdbx.AfterLiteral && m.BeforePresent, "C1 mutation: %+v", m)
	want := rtConverted(before, 2, 4)
	decoded := rtLegal(t, m.Literal, "C1")
	got := rtEnvelope(t, w.btWorld)
	logicalMDBXAssert(t, reflect.DeepEqual(got, want) && reflect.DeepEqual(decoded, want), "C1 readback: %+v want %+v", got, want)
	after := rtImage(t, w.btWorld)
	logicalMDBXAssert(t, len(after) == len(image), "C1 image shape")
	for i := range image {
		logicalMDBXAssert(t, i == 3 || bytes.Equal(image[i], after[i]), "C1: row %d other than the envelope changed", i)
	}
	logicalMDBXAssert(t, view.releases == 2, "C1: releases %d", view.releases)
}

// C2, H2: the C plan reads no cursor and orders the spans ascending whichever target role is lower.
func TestReplayTreeConversionNoCursor(t *testing.T) {
	w, before, view := rtReplayWorld(t)
	owner := NewReplayEntryOwnerV1(view, w.g)
	err := w.s.View(func(r *mdbx.Reader) error {
		base, rerr := owner.RecomputeReplayTargetMDBX(r, mdbx.MaxOperationDataBytes)
		logicalMDBXAssert(t, rerr == nil && base.Report == ReplayRecomputationPlanChangeV1, "C2 premise: %+v %v", base, rerr)
		defer base.Release()
		reference, rerr := PlanReplayTargetConversionMDBX(r, base)
		logicalMDBXAssert(t, rerr == nil, "C2 reference: %v", rerr)
		for label, edit := range map[string]func(e *mdbx.TreeAuthorityV1) (uint64, uint64){
			"PRE_GENESIS": func(e *mdbx.TreeAuthorityV1) (uint64, uint64) {
				e.Authority.Replay.Cursor = mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorPreGenesisV1}
				return 2, 4
			},
			"partial": func(e *mdbx.TreeAuthorityV1) (uint64, uint64) {
				e.Authority.Replay.Cursor = mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: 1, BlockHash: [32]byte{1}}
				return 2, 4
			},
			"target above lag": func(e *mdbx.TreeAuthorityV1) (uint64, uint64) {
				e.Authority.Replay.TargetGenerationID, e.TargetLagGenerationID = 4, 2
				return 2, 4
			},
		} {
			report := base
			replay := *before.Authority.Replay
			report.envelope = before
			report.envelope.Authority.Replay = &replay
			lo, hi := edit(&report.envelope)
			batch, cerr := PlanReplayTargetConversionMDBX(r, report)
			logicalMDBXAssert(t, cerr == nil && len(batch.Mutations) == 1, "C2 %s: %v", label, cerr)
			decoded := rtLegal(t, batch.Mutations[0].Literal, "C2 "+label)
			logicalMDBXAssert(t, reflect.DeepEqual(decoded, rtConverted(before, lo, hi)) && bytes.Equal(batch.Mutations[0].Literal, reference.Mutations[0].Literal) && reflect.DeepEqual(batch.Consulted, reference.Consulted), "C2 %s: %+v", label, decoded)
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "C2 view: %v", err)
}

// Y1 domain, D4, D2: NONE/STABLE is Q6's NOT_APPLICABLE and exact-empty absence is NOT_APPLICABLE, both with no
// inventory call and the empty conversion; a non-empty absence is TERMINAL_STORE_INTEGRITY(canonical) before Q6.
func TestReplayTreeRecomputeDomain(t *testing.T) {
	g := PublishedGenesisContextV1{ChainID: [32]byte{0xc1}, GenesisHash: [32]byte{0xc2}}
	for label, envelope := range map[string]mdbx.TreeAuthorityV1{"NONE/STABLE": rtStable(), "D4 exact-empty": {}, "PRUNE_GC/STABLE": rtPrune()} {
		w := rtNew(t, envelope)
		image := rtImage(t, w)
		view := &q148View{}
		c := rtRecompute(t, w, NewReplayEntryOwnerV1(view, g), false)
		logicalMDBXAssert(t, c.recErr == nil && c.report.Report == ReplayRecomputationNotApplicableV1 && c.report.Release == nil && reflect.DeepEqual(c.report.envelope, envelope), "%s: %+v %v", label, c.report, c.recErr)
		logicalMDBXAssert(t, c.convErr == nil && reflect.ValueOf(c.batch).IsZero() && view.limits == nil && view.calls116 == 0 && view.versions == nil, "%s: conversion %+v view %+v", label, c.batch, view)
		logicalMDBXAssert(t, c.truth == mdbx.CommitTruthOld && c.stage == mdbx.UpdateStagePrewrite && reflect.DeepEqual(image, rtImage(t, w)), "%s: %d/%d %v", label, c.truth, c.stage, c.err)
	}
	w := rtNew(t, mdbx.TreeAuthorityV1{}, btMutation(0, btMeta(0x10, 1), make([]byte, 16)))
	view := &q148View{}
	c := rtRecompute(t, w, NewReplayEntryOwnerV1(view, g), false)
	logicalMDBXAssert(t, c.recErr != nil && errors.Is(c.err, c.recErr) && reflect.ValueOf(c.report).IsZero() && recoveryClass(c.recErr, c.report.ReadResource) == selectedSideIntegrity && view.limits == nil,
		"D2: %+v %v", c.report, c.recErr)
	logicalMDBXAssert(t, c.truth == mdbx.CommitTruthOld && c.stage == mdbx.UpdateStagePrewrite, "D2: %d/%d", c.truth, c.stage)
}

// Y1 STALE: a STALE report from Q6 carries the read envelope as well; its conversion is the empty plan.
func TestReplayTreeRecomputeStale(t *testing.T) {
	w, before, view := rtReplayWorld(t)
	view.stale = true
	image := rtImage(t, w.btWorld)
	c := rtRecompute(t, w.btWorld, NewReplayEntryOwnerV1(view, w.g), false)
	logicalMDBXAssert(t, c.recErr == nil && c.report.Report == ReplayRecomputationStaleV1 && c.report.Result == replayEntryStale && reflect.DeepEqual(c.report.envelope, before), "Y1 STALE: %+v %v", c.report, c.recErr)
	logicalMDBXAssert(t, c.convErr == nil && reflect.ValueOf(c.batch).IsZero() && c.truth == mdbx.CommitTruthOld && reflect.DeepEqual(image, rtImage(t, w.btWorld)) && view.releases == 1, "Y1 STALE conversion: %+v %d", c.batch, c.truth)
}

// rtSet rewrites the envelope of a format-3 world (rows of other generations are untouched).
func rtSet(t *testing.T, w *btWorld, envelope mdbx.TreeAuthorityV1, extra ...mdbx.Mutation) {
	t.Helper()
	literal, err := envelope.Encode()
	logicalMDBXAssert(t, err == nil, "envelope encode: %v", err)
	m := btMutation(0, []byte{2}, literal)
	m.BeforePresent = true
	w.pair(t, append(extra, m)...)
}

// rtEntryWorld is btNew's NONE/STABLE envelope (active 1, lag 2, next 5) with an empty active index and a 148 sequence
// 0..3 from its own genesis, the inventory holding the genesis header (Fork F identity anchor, no published genesis);
// edit, when non-nil, rewrites the envelope.
func rtEntryWorld(t *testing.T, edit func(e *mdbx.TreeAuthorityV1)) (*q148World, *q148Seq, *q148View) {
	t.Helper()
	s := newQ148Seq(t, POW_LIMIT, 1<<30)
	s.extend(t, 3, 2*TARGET_BLOCK_INTERVAL, false)
	w := newQ148World(t, s, -1, nil)
	logicalMDBXAssert(t, reflect.DeepEqual(rtEnvelope(t, w.btWorld), rtStable()), "entry world premise")
	if edit != nil {
		e := rtStable()
		edit(&e)
		rtSet(t, w.btWorld, e)
	}
	return w, s, &q148View{inv: q148Complete([][32]byte{s.tip()}, s.headers)}
}

// rtBinding is the target image binding from AUTH 1034-1062: database {7}, commitment 1, the target's chain and
// genesis, PRE_GENESIS, the empty-tree digest sha3-256("RUBIN_UTXO_TREE_V1\x00"), Top empty, FULL_HISTORY.
func rtBinding(t *testing.T, chain, genesis [32]byte) []byte {
	t.Helper()
	encoded, err := (mdbx.RootBindingV1{DatabaseID: [32]byte{7}, CommitmentVersion: 1, ChainID: chain, GenesisHash: genesis, RootDigest: sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")), Assurance: mdbx.TreeAssuranceV1{Kind: 1}}).Encode()
	logicalMDBXAssert(t, err == nil, "binding: %v", err)
	return encoded
}

// rtEntered is the E plan's envelope from the aliases for before with n = next, target profile profile and target.
func rtEntered(before mdbx.TreeAuthorityV1, profile mdbx.StorageProfileV1, target mdbx.RecoveryTargetV1) mdbx.TreeAuthorityV1 {
	want := before
	n := before.Authority.NextGenerationID
	want.Authority.Phase, want.Authority.Lifecycle, want.Authority.PendingTargetProfile = mdbx.StoragePhaseReplayV1, mdbx.StorageLifecycleRecoveryRequiredV1, nil
	want.Authority.Replay = &mdbx.ReplayV1{TargetProfile: profile, TargetGenerationID: n, Target: target, Cursor: mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorPreGenesisV1}}
	want.Authority.NextGenerationID = n + 2
	want.TargetLagGenerationID, want.SourceKind, want.Progress = n+1, mdbx.TreeSourceGenesisReplayV1, mdbx.TreeProgressV1{}
	return want
}

// rtTargetRows asserts both target generations' zero counter and empty binding rows (E1, M6).
func rtTargetRows(t *testing.T, w *btWorld, n uint64, binding []byte, label string) {
	t.Helper()
	for _, g := range []uint64{n, n + 1} {
		logicalMDBXAssert(t, bytes.Equal(rtImageRow(t, w, btMeta(0x10, g)), make([]byte, 16)), "%s: counter row of %d", label, g)
		logicalMDBXAssert(t, bytes.Equal(rtImageRow(t, w, btMeta(0x11, g)), binding), "%s: binding row of %d", label, g)
	}
}

// rtSameExceptMeta asserts every family count other than meta and every image row other than the envelope and the
// generations 5 and 6 rows is unchanged.
func rtSameExceptMeta(t *testing.T, before, after [][]byte, label string) {
	t.Helper()
	logicalMDBXAssert(t, len(before) == len(after) && bytes.Equal(before[0][8:], after[0][8:]), "%s: a non-meta family changed", label)
	for i := 1; i < len(before); i++ {
		logicalMDBXAssert(t, i == 3 || i >= 13 || bytes.Equal(before[i], after[i]), "%s: row %d changed", label, i)
	}
}

// E1, E2, E3, X1, X2, H4, M1, M6, M7, M11: source (b) and (d) enter through one pair-only UpdateTreeV1 that allocates
// target CURRENT n and target LAG n+1 and writes both target images; the account is an owner at MinReservationLimit.
func TestReplayTreeEntry(t *testing.T) {
	archive := mdbx.StorageProfileArchiveV1
	for _, c := range []struct {
		label   string
		edit    func(e *mdbx.TreeAuthorityV1)
		profile mdbx.StorageProfileV1
	}{
		{"E1 source b", nil, mdbx.StorageProfilePrunedV1},
		{"E2 source d", func(e *mdbx.TreeAuthorityV1) {
			e.Authority.Lifecycle, e.Authority.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &archive
		}, mdbx.StorageProfileArchiveV1},
		{"E3 boundary", func(e *mdbx.TreeAuthorityV1) { e.Authority.NextGenerationID = math.MaxUint64 - 2 }, mdbx.StorageProfilePrunedV1},
	} {
		w, s, view := rtEntryWorld(t, c.edit)
		before := rtEnvelope(t, w.btWorld)
		image := rtImage(t, w.btWorld)
		out := NewReplayEntryOwnerV1(view, w.g).EnterReplayTargetMDBX(w.s, w.owner)
		target := mdbx.RecoveryTargetV1{ChainID: w.g.ChainID, GenesisHash: s.hashes[0], TipHash: s.tip(), TipHeight: 3, CumulativeChainwork: s.work(t, 3)}
		want := rtEntered(before, c.profile, target)
		logicalMDBXAssert(t, out.Err == nil && out.Truth == mdbx.CommitTruthNew && out.CanonicalTruth == "NEW" && out.Result == "" && out.Decision == "" && reflect.DeepEqual(out.Replay, want.Authority.Replay),
			"%s outcome: %+v", c.label, out)
		got := rtEnvelope(t, w.btWorld)
		decoded := rtLegal(t, rtImageRow(t, w.btWorld, []byte{2}), c.label)
		logicalMDBXAssert(t, reflect.DeepEqual(got, want) && reflect.DeepEqual(decoded, want), "%s readback: %+v want %+v", c.label, got, want)
		n := before.Authority.NextGenerationID
		rtTargetRows(t, w.btWorld, n, rtBinding(t, w.g.ChainID, s.hashes[0]), c.label)
		after := rtImage(t, w.btWorld)
		rtSameExceptMeta(t, image, after, c.label)
		logicalMDBXAssert(t, binary.BigEndian.Uint64(after[0][:8]) == binary.BigEndian.Uint64(image[0][:8])+4, "%s: meta rows %x -> %x", c.label, image[0][:8], after[0][:8])
		logicalMDBXAssert(t, view.releases == 1 && len(view.versions) == 1, "%s: ProtectV1 %v releases %d", c.label, view.versions, view.releases)
		logicalMDBXAssert(t, reflect.DeepEqual(view.limits, []uint64{replayInvLimit148(replayTreeOwnBytes)}), "%s: lane %v", c.label, view.limits)
	}
}

// X2, M10: with competing charges leaving exactly LANE_MAX of an owner at MinReservationLimit, the entry plan commits:
// OWN plus its step-5 charge fit the account ceiling and the aggregate (OWN = LANE_MAX - P_PAIR, compile-checked).
func TestReplayTreeEntryAccountFit(t *testing.T) {
	logicalMDBXAssert(t, replayTreeOwnBytes+replayTreePairBytes == mdbx.LaneMaxBytes && replayTreeOwnBytes <= mdbx.MaxOperationDataBytes && replayTreeOwnBytes >= replayRecoveryMin148Bytes, "OWN %d", replayTreeOwnBytes)
	w, _, view := rtEntryWorld(t, nil)
	var out ReplayEntryOutcomeV1
	rtCharges(t, w.owner, mdbx.MinReservationLimit-mdbx.LaneMaxBytes, func() {
		out = NewReplayEntryOwnerV1(view, w.g).EnterReplayTargetMDBX(w.s, w.owner)
	})
	logicalMDBXAssert(t, out.Err == nil && out.Truth == mdbx.CommitTruthNew, "X2: %+v", out)
}

// E4, M12: a persisted REPLAY resumes with zero mutation and no view call, also when the OWN charge is refused.
func TestReplayTreeEntryResume(t *testing.T) {
	for _, limit := range []uint64{mdbx.MinReservationLimit, 1} {
		for _, kind := range []mdbx.TreeSourceKindV1{mdbx.TreeSourceGenesisReplayV1, mdbx.TreeSourceImageV1} {
			w := q148WorldOf(t)
			e := rtStable()
			profile := mdbx.StorageProfileArchiveV1
			e.Authority.Phase, e.Authority.Lifecycle = mdbx.StoragePhaseReplayV1, mdbx.StorageLifecycleRecoveryRequiredV1
			e.Authority.Replay = &mdbx.ReplayV1{
				TargetProfile: profile, TargetGenerationID: 3, Target: mdbx.RecoveryTargetV1{ChainID: [32]byte{0xc1}, GenesisHash: [32]byte{0xc2}, TipHash: [32]byte{9}, TipHeight: 4, CumulativeChainwork: [40]byte{39: 5}},
				Cursor: mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorPreGenesisV1},
			}
			e.TargetLagGenerationID, e.SourceKind = 4, kind
			if kind == mdbx.TreeSourceImageV1 {
				e.Progress, e.Authority.Replay.Cursor = mdbx.TreeProgressV1{Kind: mdbx.TreeProgressPartialV1, Payload: []byte{1}}, mdbx.ReplayCursorV1{}
			}
			rtSet(t, w, e)
			image := rtImage(t, w)
			owner, _ := mdbx.NewOperationReservationOwner(limit)
			view := &q148View{}
			out := NewReplayEntryOwnerV1(view, PublishedGenesisContextV1{ChainID: [32]byte{0xc1}, GenesisHash: [32]byte{0xc2}}).EnterReplayTargetMDBX(w.s, owner)
			label := fmt.Sprintf("E4 limit %d kind %d", limit, kind)
			logicalMDBXAssert(t, out.Err == nil && out.Decision == replayEntryResume && out.Result == "" && out.Truth == mdbx.CommitTruthOld && out.CanonicalTruth == "OLD" && reflect.DeepEqual(out.Replay, e.Authority.Replay),
				"%s: %+v", label, out)
			logicalMDBXAssert(t, reflect.DeepEqual(image, rtImage(t, w)) && reflect.DeepEqual(rtEnvelope(t, w), e) && view.limits == nil && view.versions == nil, "%s: image or view", label)
		}
	}
}

func q148WorldOf(t *testing.T) *btWorld {
	t.Helper()
	return btNew(t)
}

// rtRefused asserts a zero-mutation OLD outcome with result.
func rtRefused(t *testing.T, out ReplayEntryOutcomeV1, result string, image, after [][]byte, label string) {
	t.Helper()
	logicalMDBXAssert(t, out.Truth == mdbx.CommitTruthOld && out.CanonicalTruth == "OLD" && out.Result == result && out.Replay == nil, "%s: %+v want %q", label, out, result)
	logicalMDBXAssert(t, reflect.DeepEqual(image, after), "%s: image changed", label)
}

// E5, E10, M3, M13: sequence exhaustion is TERMINAL_LOCAL_INVARIANT(evidence) before the DatabaseID read (the active
// CURRENT binding is deleted, so a read before the check would be integrity).
func TestReplayTreeEntryExhausted(t *testing.T) {
	for _, next := range []uint64{math.MaxUint64 - 1, math.MaxUint64} {
		w, _, view := rtEntryWorld(t, nil)
		e := rtStable()
		e.Authority.NextGenerationID = next
		rtSet(t, w.btWorld, e, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[0], Key: btMeta(0x11, 1), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
		image := rtImage(t, w.btWorld)
		out := NewReplayEntryOwnerV1(view, w.g).EnterReplayTargetMDBX(w.s, w.owner)
		rtRefused(t, out, selectedSideInvariant, image, rtImage(t, w.btWorld), fmt.Sprintf("E5 next %d", next))
		logicalMDBXAssert(t, out.Err == nil && view.releases == 1, "E5 next %d: %v releases %d", next, out.Err, view.releases)
	}
}

// D5: an absent active CURRENT binding after sequence availability is TERMINAL_STORE_INTEGRITY(canonical).
func TestReplayTreeEntryBindingAbsent(t *testing.T) {
	w, _, view := rtEntryWorld(t, nil)
	rtSet(t, w.btWorld, rtStable(), mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[0], Key: btMeta(0x11, 1), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	image := rtImage(t, w.btWorld)
	out := NewReplayEntryOwnerV1(view, w.g).EnterReplayTargetMDBX(w.s, w.owner)
	rtRefused(t, out, selectedSideIntegrity, image, rtImage(t, w.btWorld), "D5 absent")
}

// E6, E7, E8, D4: qualification refusals and exact-empty absence write nothing.
func TestReplayTreeEntryRefusals(t *testing.T) {
	for _, c := range []struct {
		label  string
		view   func(v *q148View, s *q148Seq)
		result string
	}{
		{"E6 genesis only", func(v *q148View, s *q148Seq) { v.inv = q148Complete([][32]byte{s.hashes[0]}, s.headers[:1]) }, replayEntryRecovery},
		{"E7 incomplete", func(v *q148View, _ *q148Seq) {
			v.inv = HeaderCandidateInventory148V1{Status: HeaderCandidateIncompleteV1}
		}, replayEntryRecovery},
		{"E8 stale", func(v *q148View, _ *q148Seq) { v.stale = true }, replayEntryStale},
	} {
		for _, next := range []uint64{5, math.MaxUint64} {
			w, s, view := rtEntryWorld(t, func(e *mdbx.TreeAuthorityV1) { e.Authority.NextGenerationID = next })
			c.view(view, s)
			image := rtImage(t, w.btWorld)
			out := NewReplayEntryOwnerV1(view, w.g).EnterReplayTargetMDBX(w.s, w.owner)
			rtRefused(t, out, c.result, image, rtImage(t, w.btWorld), fmt.Sprintf("%s next %d", c.label, next))
		}
	}
	w := rtNew(t, mdbx.TreeAuthorityV1{})
	image := rtImage(t, w)
	view := &q148View{}
	out := NewReplayEntryOwnerV1(view, PublishedGenesisContextV1{ChainID: [32]byte{0xc1}, GenesisHash: [32]byte{0xc2}}).EnterReplayTargetMDBX(w.s, w.owner)
	logicalMDBXAssert(t, out.Err == nil && out.Decision == replayEntryNotEligible && view.limits == nil, "D4: %+v", out)
	rtRefused(t, out, "", image, rtImage(t, w), "D4")
}

// rtCharges nests owner-level LaneOperation charges totalling live bytes, then runs body.
func rtCharges(t *testing.T, owner *mdbx.OperationReservationOwner, live uint64, body func()) {
	t.Helper()
	if live == 0 {
		body()
		return
	}
	step := min(live, mdbx.LaneMaxBytes)
	err := owner.WithReservation(step, func() error {
		rtCharges(t, owner, live-step, body)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "competing charge %d: %v", step, err)
}

// E9(a), E9(b), E10: the OWN charge refused before the authority read; the step-5 Pair copy refused after sequence
// availability; with sequence exhausted the step-5 setup is E5, and the OWN refusal precedes the sequence check.
func TestReplayTreeEntryCapacity(t *testing.T) {
	for _, next := range []uint64{5, math.MaxUint64} {
		w, _, view := rtEntryWorld(t, func(e *mdbx.TreeAuthorityV1) { e.Authority.NextGenerationID = next })
		image := rtImage(t, w.btWorld)
		owner, _ := mdbx.NewOperationReservationOwner(mdbx.MinReservationLimit - 1)
		out := NewReplayEntryOwnerV1(view, w.g).EnterReplayTargetMDBX(w.s, owner)
		rtRefused(t, out, selectedSideCapacity, image, rtImage(t, w.btWorld), fmt.Sprintf("E9(a) next %d", next))
		logicalMDBXAssert(t, view.limits == nil && view.versions == nil, "E9(a): Q5 ran")
	}
	for next, result := range map[uint64]string{5: selectedSideCapacity, math.MaxUint64: selectedSideInvariant} {
		w, _, view := rtEntryWorld(t, func(e *mdbx.TreeAuthorityV1) { e.Authority.NextGenerationID = next })
		image := rtImage(t, w.btWorld)
		var out ReplayEntryOutcomeV1
		rtCharges(t, w.owner, mdbx.MinReservationLimit-replayTreeOwnBytes, func() {
			out = NewReplayEntryOwnerV1(view, w.g).EnterReplayTargetMDBX(w.s, w.owner)
		})
		label := fmt.Sprintf("E9(b) next %d", next)
		rtRefused(t, out, result, image, rtImage(t, w.btWorld), label)
		logicalMDBXAssert(t, len(view.versions) == 1 && view.releases == 1, "%s: Q5 did not run: %+v", label, view)
		logicalMDBXAssert(t, next != 5 || mdbx.IsOperationReservationCapacity(out.Err), "%s: not the step-5 refusal: %v", label, out.Err)
	}
}

// rtPanicView panics with its armed payload once, in Inventory148V1, inside the format-3 plan callback.
type rtPanicView struct {
	*q148View
	payload any
}

func (v *rtPanicView) Inventory148V1(limit uint64) HeaderCandidateInventory148V1 {
	if payload := v.payload; payload != nil {
		v.payload = nil
		panic(payload)
	}
	return v.q148View.Inventory148V1(limit)
}

// result_and_effect_closure (panic, format 3): a panic inside the format-3 entry route's plan callback propagates with
// its payload unchanged through UpdateTreeV1 and the OWN charge, mutates nothing and runs no release (ProtectV1 never
// returned one); the next entry on the same store and owner commits E1 and runs its release exactly once. No
// test-controlled hook runs after ProtectV1 (qualify148), so this test covers the pre-ProtectV1 panic; the release after
// ProtectV1 is the shared deferred runRelease in EnterReplayTargetMDBX, checked by TestReplayEntryProtectPlacement.
func TestReplayTreeEntryPanic(t *testing.T) {
	w, _, inner := rtEntryWorld(t, nil)
	image := rtImage(t, w.btWorld)
	payload := &struct{ n int }{17}
	owner := NewReplayEntryOwnerV1(&rtPanicView{q148View: inner, payload: payload}, w.g)
	func() {
		defer func() { logicalMDBXAssert(t, recover() == payload, "panic payload changed") }()
		owner.EnterReplayTargetMDBX(w.s, w.owner)
	}()
	logicalMDBXAssert(t, reflect.DeepEqual(image, rtImage(t, w.btWorld)) && inner.versions == nil && inner.releases == 0, "panic: mutation or release: %+v", inner)
	out := owner.EnterReplayTargetMDBX(w.s, w.owner)
	logicalMDBXAssert(t, out.Truth == mdbx.CommitTruthNew && out.Err == nil && out.Result == "" && len(inner.versions) == 1 && inner.releases == 1, "after panic: %+v %+v", out, inner)
}

// Y2, M14 and direct entry (E1): the format-3 minimum share is M148 (below it no identity read and no Q5; at it Q5
// runs); at the full share the direct entry plans the E plan with lane = limit, and the plan commits through K.
func TestReplayTreeDirectEntry(t *testing.T) {
	s := q148Slow(t, 5)
	w := newQ148World(t, s, 5, nil)
	b := s.clone(2)
	b.extend(t, 5, 3*TARGET_BLOCK_INTERVAL, false)
	view := &q148View{inv: q148Complete([][32]byte{b.tip()}, b.headers[3:])}
	owner := NewReplayEntryOwnerV1(view, w.g)
	image := rtImage(t, w.btWorld)
	err := w.s.View(func(r *mdbx.Reader) error {
		plan, release, perr := owner.PlanDirectReplayEntryMDBX(r, replayRecoveryMin148Bytes-1)
		logicalMDBXAssert(t, replayRecoveryMin148Bytes-1 == 3_550_885 && release == nil && reflect.ValueOf(plan).IsZero() && recoveryClass(perr, plan.ReadResource) == selectedSideCapacity, "Y2 M148-1: %+v %v", plan, perr)
		logicalMDBXAssert(t, view.limits == nil, "Y2: Q5 ran below M148: %v", view.limits)
		// At M148 the 148 inventory share is zero, so Q5 runs and the nonempty inventory is the producer violation.
		plan, release, perr = owner.PlanDirectReplayEntryMDBX(r, replayRecoveryMin148Bytes)
		logicalMDBXAssert(t, release == nil && reflect.ValueOf(plan).IsZero() && recoveryClass(perr, "") == selectedSideInvariant, "Y2 M148: %+v %v", plan, perr)
		logicalMDBXAssert(t, reflect.DeepEqual(view.limits, []uint64{replayInvLimit148(replayRecoveryMin148Bytes)}), "Y2 M148: Q5 limits %v", view.limits)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "Y2 view: %v", err)
	view.limits = nil
	var plan ReplayRecoveryPlanV1
	var release func()
	cerr := w.owner.WithOperation(mdbx.LaneOperation, func(a *mdbx.OperationAccount) error {
		truth, _, _, uerr := w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
			var perr error
			plan, release, perr = owner.PlanDirectReplayEntryMDBX(r, mdbx.MaxOperationDataBytes)
			logicalMDBXAssert(t, perr == nil, "direct plan: %v", perr)
			return replayTreeOperation(plan.Batch)
		})
		logicalMDBXAssert(t, uerr == nil && truth == mdbx.CommitTruthNew, "direct commit: %d %v", truth, uerr)
		return nil
	})
	logicalMDBXAssert(t, cerr == nil && release != nil, "direct account: %v", cerr)
	release()
	target := mdbx.RecoveryTargetV1{ChainID: w.g.ChainID, GenesisHash: w.g.GenesisHash, TipHash: b.tip(), TipHeight: 7, CumulativeChainwork: b.work(t, 7)}
	want := rtEntered(rtStable(), mdbx.StorageProfilePrunedV1, target)
	logicalMDBXAssert(t, reflect.DeepEqual(rtEnvelope(t, w.btWorld), want), "direct readback: %+v", rtEnvelope(t, w.btWorld))
	rtTargetRows(t, w.btWorld, 5, rtBinding(t, w.g.ChainID, w.g.GenesisHash), "direct")
	rtSameExceptMeta(t, image, rtImage(t, w.btWorld), "direct")
	logicalMDBXAssert(t, reflect.DeepEqual(view.limits, []uint64{replayInvLimit148(mdbx.MaxOperationDataBytes)}), "direct lane: %v", view.limits)
	logicalMDBXAssert(t, reflect.DeepEqual(plan.Batch.Consulted, replayEntryConsulted(1, 5)), "direct consulted")
}

// D5 (direct entry): the active CURRENT binding absent is a decided integrity refusal, so ReadResource is empty.
func TestReplayTreeDirectBindingAbsent(t *testing.T) {
	s := q148Slow(t, 5)
	w := newQ148World(t, s, 5, nil)
	b := s.clone(2)
	b.extend(t, 5, 3*TARGET_BLOCK_INTERVAL, false)
	rtSet(t, w.btWorld, rtStable(), mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[0], Key: btMeta(0x11, 1), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	view := &q148View{inv: q148Complete([][32]byte{b.tip()}, b.headers[3:])}
	ran := false
	err := w.s.View(func(r *mdbx.Reader) error {
		plan, release, perr := NewReplayEntryOwnerV1(view, w.g).PlanDirectReplayEntryMDBX(r, mdbx.MaxOperationDataBytes)
		logicalMDBXAssert(t, reflect.ValueOf(plan.Batch).IsZero() && perr != nil, "D5 direct: %+v %v", plan, perr)
		logicalMDBXAssert(t, plan.ReadResource == "" && recoveryClass(perr, plan.ReadResource) == selectedSideIntegrity, "D5 direct read class: %q %v", plan.ReadResource, perr)
		// D5 follows Q5's ProtectV1, so the release is non-nil and the caller runs it once.
		logicalMDBXAssert(t, release != nil, "D5 direct: nil release after ProtectV1")
		release()
		ran = true
		return nil
	})
	logicalMDBXAssert(t, err == nil, "D5 direct view: %v", err)
	logicalMDBXAssert(t, ran && len(view.limits) == 1 && view.releases == 1, "D5 direct: Q5 limits %v releases %d", view.limits, view.releases)
}

// D4, D2 (direct entry): exact-empty absence is no plan and no error; a non-empty absence is integrity; neither reads
// the view.
func TestReplayTreeDirectAbsence(t *testing.T) {
	g := PublishedGenesisContextV1{ChainID: [32]byte{0xc1}, GenesisHash: [32]byte{0xc2}}
	for label, w := range map[string]*btWorld{"D4": rtNew(t, mdbx.TreeAuthorityV1{}), "D2": rtNew(t, mdbx.TreeAuthorityV1{}, btMutation(0, btMeta(0x10, 1), make([]byte, 16)))} {
		view := &q148View{}
		err := w.s.View(func(r *mdbx.Reader) error {
			plan, release, perr := NewReplayEntryOwnerV1(view, g).PlanDirectReplayEntryMDBX(r, mdbx.MaxOperationDataBytes)
			want := ""
			if label == "D2" {
				want = selectedSideIntegrity
			}
			logicalMDBXAssert(t, release == nil && reflect.ValueOf(plan).IsZero() && (perr == nil) == (label == "D4") && (perr == nil || recoveryClass(perr, plan.ReadResource) == want), "%s: %+v %v", label, plan, perr)
			return nil
		})
		logicalMDBXAssert(t, (err == nil || label == "D2") && view.limits == nil, "%s view: %v", label, err) // D2 latches the Store
	}
}

// X2 maximal envelope: the E plan copies every input envelope field it does not set (treeEntryBatch), so an
// ExcludedInvalidBranch with an ExactConsensusError sized to make the planned envelope exactly MaxMetadataBytes is the
// largest plan; it commits through A under an owner at MinReservationLimit with no other live charge (the account
// ceiling LANE_MAX bounds OWN plus the step-5 charge, operation_reservation.go:127).
func TestReplayTreeEntryAccountFitMaximal(t *testing.T) {
	s := newQ148Seq(t, POW_LIMIT, 1<<30)
	s.extend(t, 3, 2*TARGET_BLOCK_INTERVAL, false)
	target := mdbx.RecoveryTargetV1{ChainID: [32]byte{0xc1}, GenesisHash: s.hashes[0], TipHash: s.tip(), TipHeight: 3, CumulativeChainwork: s.work(t, 3)}
	input := rtStable()
	input.Authority.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 9, FirstInvalidBlockHash: [32]byte{0xee}, ExactConsensusError: []byte{1}}
	small, err := rtEntered(input, mdbx.StorageProfilePrunedV1, target).Encode()
	logicalMDBXAssert(t, err == nil, "small output: %v", err)
	input.Authority.ExcludedInvalidBranch.ExactConsensusError = bytes.Repeat([]byte{1}, 1+mdbx.MaxMetadataBytes-len(small))
	full, err := rtEntered(input, mdbx.StorageProfilePrunedV1, target).Encode()
	logicalMDBXAssert(t, err == nil && len(full) == mdbx.MaxMetadataBytes, "maximal output: %d %v", len(full), err)
	w, _, view := rtEntryWorld(t, func(e *mdbx.TreeAuthorityV1) { *e = input })
	out := NewReplayEntryOwnerV1(view, w.g).EnterReplayTargetMDBX(w.s, w.owner)
	logicalMDBXAssert(t, out.Err == nil && out.Truth == mdbx.CommitTruthNew && out.Result == "", "X2 maximal: %+v", out)
	logicalMDBXAssert(t, bytes.Equal(rtImageRow(t, w.btWorld, []byte{2}), full), "X2 maximal: the committed envelope is not the maximal plan")
}

// E10 (genesis first), D2 (entry): a complete published genesis at NONE/STABLE/PRE_GENESIS (empty active index) is the
// baseline genesis-first decision with no inventory, no Q5 and no ProtectV1; a meta key 2 absence whose census finds a
// row is TERMINAL_STORE_INTEGRITY(canonical)/OLD at PREWRITE before any inventory (the image does not reopen, so its
// zero mutation is the engine's OLD/PREWRITE truth, as in TestReplayTreeDirectAbsence).
func TestReplayTreeEntryGenesisFirst(t *testing.T) {
	w, s, view := rtEntryWorld(t, nil)
	w.g.Published = append(bytes.Clone(s.headers[0][:]), make([]byte, 118)...)
	hash, err := BlockHash(w.g.Published[:BLOCK_HEADER_BYTES])
	logicalMDBXAssert(t, err == nil, "genesis hash: %v", err)
	w.g.GenesisHash, w.g.ChainID = hash, sha3.Sum256(append([]byte("RUBIN-GENESIS-v1"), w.g.Published...))
	image := rtImage(t, w.btWorld)
	out := NewReplayEntryOwnerV1(view, w.g).EnterReplayTargetMDBX(w.s, w.owner)
	logicalMDBXAssert(t, out.Err == nil && out.Decision == replayEntryGenesisFirst && view.limits == nil && view.versions == nil && view.releases == 0,
		"E10 genesis first: %+v view %+v", out, view)
	rtRefused(t, out, "", image, rtImage(t, w.btWorld), "E10 genesis first")
	d2 := rtNew(t, mdbx.TreeAuthorityV1{}, btMutation(0, btMeta(0x10, 1), make([]byte, 16)))
	view = &q148View{}
	out = NewReplayEntryOwnerV1(view, PublishedGenesisContextV1{ChainID: [32]byte{0xc1}, GenesisHash: [32]byte{0xc2}}).EnterReplayTargetMDBX(d2.s, d2.owner)
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, out.Result == selectedSideIntegrity && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && out.CanonicalTruth == "OLD" &&
		out.Replay == nil && out.Decision == "" && errors.As(out.Err, &engine) && engine.Class == mdbx.EngineIntegrity && view.limits == nil, "D2 entry: %+v", out)
}

// E9(a) aggregate remainder: competing charges leave the owner (at MinReservationLimit) a remainder below OWN, so the
// OWN charge is refused and the denied UpdateTreeV1 runs the gates; at a remainder of OWN-1 the identity-page charge is
// admitted and the H>0 identity decides not eligible, at a remainder below that charge it is refused (capacity). No
// Q5, no ProtectV1 and no write either way.
func TestReplayTreeEntryCapacityRemainder(t *testing.T) {
	for remainder, want := range map[uint64][2]string{replayTreeOwnBytes - 1: {"", replayEntryNotEligible}, replayEntryIdentityBytes - 1: {selectedSideCapacity, ""}} {
		s := q148Slow(t, 5)
		w := newQ148World(t, s, 5, nil)
		view := &q148View{}
		owner, err := mdbx.NewOperationReservationOwner(mdbx.MinReservationLimit)
		logicalMDBXAssert(t, err == nil, "owner: %v", err)
		image := rtImage(t, w.btWorld)
		var out ReplayEntryOutcomeV1
		rtCharges(t, owner, mdbx.MinReservationLimit-remainder, func() {
			out = NewReplayEntryOwnerV1(view, w.g).EnterReplayTargetMDBX(w.s, owner)
		})
		label := fmt.Sprintf("E9(a) remainder %d", remainder)
		logicalMDBXAssert(t, out.Err == nil && out.Decision == want[1], "%s: %+v", label, out)
		rtRefused(t, out, want[0], image, rtImage(t, w.btWorld), label)
		logicalMDBXAssert(t, view.limits == nil && view.versions == nil, "%s: Q5 ran", label)
	}
}

// rtIntentPayload is the opaque retained source intent payload P: 1 KiB of distinct bytes.
func rtIntentPayload() []byte {
	p := make([]byte, 1024)
	for i := range p {
		p[i] = byte(i*7 + 1)
	}
	return p
}

// rtImageReplay is the C1 IMAGE REPLAY envelope (active 1, lag 2, target 3, target lag 4, next 5, zero cursor, PARTIAL
// progress) carrying a fresh copy of p as its retained source intent.
func rtImageReplay(p []byte) mdbx.TreeAuthorityV1 {
	e := rtStable()
	e.Authority.Phase, e.Authority.Lifecycle = mdbx.StoragePhaseReplayV1, mdbx.StorageLifecycleRecoveryRequiredV1
	e.Authority.Replay = &mdbx.ReplayV1{TargetProfile: mdbx.StorageProfileArchiveV1, TargetGenerationID: 3, Target: mdbx.RecoveryTargetV1{ChainID: [32]byte{0xc1}, GenesisHash: [32]byte{0xc2}, TipHash: [32]byte{9}, TipHeight: 4, CumulativeChainwork: [40]byte{39: 5}}}
	e.TargetLagGenerationID, e.SourceKind = 4, mdbx.TreeSourceImageV1
	e.Progress = mdbx.TreeProgressV1{Kind: mdbx.TreeProgressPartialV1, Payload: []byte{0xa1, 0xa2}}
	e.SourceIntent = &mdbx.TreeSourceIntentV1{Kind: mdbx.TreeSourceIntentImageV1, Payload: bytes.Clone(p)}
	return e
}

// rtPendingIntent is the pending NONE/RECOVERY_REQUIRED envelope (pending ARCHIVE) carrying a fresh copy of p.
func rtPendingIntent(p []byte) mdbx.TreeAuthorityV1 {
	e := rtStable()
	archive := mdbx.StorageProfileArchiveV1
	e.Authority.Lifecycle, e.Authority.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &archive
	e.SourceIntent = &mdbx.TreeSourceIntentV1{Kind: mdbx.TreeSourceIntentImageV1, Payload: bytes.Clone(p)}
	return e
}

// rtIntentKept asserts e carries intent kind IMAGE with payload p byte-identical.
func rtIntentKept(t *testing.T, e mdbx.TreeAuthorityV1, p []byte, label string) {
	t.Helper()
	logicalMDBXAssert(t, e.SourceIntent != nil && e.SourceIntent.Kind == mdbx.TreeSourceIntentImageV1 && bytes.Equal(e.SourceIntent.Payload, p), "%s: intent %+v", label, e.SourceIntent)
}

// rtReopened reopens w and asserts the persisted envelope is want, carries p and keeps next_generation_id.
func rtReopened(t *testing.T, w *btWorld, want mdbx.TreeAuthorityV1, p []byte, label string) {
	t.Helper()
	w.reopen(t)
	got := rtEnvelope(t, w)
	logicalMDBXAssert(t, reflect.DeepEqual(got, want) && got.Authority.NextGenerationID == want.Authority.NextGenerationID, "%s reopen: %+v want %+v", label, got, want)
	rtIntentKept(t, got, p, label+" reopen")
}

// C2, C4 conversion, H1: replayTreeConversion of a persisted IMAGE REPLAY envelope carrying P keeps P byte-identical
// in the planned literal (tag 2, carrier kind 1, length and bytes) and through UpdateTreeV1 and reopen. The report is
// built here (structural-only pre-state: a live PLAN_CHANGE needs an APPLIED cursor, a legal IMAGE REPLAY the zero one).
func TestReplayTreeIntentConversion(t *testing.T) {
	p := rtIntentPayload()
	w := q148WorldOf(t)
	before := rtImageReplay(p)
	rtSet(t, w, before)
	var batch mdbx.Batch
	var planErr error
	err := w.owner.WithOperation(mdbx.LaneOperation, func(a *mdbx.OperationAccount) error {
		truth, stage, index, uerr := w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
			read, present, rerr := r.ReadTreeAuthorityV1()
			logicalMDBXAssert(t, rerr == nil && present, "C2 read: %t %v", present, rerr)
			batch, planErr = replayTreeConversion(ReplayRecomputationV1{Report: ReplayRecomputationPlanChangeV1, envelope: read, activeTip: 2})
			if planErr != nil {
				return mdbx.TreeOperationV1{}, planErr
			}
			return replayTreeOperation(batch)
		})
		logicalMDBXAssert(t, uerr == nil && truth == mdbx.CommitTruthNew && index == -1, "C2 commit: %d/%d/%d %v", truth, stage, index, uerr)
		return nil
	})
	logicalMDBXAssert(t, err == nil && planErr == nil && len(batch.Mutations) == 1, "C2 plan: %v %v %+v", err, planErr, batch)
	want := rtConverted(before, 3, 4)
	// Separate subtests: a fatal planned-literal assertion must not hide the C2 reopened assertion.
	t.Run("C4 planned literal", func(t *testing.T) {
		literal := batch.Mutations[0].Literal
		carrier := append(binary.BigEndian.AppendUint32([]byte{1}, uint32(len(p))), p...)
		logicalMDBXAssert(t, literal[0] == 2 && bytes.HasSuffix(literal, carrier), "C4 literal: tag %d, carrier suffix missing", literal[0])
		decoded, err := mdbx.DecodeTreeAuthorityV1(literal)
		logicalMDBXAssert(t, err == nil, "C4 decode: %v", err)
		rtIntentKept(t, decoded, p, "C4 planned literal")
		logicalMDBXAssert(t, reflect.DeepEqual(decoded, want), "C2 planned: %+v want %+v", decoded, want)
	})
	t.Run("C2 reopened", func(t *testing.T) {
		rtReopened(t, w, want, p, "C2")
	})
}

// rtSameBatch reports whether a and b are equal in every Batch field; the obsolete-row fields (whose element types
// carry errors) must be empty in both, as for every pair-only conversion Batch.
func rtSameBatch(a, b mdbx.Batch) bool {
	return reflect.DeepEqual(a.Mutations, b.Mutations) && a.Reverse == b.Reverse && reflect.DeepEqual(a.Consulted, b.Consulted) &&
		reflect.DeepEqual(a.ContextConsulted, b.ContextConsulted) && reflect.DeepEqual(a.LargeConsulted, b.LargeConsulted) &&
		len(a.ObsoleteDeletes)+len(b.ObsoleteDeletes)+len(a.ObsoleteConsulted)+len(b.ObsoleteConsulted) == 0
}

// C7 (RUB-1755): the PLAN_CHANGE adapter replayTreeConversion equals the common transform replayTreeWholeTarget on the
// same envelope and active tip, for ascending and reversed target IDs, with and without an existing InvalidBranchV1
// slot. Each plan is one meta key 2 mutation whose literal decodes to the independent rtConverted envelope (slot and
// retained intent unchanged) with the active-tip Consulted rows, and the caller's envelope is not mutated. Every
// expected slot is a separately allocated pointee, so an in-place write to the caller's slot cannot reach the oracle.
func TestReplayTreeWholeTargetAdapter(t *testing.T) {
	slot := func() *mdbx.InvalidBranchV1 {
		return &mdbx.InvalidBranchV1{FirstInvalidHeight: 12, FirstInvalidBlockHash: [32]byte{0x12}, ExactConsensusError: []byte("BLOCK_ERR_WEIGHT_EXCEEDED")}
	}
	none := func() *mdbx.InvalidBranchV1 { return nil }
	cases := []struct {
		label       string
		target, lag uint64
		slot        func() *mdbx.InvalidBranchV1
		lo, hi      uint64
	}{
		{"ascending", 3, 4, none, 3, 4},
		{"reversed", 4, 3, none, 3, 4},
		{"slot kept", 3, 4, slot, 3, 4},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			p := rtIntentPayload()
			before := rtImageReplay(p)
			before.Authority.Replay.TargetGenerationID, before.TargetLagGenerationID = c.target, c.lag
			before.Authority.ExcludedInvalidBranch = c.slot()
			_, err := before.Encode()
			logicalMDBXAssert(t, err == nil, "%s: fixture envelope illegal: %v", c.label, err)
			snapshot := rtImageReplay(p)
			snapshot.Authority.Replay.TargetGenerationID, snapshot.TargetLagGenerationID = c.target, c.lag
			snapshot.Authority.ExcludedInvalidBranch = c.slot()
			adapter, aerr := replayTreeConversion(ReplayRecomputationV1{Report: ReplayRecomputationPlanChangeV1, envelope: before, activeTip: 2})
			common, cerr := replayTreeWholeTarget(before, 2)
			logicalMDBXAssert(t, aerr == nil && cerr == nil && rtSameBatch(adapter, common), "%s: adapter %+v %v, common %+v %v", c.label, adapter, aerr, common, cerr)
			logicalMDBXAssert(t, len(adapter.Mutations) == 1, "%s: mutations %+v", c.label, adapter.Mutations)
			m := adapter.Mutations[0]
			logicalMDBXAssert(t, m.DBI == mdbx.TreeSchemaV1DBIs()[0] && bytes.Equal(m.Key, []byte{0x02}) && m.AfterKind == mdbx.AfterLiteral && m.BeforePresent, "%s: mutation %+v", c.label, m)
			logicalMDBXAssert(t, reflect.DeepEqual(adapter.Consulted, rtConsulted(t)), "%s: consulted %+v", c.label, adapter.Consulted)
			decoded, err := mdbx.DecodeTreeAuthorityV1(adapter.Mutations[0].Literal)
			logicalMDBXAssert(t, err == nil, "%s: decode %v", c.label, err)
			want := rtConverted(snapshot, c.lo, c.hi)
			logicalMDBXAssert(t, reflect.DeepEqual(decoded, want), "%s: planned %+v want %+v", c.label, decoded, want)
			logicalMDBXAssert(t, reflect.DeepEqual(decoded.Authority.ExcludedInvalidBranch, c.slot()), "%s: slot %+v", c.label, decoded.Authority.ExcludedInvalidBranch)
			rtIntentKept(t, decoded, p, c.label)
			logicalMDBXAssert(t, reflect.DeepEqual(before, snapshot), "%s: caller envelope mutated: %+v", c.label, before)
		})
	}
}

// C3: the post-drain representation (the C2 envelope with one GENERATION span left) and the pending
// NONE/RECOVERY_REQUIRED envelope, each carrying P, commit through UpdateTreeV1 and read back after reopen.
func TestReplayTreeIntentRetained(t *testing.T) {
	p := rtIntentPayload()
	drained := rtConverted(rtImageReplay(p), 3, 4)
	drained.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 4}}}
	for label, e := range map[string]mdbx.TreeAuthorityV1{"C3 drained": drained, "C3 pending": rtPendingIntent(p)} {
		w := q148WorldOf(t)
		rtSet(t, w, e)
		rtReopened(t, w, e, p, label)
	}
}

// C4 entry, H1: treeEntryBatch from the committed pending envelope carrying P (active CURRENT binding present) plans
// no Batch: its GENESIS_REPLAY plan keeps P, which Encode refuses, mapped to storage_capacity with the Encode cause;
// nothing is planned and the store keeps P. The intent-free pending envelope plans the entry with intent none.
func TestReplayTreeIntentEntryRefused(t *testing.T) {
	p := rtIntentPayload()
	archive := mdbx.StorageProfileArchiveV1
	for _, withIntent := range []bool{true, false} {
		label := fmt.Sprintf("C4 intent %t", withIntent)
		w, s, view := rtEntryWorld(t, func(e *mdbx.TreeAuthorityV1) {
			e.Authority.Lifecycle, e.Authority.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &archive
			if withIntent {
				e.SourceIntent = &mdbx.TreeSourceIntentV1{Kind: mdbx.TreeSourceIntentImageV1, Payload: bytes.Clone(p)}
			}
		})
		before := rtEnvelope(t, w.btWorld)
		target := mdbx.RecoveryTargetV1{ChainID: w.g.ChainID, GenesisHash: s.hashes[0], TipHash: s.tip(), TipHeight: 3, CumulativeChainwork: s.work(t, 3)}
		call := &replayEntryCall{owner: NewReplayEntryOwnerV1(view, w.g), sentinel: errors.New("c4 decision")}
		var batch mdbx.Batch
		var planErr error
		err := w.s.View(func(r *mdbx.Reader) error {
			envelope, present, rerr := r.ReadTreeAuthorityV1()
			logicalMDBXAssert(t, rerr == nil && present, "%s read: %t %v", label, present, rerr)
			batch, planErr = call.treeEntryBatch(r, envelope, 'd', target, 3)
			return nil
		})
		logicalMDBXAssert(t, err == nil, "%s view: %v", label, err)
		if !withIntent {
			logicalMDBXAssert(t, planErr == nil && call.planned && len(batch.Mutations) == 5, "%s control: %v %+v", label, planErr, batch)
			planned := rtLegal(t, batch.Mutations[0].Literal, label)
			logicalMDBXAssert(t, planned.SourceIntent == nil && reflect.DeepEqual(planned, rtEntered(before, archive, target)), "%s control plan: %+v", label, planned)
			continue
		}
		var f *selectedSideFailure
		logicalMDBXAssert(t, errors.As(planErr, &f) && f.result == selectedSideCapacity && f.cause != nil, "%s refusal: %T %v", label, planErr, planErr)
		logicalMDBXAssert(t, reflect.ValueOf(batch).IsZero() && !call.planned && call.replay == nil, "%s: batch %+v planned %t replay %+v", label, batch, call.planned, call.replay)
		rtReopened(t, w.btWorld, before, p, label)
	}
}

// C7: SelectPrunedTreeProfileV1 on the C2 PRUNE_GC/RECOVERY_REQUIRED and the pending NONE/RECOVERY_REQUIRED envelope,
// each carrying P, decides RECOVERY_REQUIRED before any write; the envelope with P is unchanged after reopen.
func TestReplayTreeIntentPrunedProfile(t *testing.T) {
	p := rtIntentPayload()
	for label, e := range map[string]mdbx.TreeAuthorityV1{"C7 converted": rtConverted(rtImageReplay(p), 3, 4), "C7 pending": rtPendingIntent(p)} {
		w := q148WorldOf(t)
		rtSet(t, w, e)
		out := w.s.SelectPrunedTreeProfileV1(true, nil, w.owner)
		logicalMDBXAssert(t, out.Decision == "RECOVERY_REQUIRED" && out.Err == nil && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && out.Authority == nil, "%s: %+v", label, out)
		rtReopened(t, w, e, p, label)
	}
}

// rtWholeTarget is the fixed target tuple of the whole-target conversion cases.
var rtWholeTarget = mdbx.RecoveryTargetV1{ChainID: [32]byte{0xc1}, GenesisHash: [32]byte{0xc2}, TipHash: [32]byte{0xc3}, TipHeight: 37, CumulativeChainwork: [40]byte{39: 1}}

// rtWhole is the C1 pre-state: REPLAY/RECOVERY_REQUIRED GENESIS_REPLAY with active CURRENT/LAG 3/4, target
// CURRENT/LAG 5/6, next 7, active profile PRUNED with B=10/U=13690, target profile ARCHIVE, APPLIED cursor 36, slot none.
func rtWhole() mdbx.TreeAuthorityV1 {
	return mdbx.TreeAuthorityV1{Authority: mdbx.StorageAuthorityV1{
		Version: 1, ActiveProfile: mdbx.StorageProfilePrunedV1, ActiveGenerationID: 3, NextGenerationID: 7, B: 10, U: 13_690,
		Phase: mdbx.StoragePhaseReplayV1, Lifecycle: mdbx.StorageLifecycleRecoveryRequiredV1,
		Replay: &mdbx.ReplayV1{TargetProfile: mdbx.StorageProfileArchiveV1, TargetGenerationID: 5, Target: rtWholeTarget, Cursor: mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: 36, BlockHash: [32]byte{0x36}}},
	}, LagGenerationID: 4, TargetLagGenerationID: 6, SourceKind: mdbx.TreeSourceGenesisReplayV1}
}

// rtWholeDone is the C1 result as an independent literal: PRUNE_GC/RECOVERY_REQUIRED, pending ARCHIVE, Replay none,
// CleanupV1 GENERATION(lo), GENERATION(hi), target lag, source kind and progress none, active 3/4, next 7, PRUNED,
// B=10/U=13690 and the given slot.
func rtWholeDone(lo, hi uint64, slot *mdbx.InvalidBranchV1) mdbx.TreeAuthorityV1 {
	archive := mdbx.StorageProfileArchiveV1
	return mdbx.TreeAuthorityV1{Authority: mdbx.StorageAuthorityV1{
		Version: 1, ActiveProfile: mdbx.StorageProfilePrunedV1, ActiveGenerationID: 3, NextGenerationID: 7, B: 10, U: 13_690,
		Phase: mdbx.StoragePhasePruneGCV1, Lifecycle: mdbx.StorageLifecycleRecoveryRequiredV1, PendingTargetProfile: &archive,
		Cleanup:               &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: lo}, {Kind: mdbx.CleanupSpanGenerationV1, GenerationID: hi}}},
		ExcludedInvalidBranch: slot,
	}, LagGenerationID: 4}
}

// rtTuple is a fresh InvalidBranchV1 (height, hash byte 0 = h, error).
func rtTuple(height uint64, h byte, err string) *mdbx.InvalidBranchV1 {
	return &mdbx.InvalidBranchV1{FirstInvalidHeight: height, FirstInvalidBlockHash: [32]byte{h}, ExactConsensusError: []byte(err)}
}

// rtWholeConsulted is the active-generation index rows of generation g at the given heights.
func rtWholeConsulted(t *testing.T, g uint64, heights ...uint64) []mdbx.ConsultedRow {
	t.Helper()
	rows := []mdbx.ConsultedRow{}
	for _, h := range heights {
		key, err := mdbx.HeightKey(g, h)
		logicalMDBXAssert(t, err == nil, "height key: %v", err)
		rows = append(rows, mdbx.ConsultedRow{DBI: mdbx.TreeSchemaV1DBIs()[2], Key: key})
	}
	return rows
}

// rtWholeRun is one conversion attempt: the planner's Batch and error and the raw UpdateTreeV1 tuple.
type rtWholeRun struct {
	batch   mdbx.Batch
	planErr error
	truth   mdbx.CommitTruth
	stage   mdbx.UpdateStage
	index   int
	err     error
}

// rtWholePlan runs one conversion attempt: build supplies the reader parameter and the input from the callback Reader;
// the planner runs inside UpdateTreeV1's callback; after, when non-nil, runs once the planner has returned and before
// the Batch is handed to replayTreeOperation.
func rtWholePlan(t *testing.T, w *btWorld, build func(r *mdbx.Reader) (*mdbx.Reader, ReplayTargetConversionInputV1), after func()) rtWholeRun {
	t.Helper()
	var c rtWholeRun
	err := w.owner.WithOperation(mdbx.LaneOperation, func(a *mdbx.OperationAccount) error {
		c.truth, c.stage, c.index, c.err = w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
			reader, input := build(r)
			c.batch, c.planErr = PlanReplayWholeTargetConversionMDBX(reader, input)
			if after != nil {
				after()
			}
			if c.planErr != nil {
				return mdbx.TreeOperationV1{}, c.planErr
			}
			return replayTreeOperation(c.batch)
		})
		return nil
	})
	logicalMDBXAssert(t, err == nil, "conversion account: %v", err)
	return c
}

// rtWholeInput is the qualified input on the callback Reader for envelope.
func rtWholeInput(envelope mdbx.TreeAuthorityV1, cause ReplayTargetConversionCauseV1, invalidity *mdbx.InvalidBranchV1) func(r *mdbx.Reader) (*mdbx.Reader, ReplayTargetConversionInputV1) {
	return func(r *mdbx.Reader) (*mdbx.Reader, ReplayTargetConversionInputV1) {
		return r, ReplayTargetConversionInputV1{Reader: r, Envelope: envelope, Cause: cause, Invalidity: invalidity}
	}
}

// rtWholeConverted asserts a NEW commit of exactly one meta key 2 mutation whose literal and read-back envelope are
// want, with the given Consulted rows; every other imaged row and every family's entry count is unchanged (C9).
func rtWholeConverted(t *testing.T, w *btWorld, image [][]byte, c rtWholeRun, want mdbx.TreeAuthorityV1, consulted []mdbx.ConsultedRow, label string) {
	t.Helper()
	logicalMDBXAssert(t, c.planErr == nil && c.err == nil && c.truth == mdbx.CommitTruthNew && c.index == -1, "%s commit: %d/%d/%d %v %v", label, c.truth, c.stage, c.index, c.planErr, c.err)
	logicalMDBXAssert(t, len(c.batch.Mutations) == 1 && reflect.DeepEqual(c.batch.Consulted, consulted), "%s plan: %+v", label, c.batch)
	m := c.batch.Mutations[0]
	logicalMDBXAssert(t, m.DBI == mdbx.TreeSchemaV1DBIs()[0] && bytes.Equal(m.Key, []byte{2}) && m.AfterKind == mdbx.AfterLiteral && m.BeforePresent, "%s mutation: %+v", label, m)
	decoded, err := mdbx.DecodeTreeAuthorityV1(m.Literal)
	logicalMDBXAssert(t, err == nil && reflect.DeepEqual(decoded, want), "%s planned: %+v %v want %+v", label, decoded, err, want)
	got := rtEnvelope(t, w)
	logicalMDBXAssert(t, reflect.DeepEqual(got, want), "%s readback: %+v want %+v", label, got, want)
	after := rtImage(t, w)
	logicalMDBXAssert(t, len(after) == len(image), "%s image shape", label)
	for i := range image {
		logicalMDBXAssert(t, i == 3 || bytes.Equal(image[i], after[i]), "%s: row %d other than the envelope changed", label, i)
	}
}

// rtWholeRefused asserts the planner's error has class, no Batch exists, UpdateTreeV1 refused it at OLD/PREWRITE and
// the image is unchanged.
func rtWholeRefused(t *testing.T, w *btWorld, image [][]byte, c rtWholeRun, class, label string) {
	t.Helper()
	logicalMDBXAssert(t, c.planErr != nil && errors.Is(c.err, c.planErr) && reflect.ValueOf(c.batch).IsZero() && recoveryClass(c.planErr, "") == class,
		"%s: batch %+v err %v want %s", label, c.batch, c.planErr, class)
	logicalMDBXAssert(t, c.truth == mdbx.CommitTruthOld && c.stage == mdbx.UpdateStagePrewrite && c.index == -1, "%s: %d/%d/%d", label, c.truth, c.stage, c.index)
	logicalMDBXAssert(t, reflect.DeepEqual(image, rtImage(t, w)), "%s: image changed", label)
}

// C1, C2, C9, C11, R3 (GENESIS_REPLAY creates no intent): TARGET_LOCAL and RECOVERY_CORE convert the fixed target pair
// into ascending GENERATION spans with pending = the target profile and nothing else changed; reversed target IDs give
// the same ascending order. Only meta key 2 changes; next_generation_id and every counter and binding stay.
func TestReplayWholeTargetConversion(t *testing.T) {
	reversed := rtWhole()
	reversed.Authority.NextGenerationID, reversed.Authority.Replay.TargetGenerationID, reversed.TargetLagGenerationID = 10, 9, 8
	reversedDone := rtWholeDone(8, 9, nil)
	reversedDone.Authority.NextGenerationID = 10
	for _, c := range []struct {
		label  string
		before mdbx.TreeAuthorityV1
		cause  ReplayTargetConversionCauseV1
		want   mdbx.TreeAuthorityV1
	}{
		{"C1 target-local", rtWhole(), ReplayTargetConversionTargetLocalV1, rtWholeDone(5, 6, nil)},
		{"C11 recovery-core", rtWhole(), ReplayTargetConversionRecoveryCoreV1, rtWholeDone(5, 6, nil)},
		{"C2 reversed", reversed, ReplayTargetConversionTargetLocalV1, reversedDone},
	} {
		w := rtNew(t, c.before)
		image := rtImage(t, w)
		run := rtWholePlan(t, w, rtWholeInput(rtEnvelope(t, w), c.cause, nil), nil)
		rtWholeConverted(t, w, image, run, c.want, rtWholeConsulted(t, 3, 0, 1), c.label)
		got := rtEnvelope(t, w)
		logicalMDBXAssert(t, got.Authority.NextGenerationID == c.before.Authority.NextGenerationID && got.SourceIntent == nil, "%s C9/R3: %+v", c.label, got)
	}
}

// C3-C6, C12: the first-wins slot effect for every cause and slot state. REPLAY_INVALIDITY writes its tuple only into
// an empty slot; an identical, a different (in height, hash, error or all three) or any slot under TARGET_LOCAL or
// RECOVERY_CORE stays byte-identical; the conversion is planned and committed in every case.
func TestReplayWholeTargetSlot(t *testing.T) {
	cause37 := func() *mdbx.InvalidBranchV1 { return rtTuple(37, 0x37, "BLOCK_ERR_SUBSIDY_EXCEEDED") }
	slots := map[string]func() *mdbx.InvalidBranchV1{
		"none":        func() *mdbx.InvalidBranchV1 { return nil },
		"identical":   cause37,
		"different":   func() *mdbx.InvalidBranchV1 { return rtTuple(12, 0x12, "BLOCK_ERR_WEIGHT_EXCEEDED") },
		"height only": func() *mdbx.InvalidBranchV1 { return rtTuple(12, 0x37, "BLOCK_ERR_SUBSIDY_EXCEEDED") },
		"hash only":   func() *mdbx.InvalidBranchV1 { return rtTuple(37, 0x12, "BLOCK_ERR_SUBSIDY_EXCEEDED") },
		"error only":  func() *mdbx.InvalidBranchV1 { return rtTuple(37, 0x37, "BLOCK_ERR_WEIGHT_EXCEEDED") },
	}
	causes := map[string]ReplayTargetConversionCauseV1{"TARGET_LOCAL": ReplayTargetConversionTargetLocalV1, "REPLAY_INVALIDITY": ReplayTargetConversionInvalidityV1, "RECOVERY_CORE": ReplayTargetConversionRecoveryCoreV1}
	for causeLabel, cause := range causes {
		for slotLabel, slot := range slots {
			label := causeLabel + " slot " + slotLabel
			before := rtWhole()
			before.Authority.ExcludedInvalidBranch = slot()
			want := rtWholeDone(5, 6, slot())
			var invalidity *mdbx.InvalidBranchV1
			if cause == ReplayTargetConversionInvalidityV1 {
				invalidity = cause37()
				if slotLabel == "none" {
					want.Authority.ExcludedInvalidBranch = cause37()
				}
			}
			w := rtNew(t, before)
			image := rtImage(t, w)
			run := rtWholePlan(t, w, rtWholeInput(rtEnvelope(t, w), cause, invalidity), nil)
			rtWholeConverted(t, w, image, run, want, rtWholeConsulted(t, 3, 0, 1), label)
		}
	}
}

// R3, C12 IMAGE: an IMAGE-sourced target converts like any other; ReplayV1 with its progress is cleared, a retained
// first-install intent stays byte-identical after commit and reopen, and intent none stays none.
func TestReplayWholeTargetIntent(t *testing.T) {
	p := rtIntentPayload()
	for _, c := range []struct {
		label  string
		intent bool
		cause  ReplayTargetConversionCauseV1
	}{{"R3 target-local intent", true, ReplayTargetConversionTargetLocalV1}, {"C12 recovery-core intent", true, ReplayTargetConversionRecoveryCoreV1}, {"R3 intent none", false, ReplayTargetConversionTargetLocalV1}} {
		before := rtImageReplay(p)
		if !c.intent {
			before.SourceIntent = nil
		}
		w := rtNew(t, before)
		image := rtImage(t, w)
		run := rtWholePlan(t, w, rtWholeInput(rtEnvelope(t, w), c.cause, nil), nil)
		want := rtConverted(before, 3, 4)
		rtWholeConverted(t, w, image, run, want, rtWholeConsulted(t, 1, 0, 1), c.label)
		if !c.intent {
			w.reopen(t)
			got := rtEnvelope(t, w)
			logicalMDBXAssert(t, got.SourceIntent == nil && reflect.DeepEqual(got, want), "%s reopen: %+v", c.label, got)
			continue
		}
		rtReopened(t, w, want, p, c.label)
	}
}

// C10: outside the closed cause/payload/ActiveTip domain the planner returns its own TERMINAL_LOCAL_INVARIANT(evidence)
// refusal (a *selectedSideFailure, never a Reader EngineError) with no Batch and nothing written, with the slot empty or
// already set; a nil reader parameter is refused the same way before any read; the bounds 0 and 4294967295 of
// ActiveTip and of the first-invalid height are admitted.
func TestReplayWholeTargetInputDomain(t *testing.T) {
	tl, inv, rc := ReplayTargetConversionTargetLocalV1, ReplayTargetConversionInvalidityV1, ReplayTargetConversionRecoveryCoreV1
	tuple := func() *mdbx.InvalidBranchV1 { return rtTuple(37, 0x37, "BLOCK_ERR_SUBSIDY_EXCEEDED") }
	high := tuple()
	high.FirstInvalidHeight = 1 << 32
	empty, nilError := tuple(), tuple()
	empty.ExactConsensusError, nilError.ExactConsensusError = []byte{}, nil
	for label, edit := range map[string]func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader{
		"nil reader": func(*mdbx.Reader, *ReplayTargetConversionInputV1) *mdbx.Reader { return nil },
		"cause 0":    func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader { in.Cause = 0; return r },
		"cause 4":    func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader { in.Cause = 4; return r },
		"cause 255":  func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader { in.Cause = 255; return r },
		"TARGET_LOCAL zero tuple": func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader {
			in.Invalidity = &mdbx.InvalidBranchV1{}
			return r
		},
		"TARGET_LOCAL tuple": func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader {
			in.Invalidity = tuple()
			return r
		},
		"RECOVERY_CORE zero tuple": func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader {
			in.Cause, in.Invalidity = rc, &mdbx.InvalidBranchV1{}
			return r
		},
		"RECOVERY_CORE tuple": func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader {
			in.Cause, in.Invalidity = rc, tuple()
			return r
		},
		"REPLAY_INVALIDITY nil": func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader { in.Cause = inv; return r },
		"REPLAY_INVALIDITY empty": func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader {
			in.Cause, in.Invalidity = inv, empty
			return r
		},
		"REPLAY_INVALIDITY nil error": func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader {
			in.Cause, in.Invalidity = inv, nilError
			return r
		},
		"ActiveTip 4294967296": func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader { in.ActiveTip = 1 << 32; return r },
		"first-invalid 4294967296": func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader {
			in.Cause, in.Invalidity = inv, high
			return r
		},
		"RECOVERY_CORE ActiveTip 2^32": func(r *mdbx.Reader, in *ReplayTargetConversionInputV1) *mdbx.Reader {
			in.Cause, in.ActiveTip = rc, 1<<32
			return r
		},
	} {
		for _, slot := range []*mdbx.InvalidBranchV1{nil, rtTuple(12, 0x12, "BLOCK_ERR_WEIGHT_EXCEEDED")} {
			stored := rtWhole()
			stored.Authority.ExcludedInvalidBranch = slot
			w := rtNew(t, stored)
			image := rtImage(t, w)
			envelope := rtEnvelope(t, w)
			run := rtWholePlan(t, w, func(r *mdbx.Reader) (*mdbx.Reader, ReplayTargetConversionInputV1) {
				in := ReplayTargetConversionInputV1{Reader: r, Envelope: envelope, Cause: tl}
				reader := edit(r, &in)
				return reader, in
			}, nil)
			var own *selectedSideFailure
			logicalMDBXAssert(t, reflect.TypeOf(run.planErr) == reflect.TypeOf(own), "C10 %s slot %v: not the planner's own refusal: %T %v", label, slot != nil, run.planErr, run.planErr)
			rtWholeRefused(t, w, image, run, selectedSideInvariant, "C10 "+label)
		}
	}
	bound, zero := tuple(), tuple()
	bound.FirstInvalidHeight, zero.FirstInvalidHeight = math.MaxUint32, 0
	for _, c := range []struct {
		label      string
		tip        uint64
		invalidity *mdbx.InvalidBranchV1
		consulted  []uint64
	}{{"ActiveTip 4294967295", math.MaxUint32, nil, []uint64{0, 1, math.MaxUint32, 1 << 32}}, {"first-invalid 4294967295", 0, bound, []uint64{0, 1}}, {"first-invalid 0", 0, zero, []uint64{0, 1}}} {
		w := rtNew(t, rtWhole())
		image := rtImage(t, w)
		envelope := rtEnvelope(t, w)
		cause := tl
		want := rtWholeDone(5, 6, nil)
		if c.invalidity != nil {
			cause, want.Authority.ExcludedInvalidBranch = inv, rtTuple(map[string]uint64{"first-invalid 4294967295": 4294967295, "first-invalid 0": 0}[c.label], 0x37, "BLOCK_ERR_SUBSIDY_EXCEEDED")
		}
		run := rtWholePlan(t, w, func(r *mdbx.Reader) (*mdbx.Reader, ReplayTargetConversionInputV1) {
			return r, ReplayTargetConversionInputV1{Reader: r, Envelope: envelope, ActiveTip: c.tip, Cause: cause, Invalidity: c.invalidity}
		}, nil)
		rtWholeConverted(t, w, image, run, want, rtWholeConsulted(t, 3, c.consulted...), "C10 admitted "+c.label)
	}
}

// R2, R4 absence, R6, R9: an envelope outside the fixed REPLAY target (NONE/STABLE, PRUNE_GC/STABLE, an already
// converted envelope), proved exact-empty absence, an input Reader other than the callback Reader, and any field of
// the complete qualified envelope differing from the reread one (active profile with its B/U included), or an input
// envelope Encode refuses, are STALE_LOCAL_PLAN with no Batch and nothing written; the domain miss, the absence, the
// envelope mismatch and the Reader mismatch each win over a malformed cause. Value-equal inputs (fresh pointees, a nil
// versus an empty progress payload) are the same envelope and convert.
func TestReplayWholeTargetContext(t *testing.T) {
	tl := ReplayTargetConversionTargetLocalV1
	for label, c := range map[string]struct {
		stored, input mdbx.TreeAuthorityV1
		cause         ReplayTargetConversionCauseV1
	}{
		"R2 NONE/STABLE":   {rtStable(), rtStable(), tl},
		"R2 PRUNE_GC":      {rtPrune(), rtPrune(), tl},
		"R9 converted":     {rtWholeDone(5, 6, nil), rtWholeDone(5, 6, nil), ReplayTargetConversionRecoveryCoreV1},
		"R4 exact-empty":   {mdbx.TreeAuthorityV1{}, rtWhole(), tl},
		"R6 before cause":  {rtWhole(), rtWholeDone(5, 6, nil), 0},
		"R2 before domain": {rtStable(), rtStable(), 255},
		"R4 before cause":  {mdbx.TreeAuthorityV1{}, rtWhole(), 0},
	} {
		w := rtNew(t, c.stored)
		image := rtImage(t, w)
		run := rtWholePlan(t, w, rtWholeInput(c.input, c.cause, nil), nil)
		rtWholeRefused(t, w, image, run, replayEntryStale, label)
	}
	image := rtImageReplay([]byte{0xa1})
	for label, c := range map[string]struct {
		stored mdbx.TreeAuthorityV1
		edit   func(e *mdbx.TreeAuthorityV1)
	}{
		"target current ID": {rtWhole(), func(e *mdbx.TreeAuthorityV1) { e.Authority.Replay.TargetGenerationID = 2 }},
		"target lag ID":     {rtWhole(), func(e *mdbx.TreeAuthorityV1) { e.TargetLagGenerationID = 1 }},
		"active ID":         {rtWhole(), func(e *mdbx.TreeAuthorityV1) { e.Authority.ActiveGenerationID = 1 }},
		"active lag ID":     {rtWhole(), func(e *mdbx.TreeAuthorityV1) { e.LagGenerationID = 2 }},
		"source kind": {rtWhole(), func(e *mdbx.TreeAuthorityV1) {
			e.SourceKind, e.Authority.Replay.Cursor, e.Progress = mdbx.TreeSourceImageV1, mdbx.ReplayCursorV1{}, image.Progress
		}},
		"target tuple": {rtWhole(), func(e *mdbx.TreeAuthorityV1) { e.Authority.Replay.Target.TipHash[1] = 1 }},
		"cursor":       {rtWhole(), func(e *mdbx.TreeAuthorityV1) { e.Authority.Replay.Cursor.Height = 35 }},
		"slot": {rtWhole(), func(e *mdbx.TreeAuthorityV1) {
			e.Authority.ExcludedInvalidBranch = rtTuple(12, 0x12, "BLOCK_ERR_WEIGHT_EXCEEDED")
		}},
		"target profile": {rtWhole(), func(e *mdbx.TreeAuthorityV1) { e.Authority.Replay.TargetProfile = mdbx.StorageProfilePrunedV1 }},
		"sequence":       {rtWhole(), func(e *mdbx.TreeAuthorityV1) { e.Authority.NextGenerationID = 8 }},
		"active profile": {rtWhole(), func(e *mdbx.TreeAuthorityV1) {
			e.Authority.ActiveProfile, e.Authority.B, e.Authority.U = mdbx.StorageProfileArchiveV1, 0, 0
		}},
		"B/U":            {rtWhole(), func(e *mdbx.TreeAuthorityV1) { e.Authority.B, e.Authority.U = 11, 13_691 }},
		"progress":       {image, func(e *mdbx.TreeAuthorityV1) { e.Progress.Payload = []byte{0xa1, 0xa3} }},
		"intent payload": {image, func(e *mdbx.TreeAuthorityV1) { e.SourceIntent.Payload = []byte{0xa2} }},
		"intent absent":  {image, func(e *mdbx.TreeAuthorityV1) { e.SourceIntent = nil }},
		"encode refused": {rtWhole(), func(e *mdbx.TreeAuthorityV1) { e.Authority.Version = 0 }},
	} {
		w := rtNew(t, c.stored)
		before := rtImage(t, w)
		input := rtEnvelope(t, w)
		c.edit(&input)
		_, eerr := input.Encode()
		logicalMDBXAssert(t, (eerr != nil) == (label == "encode refused"), "R6 %s premise: encode %v", label, eerr)
		run := rtWholePlan(t, w, rtWholeInput(input, tl, nil), nil)
		rtWholeRefused(t, w, before, run, replayEntryStale, "R6 "+label)
	}
	t.Run("R6 Reader", func(t *testing.T) {
		w := rtNew(t, rtWhole())
		var other *mdbx.Reader
		logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error { other = r; return nil }) == nil, "other Reader view")
		for label, reader := range map[string]func(r *mdbx.Reader) *mdbx.Reader{"nil": func(*mdbx.Reader) *mdbx.Reader { return nil }, "other": func(*mdbx.Reader) *mdbx.Reader { return other }} {
			for _, cause := range []ReplayTargetConversionCauseV1{tl, 0} {
				image := rtImage(t, w)
				envelope := rtEnvelope(t, w)
				run := rtWholePlan(t, w, func(r *mdbx.Reader) (*mdbx.Reader, ReplayTargetConversionInputV1) {
					return r, ReplayTargetConversionInputV1{Reader: reader(r), Envelope: envelope, Cause: cause}
				}, nil)
				rtWholeRefused(t, w, image, run, replayEntryStale, fmt.Sprintf("R6 Reader %s cause %d", label, cause))
			}
		}
	})
	p := []byte{0xa1, 0xa2}
	for label, input := range map[string]func() mdbx.TreeAuthorityV1{
		"fresh GENESIS_REPLAY": func() mdbx.TreeAuthorityV1 {
			e := rtWhole()
			e.Progress.Payload = []byte{}
			return e
		},
		"fresh IMAGE": func() mdbx.TreeAuthorityV1 { return rtImageReplay(p) },
	} {
		stored := rtWhole()
		want := rtWholeDone(5, 6, nil)
		consulted := rtWholeConsulted(t, 3, 0, 1)
		if label == "fresh IMAGE" {
			stored, want, consulted = rtImageReplay(p), rtConverted(rtImageReplay(p), 3, 4), rtWholeConsulted(t, 1, 0, 1)
		}
		w := rtNew(t, stored)
		image := rtImage(t, w)
		run := rtWholePlan(t, w, rtWholeInput(input(), tl, nil), nil)
		rtWholeConverted(t, w, image, run, want, consulted, "R6 value-equal "+label)
	}
}

// H3: the caller's tuple bytes, hash and height mutated after the planner returned (before the Batch is committed)
// change neither the planned literal nor the stored slot. The planner encodes the envelope before it returns, so the
// Batch carries only that encoded copy; this row fails if the returned literal shares the caller's bytes.
func TestReplayWholeTargetTupleIsolation(t *testing.T) {
	w := rtNew(t, rtWhole())
	image := rtImage(t, w)
	invalidity := rtTuple(37, 0x37, "BLOCK_ERR_SUBSIDY_EXCEEDED")
	run := rtWholePlan(t, w, rtWholeInput(rtEnvelope(t, w), ReplayTargetConversionInvalidityV1, invalidity), func() {
		invalidity.ExactConsensusError[0], invalidity.FirstInvalidBlockHash[0], invalidity.FirstInvalidHeight = 'X', 0x99, 99
	})
	rtWholeConverted(t, w, image, run, rtWholeDone(5, 6, rtTuple(37, 0x37, "BLOCK_ERR_SUBSIDY_EXCEEDED")), rtWholeConsulted(t, 3, 0, 1), "H3")
	logicalMDBXAssert(t, string(invalidity.ExactConsensusError) == "XLOCK_ERR_SUBSIDY_EXCEEDED", "H3 premise: the caller tuple was not mutated")
}

// rtWholeOutcome asserts a projected CLEANUP outcome: the raw tuple kept exactly, the given Result and CanonicalTruth,
// and no Decision or Replay.
func rtWholeOutcome(t *testing.T, out ReplayEntryOutcomeV1, truth mdbx.CommitTruth, stage mdbx.UpdateStage, err error, result, canon, label string) {
	t.Helper()
	logicalMDBXAssert(t, out.Truth == truth && out.Stage == stage && reflect.ValueOf(out.Err).Equal(reflect.ValueOf(err)) && out.Result == result && out.CanonicalTruth == canon &&
		out.Decision == "" && out.Replay == nil, "%s: %+v want %s/%s", label, out, result, canon)
}

// C8, C13, R5, R11: the CLEANUP projection of each stage and truth, by raw tuple. Normal NEW and OLD keep an empty
// Result; crossed outcomes map their raw truth; precommit keeps an integrity or invariant cause; the owner's exact
// step-5 capacity refusal at PREWRITE is storage_capacity (wrapped, it is no such refusal); PREWRITE otherwise
// classifies each direct cause by native storage class; only the write snapshot mismatch is STALE_LOCAL_PLAN, any
// other direct StateMismatch (the format-2 typed-operation refusal) is TERMINAL_LOCAL_INVARIANT, also when joined with
// the snapshot mismatch, while one wrapped inside another cause is not inspected.
func TestReplayWholeTargetProjection(t *testing.T) {
	engine := func(class mdbx.EngineClass, diagnostic string) error {
		return &mdbx.EngineError{Class: class, Operation: "update", Code: -30779, Diagnostic: diagnostic}
	}
	snapshot := engine(mdbx.EngineStateMismatch, "OLD/write snapshot mismatch")
	format2 := engine(mdbx.EngineStateMismatch, "typed tree operation requires tree store")
	io, integrity := engine(mdbx.EngineIO, "io"), engine(mdbx.EngineIntegrity, "integrity")
	crossed := func(truth mdbx.CommitTruth) error {
		return &mdbx.CommitError{Truth: truth, Cause: engine(mdbx.EngineCapacity, "full")}
	}
	full, _ := mdbx.NewOperationReservationOwner(mdbx.MinReservationLimit - 1)
	step5 := full.WithReservation(1, func() error { return nil })
	logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(step5), "step-5 capacity premise: %v", step5)
	old, nw, unknown := mdbx.CommitTruthOld, mdbx.CommitTruthNew, mdbx.CommitTruthUnknown
	pre, started, may := mdbx.UpdateStagePrewrite, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, mdbx.UpdateStageCommitMayHaveCrossed
	for _, c := range []struct {
		label         string
		truth         mdbx.CommitTruth
		stage         mdbx.UpdateStage
		err           error
		result, canon string
	}{
		{"C8 normal NEW", nw, may, nil, "", "NEW"},
		{"C8 normal OLD", old, pre, nil, "", "OLD"},
		{"C8 crossed old", old, may, crossed(old), "TERMINAL_PERSISTENCE(old)", "OLD"},
		{"C8 crossed new", nw, may, crossed(nw), "TERMINAL_PERSISTENCE(new)", "NEW"},
		{"C8 crossed unknown", unknown, may, crossed(unknown), "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN"},
		{"R5 capacity", old, pre, engine(mdbx.EngineCapacity, "full"), "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD"},
		{"R5 planner capacity", old, pre, &selectedSideFailure{result: "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", cause: io}, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD"},
		{"R4 io", old, pre, io, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "OLD"},
		{"R1 integrity", old, pre, integrity, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD"},
		{"R5 precommit io", old, started, io, "LOCAL_PERSISTENCE_ERROR(precommit)", "OLD"},
		{"R5 precommit integrity", old, started, errors.Join(io, integrity), "TERMINAL_STORE_INTEGRITY(canonical)", "OLD"},
		{"R5 precommit invariant", old, started, engine(mdbx.EngineLocalInvariant, "x"), "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD"},
		{"R11 snapshot", old, pre, snapshot, "STALE_LOCAL_PLAN", "OLD"},
		{"R11 format-2 refusal", old, pre, format2, "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD"},
		{"R11 joined", old, pre, errors.Join(snapshot, format2), "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD"},
		{"R11 snapshot with a wrapped refusal", old, pre, errors.Join(snapshot, &selectedSideFailure{result: "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", cause: format2}), "STALE_LOCAL_PLAN", "OLD"},
		{"R5 step-5 capacity", old, pre, step5, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD"},
		{"R5 wrapped step-5 capacity", old, pre, fmt.Errorf("charge: %w", step5), "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD"},
		{"R2 stale planner", old, pre, &selectedSideFailure{result: "STALE_LOCAL_PLAN", cause: io}, "STALE_LOCAL_PLAN", "OLD"},
	} {
		rtWholeOutcome(t, ProjectReplayWholeTargetConversionMDBX(c.truth, c.stage, c.err), c.truth, c.stage, c.err, c.result, c.canon, c.label)
	}
}

// C8, C13, R5, R11 through the planner and UpdateTreeV1: a normal commit of each cause is NEW with an empty Result; the
// engine's step-5 Pair charge refused by the full owner aggregate after the planner returned its Batch is
// LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)/OLD with the raw refusal kept and nothing written; the plan callback on
// a format-2 store never runs and the typed-operation refusal is TERMINAL_LOCAL_INVARIANT, never STALE.
func TestReplayWholeTargetProjectedCommit(t *testing.T) {
	tuple := func() *mdbx.InvalidBranchV1 { return rtTuple(37, 0x37, "BLOCK_ERR_SUBSIDY_EXCEEDED") }
	for _, c := range []struct {
		label      string
		cause      ReplayTargetConversionCauseV1
		invalidity *mdbx.InvalidBranchV1
	}{{"C8 target-local", ReplayTargetConversionTargetLocalV1, nil}, {"C8 invalidity", ReplayTargetConversionInvalidityV1, tuple()}, {"C13 recovery-core", ReplayTargetConversionRecoveryCoreV1, nil}} {
		w := rtNew(t, rtWhole())
		image := rtImage(t, w)
		run := rtWholePlan(t, w, rtWholeInput(rtEnvelope(t, w), c.cause, c.invalidity), nil)
		var slot *mdbx.InvalidBranchV1
		if c.invalidity != nil {
			slot = tuple()
		}
		rtWholeConverted(t, w, image, run, rtWholeDone(5, 6, slot), rtWholeConsulted(t, 3, 0, 1), c.label)
		rtWholeOutcome(t, ProjectReplayWholeTargetConversionMDBX(run.truth, run.stage, run.err), mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, nil, "", "NEW", c.label)
	}
	for _, cause := range []ReplayTargetConversionCauseV1{ReplayTargetConversionTargetLocalV1, ReplayTargetConversionRecoveryCoreV1} {
		label := fmt.Sprintf("R5 step-5 capacity cause %d", cause)
		w := rtNew(t, rtWhole())
		image := rtImage(t, w)
		envelope := rtEnvelope(t, w)
		var run rtWholeRun
		rtCharges(t, w.owner, mdbx.MinReservationLimit, func() {
			run = rtWholePlan(t, w, rtWholeInput(envelope, cause, nil), nil)
		})
		logicalMDBXAssert(t, run.planErr == nil && len(run.batch.Mutations) == 1 && mdbx.IsOperationReservationCapacity(run.err) && run.index == -1, "%s premise: %+v %v %v %d", label, run.batch, run.planErr, run.err, run.index)
		rtWholeOutcome(t, ProjectReplayWholeTargetConversionMDBX(run.truth, run.stage, run.err), mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, run.err, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD", label)
		logicalMDBXAssert(t, reflect.DeepEqual(image, rtImage(t, w)), "%s: image changed", label)
	}
	legacy := newReplayWorld(t, 4)
	called := false
	var truth mdbx.CommitTruth
	var stage mdbx.UpdateStage
	var err error
	logicalMDBXAssert(t, legacy.owner.WithOperation(mdbx.LaneOperation, func(a *mdbx.OperationAccount) error {
		truth, stage, _, err = legacy.store.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
			called = true
			return mdbx.TreeOperationV1{}, nil
		})
		return nil
	}) == nil, "format-2 account")
	var e *mdbx.EngineError
	logicalMDBXAssert(t, !called && errors.As(err, &e) && e.Class == mdbx.EngineStateMismatch && e.Diagnostic == "typed tree operation requires tree store", "R11 format-2 premise: %v", err)
	rtWholeOutcome(t, ProjectReplayWholeTargetConversionMDBX(truth, stage, err), mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, err, "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD", "R11 format-2 refusal")
}

// interface_contract: the cause constants, the input fields and the planner and projector signatures are exactly the
// contract's (pinned as independent literals).
func TestReplayWholeTargetExportedSignatures(t *testing.T) {
	logicalMDBXAssert(t, reflect.TypeFor[ReplayTargetConversionCauseV1]().Kind() == reflect.Uint8 &&
		ReplayTargetConversionTargetLocalV1 == 1 && ReplayTargetConversionInvalidityV1 == 2 && ReplayTargetConversionRecoveryCoreV1 == 3, "cause type and constants")
	input := reflect.TypeFor[ReplayTargetConversionInputV1]()
	fields := make([]string, input.NumField())
	for i := range fields {
		fields[i] = input.Field(i).Name + " " + input.Field(i).Type.String()
	}
	logicalMDBXAssert(t, slices.Equal(fields, []string{"Reader *mdbx.Reader", "Envelope mdbx.TreeAuthorityV1", "ActiveTip uint64", "Cause consensus.ReplayTargetConversionCauseV1", "Invalidity *mdbx.InvalidBranchV1"}), "input fields: %v", fields)
	logicalMDBXAssert(t, reflect.TypeOf(PlanReplayWholeTargetConversionMDBX).String() == "func(*mdbx.Reader, consensus.ReplayTargetConversionInputV1) (mdbx.Batch, error)" &&
		reflect.TypeOf(ProjectReplayWholeTargetConversionMDBX).String() == "func(mdbx.CommitTruth, mdbx.UpdateStage, error) consensus.ReplayEntryOutcomeV1", "planner and projector signatures")
}
