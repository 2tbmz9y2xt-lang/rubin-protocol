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
