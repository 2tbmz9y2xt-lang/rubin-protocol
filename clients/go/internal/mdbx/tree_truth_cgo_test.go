//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Test-owned literals: identities and bytes are constructed here, never read from production helpers.
var (
	ttUTXO, ttCanonical, ttHeaders, ttBlocks, ttNode = schemaDBIs[1], schemaDBIs[2], schemaDBIs[3], schemaDBIs[4], TreeSchemaV1DBIs()[8]
	ttZ, ttU, ttX                                    = bytes.Repeat([]byte{0x11}, 44), bytes.Repeat([]byte{0x22}, 44), bytes.Repeat([]byte{0x33}, 46)
	ttR, ttC, ttOut                                  = bytes.Repeat([]byte{0x44}, 32), bytes.Repeat([]byte{0x55}, 32), []byte{0x09}
)

// ttHW is the writer high-water of the LAG operation by D2-7 sizes, replaced entries still counted at each draw:
// Z+2=46, U+2=46, X+2=48 (live 140), U absent 44 (184, live 138), X "x2-long" 53 (191, live 143), R ref 32 (175).
const ttHW = 191

type ttLedger struct {
	refuseAt, calls int
	log             []string
}

func (l *ttLedger) chargeV1(n uint64) error {
	l.calls++
	if l.calls == l.refuseAt {
		l.log = append(l.log, fmt.Sprintf("refuse %d", n))
		return errOperationReservationCapacity
	}
	l.log = append(l.log, fmt.Sprintf("charge %d", n))
	return nil
}

func (l *ttLedger) releaseV1(n uint64) { l.log = append(l.log, fmt.Sprintf("release %d", n)) }
func (l *ttLedger) mark(event string)  { l.log = append(l.log, event) }

func (l *ttLedger) after(t *testing.T, event string) []string {
	t.Helper()
	for i, entry := range l.log {
		if entry == event {
			return l.log[i+1:]
		}
	}
	t.Fatalf("marker %q missing from %v", event, l.log)
	return nil
}

func ttStore(t *testing.T) (*Store, string) {
	t.Helper()
	store, path, _ := treeNativeStore(t)
	// A valid authority row makes OpenTreeV1 skip the empty census, so a reopen can read seeded families.
	treeNativeSeed(t, store, 0, []byte{2}, treeNativeAuthorityBytes(t, 0, 0))
	return store, path
}

type ttRow struct {
	dbi       DBI
	key, want []byte
}

func ttReopen(t *testing.T, store *Store, path string, rows ...ttRow) {
	t.Helper()
	mustEnvironment(t, store.Close())
	opened, err := OpenTreeV1(path, environmentConfig(), [32]byte{7})
	mustEnvironment(t, err)
	defer func() { mustEnvironment(t, opened.Close()) }()
	for _, row := range rows {
		equal, err := FixtureRawRowEqual(opened, row.dbi.Rank, row.key, row.want)
		if err != nil || !equal {
			t.Fatalf("reopened %s %x: want %q (%v)", row.dbi.Name, row.key, row.want, err)
		}
	}
}

func ttTarget(dbi DBI, key []byte, value string) treeTargetV1 {
	if value == "" {
		return treeTargetV1{dbi: dbi, key: key}
	}
	return treeTargetV1{dbi: dbi, key: key, after: treeImageV1{present: true, value: []byte(value)}}
}

func ttImage(image treeImageV1, err error) string {
	if err != nil {
		return "error " + err.Error()
	}
	return fmt.Sprintf("%v:%s", image.present, image.value)
}

func ttEngine(t *testing.T, err error, class EngineClass, code int, diagnostic string) {
	t.Helper()
	treeNativeError(t, err, operationUpdate, class, code, diagnostic, nil)
}

func ttMismatch(t *testing.T, err error, diagnostic string) {
	t.Helper()
	ttEngine(t, err, EngineStateMismatch, -30779, diagnostic)
}

func ttOutcome(t *testing.T, outcome updateNativeOutcome, truth CommitTruth, stage UpdateStage) {
	t.Helper()
	if outcome.truth != truth || outcome.stage != stage || outcome.retainedWrite != nil || outcome.retainedRead != nil || outcome.valid() != nil {
		t.Fatalf("outcome %+v, want truth %d stage %d consumed", outcome, truth, stage)
	}
}

func ttCommitError(t *testing.T, outcome updateNativeOutcome, truth CommitTruth) *CommitError {
	t.Helper()
	ttOutcome(t, outcome, truth, UpdateStageCommitMayHaveCrossed)
	_, _, err := updateResult(outcome, nil)
	var commit *CommitError
	if !errors.As(err, &commit) || commit.Truth != truth {
		t.Fatalf("commit error %v", err)
	}
	ttEngine(t, commit.Cause, EngineCapacity, codeENOSPC, nativeDiagnostic(codeENOSPC))
	return commit
}

func ttLagSeed(t *testing.T, store *Store) {
	t.Helper()
	treeNativeSeed(t, store, 8, ttX, []byte("x0"))
	treeNativeSeed(t, store, 4, ttR, []byte("or"))
	treeNativeSeed(t, store, 3, ttC, []byte("oc"))
}

// ttLag is the LAG discriminating operation: P0 creates Z; P1 reads U, X then creates U and rewrites X;
// P2 reads U, X then deletes U, rewrites X and refers R. Each read is appended to seen.
func ttLag(old treeOldV1, emit treeEmitterV1, seen *[]string) error {
	return ttLagZ(old, emit, seen, "z1")
}

// ttLagZ is ttLag with P0's Z value given; a same-size value other than "z1" keeps every charge and breaks NEW at Z.
func ttLagZ(old treeOldV1, emit treeEmitterV1, seen *[]string, z string) error {
	steps := []func() error{
		func() error { return emit.emitV1(ttTarget(ttUTXO, ttZ, z)) },
		func() error { return ttLagRead(old, seen) },
		func() error { return emit.emitV1(ttTarget(ttUTXO, ttU, "v1")) },
		func() error { return emit.emitV1(ttTarget(ttNode, ttX, "x1")) },
		func() error { return ttLagRead(old, seen) },
		func() error { return emit.emitV1(ttTarget(ttUTXO, ttU, "")) },
		func() error { return emit.emitV1(ttTarget(ttNode, ttX, "x2-long")) },
		func() error { return emit.referV1(ttBlocks, ttR) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func ttLagRead(old treeOldV1, seen *[]string) error {
	for _, row := range []struct {
		dbi DBI
		key []byte
	}{{ttUTXO, ttU}, {ttNode, ttX}} {
		image, err := old.getV1(row.dbi, row.key)
		if err != nil {
			return err
		}
		*seen = append(*seen, ttImage(image, nil))
	}
	return nil
}

var ttLagSeen = "false:|true:x0|true:v1|true:x1"

type ttLagRun struct {
	ledger        ttLedger
	written, read []string
	calls         int
	extra         func(treeEmitterV1) error
	held          uint64
	readZ         string
}

func (run *ttLagRun) script() fixtureTreeScriptV1 {
	consulted := []ownedConsulted{{dbi: ttHeaders, key: ttC}}
	return fixtureTreeScriptV1{
		ledger: &run.ledger, consulted: consulted, mark: run.ledger.mark, calls: &run.calls, held: run.held,
		write: func(t *treeSectionV1) error {
			if err := t.pairPreflightV1(nil, consulted); err != nil {
				return err
			}
			if err := ttLag(t.oldV1(true), t.writerV1(), &run.written); err != nil {
				return err
			}
			if err := t.pairEmitV1(nil); err != nil {
				return err
			}
			return t.finalV1(nil, consulted)
		},
		readback: func(r *treeReadbackStateV1) error {
			z := "z1"
			if run.readZ != "" {
				z = run.readZ
			}
			if err := ttLagZ(r.oldV1(), r.emitterV1(), &run.read, z); err != nil {
				return err
			}
			if run.extra != nil {
				return run.extra(r.emitterV1())
			}
			return nil
		},
	}
}

// ttLagFault runs the LAG operation inside one large-image mode and returns the outcome and evidence.
func ttLagFault(t *testing.T, store *Store, run *ttLagRun, mode uint32, rank uint8, key []byte) (updateNativeOutcome, fixtureLargeEvidence) {
	t.Helper()
	var outcome updateNativeOutcome
	evidence, err := fixtureLargeFault(store, mode, rank, key, func() { outcome = fixtureTreeCommitV1(store, run.script()) })
	mustEnvironment(t, err)
	fixtureTreeReleaseV1(outcome)
	return outcome, evidence
}

// A3, H3 (definite NEW): checked reads see LAG1's U and X from P_w; definite commit needs no truth call.
func TestTreeLagDefiniteNewV1(t *testing.T) {
	store, path := ttStore(t)
	ttLagSeed(t, store)
	run := &ttLagRun{}
	outcome := fixtureTreeCommitV1(store, run.script())
	ttOutcome(t, outcome, CommitTruthNew, UpdateStageCommitMayHaveCrossed)
	if outcome.primary != nil || run.calls != 0 || strings.Join(run.written, "|") != ttLagSeen {
		t.Fatalf("definite NEW: %+v calls %d seen %v", outcome, run.calls, run.written)
	}
	ttReopen(t, store, path, ttRow{ttUTXO, ttU, nil}, ttRow{ttNode, ttX, []byte("x2-long")}, ttRow{ttUTXO, ttZ, []byte("z1")}, ttRow{ttBlocks, ttR, []byte("or")})
}

// A4, A8, R8, H3: commit-then-ENOSPC readback starts from an empty P_r and selects NEW; P is high-water charged.
func TestTreeLagReadbackNewV1(t *testing.T) {
	store, _ := ttStore(t)
	ttLagSeed(t, store)
	run := &ttLagRun{}
	outcome, evidence := ttLagFault(t, store, run, 8, 6, ttOut)
	commit := ttCommitError(t, outcome, CommitTruthNew)
	if commit.ReadbackCause != nil || evidence.commits < 1 || run.calls != 1 || strings.Join(run.read, "|") != ttLagSeen {
		t.Fatalf("readback NEW: %v %+v calls %d read %v", commit.ReadbackCause, evidence, run.calls, run.read)
	}
	// Non-fatal, so the after-commit check below is observed in the same run.
	if got := strings.Join(run.ledger.log, "|"); got != "charge 46|charge 46|charge 48|charge 44|charge 7|commit" {
		t.Errorf("P_w ledger log %s, want high-water %d", got, ttHW)
	}
	if after := run.ledger.after(t, "commit"); len(after) != 0 {
		t.Fatalf("ledger calls after commit %v", after)
	}
}

// R8, A6, R5: a reference, a domain identity and a Consulted row drifted after commit give UNKNOWN; break gives OLD.
func TestTreeLagReadbackDriftV1(t *testing.T) {
	for _, row := range []struct {
		name  string
		mode  uint32
		rank  uint8
		key   []byte
		truth CommitTruth
	}{
		{"reference drift", 3, 4, ttR, CommitTruthUnknown},
		{"target drift", 3, 1, ttZ, CommitTruthUnknown},
		{"consulted drift", 3, 3, ttC, CommitTruthUnknown},
		{"break", 7, 6, ttOut, CommitTruthOld},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, _ := ttStore(t)
			ttLagSeed(t, store)
			run := &ttLagRun{}
			outcome, evidence := ttLagFault(t, store, run, row.mode, row.rank, row.key)
			commit := ttCommitError(t, outcome, row.truth)
			if commit.ReadbackCause != nil || evidence.commits < 1 || row.mode == 3 && evidence.drift != 1 {
				t.Fatalf("%s: %v %+v", row.name, commit.ReadbackCause, evidence)
			}
		})
	}
}

// A5: both predicates hold, OLD wins.
func TestTreeReadbackOldFirstV1(t *testing.T) {
	store, _ := ttStore(t)
	ttLagSeed(t, store)
	steps := func(emit treeEmitterV1) error {
		if err := emit.emitV1(ttTarget(ttNode, ttX, "x1")); err != nil {
			return err
		}
		return emit.emitV1(ttTarget(ttNode, ttX, "x0"))
	}
	ledger := &ttLedger{}
	var outcome updateNativeOutcome
	evidence, err := fixtureLargeFault(store, 8, 6, ttOut, func() {
		outcome = fixtureTreeCommitV1(store, fixtureTreeScriptV1{
			ledger:   ledger,
			write:    func(t *treeSectionV1) error { return steps(t.writerV1()) },
			readback: func(r *treeReadbackStateV1) error { return steps(r.emitterV1()) },
		})
	})
	mustEnvironment(t, err)
	if commit := ttCommitError(t, outcome, CommitTruthOld); commit.ReadbackCause != nil || evidence.commits < 1 {
		t.Fatalf("OLD first: %v", commit.ReadbackCause)
	}
}

// A7, A14, M-R8, M-SEAM: the fold reads a later identity after a false predicate; the EIO read is the cause.
func TestTreeReadbackCompletesAfterFalseV1(t *testing.T) {
	store, _ := ttStore(t)
	ttLagSeed(t, store)
	var plain string
	evidence, err := fixtureLargeFault(store, 8, 4, ttR, func() {
		mustEnvironment(t, fixtureTreeOldV1(store, func(old treeOldV1) error { plain = ttImage(old.getV1(ttBlocks, ttR)); return nil }))
	})
	mustEnvironment(t, err)
	if plain != "true:or" || evidence.gets != 0 {
		t.Fatalf("ORIGINAL OLD capture %s %+v", plain, evidence)
	}
	run := &ttLagRun{readZ: "z9"}
	outcome, evidence := ttLagFault(t, store, run, 8, 4, ttR)
	commit := ttCommitError(t, outcome, CommitTruthUnknown)
	// Non-fatal, so the cause assertion below is observed in the same run.
	if evidence.gets < 1 || evidence.commits < 1 {
		t.Errorf("fault evidence %+v", evidence)
	}
	ttEngine(t, commit.ReadbackCause, EngineIO, codeEIO, nativeDiagnostic(codeEIO))
}

// R9, M28, M-R7: S_r is drawn before any snapshot read; the exact budget S_r + HW selects NEW, one byte less refuses.
func TestTreeReadbackBudgetV1(t *testing.T) {
	const maxStateEntry = 65596
	for _, row := range []struct {
		name string
		held uint64
		key  []byte
		rank uint8
		new  bool
	}{
		{"S_r refused before read", 2*maxStateEntry - 1, ttR, 4, false},
		{"exact", 2*maxStateEntry + ttHW, ttOut, 6, true},
		{"exact minus one", 2*maxStateEntry + ttHW - 1, ttOut, 6, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, _ := ttStore(t)
			ttLagSeed(t, store)
			run := &ttLagRun{held: row.held}
			outcome, evidence := ttLagFault(t, store, run, 8, row.rank, row.key)
			if evidence.commits < 1 {
				t.Fatalf("commit transport %+v", evidence)
			}
			if row.new {
				if commit := ttCommitError(t, outcome, CommitTruthNew); commit.ReadbackCause != nil {
					t.Fatal(commit.ReadbackCause)
				}
				return
			}
			commit := ttCommitError(t, outcome, CommitTruthUnknown)
			// Non-fatal, so the after-commit check below is observed in the same run.
			if !treeSameErrorV1(commit.ReadbackCause, errOperationReservationCapacity) {
				t.Errorf("budget refusal %v", commit.ReadbackCause)
			}
			if after := run.ledger.after(t, "commit"); len(after) != 0 {
				t.Fatalf("ledger calls after commit %v", after)
			}
		})
	}
}

// R4, M10, M12: one readback entry beyond the writer stops the readback without a ledger call.
func TestTreeReadbackOverBudgetV1(t *testing.T) {
	store, _ := ttStore(t)
	ttLagSeed(t, store)
	run := &ttLagRun{}
	var later, small error
	run.extra = func(emit treeEmitterV1) error {
		err := emit.referV1(ttHeaders, bytes.Repeat([]byte{0x66}, 32))
		later = emit.emitV1(ttTarget(ttUTXO, bytes.Repeat([]byte{0x67}, 44), "v"))
		small = emit.referV1(ttHeaders, []byte{0x68})
		return err
	}
	outcome, _ := ttLagFault(t, store, run, 8, 6, ttOut)
	commit := ttCommitError(t, outcome, CommitTruthUnknown)
	// Non-fatal, so each of the three properties is observed in the same run.
	if !treeSameErrorV1(commit.ReadbackCause, errOperationReservationCapacity) || !treeSameErrorV1(later, errOperationReservationCapacity) || !treeSameErrorV1(small, errOperationReservationCapacity) {
		t.Errorf("over budget %v / %v / %v", commit.ReadbackCause, later, small)
	}
	_, _, err := updateResult(outcome, nil)
	if IsOperationReservationCapacity(err) || !IsOperationReservationCapacity(commit.ReadbackCause) {
		t.Errorf("capacity identity %v / %v", err, commit.ReadbackCause)
	}
	if after := run.ledger.after(t, "commit"); len(after) != 0 {
		t.Fatalf("ledger calls after commit %v", after)
	}
}

// H1: a readback step failure is UNKNOWN with that exact cause, although the transport really committed NEW.
func TestTreeReadbackStepFailureV1(t *testing.T) {
	store, path := ttStore(t)
	ttLagSeed(t, store)
	sentinel := errors.New("scripted readback failure")
	run := &ttLagRun{extra: func(treeEmitterV1) error { return sentinel }}
	outcome, _ := ttLagFault(t, store, run, 8, 6, ttOut)
	if commit := ttCommitError(t, outcome, CommitTruthUnknown); !treeSameErrorV1(commit.ReadbackCause, sentinel) {
		t.Fatalf("cause %v", commit.ReadbackCause)
	}
	ttReopen(t, store, path, ttRow{ttUTXO, ttU, nil}, ttRow{ttNode, ttX, []byte("x2-long")})
}

// H2: read-abort faults keep the existing retained/consumed shapes through the tree and the legacy readback.
func TestTreeReadbackAbortFaultsV1(t *testing.T) {
	for _, mode := range []uint32{15, 16} {
		for _, legacy := range []bool{false, true} {
			store, _ := ttStore(t)
			ttLagSeed(t, store)
			run := &ttLagRun{}
			script := run.script()
			if legacy {
				script.readback = nil
			}
			var outcome updateNativeOutcome
			evidence, err := fixtureLargeFault(store, mode, 6, ttOut, func() { outcome = fixtureTreeCommitV1(store, script) })
			mustEnvironment(t, err)
			retained := outcome.retainedRead != nil
			fixtureTreeReleaseV1(outcome)
			abort := outcome.secondary
			if mode == 15 && !retained || mode == 16 && retained || evidence.commits < 1 {
				t.Fatalf("mode %d legacy %v: %+v", mode, legacy, outcome)
			}
			want := map[uint32]int{15: codeThreadMismatch, 16: codeEIO}[mode]
			engine, ok := directTestEngineError(abort)
			if !ok || engine.Operation != string(operationAbort) || engine.Code != want {
				t.Fatalf("mode %d legacy %v secondary %v", mode, legacy, abort)
			}
		}
	}
}

// H3: RESULT_TRUE is definite OLD at the reached stage without a truth call.
func TestTreeResultTrueV1(t *testing.T) {
	store, _ := ttStore(t)
	calls := 0
	outcome := fixtureTreeCommitV1(store, fixtureTreeScriptV1{
		ledger: &ttLedger{}, calls: &calls,
		write: func(t *treeSectionV1) error {
			if err := t.writerV1().emitV1(ttTarget(ttUTXO, ttZ, "z1")); err != nil {
				return err
			}
			return fixtureTreeBreakV1(t)
		},
		readback: func(*treeReadbackStateV1) error { return nil },
	})
	ttOutcome(t, outcome, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit)
	if !outcome.commitAttempted || calls != 0 {
		t.Fatalf("RESULT_TRUE %+v calls %d", outcome, calls)
	}
}

// A1, A2, A11, A12, M6, M7, M19, M20: amended and checked reads over P_w, references and the ledger.
func TestTreeAmendedReadV1(t *testing.T) {
	store, path := ttStore(t)
	a, b, c := []byte{0xa1}, []byte{0xb1}, []byte{0xc1}
	for _, row := range []ttRow{{ttUTXO, a, []byte("oa")}, {ttUTXO, b, []byte("ob")}, {ttUTXO, c, []byte("oc")}} {
		treeNativeSeed(t, store, 1, row.key, row.want)
	}
	read := func(old treeOldV1) string {
		var out []string
		for _, key := range [][]byte{a, b, c} {
			out = append(out, ttImage(old.getV1(ttUTXO, key)))
		}
		for _, from := range [][]byte{a, append([]byte{0xa1}, 0), append([]byte{0xb1}, 0), append([]byte{0xc1}, 0)} {
			key, image, ok, err := old.nextV1(ttUTXO, from)
			out = append(out, fmt.Sprintf("%x=%s/%v", key, ttImage(image, err), ok))
		}
		return strings.Join(out, " ")
	}
	var plain string
	mustEnvironment(t, fixtureTreeOldV1(store, func(old treeOldV1) error { plain = read(old); return nil }))
	if plain != "true:oa true:ob true:oc a1=true:oa/true b1=true:ob/true c1=true:oc/true =false:/false" {
		t.Fatalf("plain ORIGINAL OLD %s", plain)
	}
	ledger := &ttLedger{}
	mustEnvironment(t, fixtureTreeSectionV1(store, ledger, func(s *treeSectionV1) error {
		if s.pBudgetV1() != 0 || read(s.oldV1(false)) != plain || read(s.oldV1(true)) != plain {
			t.Fatal("A11 empty section reads")
		}
		w := s.writerV1()
		mustEnvironment(t, w.emitV1(ttTarget(ttUTXO, a, "na")))
		mustEnvironment(t, w.emitV1(ttTarget(ttUTXO, b, "")))
		mustEnvironment(t, w.referV1(ttUTXO, c))
		want := "true:na false: true:oc a1=true:na/true c1=true:oc/true c1=true:oc/true =false:/false"
		if got := read(s.oldV1(false)); got != want {
			t.Fatalf("A1 amended %s", got)
		}
		if got := read(s.oldV1(true)); got != want {
			t.Fatalf("A2 checked %s", got)
		}
		held := s.pBudgetV1()
		mustEnvironment(t, w.referV1(ttUTXO, c))
		mustEnvironment(t, w.referV1(ttUTXO, a))
		r := bytes.Repeat([]byte{0x99}, 7)
		mustEnvironment(t, w.referV1(ttBlocks, r))
		if got := strings.Join(ledger.log, "|"); got != "charge 3|charge 1|charge 1|charge 7" || s.pBudgetV1() != held+7 {
			t.Fatalf("A12 reference charges %s", got)
		}
		image, err := s.oldV1(true).getV1(ttBlocks, r)
		if err != nil || image.present {
			t.Fatalf("A12 reference wrote: %v %v", image, err)
		}
		return nil
	}))
	ttReopen(t, store, path, ttRow{ttUTXO, a, []byte("oa")}, ttRow{ttUTXO, b, []byte("ob")})
}

// R1, R2, M3, M14, M24: a stale protected view on a row or a node row is the exact snapshot mismatch.
func TestTreeCheckedStaleV1(t *testing.T) {
	cases := []struct {
		name   string
		dbi    DBI
		key    []byte
		seeded bool
		next   bool
	}{
		{"row point", ttUTXO, ttU, true, false},
		{"row inserted in range", ttUTXO, ttU, false, true},
		{"node point", ttNode, ttX, true, false},
		{"node range", ttNode, ttX, true, true},
	}
	for _, row := range cases {
		for _, written := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s written %v", row.name, written), func(t *testing.T) {
				store, path := ttStore(t)
				if row.seeded {
					treeNativeSeed(t, store, row.dbi.Rank, row.key, []byte("n0"))
				}
				ledger := &ttLedger{}
				var outcome updateNativeOutcome
				drift, err := FixtureWriteSnapshotDrift(store, row.dbi.Rank, row.key, func() {
					outcome = fixtureTreeCommitV1(store, fixtureTreeScriptV1{ledger: ledger, mark: ledger.mark, write: func(s *treeSectionV1) error {
						if written {
							mustEnvironment(t, s.writerV1().emitV1(ttTarget(ttUTXO, ttZ, "z1")))
						}
						if unchecked := ttImage(s.oldV1(false).getV1(row.dbi, row.key)); row.seeded && unchecked != "true:n0" {
							t.Fatalf("unchecked read %s", unchecked)
						}
						if row.next {
							_, _, _, err := s.oldV1(true).nextV1(row.dbi, row.key[:1])
							return err
						}
						_, err := s.oldV1(true).getV1(row.dbi, row.key)
						return err
					}})
				})
				mustEnvironment(t, err)
				ttMismatch(t, outcome.primary, "OLD/write snapshot mismatch")
				stage := UpdateStagePrewrite
				if written {
					stage = UpdateStageWriteStartedDefinitelyPrecommit
				}
				ttOutcome(t, outcome, CommitTruthOld, stage)
				// Non-fatal, so the after-abort check below is observed in the same run.
				if drift != 1 {
					t.Errorf("drift %d", drift)
				}
				if after := ledger.after(t, "abort"); len(after) != 0 {
					t.Fatalf("ledger calls after abort %v", after)
				}
				ttReopen(t, store, path, ttRow{row.dbi, row.key, []byte{0x7f}}, ttRow{ttUTXO, ttZ, nil})
			})
		}
	}
	plain, err := Create(t.TempDir()+"/plain", environmentConfig())
	mustEnvironment(t, err)
	defer func() { mustEnvironment(t, plain.Close()) }()
	if _, err := FixtureWriteSnapshotDrift(plain, 8, ttX, func() {}); err == nil || err.Error() != "invalid write snapshot drift fixture" {
		t.Fatalf("non-tree rank 8: %v", err)
	}
}

// R3, M11, M-REL: a refused P_w growth leaves P_w and the budget unchanged and aborts without a release.
func TestTreeWriterChargeRefusedV1(t *testing.T) {
	store, path := ttStore(t)
	ttLagSeed(t, store)
	ledger := &ttLedger{refuseAt: 3}
	var after string
	var held uint64
	outcome := fixtureTreeCommitV1(store, fixtureTreeScriptV1{ledger: ledger, mark: ledger.mark, write: func(s *treeSectionV1) error {
		var seen []string
		err := ttLag(s.oldV1(true), s.writerV1(), &seen)
		after, held = ttImage(s.oldV1(false).getV1(ttNode, ttX)), s.pBudgetV1()
		return err
	}})
	if !treeSameErrorV1(outcome.primary, errOperationReservationCapacity) || after != "true:x0" || held != 92 {
		t.Fatalf("refusal %v after %s held %d", outcome.primary, after, held)
	}
	ttOutcome(t, outcome, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit)
	if got := strings.Join(ledger.log, "|"); got != "charge 46|charge 46|refuse 48|abort" {
		t.Fatalf("ledger %s", got)
	}
	ttReopen(t, store, path, ttRow{ttNode, ttX, []byte("x0")}, ttRow{ttUTXO, ttZ, nil})
}

// R6, R7, M18, M23: references and the Pair/Consulted domain are checked against ORIGINAL OLD.
func TestTreeFinalAndPairPreflightV1(t *testing.T) {
	pairKey := bytes.Repeat([]byte{0x70}, 44)
	pair := []ownedMutation{{dbi: ttUTXO, key: pairKey, after: AfterLiteral, literal: []byte("p1")}}
	for _, row := range []struct {
		name, diagnostic string
		dbi              DBI
		key              []byte
		final            bool
	}{
		{"reference", "final update image mismatch", ttBlocks, ttR, true},
		{"pair target", "OLD/write snapshot mismatch", ttUTXO, pairKey, false},
		{"consulted", "OLD/write snapshot mismatch", ttHeaders, ttC, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, path := ttStore(t)
			ttLagSeed(t, store)
			calls := 0
			consulted := []ownedConsulted{{dbi: ttHeaders, key: ttC}}
			var outcome updateNativeOutcome
			_, err := FixtureWriteSnapshotDrift(store, row.dbi.Rank, row.key, func() {
				outcome = fixtureTreeCommitV1(store, fixtureTreeScriptV1{
					ledger: &ttLedger{}, pair: pair, consulted: consulted, calls: &calls,
					readback: func(*treeReadbackStateV1) error { return nil },
					write: func(s *treeSectionV1) error {
						if !row.final {
							return s.pairPreflightV1(pair, consulted)
						}
						mustEnvironment(t, s.writerV1().referV1(ttBlocks, ttR))
						mustEnvironment(t, s.writerV1().emitV1(ttTarget(ttUTXO, ttZ, "z1")))
						return s.finalV1(nil, nil)
					},
				})
			})
			mustEnvironment(t, err)
			ttMismatch(t, outcome.primary, row.diagnostic)
			stage := UpdateStagePrewrite
			if row.final {
				stage = UpdateStageWriteStartedDefinitelyPrecommit
			}
			ttOutcome(t, outcome, CommitTruthOld, stage)
			if calls != 0 {
				t.Fatal("truth function called")
			}
			var pairWant []byte
			if bytes.Equal(row.key, pairKey) {
				pairWant = []byte{0x7f}
			}
			ttReopen(t, store, path, ttRow{ttUTXO, ttZ, nil}, ttRow{ttUTXO, pairKey, pairWant})
		})
	}
}

// A9, M13: zero primitives use only the Pair domain and the legacy readback (truth = nil).
func TestTreeZeroPrimitivesV1(t *testing.T) {
	insert, replace := bytes.Repeat([]byte{0x71}, 44), bytes.Repeat([]byte{0x72}, 44)
	pair := []ownedMutation{
		{dbi: ttUTXO, key: insert, after: AfterLiteral, literal: []byte("i1")},
		{dbi: ttUTXO, key: replace, beforePresent: true, after: AfterLiteral, literal: []byte("r1")},
	}
	consulted := []ownedConsulted{{dbi: ttHeaders, key: ttC}}
	for _, row := range []struct {
		name  string
		mode  uint32
		key   []byte
		truth CommitTruth
		rank  uint8
	}{
		{"definite", 0, nil, CommitTruthNew, 0},
		{"enospc", 8, ttOut, CommitTruthNew, 6},
		{"break", 7, ttOut, CommitTruthOld, 6},
		{"drift", 3, insert, CommitTruthUnknown, 1},
		{"consulted before write", 14, ttC, CommitTruthOld, 3},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, path := ttStore(t)
			treeNativeSeed(t, store, 1, replace, []byte("r0"))
			treeNativeSeed(t, store, 3, ttC, []byte("oc"))
			ledger := &ttLedger{}
			var outcome updateNativeOutcome
			var held uint64
			op := func() {
				outcome = fixtureTreeCommitV1(store, fixtureTreeScriptV1{ledger: ledger, pair: pair, consulted: consulted, write: func(s *treeSectionV1) error {
					if err := s.pairPreflightV1(pair, consulted); err != nil {
						return err
					}
					if err := s.pairEmitV1(pair); err != nil {
						return err
					}
					err := s.finalV1(pair, consulted)
					held = s.pBudgetV1()
					return err
				}})
			}
			if row.mode == 0 {
				op()
			} else {
				_, err := fixtureLargeFault(store, row.mode, row.rank, row.key, op)
				mustEnvironment(t, err)
			}
			if held != 0 || len(ledger.log) != 0 {
				t.Fatalf("zero primitives charged: %d %v", held, ledger.log)
			}
			if row.mode == 14 {
				ttMismatch(t, outcome.primary, "OLD/write snapshot mismatch")
				ttOutcome(t, outcome, CommitTruthOld, UpdateStagePrewrite)
				ttReopen(t, store, path, ttRow{ttUTXO, insert, nil}, ttRow{ttUTXO, replace, []byte("r0")})
				return
			}
			if row.mode == 0 {
				ttOutcome(t, outcome, CommitTruthNew, UpdateStageCommitMayHaveCrossed)
				return
			}
			ttCommitError(t, outcome, row.truth)
		})
	}
}

// R10, R11, R12, R16, M8, M27, M-PRIOR: mode 13 changes the write txn right after its first put.
func TestTreeWriteHookMismatchV1(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{0x81}, 44), bytes.Repeat([]byte{0x82}, 44)
	for _, row := range []struct {
		name       string
		dbi        DBI
		armed      []byte
		code       int
		diagnostic string
		script     func(s *treeSectionV1) error
		rows       []ttRow
	}{
		{"G1a fused", ttUTXO, k1, -30779, "final update image mismatch", func(s *treeSectionV1) error {
			return s.writerV1().emitV1(ttTarget(ttUTXO, k1, "v1"))
		}, []ttRow{{ttUTXO, k1, nil}}},
		{"G1b P_w target", ttUTXO, ttU, -30779, "final update image mismatch", func(s *treeSectionV1) error {
			mustEnvironment(t, s.writerV1().emitV1(ttTarget(ttUTXO, ttU, "")))
			mustEnvironment(t, s.writerV1().emitV1(ttTarget(ttUTXO, k1, "vr")))
			return s.finalV1(nil, nil)
		}, []ttRow{{ttUTXO, ttU, []byte("od")}, {ttUTXO, k1, nil}}},
		{"G1c reference", ttBlocks, ttR, -30779, "final update image mismatch", func(s *treeSectionV1) error {
			mustEnvironment(t, s.writerV1().referV1(ttBlocks, ttR))
			mustEnvironment(t, s.writerV1().emitV1(ttTarget(ttUTXO, k1, "v1")))
			return s.finalV1(nil, nil)
		}, []ttRow{{ttBlocks, ttR, []byte("or")}}},
		{"prior absent KEYEXIST", ttUTXO, k2, codeKeyExist, nativeDiagnostic(codeKeyExist), func(s *treeSectionV1) error {
			mustEnvironment(t, s.writerV1().emitV1(ttTarget(ttUTXO, k1, "v1")))
			return s.writerV1().emitV1(ttTarget(ttUTXO, k2, "v2"))
		}, []ttRow{{ttUTXO, k1, nil}, {ttUTXO, k2, nil}}},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, path := ttStore(t)
			treeNativeSeed(t, store, 1, ttU, []byte("od"))
			treeNativeSeed(t, store, 4, ttR, []byte("or"))
			var outcome updateNativeOutcome
			evidence, err := fixtureLargeFault(store, 13, row.dbi.Rank, row.armed, func() {
				outcome = fixtureTreeCommitV1(store, fixtureTreeScriptV1{ledger: &ttLedger{}, write: row.script})
			})
			mustEnvironment(t, err)
			ttEngine(t, outcome.primary, EngineStateMismatch, row.code, row.diagnostic)
			ttOutcome(t, outcome, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit)
			if evidence.drift != 1 || evidence.commits != 0 {
				t.Fatalf("evidence %+v", evidence)
			}
			ttReopen(t, store, path, row.rows...)
		})
	}
}

// R13, R14, R15, R17, M29, M30, M-DEL: begin, Pair put/delete and emit delete failures stay the exact native error.
func TestTreeSelectedDamageV1(t *testing.T) {
	kp := bytes.Repeat([]byte{0x91}, 44)
	insert := []ownedMutation{{dbi: ttUTXO, key: kp, after: AfterLiteral, literal: []byte("p1")}}
	remove := []ownedMutation{{dbi: ttUTXO, key: ttU, beforePresent: true, after: AfterAbsent}}
	pairScript := func(pair []ownedMutation) func(s *treeSectionV1) error {
		return func(s *treeSectionV1) error {
			if err := s.pairPreflightV1(pair, nil); err != nil {
				return err
			}
			return s.pairEmitV1(pair)
		}
	}
	ran := false
	for _, row := range []struct {
		name     string
		scenario SelectedDamageScenario
		rank     uint8
		key      []byte
		code     int
		class    EngineClass
		stage    UpdateStage
		script   func(s *treeSectionV1) error
	}{
		{"begin", SelectedDamageWriteBeginTxnFull, 0, nil, codeTxnFull, EngineTransaction, UpdateStagePrewrite, func(*treeSectionV1) error { ran = true; return nil }},
		{"pair put", SelectedDamagePutEIO, 1, kp, codeEIO, EngineIO, UpdateStageWriteStartedDefinitelyPrecommit, pairScript(insert)},
		{"pair delete", SelectedDamageDeleteEIO, 0, nil, codeEIO, EngineIO, UpdateStageWriteStartedDefinitelyPrecommit, pairScript(remove)},
		{"emit delete", SelectedDamageDeleteEIO, 0, nil, codeEIO, EngineIO, UpdateStageWriteStartedDefinitelyPrecommit, func(s *treeSectionV1) error {
			return s.writerV1().emitV1(ttTarget(ttUTXO, ttU, ""))
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, path := ttStore(t)
			treeNativeSeed(t, store, 1, ttU, []byte("od"))
			ledger := &ttLedger{}
			var outcome updateNativeOutcome
			evidence, err := FixtureSelectedDamage(store, nil, row.scenario, row.rank, row.key, func() {
				outcome = fixtureTreeCommitV1(store, fixtureTreeScriptV1{ledger: ledger, write: row.script})
			})
			mustEnvironment(t, err)
			ttEngine(t, outcome.primary, row.class, row.code, nativeDiagnostic(row.code))
			ttOutcome(t, outcome, CommitTruthOld, row.stage)
			if ran || evidence.Faults != 1 || evidence.Commits != 0 || len(ledger.log) != 0 || row.scenario == SelectedDamageDeleteEIO && evidence.Deletes != 1 || row.scenario == SelectedDamageWriteBeginTxnFull && evidence.BeginWrite != 1 {
				t.Fatalf("evidence %+v log %v ran %v", evidence, ledger.log, ran)
			}
			ttReopen(t, store, path, ttRow{ttUTXO, ttU, []byte("od")}, ttRow{ttUTXO, kp, nil})
		})
	}
	if diagnostic := nativeDiagnostic(codeEIO); diagnostic != fmt.Sprintf("error %d", codeEIO) {
		t.Fatalf("EIO diagnostic %s", diagnostic)
	}
}

// R18, R19, M-NF, M-ABS: a canonical-v1 row deleted after ORIGINAL OLD began and before the write txn.
func TestTreeOutOfBandDeleteV1(t *testing.T) {
	kd := append(make([]byte, 7), 1, 0, 0, 0, 0, 0, 0, 0, 5)
	for _, checked := range []bool{false, true} {
		t.Run(fmt.Sprintf("checked %v", checked), func(t *testing.T) {
			store, _, _ := treeNativeStore(t)
			mustEnvironment(t, fixtureSeedPrefixRawRow(store, ttCanonical, kd, []byte("od")))
			ledger := &ttLedger{}
			var outcome updateNativeOutcome
			var control string
			var checkedErr error
			evidence, err := FixtureCanonicalTipStep(store, 4, kd, nil, false, func() {
				if !checked {
					outcome = fixtureTreeCommitV1(store, fixtureTreeScriptV1{ledger: ledger, write: func(s *treeSectionV1) error {
						return s.writerV1().emitV1(ttTarget(ttCanonical, kd, ""))
					}})
					return
				}
				mustEnvironment(t, fixtureTreeSectionV1(store, ledger, func(s *treeSectionV1) error {
					control = ttImage(s.oldV1(false).getV1(ttCanonical, kd))
					_, checkedErr = s.oldV1(true).getV1(ttCanonical, kd)
					outcome = s.abortV1(checkedErr)
					return nil
				}))
			})
			mustEnvironment(t, err)
			if checked {
				if control != "true:od" {
					t.Fatalf("control %s", control)
				}
				ttMismatch(t, checkedErr, "OLD/write snapshot mismatch")
				ttOutcome(t, outcome, CommitTruthOld, UpdateStagePrewrite)
			} else {
				ttEngine(t, outcome.primary, EngineStateMismatch, codeNotFound, "MDBX_NOTFOUND: No matching key/data pair found")
				ttOutcome(t, outcome, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit)
			}
			if evidence.Drift < 1 || evidence.Commits != 0 || len(ledger.log) != 0 {
				t.Fatalf("evidence %+v log %v", evidence, ledger.log)
			}
			var after string
			mustEnvironment(t, fixtureTreeOldV1(store, func(old treeOldV1) error { after = ttImage(old.getV1(ttCanonical, kd)); return nil }))
			if after != "false:" {
				t.Fatalf("after %s", after)
			}
		})
	}
}

// R20, M-CANON-SKIP, M-CANON-LATE: canonical pairing runs first in the Pair preflight.
func TestTreePairPreflightPairingV1(t *testing.T) {
	x, work := [32]byte{0x10}, [40]byte{39: 1}
	forward := canonicalForwardLiteral(3, 7, x, work)
	owner := canonicalOwnerPairOf(forward)
	owned := func(m Mutation) ownedMutation {
		return ownedMutation{dbi: m.DBI, key: m.Key, after: m.AfterKind, literal: m.Literal}
	}
	for _, row := range []struct {
		name  string
		pair  []ownedMutation
		drift bool
	}{
		{"unpaired", []ownedMutation{owned(forward)}, false},
		{"unpaired drifted", []ownedMutation{owned(forward)}, true},
		{"paired", []ownedMutation{owned(forward), owned(owner)}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, _, _ := treeNativeStore(t)
			var preflight error
			var outcome updateNativeOutcome
			op := func() {
				outcome = fixtureTreeCommitV1(store, fixtureTreeScriptV1{ledger: &ttLedger{}, write: func(s *treeSectionV1) error {
					preflight = s.pairPreflightV1(row.pair, nil)
					return errors.Join(preflight, errors.New("stop"))
				}})
			}
			if row.drift {
				drift, err := FixtureWriteSnapshotDrift(store, 2, forward.Key, op)
				mustEnvironment(t, err)
				if drift < 1 {
					t.Fatal("drift not fired")
				}
			} else {
				op()
			}
			ttOutcome(t, outcome, CommitTruthOld, UpdateStagePrewrite)
			if len(row.pair) == 2 {
				if preflight != nil {
					t.Fatal(preflight)
				}
				return
			}
			ttEngine(t, preflight, EngineInvalidInput, codeEINVAL, "unpaired canonical owner mutation")
			var after string
			mustEnvironment(t, fixtureTreeOldV1(store, func(old treeOldV1) error { after = ttImage(old.getV1(ttCanonical, forward.Key)); return nil }))
			if want := map[bool]string{false: "false:", true: "true:\x7f"}[row.drift]; after != want {
				t.Fatalf("after abort %q", after)
			}
		})
	}
}

func BenchmarkTreeProjectionStoreV1(b *testing.B) {
	b.ReportAllocs()
	key, value := bytes.Repeat([]byte{1}, 44), bytes.Repeat([]byte{2}, 64)
	for i := 0; i < b.N; i++ {
		var p treeProjectionV1
		for j := byte(0); j < 16; j++ {
			key[0] = j
			at, found := p.findV1(ttUTXO, key)
			p.storeV1(at, found, ttUTXO, key, treeEntryImageV1, value)
		}
	}
}

// M-R8: a failed plain getV1 point read of ORIGINAL OLD at the writer position (mode 28) is
// nativeError(operationUpdate, rc) (D14-8), never operationGet, and it is the abort primary.
func TestTreeOldReadFailureV1(t *testing.T) {
	store, _ := ttStore(t)
	treeNativeSeed(t, store, 1, ttU, []byte("od"))
	var read error
	var outcome updateNativeOutcome
	evidence, err := fixtureLargeFault(store, 28, 1, ttU, func() {
		outcome = fixtureTreeCommitV1(store, fixtureTreeScriptV1{ledger: &ttLedger{}, write: func(s *treeSectionV1) error {
			_, read = s.oldV1(false).getV1(ttUTXO, ttU)
			return read
		}})
	})
	mustEnvironment(t, err)
	fixtureTreeReleaseV1(outcome)
	if evidence.gets < 1 || outcome.truth != CommitTruthOld {
		t.Fatalf("old read fault %+v %+v", evidence, outcome)
	}
	ttEngine(t, read, EngineIO, codeEIO, nativeDiagnostic(codeEIO))
	ttEngine(t, outcome.primary, EngineIO, codeEIO, nativeDiagnostic(codeEIO))
}

// M-R8n: a failed plain nextV1 lower-bound read (treeReadNextV1) is nativeError(operationUpdate, rc) (D14-8). Mode 29
// fails every lower-bound read of the second intercepted RDONLY txn on a DBI other than the armed one: the outer
// seam's ORIGINAL OLD is the first RDONLY txn and reads normally, the nested seam's ORIGINAL OLD is the second.
func TestTreeNextReadFailureV1(t *testing.T) {
	store, _ := ttStore(t)
	treeNativeSeed(t, store, 1, ttU, []byte("od"))
	var control string
	var failed error
	evidence, err := fixtureLargeFault(store, 29, 4, ttR, func() {
		mustEnvironment(t, fixtureTreeOldV1(store, func(outer treeOldV1) error {
			key, image, ok, err := outer.nextV1(ttUTXO, ttU[:1])
			control = fmt.Sprintf("%x=%s/%v", key, ttImage(image, err), ok)
			return fixtureTreeOldV1(store, func(inner treeOldV1) error {
				_, _, _, failed = inner.nextV1(ttUTXO, ttU[:1])
				return nil
			})
		}))
	})
	mustEnvironment(t, err)
	if control != fmt.Sprintf("%x=true:od/true", ttU) || evidence.gets != 1 {
		t.Errorf("control %s evidence %+v", control, evidence)
	}
	ttEngine(t, failed, EngineIO, codeEIO, nativeDiagnostic(codeEIO))
}

// L3-LT literals: keys in ascending order b, c, d, e, a, a2, f on one DBI of rank below 8; no byte of va or va2
// occurs in any other literal of the row.
var (
	ltB, ltC, ltD, ltE, ltA, ltA2, ltF = bytes.Repeat([]byte{0x01}, 44), bytes.Repeat([]byte{0x02}, 44), bytes.Repeat([]byte{0x03}, 44), bytes.Repeat([]byte{0x04}, 44), bytes.Repeat([]byte{0x05}, 44), bytes.Repeat([]byte{0x06}, 44), bytes.Repeat([]byte{0x07}, 44)
	ltVA, ltVA2                        = []byte{0xa1, 0xa2, 0xa3, 0xa4}, []byte{0xb1, 0xb2, 0xb3, 0xb4}
)

const ltOD, ltVD1, ltVB, ltVC1, ltVC2 = "\x42", "\x41\x41", "\x21\x21", "\x31", "\x32\x32\x32"

// ltHeld checks that the held a and a2 images still equal va and va2 after step.
func ltHeld(step string, ia, ia2 treeImageV1) error {
	if !ia.present || !bytes.Equal(ia.value, ltVA) || !ia2.present || !bytes.Equal(ia2.value, ltVA2) {
		return fmt.Errorf("L3-LT held images after %s: %x %x", step, ia.value, ia2.value)
	}
	return nil
}

func ltPrimitive0(emit treeEmitterV1) error {
	for _, target := range []treeTargetV1{ttTarget(ttUTXO, ltC, ltVC1), ttTarget(ttUTXO, ltD, ltVD1), {dbi: ttUTXO, key: ltA, after: treeImageV1{true, ltVA}}, {dbi: ttUTXO, key: ltA2, after: treeImageV1{true, ltVA2}}} {
		if err := emit.emitV1(target); err != nil {
			return err
		}
	}
	return nil
}

// ltScript is the L3-LT operation at either position; any held-image divergence is returned as an error.
func ltScript(old treeOldV1, emit treeEmitterV1) error {
	if err := ltPrimitive0(emit); err != nil {
		return err
	}
	ia, err := old.getV1(ttUTXO, ltA)
	if err != nil {
		return err
	}
	ia2, err := old.getV1(ttUTXO, ltA2)
	if err != nil {
		return err
	}
	steps := []struct {
		name string
		do   func() error
	}{
		{"insert b", func() error { return emit.emitV1(ttTarget(ttUTXO, ltB, ltVB)) }},
		{"longer c", func() error { return emit.emitV1(ttTarget(ttUTXO, ltC, ltVC2)) }},
		{"absent d", func() error { return emit.emitV1(ttTarget(ttUTXO, ltD, "")) }},
		{"refer e", func() error { return emit.referV1(ttUTXO, ltE) }},
	}
	for _, step := range steps {
		if err = step.do(); err != nil {
			return err
		}
		if err = ltHeld(step.name, ia, ia2); err != nil {
			return err
		}
	}
	if err = emit.emitV1(treeTargetV1{dbi: ttUTXO, key: ltF, after: ia}); err != nil {
		return err
	}
	if f, err := old.getV1(ttUTXO, ltF); err != nil || !f.present || !bytes.Equal(f.value, ltVA) {
		return fmt.Errorf("L3-LT f %s, want va", ttImage(f, err))
	}
	return nil
}

// L3-LT, M-LT-REUSE: a held P image survives insert, longer replacement, absent marker and reference of other
// identities and can be emitted as another identity's value, at the writer and the readback position (D20 item 1).
func TestTreeHeldImageLifetimeV1(t *testing.T) {
	t.Run("writer", func(t *testing.T) {
		store, _ := ttStore(t)
		treeNativeSeed(t, store, 1, ltD, []byte(ltOD))
		var script error
		mustEnvironment(t, fixtureTreeSectionV1(store, &ttLedger{}, func(s *treeSectionV1) error {
			script = ltScript(s.oldV1(false), s.writerV1())
			return nil
		}))
		if script != nil {
			t.Fatal(script)
		}
	})
	t.Run("readback", func(t *testing.T) {
		store, _ := ttStore(t)
		treeNativeSeed(t, store, 1, ltD, []byte(ltOD))
		ledger := &ttLedger{}
		var written, read error
		script := fixtureTreeScriptV1{
			ledger: ledger, mark: ledger.mark,
			write: func(s *treeSectionV1) error {
				if written = ltScript(s.oldV1(false), s.writerV1()); written != nil {
					return written
				}
				return s.finalV1(nil, nil)
			},
			readback: func(r *treeReadbackStateV1) error {
				read = ltScript(r.oldV1(), r.emitterV1())
				return read
			},
		}
		var outcome updateNativeOutcome
		evidence, err := fixtureLargeFault(store, 8, 6, ttOut, func() { outcome = fixtureTreeCommitV1(store, script) })
		mustEnvironment(t, err)
		fixtureTreeReleaseV1(outcome)
		if written != nil || read != nil {
			t.Fatalf("writer %v / readback %v", written, read)
		}
		if commit := ttCommitError(t, outcome, CommitTruthNew); commit.ReadbackCause != nil || evidence.commits < 1 {
			t.Fatalf("L3-LT readback %v %+v", commit.ReadbackCause, evidence)
		}
	})
}
