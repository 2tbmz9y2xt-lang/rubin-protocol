//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"
	"weak"
)

// Test-owned literals for the L5a composer rows. Keys, frames, values, bindings and amounts are built here from the
// schema layouts and the D12-E/D13-14/D14-2/D33-D37 constants, never through tree_compose_cgo.go.
const (
	tcStep  = 65_536 + 4_096 + 4_096 + 1_144 // W + F_fixed + C + R = 74,872
	tcV     = 65_560
	tcL2    = 147_968
	tcSr    = 131_192
	tcBrFix = 288_400 // W + F_fixed + C + R + V + L2
)

var (
	tcB0, tcB1, tcB2 = tdTxid(0xb0), tdTxid(0xb1), tdTxid(0xb2)
	tcT0, tcTU, tcTC = tdTxid(0x10), tdTxid(0x20), tdTxid(0x30)
	tcF0, tcFU, tcFC = tdFrame(100, 0, nil), tdFrame(200, 0, []byte{1}), tdFrame(300, 0, nil)
	tcOldEP          = tcEndpoint(4, tdTxid(0x04))
	tcSentinel       = errors.New("tc provider sentinel")
)

// tcLedger is the scriptable test ledger: limit (0 = none), refuse the n-th charge, hooks at the n-th charge,
// and violation records (never t.Fatal: releaseV1 runs on the worker goroutine).
type tcLedger struct {
	limit, held uint64
	refuseAt    int
	calls       int
	log         []string
	hook        map[int]func()
	noCharge    bool
	refuseStep  bool // refuse the next step-1 charge
	refuseNext  bool // refuse the next charge of any amount
	refuseOther bool // refuse the next charge whose amount is not tcL2 (R2)
	refuseL2    int  // refuse the refuseL2-th following charge of amount tcL2 (R13)
	stepHeld    []uint64
	violations  []string
	before      func(n uint64) // runs at the start of every chargeV1 (H6, H7)
}

func (l *tcLedger) chargeV1(n uint64) error {
	l.calls++
	if l.before != nil {
		l.before(n)
	}
	if hook := l.hook[l.calls]; hook != nil {
		hook()
	}
	if l.noCharge {
		l.violations = append(l.violations, fmt.Sprintf("charge %d after readback entry", n))
	}
	if n == tcStep {
		l.stepHeld = append(l.stepHeld, l.held)
	}
	if l.armed(n) || l.calls == l.refuseAt || l.limit != 0 && n > l.limit-l.held {
		l.refuseStep, l.refuseNext, l.refuseOther = false, false, false
		l.log = append(l.log, fmt.Sprintf("refuse %d", n))
		return errOperationReservationCapacity
	}
	l.held += n
	l.log = append(l.log, fmt.Sprintf("charge %d", n))
	return nil
}

// armed reports whether a provider-set selector refuses this charge of amount n.
func (l *tcLedger) armed(n uint64) bool {
	if l.refuseL2 > 0 && n == tcL2 {
		l.refuseL2--
		if l.refuseL2 == 0 {
			return true
		}
	}
	return l.refuseStep && n == tcStep || l.refuseNext || l.refuseOther && n != tcL2
}

func (l *tcLedger) releaseV1(n uint64) {
	if n > l.held {
		l.violations = append(l.violations, fmt.Sprintf("release %d above held %d", n, l.held))
		return
	}
	l.held -= n
	l.log = append(l.log, fmt.Sprintf("release %d", n))
}

func (l *tcLedger) mark(s string) { l.log = append(l.log, s) }

// tcPrim is one test primitive and its provider. act runs after the stream at a position (nil: return nil).
type tcPrim struct {
	prim    treePrimitiveV1
	txCount uint32
	events  []tdEv
	calls   [3]int
	ledger  *tcLedger
	name    string
	act     func(pos treePositionV1, old *Reader, rec *treeRecorderV1) error
	custom  func(old *Reader, rec *treeRecorderV1) error // replaces the stream and act
}

func (p *tcPrim) source(pos treePositionV1, old *Reader, rec *treeRecorderV1) error {
	p.calls[pos]++
	p.ledger.mark(fmt.Sprintf("enter %d %s", pos, p.name))
	if pos == treeReadbackV1 && p.name == "C" {
		p.ledger.noCharge = true
	}
	var err error
	if p.custom != nil {
		err = p.custom(old, rec)
	} else {
		err = p.stream(rec)
	}
	if err == nil && p.custom == nil && p.act != nil {
		err = p.act(pos, old, rec)
	}
	p.ledger.mark(fmt.Sprintf("return %d %s", pos, p.name))
	return err
}

func (p *tcPrim) stream(rec *treeRecorderV1) error {
	if err := rec.beginV1(p.txCount, uint32(len(p.events)), [16]byte{}); err != nil {
		return err
	}
	for _, e := range p.events {
		if err := e.feed(rec); err != nil {
			return err
		}
	}
	return nil
}

func tcEndpoint(height uint64, block [32]byte) TreeEndpointV1 {
	var work [40]byte
	work[39] = byte(height)
	return TreeEndpointV1{Kind: TreeEndpointAppliedV1, Height: height, BlockHash: block, CumulativeChainwork: work}
}

func tcForward(kind uint8, g, height uint64, block [32]byte) treePrimitiveV1 {
	return treePrimitiveV1{direction: treeForwardV1, kind: kind, undo: treeUndoWriteOrReuseV1, generation: g, height: height, block: block, endpoint: tcEndpoint(height, block)}
}

func tcEntry(key, value []byte) testTreeEntry {
	var k [36]byte
	copy(k[:], key[8:])
	return testTreeEntry{k, value}
}

func tcBindingKey(g uint64) []byte { return append([]byte{0x11}, tdUTXOKey(g, [32]byte{}, 0)[:8]...) }

func tcBinding(t *testing.T, g uint64, ep TreeEndpointV1, entries ...testTreeEntry) []byte {
	t.Helper()
	return tcBindingID(t, [32]byte{7}, g, ep, entries...)
}

func tcBindingID(t *testing.T, id [32]byte, g uint64, ep TreeEndpointV1, entries ...testTreeEntry) []byte {
	t.Helper()
	var top *testTreeNode
	if len(entries) > 0 {
		node := testTreeBuild(g, entries, map[string][]byte{})
		top = &node
	}
	binding := testTreeOldBinding(top, ep)
	binding.DatabaseID = id
	encoded, err := binding.Encode()
	mustEnvironment(t, err)
	return encoded
}

// tcScene is the A1 plan: CURRENT (gen 1, height 10, Pair body B0, coinbase T0), LAG1 (gen 2, height 5, stored
// body B1, coinbase u) and LAG2 (gen 2, height 6, stored body B2, coinbase c2 and tx 1 spending u).
type tcScene struct {
	store  *Store
	path   string
	ledger *tcLedger
	prims  []*tcPrim
	pair   []ownedMutation
}

func tcNew(t *testing.T, n int) *tcScene {
	t.Helper()
	store, path := ttStore(t)
	treeNativeSeed(t, store, 0, tcBindingKey(1), tcBinding(t, 1, tcOldEP))
	treeNativeSeed(t, store, 0, tcBindingKey(2), tcBinding(t, 2, tcOldEP))
	treeNativeSeed(t, store, 4, tcB1[:], tcFU)
	treeNativeSeed(t, store, 4, tcB2[:], tcFC)
	s := &tcScene{store: store, path: path, ledger: &tcLedger{}}
	s.pair = []ownedMutation{{dbi: ttBlocks, key: tcB0[:], after: AfterLiteral, literal: tcF0}}
	all := []*tcPrim{
		{name: "C", prim: tcForward(treeKindConnectV1, 1, 10, tcB0), txCount: 1, events: []tdEv{tdCreate(tcT0, 0, 0, 0, uint32(len(tcF0)))}},
		{name: "L1", prim: tcForward(treeKindLagForwardV1, 2, 5, tcB1), txCount: 1, events: []tdEv{tdCreate(tcTU, 0, 0, 0, uint32(len(tcFU)))}},
		{name: "L2", prim: tcForward(treeKindLagForwardV1, 2, 6, tcB2), txCount: 2, events: []tdEv{tdCreate(tcTC, 0, 0, 0, uint32(len(tcFC))), tdSpend(tcTU, 0, 1, 0)}},
	}
	for _, p := range all[:n] {
		p.ledger = s.ledger
	}
	s.prims = all[:n]
	return s
}

func (s *tcScene) plan() *treePlanV1 {
	plan := &treePlanV1{pair: s.pair}
	for _, p := range s.prims {
		plan.primitives = append(plan.primitives, treePrimitivePlanV1{treePrimitiveV1: p.prim, source: p.source})
	}
	return plan
}

type tcResult struct {
	truth  CommitTruth
	stage  UpdateStage
	index  int
	unwind treeUnwindV1
	err    error
}

func (s *tcScene) run(hook func()) tcResult {
	var r tcResult
	r.truth, r.stage, r.index, r.unwind, r.err = fixtureTreeComposeV1(s.store, s.ledger, s.plan(), hook)
	return r
}

// goexitRun runs the seam in a goroutine whose provider calls runtime.Goexit; inspect runs before resumeV1.
func (s *tcScene) goexitRun(t *testing.T, inspect func(tcResult)) {
	t.Helper()
	done, resumed := make(chan struct{}), false
	go func() {
		defer close(done)
		r := s.run(nil)
		inspect(r)
		r.unwind.resumeV1()
		resumed = true
	}()
	<-done
	if resumed {
		t.Fatal("statement after resumeV1 ran")
	}
}

func (r tcResult) want(t *testing.T, truth CommitTruth, stage UpdateStage, index int) {
	t.Helper()
	if r.truth != truth || r.stage != stage || r.index != index {
		t.Fatalf("result truth %d stage %d index %d (err %v), want %d %d %d", r.truth, r.stage, r.index, r.err, truth, stage, index)
	}
}

// check is want without stopping, so the named assertions after it in a row still run. It is not a t.Helper, so each
// field fails at its own line here.
func (r tcResult) check(t *testing.T, truth CommitTruth, stage UpdateStage, index int) {
	if r.truth != truth {
		t.Errorf("result truth %d (err %v), want %d", r.truth, r.err, truth)
	}
	if r.stage != stage {
		t.Errorf("result stage %d (err %v), want %d", r.stage, r.err, stage)
	}
	if r.index != index {
		t.Errorf("result index %d (err %v), want %d", r.index, r.err, index)
	}
}

// tcFirstRefusal is the first refused amount in the ledger log, or "(none)".
func tcFirstRefusal(log []string) string {
	for _, e := range log {
		if strings.HasPrefix(e, "refuse ") {
			return e
		}
	}
	return "(none)"
}

// reopenNow is reopen for the rows a row names before its first fatal check; it reports with t.Errorf.
func (s *tcScene) reopenNow(t *testing.T, rows ...ttRow) {
	t.Helper()
	if s.store.state == storeOPEN {
		mustEnvironment(t, s.store.Close())
	}
	opened, err := OpenTreeV1(s.path, environmentConfig(), [32]byte{7})
	mustEnvironment(t, err)
	defer func() { mustEnvironment(t, opened.Close()) }()
	for _, row := range rows {
		equal, err := FixtureRawRowEqual(opened, row.dbi.Rank, row.key, row.want)
		if err != nil || !equal {
			t.Errorf("reopened %s %x: want %x (%v)", row.dbi.Name, row.key, row.want, err)
		}
	}
}

func (s *tcScene) settled(t *testing.T) {
	t.Helper()
	if s.ledger.held != 0 {
		t.Errorf("ledger held %d, want 0 (log %v)", s.ledger.held, s.ledger.log)
	}
	if len(s.ledger.violations) != 0 {
		t.Errorf("ledger violations %v", s.ledger.violations)
	}
}

// settledNow is settled for a goroutine that may not call t.Fatal (H4 before resumeV1).
func (s *tcScene) settledNow(t *testing.T) {
	if s.ledger.held != 0 {
		t.Errorf("ledger before resume held %d, want 0", s.ledger.held)
	}
	if len(s.ledger.violations) != 0 {
		t.Errorf("ledger before resume violations %v", s.ledger.violations)
	}
}

// consumed checks the CLOSED Store and the next legacy Update returning (want, Prewrite, the cached terminal) without a
// callback (D868: store.terminalTruth clamped by refusedUpdate; want is the truth the row states).
func (s *tcScene) consumed(t *testing.T, want CommitTruth, err error) {
	t.Helper()
	if s.store.state != storeCLOSED {
		t.Errorf("store state %v, want CLOSED", s.store.state)
	}
	if s.store.terminal == nil {
		t.Errorf("store terminal nil, want the cached terminal")
	}
	calls := 0
	truth, stage, next := s.store.Update(func(*Reader) (Batch, error) { calls++; return Batch{}, nil })
	if calls != 0 {
		t.Errorf("next Update callback count %d, want 0", calls)
	}
	if stage != UpdateStagePrewrite {
		t.Errorf("next Update stage %d, want Prewrite", stage)
	}
	if next == nil || err != nil && !sameError(next, err) {
		t.Errorf("next Update err %v, want cached terminal %v", next, err)
	}
	if truth != want {
		t.Errorf("next Update truth %d, want %d", truth, want)
	}
}

// following runs the next legal operation on an OPEN Store: a seam call of a zero-primitive plan whose one Pair puts a
// fresh blocks-v1 key, expected NEW at stage 3; it returns that row for the reopen.
func (s *tcScene) following(t *testing.T) ttRow {
	t.Helper()
	if s.store.state != storeOPEN {
		t.Fatalf("store state %v before the following seam call, want OPEN", s.store.state)
	}
	key := tdTxid(0xee)
	s.prims = nil
	s.pair = []ownedMutation{{dbi: ttBlocks, key: key[:], after: AfterLiteral, literal: []byte{0x5a}}}
	r := s.run(nil)
	r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	if r.err != nil {
		t.Fatalf("following seam call err %v", r.err)
	}
	return ttRow{ttBlocks, key[:], []byte{0x5a}}
}

func (s *tcScene) reopen(t *testing.T, rows ...ttRow) {
	t.Helper()
	if s.store.state == storeOPEN {
		mustEnvironment(t, s.store.Close())
	}
	opened, err := OpenTreeV1(s.path, environmentConfig(), [32]byte{7})
	mustEnvironment(t, err)
	defer func() { mustEnvironment(t, opened.Close()) }()
	for _, row := range rows {
		equal, err := FixtureRawRowEqual(opened, row.dbi.Rank, row.key, row.want)
		if err != nil || !equal {
			t.Errorf("reopened %s %x: want %x (%v)", row.dbi.Name, row.key, row.want, err)
		}
	}
}

// reopenOpen closes the Store if OPEN, reopens it, checks rows and keeps the reopened Store for the next seam call.
func (s *tcScene) reopenOpen(t *testing.T, rows ...ttRow) {
	t.Helper()
	if s.store.state == storeOPEN {
		mustEnvironment(t, s.store.Close())
	}
	opened, err := OpenTreeV1(s.path, environmentConfig(), [32]byte{7})
	mustEnvironment(t, err)
	t.Cleanup(func() { _ = opened.Close() })
	for _, row := range rows {
		equal, err := FixtureRawRowEqual(opened, row.dbi.Rank, row.key, row.want)
		if err != nil || !equal {
			t.Errorf("reopened %s %x: want %x (%v)", row.dbi.Name, row.key, row.want, err)
		}
	}
	s.store = opened
}

func tcValue(frame []byte, height uint64) []byte { return tdFormed(frame, height, 1) }

// oldRows are the ORIGINAL OLD bytes of every A1 target.
func (s *tcScene) oldRows(t *testing.T) []ttRow {
	return []ttRow{
		{ttUTXO, tdUTXOKey(1, tcT0, 0), nil},
		{ttBlocks, tcB0[:], nil},
		{schemaDBIs[5], tdManifestKey(tcB0), nil},
		{TreeSchemaV1DBIs()[0], tcBindingKey(1), tcBinding(t, 1, tcOldEP)},
		{ttUTXO, tdUTXOKey(2, tcTU, 0), nil},
		{TreeSchemaV1DBIs()[0], tcBindingKey(2), tcBinding(t, 2, tcOldEP)},
	}
}

// newRows are the NEW bytes of the three-primitive A1 plan.
func (s *tcScene) newRows(t *testing.T) []ttRow {
	kT0, kU, kC := tdUTXOKey(1, tcT0, 0), tdUTXOKey(2, tcTU, 0), tdUTXOKey(2, tcTC, 0)
	vT0, vU, vC := tcValue(tcF0, 10), tcValue(tcFU, 5), tcValue(tcFC, 6)
	return []ttRow{
		{ttUTXO, kT0, vT0},
		{ttBlocks, tcB0[:], tcF0},
		{schemaDBIs[5], tdManifestKey(tcB0), tdManifest(10, [16]byte{}, 1, 0)},
		{TreeSchemaV1DBIs()[0], tcBindingKey(1), tcBinding(t, 1, tcEndpoint(10, tcB0), tcEntry(kT0, vT0))},
		{ttUTXO, kU, nil},
		{ttUTXO, kC, vC},
		{schemaDBIs[5], tdManifestKey(tcB1), tdManifest(5, [16]byte{}, 1, 0)},
		{schemaDBIs[5], tdManifestKey(tcB2), tdManifest(6, [16]byte{}, 2, 1)},
		{schemaDBIs[5], tdEntryKey(tcB2, tcTU, 1, 0, 0), vU},
		{TreeSchemaV1DBIs()[0], tcBindingKey(2), tcBinding(t, 2, tcEndpoint(6, tcB2), tcEntry(kC, vC))},
	}
}

func tcHr(maxEvents uint64) uint64 { return tcSr + tcBrFix + tdSize*maxEvents }

// A1, M1, M5, M20, M23, M27, M36, M37, M43, M44, M-C: order and charge placement on a definite commit.
func TestTreeComposeOrderV1(t *testing.T) {
	s := tcNew(t, 3)
	r := s.run(nil)
	r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	if r.err != nil {
		t.Errorf("A1 err %v, want nil", r.err)
	}
	if r.unwind.kind != 0 {
		t.Errorf("A1 unwind %+v, want none", r.unwind)
	}
	r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	log := s.ledger.log
	for j, p := range s.prims {
		if p.calls[treeWriterV1] != 1 {
			t.Fatalf("%s writer calls %d", p.name, p.calls[treeWriterV1])
		}
		at := tcIndex(t, log, fmt.Sprintf("enter 1 %s", p.name))
		prev := "(none)"
		if at > 0 {
			prev = log[at-1]
		}
		if prev != fmt.Sprintf("charge %d", tcStep) {
			t.Fatalf("primitive %d: %q precedes entry, want the step-1 charge (%v)", j, prev, log)
		}
	}
	budgets := tcPBudgets(t)
	if want := []uint64{0, budgets[0], budgets[1]}; fmt.Sprint(s.ledger.stepHeld) != fmt.Sprint(want) {
		t.Fatalf("held before each step-1 charge %v, want the P budget after the previous primitive %v", s.ledger.stepHeld, want)
	}
	tcReleasedBefore(t, log, "L1", 1)
	tcReleasedBefore(t, log, "L2", 1)
	if last := tcLastCharge(log); last != fmt.Sprintf("charge %d", tcHr(2)) {
		t.Fatalf("last charge %q, want H_r %d", last, tcHr(2))
	}
	s.settled(t)
	if treeReaderBytesV1 != 208+728+128+80 || tcStep != 74_872 {
		t.Fatal("R literal drifted")
	}
	tcAllocationGuards(t, s.store)
	s.reopen(t, append(s.newRows(t), s.following(t))...)
}

// tcP replays P_w per D2-7 (len(key)+len(value); len(key) for an absent marker or reference). The new entry is
// covered before its copy while a replaced entry is still held (D5-2 shortfall before the copy), and the replaced
// size leaves live after it; high is the high-water mark, the P budget.
type tcP struct {
	live, high uint64
	sizes      map[string]uint64
}

func (p *tcP) put(rank int, key []byte, value int) {
	id := fmt.Sprintf("%d:%x", rank, key)
	n := uint64(len(key) + value)
	p.high = max(p.high, p.live+n)
	p.live = p.live - p.sizes[id] + n
	p.sizes[id] = n
}

// tcPBudgets is the P budget after CURRENT, LAG1 and LAG2 of the A1 plan, from the planned images in applyV1 order
// (D14-1 as amended by D20: a forward SPEND's undo entry precedes its UTXO effect) and L2's node and binding targets.
func tcPBudgets(t *testing.T) [3]uint64 {
	p := &tcP{sizes: map[string]uint64{}}
	kT0, kU, kC := tdUTXOKey(1, tcT0, 0), tdUTXOKey(2, tcTU, 0), tdUTXOKey(2, tcTC, 0)
	vT0, vU, vC := tcValue(tcF0, 10), tcValue(tcFU, 5), tcValue(tcFC, 6)
	leaf := func(g uint64, key []byte) []byte { return testTreeNodeKey(g, 288, [36]byte(key[8:])) }
	manifest := len(tdManifest(0, [16]byte{}, 0, 0))
	var out [3]uint64
	p.put(1, kT0, len(vT0))
	p.put(5, tdManifestKey(tcB0), manifest)
	p.put(8, leaf(1, kT0), 32)
	p.put(0, tcBindingKey(1), len(tcBinding(t, 1, tcEndpoint(10, tcB0), tcEntry(kT0, vT0))))
	out[0] = p.high
	p.put(4, tcB1[:], 0)
	p.put(1, kU, len(vU))
	p.put(5, tdManifestKey(tcB1), manifest)
	p.put(8, leaf(2, kU), 32)
	p.put(0, tcBindingKey(2), len(tcBinding(t, 2, tcEndpoint(5, tcB1), tcEntry(kU, vU))))
	out[1] = p.high
	p.put(4, tcB2[:], 0)
	p.put(1, kC, len(vC))
	p.put(5, tdEntryKey(tcB2, tcTU, 1, 0, 0), len(vU))
	p.put(1, kU, 0)
	p.put(5, tdManifestKey(tcB2), manifest)
	p.put(8, leaf(2, kU), 0)
	p.put(8, leaf(2, kC), 32)
	p.put(0, tcBindingKey(2), len(tcBinding(t, 2, tcEndpoint(6, tcB2), tcEntry(kC, vC))))
	out[2] = p.high
	return out
}

var tcOldSink treeOldV1

// tcAllocAvg is the runtime.MemStats TotalAlloc delta of f averaged over 100 runs after one warm-up run.
func tcAllocAvg(f func()) float64 {
	f()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 100 {
		f()
	}
	runtime.ReadMemStats(&after)
	return float64(after.TotalAlloc-before.TotalAlloc) / 100
}

// tcAllocationGuards are the A1 bounds behind R = 208 + 728 + 128 + 80 (D33, D34, D36, D37) on a read txn of the
// committed A1 Store.
func tcAllocationGuards(t *testing.T, store *Store) {
	t.Helper()
	if size := unsafe.Sizeof(Reader{}); size > 208 {
		t.Fatalf("Reader is %d bytes, above 208 (D33)", size)
	}
	old, err := treeBeginV1(store.env, false)
	mustEnvironment(t, err)
	defer updateAbortOld(old)
	reader := store.newUpdateReaderV1(old)
	defer func() { reader.expire().retire() }()
	tcVisitGuard(t, reader)
	tcOldGuard(t, &treeSectionV1{old: old, handles: store.dbis}, &treeReadbackStateV1{old: old, handles: store.dbis})
	marker := append(append(make([]byte, 32), 1), make([]byte, 44)...)
	projection := &treeProjectionV1{entries: []treeEntryV1{{dbi: schemaDBIs[5], key: marker, kind: treeEntryAbsentV1}}}
	tcSeekGuard(t, &treeAmendedV1{old: old, handles: store.dbis, p: projection}, marker)
}

// tcVisitGuard: one LargeImageBlockBodyV1 visit of CURRENT's committed body with one ReadAt into a preallocated
// 65,536-byte buffer allocates at most 728 bytes (D34).
func tcVisitGuard(t *testing.T, reader *Reader) {
	t.Helper()
	buf, reads := make([]byte, 65_536), 0
	visitor := func(row LargeImageRowV1) error {
		reads++
		n, err := row.ReadAt(buf, 0)
		if n != len(tcF0) {
			return fmt.Errorf("read %d bytes: %w", n, err)
		}
		return nil
	}
	var visitErr error
	visit := tcAllocAvg(func() {
		visitErr = errors.Join(visitErr, reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: LargeImageBlockBodyV1, Hash: tcB0}, visitor))
	})
	t.Logf("D34 visit allocation %.1f bytes", visit)
	if visitErr != nil || visit > 728 || reads != 101 {
		t.Fatalf("block-body visit with one ReadAt: %.1f bytes, %d reads, err %v (D34 bound 728)", visit, reads, visitErr)
	}
}

// tcOldGuard: each oldV1 result stored into a package-level treeOldV1 allocates at most 64 bytes (D36).
func tcOldGuard(t *testing.T, section *treeSectionV1, readback *treeReadbackStateV1) {
	t.Helper()
	for _, row := range []struct {
		name string
		f    func()
	}{
		{"checked", func() { tcOldSink = section.oldV1(true) }},
		{"writer", func() { tcOldSink = section.oldV1(false) }},
		{"readback", func() { tcOldSink = readback.oldV1() }},
	} {
		got := tcAllocAvg(row.f)
		t.Logf("D36 %s oldV1 allocation %.1f bytes", row.name, got)
		if got > 64 {
			t.Fatalf("%s oldV1 allocates %.1f bytes, above 64 (D36)", row.name, got)
		}
	}
}

// tcSeekGuard: one nextV1 (write nil, so only mergedNextV1) from 0x00 x 32 over the shadowed 77-byte absent marker
// allocates at most 80 bytes (D37); the marker is stepped over, so the returned key sorts after it.
func tcSeekGuard(t *testing.T, amended *treeAmendedV1, marker []byte) {
	t.Helper()
	var key []byte
	var nextErr error
	from := make([]byte, 32)
	got := tcAllocAvg(func() {
		var err error
		key, _, _, err = amended.nextV1(schemaDBIs[5], from)
		nextErr = errors.Join(nextErr, err)
	})
	t.Logf("D37 seek allocation %.1f bytes", got)
	if nextErr != nil || got > 80 || string(key) <= string(marker) {
		t.Fatalf("seek over a shadowed marker: %.1f bytes, key %x, err %v (D37 bound 80)", got, key, nextErr)
	}
}

func tcIndex(t *testing.T, log []string, entry string) int {
	t.Helper()
	for i, e := range log {
		if e == entry {
			return i
		}
	}
	t.Fatalf("%q missing from %v", entry, log)
	return -1
}

// tcReleasedBefore checks that the step-1 charge, D_j + V and the L2 allowance of the previous primitive were
// released before next's step-1 charge (the entry of next minus one).
func tcReleasedBefore(t *testing.T, log []string, next string, events uint64) {
	t.Helper()
	window := strings.Join(log[:tcIndex(t, log, "enter 1 "+next)-1], "|")
	from := strings.LastIndex(window, "return 1 ")
	tail := window[from:]
	for _, want := range []string{fmt.Sprintf("release %d", tdSize*events+tcV), fmt.Sprintf("release %d", tcStep)} {
		if !strings.Contains(tail, want) {
			t.Fatalf("before %s: %q not released in %s", next, want, tail)
		}
	}
	if strings.Count(tail, fmt.Sprintf("release %d", tcL2)) != 2 {
		t.Fatalf("before %s: L2 allowance not released twice in %s", next, tail)
	}
}

func tcLastCharge(log []string) string {
	for i := len(log) - 1; i >= 0; i-- {
		if strings.HasPrefix(log[i], "charge ") || strings.HasPrefix(log[i], "refuse ") {
			return log[i]
		}
	}
	return ""
}

// A3, M14, M30: zero primitives make no ledger call and keep the legacy pair readback.
func TestTreeComposeZeroPrimitivesV1(t *testing.T) {
	for _, crossed := range []bool{false, true} {
		t.Run(fmt.Sprint(crossed), func(t *testing.T) {
			s := tcNew(t, 0)
			var r tcResult
			if crossed {
				evidence, err := fixtureLargeFault(s.store, 12, 0, tcOut(), func() { r = s.run(nil) })
				if len(s.ledger.log) != 0 {
					t.Errorf("zero primitives touched the ledger: %v", s.ledger.log)
				}
				mustEnvironment(t, err)
				if evidence.commits < 1 {
					t.Errorf("mode 12 did not commit")
				}
				r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
				tcCrossedCause(t, r.err, CommitTruthNew, nil)
				r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
			} else {
				r = s.run(nil)
				if len(s.ledger.log) != 0 {
					t.Errorf("zero primitives touched the ledger: %v", s.ledger.log)
				}
				r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
				r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
				mustEnvironment(t, r.err)
			}
			rows := []ttRow{{ttBlocks, tcB0[:], tcF0}}
			if crossed {
				s.consumed(t, CommitTruthNew, r.err)
			} else {
				rows = append(rows, s.following(t))
			}
			s.reopen(t, rows...)
		})
	}
}

func tcOut() []byte { return []byte{0x09} }

func tcCrossedCause(t *testing.T, err error, truth CommitTruth, readback error) {
	t.Helper()
	var commit *CommitError
	if !errors.As(err, &commit) {
		t.Errorf("commit error %v is not a CommitError", err)
		return
	}
	if commit.Truth != truth {
		t.Errorf("commit error truth %d, want %d", commit.Truth, truth)
	}
	if !sameError(commit.ReadbackCause, readback) {
		t.Errorf("commit error ReadbackCause %v, want %v", commit.ReadbackCause, readback)
	}
	treeNativeError(t, commit.Cause, operationUpdate, EngineCapacity, codeENOSPC, "error 28", nil)
}

// R1, R12, M2, M3, M-BODY-FIRST: the step-1 refusal at LAG1 wins over its absent stored body.
func TestTreeComposeStepRefusalV1(t *testing.T) {
	for _, absent := range []bool{false, true} {
		t.Run(fmt.Sprint(absent), func(t *testing.T) {
			s := tcNew(t, 3)
			if absent {
				mustEnvironment(t, fixtureDeletePrefixRow(s.store, ttBlocks, tcB1[:]))
			}
			s.armRefuseStep("L1")
			r := s.run(nil)
			if s.prims[2].calls[1] != 0 {
				t.Errorf("R1 LAG2 writer count %d, want 0", s.prims[2].calls[1])
			}
			r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
			if !IsOperationReservationCapacity(r.err) {
				t.Errorf("R1/R12 err %v, want errOperationReservationCapacity", r.err)
			}
			if s.prims[1].calls[1] != 0 {
				t.Errorf("R1 LAG1 writer count %d, want 0", s.prims[1].calls[1])
			}
			r.want(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
			s.settled(t)
			s.consumed(t, CommitTruthOld, r.err)
			s.reopen(t, s.oldRows(t)...)
		})
	}
}

// armRefuseStep makes the ledger refuse the first step-1 charge after the named primitive's predecessor returned.
func (s *tcScene) armRefuseStep(name string) {
	prev := map[string]string{"L1": "C", "L2": "L1"}[name]
	l := s.ledger
	for _, p := range s.prims {
		if p.name != prev {
			continue
		}
		act := p.act
		p.act = func(pos treePositionV1, old *Reader, rec *treeRecorderV1) error {
			if pos == treeWriterV1 {
				l.refuseStep = true
			}
			if act != nil {
				return act(pos, old, rec)
			}
			return nil
		}
	}
}

// R7, M17: a drifted Pair target is refused at Prewrite before any Source and any ledger call.
func TestTreeComposePairPreflightV1(t *testing.T) {
	for _, n := range []int{2, 0} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s := tcNew(t, n)
			r := s.run(func() { treeNativeSeed(t, s.store, 4, tcB0[:], []byte{0x7f}) })
			r.check(t, CommitTruthOld, UpdateStagePrewrite, -1)
			for _, p := range s.prims {
				if p.calls[1] != 0 {
					t.Errorf("%s called", p.name)
				}
			}
			if len(s.ledger.log) != 0 {
				t.Errorf("ledger touched: %v", s.ledger.log)
			}
			s.settled(t)
			ttMismatch(t, r.err, "OLD/write snapshot mismatch")
			r.want(t, CommitTruthOld, UpdateStagePrewrite, -1)
			s.consumed(t, CommitTruthOld, r.err)
			s.reopen(t, ttRow{ttBlocks, tcB0[:], []byte{0x7f}}, ttRow{ttUTXO, tdUTXOKey(1, tcT0, 0), nil})
		})
	}
}

// R9, M25: LAG1's absent stored body is an integrity result of index 1 before its Source call.
func TestTreeComposeAbsentBodyV1(t *testing.T) {
	s := tcNew(t, 3)
	mustEnvironment(t, fixtureDeletePrefixRow(s.store, ttBlocks, tcB1[:]))
	r := s.run(nil)
	if s.prims[1].calls[1] != 0 {
		t.Errorf("R9 LAG1 writer count %d, want 0", s.prims[1].calls[1])
	}
	if s.prims[2].calls[1] != 0 {
		t.Errorf("R9 LAG2 writer count %d, want 0", s.prims[2].calls[1])
	}
	r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
	r.want(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
	treeNativeIntegrity(t, r.err, operationUpdate, nil)
	s.settled(t)
	s.consumed(t, CommitTruthOld, r.err)
	s.reopen(t, s.oldRows(t)...)
}

// tcCapacity is the R4 capacity provider: the ledger refuses D_j + V at its beginV1, a following eventV1 returns that
// same recorded singleton (precondition, checked here), and the provider returns it with no Reader failure.
func tcCapacity(t *testing.T, l *tcLedger) func(*Reader, *treeRecorderV1) error {
	return func(old *Reader, rec *treeRecorderV1) error {
		l.refuseNext = true
		begin := rec.beginV1(1, 1, [16]byte{})
		event := rec.eventV1(2, tcTU, 0, 0, 0, 0, uint32(len(tcFU)))
		if begin != errOperationReservationCapacity || event != begin || old.failure != nil {
			t.Errorf("R4 capacity precondition: begin %v event %v reader %v", begin, event, old.failure)
		}
		return begin
	}
}

// R4, M3, M15, M45: E at LAG1's writer after CURRENT emitted; a returned recorded singleton stays the singleton.
func TestTreeComposeProviderErrorV1(t *testing.T) {
	recorded := treeIntegrity(operationGet, nil)
	for _, row := range []struct {
		name string
		act  func(t *testing.T, s *tcScene) func(*Reader, *treeRecorderV1) error
		want error
	}{
		{"sentinel", func(*testing.T, *tcScene) func(*Reader, *treeRecorderV1) error {
			return func(*Reader, *treeRecorderV1) error { return tcSentinel }
		}, tcSentinel},
		{"recorded", func(*testing.T, *tcScene) func(*Reader, *treeRecorderV1) error {
			return func(old *Reader, _ *treeRecorderV1) error { old.failure = recorded; return nil }
		}, recorded},
		{"capacity", func(t *testing.T, s *tcScene) func(*Reader, *treeRecorderV1) error { return tcCapacity(t, s.ledger) }, errOperationReservationCapacity},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := tcNew(t, 3)
			act := row.act(t, s)
			if row.name == "capacity" {
				s.prims[1].custom = act
			} else {
				s.prims[1].act = func(_ treePositionV1, old *Reader, rec *treeRecorderV1) error { return act(old, rec) }
			}
			r := s.run(nil)
			if !sameError(r.err, row.want) {
				t.Errorf("R4 %s err %v, want %v", row.name, r.err, row.want)
			}
			r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
			if row.name == "capacity" && r.err != errOperationReservationCapacity {
				t.Errorf("R4 capacity err %v is not the singleton by identity", r.err)
			}
			if row.name == "capacity" && !IsOperationReservationCapacity(r.err) {
				t.Errorf("R4 capacity IsOperationReservationCapacity(%v) false", r.err)
			}
			if s.prims[2].calls[1] != 0 {
				t.Errorf("R4 LAG2 writer count %d, want 0", s.prims[2].calls[1])
			}
			r.want(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
			s.settled(t)
			s.consumed(t, CommitTruthOld, row.want)
			s.reopen(t, s.oldRows(t)...)
		})
	}
}

// R8, M19: two recorded failures are both in the primary (returned s or nil); one recorded F returned is F itself.
func TestTreeComposePrimaryCompositionV1(t *testing.T) {
	f := treeIntegrity(operationGet, nil)
	for _, variant := range []string{"returned", "nil", "single"} {
		t.Run(variant, func(t *testing.T) {
			s := tcNew(t, 3)
			var sink error
			s.prims[1].custom = func(old *Reader, rec *treeRecorderV1) error {
				old.failure = f
				switch variant {
				case "single":
					return f
				case "returned":
					sink = rec.beginV1(0, 0, [16]byte{})
					return sink
				}
				sink = rec.beginV1(0, 0, [16]byte{})
				return nil
			}
			r := s.run(nil)
			r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
			if s.prims[2].calls[treeWriterV1] != 0 {
				t.Errorf("R8 LAG2 writer count %d, want 0", s.prims[2].calls[treeWriterV1])
			}
			if variant == "single" {
				if r.err != f {
					t.Errorf("R8 single primary %v, want F by identity", r.err)
				}
			} else {
				if sink == nil {
					t.Errorf("R8 rec.beginV1(0) recorded no s")
				}
				if !errors.Is(r.err, f) {
					t.Errorf("primary %v lacks F", r.err)
				}
				if !errors.Is(r.err, sink) {
					t.Errorf("primary %v lacks s", r.err)
				}
			}
			r.want(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
			s.settled(t)
			s.consumed(t, CommitTruthOld, r.err)
			s.reopen(t, s.oldRows(t)...)
		})
	}
}

// tcFail makes a provider's failure before its unwind: "recorded" records F on its Reader, "sink" calls
// rec.beginV1(0, 0) (L1 records s, the D12-G2 BEGIN refusal, with no charge) and returns s; "clean" does nothing.
func tcFail(t *testing.T, variant string, f error, old *Reader, rec *treeRecorderV1) error {
	switch variant {
	case "recorded":
		old.failure = f
		return f
	case "sink":
		sink := rec.beginV1(0, 0, [16]byte{})
		if sink == nil || rec.failureV1() != sink || old.failure != nil {
			t.Errorf("sink-only precondition: s %v recorded %v reader %v", sink, rec.failureV1(), old.failure)
		}
		return sink
	}
	return nil
}

// H1, M11, M12, M39: a clean writer panic leaves the Store OPEN; a recorded F or sink-only s consumes it.
func TestTreeComposeWriterPanicV1(t *testing.T) {
	f := treeIntegrity(operationGet, nil)
	for _, variant := range []string{"clean", "recorded", "sink"} {
		t.Run(variant, func(t *testing.T) {
			s := tcNew(t, 3)
			v := new(int)
			var escaped *Reader
			var want error
			s.prims[1].custom = func(old *Reader, rec *treeRecorderV1) error {
				escaped = old
				if variant != "sink" {
					mustEnvironment(t, s.prims[1].stream(rec))
				}
				want = tcFail(t, variant, f, old, rec)
				panic(v)
			}
			var r tcResult
			early := func() (p any) { defer func() { p = recover() }(); r = s.run(nil); return nil }()
			if early != nil {
				t.Errorf("%s: resumed inside the composer %v", variant, early)
			}
			if variant != "clean" && s.store.state != storeCLOSED {
				t.Errorf("%s: state %v before resume", variant, s.store.state)
			}
			if variant == "clean" && s.store.state != storeOPEN {
				t.Errorf("H1 clean state %v before resume, want OPEN", s.store.state)
			}
			if variant == "clean" && s.store.terminal != nil {
				t.Errorf("H1 clean terminal %v before resume, want nil", s.store.terminal)
			}
			if early != nil {
				t.FailNow()
			}
			r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
			if r.unwind.kind != 1 {
				t.Errorf("unwind kind %d, want 1", r.unwind.kind)
			}
			if escaped.usable() {
				t.Errorf("escaped provider Reader still usable")
			}
			recorded := variant != "clean"
			if recorded && !sameError(r.err, want) {
				t.Errorf("%s panic err %v, want %v", variant, r.err, want)
			}
			if recorded && s.store.terminal != want {
				t.Errorf("%s panic terminal %v, want %v", variant, s.store.terminal, want)
			}
			if !recorded && r.err != nil {
				t.Errorf("clean panic err %v, want nil", r.err)
			}
			if !recorded && s.store.state != storeOPEN {
				t.Errorf("clean panic state %v, want OPEN", s.store.state)
			}
			if !recorded && s.store.terminal != nil {
				t.Errorf("clean panic terminal %v, want nil", s.store.terminal)
			}
			r.want(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
			s.settled(t)
			if recorded {
				s.consumed(t, CommitTruthOld, want)
			}
			func() {
				defer func() {
					if got := recover(); got != v {
						t.Fatalf("resumed %v", got)
					}
				}()
				r.unwind.resumeV1()
			}()
			if !recorded {
				s.prims[1].custom = nil
				s.reopenOpen(t, s.oldRows(t)...)
				next := s.run(nil)
				next.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
				return
			}
			s.reopen(t, s.oldRows(t)...)
		})
	}
}

// H2, H5, M18b, M22b, M26, M40, M41: a writer Goexit after a valid BEGIN releases D_j + V once and projects from
// the capture; a recorded F or sink-only s consumes the Store; mode 9 (nil primary, OLD cleanup EIO) consumes it with E.
func TestTreeComposeWriterGoexitV1(t *testing.T) {
	f := treeIntegrity(operationGet, nil)
	for _, variant := range []string{"clean", "recorded", "sink", "mode9"} {
		t.Run(variant, func(t *testing.T) {
			s := tcNew(t, 3)
			var kept *treeRecorderV1
			var want error
			s.prims[1].custom = func(old *Reader, rec *treeRecorderV1) error {
				kept = rec
				if variant != "sink" {
					if err := s.prims[1].stream(rec); err != nil {
						t.Errorf("stream: %v", err)
					}
				}
				want = tcFail(t, variant, f, old, rec)
				runtime.Goexit()
				return nil
			}
			inspect := func(r tcResult) {
				if r.unwind.kind != 2 {
					t.Errorf("goexit unwind kind %d, want 2", r.unwind.kind)
				}
				r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
				tcExpired(t, kept, want, variant == "sink")
				s.settledNow(t)
				if variant == "mode9" && (r.err == nil || r.err != s.store.terminal) {
					t.Errorf("goexit mode 9 err %v, want the terminal %v", r.err, s.store.terminal)
				}
				if variant != "mode9" && !sameError(r.err, want) {
					t.Errorf("goexit err %v, want %v", r.err, want)
				}
				if variant == "recorded" || variant == "sink" {
					if s.store.state != storeCLOSED {
						t.Errorf("goexit %s state %v before resume, want CLOSED", variant, s.store.state)
					}
				}
			}
			if variant != "mode9" {
				s.goexitRun(t, inspect)
			} else {
				evidence, err := fixtureLargeFault(s.store, 9, 0, []byte{0}, func() { s.goexitRun(t, inspect) })
				mustEnvironment(t, err)
				if evidence.aborts != 1 {
					t.Errorf("mode 9 aborts %d, want 1", evidence.aborts)
				}
				if evidence.commits != 0 {
					t.Errorf("mode 9 commits %d, want 0", evidence.commits)
				}
			}
			s.settled(t)
			switch variant {
			case "clean":
				if s.store.state != storeOPEN {
					t.Fatalf("clean goexit state %v", s.store.state)
				}
				s.prims[1].custom = nil
				s.run(nil).want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
				s.reopen(t, s.newRows(t)...)
				return
			case "mode9":
				tcMode9(t, s)
			default:
				if s.store.terminal != want {
					t.Errorf("terminal %v, want %v", s.store.terminal, want)
				}
				s.consumed(t, CommitTruthOld, want)
			}
			s.reopen(t, s.oldRows(t)...)
		})
	}
}

// tcExpired is the H5 observation on a retained recorder: eventV1 is the D6-3 expired-sink refusal, windowV1 is nil
// and failureV1 is unchanged (s for a sink-only provider, else nil). It never calls t.Fatal (worker-safe).
func tcExpired(t *testing.T, rec *treeRecorderV1, sink error, sinkOnly bool) {
	var engine *EngineError
	err := rec.eventV1(2, tcTC, 0, 0, 0, 0, 20)
	if !errors.As(err, &engine) || engine.Class != EngineInvalidInput || engine.Code != codeEINVAL || engine.Diagnostic != "tree delta sink is not active" || engine.Cause != nil {
		t.Errorf("retained recorder event %v", err)
	}
	want := error(nil)
	if sinkOnly {
		want = sink
	}
	if rec.windowV1() != nil {
		t.Errorf("retained recorder window not nil")
	}
	if rec.failureV1() != want {
		t.Errorf("retained recorder failure %v, want %v", rec.failureV1(), want)
	}
}

// tcMode9 checks the H2 nil-primary cleanup-failure outcome: CLOSED with the OLD-abort EIO and the next legacy Update.
func tcMode9(t *testing.T, s *tcScene) {
	t.Helper()
	engine := requireEnvironmentError(t, s.store.terminal, EngineIO, operationAbort, 5, "error 5")
	if engine.Cause != nil {
		t.Errorf("mode 9 terminal cause %v, want nil", engine.Cause)
	}
	if engine.ReopenRequired {
		t.Errorf("mode 9 terminal ReopenRequired true")
	}
	if s.store.state != storeCLOSED {
		t.Errorf("mode 9 state %v, want CLOSED", s.store.state)
	}
	calls := 0
	truth, stage, next := s.store.Update(func(*Reader) (Batch, error) { calls++; return Batch{}, nil })
	if truth != CommitTruthOld {
		t.Errorf("next Update truth %d, want OLD", truth)
	}
	if stage != UpdateStagePrewrite {
		t.Errorf("next Update stage %d, want Prewrite", stage)
	}
	if next != s.store.terminal {
		t.Errorf("next Update err %v, want the terminal", next)
	}
	if calls != 0 {
		t.Errorf("next Update callback count %d, want 0", calls)
	}
}

// A2, R5, M6, M7, M16, M21, M28: exact H_r on the P + H_r ledger, crossed run ending NEW; refusal at P + H_r - 1.
func TestTreeComposeHoldV1(t *testing.T) {
	p := tcPBudgets(t)[2]
	for _, row := range []struct {
		name    string
		limit   uint64
		crossed bool
	}{{"exact", p + tcHr(2), false}, {"crossed", p + tcHr(2), true}, {"short", p + tcHr(2) - 1, false}} {
		t.Run(row.name, func(t *testing.T) {
			s := tcNew(t, 3)
			s.ledger.limit = row.limit
			var r tcResult
			if row.crossed {
				evidence, err := fixtureLargeFault(s.store, 12, 0, tcOut(), func() { r = s.run(nil) })
				mustEnvironment(t, err)
				if evidence.commits < 1 {
					t.Errorf("mode 12 did not commit")
				}
				for _, e := range s.ledger.log[tcIndex(t, s.ledger.log, "enter 2 C"):] {
					if strings.HasPrefix(e, "charge ") {
						t.Errorf("A2 %s after the commit (after the first readback entry)", e)
					}
				}
				tcCrossedCause(t, r.err, CommitTruthNew, nil)
			}
			if !row.crossed {
				r = s.run(nil)
			}
			last := tcLastCharge(s.ledger.log)
			if row.name == "short" {
				s.reopenNow(t, s.oldRows(t)...)
				r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, -1)
				if !IsOperationReservationCapacity(r.err) {
					t.Errorf("R5 err %v, want errOperationReservationCapacity", r.err)
				}
				if last != fmt.Sprintf("refuse %d", tcHr(2)) {
					t.Errorf("R5 last %q, want refuse H_r", last)
				}
				r.want(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, -1)
				s.settled(t)
				s.consumed(t, CommitTruthOld, r.err)
				return
			}
			r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
			if last != fmt.Sprintf("charge %d", tcHr(2)) {
				t.Errorf("last charge %q", last)
			}
			if row.crossed && s.prims[0].calls[treeReadbackV1] != 1 {
				t.Errorf("readback did not run")
			}
			r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
			tcNoChargeAfterHr(t, s.ledger.log)
			s.settled(t)
			rows := s.newRows(t)
			if row.crossed {
				s.consumed(t, CommitTruthNew, r.err)
			} else {
				rows = append(rows, s.following(t))
			}
			s.reopen(t, rows...)
		})
	}
}

// tcCrossed runs the A1 plan under the mode-12 clean crossing.
func (s *tcScene) crossed(t *testing.T) tcResult {
	t.Helper()
	var r tcResult
	evidence, err := fixtureLargeFault(s.store, 12, 0, tcOut(), func() { r = s.run(nil) })
	mustEnvironment(t, err)
	if evidence.commits < 1 {
		t.Errorf("mode 12 did not commit")
	}
	return r
}

// R6, M8, M9, M10: a readback provider error is the ReadbackCause; LAG2's readback is unreached. Subcase recorded:
// LAG1's readback provider records F on its Reader and returns nil, so ReadbackCause == F.
func TestTreeComposeReadbackErrorV1(t *testing.T) {
	f := treeIntegrity(operationGet, nil)
	for _, variant := range []string{"sentinel", "recorded"} {
		t.Run(variant, func(t *testing.T) {
			s := tcNew(t, 3)
			want := error(tcSentinel)
			s.prims[1].act = func(pos treePositionV1, old *Reader, _ *treeRecorderV1) error {
				if pos != treeReadbackV1 {
					return nil
				}
				if variant == "recorded" {
					old.failure = f
					return nil
				}
				return tcSentinel
			}
			if variant == "recorded" {
				want = f
			}
			r := s.crossed(t)
			var commit *CommitError
			if !errors.As(r.err, &commit) || commit.ReadbackCause != want {
				t.Errorf("R6 err %v, want a CommitError whose ReadbackCause is %v by identity", r.err, want)
			}
			if s.prims[2].calls[treeReadbackV1] != 0 {
				t.Errorf("R6 LAG2 readback count %d, want 0", s.prims[2].calls[treeReadbackV1])
			}
			r.check(t, CommitTruthUnknown, UpdateStageCommitMayHaveCrossed, -1)
			tcCrossedCause(t, r.err, CommitTruthUnknown, want)
			r.want(t, CommitTruthUnknown, UpdateStageCommitMayHaveCrossed, -1)
			if s.store.state != storeCLOSED {
				t.Errorf("R6 state %v, want CLOSED", s.store.state)
			}
			if s.store.terminalTruth != CommitTruthUnknown {
				t.Errorf("R6 terminal truth %d, want UNKNOWN", s.store.terminalTruth)
			}
			tcNoChargeAfterHr(t, s.ledger.log)
			s.settled(t)
			s.consumed(t, CommitTruthUnknown, r.err)
			s.reopen(t, s.newRows(t)...)
		})
	}
}

// tcNoChargeAfterHr is the "no chargeV1 after the commit" observation: the composer goes from the H_r charge straight
// into commitV1, so no "charge " entry follows the H_r charge in the ledger log.
func tcNoChargeAfterHr(t *testing.T, log []string) {
	t.Helper()
	at := tcIndex(t, log, fmt.Sprintf("charge %d", tcHr(2)))
	for _, e := range log[at+1:] {
		if strings.HasPrefix(e, "charge ") {
			t.Errorf("%s after the H_r charge (after the commit)", e)
		}
	}
}

// H3 (clean, recorded and sink-only RP and RG), M13, M18b, M34, M35, M42: readback unwinds consume the Store with
// UNKNOWN from the capture and ReadbackCause nil, F or s.
func TestTreeComposeReadbackUnwindV1(t *testing.T) {
	f := treeIntegrity(operationGet, nil)
	for _, goexit := range []bool{false, true} {
		for _, variant := range []string{"clean", "recorded", "sink"} {
			t.Run(fmt.Sprint(goexit, variant), func(t *testing.T) {
				tcReadbackUnwind(t, goexit, variant, f)
			})
		}
	}
}

func tcReadbackUnwind(t *testing.T, goexit bool, variant string, f error) {
	s := tcNew(t, 3)
	v := new(int)
	var want error
	lag1 := s.prims[1]
	lag1.custom = func(old *Reader, rec *treeRecorderV1) error {
		if lag1.calls[treeReadbackV1] == 0 {
			return lag1.stream(rec)
		}
		if variant != "sink" {
			if err := lag1.stream(rec); err != nil {
				t.Errorf("readback stream: %v", err)
			}
		}
		want = tcFail(t, variant, f, old, rec)
		if goexit {
			runtime.Goexit()
		}
		panic(v)
	}
	check := func(r tcResult) {
		if s.store.state != storeCLOSED {
			t.Errorf("H3 state %v, want CLOSED", s.store.state)
		}
		r.check(t, CommitTruthUnknown, UpdateStageCommitMayHaveCrossed, -1)
		if r.unwind.kind != map[bool]uint8{false: 1, true: 2}[goexit] {
			t.Errorf("readback unwind kind %d", r.unwind.kind)
		}
		tcUnwindCause(t, r.err, want)
		if s.store.terminalTruth != CommitTruthUnknown {
			t.Errorf("terminal truth %d, want UNKNOWN", s.store.terminalTruth)
		}
		if s.prims[2].calls[treeReadbackV1] != 0 {
			t.Errorf("LAG2 readback count %d, want 0", s.prims[2].calls[treeReadbackV1])
		}
		s.settledNow(t)
	}
	done, resumed := make(chan struct{}), false
	var got tcResult
	go func() {
		defer close(done)
		var r tcResult
		defer func() { got = r }()
		evidence, err := fixtureLargeFault(s.store, 12, 0, tcOut(), func() { r = s.run(nil) })
		if err != nil || evidence.commits < 1 {
			t.Errorf("mode 12: %v %d", err, evidence.commits)
		}
		check(r)
		defer func() {
			if got := recover(); !goexit && got != v {
				t.Errorf("resumed %v", got)
			}
		}()
		r.unwind.resumeV1()
		resumed = true
	}()
	<-done
	if resumed {
		t.Fatal("statement after resumeV1 ran")
	}
	s.settled(t)
	s.consumed(t, CommitTruthUnknown, got.err)
	s.reopen(t, s.newRows(t)...)
}

// A4, M29: the readback returns W + F_fixed + C + R and D_j + V of CURRENT before LAG1's draw, so it completes
// inside P + S_r + B_r; EventCount 1 for CURRENT and 2 for LAG1 (two coinbase outputs over a two-frame body).
// tcUnwindCause checks the H3 CommitError field by field; it never calls t.Fatal (worker goroutine).
func tcUnwindCause(t *testing.T, err error, want error) {
	var commit *CommitError
	if !errors.As(err, &commit) {
		t.Errorf("readback unwind err %v is not a CommitError", err)
		return
	}
	if !sameError(commit.ReadbackCause, want) {
		t.Errorf("readback unwind ReadbackCause %v, want %v", commit.ReadbackCause, want)
	}
	if commit.Truth != CommitTruthUnknown {
		t.Errorf("readback unwind CommitError truth %d, want UNKNOWN", commit.Truth)
	}
	var cause *EngineError
	if !errors.As(commit.Cause, &cause) {
		t.Errorf("readback unwind Cause %v is not an EngineError", commit.Cause)
		return
	}
	if cause.Class != EngineCapacity {
		t.Errorf("readback unwind Cause class %v, want Capacity", cause.Class)
	}
	if cause.Code != codeENOSPC {
		t.Errorf("readback unwind Cause code %d, want ENOSPC", cause.Code)
	}
	if cause.Diagnostic != "error 28" {
		t.Errorf("readback unwind Cause diagnostic %q", cause.Diagnostic)
	}
	if cause.Cause != nil {
		t.Errorf("readback unwind Cause cause %v, want nil", cause.Cause)
	}
}

func TestTreeComposeReadbackReturnV1(t *testing.T) {
	s := tcNew(t, 2)
	body := append(append([]byte(nil), tcFU...), tcFC...)
	treeNativeSeed(t, s.store, 4, tcB1[:], body)
	s.prims[1].events = []tdEv{tdCreate(tcTU, 0, 0, 0, uint32(len(tcFU))), tdCreate(tcTU, 1, 0, uint64(len(tcFU)), uint32(len(tcFC)))}
	r := s.crossed(t)
	r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	tcCrossedCause(t, r.err, CommitTruthNew, nil)
	log := s.ledger.log
	if s.prims[0].calls[treeReadbackV1] != 1 {
		t.Errorf("CURRENT readback calls %d, want 1", s.prims[0].calls[treeReadbackV1])
	}
	if s.prims[1].calls[treeReadbackV1] != 1 {
		t.Errorf("LAG1 readback calls %d, want 1", s.prims[1].calls[treeReadbackV1])
	}
	if tcIndex(t, log, "enter 2 C") > tcIndex(t, log, "enter 2 L1") {
		t.Errorf("readback order %v", log)
	}
	if last := tcLastCharge(log); last != fmt.Sprintf("charge %d", tcHr(2)) {
		t.Errorf("last charge %q, want H_r %d", last, tcHr(2))
	}
	s.settled(t)
	s.consumed(t, CommitTruthNew, r.err)
	s.reopen(t, tcA4Rows(t, s)...)
}

// tcA4Rows are NEW bytes of A4's plan: CURRENT's A1 targets and LAG1's first coinbase output (not spent here).
func tcA4Rows(t *testing.T, s *tcScene) []ttRow {
	return append(s.newRows(t)[:4], ttRow{ttUTXO, tdUTXOKey(2, tcTU, 0), tcValue(tcFU, 5)})
}

// A5, M24: a Pair put of CURRENT's absent blocks-v1 row is its body.
func TestTreeComposePairBodyV1(t *testing.T) {
	s := tcNew(t, 1)
	r := s.run(nil)
	r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	if r.err != nil {
		t.Errorf("A5 err %v, want nil", r.err)
	}
	if r.unwind.kind != 0 {
		t.Errorf("A5 unwind %+v, want none", r.unwind)
	}
	if s.prims[0].calls[treeWriterV1] != 1 {
		t.Errorf("A5 writer calls %d, want 1", s.prims[0].calls[treeWriterV1])
	}
	s.settled(t)
	r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	s.reopen(t, append(s.newRows(t)[:4], s.following(t))...)
}

// tcRollback is the A6 plan: ROLLBACK_NEW (SourceDelete) of block BR at generation 3, height 8, whose coinbase
// created kR; the Pair deletes blocks-v1[BR]. seeded false leaves blocks-v1[BR] absent (R10).
func tcRollback(t *testing.T, seeded bool) (*tcScene, []ttRow) {
	t.Helper()
	store, path := ttStore(t)
	block, txid, frame := tdTxid(0xc0), tdTxid(0x40), tdFrame(400, 0, nil)
	key, value := tdUTXOKey(3, txid, 0), tdFormed(frame, 8, 1)
	parent := tcEndpoint(7, tdTxid(0xbf))
	if seeded {
		treeNativeSeed(t, store, 4, block[:], frame)
	}
	leaf, digest := testTreeNodeKey(3, 288, [36]byte(key[8:])), testTreeLeafPreimage([36]byte(key[8:]), value)
	for _, row := range []ttRow{
		{ttUTXO, key, value},
		{schemaDBIs[5], tdManifestKey(block), tdManifest(8, [16]byte{}, 1, 0)},
		{TreeSchemaV1DBIs()[8], leaf, digest[:]},
		{TreeSchemaV1DBIs()[0], tcBindingKey(3), tcBinding(t, 3, tcEndpoint(8, block), tcEntry(key, value))},
	} {
		treeNativeSeed(t, store, row.dbi.Rank, row.key, row.want)
	}
	s := &tcScene{store: store, path: path, ledger: &tcLedger{}}
	s.pair = []ownedMutation{{dbi: ttBlocks, key: block[:], beforePresent: true, after: AfterAbsent}}
	prim := treePrimitiveV1{direction: treeInverseV1, kind: treeKindRollbackNewV1, undo: treeUndoSourceDeleteV1, generation: 3, height: 8, block: block, endpoint: parent}
	s.prims = []*tcPrim{{name: "R", prim: prim, txCount: 1, events: []tdEv{tdCreate(txid, 0, 0, 0, uint32(len(frame)))}, ledger: s.ledger}}
	after := []ttRow{
		{ttBlocks, block[:], nil},
		{ttUTXO, key, nil},
		{schemaDBIs[5], tdManifestKey(block), nil},
		{TreeSchemaV1DBIs()[8], leaf, nil},
		{TreeSchemaV1DBIs()[0], tcBindingKey(3), tcBinding(t, 3, parent)},
	}
	return s, after
}

// A6, M-REF-DEL: a Pair-deleted body is the ORIGINAL OLD row bound with pair = true; the rollback commits NEW.
func TestTreeComposePairDeleteV1(t *testing.T) {
	s, after := tcRollback(t, true)
	r := s.run(nil)
	r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	if r.err != nil {
		t.Errorf("A6 err %v, want nil", r.err)
	}
	if s.prims[0].calls[treeWriterV1] != 1 {
		t.Errorf("A6 writer calls %d, want 1", s.prims[0].calls[treeWriterV1])
	}
	s.settled(t)
	r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	s.reopen(t, append(after, s.following(t))...)
}

// R10, M-DEL-ABS: a Pair delete of an absent ORIGINAL OLD body is the stored-body integrity result at index 0.
func TestTreeComposePairDeleteAbsentV1(t *testing.T) {
	s, _ := tcRollback(t, false)
	r := s.run(nil)
	r.check(t, CommitTruthOld, UpdateStagePrewrite, 0)
	if engine, ok := directTestEngineError(r.err); !ok || engine.Class != EngineClass("Integrity") {
		t.Errorf("R10 err %v, want the Integrity class", r.err)
	}
	if s.prims[0].calls[treeWriterV1] != 0 {
		t.Errorf("R10 CURRENT writer calls %d, want 0", s.prims[0].calls[treeWriterV1])
	}
	r.want(t, CommitTruthOld, UpdateStagePrewrite, 0)
	treeNativeIntegrity(t, r.err, operationUpdate, nil)
	if fmt.Sprint(s.ledger.log) != fmt.Sprintf("[charge %d release %d]", tcStep, tcStep) {
		t.Errorf("R10 log %v", s.ledger.log)
	}
	s.settled(t)
	s.consumed(t, CommitTruthOld, r.err)
	block := tdTxid(0xc0)
	key, value := tdUTXOKey(3, tdTxid(0x40), 0), tdFormed(tdFrame(400, 0, nil), 8, 1)
	s.reopen(t, ttRow{ttBlocks, block[:], nil}, ttRow{ttUTXO, key, value}, ttRow{TreeSchemaV1DBIs()[0], tcBindingKey(3), tcBinding(t, 3, tcEndpoint(8, block), tcEntry(key, value))})
}

// R2, M2, M3 (D40): the first charge after LAG1's writer provider returned whose amount is not 147,968 is refused:
// LAG1's step-6 reference of its 32-byte stored-body key, after exactly its step-5 fold charge and release.
func TestTreeComposeGrowthRefusalV1(t *testing.T) {
	s := tcNew(t, 3)
	s.prims[1].act = func(pos treePositionV1, _ *Reader, _ *treeRecorderV1) error {
		s.ledger.refuseOther = pos == treeWriterV1
		return nil
	}
	r := s.run(nil)
	r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
	if r.err != errOperationReservationCapacity {
		t.Errorf("R2 err %v, want errOperationReservationCapacity", r.err)
	}
	if s.prims[2].calls[treeWriterV1] != 0 {
		t.Errorf("R2 LAG2 writer calls %d, want 0", s.prims[2].calls[treeWriterV1])
	}
	r.want(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
	from := tcIndex(t, s.ledger.log, "return 1 L1") + 1
	to := tcIndex(t, s.ledger.log, "refuse 32")
	if got := strings.Join(s.ledger.log[from:to+1], ","); got != "charge 147968,release 147968,refuse 32" {
		t.Fatalf("R2 ledger after LAG1 return %q", got)
	}
	s.settled(t)
	s.consumed(t, CommitTruthOld, r.err)
	s.reopen(t, s.oldRows(t)...)
}

// R13, M46, M47 (D40): (a) the first charge of any amount after CURRENT's writer provider returned is refused, which
// is CURRENT's step-5 fold charge; (b) the second 147,968 charge after LAG1's writer provider returned, its step-7
// emission charge, is refused.
func TestTreeComposeWorkRefusalV1(t *testing.T) {
	t.Run("fold", func(t *testing.T) {
		s := tcNew(t, 3)
		s.prims[0].act = func(pos treePositionV1, _ *Reader, _ *treeRecorderV1) error {
			s.ledger.refuseNext = pos == treeWriterV1
			return nil
		}
		r := s.run(nil)
		r.check(t, CommitTruthOld, UpdateStagePrewrite, 0)
		if got := tcFirstRefusal(s.ledger.log); got != "refuse 147968" {
			t.Errorf("R13a first refusal %q, want refuse 147968", got)
		}
		if r.err != errOperationReservationCapacity {
			t.Errorf("R13a err %v, want errOperationReservationCapacity", r.err)
		}
		if s.prims[0].calls[treeWriterV1] != 1 {
			t.Errorf("R13a CURRENT writer calls %d, want 1", s.prims[0].calls[treeWriterV1])
		}
		if s.prims[1].calls[treeWriterV1] != 0 {
			t.Errorf("R13a LAG1 writer calls %d, want 0", s.prims[1].calls[treeWriterV1])
		}
		if s.prims[2].calls[treeWriterV1] != 0 {
			t.Errorf("R13a LAG2 writer calls %d, want 0", s.prims[2].calls[treeWriterV1])
		}
		r.want(t, CommitTruthOld, UpdateStagePrewrite, 0)
		at := tcIndex(t, s.ledger.log, "refuse 147968")
		if tcIndex(t, s.ledger.log, "return 1 C")+1 != at {
			t.Errorf("R13a refusal is not the first charge after CURRENT returned: %v", s.ledger.log)
		}
		if slices.Contains(s.ledger.log[at:], "release 147968") {
			t.Errorf("R13a release of 147968 after the refusal: %v", s.ledger.log)
		}
		s.settled(t)
		s.consumed(t, CommitTruthOld, r.err)
		s.reopen(t, s.oldRows(t)...)
	})
	t.Run("emit", func(t *testing.T) {
		s := tcRefuseL2(t)
		r := s.run(nil)
		r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
		if s.prims[2].calls[treeWriterV1] != 0 {
			t.Errorf("R13b LAG2 writer calls %d, want 0", s.prims[2].calls[treeWriterV1])
		}
		if r.err != errOperationReservationCapacity {
			t.Errorf("R13b err %v, want errOperationReservationCapacity", r.err)
		}
		r.want(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
		from := tcIndex(t, s.ledger.log, "return 1 L1") + 1
		to := tcIndex(t, s.ledger.log, "refuse 147968")
		seg := s.ledger.log[from:to]
		if len(seg) < 2 || seg[0] != "charge 147968" {
			t.Errorf("R13b fold charge is not the first charge after LAG1 returned: %v", seg)
		}
		if len(seg) < 2 || seg[1] != "release 147968" {
			t.Errorf("R13b fold charge not released before the refusal: %v", seg)
		}
		if len(seg) >= 2 && slices.Contains(seg[2:], "charge 147968") {
			t.Errorf("R13b another admitted 147968 charge before the refusal: %v", seg)
		}
		s.settled(t)
		s.consumed(t, CommitTruthOld, r.err)
		s.reopen(t, s.oldRows(t)...)
	})
}

// tcRefuseL2 arms, after LAG1's writer stream (its beginV1 charge included), refusal of the second following charge
// of amount 147,968.
func tcRefuseL2(t *testing.T) *tcScene {
	t.Helper()
	s := tcNew(t, 3)
	s.prims[1].act = func(pos treePositionV1, _ *Reader, _ *treeRecorderV1) error {
		if pos == treeWriterV1 {
			s.ledger.refuseL2 = 2
		}
		return nil
	}
	return s
}

// R3, M4: a checked-read drift at CURRENT is STALE before any put (stage 1, index 0); a drift only LAG2 reads is
// STALE at index 2 after the earlier puts (stage 2), before LAG2's fold charge.
func TestTreeComposeCheckedDriftV1(t *testing.T) {
	for _, row := range []struct {
		name  string
		key   []byte
		stage UpdateStage
		index int
	}{
		{"current", tdUTXOKey(1, tcT0, 0), UpdateStagePrewrite, 0},
		{"lag2", tdUTXOKey(2, tcTC, 0), UpdateStageWriteStartedDefinitelyPrecommit, 2},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := tcNew(t, 3)
			r := s.run(func() { treeNativeSeed(t, s.store, 1, row.key, []byte{0x7f}) })
			r.check(t, CommitTruthOld, row.stage, row.index)
			if row.index == 0 && s.prims[1].calls[treeWriterV1] != 0 {
				t.Errorf("LAG1 called after CURRENT's STALE")
			}
			r.want(t, CommitTruthOld, row.stage, row.index)
			ttMismatch(t, r.err, "OLD/write snapshot mismatch")
			log := s.ledger.log
			if row.index == 2 && strings.Contains(strings.Join(log[tcIndex(t, log, "return 1 L2"):], "|"), fmt.Sprintf("charge %d", tcL2)) {
				t.Fatalf("LAG2 fold reached after its STALE: %v", log)
			}
			s.settled(t)
			s.consumed(t, CommitTruthOld, r.err)
			rows := append(s.oldRows(t)[1:], ttRow{ttUTXO, row.key, []byte{0x7f}})
			if row.index == 2 {
				rows = append(s.oldRows(t), ttRow{ttUTXO, row.key, []byte{0x7f}})
			}
			s.reopen(t, rows...)
		})
	}
}

// H5, M18: a recorder LAG1's writer provider retains is expired after the seam returns (sentinel) and before the
// panic marker is resumed: eventV1 is the expired-sink refusal, windowV1 nil, failureV1 still nil.
func TestTreeComposeRetainedRecorderV1(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(fmt.Sprint(panics), func(t *testing.T) {
			s := tcNew(t, 3)
			v := new(int)
			var kept *treeRecorderV1
			s.prims[1].act = func(_ treePositionV1, _ *Reader, rec *treeRecorderV1) error {
				kept = rec
				if panics {
					panic(v)
				}
				return tcSentinel
			}
			r := s.run(nil)
			r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
			tcExpired(t, kept, nil, false)
			r.want(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, 1)
			if t.Failed() {
				t.FailNow()
			}
			s.settled(t)
			if !panics {
				if r.err != tcSentinel {
					t.Fatalf("H5 err %v", r.err)
				}
				s.consumed(t, CommitTruthOld, tcSentinel)
				s.reopen(t, s.oldRows(t)...)
				return
			}
			func() {
				defer func() {
					if got := recover(); got != v {
						t.Fatalf("resumed %v", got)
					}
				}()
				r.unwind.resumeV1()
			}()
			s.prims[1].act = nil
			s.reopenOpen(t, s.oldRows(t)...)
			s.run(nil).want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
		})
	}
}

// tcWeak is one primitive's weak pointers to its recorder, window and provider Reader (H6).
type tcWeak struct {
	rec    weak.Pointer[treeRecorderV1]
	window weak.Pointer[byte]
	reader weak.Pointer[Reader]
}

func (w *tcWeak) take(old *Reader, rec *treeRecorderV1) {
	w.rec, w.window, w.reader = weak.Make(rec), weak.Make(&rec.windowV1()[0]), weak.Make(old)
}

func (w *tcWeak) live() int {
	n := 0
	for _, alive := range []bool{w.rec.Value() != nil, w.window.Value() != nil, w.reader.Value() != nil} {
		if alive {
			n++
		}
	}
	return n
}

func tcGC() {
	runtime.GC()
	runtime.GC()
}

// tcTakeWeak makes p's writer provider take its weak pointers while its sink is active, after its stream.
func tcTakeWeak(p *tcPrim, w *tcWeak) {
	p.custom = func(old *Reader, rec *treeRecorderV1) error {
		err := p.stream(rec)
		w.take(old, rec)
		return err
	}
}

// H6, M31, M36: no recorder, window or provider Reader of an earlier writer primitive survives its step 8 at LAG1's
// and LAG2's step-1 charge and at the H_r charge; at the readback, CURRENT's three are gone at LAG1's entry.
func TestTreeComposeNoSurvivorV1(t *testing.T) {
	s := tcNew(t, 3)
	var weaks [3]tcWeak
	for j, p := range s.prims {
		tcTakeWeak(p, &weaks[j])
	}
	steps := 0
	var seen []int
	s.ledger.before = func(n uint64) {
		if n != tcStep && n != tcHr(2) {
			return
		}
		if n == tcStep {
			steps++
		}
		earlier := steps - 1
		if n == tcHr(2) {
			earlier = 3
		}
		if earlier < 1 {
			return
		}
		tcGC()
		live := 0
		for j := range earlier {
			live += weaks[j].live()
		}
		seen = append(seen, live)
	}
	r := s.run(nil)
	r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	if fmt.Sprint(seen) != "[0 0 0]" {
		t.Errorf("live weak pointers at LAG1 step, LAG2 step, H_r: %v", seen)
	}
	r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	s.settled(t)
	s.ledger.before = nil
	s.reopen(t, append(s.newRows(t), s.following(t))...)
}

// H6 readback subcase on A4's plan: LAG1's readback provider, first, collects and finds CURRENT's readback objects gone.
func TestTreeComposeNoSurvivorReadbackV1(t *testing.T) {
	s := tcNew(t, 2)
	body := append(append([]byte(nil), tcFU...), tcFC...)
	treeNativeSeed(t, s.store, 4, tcB1[:], body)
	s.prims[1].events = []tdEv{tdCreate(tcTU, 0, 0, 0, uint32(len(tcFU))), tdCreate(tcTU, 1, 0, uint64(len(tcFU)), uint32(len(tcFC)))}
	var current tcWeak
	cur, lag1 := s.prims[0], s.prims[1]
	cur.custom = func(old *Reader, rec *treeRecorderV1) error {
		err := cur.stream(rec)
		if cur.calls[treeReadbackV1] == 1 {
			current.take(old, rec)
		}
		return err
	}
	live := -1
	lag1.custom = func(old *Reader, rec *treeRecorderV1) error {
		if lag1.calls[treeReadbackV1] == 1 {
			tcGC()
			live = current.live()
		}
		return lag1.stream(rec)
	}
	r := s.crossed(t)
	r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	if live != 0 {
		t.Errorf("CURRENT readback objects live at LAG1 readback entry: %d", live)
	}
	r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	s.settled(t)
	s.consumed(t, CommitTruthNew, r.err)
	s.reopen(t, tcA4Rows(t, s)...)
}

// tcTipCell is the H7 provider action: CanonicalTipV1 of a generation with no canonical-v1 row stores a cell on the
// Reader; the test keeps the Reader and the cell pointer. It never calls t.Fatal (worker goroutine).
type tcTipCell struct {
	old  *Reader
	cell *canonicalTipCell
}

func (c *tcTipCell) take(t *testing.T, old *Reader) {
	point, err := old.CanonicalTipV1(9)
	if point != nil || err != nil || old.tip == nil || old.tip.generation != 9 {
		t.Errorf("CanonicalTipV1(9) %v %v cell %+v", point, err, old.tip)
	}
	c.old, c.cell = old, old.tip
}

// expired reports the M38 half of the H7 observation: the provider Reader is unusable.
func (c *tcTipCell) expired() bool { return c.old != nil && !c.old.usable() }

// cleared reports the M39 half of the H7 observation: the cell is canonicalTipCell{}.
func (c *tcTipCell) cleared() bool { return c.cell != nil && *c.cell == canonicalTipCell{} }

// tcRetired checks both H7 halves on their own lines; it never calls t.Fatal (worker goroutine).
func tcRetired(t *testing.T, at string, expired, cleared bool) {
	if !expired {
		t.Errorf("%s: provider Reader still usable", at)
	}
	if !cleared {
		t.Errorf("%s: canonicalTipCell not retired", at)
	}
}

// H7, M38-M40: the provider Reader is expired and its source cell retired when its call returns (writer, at the
// first charge after CURRENT's writer provider returned), on a writer Goexit (before resume) and at the readback.
func TestTreeComposeReaderExpiryV1(t *testing.T) {
	t.Run("writer", func(t *testing.T) {
		s := tcNew(t, 3)
		var tip tcTipCell
		cur, returned, observed := s.prims[0], false, false
		var amount uint64
		var expired, cleared bool
		cur.custom = func(old *Reader, rec *treeRecorderV1) error {
			tip.take(t, old)
			err := cur.stream(rec)
			returned = true
			return err
		}
		s.ledger.before = func(n uint64) {
			if returned && !observed {
				observed, amount, expired, cleared = true, n, tip.expired(), tip.cleared()
			}
		}
		r := s.run(nil)
		r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
		if !observed || amount == tcStep {
			t.Errorf("first charge after CURRENT returned is %d (observed %v), want one before its step 8", amount, observed)
		}
		tcRetired(t, "first charge after CURRENT returned", expired, cleared)
		r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
		s.settled(t)
		s.ledger.before = nil
		s.reopen(t, append(s.newRows(t), s.following(t))...)
	})
	t.Run("goexit", func(t *testing.T) {
		s := tcNew(t, 3)
		var tip tcTipCell
		lag1 := s.prims[1]
		lag1.custom = func(old *Reader, rec *treeRecorderV1) error {
			tip.take(t, old)
			if err := lag1.stream(rec); err != nil {
				t.Errorf("stream: %v", err)
			}
			runtime.Goexit()
			return nil
		}
		s.goexitRun(t, func(r tcResult) {
			if r.unwind.kind != 2 {
				t.Errorf("goexit unwind %d, want 2", r.unwind.kind)
			}
			tcRetired(t, "goexit before resume", tip.expired(), tip.cleared())
		})
		s.settled(t)
		s.reopen(t, append(s.oldRows(t), s.following(t))...)
	})
	t.Run("readback", func(t *testing.T) {
		s := tcNew(t, 2)
		body := append(append([]byte(nil), tcFU...), tcFC...)
		treeNativeSeed(t, s.store, 4, tcB1[:], body)
		s.prims[1].events = []tdEv{tdCreate(tcTU, 0, 0, 0, uint32(len(tcFU))), tdCreate(tcTU, 1, 0, uint64(len(tcFU)), uint32(len(tcFC)))}
		var tip tcTipCell
		cur, lag1 := s.prims[0], s.prims[1]
		var expired, cleared bool
		cur.custom = func(old *Reader, rec *treeRecorderV1) error {
			if cur.calls[treeReadbackV1] == 1 {
				tip.take(t, old)
			}
			return cur.stream(rec)
		}
		lag1.custom = func(old *Reader, rec *treeRecorderV1) error {
			if lag1.calls[treeReadbackV1] == 1 {
				expired, cleared = tip.expired(), tip.cleared()
			}
			return lag1.stream(rec)
		}
		r := s.crossed(t)
		r.check(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
		tcRetired(t, "CURRENT's readback at LAG1's readback entry", expired, cleared)
		r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
		s.settled(t)
		s.consumed(t, CommitTruthNew, r.err)
		s.reopen(t, tcA4Rows(t, s)...)
	})
}

// N1: CURRENT's generation binding row absent, malformed (132 bytes) or of another DatabaseID is the fold's integrity
// result at index 0 before any put (stage 1); the provider ran once.
func TestTreeComposeBindingStageV1(t *testing.T) {
	malformed := make([]byte, 132)
	for _, variant := range []string{"absent", "malformed", "foreign"} {
		t.Run(variant, func(t *testing.T) {
			s := tcNew(t, 1)
			bindings, key := TreeSchemaV1DBIs()[0], tcBindingKey(1)
			var row []byte
			switch variant {
			case "absent":
				mustEnvironment(t, fixtureDeletePrefixRow(s.store, bindings, key))
			case "malformed":
				row = malformed
			case "foreign":
				row = tcBindingID(t, [32]byte{8}, 1, tcOldEP)
			}
			if row != nil {
				mustEnvironment(t, fixtureSeedPrefixRawRow(s.store, bindings, key, row))
			}
			r := s.run(nil)
			r.check(t, CommitTruthOld, UpdateStagePrewrite, 0)
			if s.prims[0].calls[treeWriterV1] != 1 {
				t.Errorf("provider calls %d, want 1", s.prims[0].calls[treeWriterV1])
			}
			r.want(t, CommitTruthOld, UpdateStagePrewrite, 0)
			engine, direct := directTestEngineError(r.err)
			if !direct {
				t.Fatalf("N1 err %+v is not a direct EngineError", r.err)
			}
			if engine.Class != EngineIntegrity {
				t.Errorf("N1 class %v, want Integrity", engine.Class)
			}
			if engine.Operation != string(operationUpdate) {
				t.Errorf("N1 operation %q, want update", engine.Operation)
			}
			if engine.Code != codeCorrupted {
				t.Errorf("N1 code %d, want corrupted", engine.Code)
			}
			if engine.Diagnostic != "invalid tree native representation" {
				t.Errorf("N1 diagnostic %q", engine.Diagnostic)
			}
			if engine.ReopenRequired {
				t.Errorf("N1 ReopenRequired true")
			}
			_, decodeErr := DecodeRootBindingV1(malformed)
			if variant == "malformed" && (decodeErr == nil || !errors.Is(engine.Cause, decodeErr)) {
				t.Errorf("N1 cause %v, want the decode error %v", engine.Cause, decodeErr)
			}
			if variant != "malformed" && engine.Cause != nil {
				t.Errorf("N1 cause %v, want nil", engine.Cause)
			}
			s.settled(t)
			s.consumed(t, CommitTruthOld, r.err)
			s.reopen(t, ttRow{ttUTXO, tdUTXOKey(1, tcT0, 0), nil}, ttRow{ttBlocks, tcB0[:], nil}, ttRow{schemaDBIs[5], tdManifestKey(tcB0), nil}, ttRow{bindings, key, row})
		})
	}
}

// tcTwoLeaf is the N2 plan: generation 1 holds UTXO rows a and b (leaves A and B under root branch R); CURRENT
// (tx 0 coinbase without outputs, tx 1 spends a) changes only a, so leaf B is the boundary reference.
func tcTwoLeaf(t *testing.T) (*tcScene, []byte) {
	t.Helper()
	store, path := ttStore(t)
	frame := tdFrame(500, 0, nil)
	keyA, keyB := tdUTXOKey(1, tdTxid(0xa1), 0), tdUTXOKey(1, tdTxid(0xa2), 0)
	value := tdFormed(frame, 3, 0)
	entries := []testTreeEntry{tcEntry(keyA, value), tcEntry(keyB, value)}
	nodes := map[string][]byte{}
	testTreeBuild(1, entries, nodes)
	for name, row := range nodes {
		key := make([]byte, (len(name)-2)/2)
		_, err := fmt.Sscanf(name[2:], "%x", &key)
		mustEnvironment(t, err)
		treeNativeSeed(t, store, 8, key, row)
	}
	treeNativeSeed(t, store, 1, keyA, value)
	treeNativeSeed(t, store, 1, keyB, value)
	treeNativeSeed(t, store, 0, tcBindingKey(1), tcBinding(t, 1, tcOldEP, entries...))
	s := &tcScene{store: store, path: path, ledger: &tcLedger{}}
	s.pair = []ownedMutation{{dbi: ttBlocks, key: tcB0[:], after: AfterLiteral, literal: tcF0}}
	s.prims = []*tcPrim{{name: "C", prim: tcForward(treeKindConnectV1, 1, 10, tcB0), txCount: 2, events: []tdEv{tdSpend(tdTxid(0xa1), 0, 1, 0)}, ledger: s.ledger}}
	return s, testTreeNodeKey(1, 288, [36]byte(keyB[8:]))
}

// N2: mode 4 deletes leaf B (CURRENT's boundary reference) after the commit; the readback's predicate fails, UNKNOWN.
func TestTreeComposeBoundaryReferenceV1(t *testing.T) {
	s, leafB := tcTwoLeaf(t)
	var r tcResult
	evidence, err := fixtureLargeFault(s.store, 4, 8, leafB, func() { r = s.run(nil) })
	mustEnvironment(t, err)
	if evidence.commits < 1 {
		t.Errorf("mode 4 did not commit: %+v", evidence)
	}
	if evidence.drift < 1 {
		t.Errorf("mode 4 did not drift: %+v", evidence)
	}
	r.check(t, CommitTruthUnknown, UpdateStageCommitMayHaveCrossed, -1)
	tcCrossedCause(t, r.err, CommitTruthUnknown, nil)
	r.want(t, CommitTruthUnknown, UpdateStageCommitMayHaveCrossed, -1)
	if s.store.state != storeCLOSED {
		t.Errorf("N2 state %v, want CLOSED", s.store.state)
	}
	if s.store.terminalTruth != CommitTruthUnknown {
		t.Errorf("N2 terminal truth %d, want UNKNOWN", s.store.terminalTruth)
	}
	s.settled(t)
	s.consumed(t, CommitTruthUnknown, r.err)
	s.reopen(t, ttRow{TreeSchemaV1DBIs()[8], leafB, nil}, ttRow{ttUTXO, tdUTXOKey(1, tdTxid(0xa1), 0), nil}, ttRow{ttBlocks, tcB0[:], tcF0})
}

// tcNetClean is the N3 plan: CURRENT's tx 1 creates u and tx 2 spends it (no target at UTXOKey(1, u)).
func tcNetClean(t *testing.T) (*tcScene, []byte) {
	t.Helper()
	s := tcNew(t, 1)
	u, fu := tdTxid(0x60), tdFrame(600, 0, nil)
	body := append(append([]byte(nil), tcF0...), fu...)
	s.pair[0].literal = body
	s.prims[0].txCount = 3
	s.prims[0].events = []tdEv{tdCreate(tcT0, 0, 0, 0, uint32(len(tcF0))), tdCreate(u, 0, 1, uint64(len(tcF0)), uint32(len(fu))), tdSpend(u, 0, 2, 0)}
	return s, tdUTXOKey(1, u, 0)
}

// N3: the non-net-dirty outpoint u is a reference: drift there after the commit (mode 3) is UNKNOWN, and drift in
// the write txn after the first put (mode 13) is refused by complete final pair equality.
func TestTreeComposeNetCleanReferenceV1(t *testing.T) {
	t.Run("readback", func(t *testing.T) {
		s, key := tcNetClean(t)
		var r tcResult
		evidence, err := fixtureLargeFault(s.store, 3, 1, key, func() { r = s.run(nil) })
		mustEnvironment(t, err)
		if evidence.commits < 1 {
			t.Errorf("mode 3 did not commit: %+v", evidence)
		}
		if evidence.drift < 1 {
			t.Errorf("mode 3 did not drift: %+v", evidence)
		}
		r.check(t, CommitTruthUnknown, UpdateStageCommitMayHaveCrossed, -1)
		tcCrossedCause(t, r.err, CommitTruthUnknown, nil)
		r.want(t, CommitTruthUnknown, UpdateStageCommitMayHaveCrossed, -1)
		s.settled(t)
		s.consumed(t, CommitTruthUnknown, r.err)
		s.reopen(t, ttRow{ttUTXO, key, []byte{0x7f}}, ttRow{ttBlocks, tcB0[:], s.pair[0].literal})
	})
	t.Run("writer", func(t *testing.T) {
		s, key := tcNetClean(t)
		var r tcResult
		evidence, err := fixtureLargeFault(s.store, 13, 1, key, func() { r = s.run(nil) })
		mustEnvironment(t, err)
		if evidence.drift < 1 {
			t.Errorf("mode 13 did not fire: %+v", evidence)
		}
		r.check(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, -1)
		if engine, ok := directTestEngineError(r.err); !ok || engine.Diagnostic != "final update image mismatch" {
			t.Errorf("N3 writer err %v, want final update image mismatch", r.err)
		}
		s.reopenNow(t, ttRow{ttUTXO, key, nil})
		r.want(t, CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, -1)
		ttMismatch(t, r.err, "final update image mismatch")
		s.settled(t)
		s.consumed(t, CommitTruthOld, r.err)
		s.reopen(t, append(s.oldRows(t)[:4], ttRow{ttUTXO, key, nil})...)
	})
}

// Control for N2 and N3: the same plans under the clean crossing (mode 12, no drift) read back NEW, so their UNKNOWN
// and final-equality results come from the armed drift.
func TestTreeComposeReferenceControlV1(t *testing.T) {
	for name, build := range map[string]func(*testing.T) (*tcScene, []byte){"N2": tcTwoLeaf, "N3": tcNetClean} {
		t.Run(name, func(t *testing.T) {
			s, _ := build(t)
			r := s.crossed(t)
			r.want(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
			tcCrossedCause(t, r.err, CommitTruthNew, nil)
			s.settled(t)
		})
	}
}

const (
	tcPoisonedChildEnv    = "RUBIN_MDBX_TC_POISONED_CHILD"
	tcPoisonedChildMarker = "RUBIN_MDBX_TC_POISONED_REACHED"
)

// H3 mode-15 poisoned Goexit subcase, M22: run in a child test process (test_evidence_rules child-process rule) so no
// parked runTreeLockedV1 worker remains in the parent test binary.
func TestTreeComposePoisonedGoexitV1(t *testing.T) {
	t.Run("mode15", func(t *testing.T) {
		if os.Getenv(tcPoisonedChildEnv) != "" {
			tcPoisonedChild(t)
			if !t.Failed() {
				fmt.Println(tcPoisonedChildMarker)
			}
			return
		}
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTreeComposePoisonedGoexitV1$/^mode15$", "-test.count=1")
		cmd.Env = append(os.Environ(), tcPoisonedChildEnv+"=1")
		output, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "\n"+tcPoisonedChildMarker+"\n") {
			t.Fatalf("poisoned child: %v\n%s", err, output)
		}
	})
}

// tcPoisonedCause checks the mode-15 ReadbackCause field by field; it never calls t.Fatal (worker goroutine).
func tcPoisonedCause(t *testing.T, err error) {
	var commit *CommitError
	var cause *EngineError
	if !errors.As(err, &commit) || !errors.As(commit.ReadbackCause, &cause) {
		t.Errorf("mode 15 err %v, want a CommitError with an EngineError ReadbackCause", err)
		return
	}
	if cause.Class != EngineLocalInvariant {
		t.Errorf("mode 15 ReadbackCause class %v", cause.Class)
	}
	if cause.Operation != string(operationAbort) {
		t.Errorf("mode 15 ReadbackCause operation %q", cause.Operation)
	}
	if cause.Code != -30416 {
		t.Errorf("mode 15 ReadbackCause code %d", cause.Code)
	}
	if cause.Diagnostic != expectedNativeDiagnostic(-30416) {
		t.Errorf("mode 15 ReadbackCause diagnostic %q", cause.Diagnostic)
	}
}

func tcPoisonedChild(t *testing.T) {
	s := tcNew(t, 3)
	lag1 := s.prims[1]
	lag1.custom = func(_ *Reader, rec *treeRecorderV1) error {
		err := lag1.stream(rec)
		if lag1.calls[treeReadbackV1] == 1 {
			runtime.Goexit()
		}
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var r tcResult
		evidence, err := fixtureLargeFault(s.store, 15, 0, tcOut(), func() { r = s.run(nil) })
		if err != nil || evidence.commits < 1 {
			t.Errorf("mode 15: %v %+v", err, evidence)
		}
		if r.unwind.kind != 2 {
			t.Errorf("mode 15 unwind kind %d, want 2", r.unwind.kind)
		}
		r.check(t, CommitTruthUnknown, UpdateStageCommitMayHaveCrossed, -1)
		tcPoisonedCause(t, r.err)
		if s.store.state != storePOISONEDTHREAD {
			t.Errorf("mode 15 state %v", s.store.state)
		}
		s.settledNow(t)
		r.unwind.resumeV1()
	}()
	<-done
	if !treeCallPoll(treeCallParkedWorker) {
		t.Fatal("no parked runTreeLockedV1 worker after a poisoned delivery")
	}
	mustEnvironment(t, fixtureLargeRelease(s.store))
	s.settled(t)
	s.reopen(t, s.newRows(t)...)
}
