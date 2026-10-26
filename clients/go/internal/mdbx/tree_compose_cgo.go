//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

/*
#include "../../../../third_party/libmdbx/mdbx.h"
*/
import "C"

import "bytes"

// ---- tree_compose_cgo.go (owner L5a) ----

const treeReaderBytesV1 uint64 = 1152 // R: the provider Reader newUpdateReaderV1 allocates per Source call (216, D33) plus the engine-side allocation of one LargeImageBlockBodyV1 visit with one ReadAt on it (728, D34) plus two 64-byte amended read objects reachable at once (128, D36) plus one mergedNextV1 seek copy (80, D37)

// treeStepBytesV1 is the per-primitive charge W + F_fixed + C + R (D12-E, D14-2, D33), made before the body read.
const treeStepBytesV1 = treeWindowBytesV1 + treeFixedBytesV1 + treeControlBytesV1 + treeReaderBytesV1

type treeSourceV1 func(position treePositionV1, old *Reader, rec *treeRecorderV1) error

func (source treeSourceV1) TreeDeltaV1(position TreePositionV1, old *Reader, sink *TreeDeltaSinkV1) error {
	return source(treePositionV1(position), old, sink.recorder)
}

// treeAdmittedPrimitiveV1 converts only the reached record after its step charge.
func treeAdmittedPrimitiveV1(p *TreePrimitiveV1) treePrimitiveV1 {
	return treePrimitiveV1{
		direction: uint8(p.Direction), kind: uint8(p.Kind), undo: uint8(p.Undo),
		generation: p.Generation, height: p.Height, block: p.Block, endpoint: p.Endpoint,
	}
}

type treePlanV1 struct {
	primitives []TreePrimitiveV1 // immutable caller backing borrowed through completion
	pair       []ownedMutation
	consulted  []ownedConsulted
}

// treeScopeV1 is one position's slots (op or the truth evaluator, D30, D35): the Reader slot, the recorder slot and
// the unwind capture recorded. call is the Source call wrapper, created once per scope before primitive 0 (D34).
type treeScopeV1 struct {
	s           *Store
	old         *C.MDBX_txn
	plan        *treePlanV1
	position    treePositionV1
	ledger      treeLedgerV1
	t           *treeSectionV1
	rb          *treeReadbackStateV1
	j           int
	reader      *Reader
	rec         *treeRecorderV1
	recorded    error
	unwind      treeUnwindV1
	call        func() error
	held        bool   // W + F_fixed + C + R of j is charged
	events      uint32 // max_j EventCount_j at the writer
	observation TreeObservationV1
}

// treeComposeV1 is the frame-held state of one updateTreeLockedV1 call: the captured outcome and index (D17 item 3)
// and every engine charge op still holds.
type treeComposeV1 struct {
	writer    *treeScopeV1
	outcome   updateNativeOutcome
	index     int
	unwind    treeUnwindV1
	done      bool   // op assigned outcome on a normal path
	committed bool   // commitV1 was entered
	heldR     uint64 // S_r + B_r
}

func newTreeScopeV1(s *Store, old *C.MDBX_txn, plan *treePlanV1, position treePositionV1, ledger treeLedgerV1) *treeScopeV1 {
	e := &treeScopeV1{s: s, old: old, plan: plan, position: position, ledger: ledger}
	e.call = e.sourceV1
	return e
}

func (e *treeScopeV1) sourceV1() error {
	return e.plan.primitives[e.j].Source.TreeDeltaV1(TreePositionV1(e.position), e.reader, &TreeDeltaSinkV1{recorder: e.rec})
}

// slotV1 is the scope's one deferred slot function: a Reader still in its slot means the call did not return (a
// provider Goexit), so it is expired and its cell retired before the recorder expires and R_j is captured (D35).
func (e *treeScopeV1) slotV1() {
	if e.reader != nil {
		e.reader.expire().retire()
		e.rec.expireV1()
		e.recorded = joinErrors(e.reader.failure, e.rec.failureV1())
		e.reader = nil
	}
	if e.rec != nil {
		e.rec.expireV1()
		e.rec.releaseV1()
		e.rec = nil
	}
}

// treeExactV1 reports whether provider is exactly f: interface identity for every dynamic type of f (D39). Every f is
// a pointer-typed engine value, so the comparison cannot panic.
func treeExactV1(provider, f error) bool {
	return any(provider) == any(f)
}

// treePrimaryV1 is the D12-G1 provider primary: providerErr, then the Reader's and the recorder's failure in that order.
func treePrimaryV1(provider, reader, sink error) error {
	primary := provider
	for _, f := range [2]error{reader, sink} {
		if f != nil && !treeExactV1(provider, f) {
			primary = joinErrors(primary, f)
		}
	}
	return primary
}

// invokeV1 runs Source j over a fresh provider Reader. When the call returns, the Reader is expired and its cell
// retired, then the recorder expires, then the primary is read (D13-9, D35); on a recovered panic it is R_j.
func (e *treeScopeV1) invokeV1() error {
	e.reader = e.s.newUpdateReaderV1(e.old)
	unwind, providerErr := treeCallV1(e.call)
	e.reader.expire().retire()
	e.rec.expireV1()
	primary := treePrimaryV1(providerErr, e.reader.failure, e.rec.failureV1())
	e.reader = nil
	e.unwind = unwind
	return primary
}

// treePairBodyV1 is the Pair mutation of blocks-v1[block], if any (D13-5, D14-4).
func treePairBodyV1(pair []ownedMutation, block [32]byte) *ownedMutation {
	for i := range pair {
		if pair[i].dbi.Rank == 4 && bytes.Equal(pair[i].key, block[:]) {
			return &pair[i]
		}
	}
	return nil
}

// bodyV1 binds j's body: a Pair literal; else the ORIGINAL OLD row, with pair = true for a Pair delete (D14-4).
func (e *treeScopeV1) bodyV1(block [32]byte) (treeBodyV1, error) {
	mutation := treePairBodyV1(e.plan.pair, block)
	if mutation != nil && mutation.after == AfterLiteral {
		return treeBodyV1{bytes: mutation.literal, pair: true}, nil
	}
	body, err := treeStoredBodyV1(e.checkedV1(), block)
	body.pair = mutation != nil
	return body, err
}

func (e *treeScopeV1) checkedV1() treeOldV1 {
	if e.rb != nil {
		return e.rb.oldV1()
	}
	return e.t.oldV1(true)
}

func (e *treeScopeV1) uncheckedV1() treeOldV1 {
	if e.rb != nil {
		return e.rb.oldV1()
	}
	return e.t.oldV1(false)
}

func (e *treeScopeV1) emitterV1() treeEmitterV1 {
	if e.rb != nil {
		return e.rb.emitterV1()
	}
	return e.t.writerV1()
}

// stepV1 runs primitive j (I-SEQ steps 1-8). A nil error with e.unwind.kind != 0 is a recovered provider panic.
func (e *treeScopeV1) stepV1(j int) error {
	e.j = j
	err := e.ledger.chargeV1(treeStepBytesV1)
	if err != nil {
		return err
	}
	e.held = true
	prim := treeAdmittedPrimitiveV1(&e.plan.primitives[j])
	body, err := e.bodyV1(prim.block)
	if err != nil {
		return err
	}
	e.rec = newTreeRecorderV1(e.position, prim, body, make([]byte, treeWindowBytesV1), e.ledger)
	if coverage := e.plan.primitives[j].Coverage; coverage != nil {
		e.rec.coverage = *coverage
		e.observation = TreeObservationV1{DatabaseID: coverage.DatabaseID, Generation: prim.generation, Block: prim.block, Height: prim.height, Primitive: j, Position: TreePositionV1(e.position)}
		e.rec.observation = &e.observation
	}
	err = e.invokeV1()
	if err != nil || e.unwind.kind != 0 {
		return err
	}
	err = e.deltaV1(&prim)
	if err != nil {
		return err
	}
	e.rec.releaseV1()
	e.rec = nil
	e.held = false
	e.ledger.releaseV1(treeStepBytesV1)
	return nil
}

// deltaV1 is steps 3-7: finish, resolve, the writer-only fold, apply and node emission.
func (e *treeScopeV1) deltaV1(prim *treePrimitiveV1) error {
	d, err := e.rec.finishV1()
	if err != nil {
		return err
	}
	e.events = max(e.events, e.rec.eventCount)
	err = d.resolveV1(e.checkedV1())
	if err != nil {
		return err
	}
	if e.rb == nil {
		err = treeFoldV1(e.checkedV1(), prim.generation, prim.endpoint, e.s.databaseID, d.leavesV1(), e.ledger, e.rec.observation)
		if err != nil {
			return err
		}
	}
	err = d.applyV1(e.emitterV1())
	if err != nil {
		return err
	}
	return treeEmitNodesV1(e.uncheckedV1(), prim.generation, prim.endpoint, e.s.databaseID, d.leavesV1(), e.emitterV1(), e.ledger, e.rec.observation)
}

// loopV1 runs every primitive in index order and stops at the first result or unwind; it reports the stop.
func (e *treeScopeV1) loopV1() (bool, error) {
	for j := range e.plan.primitives {
		err := e.stepV1(j)
		if err != nil || e.unwind.kind != 0 {
			return true, err
		}
	}
	return false, nil
}

// updateTreeLockedV1 runs F1 steps 6-9 for an admitted borrowed-primitive / owned-Pair plan under s.operations held by the caller.
// Its op closure assigns a frame-held updateNativeOutcome and index on every exit, deferred cleanup included;
// *out receives err and poisoned field by field from it. On Goexit, truth, stage, index and the primary-vs-cleanup
// split are read from that captured value, never from *out. Precondition: every primitive Generation != 0, and no Block is in both a forward and an inverse primitive (L5b phase P, D27).
func (s *Store) updateTreeLockedV1(old *C.MDBX_txn, ledger treeLedgerV1, plan *treePlanV1) (CommitTruth, UpdateStage, int, treeUnwindV1, error) {
	c := &treeComposeV1{writer: newTreeScopeV1(s, old, plan, treeWriterV1, ledger), index: -1}
	_, unwind := runTreeLockedV1(c.opV1)
	cleanup, oldRetained := updateAbortOld(old)
	if unwind.kind != 0 && c.outcome.primary == nil {
		return c.outcome.truth, c.outcome.stage, c.index, unwind, s.treeUnwoundV1(c.outcome, old, cleanup, oldRetained)
	}
	truth, stage, err := s.applyUpdateOutcome(c.outcome, old, cleanup, oldRetained)
	return truth, stage, c.index, unwind, err
}

// treeUnwoundV1 is the nil-primary law of D3 P(b)/D4 WG(b): both aborts clean -> OPEN; a retained write or OLD ->
// POISONED_THREAD; any other abort or cleanup error -> CLOSED. No cleanup error becomes a primary (D17 item 3).
func (s *Store) treeUnwoundV1(outcome updateNativeOutcome, old *C.MDBX_txn, cleanup error, oldRetained bool) error {
	failure := joinErrors(outcome.secondary, cleanup)
	retained := updateRetained(outcome)
	if retained == nil && oldRetained {
		retained = old
	}
	if retained != nil {
		return s.poison(retained, failure).err
	}
	if failure == nil {
		return nil
	}
	_, failure = s.consume(failure)
	return failure
}

func (c *treeComposeV1) opV1(out *transactionOutcome) treeUnwindV1 {
	defer c.cleanupV1(out)
	defer c.writer.slotV1()
	c.runV1()
	return c.unwind
}

// cleanupV1 is op's deferred cleanup (D4 T3), run after the slot function expired and released the recorder: it
// releases every engine charge still held exactly once, then on a writer-position panic or Goexit aborts the write
// txn with R_j, and writes *out field by field from the captured outcome.
func (c *treeComposeV1) cleanupV1(out *transactionOutcome) {
	unwound := !c.done && !c.committed && c.writer.t != nil
	c.releaseV1()
	if unwound {
		c.outcome, c.index = c.writer.t.abortV1(c.writer.recorded), c.writer.j
	}
	out.err = c.outcome.primary
	out.poisoned = c.outcome.retainedWrite != nil || c.outcome.retainedRead != nil
}

func (c *treeComposeV1) releaseV1() {
	w := c.writer
	if w.held {
		w.held = false
		w.ledger.releaseV1(treeStepBytesV1)
	}
	if w.t != nil && w.t.pBudgetV1() != 0 {
		w.ledger.releaseV1(w.t.pBudgetV1())
	}
	if c.heldR != 0 {
		w.ledger.releaseV1(c.heldR)
	}
}

func (c *treeComposeV1) runV1() {
	w := c.writer
	t, outcome := beginTreeSectionV1(w.s.env, w.s.dbis, w.old, w.ledger)
	if t == nil {
		c.outcome, c.done = outcome, true
		return
	}
	w.t = t
	t.covered = len(w.plan.primitives) != 0 && w.plan.primitives[0].Coverage != nil
	err := t.pairPreflightV1(w.plan.pair, w.plan.consulted)
	if err != nil {
		c.abortV1(err, -1)
		return
	}
	stopped, err := w.loopV1()
	if stopped && w.unwind.kind != 0 {
		c.unwind, w.recorded = w.unwind, err // P: R_j is the step-2 primary; cleanupV1 aborts after the release (T3)
		return
	}
	if stopped {
		c.abortV1(err, w.j)
		return
	}
	err = c.holdV1()
	if err != nil {
		c.abortV1(err, -1)
		return
	}
	c.commitV1()
}

func (c *treeComposeV1) abortV1(err error, index int) {
	c.outcome, c.index, c.done = c.writer.t.abortV1(err), index, true
}

// holdV1 emits the Pair, runs complete final pair equality and, with at least one primitive, charges
// H_r = S_r + B_r with B_r = W + F_fixed + C + R + V + L2 + descSize x max_j EventCount_j (D13-14).
func (c *treeComposeV1) holdV1() error {
	w := c.writer
	if w.t.covered {
		return c.coveredHoldV1()
	}
	err := w.t.pairEmitV1(w.plan.pair)
	if err != nil {
		return err
	}
	err = w.t.finalV1(w.plan.pair, w.plan.consulted)
	if err != nil {
		return err
	}
	return c.reserveV1()
}

func (c *treeComposeV1) coveredHoldV1() error {
	w := c.writer
	err := w.t.freezeV1(w.plan.pair, w.plan.consulted)
	if err != nil {
		return err
	}
	err = c.reserveV1()
	if err != nil {
		return err
	}
	err = w.t.flushV1(w.plan.pair)
	if err != nil {
		return err
	}
	return w.t.finalV1(w.plan.pair, w.plan.consulted)
}

func (c *treeComposeV1) reserveV1() error {
	w := c.writer
	if len(w.plan.primitives) == 0 {
		return nil
	}
	hr := treeScratchBytesV1 + treeStepBytesV1 + treeValueBytesV1 + treeNodeWorkBytesV1 + treeDescSizeV1*uint64(w.events)
	err := w.ledger.chargeV1(hr)
	if err != nil {
		return err
	}
	c.heldR = hr
	return nil
}

func (c *treeComposeV1) commitV1() {
	w := c.writer
	var truth treeTruthV1
	if len(w.plan.primitives) != 0 {
		truth = c.truthV1
	}
	c.committed = true
	c.outcome = w.t.commitV1(w.plan.pair, w.plan.consulted, truth)
	c.index, c.done = -1, true
}

// truthV1 is the truth evaluator: one strict snapshot, its own slots and capture (D30, D35). Its first deferred
// function aborts the snapshot only when a provider Goexit unwinds it (D32).
func (c *treeComposeV1) truthV1(read *C.MDBX_txn, primary error) (CommitTruth, error) {
	completed := false
	e := newTreeScopeV1(c.writer.s, c.writer.old, c.writer.plan, treeReadbackV1, nil)
	defer c.unwoundV1(&completed, e, read, primary)
	defer e.slotV1()
	truth, err := c.readbackV1(e, read)
	completed = true
	return truth, err
}

// unwoundV1 records the readback Goexit outcome (RG): X = R_j from the capture, the snapshot abort, index -1.
func (c *treeComposeV1) unwoundV1(completed *bool, e *treeScopeV1, read *C.MDBX_txn, primary error) {
	if *completed {
		return
	}
	abortErr, retained := updateAbortOld(read)
	secondary := joinErrors(e.recorded, abortErr)
	c.outcome = updateNativeConsumed(CommitTruthUnknown, true, primary, secondary, UpdateStageCommitMayHaveCrossed)
	if retained {
		c.outcome = updateNativeRetainedRead(primary, secondary, read)
	}
	c.index = -1
}

// readbackV1 replays every primitive at the readback position inside budget = P + S_r + B_r (D13-15), then verdictV1.
func (c *treeComposeV1) readbackV1(e *treeScopeV1, read *C.MDBX_txn) (CommitTruth, error) {
	budget := treeBudgetV1{held: c.writer.t.pBudgetV1() + c.heldR}
	rb, err := newTreeReadbackV1(e.old, read, e.s.dbis, &budget)
	if err != nil {
		return CommitTruthUnknown, err
	}
	e.rb, e.ledger = rb, budget.ledgerV1()
	if stopped, err := e.loopV1(); stopped {
		c.unwind = e.unwind
		return CommitTruthUnknown, err
	}
	return rb.verdictV1(e.plan.pair, e.plan.consulted)
}
