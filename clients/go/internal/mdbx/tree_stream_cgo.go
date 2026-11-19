//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

/*
#include "../../../../third_party/libmdbx/mdbx.h"
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"slices"
	"unsafe"
)

// TreePairV1 contains ordinary non-tree targets, unchanged consulted rows and the optional physical scope below.
// Mutations and Consulted rows must be strictly (rank, key) ordered in each slice and disjoint. Rank 8
// is never a Mutations or Consulted row. AfterOldValueRef is forbidden. The operation owns copies
// after admission. Pair slices, records and Key/Literal bytes remain immutable
// through the first Source call, or operation completion if no Source is reached; for a
// physical-scope Pair, through its owned admission, with the caller's charged backing kept until return.
type TreePairV1 struct {
	Mutations []Mutation
	Consulted []ConsultedRow
	// PrepaidReadBytes declares same-account coverage exclusively assigned by a trusted
	// caller to ordinary Pair reads through completion, including readback and cleanup.
	// It excludes original input, PC, context and ENTRY data. Zero uses engine funding.
	// Positive values require no primitives and cannot exceed the account ceiling.
	// The engine neither authenticates this declaration nor releases the caller's grant.
	PrepaidReadBytes uint64
	// EntryInventory accepts the completed token for this same entry, account and Pair.
	EntryInventory *EntryInventoryV1
	// ContextConsulted is an optional canonical context window with the legacy Batch.ContextConsulted semantics
	// and format-3 widths: each 104-byte index row and the 148-byte header selected by its leading 32 bytes must
	// be present and byte-identical at ORIGINAL OLD qualification, write snapshot, final image and possible-crossed
	// readback. nil adds no domain. A non-nil window cannot be combined with EntryInventory ("invalid Update
	// Batch"). A non-nil window takes exactly one fixed 344-byte charge, held to operation completion; its rows are
	// reread from ORIGINAL OLD one pair at a time and not retained, and context data the caller reads or holds stays
	// on the caller's own charges. The engine copies the descriptor at step 5 and never reads the caller's value
	// after; the caller must keep *ContextConsulted unchanged from the callback's return until that copy.
	ContextConsulted *CanonicalContextWindowV1
	// PreserveReplayObservations retains the callback endpoint and declares absent
	// undo for a selected CURRENT Transient replay through final and strict equality.
	// Deletion requires a successful callback endpoint; every other shape refuses.
	PreserveReplayObservations bool
	// ObsoleteDeletes and ObsoleteConsulted hold tokens read from this operation's ORIGINAL OLD Reader
	// only; LargeConsulted holds plain (Kind, Hash) selector values. For all three nil and empty are
	// equivalent, and they are read only after the callback. Any nonempty field makes the operation a physical-scope Pair, which needs a
	// LaneOperation account, no primitives, Proof, HeaderSlot, EntryInventory or ContextConsulted,
	// zero PrepaidReadBytes, PreserveReplayObservations false and at least one Mutation or ObsoleteDeletes row. After the ordinary Pair checks, which keep their own refusals,
	// the refusals are, in order: any other shape is "invalid Update Batch"; more than 2391106
	// deletes plus witnesses, more than 2880 selectors or more than 1440 of one kind is "Update Batch
	// exceeds bound"; a token not from this operation's Reader is "invalid Update Batch"; after the
	// closed-account refusal, the metadata charge refuses with the operation-reservation capacity
	// error; then a duplicate witness or delete, an uncovered delete, or a delete overlapping a
	// Mutation or Consulted row is "invalid Update Batch"; the combined Update Batch caps refuse
	// with "Update Batch exceeds bound"; then an unknown-kind or not strictly (Kind, Hash) ordered
	// selector, or a Consulted row inside a selector, is "invalid Update Batch"; last, more than
	// 2391106 coalesced domains, points and selectors, or their control keys above 137676154 bytes,
	// is "Update Batch exceeds bound". ObsoleteDeletes may be unordered and may delete rank-8 and
	// generation root rows. The caller charges each raw page, token, key, continuation and selector
	// backing and each ordinary input backing on this same LaneOperation account before creating or
	// reading it and keeps that grant through the backing's last use; the engine neither
	// authenticates that grant nor supplies a second account.
	ObsoleteDeletes   []ObsoleteRowV1
	ObsoleteConsulted []ObsoletePageWitnessV1
	LargeConsulted    []LargeImageSelectorV1
}

// TreeSourceV1 is an immutable, replayable complete block source. At each position
// it calls BeginV1 once first, then emits every forward event in original body
// order, with an identical stream at TreeWriterV1 and TreeReadbackV1.
//
// Compute txid as incremental SHA3-256 of contiguous raw core bytes [txStart,
// coreEnd), excluding witness, da_payload_len and da_payload. Emit CREATE only
// in a second output-region read after txid is final, retaining per transaction
// only txStart, outputs start, output count and the 32-byte txid. Emit no SPEND
// for transaction 0's coinbase input and exactly one for each input of every
// transaction index >= 1. Omit CREATE for covenant types 0x0002 and 0x0103,
// preserving every other output's real index. Derive FrameOffset/FrameLength
// from fixed fields and covenant_data_len CompactSize without holding a complete
// frame. Read tx_count at the stored header width (116 legacy, 148 initial148).
//
// Supply no values, presence flags, digest or node data. Make no reservation
// (account/owner WithReservation or WithOperation) inside TreeDeltaV1, allocate
// no block-growing memory, and keep fixed live state within 4,096 bytes. Read
// stored bodies only through old.VisitLargeImageV1 and LargeImageRowV1.ReadAt
// into sink.WindowV1(); CURRENT bytes must already be held under the composer's
// validation charge. Retain neither window, record nor sink after returning,
// start no goroutine that outlives the call, and return sink refusals unchanged.
// Source bytes and objects remain complete and immutable through their last
// writer/equality consumer. Original Pair buffers cannot also be mutable backing
// still needed by a Source.
type TreeSourceV1 interface {
	TreeDeltaV1(position TreePositionV1, old *Reader, sink *TreeDeltaSinkV1) error
}

// TreePrimitiveV1 is one CURRENT or subsequent LAG primitive. Generation is
// nonzero. A Block cannot occur in both directions in one operation. Source is
// complete and replayable; Kind, Direction and Undo must follow the closed table.
// DirectApply admits WriteOrReuse/Transient; Connect and FirstGenesis admit
// WriteOrReuse; ReplayNext admits WriteOrReuse/Transient/Compare/CompareDelete;
// RestoreOld admits Compare; LagForward admits WriteOrReuse/Transient;
// Disconnect admits SourceRetain; RollbackNew and LagReverse admit
// SourceRetain/SourceDelete. No other Kind/Undo pair is admitted.
type TreePrimitiveV1 struct {
	Direction  TreeDirectionV1
	Kind       TreePrimitiveKindV1
	Generation uint64
	Block      [32]byte
	Height     uint64
	Source     TreeSourceV1
	Undo       TreeUndoEffectV1
	// Endpoint is composer-qualified, including cumulative chainwork. Forward
	// requires Applied(Height, Block); inverse at height 0 requires PreGenesis,
	// otherwise Applied(Height-1). Valid chainwork is preserved without recomputation.
	Endpoint TreeEndpointV1
	// Coverage binds a qualified complete source. All primitives carry it or
	// all omit it. Covered operations finish planning before native mutation.
	Coverage *TreeSourceCoverageV1
}

// TreeOperationV1 is one immutable complete CURRENT/LAG plan and ordinary Pair.
// Primitive backing and Source bindings remain immutable through completion,
// including readback and unwind cleanup. At the first Source call all owned Pair
// copies exist; only the independent original Pair buffers may then be mutated.
// Borrowed input remains the caller's funding obligation.
//
// Proof is optional. When non-nil, admission refuses with "invalid Update
// Batch" (OLD/Prewrite/-1) unless the operation has at least one primitive,
// every primitive carries Coverage, and Primitives[1:] share one generation
// distinct from Primitives[0].Generation; the step-5 plan-copy charge then also
// covers the TreeDeltaReportV1 backing. UpdateTreeV1 calls Proof exactly once,
// after the complete covered preflight, freeze and reservation and before the
// first native write, never at readback; Proof is not called when an earlier
// step refuses. A non-nil result E ends the attempt as (OLD, Prewrite, -1, E)
// with no write, consumes or retains Store resources under the existing owner
// and releases the account charges once. A Proof panic or Goexit takes the writer-position unwind with
// index -1; a clean unwind leaves the Store OPEN, then the panic or Goexit
// resumes. A nil result continues, with HeaderSlot non-nil, to the header-slot
// resolution below, which can still refuse, and then to flush, final checks and
// commit.
// Proof must not call any Store, Reader or OperationAccount method,
// must not retain the report, and must start no goroutine that outlives the call.
//
// HeaderSlot is optional. When non-nil, after the Proof row and before the
// step-5 charge, admission refuses with "invalid Update Batch" when Proof is
// nil, when ValidateTreeRow(headers-v1, Hash, Header) fails, or when a Pair
// mutation or Consulted row names headers-v1 at Hash; it refuses with "Update
// Batch exceeds bound" when the slot, counted as one more auxiliary 32-byte-key
// 148-byte-literal mutation and one more Consulted row, exceeds a Pair cap.
// Every earlier admission row wins; every slot admission refusal wins over the
// refusal saved for an operation account closed before the hold. A context window
// whose ORIGINAL OLD index selects a header key equal to Hash is refused with
// "invalid Update Batch" at context qualification, whatever the slot would resolve to. The step-5 charge
// then also covers one owned mutation and one owned Consulted row with the
// slot's key and literal; the engine copies the slot at step 5 and never reads the caller's value after.
// The caller must keep *HeaderSlot unchanged from the callback's return until
// that step-5 copy.
// After Proof returns nil and before the first write, with the stage still
// Prewrite, the engine compares the ORIGINAL OLD and write images of row x =
// headers-v1 at Hash, then reads x once more from ORIGINAL OLD to decide it:
// absent inserts Header; a byte-identical 148-byte row is reused with no
// write; any other present value refuses with no write. Both refusals are an
// *EngineError with Class StateMismatch, Operation "update", Code -30779,
// Cause nil, ReopenRequired false and TreeObservation nil; the Diagnostic is
// "OLD/write snapshot mismatch" when the two images differ and "tree header
// slot differs" for a differing row. Each resolution refusal (these two and
// any read error, returned unchanged) takes the Proof error route: OLD,
// Prewrite, index -1, Store resources consumed or retained under the existing
// owner; the admission refusals above leave the Store open. Final equality and
// the readback then cover the insert as a
// Pair target and the reuse as a Consulted row. The engine verifies nothing of
// Header beyond the admission check.
type TreeOperationV1 struct {
	Primitives []TreePrimitiveV1
	Pair       TreePairV1
	Proof      func(*TreeDeltaReportV1) error
	HeaderSlot *TreeHeaderSlotV1
}

// BeginV1 supplies the block header before any event.
func (s *TreeDeltaSinkV1) BeginV1(block TreeBlockV1) error {
	if s == nil || s.recorder == nil {
		return treeSinkInactiveV1()
	}
	return s.recorder.beginV1(block.TxCount, block.EventCount, block.Generated)
}

// EventV1 supplies one forward event, copied independently of the caller's record.
func (s *TreeDeltaSinkV1) EventV1(event TreeEventV1) error {
	if s == nil || s.recorder == nil {
		return treeSinkInactiveV1()
	}
	return s.recorder.eventV1(uint8(event.Kind), event.Outpoint.Txid, event.Outpoint.Vout,
		event.TxIndex, event.InputIndex, event.FrameOffset, event.FrameLength)
}

// WindowV1 lends the bounded read window for the current source call only.
func (s *TreeDeltaSinkV1) WindowV1() []byte {
	if s == nil || s.recorder == nil {
		return nil
	}
	return s.recorder.windowV1()
}

// UpdateTreeV1 admits one typed operation under the Store.Update transaction
// owner. Before locking it refuses nil Store, callback or account and zero/closed
// account. Busy, terminal and non-tree Stores are refused before callback. The
// input diagnostics are "nil Store", "nil UpdateTreeV1 callback", "nil operation
// account" and "closed operation account" (InvalidInput/update/EINVAL, no cause).
// Busy is "store operation in progress"; format 2 is StateMismatch/update/-30779
// with "typed tree operation requires tree store" and no cause.
// ORIGINAL OLD read begin uses the existing consuming failure lifecycle. The
// callback's Reader expires at callback exit; error, panic and Goexit clean OLD
// before delivery, retaining the existing infrastructure failure disposition.
//
// Admission before any reservation or write checks operation gates, primitives,
// Mutations, Consulted, then cross-row relations. Structural failures are "invalid
// Update Batch"; Pair caps are "Update Batch exceeds bound"; the first refused
// row wins. Admission and account refusals abort OLD and leave the Store reusable
// on successful cleanup, except that a native read error or an invalid native
// result shape ("mdbx_get returned invalid result shape") at context qualification
// keeps its infrastructure disposition and uses the existing consuming failure
// lifecycle.
// With Pair.ContextConsulted non-nil, after the HeaderSlot row and before the step-5
// charge: the charge-free descriptor rows (a window with EntryInventory, then the
// legacy scalar "invalid Update Batch", the 10,080-pair "Update Batch exceeds
// bound" and the last-height wrap rows) win over the refusal saved for a closed
// account; then that saved refusal; then one 344-byte context charge; then every
// index key against Pair targets and Consulted rows ("invalid Update Batch") before
// any native read; then ORIGINAL OLD qualification per ascending offset (index
// present with 104 bytes, header key not a Pair row nor HeaderSlot.Hash, header
// present with 148 bytes; "canonical context OLD image is incomplete"). One primitive requires TreeOperation; pair-only plans
// also admit LaneOperation and need at least one Mutation or ObsoleteDeletes row. Rank 8 and
// references are forbidden in Pair Mutations and Consulted rows, as are primitive-owned undo
// families and generation root bindings; ObsoleteDeletes may delete such rows covered by its tokens.
// Meta keys 0, 1, 3 and 0x12 are immutable targets; 2 is literal-only, 0x10 and 0x11 allow literal/delete, and all valid meta keys may be consulted.
// Non-reverse Pair caps are 2,391,106 mutations, 137,676,154 key bytes,
// 155,659,727 literal bytes, 414,634 UTXO deletes, 1,545,454 UTXO literals,
// 16,384 other mutations and 16,384 consulted rows. Mutation shape/order/value
// precede that row's cap; consulted shape/order precede its count. For Pair
// rows, caps precede every own-family, generation-root and consulted/target
// overlap check. The TreeOperationV1.HeaderSlot row follows every Pair row and
// checks its own overlap before its caps.
//
// One account hold charges complete owned Pair arrays and key/literal copies
// before allocating or cloning, then serves
// every engine charge exactly. It is released before result, panic or Goexit
// delivery. Capacity/input errors retain identity. The composer chooses account
// kind; hash-global absent rows become expected-absent targets, identical rows
// become Consulted, and differing rows must be classified before returning the
// plan. The engine never classifies an owner. For the headers-v1 row of
// TreeOperationV1.HeaderSlot it only decides, after Proof, whether the row is
// absent, byte-identical or differing, and refuses a differing row with no
// write, as documented on TreeOperationV1.
// Pair inputs remain immutable through the first Source call (or completion if
// none; owned admission for a physical-scope Pair, whose charged backing the caller keeps until
// return); primitive backing and Source bindings remain immutable through completion
// including unwind cleanup. Source backing remains immutable through its last
// consumer and cannot alias Pair buffers mutated after their independent copy.
//
// Results preserve the composer's truth, reached stage and error; index is the
// primitive owning the first reached source-owned result, otherwise -1. Every
// pre-section refusal is OLD/Prewrite/-1 except cached terminal truth. In-section
// failures consume or retain Store resources under the existing owner; clean
// writer unwind leaves OPEN, readback failure preserves UNKNOWN and its causes.
func (s *Store) UpdateTreeV1(account *OperationAccount, callback func(*Reader) (TreeOperationV1, error)) (CommitTruth, UpdateStage, int, error) {
	err := treeEntryInputV1(s, account, callback)
	if err != nil {
		return CommitTruthOld, UpdateStagePrewrite, -1, err
	}
	serving := s.requestServingCloseV1()
	defer serving.completeV1()
	if !s.operations.TryLock() {
		s.contendedServingCloseV1()
		return CommitTruthOld, UpdateStagePrewrite, -1, adapterError(operationUpdate, EngineConcurrency, codeBusy, "store operation in progress", nil)
	}
	var unwind treeUnwindV1
	defer func() { unwind.resumeV1() }()
	defer s.notifyServingCompletionV1()
	defer s.operations.Unlock()
	truth, stage, index, unwind, err := s.treeEntryLockedV1(account, callback)
	return truth, stage, index, err
}

func treeEntryInputV1(s *Store, account *OperationAccount, callback func(*Reader) (TreeOperationV1, error)) error {
	var diagnostic string
	switch {
	case s == nil:
		diagnostic = "nil Store"
	case callback == nil:
		diagnostic = "nil UpdateTreeV1 callback"
	case account == nil:
		diagnostic = "nil operation account"
	case !account.openV1():
		diagnostic = "closed operation account"
	default:
		return nil
	}
	return adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, diagnostic, nil)
}

func (s *Store) treeEntryLockedV1(account *OperationAccount, callback func(*Reader) (TreeOperationV1, error)) (CommitTruth, UpdateStage, int, treeUnwindV1, error) {
	if err, _ := s.observationStateError(operationUpdate); err != nil {
		truth, stage, refused := s.refusedUpdate(err)
		return truth, stage, -1, treeUnwindV1{}, refused
	}
	if s.format.Load() != 3 {
		return CommitTruthOld, UpdateStagePrewrite, -1, treeUnwindV1{}, treeStreamRefusalV1()
	}
	defer s.latchUpdateTerminalTruth()
	old, err := treeBeginV1(s.env, false)
	if err != nil {
		return CommitTruthOld, UpdateStagePrewrite, -1, treeUnwindV1{}, s.failedReadBegin(old, err)
	}
	e := treePublicEntryV1{store: s, old: old, reader: s.newUpdateReaderV1(old)}
	return e.executeV1(account, callback)
}

// treePublicEntryV1 owns ORIGINAL OLD only until callback refusal or composer handoff.
type treePublicEntryV1 struct {
	store     *Store
	old       *C.MDBX_txn
	reader    *Reader
	hold      *operationHold
	inventory *entryInventoryStateV1
	tip       *canonicalTipCell
}

// callbackV1 expires public borrows while retaining successful ENTRY recipes for admission.
func (e *treePublicEntryV1) callbackV1(callback func(*Reader) (TreeOperationV1, error)) (TreeOperationV1, treeUnwindV1, error) {
	returned := false
	defer func() {
		if !returned {
			e.reader.expire().retire()
			e.retireEntryV1()
			primary, infrastructure := readPrimary(nil, e.reader.failure)
			_ = e.store.abortReadLocked(e.old, primary, infrastructure)
		}
	}()
	op, value, panicked, err := invokeUpdate(callback, e.reader)
	returned = true
	tip := e.reader.expire()
	e.expireEntryV1()
	primary, infrastructure := readPrimary(err, e.reader.failure)
	if !panicked && primary == nil && op.Pair.PreserveReplayObservations {
		e.tip = tip
	} else {
		tip.retire()
	}
	if panicked {
		e.retireEntryV1()
		return TreeOperationV1{}, treeUnwindV1{kind: 1, value: value}, e.store.abortReadLocked(e.old, primary, infrastructure)
	}
	if primary != nil {
		e.retireEntryV1()
		return TreeOperationV1{}, treeUnwindV1{}, e.store.abortReadLocked(e.old, primary, infrastructure)
	}
	return op, treeUnwindV1{}, nil
}

func (e *treePublicEntryV1) executeV1(account *OperationAccount, callback func(*Reader) (TreeOperationV1, error)) (CommitTruth, UpdateStage, int, treeUnwindV1, error) {
	truth, stage, index := CommitTruthOld, UpdateStagePrewrite, -1
	var unwind treeUnwindV1
	started := false
	err := account.withHold(func(hold *operationHold) error {
		started = true
		e.reader.getMu.Lock()
		e.hold = hold
		e.reader.entry = e
		e.reader.getMu.Unlock()
		var err error
		truth, stage, index, unwind, err = e.admittedV1(account, callback, nil)
		return err
	})
	if !started {
		// Closing between the public precheck and hold entry never suppresses
		// the original callback, its unwind or ordinary admission priority.
		return e.admittedV1(account, callback, err)
	}
	return truth, stage, index, unwind, err
}

// admittedV1 admits before cloning the Pair and rebinding ENTRY through native completion.
func (e *treePublicEntryV1) admittedV1(account *OperationAccount, callback func(*Reader) (TreeOperationV1, error), saved error) (CommitTruth, UpdateStage, int, treeUnwindV1, error) {
	op, unwind, err := e.callbackV1(callback)
	if err != nil || unwind.kind != 0 {
		return CommitTruthOld, UpdateStagePrewrite, -1, unwind, err
	}
	err = e.prewriteV1(account, op, saved)
	if err != nil {
		e.tip.retire()
		e.tip = nil
		e.retireEntryV1()
		return CommitTruthOld, UpdateStagePrewrite, -1, treeUnwindV1{}, e.prewriteAbortV1(err)
	}
	plan := treeOwnPlanV1(op)
	err = e.scopeCompileV1(op, &plan)
	if err != nil {
		e.retireEntryV1()
		return CommitTruthOld, UpdateStagePrewrite, -1, treeUnwindV1{}, e.prewriteAbortV1(err)
	}
	if e.inventory != nil {
		plan.inventory = e.inventory
		plan.inventory.ownV1(&plan)
	}
	err = e.replayAdmitV1(&plan)
	if err != nil {
		e.tip.retire()
		e.tip = nil
		e.retireEntryV1()
		return CommitTruthOld, UpdateStagePrewrite, -1, treeUnwindV1{}, e.prewriteAbortV1(err)
	}
	return e.store.updateTreeLockedV1(e.old, treeAccountLedgerV1{e.hold}, &plan)
}

// replayAdmitV1 binds the selected owned plan before charging and transferring its witness.
func (e *treePublicEntryV1) replayAdmitV1(plan *treePlanV1) error {
	if !plan.preserveReplay {
		return nil
	}
	if !treeReplayBoundedPlanV1(plan) {
		return updateInvalidBatch()
	}
	if e.tip == nil && treeReplayDeletesV1(plan) {
		return updateInvalidBatch()
	}
	err := canonicalTipAdmit(plan.pair, e.tip)
	if err != nil {
		return err
	}
	err = e.hold.grow(512)
	if err != nil {
		return err
	}
	plan.tip, e.tip = e.tip, nil
	return nil
}

// treeReplayDeletesV1 identifies the selected deletions requiring a callback endpoint.
func treeReplayDeletesV1(plan *treePlanV1) bool {
	if plan.primitives[0].Undo == UndoCompareDeleteV1 {
		return true
	}
	for _, m := range plan.pair {
		if m.dbi.Rank == 4 && m.after == AfterAbsent {
			return true
		}
	}
	return false
}

// prewriteV1 preserves ordinary/ENTRY/Proof/refusal priority before the owned-plan charge.
func (e *treePublicEntryV1) prewriteV1(account *OperationAccount, op TreeOperationV1, saved error) error {
	slotOver, admissionErr := e.admitScopedV1(op, account)
	if admissionErr != nil {
		return admissionErr
	}
	err := e.entryAdmitV1(&op, account)
	if err != nil {
		return err
	}
	if op.Proof != nil && !treeProofShapeV1(op.Primitives) {
		return updateInvalidBatch()
	}
	slotErr := treeHeaderSlotAdmitV1(op, slotOver)
	if slotErr != nil {
		return slotErr
	}
	err = e.contextQualifyV1(&op, saved)
	if err != nil {
		return err
	}
	// A zero-byte grow also preserves the post-callback open check.
	return e.hold.grow(treePrewriteBytesV1(op))
}

// treePrewriteBytesV1 is the one post-admission charge: for a physical scope its metadata
// envelope, which covers its plan copy; otherwise treeStepFiveBytesV1.
func treePrewriteBytesV1(op TreeOperationV1) uint64 {
	if treeScopePresentV1(&op.Pair) {
		return treeScopeBytesV1(&op.Pair)
	}
	return treeStepFiveBytesV1(op)
}

// treeScopeBytesV1 is the physical-scope metadata envelope: 4096 fixed bytes, the ordinary plan
// copy, 136 bytes per delete, 280 per witness, 64 per witness point, 33 per selector, and every
// delete key and witness key byte.
func treeScopeBytesV1(pair *TreePairV1) uint64 {
	d, w := uint64(len(pair.ObsoleteDeletes)), uint64(len(pair.ObsoleteConsulted))
	n := treePlanChargeAddV1(treePlanCopyBytesV1(*pair), 1, 4096)
	n = treePlanChargeAddV1(n, d, 128+8)
	n = treePlanChargeAddV1(n, w, 176+8+3*32)
	n = treePlanChargeAddV1(n, uint64(len(pair.LargeConsulted)), 33)
	for _, row := range pair.ObsoleteDeletes {
		n = treePlanChargeAddV1(n, uint64(len(row.span.key)), 1)
	}
	for _, token := range pair.ObsoleteConsulted {
		n = treeWitnessChargeV1(n, token.scope)
	}
	return n
}

// treeWitnessChargeV1 adds one witness's domain bound bytes and, per point, 64 bytes plus its key bytes.
func treeWitnessChargeV1(n uint64, witness *obsoleteWitness) uint64 {
	n = treePlanChargeAddV1(n, uint64(len(witness.domain.prefix)), 1)
	n = treePlanChargeAddV1(n, uint64(len(witness.domain.after)), 1)
	n = treePlanChargeAddV1(n, uint64(len(witness.domain.last)), 1)
	for _, point := range witness.points {
		n = treePlanChargeAddV1(n, 1, 32+32)
		n = treePlanChargeAddV1(n, uint64(len(point.key)), 1)
	}
	return n
}

// scopeCompileV1 compiles raw targets, then the owned large/raw scope, under the admitted metadata charge.
// The scope carries the engine-captured format-3 context of this Store's ORIGINAL OLD Reader.
func (e *treePublicEntryV1) scopeCompileV1(op TreeOperationV1, plan *treePlanV1) error {
	if !treeScopePresentV1(&op.Pair) {
		return nil
	}
	batch := Batch{Mutations: op.Pair.Mutations, ObsoleteDeletes: op.Pair.ObsoleteDeletes, ObsoleteConsulted: op.Pair.ObsoleteConsulted, LargeConsulted: op.Pair.LargeConsulted}
	err := treeScopeRowsV1(batch, e.reader, plan)
	if err != nil {
		return err
	}
	scope, err := updateOwnedLarge(batch, plan.consulted, e.reader.maxKey)
	if err != nil {
		return err
	}
	scope.databaseID, scope.config = e.reader.databaseID, e.reader.treeConfig
	plan.scope = &scope
	return nil
}

// treeScopeRowsV1: witness identity, coverage/duplicate/target overlap, Consulted disjointness, then caps.
func treeScopeRowsV1(batch Batch, reader *Reader, plan *treePlanV1) error {
	err := obsoleteWitnesses(batch, reader)
	if err != nil {
		return err
	}
	rows, err := obsoleteAdmitRows(batch, reader, plan.pair)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if obsoleteConsultedContains(plan.consulted, row.span.rank, row.span.key) {
			return updateInvalidBatch()
		}
	}
	plan.pair, err = obsoleteCompileRows(batch, rows, plan.pair)
	return err
}

// prewriteAbortV1 aborts OLD after a prewrite refusal; only a wrapped context qualification error is infrastructure.
func (e *treePublicEntryV1) prewriteAbortV1(err error) error {
	primary, infrastructure := contextTreeAbortV1(err)
	return e.store.abortReadLocked(e.old, primary, infrastructure)
}

// contextQualifyV1 runs the charge-free descriptor rows, then the refusal saved for an account closed before the
// hold, then charges the fixed 344-byte context reservation, scans index overlaps and qualifies at ORIGINAL OLD.
// With a nil window only the saved refusal remains, at its merged position.
func (e *treePublicEntryV1) contextQualifyV1(op *TreeOperationV1, saved error) error {
	err := contextTreeAdmitV1(&op.Pair)
	if err != nil {
		return err
	}
	window := op.Pair.ContextConsulted
	if saved != nil || window == nil {
		return saved
	}
	err = e.hold.grow(344)
	if err != nil {
		return err
	}
	err = contextTreeOverlapV1(&op.Pair, *window)
	if err != nil {
		return err
	}
	return contextTreeQualifyV1(e, &op.Pair, op.HeaderSlot, *window)
}

type treeAccountLedgerV1 struct{ hold *operationHold }

func (l treeAccountLedgerV1) chargeV1(n uint64) error { return l.hold.grow(n) }

func (l treeAccountLedgerV1) releaseV1(n uint64) { _ = l.hold.shrink(n) }

func treeAdmitV1(op TreeOperationV1, account *OperationAccount, databaseID [32]byte) error {
	_, err := treeAdmitSlotV1(op, account, databaseID, false)
	return err
}

// admitScopedV1 runs the ordinary admission rows, then the charge-free physical-scope shape,
// count and provenance rows on the post-callback path only.
func (e *treePublicEntryV1) admitScopedV1(op TreeOperationV1, account *OperationAccount) (bool, error) {
	over, err := treeAdmitSlotV1(op, account, e.store.databaseID, len(op.Pair.ObsoleteDeletes) != 0)
	if err != nil {
		return false, err
	}
	return over, treeScopeAdmitV1(op, account, e.reader)
}

// treeScopePresentV1 reports whether a physical-scope field selects the pair-only domain.
func treeScopePresentV1(pair *TreePairV1) bool {
	return len(pair.ObsoleteDeletes) != 0 || len(pair.ObsoleteConsulted) != 0 || len(pair.LargeConsulted) != 0
}

// treeScopeShapeV1 is the closed pair-only physical-scope shape.
func treeScopeShapeV1(op TreeOperationV1, account *OperationAccount) bool {
	if len(op.Primitives) != 0 || op.Proof != nil || op.HeaderSlot != nil {
		return false
	}
	p := &op.Pair
	if p.EntryInventory != nil || p.ContextConsulted != nil || p.PrepaidReadBytes != 0 || p.PreserveReplayObservations {
		return false
	}
	return account.shared.ceiling == LaneMaxBytes
}

// treeScopeAdmitV1 checks shape, then counts (Capacity), then raw provenance, without allocating.
func treeScopeAdmitV1(op TreeOperationV1, account *OperationAccount, reader *Reader) error {
	pair := &op.Pair
	if !treeScopePresentV1(pair) {
		return nil
	}
	if !treeScopeShapeV1(op, account) {
		return updateInvalidBatch()
	}
	if uint64(len(pair.ObsoleteDeletes))+uint64(len(pair.ObsoleteConsulted)) > maxUpdateMutations {
		return updateBoundError()
	}
	countErr := largeSelectorCounts(pair.LargeConsulted)
	if countErr != nil {
		return countErr
	}
	return treeScopeProvenanceV1(pair, reader)
}

// treeScopeProvenanceV1 requires every token from this operation's ORIGINAL OLD Reader.
func treeScopeProvenanceV1(pair *TreePairV1, reader *Reader) error {
	if !reader.updateOld {
		return updateInvalidBatch()
	}
	for _, token := range pair.ObsoleteConsulted {
		if token.scope == nil || token.scope.reader != reader {
			return updateInvalidBatch()
		}
	}
	for _, row := range pair.ObsoleteDeletes {
		if row.span == nil || row.span.reader != reader {
			return updateInvalidBatch()
		}
	}
	return nil
}

// treeEmptyOperationV1 is the nonempty-operation row; raw admits a raw-delete-only post-callback plan.
func treeEmptyOperationV1(op TreeOperationV1, raw bool) bool {
	return len(op.Primitives) == 0 && len(op.Pair.Mutations) == 0 && !raw
}

// treeAdmitSlotV1 is treeAdmitV1 (which passes raw=false) that also admits a Pair-mutation-free plan when raw
// reports raw deletes, and returns the verdict of its one Pair scan on whether op.HeaderSlot, as
// one more auxiliary mutation, exceeds a non-reverse Pair mutation cap; the verdict is false without a slot or on
// error. Only that verdict, never a budget, is held in the frames live during the scan (RUB-1750 resource_boundary).
func treeAdmitSlotV1(op TreeOperationV1, account *OperationAccount, databaseID [32]byte, raw bool) (bool, error) {
	if treeEmptyOperationV1(op, raw) {
		return false, updateInvalidBatch()
	}
	if len(op.Primitives) != 0 && account.shared.ceiling != TreeLaneMaxBytes {
		return false, updateInvalidBatch()
	}
	err := treePrimitivesAdmitV1(op, databaseID)
	if err != nil {
		return false, err
	}
	over, err := treePairScanV1(&op.Pair, op.HeaderSlot)
	if err != nil {
		return false, err
	}
	err = treePairRelationsV1(op)
	if err != nil {
		return false, err
	}
	return over, treePairPrepaidAdmitV1(op.Pair.PrepaidReadBytes, len(op.Primitives), account.shared.ceiling)
}

// treePairPrepaidAdmitV1 checks the trusted scalar only after ordinary Pair relations.
func treePairPrepaidAdmitV1(credit uint64, primitives int, ceiling uint64) error {
	if credit > ceiling || credit != 0 && primitives != 0 {
		return updateInvalidBatch()
	}
	return nil
}

func treeCoverageAdmitV1(op TreeOperationV1, p TreePrimitiveV1, databaseID [32]byte) bool {
	if (p.Coverage == nil) != (op.Primitives[0].Coverage == nil) {
		return false
	}
	if p.Coverage == nil {
		return true
	}
	c := p.Coverage
	return treeCoverageIdentityV1(c, p, databaseID) && c.HeaderBytes == 148 && treeCoverageMetaV1(c) && treeCoverageBodyV1(op.Pair, p)
}

func treeCoverageIdentityV1(c *TreeSourceCoverageV1, p TreePrimitiveV1, databaseID [32]byte) bool {
	return c.DatabaseID == databaseID && c.Generation == p.Generation && c.Block == p.Block && c.Height == p.Height
}

func treeCoverageMetaV1(c *TreeSourceCoverageV1) bool {
	if c.BlockMeta.TxCount == 0 {
		return false
	}
	return c.Height != 0 || c.BlockMeta.TxCount == 1 && c.BlockMeta.Generated == [16]byte{}
}

func treeCoverageBodyV1(pair TreePairV1, p TreePrimitiveV1) bool {
	c := p.Coverage
	for _, m := range pair.Mutations {
		if m.DBI.Rank != 4 || !bytes.Equal(m.Key, p.Block[:]) {
			continue
		}
		return treeCoveragePairBodyV1(m, c)
	}
	if c.BodyKind == 3 {
		return len(c.CurrentBody) != 0
	}
	return c.BodyKind == 2 && c.CurrentBody == nil
}

// treeCoveragePairBodyV1 admits only the literal/stored kinds beside a body target.
func treeCoveragePairBodyV1(m Mutation, c *TreeSourceCoverageV1) bool {
	if c.BodyKind == 2 {
		return c.CurrentBody == nil && m.AfterKind != AfterLiteral
	}
	return c.BodyKind == 1 && treeCoverageLiteralV1(m, c)
}

func treeCoverageLiteralV1(m Mutation, c *TreeSourceCoverageV1) bool {
	if len(c.CurrentBody) == 0 || len(m.Literal) != len(c.CurrentBody) {
		return false
	}
	return !m.BeforePresent && m.AfterKind == AfterLiteral && &m.Literal[0] == &c.CurrentBody[0]
}

func treePrimitivesAdmitV1(op TreeOperationV1, databaseID [32]byte) error {
	for j, p := range op.Primitives {
		if !treePrimitiveShapeV1(p, j) || !treeBlockDirectionsV1(op.Primitives[:j], p) {
			return updateInvalidBatch()
		}
		if !treeUndoAllowedV1(p) || !treeEndpointAllowedV1(p) {
			return updateInvalidBatch()
		}
		if !treeCoverageAdmitV1(op, p, databaseID) {
			return updateInvalidBatch()
		}
	}
	return nil
}

func treePrimitiveDomainV1(p TreePrimitiveV1) bool {
	if p.Direction < 1 || p.Direction > 2 || p.Kind < 1 || p.Kind > 9 {
		return false
	}
	return (p.Kind <= 6) == (p.Direction == TreeForwardV1)
}

func treePrimitiveShapeV1(p TreePrimitiveV1, j int) bool {
	if !treePrimitiveDomainV1(p) {
		return false
	}
	lag := p.Kind == TreeKindLagForwardV1 || p.Kind == TreeKindLagReverseV1
	return lag == (j != 0) && p.Source != nil && p.Generation != 0
}

func treeBlockDirectionsV1(previous []TreePrimitiveV1, p TreePrimitiveV1) bool {
	for _, q := range previous {
		if q.Block == p.Block && q.Direction != p.Direction {
			return false
		}
	}
	return true
}

func treeUndoAllowedV1(p TreePrimitiveV1) bool {
	if p.Undo < 1 || p.Undo > 6 {
		return false
	}
	// Bit n admits Undo value n, indexed by the already-admitted Kind.
	return [10]uint8{0, 6, 2, 30, 2, 8, 6, 32, 96, 96}[p.Kind]&(1<<p.Undo) != 0
}

func treeEndpointAllowedV1(p TreePrimitiveV1) bool {
	if !validTreeEndpoint(p.Endpoint) {
		return false
	}
	if p.Direction == TreeForwardV1 {
		return p.Endpoint.Kind == TreeEndpointAppliedV1 && p.Endpoint.Height == p.Height && p.Endpoint.BlockHash == p.Block
	}
	if p.Height == 0 {
		return p.Endpoint.Kind == TreeEndpointPreGenesisV1
	}
	return p.Endpoint.Kind == TreeEndpointAppliedV1 && p.Endpoint.Height == p.Height-1
}

func treePairScanV1(pair *TreePairV1, slot *TreeHeaderSlotV1) (bool, error) {
	var budget updateBudget
	var previous Mutation
	for j, m := range pair.Mutations {
		err := treeMutationScanV1(j == 0, previous, m, &budget)
		if err != nil {
			return false, err
		}
		previous = m
	}
	var count uint64
	var prior ConsultedRow
	for j, row := range pair.Consulted {
		err := treeConsultedScanV1(j == 0, prior, row, &count)
		if err != nil {
			return false, err
		}
		prior = row
	}
	return treeHeaderSlotOverV1(budget, slot), nil
}

// treeHeaderSlotOverV1 reports whether slot, added as one more auxiliary 32-byte-key 148-byte-literal mutation to
// the budget of the scanned Pair, exceeds a mutation cap; false without a slot.
func treeHeaderSlotOverV1(budget updateBudget, slot *TreeHeaderSlotV1) bool {
	if slot == nil {
		return false
	}
	return !budget.addMutation(Mutation{DBI: schemaDBIs[3], Key: slot.Hash[:], AfterKind: AfterLiteral, Literal: slot.Header[:]})
}

func treePairIdentityV1(dbi DBI, key []byte) bool {
	return TreeValidateDBI(dbi) == nil && dbi.Rank <= 7 && treeValidKey(dbi.Rank, key)
}

func treePairPayloadV1(m Mutation) bool {
	if m.DBI.Rank == 0 && !treePairMetaV1(m.Key, m.AfterKind) {
		return false
	}
	switch m.AfterKind {
	case AfterAbsent:
		return updateAbsentPayload(m)
	case AfterLiteral:
		return updateLiteralPayload(m)
	default:
		return false
	}
}

func treePairMetaV1(key []byte, after AfterKind) bool {
	switch key[0] {
	case 2:
		return after == AfterLiteral
	case 0x10, 0x11:
		return true
	default:
		return false
	}
}

func treeMutationScanV1(first bool, previous, m Mutation, budget *updateBudget) error {
	if !treePairIdentityV1(m.DBI, m.Key) || !treePairPayloadV1(m) {
		return updateInvalidBatch()
	}
	if !first && !updateOrdered(previous, m) {
		return updateInvalidBatch()
	}
	if m.AfterKind == AfterLiteral && ValidateTreeRow(m.DBI, m.Key, m.Literal) != nil {
		return updateInvalidBatch()
	}
	if !budget.addMutation(m) {
		return updateBoundError()
	}
	return nil
}

func treeConsultedScanV1(first bool, previous, row ConsultedRow, count *uint64) error {
	if !treePairIdentityV1(row.DBI, row.Key) {
		return updateInvalidBatch()
	}
	if !first && !updateKeyOrdered(previous.DBI.Rank, previous.Key, row.DBI.Rank, row.Key) {
		return updateInvalidBatch()
	}
	var ok bool
	if *count, ok = updateAdd(*count, 1, maxUpdateConsulted); !ok {
		return updateBoundError()
	}
	return nil
}

func treePairRelationsV1(op TreeOperationV1) error {
	for _, m := range op.Pair.Mutations {
		if treePairOwnedV1(op.Primitives, m.DBI, m.Key, true) || updateConsultedContains(op.Pair.Consulted, m.DBI, m.Key) {
			return updateInvalidBatch()
		}
	}
	for _, row := range op.Pair.Consulted {
		if treePairOwnedV1(op.Primitives, row.DBI, row.Key, false) {
			return updateInvalidBatch()
		}
	}
	return nil
}

func treePairOwnedV1(primitives []TreePrimitiveV1, dbi DBI, key []byte, mutation bool) bool {
	switch dbi.Rank {
	case 0:
		return treePairMetaOwnedV1(primitives, key)
	case 1:
		return mutation && len(primitives) != 0 && primitives[0].Coverage != nil
	case 5:
		for _, p := range primitives {
			if bytes.HasPrefix(key, p.Block[:]) {
				return true
			}
		}
	}
	return false
}

func treePairMetaOwnedV1(primitives []TreePrimitiveV1, key []byte) bool {
	if len(key) != 9 {
		return false
	}
	if key[0] == 0x11 {
		return treePairGenerationOwnedV1(primitives, binary.BigEndian.Uint64(key[1:]))
	}
	if key[0] != 0x10 || len(primitives) == 0 {
		return false
	}
	return primitives[0].Coverage != nil && treePairGenerationOwnedV1(primitives, binary.BigEndian.Uint64(key[1:]))
}

func treePairGenerationOwnedV1(primitives []TreePrimitiveV1, generation uint64) bool {
	for _, p := range primitives {
		if generation == p.Generation {
			return true
		}
	}
	return false
}

func treePlanChargeAddV1(total, count, size uint64) uint64 {
	if total > TreeLaneMaxBytes || count > (TreeLaneMaxBytes-total)/size {
		return TreeLaneMaxBytes + 1
	}
	return total + count*size
}

// treeProofShapeV1 is the Proof admission row: a non-empty covered plan whose
// LAG primitives share one generation distinct from CURRENT.
func treeProofShapeV1(primitives []TreePrimitiveV1) bool {
	if len(primitives) == 0 {
		return false
	}
	for j, p := range primitives {
		if p.Coverage == nil || j != 0 && !treeProofLagV1(primitives, p) {
			return false
		}
	}
	return true
}

func treeProofLagV1(primitives []TreePrimitiveV1, p TreePrimitiveV1) bool {
	return p.Generation == primitives[1].Generation && p.Generation != primitives[0].Generation
}

// treeHeaderSlotAdmitV1 is the header-slot admission row; its first failing
// check wins: Proof nil, representation, Pair overlap, then caps.
// over is the Pair scan's mutation-cap verdict for the slot; the Consulted cap is counted here.
func treeHeaderSlotAdmitV1(op TreeOperationV1, over bool) error {
	slot := op.HeaderSlot
	if slot == nil {
		return nil
	}
	if op.Proof == nil || ValidateTreeRow(schemaDBIs[3], slot.Hash[:], slot.Header[:]) != nil || treeHeaderSlotOverlapV1(op.Pair, slot.Hash[:]) {
		return updateInvalidBatch()
	}
	if over || uint64(len(op.Pair.Consulted)) >= maxUpdateConsulted {
		return updateBoundError()
	}
	return nil
}

// treeHeaderSlotOverlapV1 binary-searches the admitted, strictly (rank, key) ordered Mutations and Consulted rows.
func treeHeaderSlotOverlapV1(pair TreePairV1, hash []byte) bool {
	k := treeRowKeyV1{rank: 3, key: hash}
	_, inPair := slices.BinarySearchFunc(pair.Mutations, k, treeMutationCmpV1)
	_, inConsulted := slices.BinarySearchFunc(pair.Consulted, k, treeConsultedRowCmpV1)
	return inPair || inConsulted
}

// treeRowKeyV1 is one (rank, key) search target over (rank, key) ordered rows.
type treeRowKeyV1 struct {
	rank uint8
	key  []byte
}

func treeRowCmpV1(rank uint8, key []byte, k treeRowKeyV1) int {
	if rank != k.rank {
		return int(rank) - int(k.rank)
	}
	return bytes.Compare(key, k.key)
}

func treeMutationCmpV1(m Mutation, k treeRowKeyV1) int { return treeRowCmpV1(m.DBI.Rank, m.Key, k) }

func treeConsultedRowCmpV1(row ConsultedRow, k treeRowKeyV1) int {
	return treeRowCmpV1(row.DBI.Rank, row.Key, k)
}

// treeHeaderSlotCopyBytesV1 is the step-5 charge of the slot: one owned
// mutation with its key and literal and one owned Consulted row with its key.
var treeHeaderSlotCopyBytesV1 = uint64(reflect.TypeFor[ownedMutation]().Size()+reflect.TypeFor[ownedConsulted]().Size()) + 32 + 148 + 32

// Actual report backing sizes, pinned by TestTreeStreamResourceLayoutV1.
var (
	treeReportBytesV1     = uint64(reflect.TypeFor[TreeDeltaReportV1]().Size())
	treeUndoRecordBytesV1 = uint64(reflect.TypeFor[TreeUndoChargeV1]().Size())
)

// treeStepFiveBytesV1 is the single step-5 charge: the plan copy, plus with a
// HeaderSlot its owned mutation and Consulted row, plus with a Proof the report
// and its per-primitive undo records.
func treeStepFiveBytesV1(op TreeOperationV1) uint64 {
	n := treePlanCopyBytesV1(op.Pair)
	if op.HeaderSlot != nil {
		n = treePlanChargeAddV1(n, 1, treeHeaderSlotCopyBytesV1)
	}
	if op.Proof == nil {
		return n
	}
	n = treePlanChargeAddV1(n, 1, treeReportBytesV1)
	return treePlanChargeAddV1(n, uint64(len(op.Primitives)), treeUndoRecordBytesV1)
}

func treePlanCopyBytesV1(pair TreePairV1) uint64 {
	n := treePlanChargeAddV1(0, uint64(len(pair.Mutations)), uint64(unsafe.Sizeof(ownedMutation{})))
	n = treePlanChargeAddV1(n, uint64(len(pair.Consulted)), uint64(unsafe.Sizeof(ownedConsulted{})))
	for _, m := range pair.Mutations {
		n = treePlanChargeAddV1(n, uint64(len(m.Key)), 1)
		n = treePlanChargeAddV1(n, uint64(len(m.Literal)), 1)
	}
	for _, row := range pair.Consulted {
		n = treePlanChargeAddV1(n, uint64(len(row.Key)), 1)
	}
	return n
}

func treeOwnPlanV1(op TreeOperationV1) treePlanV1 {
	extra := treeHeaderSlotRowsV1(op.HeaderSlot)
	plan := treePlanV1{primitives: op.Primitives, slot: treeOwnHeaderSlotV1(op.HeaderSlot), prepaidReadBytes: op.Pair.PrepaidReadBytes, preserveReplay: op.Pair.PreserveReplayObservations}
	plan.pair = make([]ownedMutation, len(op.Pair.Mutations), len(op.Pair.Mutations)+extra+len(op.Pair.ObsoleteDeletes))
	plan.consulted = make([]ownedConsulted, len(op.Pair.Consulted), len(op.Pair.Consulted)+extra)
	for j, m := range op.Pair.Mutations {
		plan.pair[j] = ownedMutation{m.DBI, updateClone(m.Key), m.BeforePresent, m.AfterKind, updateClone(m.Literal), m.RefDBI, updateClone(m.RefKey)}
	}
	for j, row := range op.Pair.Consulted {
		plan.consulted[j] = ownedConsulted{dbi: row.DBI, key: updateClone(row.Key)}
	}
	if op.Pair.ContextConsulted != nil {
		plan.context = *op.Pair.ContextConsulted
	}
	if op.Proof != nil {
		plan.proof, plan.report = op.Proof, &TreeDeltaReportV1{Undo: make([]TreeUndoChargeV1, len(op.Primitives))}
	}
	return plan
}

// treeBoundedPlanV1 recognizes the admitted ordinary and replay owned shapes.
// It grants no caller capability and every other legal shape keeps P fallback.
func treeBoundedPlanV1(plan *treePlanV1) bool {
	if treeReplayBoundedPlanV1(plan) {
		return true
	}
	if len(plan.primitives) != 1 || !treeBoundedAuxV1(plan) {
		return false
	}
	p := &plan.primitives[0]
	if !treeBoundedPrimitiveV1(p) {
		return false
	}
	var domains uint8
	for i := range plan.pair {
		domain := treeBoundedPairV1(&plan.pair[i], p)
		if domain == 0 || domains&domain != 0 {
			return false
		}
		domains |= domain
	}
	return domains|8 == 15
}

// treeReplayBoundedPlanV1 selects only the admitted same-block replay roles.
func treeReplayBoundedPlanV1(plan *treePlanV1) bool {
	if len(plan.primitives) < 1 || len(plan.primitives) > 2 {
		return false
	}
	if !treeReplayAuxV1(plan) {
		return false
	}
	p := &plan.primitives[0]
	if !treeReplayPrimitiveV1(p, false) {
		return false
	}
	if len(plan.primitives) == 2 && !treeReplaySiblingV1(p, &plan.primitives[1]) {
		return false
	}
	return treeReplayConsultedV1(plan, p) && treeReplayPairsV1(plan)
}

// treeReplayAuxV1 excludes the separate hook, inventory and credit owners.
func treeReplayAuxV1(plan *treePlanV1) bool {
	return plan.proof == nil && plan.slot == nil && plan.inventory == nil && plan.prepaidReadBytes == 0
}

// treeReplayConsultedV1 keeps the finite metadata/UTXO/index/header/body/owner domain.
func treeReplayConsultedV1(plan *treePlanV1, p *TreePrimitiveV1) bool {
	for _, row := range plan.consulted {
		if !treeReplayConsultedRowV1(row, p.Block) {
			return false
		}
	}
	return true
}

func treeReplayConsultedRowV1(row ownedConsulted, block [32]byte) bool {
	switch row.dbi.Rank {
	case 0, 1, 2, 3, 7:
		return true
	case 4:
		return bytes.Equal(row.key, block[:])
	}
	return false
}

// treeReplayPrimitiveV1 preserves the closed kind/undo/body discriminator set.
func treeReplayPrimitiveV1(p *TreePrimitiveV1, lag bool) bool {
	if p.Direction != TreeForwardV1 || p.Coverage == nil || p.Coverage.HeaderBytes != 148 {
		return false
	}
	c := p.Coverage
	if !treeReplayCoverageV1(c, *p) {
		return false
	}
	return treeReplayRoleV1(p, lag)
}

// treeReplayRoleV1 owns the selected CURRENT/LAG kind and undo pairing.
func treeReplayRoleV1(p *TreePrimitiveV1, lag bool) bool {
	if lag {
		return p.Kind == TreeKindLagForwardV1 && p.Undo == UndoTransientV1
	}
	return p.Kind == TreeKindReplayNextV1 && p.Undo >= UndoWriteOrReuseV1 && p.Undo <= UndoCompareDeleteV1
}

// treeReplayCoverageV1 binds every admitted coverage field before selection.
func treeReplayCoverageV1(c *TreeSourceCoverageV1, p TreePrimitiveV1) bool {
	if !treeCoverageIdentityV1(c, p, c.DatabaseID) || !treeCoverageMetaV1(c) {
		return false
	}
	switch c.BodyKind {
	case 1, 3:
		return len(c.CurrentBody) != 0
	case 2:
		return c.CurrentBody == nil
	}
	return false
}

// treeReplaySiblingV1 requires identity of the immutable caller body backing.
func treeReplaySiblingV1(p, lag *TreePrimitiveV1) bool {
	if !treeReplayPrimitiveV1(lag, true) || lag.Generation == p.Generation {
		return false
	}
	a, b := p.Coverage, lag.Coverage
	if !treeReplayIdentityV1(p, lag) || len(a.CurrentBody) != len(b.CurrentBody) {
		return false
	}
	return a.BodyKind == 2 || &a.CurrentBody[0] == &b.CurrentBody[0]
}

// treeReplayIdentityV1 binds the independent role and complete-source fields.
func treeReplayIdentityV1(p, lag *TreePrimitiveV1) bool {
	a, b := p.Coverage, lag.Coverage
	return p.Block == lag.Block && p.Height == lag.Height && p.Endpoint == lag.Endpoint &&
		a.DatabaseID == b.DatabaseID && a.BodyKind == b.BodyKind && a.BlockMeta == b.BlockMeta
}

// treeReplayPairsV1 counts only role-owned index/owner and shared auxiliary rows.
func treeReplayPairsV1(plan *treePlanV1) bool {
	var domains [2]uint8
	var shared uint8
	for i := range plan.pair {
		if !treeReplayPairRowV1(plan, &plan.pair[i], &domains, &shared) {
			return false
		}
	}
	for j := range plan.primitives {
		if domains[j] != 3 {
			return false
		}
	}
	return plan.primitives[0].Coverage.BodyKind != 1 || shared&4 != 0
}

// treeReplayPairRowV1 assigns one admitted row to exactly one role/shared slot.
func treeReplayPairRowV1(plan *treePlanV1, m *ownedMutation, domains *[2]uint8, shared *uint8) bool {
	if m.dbi.Rank == 2 || m.dbi.Rank == 7 {
		return treeReplayRolePairV1(plan, m, domains)
	}
	domain := treeReplayAuxPairV1(m, &plan.primitives[0])
	if domain == 0 || *shared&domain != 0 {
		return false
	}
	*shared |= domain
	return true
}

// treeReplayRolePairV1 binds an index/owner to its one matching generation.
func treeReplayRolePairV1(plan *treePlanV1, m *ownedMutation, domains *[2]uint8) bool {
	for j := range plan.primitives {
		domain := treeBoundedPairV1(m, &plan.primitives[j])
		if domain != 0 && domains[j]&domain == 0 {
			domains[j] |= domain
			return true
		}
	}
	return false
}

// treeReplayAuxPairV1 admits only the shared body/header and authority envelope.
func treeReplayAuxPairV1(m *ownedMutation, p *TreePrimitiveV1) uint8 {
	switch m.dbi.Rank {
	case 0:
		if bytes.Equal(m.key, []byte{2}) && m.after == AfterLiteral {
			return 16
		}
	case 3:
		if m.after == AfterLiteral {
			return treeBoundedHeaderV1(m, p)
		}
	case 4:
		return treeReplayBodyPairV1(m, p)
	}
	return 0
}

// treeReplayBodyPairV1 preserves the absent-literal/stored-delete payload law.
func treeReplayBodyPairV1(m *ownedMutation, p *TreePrimitiveV1) uint8 {
	if !bytes.Equal(m.key, p.Block[:]) {
		return 0
	}
	switch p.Coverage.BodyKind {
	case 1:
		if m.after == AfterLiteral && !m.beforePresent {
			return treeBoundedBodyV1(m, p)
		}
	case 2:
		if m.after == AfterAbsent && m.beforePresent {
			return 4
		}
	}
	return 0
}

// treeBoundedAuxV1 excludes every auxiliary ownership domain from streaming.
func treeBoundedAuxV1(plan *treePlanV1) bool {
	return plan.proof == nil && plan.slot == nil && plan.inventory == nil &&
		plan.context.Count == 0 && len(plan.consulted) == 0 && plan.prepaidReadBytes == 0
}

// treeBoundedPrimitiveV1 preserves the fixed forward/direct/transient profile.
func treeBoundedPrimitiveV1(p *TreePrimitiveV1) bool {
	c := p.Coverage
	return p.Direction == TreeForwardV1 && p.Kind == TreeKindDirectApplyV1 && p.Undo == UndoTransientV1 &&
		c != nil && c.HeaderBytes == 148 && c.BodyKind == 1
}

// treeBoundedPairV1 identifies the disjoint generation/block/height-bound rows.
func treeBoundedPairV1(m *ownedMutation, p *TreePrimitiveV1) uint8 {
	if m.after != AfterLiteral {
		return 0
	}
	switch m.dbi.Rank {
	case 2:
		return treeBoundedIndexV1(m, p)
	case 7:
		return treeBoundedOwnerV1(m, p)
	case 4:
		return treeBoundedBodyV1(m, p)
	case 3:
		return treeBoundedHeaderV1(m, p)
	}
	return 0
}

// treeBoundedBodyV1 recognizes the already-admitted owned BodyKind1 clone.
func treeBoundedBodyV1(m *ownedMutation, p *TreePrimitiveV1) uint8 {
	if bytes.Equal(m.key, p.Block[:]) && len(m.literal) == len(p.Coverage.CurrentBody) {
		return 4
	}
	return 0
}

// treeBoundedHeaderV1 recognizes only the optional expected-absent header.
func treeBoundedHeaderV1(m *ownedMutation, p *TreePrimitiveV1) uint8 {
	if !m.beforePresent && bytes.Equal(m.key, p.Block[:]) && len(m.literal) == 148 {
		return 8
	}
	return 0
}

// treeBoundedIndexV1 checks the canonical index without changing admission.
func treeBoundedIndexV1(m *ownedMutation, p *TreePrimitiveV1) uint8 {
	if len(m.key) != 16 || len(m.literal) != 104 {
		return 0
	}
	bound := binary.BigEndian.Uint64(m.key) == p.Generation && binary.BigEndian.Uint64(m.key[8:]) == p.Height
	if bound && bytes.Equal(m.literal[:32], p.Block[:]) && bytes.Equal(m.literal[64:], p.Endpoint.CumulativeChainwork[:]) {
		return 1
	}
	return 0
}

// treeBoundedOwnerV1 checks the matching canonical owner and height literal.
func treeBoundedOwnerV1(m *ownedMutation, p *TreePrimitiveV1) uint8 {
	if len(m.key) != 40 || len(m.literal) != 8 {
		return 0
	}
	bound := binary.BigEndian.Uint64(m.key) == p.Generation && bytes.Equal(m.key[8:], p.Block[:])
	if bound && binary.BigEndian.Uint64(m.literal) == p.Height {
		return 2
	}
	return 0
}

// treeHeaderSlotRowsV1 is the spare owned Pair and Consulted capacity of a slot.
func treeHeaderSlotRowsV1(slot *TreeHeaderSlotV1) int {
	if slot == nil {
		return 0
	}
	return 1
}

// treeOwnHeaderSlotV1 copies the slot as Hash||Header; nil without a slot.
func treeOwnHeaderSlotV1(slot *TreeHeaderSlotV1) []byte {
	if slot == nil {
		return nil
	}
	owned := make([]byte, 0, 180)
	owned = append(owned, slot.Hash[:]...)
	return append(owned, slot.Header[:]...)
}
