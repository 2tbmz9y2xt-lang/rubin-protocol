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
	"unsafe"
)

// TreePairV1 contains ordinary non-tree targets and unchanged consulted rows.
// Rows must be strictly (rank, key) ordered in each slice and disjoint. Rank 8
// is never a Pair row. AfterOldValueRef is forbidden. The operation owns copies
// after admission. Pair slices, records and Key/Literal bytes remain immutable
// through the first Source call, or operation completion if no Source is reached.
type TreePairV1 struct {
	Mutations []Mutation
	Consulted []ConsultedRow
	// EntryInventory accepts the completed token for this same entry, account and Pair.
	EntryInventory *EntryInventoryV1
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
// with no write, consumes the Store with terminal E and releases the account
// charges once. A Proof panic or Goexit takes the writer-position unwind with
// index -1; a clean unwind leaves the Store OPEN, then the panic or Goexit
// resumes. A nil result continues to flush, final checks and commit unchanged.
// Proof must not call any Store, Reader or OperationAccount method,
// must not retain the report, and must start no goroutine that outlives the call.
type TreeOperationV1 struct {
	Primitives []TreePrimitiveV1
	Pair       TreePairV1
	Proof      func(*TreeDeltaReportV1) error
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
// on successful cleanup. One primitive requires TreeOperation; pair-only plans
// also admit LaneOperation and need at least one target. Rank 8 and references
// are forbidden in Pairs, as are primitive-owned undo families and generation
// root bindings. Meta keys 0, 1, 3 and 0x12 are immutable targets; 2 is literal-only,
// 0x10 and 0x11 allow literal/delete, and all valid meta keys may be consulted.
// Non-reverse Pair caps are 2,391,106 mutations, 137,676,154 key bytes,
// 155,659,727 literal bytes, 414,634 UTXO deletes, 1,545,454 UTXO literals,
// 16,384 other mutations and 16,384 consulted rows. Mutation shape/order/value
// precede that row's cap; consulted shape/order precede its count. Caps precede
// every own-family, generation-root and consulted/target overlap check.
//
// One account hold charges complete owned Pair arrays and key/literal copies
// before allocating or cloning, then serves
// every engine charge exactly. It is released before result, panic or Goexit
// delivery. Capacity/input errors retain identity. The composer chooses account
// kind; hash-global absent rows become expected-absent targets, identical rows
// become Consulted, and differing rows must be classified before returning the
// plan. The engine performs no hash-global classification.
// Pair inputs remain immutable through the first Source call (or completion if
// none); primitive backing and Source bindings remain immutable through completion
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
	if !s.operations.TryLock() {
		return CommitTruthOld, UpdateStagePrewrite, -1, adapterError(operationUpdate, EngineConcurrency, codeBusy, "store operation in progress", nil)
	}
	var unwind treeUnwindV1
	defer func() { unwind.resumeV1() }()
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
	e.reader.expire().retire()
	e.expireEntryV1()
	primary, infrastructure := readPrimary(err, e.reader.failure)
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
		e.retireEntryV1()
		return CommitTruthOld, UpdateStagePrewrite, -1, treeUnwindV1{}, e.store.abortReadLocked(e.old, err, false)
	}
	plan := treeOwnPlanV1(op)
	if e.inventory != nil {
		plan.inventory = e.inventory
		plan.inventory.ownV1(&plan)
	}
	return e.store.updateTreeLockedV1(e.old, treeAccountLedgerV1{e.hold}, &plan)
}

// prewriteV1 preserves ordinary/ENTRY/Proof/refusal priority before the owned-plan charge.
func (e *treePublicEntryV1) prewriteV1(account *OperationAccount, op TreeOperationV1, saved error) error {
	admissionErr := treeAdmitV1(op, account, e.store.databaseID)
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
	if saved != nil {
		return saved
	}
	// A zero-byte grow also preserves the post-callback open check.
	return e.hold.grow(treeStepFiveBytesV1(op))
}

type treeAccountLedgerV1 struct{ hold *operationHold }

func (l treeAccountLedgerV1) chargeV1(n uint64) error { return l.hold.grow(n) }

func (l treeAccountLedgerV1) releaseV1(n uint64) { _ = l.hold.shrink(n) }

func treeAdmitV1(op TreeOperationV1, account *OperationAccount, databaseID [32]byte) error {
	if len(op.Primitives) == 0 && len(op.Pair.Mutations) == 0 {
		return updateInvalidBatch()
	}
	if len(op.Primitives) != 0 && account.shared.ceiling != TreeLaneMaxBytes {
		return updateInvalidBatch()
	}
	err := treePrimitivesAdmitV1(op, databaseID)
	if err != nil {
		return err
	}
	err = treePairScanV1(op.Pair)
	if err != nil {
		return err
	}
	return treePairRelationsV1(op)
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
		if c.BodyKind == 2 {
			return c.CurrentBody == nil && m.AfterKind != AfterLiteral
		}
		return c.BodyKind == 1 && treeCoverageLiteralV1(m, c)
	}
	return c.BodyKind == 2 && c.CurrentBody == nil
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

func treePairScanV1(pair TreePairV1) error {
	var budget updateBudget
	var previous Mutation
	for j, m := range pair.Mutations {
		err := treeMutationScanV1(j == 0, previous, m, &budget)
		if err != nil {
			return err
		}
		previous = m
	}
	var count uint64
	var prior ConsultedRow
	for j, row := range pair.Consulted {
		err := treeConsultedScanV1(j == 0, prior, row, &count)
		if err != nil {
			return err
		}
		prior = row
	}
	return nil
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

// Actual report backing sizes, pinned by TestTreeStreamResourceLayoutV1.
var (
	treeReportBytesV1     = uint64(reflect.TypeFor[TreeDeltaReportV1]().Size())
	treeUndoRecordBytesV1 = uint64(reflect.TypeFor[TreeUndoChargeV1]().Size())
)

// treeStepFiveBytesV1 is the single step-5 charge: the plan copy plus, with a
// Proof, the report and its per-primitive undo records.
func treeStepFiveBytesV1(op TreeOperationV1) uint64 {
	n := treePlanCopyBytesV1(op.Pair)
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
	plan := treePlanV1{primitives: op.Primitives, pair: make([]ownedMutation, len(op.Pair.Mutations)), consulted: make([]ownedConsulted, len(op.Pair.Consulted))}
	for j, m := range op.Pair.Mutations {
		plan.pair[j] = ownedMutation{m.DBI, updateClone(m.Key), m.BeforePresent, m.AfterKind, updateClone(m.Literal), m.RefDBI, updateClone(m.RefKey)}
	}
	for j, row := range op.Pair.Consulted {
		plan.consulted[j] = ownedConsulted{dbi: row.DBI, key: updateClone(row.Key)}
	}
	if op.Proof != nil {
		plan.proof, plan.report = op.Proof, &TreeDeltaReportV1{Undo: make([]TreeUndoChargeV1, len(op.Primitives))}
	}
	return plan
}
