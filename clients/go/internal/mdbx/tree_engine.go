package mdbx

// ---- tree_engine.go (owner L3; untagged; used by L1, L2, L5a) ----
// treePositionV1 is the engine-internal emitter position. L5b maps TreeWriterV1/TreeReadbackV1 onto it.
type treePositionV1 uint8

const (
	treeWriterV1   treePositionV1 = 1
	treeReadbackV1 treePositionV1 = 2
)

// Exact charge constants (D6-6, D5-3, D12-E, D13-14). S_r applies only when the plan has at least one primitive (D9-4).
const (
	treeWindowBytesV1   uint64 = 65536  // W: the LargeImageRowV1.ReadAt dst cap
	treeFixedBytesV1    uint64 = 4096   // F_fixed: provider fixed-state allowance (RUB-1612 P0 bound)
	treeValueBytesV1    uint64 = 65560  // V: MAX_STATE_ENTRY_BYTES - 36, the leaf value scratch
	treeScratchBytesV1  uint64 = 131192 // S_r: 2 * MAX_STATE_ENTRY_BYTES, the two readback scratches
	treeNodeWorkBytesV1 uint64 = 147968 // L2 per-call working memory: 289 frames * 512 bytes
)

// Primitive encodings (D13-7): 0 is invalid. Kinds 1-6 are forward, 7-9 inverse (MEMPOOL L2984-2989).
const (
	treeForwardV1 uint8 = 1
	treeInverseV1 uint8 = 2
)

const (
	treeKindDirectApplyV1  uint8 = 1
	treeKindConnectV1      uint8 = 2
	treeKindReplayNextV1   uint8 = 3
	treeKindFirstGenesisV1 uint8 = 4
	treeKindRestoreOldV1   uint8 = 5
	treeKindLagForwardV1   uint8 = 6
	treeKindDisconnectV1   uint8 = 7
	treeKindRollbackNewV1  uint8 = 8
	treeKindLagReverseV1   uint8 = 9
)

// treeImageV1 is one row image. An image served from the ORIGINAL OLD txn stays valid until that txn ends (it stays
// open through write, commit and readback, D2-2). An image served from a P entry stays valid until that section's
// finalV1 or abortV1 or the end of that readback; no emitV1 or referV1, of its own or another identity, moves or
// overwrites its bytes (replacing a P entry leaves the replaced bytes unchanged), and the image may be passed as
// after.value to emitV1 of another identity (D20, D24).
type treeImageV1 struct {
	present bool
	value   []byte
}

// treePrimitiveV1 is the engine view of one admitted primitive. L5a's plan embeds it.
// endpoint is the generation's endpoint after this primitive (forward: Applied(height, block, chainwork);
// reverse: the parent endpoint, PreGenesis at height 0); L5b admits it (D12-H).
type treePrimitiveV1 struct {
	direction, kind, undo uint8
	generation, height    uint64
	block                 [32]byte
	endpoint              TreeEndpointV1
}

// treeBodyV1 is primitive j's body binding (D6-5, D14-4). pair = true iff the Pair holds a mutation of blocks-v1[Block]:
// bytes = that Pair literal, or for a Pair delete the ORIGINAL OLD row from treeStoredBodyV1; the row is a Pair target and
// is never referred. pair = false: the ORIGINAL OLD blocks-v1 row from treeStoredBodyV1, referred by applyV1.
type treeBodyV1 struct {
	bytes []byte
	pair  bool
}

// treeLedgerV1 is the engine view of the operation account (F1 (c), D2-7, D5, D6-6).
// chargeV1 reserves n bytes before the allocation or copy it covers. On refusal it returns the account error
// unchanged (errOperationReservationCapacity by identity, or errOperationReservationInput) and charges nothing.
// releaseV1 returns n bytes that chargeV1 charged earlier; every charged byte is released exactly once.
// No chargeV1 call on the account is made after mdbx_txn_commit (D5-1). Implementations: L5b's adapter,
// treeBudgetV1.ledgerV1, and the test ledgers.
type treeLedgerV1 interface {
	chargeV1(n uint64) error
	releaseV1(n uint64)
}

// treeBudgetV1 is engine-local sub-accounting inside bytes the ledger already holds (D5-1/D5-2, D6-6 E3).
// drawV1 reports false (no ledger call) when used+n would exceed held; that is the D5-5 structural stop.
// returnV1 with n > used is an engine defect handled fail-closed: used = 0 and held = 0, so every later drawV1 is false.
// ledgerV1 is the readback-position ledger view: chargeV1 = drawV1 or errOperationReservationCapacity; releaseV1 = returnV1.
type treeBudgetV1 struct{ held, used uint64 }

func (b *treeBudgetV1) drawV1(n uint64) bool {
	if b.used > b.held || n > b.held-b.used {
		return false
	}
	b.used += n
	return true
}

func (b *treeBudgetV1) returnV1(n uint64) {
	if n > b.used {
		b.held, b.used = 0, 0
		return
	}
	b.used -= n
}

func (b *treeBudgetV1) ledgerV1() treeLedgerV1 { return treeBudgetLedgerV1{b} }

// treeBudgetLedgerV1 is the treeLedgerV1 view of one treeBudgetV1; it never reaches the operation account.
type treeBudgetLedgerV1 struct{ budget *treeBudgetV1 }

func (l treeBudgetLedgerV1) chargeV1(n uint64) error {
	if !l.budget.drawV1(n) {
		return errOperationReservationCapacity
	}
	return nil
}

func (l treeBudgetLedgerV1) releaseV1(n uint64) { l.budget.returnV1(n) }

// treeOldV1 reads primitive j's protected logical OLD at the current position (D2-2): P_x overlay, then ORIGINAL OLD.
// A reference entry in P passes through to ORIGINAL OLD. In checked mode (writer steps 4-5) every access also reads
// the write txn at the same identity (getV1) or range (nextV1); a difference returns the existing EngineStateMismatch
// "OLD/write snapshot mismatch" (D3 S). nextV1 returns the first present identity with key >= from in dbi; absent markers are skipped.
type treeOldV1 interface {
	getV1(dbi DBI, key []byte) (treeImageV1, error)
	nextV1(dbi DBI, from []byte) (key []byte, image treeImageV1, ok bool, err error)
}

// treeTargetV1 is one planned final target of primitive j. key and after.value are borrowed for the call only.
type treeTargetV1 struct {
	dbi   DBI
	key   []byte
	after treeImageV1
}

// treeEmitterV1 receives j's targets and references.
// emitV1, writer (D14-10): prior presence = the amended logical read (P_w entry, else ORIGINAL OLD), never the write txn.
// present->present: delete then put; present->absent: delete; absent->present: put (put_nooverwrite); absent->absent: no
// native write call. rc law of updateNativePut/updateNativeDeletes: stage 2 before the call; KEYEXIST (put) and NOTFOUND
// (delete) -> EngineStateMismatch with the native code; other failures -> nativeError(operationUpdate, rc). Then fused
// final equality, then the P_w entry (len(key)+len(value), or len(key) when absent); only the shortfall
// max(0, n - (heldP - liveP)) is charged on the ledger before the copy (D5-2).
// emitV1, readback (D14-7): drawV1(n) for the new P_r entry; when P_r already holds that identity (image, absent marker
// or reference) returnV1(replaced size) follows the draw, so the readback peak equals the writer's high-water.
// referV1 records a non-target identity whose expectation is ORIGINAL OLD in the writer final equality and in both
// readback predicates; it costs a len(key) reference entry and is a no-op when P already holds the identity.
// Each identity is emitted at most once per primitive. Node targets come zero-first, children before branch,
// root binding last (L2's obligation).
type treeEmitterV1 interface {
	emitV1(target treeTargetV1) error
	referV1(dbi DBI, key []byte) error
}

// treeLeafV1 is one net-dirty UTXO identity of primitive j in native key order (D6-4: k groups). net-dirty:
// final presence != logical OLD presence, or both present and final value bytes differ (D12-K).
// newValue is the stored utxo-v1 value frame || u64le(height) || coinbase, held in L1's value scratch V.
// It is borrowed until the next nextV1 on the same stream.
type treeLeafV1 struct {
	key        [44]byte
	oldPresent bool
	newPresent bool
	newValue   []byte
}

// treeLeavesV1 is a fresh iterator over the same frozen group array on every call (fold, then emit).
type treeLeavesV1 interface {
	nextV1() (treeLeafV1, bool, error)
}
