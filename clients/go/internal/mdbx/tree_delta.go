package mdbx

import (
	"bytes"
	"encoding/binary"
	"slices"
	"sync"
	"sync/atomic"
)

// ---- tree_delta.go (owner L1) ----
// treeRecorderV1 is the unexported state behind TreeDeltaSinkV1 (D6-3, D6-6 E1/E3, D8-5); it records the first failure.
// newTreeRecorderV1 binds one primitive at one position. ledger is the account ledger at the writer and
// budget.ledgerV1() at the readback. beginV1 charges D_j + V through ledger before allocating; the window
// (W + F_fixed) is charged by L5a before the Source call and lent here by windowV1.
// D6-2 BEGIN constraints are D6-3 refusals: TxCount == 0, or at height 0 TxCount != 1 or Generated != 0, at beginV1;
// a SPEND at height 0 at eventV1. expireV1 is idempotent: it stores the inactive flag, then takes and releases the
// recorder mutex so an in-flight call completes (beginV1 and eventV1 test the flag while holding the mutex). After it
// every sink method returns "tree delta sink is not active" without a charge or copy, windowV1 returns nil, and
// failureV1 no longer changes (the refusal is not recorded). finishV1 and releaseV1 call expireV1 first. releaseV1 is
// idempotent and then returns D_j + V through ledger exactly once if beginV1 charged them; the recorder owns that
// charge for the whole position (D13-8, D26). L1 heap-allocates only the recorder, the delta, one iterator per leavesV1
// call, the D_j array, the V scratch, one key scratch (a type with no Go pointer: every key and from L1 passes to
// treeOldV1 or treeEmitterV1 and the regenerated manifest bytes) and at most one 32-byte copy of block in
// treeStoredBodyV1; the fixed objects, the key scratch and that copy fit treeControlBytesV1, which L5a charges before
// treeStoredBodyV1 and newTreeRecorderV1 (D14-2, D25, D28).
const treeControlBytesV1 uint64 = 4096 // C: L1 per-primitive control objects (recorder, delta, key scratch, 2 leaves iterators, treeStoredBodyV1's 32-byte block copy)

// Event kinds of the closed grammar (BLOCK 3016) and the descriptor flag bits.
const (
	treeSpendV1  uint8 = 1
	treeCreateV1 uint8 = 2

	treeDescOldV1   uint8 = 1 // group-first: group OLD presence (first event is SPEND)
	treeDescNewV1   uint8 = 2 // group-first: group NEW presence (last event is CREATE)
	treeDescDirtyV1 uint8 = 4 // group-first: net-dirty (D12-K), set by resolveV1
)

// treeDescV1 is one admitted event, copied by value (G5). After finishV1 the array is in (UTXO key, seq) order;
// pos of the descriptor at index s is the sorted index of the event with arrival sequence s; group and last are
// the sorted indices of its group's first and last event; img is the image resolveV1 borrowed for a group-first
// descriptor (forward: logical OLD value; inverse: the retained undo entry value).
type treeDescV1 struct {
	txid                                   [32]byte
	img                                    []byte
	frameOffset                            uint64
	vout, txIndex, inputIndex, frameLength uint32
	seq, pos, group, last                  uint32
	kind, flags                            uint8
}

// treeDescSizeV1 is descSize, the byte size of treeDescV1 on the 64-bit targets this package builds for (pinned
// against unsafe.Sizeof by TestTreeDeltaControlBoundV1); the array below is its compile-time guard descSize <= 128.
const treeDescSizeV1 uint64 = 104

var _ [128 - treeDescSizeV1]struct{} // descSize <= 128 (D6-6 E1, BLOCK 3063)

type treeRecorderV1 struct {
	mu                             sync.Mutex
	inactive                       atomic.Bool
	position                       treePositionV1
	prim                           treePrimitiveV1
	body                           treeBodyV1
	window                         []byte
	ledger                         treeLedgerV1
	failure                        error
	count                          uint32 // accepted events
	begun, charged, released, have bool
	expired                        bool
	txCount, eventCount            uint32
	generated                      [16]byte
	lastTx, lastIndex              uint32
	lastPhase                      uint8
	charge                         uint64
	descs                          []treeDescV1
	value                          []byte
}

func newTreeRecorderV1(position treePositionV1, prim treePrimitiveV1, body treeBodyV1, window []byte, ledger treeLedgerV1) *treeRecorderV1 {
	return &treeRecorderV1{position: position, prim: prim, body: body, window: window, ledger: ledger}
}

func (r *treeRecorderV1) windowV1() []byte {
	if r.inactive.Load() {
		return nil
	}
	return r.window
}

func (r *treeRecorderV1) failureV1() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failure
}

func (r *treeRecorderV1) expireV1() {
	r.inactive.Store(true)
	r.mu.Lock()
	r.expired = true // under the mutex: an in-flight sink call has returned (G7)
	r.mu.Unlock()
}

func (r *treeRecorderV1) releaseV1() {
	r.expireV1()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.charged && !r.released {
		r.released = true
		r.ledger.releaseV1(r.charge)
	}
}

// treeOrderAfterV1 reports whether (txIndex, phase, index) strictly follows the last accepted order key (G3).
func (r *treeRecorderV1) treeOrderAfterV1(txIndex uint32, phase uint8, index uint32) bool {
	if !r.have || txIndex != r.lastTx {
		return !r.have || txIndex > r.lastTx
	}
	if phase != r.lastPhase {
		return phase > r.lastPhase
	}
	return index > r.lastIndex
}

// treeCovenantRefusedV1 reads covenant_type from the bound body when [offset, offset+10) lies inside it (G4).
func treeCovenantRefusedV1(body []byte, offset uint64) bool {
	if offset > uint64(len(body)) || uint64(len(body))-offset < 10 {
		return false
	}
	covenant := binary.LittleEndian.Uint16(body[offset+8:])
	return covenant == 0x0002 || covenant == 0x0103
}

// treeCompareDescV1 orders by UTXO key (one generation, so txid then big-endian vout), then arrival sequence.
func treeCompareDescV1(a, b treeDescV1) int {
	if c := bytes.Compare(a.txid[:], b.txid[:]); c != 0 {
		return c
	}
	if a.vout != b.vout {
		return treeCmpU32V1(a.vout, b.vout)
	}
	return treeCmpU32V1(a.seq, b.seq)
}

func treeCmpU32V1(a, b uint32) int {
	if a < b {
		return -1
	}
	return 1
}

func treeSameKeyV1(a, b *treeDescV1) bool { return a.txid == b.txid && a.vout == b.vout }

// treeGroupV1 sorts the n admitted descriptors in place and coalesces groups; false means two consecutive events of
// one kind in a group (G6).
func treeGroupV1(descs []treeDescV1, n uint32) bool {
	slices.SortFunc(descs, treeCompareDescV1)
	first := uint32(0)
	for i := uint32(1); i < n; i++ {
		if !treeSameKeyV1(&descs[i], &descs[first]) {
			treeCloseGroupV1(descs, first, i-1)
			first = i
		} else if descs[i].kind == descs[i-1].kind {
			return false
		}
		descs[i].group = first
	}
	if n > 0 {
		descs[0].group = 0
		treeCloseGroupV1(descs, first, n-1)
	}
	treePermuteV1(descs, n)
	return true
}

func treeCloseGroupV1(descs []treeDescV1, first, last uint32) {
	g := &descs[first]
	g.last = last
	g.flags = 0
	if g.kind == treeSpendV1 {
		g.flags |= treeDescOldV1
	}
	if descs[last].kind == treeCreateV1 {
		g.flags |= treeDescNewV1
	}
}

// treePermuteV1 stores the original-order permutation inside the array (pos of index seq = sorted index).
func treePermuteV1(descs []treeDescV1, n uint32) {
	for i := uint32(0); i < n; i++ {
		descs[descs[i].seq].pos = i
	}
}

// treeUTXOValueOKV1 is the DecodeUTXOValue acceptance check (schema.go:194-209) without the covenant-data copy.
func treeUTXOValueOKV1(b []byte) bool {
	if len(b) < 20 || len(b) > 65_560 {
		return false
	}
	n, used, ok := readCompactSize(b[10:])
	if !ok || 10+used+n+9 != uint64(len(b)) {
		return false
	}
	return b[len(b)-1] <= 1
}

// treeUndoValueOKV1 is the validateUndoValue acceptance check (schema.go:347-356) without allocation (S6c).
func treeUndoValueOKV1(key, value []byte) bool {
	if key[32] == 0 {
		return len(value) == 33 && value[0] == 1
	}
	return treeUTXOValueOKV1(value)
}

// treeDeltaV1 is primitive j's admitted delta after the provider returned. finishV1 runs the count check and D6-4.
// resolveV1 reads only through old (checked at the writer) and writes nothing. Fixed order, first failure returns,
// each identity read at most once: (i) S2 frames for all CREATE events, no read; (ii) family head nextV1 unless
// Transient, manifest checked (present family without manifest: treeIntegrity(operationUpdate, nil)); (iii) events
// in original order: one getV1(utxo-v1) per group-first event, then S3, then S4; at a forward SPEND group-first
// event whose effect is WriteOrReuse, Compare or CompareDelete (never Transient, never inverse) the held OLD value
// then passes the non-allocating DecodeUTXOValue accept-set check, else treeIntegrity(operationUpdate, errSchema)
// (D18); a SPEND group-first event with the family present then takes the next nextV1 row, which must equal its
// UndoEntryKey (else integrity nil), value checked while the OLD value is held; (iv) the tail nextV1 must leave the
// family prefix. WriteOrReuse, Compare and CompareDelete family values are byte comparisons: a WriteOrReuse
// difference is treeIntegrity(operationUpdate, nil) (D8-3, rx D876); Compare/CompareDelete mismatch is
// treeIntegrity(operationUpdate, nil). Only SourceRetain/SourceDelete undo values (validateUndoValue accept set) and
// the D18 forward OLD values (its entry-form branch) are checked without allocation; that refusal is
// treeIntegrity(operationUpdate, errSchema).
// applyV1 (D14-1 as amended by D20), same order at both positions: referV1 of the body row when body.pair is false; then
// events in original order; at each event that is its group's first event: forward, for a SPEND that input's undo-entry
// effect (D8-3) then the group's UTXO effect (target if net-dirty, else referV1); inverse, the group's UTXO effect then,
// for a SPEND, that input's undo-entry effect; after the last event the manifest effect. Unchanged family rows are
// referred (D13-5, D13-6).
// applyV1 and leavesV1 read nothing. applyV1 copies no OLD or entry value: each emitted value is the body span, a value
// formed in V, the regenerated manifest or an image resolveV1 obtained, passed as after.value, and each such image is
// consumed before any emitV1 or referV1 of its own identity in this primitive (D20). Each leaves nextV1 writes newValue
// into V: the formed body value, or, for an inverse group with newPresent true, a copy of the entry image resolveV1
// obtained for that group, which the treeImageV1 lifetime keeps readable after applyV1 (D24).
type treeDeltaV1 struct {
	rec    *treeRecorderV1
	keys   *treeKeysV1
	spent  uint32 // number of SPEND-first groups
	family bool   // own family present at the S12 (ii) head read
	cursor int    // length of the undo-v1 cursor key in keys.from
}

// treeKeysV1 is the key scratch K (D28, G10): every key and from L1 passes to treeOldV1 or treeEmitterV1 and the
// regenerated manifest. It holds only byte arrays, so a slice of it is a valid cgo argument.
type treeKeysV1 struct {
	block    [32]byte
	manifest [33]byte
	utxo     [44]byte
	entry    [77]byte
	from     [78]byte
}

// Undo effect values (D8-2), compared by number as L5b converts them by identity.
const (
	treeUndoWriteOrReuseV1  uint8 = 1
	treeUndoTransientV1     uint8 = 2
	treeUndoCompareV1       uint8 = 3
	treeUndoCompareDeleteV1 uint8 = 4
	treeUndoSourceRetainV1  uint8 = 5
	treeUndoSourceDeleteV1  uint8 = 6
)

// Own-family effect of one row: no call, referV1, an absent target, or a present target.
const (
	treeEffectNoneV1 uint8 = iota
	treeEffectReferV1
	treeEffectAbsentV1
	treeEffectPresentV1
)

func (d *treeDeltaV1) forwardV1() bool { return d.rec.prim.direction == treeForwardV1 }

// familyEffectV1 is the S6/S6b effect of every own-family row after a nil resolveV1.
func (d *treeDeltaV1) familyEffectV1() uint8 {
	switch d.rec.prim.undo {
	case treeUndoTransientV1:
		return treeEffectNoneV1
	case treeUndoCompareDeleteV1, treeUndoSourceDeleteV1:
		return treeEffectAbsentV1
	case treeUndoWriteOrReuseV1:
		if !d.family {
			return treeEffectPresentV1
		}
	}
	return treeEffectReferV1
}

// buildManifestV1 regenerates UndoManifestValue(Height, Generated, TxCount, spentCount) into d.keys.manifest (S5).
func (d *treeDeltaV1) buildManifestV1() {
	r := d.rec
	d.keys.manifest[0] = 1
	binary.BigEndian.PutUint64(d.keys.manifest[1:], r.prim.height)
	copy(d.keys.manifest[9:], r.generated[:])
	binary.BigEndian.PutUint32(d.keys.manifest[25:], r.txCount)
	binary.BigEndian.PutUint32(d.keys.manifest[29:], d.spent)
}

// utxoKeyV1 writes UTXOKey(Generation, txid, vout) (schema.go:159-167) into d.keys.utxo.
func (d *treeDeltaV1) utxoKeyV1(e *treeDescV1) []byte {
	binary.BigEndian.PutUint64(d.keys.utxo[:], d.rec.prim.generation)
	copy(d.keys.utxo[8:], e.txid[:])
	binary.BigEndian.PutUint32(d.keys.utxo[40:], e.vout)
	return d.keys.utxo[:]
}

// entryKeyV1 writes UndoEntryKey(Block, txid, txIndex, inputIndex, vout) (schema.go:276-284) into d.keys.entry.
func (d *treeDeltaV1) entryKeyV1(e *treeDescV1) []byte {
	copy(d.keys.entry[:], d.keys.block[:])
	d.keys.entry[32] = 1
	binary.BigEndian.PutUint32(d.keys.entry[33:], e.txIndex)
	binary.BigEndian.PutUint32(d.keys.entry[37:], e.inputIndex)
	copy(d.keys.entry[41:], e.txid[:])
	binary.BigEndian.PutUint32(d.keys.entry[73:], e.vout)
	return d.keys.entry[:]
}

// manifestKeyV1 writes Block || 0x00 into d.keys.from and returns it.
func (d *treeDeltaV1) manifestKeyV1() []byte {
	copy(d.keys.from[:], d.keys.block[:])
	d.keys.from[32] = 0
	return d.keys.from[:33]
}

// afterV1 writes key || 0x00 into d.keys.from: the first key strictly after key (T1).
func (d *treeDeltaV1) afterV1(key []byte) {
	n := copy(d.keys.from[:], key)
	d.keys.from[n] = 0
	d.cursor = n + 1
}

// formV1 forms the stored value frame || u64le(Height) || coinbase of CREATE e in V (S2, S7).
func (d *treeDeltaV1) formV1(e *treeDescV1) []byte {
	r := d.rec
	n := int(e.frameLength)
	v := r.value[:n+9]
	copy(v, r.body.bytes[e.frameOffset:e.frameOffset+uint64(e.frameLength)])
	binary.LittleEndian.PutUint64(v[n:], r.prim.height)
	v[n+8] = 0
	if e.txIndex == 0 {
		v[n+8] = 1
	}
	return v
}

// frameInsideV1 reports whether CREATE e's frame lies inside the bound body (S2).
func (d *treeDeltaV1) frameInsideV1(e *treeDescV1) bool {
	end := e.frameOffset + uint64(e.frameLength)
	return end <= uint64(len(d.rec.body.bytes))
}

// eventAtV1 is the descriptor of the event with arrival sequence s.
func (d *treeDeltaV1) eventAtV1(s int) *treeDescV1 {
	descs := d.rec.descs
	return &descs[descs[s].pos]
}

// groupFirstV1 returns e's group-first descriptor and whether e is it.
func (d *treeDeltaV1) groupFirstV1(e *treeDescV1) (*treeDescV1, bool) {
	g := &d.rec.descs[e.group]
	return g, g == e
}

func (d *treeDeltaV1) applyV1(emit treeEmitterV1) error {
	r := d.rec
	if !r.body.pair {
		err := emit.referV1(schemaDBIs[4], d.keys.block[:])
		if err != nil {
			return err
		}
	}
	for s := range r.descs {
		e := d.eventAtV1(s)
		g, first := d.groupFirstV1(e)
		if !first {
			continue
		}
		err := d.applyGroupV1(emit, g)
		if err != nil {
			return err
		}
	}
	return d.familyRowV1(emit, d.manifestKeyV1(), d.keys.manifest[:])
}

// applyGroupV1 emits one group's effects at its first event in the S11 order.
func (d *treeDeltaV1) applyGroupV1(emit treeEmitterV1, g *treeDescV1) error {
	spend := g.kind == treeSpendV1
	if spend && d.forwardV1() {
		err := d.familyRowV1(emit, d.entryKeyV1(g), g.img)
		if err != nil {
			return err
		}
	}
	err := d.utxoEffectV1(emit, g)
	if err != nil || !spend || d.forwardV1() {
		return err
	}
	return d.familyRowV1(emit, d.entryKeyV1(g), nil)
}

// familyRowV1 emits one own-family row's effect; value is the present-target value (forward entry or manifest).
func (d *treeDeltaV1) familyRowV1(emit treeEmitterV1, key, value []byte) error {
	switch d.familyEffectV1() {
	case treeEffectReferV1:
		return emit.referV1(schemaDBIs[5], key)
	case treeEffectAbsentV1:
		return emit.emitV1(treeTargetV1{dbi: schemaDBIs[5], key: key})
	case treeEffectPresentV1:
		return emit.emitV1(treeTargetV1{dbi: schemaDBIs[5], key: key, after: treeImageV1{present: true, value: value}})
	}
	return nil
}

// utxoEffectV1 emits the S7 target of a net-dirty group, else referV1 of its key (S6b).
func (d *treeDeltaV1) utxoEffectV1(emit treeEmitterV1, g *treeDescV1) error {
	key := d.utxoKeyV1(g)
	if g.flags&treeDescDirtyV1 == 0 {
		return emit.referV1(schemaDBIs[1], key)
	}
	present, value := d.finalV1(g)
	return emit.emitV1(treeTargetV1{dbi: schemaDBIs[1], key: key, after: treeImageV1{present: present, value: value}})
}

// finalV1 is a group's final presence and value at this primitive's position: forward, the formed body value of the
// last CREATE (in V); inverse, the borrowed retained entry image.
func (d *treeDeltaV1) finalV1(g *treeDescV1) (bool, []byte) {
	if !d.forwardV1() {
		return g.flags&treeDescOldV1 != 0, g.img
	}
	if g.flags&treeDescNewV1 == 0 {
		return false, nil
	}
	return true, d.formV1(&d.rec.descs[g.last])
}

func (d *treeDeltaV1) leavesV1() treeLeavesV1 { return &treeLeafIterV1{delta: d} }

// treeLeafIterV1 walks the sorted group array; each call of leavesV1 returns a fresh one.
type treeLeafIterV1 struct {
	delta *treeDeltaV1
	next  int
}

func (it *treeLeafIterV1) nextV1() (treeLeafV1, bool, error) {
	d := it.delta
	descs := d.rec.descs
	for it.next < len(descs) {
		g := &descs[it.next]
		it.next = int(g.last) + 1
		if g.flags&treeDescDirtyV1 != 0 {
			return d.leafV1(g), true, nil
		}
	}
	return treeLeafV1{}, false, nil
}

// leafV1 builds one net-dirty leaf; newValue is written into V (S8, D24).
func (d *treeDeltaV1) leafV1(g *treeDescV1) treeLeafV1 {
	var leaf treeLeafV1
	copy(leaf.key[:], d.utxoKeyV1(g))
	old, created := g.flags&treeDescOldV1 != 0, g.flags&treeDescNewV1 != 0
	leaf.oldPresent, leaf.newPresent = old, created
	if !d.forwardV1() {
		leaf.oldPresent, leaf.newPresent = created, old
	}
	leaf.newValue = d.rec.value[:0]
	if !leaf.newPresent {
		return leaf
	}
	if d.forwardV1() {
		leaf.newValue = d.formV1(&d.rec.descs[g.last])
		return leaf
	}
	leaf.newValue = d.rec.value[:copy(d.rec.value, g.img)]
	return leaf
}
