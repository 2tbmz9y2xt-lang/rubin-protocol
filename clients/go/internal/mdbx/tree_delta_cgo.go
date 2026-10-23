//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
)

// treeStoredBodyV1 reads the blocks-v1 (rank 4) row of block through old. Absent -> treeIntegrity(operationUpdate, nil).
// Present -> {bytes: the image value, uncopied; pair: false}. Its only heap allocation is at most one 32-byte copy of
// block (block[:] is passed to getV1), counted in treeControlBytesV1 (D25).
func treeStoredBodyV1(old treeOldV1, block [32]byte) (treeBodyV1, error) {
	image, err := old.getV1(schemaDBIs[4], block[:])
	if err != nil {
		return treeBodyV1{}, err
	}
	if !image.present {
		return treeBodyV1{}, treeIntegrity(operationUpdate, nil)
	}
	return treeBodyV1{bytes: image.value}, nil
}

func treeDeltaInvalidV1() error {
	return adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "invalid tree delta", nil)
}

func treeSinkInactiveV1() error {
	return adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "tree delta sink is not active", nil)
}

// recordV1 records err as the first failure and returns it.
func (r *treeRecorderV1) recordV1(err error) error {
	r.failure = err
	return err
}

// sinkStateV1 is the refusal every sink call checks first: not active (not recorded), then the recorded failure.
func (r *treeRecorderV1) sinkStateV1() error {
	if r.inactive.Load() {
		return treeSinkInactiveV1()
	}
	return r.failure
}

func (r *treeRecorderV1) beginV1(blockTxCount, eventCount uint32, generated [16]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.sinkStateV1(); err != nil {
		return err
	}
	if r.begun || r.beginRefusedV1(blockTxCount, generated) {
		return r.recordV1(treeDeltaInvalidV1())
	}
	if r.observation != nil && r.coverage.BlockMeta != (TreeBlockV1{TxCount: blockTxCount, EventCount: eventCount, Generated: generated}) {
		return r.recordV1(treeDeltaInvalidV1())
	}
	n := treeDescSizeV1*uint64(eventCount) + treeValueBytesV1
	if err := r.ledger.chargeV1(n); err != nil {
		return r.recordV1(err)
	}
	r.begun, r.charged, r.charge = true, true, n
	r.txCount, r.eventCount, r.generated = blockTxCount, eventCount, generated
	r.descs = make([]treeDescV1, 0, eventCount)
	r.value = make([]byte, treeValueBytesV1)
	return nil
}

// beginRefusedV1 is the D6-2 BEGIN constraint set (G2b).
func (r *treeRecorderV1) beginRefusedV1(blockTxCount uint32, generated [16]byte) bool {
	if blockTxCount == 0 {
		return true
	}
	return r.prim.height == 0 && (blockTxCount != 1 || generated != [16]byte{})
}

func (r *treeRecorderV1) eventV1(kind uint8, txid [32]byte, vout, txIndex, inputIndex uint32, frameOffset uint64, frameLength uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.sinkStateV1(); err != nil {
		return err
	}
	e := treeDescV1{txid: txid, vout: vout, txIndex: txIndex, inputIndex: inputIndex, frameOffset: frameOffset, frameLength: frameLength, kind: kind}
	if !r.eventAdmittedV1(&e) || kind == treeCreateV1 && treeCovenantRefusedV1(r.body.bytes, frameOffset) {
		return r.recordV1(treeDeltaInvalidV1())
	}
	phase, index := treeEventOrderV1(&e)
	r.have, r.lastTx, r.lastPhase, r.lastIndex = true, txIndex, phase, index
	e.seq = r.count
	r.descs = append(r.descs, e)
	r.count++
	return nil
}

// treeEventOrderV1 is the order key's phase (SPEND 0 < CREATE 1) and index (input index or vout).
func treeEventOrderV1(e *treeDescV1) (uint8, uint32) {
	if e.kind == treeSpendV1 {
		return 0, e.inputIndex
	}
	return 1, e.vout
}

// eventAdmittedV1 runs the G3 grammar checks.
func (r *treeRecorderV1) eventAdmittedV1(e *treeDescV1) bool {
	if !r.begun || !treeEventShapeV1(e, r.prim.height) || e.txIndex >= r.txCount {
		return false
	}
	phase, index := treeEventOrderV1(e)
	return r.treeOrderAfterV1(e.txIndex, phase, index) && r.count < r.eventCount
}

// treeEventShapeV1 checks the kind and the per-kind fields (G3, D12-G2).
func treeEventShapeV1(e *treeDescV1, height uint64) bool {
	switch e.kind {
	case treeSpendV1:
		return e.frameOffset == 0 && e.frameLength == 0 && height != 0
	case treeCreateV1:
		return e.inputIndex == 0 && e.frameLength >= 11 && e.frameLength <= 65_551 && e.frameOffset <= ^uint64(0)-uint64(e.frameLength)
	}
	return false
}

func (r *treeRecorderV1) finishV1() (*treeDeltaV1, error) {
	r.expireV1()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failure != nil {
		return nil, r.failure
	}
	if !r.begun || r.count != r.eventCount || !treeGroupV1(r.descs, r.count) {
		return nil, treeDeltaInvalidV1()
	}
	d := &treeDeltaV1{rec: r, keys: &treeKeysV1{block: r.prim.block}}
	for i := uint32(0); i < r.count; i++ {
		if r.descs[i].group == i && r.descs[i].kind == treeSpendV1 {
			d.spent++
		}
	}
	d.buildManifestV1()
	return d, nil
}

func (d *treeDeltaV1) resolveV1(old treeOldV1) error {
	if !d.framesOKV1() {
		return treeIntegrity(operationUpdate, nil)
	}
	if err := d.headV1(old); err != nil {
		return err
	}
	if err := d.counterHeadV1(old); err != nil {
		return err
	}
	for s := range d.rec.descs {
		e := d.eventAtV1(s)
		g, first := d.groupFirstV1(e)
		if !first {
			continue
		}
		if err := d.resolveGroupV1(old, g); err != nil {
			return err
		}
	}
	if err := d.tailV1(old); err != nil {
		return err
	}
	return d.counterFinishV1()
}

func (d *treeDeltaV1) counterHeadV1(old treeOldV1) error {
	if d.rec.observation == nil || d.rec.rootReadOnly {
		return nil
	}
	d.keys.counterKey[0] = 0x10
	binary.BigEndian.PutUint64(d.keys.counterKey[1:], d.rec.prim.generation)
	image, err := old.getV1(schemaDBIs[0], d.keys.counterKey[:])
	if err != nil {
		return err
	}
	if !image.present {
		return d.counterFailureV1(image, TreeObservationAbsentV1, nil)
	}
	if len(image.value) != 16 {
		return d.counterFailureV1(image, TreeObservationMalformedV1, errSchema)
	}
	d.parentBytes = binary.BigEndian.Uint64(image.value)
	d.parentCount = binary.BigEndian.Uint64(image.value[8:])
	if !d.counterRecordOKV1() {
		return d.counterFailureV1(image, TreeObservationMalformedV1, nil)
	}
	if !treeCounterEnvelopeV1(d.parentBytes, d.parentCount, 1<<59) {
		return treeIntegrity(operationUpdate, nil)
	}
	return nil
}

func (d *treeDeltaV1) counterRecordOKV1() bool {
	// Endpoint admission bounds height to at most 2^32, so both products fit
	// uint64. Forward reads U_parent (h heights); inverse reads U_h (h+1).
	heights := d.rec.prim.height
	if !d.forwardV1() {
		heights++
	}
	return d.parentBytes <= heights*86_545_430 && d.parentCount <= heights*1_545_454
}

func (d *treeDeltaV1) counterFailureV1(image treeImageV1, kind TreeObservationKindV1, cause error) error {
	if image.planned {
		return treeIntegrity(operationUpdate, cause)
	}
	return treeObserveV1(treeIntegrity(operationUpdate, cause), d.rec.observation, 0, d.keys.counterKey[:], kind, image, !image.planned)
}

func treeCounterEnvelopeV1(total, count, limit uint64) bool {
	if total >= limit {
		return false
	}
	return count <= total/56 && count >= (total+65595)/65596
}

// Counter subsets include equal replacements and cancellations, not only leaves.
// Check the residual before deriving parent-before+after, so input integrity wins.
func (d *treeDeltaV1) counterFinishV1() error {
	if d.rec.observation == nil || d.rec.rootReadOnly {
		return nil
	}
	if d.beforeBytes > d.parentBytes || d.beforeCount > d.parentCount {
		return treeIntegrity(operationUpdate, nil)
	}
	residualBytes, residualCount := d.parentBytes-d.beforeBytes, d.parentCount-d.beforeCount
	if !treeCounterEnvelopeV1(residualBytes, residualCount, 1<<59) {
		return treeIntegrity(operationUpdate, nil)
	}
	return d.counterResultV1(residualBytes, residualCount)
}

func (d *treeDeltaV1) counterResultV1(residualBytes, residualCount uint64) error {
	if d.afterBytes > ^uint64(0)-residualBytes || d.afterCount > ^uint64(0)-residualCount {
		return updateNativeInvariant("derived logical state counters exceed bounds")
	}
	total, count := residualBytes+d.afterBytes, residualCount+d.afterCount
	if !treeCounterEnvelopeV1(total, count, 1<<59) || d.afterBytes >= 1<<60 || d.parentBytes > (1<<60)-1-d.afterBytes {
		return updateNativeInvariant("derived logical state counters exceed bounds")
	}
	binary.BigEndian.PutUint64(d.counter[:], total)
	binary.BigEndian.PutUint64(d.counter[8:], count)
	return nil
}

func treeCounterAddV1(total, count *uint64, length uint64) error {
	if length > ^uint64(0)-*total || *count == ^uint64(0) {
		return updateNativeInvariant("logical state subset exceeds uint64")
	}
	*total += length
	*count++
	return nil
}

// framesOKV1 is S2 for every CREATE event: frame inside the body and the formed value in the DecodeUTXOValue domain.
func (d *treeDeltaV1) framesOKV1() bool {
	for s := range d.rec.descs {
		e := d.eventAtV1(s)
		if e.kind == treeCreateV1 && (!d.frameInsideV1(e) || !treeUTXOValueOKV1(d.formV1(e))) {
			return false
		}
	}
	return true
}

// headV1 is S12 (ii): the family head read and the manifest check for the effect.
func (d *treeDeltaV1) headV1(old treeOldV1) error {
	undo := d.rec.prim.undo
	if undo == treeUndoTransientV1 {
		return nil
	}
	block := d.keys.block[:]
	key, image, ok, err := old.nextV1(schemaDBIs[5], block)
	if err != nil {
		return err
	}
	if !ok || !bytes.HasPrefix(key, block) {
		return d.absentFamilyV1()
	}
	return d.manifestRowV1(key, image.value)
}

// manifestRowV1: the head row must be the manifest key; its value passes S6c/S6 (retained) or equals the regenerated one.
func (d *treeDeltaV1) manifestRowV1(key, value []byte) error {
	if len(key) != 33 || key[32] != 0 {
		return treeIntegrity(operationUpdate, nil)
	}
	d.family = true
	d.afterV1(key)
	undo := d.rec.prim.undo
	if undo == treeUndoSourceRetainV1 || undo == treeUndoSourceDeleteV1 {
		return d.retainedManifestV1(key, value)
	}
	if !bytes.Equal(value, d.keys.manifest[:]) {
		return treeIntegrity(operationUpdate, nil)
	}
	return nil
}

func (d *treeDeltaV1) absentFamilyV1() error {
	if d.rec.prim.undo == treeUndoWriteOrReuseV1 {
		return nil
	}
	return treeIntegrity(operationUpdate, nil)
}

// retainedManifestV1 is S6c, then the S6 height, txCount and spentCount checks of a retained manifest.
func (d *treeDeltaV1) retainedManifestV1(key, value []byte) error {
	if !treeUndoValueOKV1(key, value) {
		return treeIntegrity(operationUpdate, errSchema)
	}
	if !bytes.Equal(value[1:9], d.keys.manifest[1:9]) || !bytes.Equal(value[25:33], d.keys.manifest[25:33]) {
		return treeIntegrity(operationUpdate, nil)
	}
	if d.rec.observation != nil && !bytes.Equal(value[9:25], d.keys.manifest[9:25]) {
		return treeIntegrity(operationUpdate, nil)
	}
	return nil
}

// resolveGroupV1 is S12 (iii) at one group-first event: OLD read, S3, S4, S13, then the undo entry.
func (d *treeDeltaV1) resolveGroupV1(old treeOldV1, g *treeDescV1) error {
	image, err := old.getV1(schemaDBIs[1], d.utxoKeyV1(g))
	if err != nil {
		return err
	}
	if !d.coveredV1(g, image) {
		return treeIntegrity(operationUpdate, nil)
	}
	if d.oldValueRefusedV1(g, image.value) {
		return treeIntegrity(operationUpdate, errSchema)
	}
	if err := d.counterBeforeV1(image); err != nil {
		return err
	}
	g.img = image.value
	d.markDirtyV1(g, image)
	if g.kind == treeSpendV1 && d.family {
		if err := d.entryV1(old, g, image.value); err != nil {
			return err
		}
	}
	return d.counterGroupV1(g)
}

func (d *treeDeltaV1) counterBeforeV1(image treeImageV1) error {
	if d.rec.observation == nil || d.rec.rootReadOnly || !image.present {
		return nil
	}
	if !treeUTXOValueOKV1(image.value) {
		return treeIntegrity(operationUpdate, errSchema)
	}
	return treeCounterAddV1(&d.beforeBytes, &d.beforeCount, 36+uint64(len(image.value)))
}

func (d *treeDeltaV1) counterGroupV1(g *treeDescV1) error {
	if d.rec.observation == nil || d.rec.rootReadOnly {
		return nil
	}
	present, value := d.finalV1(g)
	if !present {
		return nil
	}
	return treeCounterAddV1(&d.afterBytes, &d.afterCount, 36+uint64(len(value)))
}

// coveredV1 is S3 presence coverage and the inverse S4 removal check.
func (d *treeDeltaV1) coveredV1(g *treeDescV1, image treeImageV1) bool {
	if !d.forwardV1() {
		created := g.flags&treeDescNewV1 != 0
		return image.present == created && (!created || bytes.Equal(image.value, d.formV1(&d.rec.descs[g.last])))
	}
	return image.present == (g.flags&treeDescOldV1 != 0)
}

// oldValueRefusedV1 is S13 (D18).
func (d *treeDeltaV1) oldValueRefusedV1(g *treeDescV1, value []byte) bool {
	undo := d.rec.prim.undo
	checked := undo == treeUndoWriteOrReuseV1 || undo == treeUndoCompareV1 || undo == treeUndoCompareDeleteV1
	return checked && d.forwardV1() && g.kind == treeSpendV1 && !treeUTXOValueOKV1(value)
}

// markDirtyV1 sets the D12-K net-dirty bit from the logical OLD image (forward: final value is the formed body
// value; inverse: entryV1 completes a present/present group).
func (d *treeDeltaV1) markDirtyV1(g *treeDescV1, image treeImageV1) {
	old, created := g.flags&treeDescOldV1 != 0, g.flags&treeDescNewV1 != 0
	if old != created {
		g.flags |= treeDescDirtyV1
		return
	}
	if old && d.forwardV1() && !bytes.Equal(image.value, d.formV1(&d.rec.descs[g.last])) {
		g.flags |= treeDescDirtyV1
	}
}

// entryV1 takes the next undo-v1 row, which must be g's UndoEntryKey, and checks its value while OLD is held.
func (d *treeDeltaV1) entryV1(old treeOldV1, g *treeDescV1, oldValue []byte) error {
	key, image, ok, err := old.nextV1(schemaDBIs[5], d.keys.from[:d.cursor])
	if err != nil {
		return err
	}
	want := d.entryKeyV1(g)
	if !ok || !bytes.Equal(key, want) {
		return treeIntegrity(operationUpdate, nil)
	}
	d.afterV1(want)
	if !d.forwardV1() {
		return inverseEntryV1(g, want, image.value, oldValue)
	}
	if !bytes.Equal(image.value, oldValue) {
		return treeIntegrity(operationUpdate, nil)
	}
	return nil
}

// inverseEntryV1: S6c on a retained entry, which becomes the restore value and completes the net-dirty bit.
func inverseEntryV1(g *treeDescV1, want, value, oldValue []byte) error {
	if !treeUndoValueOKV1(want, value) {
		return treeIntegrity(operationUpdate, errSchema)
	}
	g.img = value
	if g.flags&treeDescOldV1 != 0 && g.flags&treeDescNewV1 != 0 && !bytes.Equal(value, oldValue) {
		g.flags |= treeDescDirtyV1
	}
	return nil
}

// tailV1 is S12 (iv): with the family present, the next undo-v1 row must not be under Block.
func (d *treeDeltaV1) tailV1(old treeOldV1) error {
	if !d.family {
		return nil
	}
	key, _, ok, err := old.nextV1(schemaDBIs[5], d.keys.from[:d.cursor])
	if err != nil {
		return err
	}
	if ok && bytes.HasPrefix(key, d.keys.block[:]) {
		return treeIntegrity(operationUpdate, nil)
	}
	return nil
}
