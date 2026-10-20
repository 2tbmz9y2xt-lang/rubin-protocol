//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
)

// treeFrameCapV1 is 288 branches plus one leaf (CSM 2.6: a path has at most 288 branches).
const treeFrameCapV1 = 289

// treeNodeRefV1 names one node (depth 288 is a leaf; key is its routing key, else the branch prefix) with its digest.
type treeNodeRefV1 struct {
	digest  [32]byte
	key     [36]byte
	depth   uint16
	emitted bool
}

// treeFrameV1 is one pointer-free traversal frame. Index i holds the i-th read OLD node of the current path
// (old, oldValue, oldNext) and, independently, the i-th open NEW branch (open, zero).
type treeFrameV1 struct {
	old      treeNodeRefV1
	oldValue [140]byte
	oldNext  uint8
	open     treeNodeRefV1
	zero     treeNodeRefV1
}

type treeStreamKeyV1 struct {
	key        [36]byte
	digest     [32]byte
	oldPresent bool
	newPresent bool
}

// treeWalkV1 is the single per-call working object: the frame array plus fixed scratch.
type treeWalkV1 struct {
	frames           [treeFrameCapV1]treeFrameV1
	oldN, openN      int
	cur, top         treeNodeRefV1
	hasCur, curLeaf  bool
	topPending       bool
	leaf             treeStreamKeyV1
	leafOK, leafDone bool
	kidZero, kidOne  treeNodeRefV1
	keyBuf           [46]byte
	valBuf           [140]byte
	metaKey          [9]byte
	generation       uint64
	old              treeOldV1
	leaves           treeLeavesV1
	emit             treeEmitterV1
}

var treeAllOnesV1 = [36]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// treeFoldV1 is the read-only fold: the reads, checks and Encode validation of treeEmitNodesV1, with no emitter.
func treeFoldV1(old treeOldV1, generation uint64, endpoint TreeEndpointV1, databaseID [32]byte, leaves treeLeavesV1, ledger treeLedgerV1) error {
	return treeRunV1(old, generation, endpoint, databaseID, leaves, nil, ledger)
}

// treeEmitNodesV1 emits j's node delta in ascending TreeNodeKey, refers the required unchanged boundary set and
// emits the root binding of generation last. On a refusal it returns the first error and calls nothing later.
func treeEmitNodesV1(old treeOldV1, generation uint64, endpoint TreeEndpointV1, databaseID [32]byte, leaves treeLeavesV1, emit treeEmitterV1, ledger treeLedgerV1) error {
	return treeRunV1(old, generation, endpoint, databaseID, leaves, emit, ledger)
}

func treeRunV1(old treeOldV1, generation uint64, endpoint TreeEndpointV1, databaseID [32]byte, leaves treeLeavesV1, emit treeEmitterV1, ledger treeLedgerV1) error {
	if err := ledger.chargeV1(treeNodeWorkBytesV1); err != nil {
		return err
	}
	defer ledger.releaseV1(treeNodeWorkBytesV1)
	w := &treeWalkV1{generation: generation, old: old, leaves: leaves, emit: emit}
	binding, err := w.readBinding(databaseID)
	if err != nil {
		return err
	}
	if err := w.walk(); err != nil {
		return err
	}
	return w.finish(binding, endpoint)
}

func (w *treeWalkV1) readBinding(databaseID [32]byte) (RootBindingV1, error) {
	w.metaKey[0] = 0x11
	binary.BigEndian.PutUint64(w.metaKey[1:], w.generation)
	image, err := w.old.getV1(TreeSchemaV1DBIs()[0], w.metaKey[:])
	if err != nil {
		return RootBindingV1{}, err
	}
	if !image.present {
		return RootBindingV1{}, treeIntegrity(operationUpdate, nil)
	}
	binding, err := DecodeRootBindingV1(image.value)
	if err != nil {
		return RootBindingV1{}, treeIntegrity(operationUpdate, err)
	}
	if binding.DatabaseID != databaseID {
		return RootBindingV1{}, treeIntegrity(operationUpdate, nil)
	}
	return binding, w.setTop(binding)
}

func (w *treeWalkV1) setTop(binding RootBindingV1) error {
	if binding.Top.Kind == TreeTopEmptyV1 {
		if binding.RootDigest != treeEmptyDigestV1() {
			return treeIntegrity(operationUpdate, nil)
		}
		return nil
	}
	w.top = treeRefOfID(*binding.Top.Node, binding.RootDigest)
	w.topPending = true
	return nil
}

func (w *treeWalkV1) walk() error {
	for {
		cand, ok, err := w.nextCandidate()
		if err != nil || !ok {
			if err != nil {
				return err
			}
			break
		}
		if err := w.visit(cand); err != nil {
			return err
		}
	}
	if err := w.keysUntil(treeAllOnesV1, true); err != nil {
		return err
	}
	return w.closeTo(treeAllOnesV1, true)
}

// nextCandidate returns the next unvisited OLD subtree in ascending order, finishing exhausted OLD frames.
func (w *treeWalkV1) nextCandidate() (treeNodeRefV1, bool, error) {
	if w.topPending {
		w.topPending = false
		return w.top, true, nil
	}
	for w.oldN > 0 {
		i := w.oldN - 1
		if w.frames[i].oldNext < 2 {
			side := w.frames[i].oldNext
			w.frames[i].oldNext++
			return w.frames[i].child(side), true, nil
		}
		up := treeUpperV1(w.frames[i].old)
		if err := w.keysUntil(up, true); err != nil {
			return treeNodeRefV1{}, false, err
		}
		if err := w.closeTo(up, true); err != nil {
			return treeNodeRefV1{}, false, err
		}
	}
	return treeNodeRefV1{}, false, nil
}

func (w *treeWalkV1) visit(cand treeNodeRefV1) error {
	if err := w.keysUntil(cand.key, false); err != nil {
		return err
	}
	ok, err := w.peek()
	if err != nil {
		return err
	}
	if !ok || !treeContainsV1(cand, w.leaf.key) {
		return w.feed(cand, false)
	}
	return w.read(cand)
}

// read reads one R_j node, checks its record and its digest against the parent's (or the binding's) value.
func (w *treeWalkV1) read(cand treeNodeRefV1) error {
	image, err := w.old.getV1(TreeSchemaV1DBIs()[8], w.nodeKey(cand))
	if err != nil {
		return err
	}
	if !image.present {
		return treeIntegrity(operationUpdate, nil)
	}
	if !treeRecordOKV1(cand, image.value) {
		return treeIntegrity(operationUpdate, errSchema)
	}
	i := w.oldN
	w.oldN++
	w.frames[i].old = cand
	copy(w.frames[i].oldValue[:], image.value)
	w.frames[i].oldNext = 0
	if w.frames[i].recordDigest() != cand.digest {
		return treeIntegrity(operationUpdate, nil)
	}
	if cand.depth == 288 {
		w.frames[i].oldNext = 2
		return w.matchLeaf()
	}
	return nil
}

func (w *treeWalkV1) matchLeaf() error {
	u := w.leaf
	w.leafOK = false
	if !u.oldPresent {
		return treeIntegrity(operationUpdate, nil)
	}
	if u.newPresent {
		return w.feed(treeNodeRefV1{key: u.key, depth: 288, digest: u.digest}, true)
	}
	return nil
}

// outsideKey handles a stream key whose OLD path misses its leaf.
func (w *treeWalkV1) outsideKey() error {
	u := w.leaf
	w.leafOK = false
	if u.oldPresent {
		return treeIntegrity(operationUpdate, nil)
	}
	if u.newPresent {
		return w.feed(treeNodeRefV1{key: u.key, depth: 288, digest: u.digest}, true)
	}
	return nil
}

func (w *treeWalkV1) keysUntil(x [36]byte, inclusive bool) error {
	for {
		ok, err := w.peek()
		if err != nil {
			return err
		}
		if !ok || !treeBelowV1(w.leaf.key, x, inclusive) {
			return nil
		}
		if err := w.outsideKey(); err != nil {
			return err
		}
	}
}

func (w *treeWalkV1) peek() (bool, error) {
	if w.leafOK || w.leafDone {
		return w.leafOK, nil
	}
	leaf, ok, err := w.leaves.nextV1()
	if err != nil {
		return false, err
	}
	if !ok {
		w.leafDone = true
		return false, nil
	}
	copy(w.leaf.key[:], leaf.key[8:])
	w.leaf.oldPresent, w.leaf.newPresent = leaf.oldPresent, leaf.newPresent
	if leaf.newPresent {
		w.leaf.digest = treeLeafDigestV1(w.leaf.key, leaf.newValue)
	}
	w.leafOK = true
	return true, nil
}

// feed adds one NEW atom (an unread OLD subtree, or a stream leaf when leaf is true) in ascending order.
func (w *treeWalkV1) feed(atom treeNodeRefV1, leaf bool) error {
	if err := w.closeTo(atom.key, false); err != nil {
		return err
	}
	if w.hasCur {
		d := treeFirstDiffV1(w.cur.key, atom.key)
		i := w.openN
		w.openN++
		w.frames[i].open = treeNodeRefV1{key: treeMask(atom.key, d, false), depth: d}
		w.frames[i].zero = w.cur
	}
	w.cur, w.hasCur, w.curLeaf = atom, true, leaf
	return nil
}

// closeTo finalizes, in ascending TreeNodeKey, every pending OLD and NEW node whose upper bound is below x.
func (w *treeWalkV1) closeTo(x [36]byte, inclusive bool) error {
	for {
		oldOK := w.oldN > 0 && treeBelowV1(treeUpperV1(w.frames[w.oldN-1].old), x, inclusive)
		next, newOK := w.newTop()
		newOK = newOK && treeBelowV1(treeUpperV1(next), x, inclusive)
		if !oldOK && !newOK {
			return nil
		}
		if err := w.closeOne(oldOK, newOK, next); err != nil {
			return err
		}
	}
}

func (w *treeWalkV1) newTop() (treeNodeRefV1, bool) {
	if w.curLeaf {
		return w.cur, true
	}
	if w.openN > 0 {
		return w.frames[w.openN-1].open, true
	}
	return treeNodeRefV1{}, false
}

func (w *treeWalkV1) closeOne(oldOK, newOK bool, next treeNodeRefV1) error {
	if !newOK {
		return w.closeOld()
	}
	if !oldOK {
		return w.emitNode(w.buildNew())
	}
	switch c := treeCompareKeyV1(w.frames[w.oldN-1].old, next); {
	case c < 0:
		return w.closeOld()
	case c > 0:
		return w.emitNode(w.buildNew())
	default:
		return w.closeCommon()
	}
}

func (w *treeWalkV1) closeOld() error {
	w.oldN--
	if w.emit == nil {
		return nil
	}
	return w.emit.emitV1(treeTargetV1{dbi: TreeSchemaV1DBIs()[8], key: w.nodeKey(w.frames[w.oldN].old)})
}

func (w *treeWalkV1) closeCommon() error {
	w.oldN--
	node, n := w.buildNew()
	if bytes.Equal(w.frames[w.oldN].oldValue[:n], w.valBuf[:n]) {
		return nil
	}
	return w.emitNode(node, n)
}

// buildNew closes the NEW chain top (a stream leaf, else the deepest open branch) into cur and its value in valBuf.
func (w *treeWalkV1) buildNew() (treeNodeRefV1, int) {
	if w.curLeaf {
		w.curLeaf = false
		copy(w.valBuf[:32], w.cur.digest[:])
		return w.cur, 32
	}
	w.openN--
	f := &w.frames[w.openN]
	zero, one := f.zero, w.cur
	node := treeNodeRefV1{key: f.open.key, depth: f.open.depth}
	node.digest = treeBranchDigestV1(node.id(), zero.digest, one.digest)
	treeSuffixV1(w.valBuf[0:38], zero)
	copy(w.valBuf[38:70], zero.digest[:])
	treeSuffixV1(w.valBuf[70:108], one)
	copy(w.valBuf[108:140], one.digest[:])
	w.kidZero, w.kidOne, w.cur = zero, one, node
	return node, 140
}

func (w *treeWalkV1) emitNode(node treeNodeRefV1, n int) error {
	w.cur.emitted = true
	if w.emit == nil {
		return nil
	}
	target := treeTargetV1{dbi: TreeSchemaV1DBIs()[8], key: w.nodeKey(node), after: treeImageV1{present: true, value: w.valBuf[:n]}}
	if err := w.emit.emitV1(target); err != nil {
		return err
	}
	if n == 32 {
		return nil
	}
	if err := w.referIfKept(w.kidZero); err != nil {
		return err
	}
	return w.referIfKept(w.kidOne)
}

func (w *treeWalkV1) referIfKept(node treeNodeRefV1) error {
	if node.emitted {
		return nil
	}
	return w.emit.referV1(TreeSchemaV1DBIs()[8], w.nodeKey(node))
}

func (w *treeWalkV1) finish(binding RootBindingV1, endpoint TreeEndpointV1) error {
	next := binding
	next.Endpoint = endpoint
	next.RootDigest, next.Top = treeEmptyDigestV1(), TreeTopV1{Kind: TreeTopEmptyV1}
	if w.hasCur {
		id := w.cur.id()
		next.RootDigest, next.Top = w.cur.digest, TreeTopV1{Kind: TreeTopKindV1(id.Kind), Node: &id}
	}
	encoded, err := next.Encode()
	if err != nil {
		return treeIntegrity(operationUpdate, err)
	}
	if w.emit == nil {
		return nil
	}
	if w.hasCur {
		if err := w.referIfKept(w.cur); err != nil {
			return err
		}
	}
	return w.emit.emitV1(treeTargetV1{dbi: TreeSchemaV1DBIs()[0], key: w.metaKey[:], after: treeImageV1{present: true, value: encoded}})
}

// nodeKey builds the 46-byte form byte-equal to TreeNodeKey(generation, id) in keyBuf.
func (w *treeWalkV1) nodeKey(node treeNodeRefV1) []byte {
	binary.BigEndian.PutUint64(w.keyBuf[:8], w.generation)
	treeSuffixV1(w.keyBuf[8:], node)
	return w.keyBuf[:]
}

func (f *treeFrameV1) child(side uint8) treeNodeRefV1 {
	off := 70 * int(side)
	id, _ := decodeTreeSuffix(f.oldValue[off : off+38])
	var digest [32]byte
	copy(digest[:], f.oldValue[off+38:off+70])
	return treeRefOfID(id, digest)
}

func (f *treeFrameV1) recordDigest() [32]byte {
	var out, zero, one [32]byte
	if f.old.depth == 288 {
		copy(out[:], f.oldValue[:32])
		return out
	}
	copy(zero[:], f.oldValue[38:70])
	copy(one[:], f.oldValue[108:140])
	return treeBranchDigestV1(f.old.id(), zero, one)
}

func (r treeNodeRefV1) id() TreeNodeIDV1 {
	if r.depth == 288 {
		return TreeNodeIDV1{Kind: TreeNodeLeafV1, RoutingKey: r.key, Depth: 288}
	}
	return TreeNodeIDV1{Kind: TreeNodeBranchV1, Depth: r.depth, Prefix: r.key}
}

func treeRefOfID(id TreeNodeIDV1, digest [32]byte) treeNodeRefV1 {
	if id.Kind == TreeNodeLeafV1 {
		return treeNodeRefV1{key: id.RoutingKey, depth: 288, digest: digest}
	}
	return treeNodeRefV1{key: id.Prefix, depth: id.Depth, digest: digest}
}

// treeRecordOKV1 is DecodeTreeNodeValue's accept set without allocation.
func treeRecordOKV1(node treeNodeRefV1, value []byte) bool {
	if node.depth == 288 {
		return len(value) == 32
	}
	if len(value) != 140 {
		return false
	}
	zero, errZero := decodeTreeSuffix(value[0:38])
	one, errOne := decodeTreeSuffix(value[70:108])
	id := node.id()
	return all(errZero == nil, errOne == nil) && treeChildFits(id, zero, 0) && treeChildFits(id, one, 1)
}

func treeUpperV1(node treeNodeRefV1) [36]byte {
	if node.depth == 288 {
		return node.key
	}
	return treeMask(node.key, node.depth, true)
}

func treeSuffixV1(dst []byte, node treeNodeRefV1) {
	upper := treeUpperV1(node)
	copy(dst[:36], upper[:])
	binary.BigEndian.PutUint16(dst[36:38], 288-node.depth)
}

func treeContainsV1(node treeNodeRefV1, key [36]byte) bool {
	if node.depth == 288 {
		return node.key == key
	}
	return treeMask(key, node.depth, false) == node.key
}

// treeCompareKeyV1 orders two nodes by TreeNodeKey: upper bound, then the greater depth first.
func treeCompareKeyV1(a, b treeNodeRefV1) int {
	ua, ub := treeUpperV1(a), treeUpperV1(b)
	if c := bytes.Compare(ua[:], ub[:]); c != 0 {
		return c
	}
	switch {
	case a.depth > b.depth:
		return -1
	case a.depth < b.depth:
		return 1
	}
	return 0
}

func treeBelowV1(a, x [36]byte, inclusive bool) bool {
	c := bytes.Compare(a[:], x[:])
	return c < 0 || (inclusive && c == 0)
}

// treeFirstDiffV1 is the first bit at which a and b differ; the caller guarantees a != b.
func treeFirstDiffV1(a, b [36]byte) uint16 {
	d := uint16(0)
	for a[d/8] == b[d/8] {
		d += 8
	}
	for x := a[d/8] ^ b[d/8]; x&0x80 == 0; x <<= 1 {
		d++
	}
	return d
}
