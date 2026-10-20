//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unsafe"
)

// tdScene is the A4 primitive (height 7, generation 9, TxCount 3): CREATE kB (tx 0, coinbase); SPEND kA (tx 1,
// in 0); CREATE kC (tx 1); SPEND kC (tx 2, in 0); SPEND kD (tx 2, in 1); CREATE kD (tx 2) with a new value. Every
// key and value below is built from the schema layouts in this file.
type tdScene struct {
	c               tdCase
	kA, kB, kC, kD  []byte
	eA, eD, mK, man []byte
	vA, vD, nB, nD  []byte
	fB, fC, fD      []byte
}

var tdGen = [16]byte{0: 0x47, 15: 0x01}

func tdA4(dir, undo uint8) tdScene {
	block, gen := tdTxid(0xbb), uint64(9)
	ta, tb, tc, td := tdTxid(0x0a), tdTxid(0x0b), tdTxid(0x0c), tdTxid(0x0d)
	s := tdScene{fB: tdFrame(500, 0, nil), fC: tdFrame(600, 0, []byte{0xc1}), fD: tdFrame(700, 0, []byte{0xd1, 0xd2})}
	body := append(append(append([]byte(nil), s.fB...), s.fC...), s.fD...)
	oc, od := uint64(len(s.fB)), uint64(len(s.fB)+len(s.fC))
	s.c = tdCase{dir: dir, undo: undo, height: 7, gen: gen, block: block, generated: tdGen, txCount: 3, body: body, events: []tdEv{
		tdCreate(tb, 0, 0, 0, uint32(len(s.fB))), tdSpend(ta, 0, 1, 0), tdCreate(tc, 0, 1, oc, uint32(len(s.fC))),
		tdSpend(tc, 0, 2, 0), tdSpend(td, 0, 2, 1), tdCreate(td, 0, 2, od, uint32(len(s.fD))),
	}}
	s.kA, s.kB, s.kC, s.kD = tdUTXOKey(gen, ta, 0), tdUTXOKey(gen, tb, 0), tdUTXOKey(gen, tc, 0), tdUTXOKey(gen, td, 0)
	s.eA, s.eD, s.mK = tdEntryKey(block, ta, 1, 0, 0), tdEntryKey(block, td, 2, 1, 0), tdManifestKey(block)
	s.man = tdManifest(7, tdGen, 3, 2)
	s.vA, s.vD = tdFormed(tdFrame(11, 0, []byte{0xa1}), 3, 0), tdFormed(tdFrame(12, 0, nil), 4, 1)
	s.nB, s.nD = tdFormed(s.fB, 7, 1), tdFormed(s.fD, 7, 0)
	return s
}

func (s tdScene) pre() []tdMemRow {
	return []tdMemRow{{4, s.c.block[:], s.c.body}, {1, s.kA, s.vA}, {1, s.kD, s.vD}}
}

func (s tdScene) post() []tdMemRow {
	return []tdMemRow{{4, s.c.block[:], s.c.body}, {1, s.kB, s.nB}, {1, s.kD, s.nD}}
}

func (s tdScene) family() []tdMemRow {
	return []tdMemRow{{5, s.mK, s.man}, {5, s.eA, s.vA}, {5, s.eD, s.vD}}
}

func tdStore(t *testing.T, rows ...[]tdMemRow) *Store {
	t.Helper()
	store, _ := ttStore(t)
	for _, set := range rows {
		for _, row := range set {
			treeNativeSeed(t, store, row.rank, slices.Clone(row.key), slices.Clone(row.value))
		}
	}
	return store
}

func tdRef(rank uint8, key []byte) string { return fmt.Sprintf("refer %d %x", rank, key) }
func tdDel(rank uint8, key []byte) string { return fmt.Sprintf("emit %d %x -", rank, key) }
func tdPut(rank uint8, key, value []byte) string {
	return fmt.Sprintf("emit %d %x + %x", rank, key, value)
}

// tdRec logs every call at call time, then forwards to next when set.
type tdRec struct {
	log  []string
	next treeEmitterV1
}

func (e *tdRec) emitV1(target treeTargetV1) error {
	if target.after.present {
		e.log = append(e.log, tdPut(target.dbi.Rank, target.key, target.after.value))
	} else {
		e.log = append(e.log, tdDel(target.dbi.Rank, target.key))
	}
	if e.next == nil {
		return nil
	}
	return e.next.emitV1(target)
}

func (e *tdRec) referV1(dbi DBI, key []byte) error {
	e.log = append(e.log, tdRef(dbi.Rank, key))
	if e.next == nil {
		return nil
	}
	return e.next.referV1(dbi, key)
}

// tdOld forwards every read, logs it (requested key for getV1, returned key for nextV1), may fail a call and may
// overlay one utxo-v1 value (a LAG intermediate).
type tdOld struct {
	inner   treeOldV1
	log     []string
	fail    func(n int, method string) error
	overlay map[string][]byte
}

func (o *tdOld) getV1(dbi DBI, key []byte) (treeImageV1, error) {
	n := len(o.log)
	o.log = append(o.log, fmt.Sprintf("get %d %x", dbi.Rank, key))
	if o.fail != nil {
		if err := o.fail(n, "get"); err != nil {
			return treeImageV1{}, err
		}
	}
	if value, ok := o.overlay[string(key)]; ok && dbi.Rank == 1 {
		return treeImageV1{present: true, value: value}, nil
	}
	return o.inner.getV1(dbi, key)
}

func (o *tdOld) nextV1(dbi DBI, from []byte) ([]byte, treeImageV1, bool, error) {
	n := len(o.log)
	if o.fail != nil {
		if err := o.fail(n, "next"); err != nil {
			o.log = append(o.log, fmt.Sprintf("next %d failed", dbi.Rank))
			return nil, treeImageV1{}, false, err
		}
	}
	key, image, ok, err := o.inner.nextV1(dbi, from)
	if ok && bytes.HasPrefix(key, from[:min(len(from), 32)]) {
		o.log = append(o.log, fmt.Sprintf("next %d %x", dbi.Rank, key))
	} else {
		o.log = append(o.log, fmt.Sprintf("next %d outside", dbi.Rank))
	}
	return key, image, ok, err
}

func (o *tdOld) undoReads() int {
	n := 0
	for _, line := range o.log {
		if strings.HasPrefix(line, "next 5") || strings.HasPrefix(line, "get 5") {
			n++
		}
	}
	return n
}

type tdOut struct {
	err    error
	log    []string
	leaves []string
	reads  []string
	undo   int
}

type tdOpt struct {
	fail    func(n int, method string) error
	overlay map[string][]byte
	pair    bool
}

func tdLeaves(d *treeDeltaV1) []string {
	var out []string
	it := d.leavesV1()
	for {
		leaf, ok, err := it.nextV1()
		if err != nil || !ok {
			return out
		}
		out = append(out, fmt.Sprintf("%x %v %v %x", leaf.key, leaf.oldPresent, leaf.newPresent, leaf.newValue))
	}
}

// tdRunAt resolves and, on success, applies c at pos over the store's ORIGINAL OLD.
func tdRunAt(t *testing.T, store *Store, c tdCase, pos treePositionV1, opt tdOpt) tdOut {
	t.Helper()
	c.pair = opt.pair
	var out tdOut
	run := func(inner treeOldV1, ledger treeLedgerV1) error {
		old := &tdOld{inner: inner, fail: opt.fail, overlay: opt.overlay}
		r, d := c.delta(t, pos, ledger)
		defer r.releaseV1()
		out.err = d.resolveV1(old)
		out.reads, out.undo = old.log, old.undoReads()
		if out.err != nil {
			return nil
		}
		rec := &tdRec{}
		mustEnvironment(t, d.applyV1(rec))
		out.log, out.leaves = rec.log, tdLeaves(d)
		return nil
	}
	if pos == treeWriterV1 {
		mustEnvironment(t, fixtureTreeSectionV1(store, &tdLedger{}, func(s *treeSectionV1) error { return run(s.oldV1(true), &tdLedger{}) }))
	} else {
		budget := &treeBudgetV1{held: 1 << 30}
		mustEnvironment(t, fixtureTreeOldV1(store, func(old treeOldV1) error { return run(old, budget.ledgerV1()) }))
	}
	tdDisjoint(t, out.log)
	return out
}

// tdBoth runs both positions and requires the same result, emission log and leaves (S9).
func tdBoth(t *testing.T, store *Store, c tdCase, opt tdOpt) tdOut {
	t.Helper()
	w := tdRunAt(t, store, c, treeWriterV1, opt)
	r := tdRunAt(t, store, c, treeReadbackV1, opt)
	if fmt.Sprint(w.err) != fmt.Sprint(r.err) || !slices.Equal(w.log, r.log) || !slices.Equal(w.leaves, r.leaves) {
		t.Fatalf("positions differ:\nwriter %v %v\nreadback %v %v", w.err, w.log, r.err, r.log)
	}
	return w
}

// tdDisjoint: no referV1 key is also an emitV1 key (A14).
func tdDisjoint(t *testing.T, log []string) {
	t.Helper()
	emitted := map[string]bool{}
	for _, line := range log {
		if f := strings.Fields(line); f[0] == "emit" {
			emitted[f[1]+f[2]] = true
		}
	}
	for _, line := range log {
		if f := strings.Fields(line); f[0] == "refer" && emitted[f[1]+f[2]] {
			t.Fatalf("identity both referred and emitted: %s", line)
		}
	}
}

func tdLog(t *testing.T, name string, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s:\n got %q\nwant %q", name, got, want)
	}
}

func tdLeaf(key []byte, old, created bool, value []byte) string {
	return fmt.Sprintf("%x %v %v %x", key, old, created, value)
}

// tdIntegrity asserts the treeIntegrity tuple and its cause by identity; errSchema also by errors.Is.
func tdIntegrity(t *testing.T, err, cause error) {
	t.Helper()
	treeNativeIntegrity(t, err, operationUpdate, cause)
	if errors.Is(err, errSchema) != (cause == errSchema) {
		t.Fatalf("errors.Is(err, errSchema) = %v", errors.Is(err, errSchema))
	}
}

// tdFail returns a tdOut-only integrity check with zero emission.
func tdRefused(t *testing.T, name string, out tdOut, cause error) {
	t.Helper()
	if out.err == nil {
		t.Fatalf("%s: resolveV1 returned nil", name)
	}
	tdIntegrity(t, out.err, cause)
	if len(out.log) != 0 {
		t.Fatalf("%s: emitted %v", name, out.log)
	}
}

// A4, A11, A16, M11, M12: the four presence cases, forward WriteOrReuse with the family absent, both positions.
func TestTreeDeltaPresenceCasesV1(t *testing.T) {
	s := tdA4(1, 1)
	out := tdBoth(t, tdStore(t, s.pre()), s.c, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "A4", out.log, tdRef(4, s.c.block[:]), tdPut(1, s.kB, s.nB), tdPut(5, s.eA, s.vA), tdDel(1, s.kA),
		tdRef(1, s.kC), tdPut(5, s.eD, s.vD), tdPut(1, s.kD, s.nD), tdPut(5, s.mK, s.man))
	tdLog(t, "A4 leaves", out.leaves, tdLeaf(s.kA, true, false, nil), tdLeaf(s.kB, false, true, s.nB), tdLeaf(s.kD, true, true, s.nD))
}

// A5: a LAG intermediate served by the overlay is the regenerated entry value.
func TestTreeDeltaLagIntermediateV1(t *testing.T) {
	s := tdA4(1, 1)
	lag := tdFormed(tdFrame(99, 0, []byte{9, 9}), 6, 0)
	store := tdStore(t, [][]tdMemRow{s.pre()[:1], s.pre()[2:]}...)
	out := tdBoth(t, store, s.c, tdOpt{overlay: map[string][]byte{string(s.kA): lag}})
	mustEnvironment(t, out.err)
	if out.log[2] != tdPut(5, s.eA, lag) {
		t.Fatalf("A5 entry %s", out.log[2])
	}
}

// A6, A11, A14, M13, M23: a byte-identical family is reused and referred.
func TestTreeDeltaReuseV1(t *testing.T) {
	s := tdA4(1, 1)
	out := tdBoth(t, tdStore(t, s.pre(), s.family()), s.c, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "A6", out.log, tdRef(4, s.c.block[:]), tdPut(1, s.kB, s.nB), tdRef(5, s.eA), tdDel(1, s.kA),
		tdRef(1, s.kC), tdRef(5, s.eD), tdPut(1, s.kD, s.nD), tdRef(5, s.mK))
}

// A7, A11, A14, M14: Transient reads, protects and emits nothing of the family.
func TestTreeDeltaTransientV1(t *testing.T) {
	s := tdA4(1, 2)
	out := tdBoth(t, tdStore(t, s.pre()), s.c, tdOpt{})
	mustEnvironment(t, out.err)
	if out.undo != 0 {
		t.Fatalf("A7 undo-v1 reads %v", out.reads)
	}
	tdLog(t, "A7", out.log, tdRef(4, s.c.block[:]), tdPut(1, s.kB, s.nB), tdDel(1, s.kA), tdRef(1, s.kC), tdPut(1, s.kD, s.nD))
}

// A8, A11, A14, M15, M22, M24, M31, M32: Compare refers the identical family; CompareDelete deletes it.
func TestTreeDeltaCompareV1(t *testing.T) {
	s := tdA4(1, 3)
	store := tdStore(t, s.pre(), s.family())
	out := tdBoth(t, store, s.c, tdOpt{})
	mustEnvironment(t, out.err)
	compare := []string{
		tdRef(4, s.c.block[:]), tdPut(1, s.kB, s.nB), tdRef(5, s.eA), tdDel(1, s.kA),
		tdRef(1, s.kC), tdRef(5, s.eD), tdPut(1, s.kD, s.nD), tdRef(5, s.mK),
	}
	tdLog(t, "A8 Compare", out.log, compare...)
	pair := tdBoth(t, store, s.c, tdOpt{pair: true})
	tdLog(t, "A14 Pair body", pair.log, compare[1:]...)
	s.c.undo = 4
	out = tdBoth(t, store, s.c, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "A8 CompareDelete", out.log, tdRef(4, s.c.block[:]), tdPut(1, s.kB, s.nB), tdDel(5, s.eA), tdDel(1, s.kA),
		tdRef(1, s.kC), tdDel(5, s.eD), tdPut(1, s.kD, s.nD), tdDel(5, s.mK))
}

// A9, A11, A14, M16, M17: inverse SourceRetain restores entries and refers the family; SourceDelete deletes it.
func TestTreeDeltaInverseV1(t *testing.T) {
	s := tdA4(2, 5)
	store := tdStore(t, s.post(), s.family())
	out := tdBoth(t, store, s.c, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "A9 SourceRetain", out.log, tdRef(4, s.c.block[:]), tdDel(1, s.kB), tdPut(1, s.kA, s.vA), tdRef(5, s.eA),
		tdRef(1, s.kC), tdPut(1, s.kD, s.vD), tdRef(5, s.eD), tdRef(5, s.mK))
	tdLog(t, "A9 leaves", out.leaves, tdLeaf(s.kA, false, true, s.vA), tdLeaf(s.kB, true, false, nil), tdLeaf(s.kD, true, true, s.vD))
	s.c.undo = 6
	out = tdBoth(t, store, s.c, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "A9 SourceDelete", out.log, tdRef(4, s.c.block[:]), tdDel(1, s.kB), tdPut(1, s.kA, s.vA), tdDel(5, s.eA),
		tdRef(1, s.kC), tdPut(1, s.kD, s.vD), tdDel(5, s.eD), tdDel(5, s.mK))
}

// A10, A16: zero SPEND-first groups give spentCount 0 and no entry; leaves still flow.
func TestTreeDeltaZeroSpentV1(t *testing.T) {
	s := tdA4(1, 1)
	s.c.events = s.c.events[:1]
	s.c.txCount = 1
	out := tdBoth(t, tdStore(t, s.pre()[:1]), s.c, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "A10", out.log, tdRef(4, s.c.block[:]), tdPut(1, s.kB, s.nB), tdPut(5, s.mK, tdManifest(7, tdGen, 1, 0)))
	// A16: zero net-dirty groups: an equal-bytes present/present group yields no leaf while the family is regenerated.
	s.c.events = []tdEv{tdSpend(tdTxid(0x0b), 0, 1, 0), tdCreate(tdTxid(0x0b), 0, 1, 0, uint32(len(s.fB)))}
	s.c.txCount = 2
	same := tdFormed(s.fB, 7, 0)
	out = tdBoth(t, tdStore(t, []tdMemRow{{4, s.c.block[:], s.c.body}, {1, s.kB, same}}), s.c, tdOpt{})
	mustEnvironment(t, out.err)
	entry := tdEntryKey(s.c.block, tdTxid(0x0b), 1, 0, 0)
	tdLog(t, "A16 zero dirty", out.log, tdRef(4, s.c.block[:]), tdPut(5, entry, same), tdRef(1, s.kB), tdPut(5, s.mK, tdManifest(7, tdGen, 2, 1)))
	if len(out.leaves) != 0 {
		t.Fatalf("A16 leaves %v", out.leaves)
	}
}

// A3 (absent/absent), A12, A18, M20, M34: cancellations and equal rewrites are referred, never leaves or targets.
func TestTreeDeltaNotDirtyV1(t *testing.T) {
	s := tdA4(1, 1)
	k, k2 := tdTxid(0x50), tdTxid(0x51)
	frame := s.fB
	s.c.body = append(append([]byte(nil), frame...), frame...)
	s.c.events = []tdEv{tdCreate(k, 0, 1, 0, uint32(len(frame))), tdSpend(k, 0, 2, 0), tdSpend(k2, 0, 2, 1), tdCreate(k2, 0, 2, uint64(len(frame)), uint32(len(frame)))}
	key, key2, kept := tdUTXOKey(9, k, 0), tdUTXOKey(9, k2, 0), tdFormed(frame, 7, 0)
	// k is created and spent in the block (absent/absent); k2 is spent and recreated with the exact stored bytes.
	store := tdStore(t, []tdMemRow{{4, s.c.block[:], s.c.body}, {1, key2, kept}})
	out := tdBoth(t, store, s.c, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "A3/A18", out.log, tdRef(4, s.c.block[:]), tdRef(1, key), tdPut(5, tdEntryKey(s.c.block, k2, 2, 1, 0), kept),
		tdRef(1, key2), tdPut(5, s.mK, tdManifest(7, tdGen, 3, 1)))
	if len(out.leaves) != 0 {
		t.Fatalf("A12 leaves %v", out.leaves)
	}
	// A12: two leaves iterators yield identical sequences (drained one after the other, T2).
	s4 := tdA4(1, 1)
	mustEnvironment(t, fixtureTreeOldV1(tdStore(t, s4.pre()), func(old treeOldV1) error {
		_, d := s4.c.delta(t, treeWriterV1, &tdLedger{})
		mustEnvironment(t, d.resolveV1(old))
		first, second := tdLeaves(d), tdLeaves(d)
		if len(first) != 3 || !slices.Equal(first, second) {
			t.Fatalf("A12 %v / %v", first, second)
		}
		return nil
	}))
}

// A17, R9, M33: the stored body is read once and aliased; an absent row is integrity; a source error passes through.
func TestTreeDeltaStoredBodyV1(t *testing.T) {
	block := tdTxid(0x77)
	body := []byte("seeded block body")
	store := tdStore(t, []tdMemRow{{4, block[:], body}})
	mustEnvironment(t, fixtureTreeOldV1(store, func(inner treeOldV1) error {
		old := &tdOld{inner: inner}
		got, err := treeStoredBodyV1(old, block)
		if err != nil || got.pair || !bytes.Equal(got.bytes, body) || len(old.log) != 1 || old.log[0] != fmt.Sprintf("get 4 %x", block) {
			t.Fatalf("A17 %v %v %v", got, err, old.log)
		}
		_, err = treeStoredBodyV1(old, tdTxid(0x78))
		tdIntegrity(t, err, nil)
		sentinel := errors.New("sentinel")
		_, err = treeStoredBodyV1(&tdOld{inner: inner, fail: func(int, string) error { return sentinel }}, block)
		if !sameError(err, sentinel) {
			t.Fatalf("R9 sentinel %v", err)
		}
		return nil
	}))
}

// A20, M44: targets are emitted in the order of their groups' first events, not in key order.
func TestTreeDeltaEmissionOrderV1(t *testing.T) {
	s := tdA4(1, 2)
	z, a := tdTxid(0xf0), tdTxid(0x01)
	s.c.txCount = 3
	s.c.body = append(append([]byte(nil), s.fB...), s.fB...)
	s.c.events = []tdEv{tdCreate(z, 0, 1, 0, uint32(len(s.fB))), tdCreate(a, 0, 2, uint64(len(s.fB)), uint32(len(s.fB)))}
	out := tdBoth(t, tdStore(t, s.pre()[:1]), s.c, tdOpt{})
	mustEnvironment(t, out.err)
	value := tdFormed(s.fB, 7, 0)
	tdLog(t, "A20", out.log, tdRef(4, s.c.block[:]), tdPut(1, tdUTXOKey(9, z, 0), value), tdPut(1, tdUTXOKey(9, a, 0), value))
}

// tdA21 is the A21 primitive: e1 CREATE kB (tx 0); e2 SPEND kA (tx 1); e3 CREATE kC (tx 1); e4 SPEND kC (tx 2);
// e5 SPEND kD (tx 2, in 1).
func tdA21(dir, undo uint8) tdScene {
	s := tdA4(dir, undo)
	s.c.events = s.c.events[:5]
	s.c.body = append(append([]byte(nil), s.fB...), s.fC...)
	return s
}

// A21, M45, M-VF-STALE, M-UNDO-I: the S11 emission sequence at both positions.
func TestTreeDeltaEmissionSequenceV1(t *testing.T) {
	s := tdA21(1, 1)
	pre := []tdMemRow{{4, s.c.block[:], s.c.body}, {1, s.kA, s.vA}, {1, s.kD, s.vD}}
	out := tdBoth(t, tdStore(t, pre), s.c, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "A21 (a)", out.log, tdRef(4, s.c.block[:]), tdPut(1, s.kB, s.nB), tdPut(5, s.eA, s.vA), tdDel(1, s.kA),
		tdRef(1, s.kC), tdPut(5, s.eD, s.vD), tdDel(1, s.kD), tdPut(5, s.mK, s.man))
	inv := tdA21(2, 6)
	post := []tdMemRow{{4, s.c.block[:], s.c.body}, {1, s.kB, s.nB}}
	out = tdBoth(t, tdStore(t, post, s.family()), inv.c, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "A21 (b)", out.log, tdRef(4, s.c.block[:]), tdDel(1, s.kB), tdPut(1, s.kA, s.vA), tdDel(5, s.eA),
		tdRef(1, s.kC), tdPut(1, s.kD, s.vD), tdDel(5, s.eD), tdDel(5, s.mK))
	cmp := tdA21(1, 3)
	out = tdBoth(t, tdStore(t, pre, s.family()), cmp.c, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "A21 (c)", out.log, tdRef(4, s.c.block[:]), tdPut(1, s.kB, s.nB), tdRef(5, s.eA), tdDel(1, s.kA),
		tdRef(1, s.kC), tdRef(5, s.eD), tdDel(1, s.kD), tdRef(5, s.mK))
}

// R3, M7, M8: the covenant check reads the bound body, never the window.
func TestTreeDeltaCovenantV1(t *testing.T) {
	block := tdTxid(0x66)
	f2, f3, f0 := tdFrame(1, 0x0002, nil), tdFrame(1, 0x0103, nil), tdFrame(1, 0, nil)
	native := append(append(append([]byte(nil), f2...), f3...), f0...)
	store := tdStore(t, []tdMemRow{{4, block[:], native}})
	mustEnvironment(t, fixtureTreeOldV1(store, func(old treeOldV1) error {
		body, err := treeStoredBodyV1(old, block)
		mustEnvironment(t, err)
		c := tdCase{dir: 1, undo: 2, height: 7, gen: 9, block: block, txCount: 2, body: body.bytes}
		for i, admitted := range []bool{false, false, true} {
			r := newTreeRecorderV1(treeWriterV1, c.prim(), body, make([]byte, 65_536), &tdLedger{})
			mustEnvironment(t, r.beginV1(2, 1, [16]byte{}))
			err := tdCreate(tdTxid(1), 0, 1, uint64(11*i), 11).feed(r)
			if admitted {
				mustEnvironment(t, err)
				continue
			}
			tdInvalid(t, err)
			if !sameError(r.failureV1(), err) {
				t.Fatal("covenant refusal not recorded")
			}
		}
		c.events = []tdEv{tdCreate(tdTxid(1), 0, 1, uint64(len(native)), 11)}
		_, d := c.delta(t, treeWriterV1, &tdLedger{})
		tdIntegrity(t, d.resolveV1(old), nil)
		return nil
	}))
}

// tdVariant builds one rejected input from the A4 scene: store rows and the case.
type tdVariant struct {
	name  string
	rows  []tdMemRow
	c     tdCase
	cause error
}

func tdReplace(rows []tdMemRow, key, value []byte) []tdMemRow {
	out := slices.Clone(rows)
	for i := range out {
		if bytes.Equal(out[i].key, key) {
			out[i].value = value
		}
	}
	return out
}

func tdDrop(rows []tdMemRow, key []byte) []tdMemRow {
	return slices.DeleteFunc(slices.Clone(rows), func(row tdMemRow) bool { return bytes.Equal(row.key, key) })
}

func tdFlip(b []byte, i int) []byte {
	out := slices.Clone(b)
	out[i] ^= 0x01
	return out
}

// tdFrameVariant replaces the body so that kB's frame (offset 0) is bad and keeps every other frame position.
func tdFrameVariant(s tdScene, frame []byte) tdCase {
	c := s.c
	c.body = append(append([]byte(nil), frame...), c.body[len(s.fB):]...)
	c.events = slices.Clone(c.events)
	c.events[0].n = uint32(len(frame))
	delta := uint64(len(frame)) - uint64(len(s.fB))
	c.events[2].off += delta
	c.events[5].off += delta
	return c
}

func tdRejected() []tdVariant {
	f, r, i := tdA4(1, 3), tdA4(2, 5), tdA4(2, 5)
	pre, fam, post := f.pre(), f.family(), r.post()
	extra := tdEntryKey(f.c.block, tdTxid(0x01), 1, 0, 0)
	wor, cmp := f.c, f.c
	wor.undo = 1
	short := f.c
	short.body = short.body[:len(short.body)-1]
	nonMinimal := append(tdFrame(1, 0, nil)[:10], 0xfd, 2, 0, 7, 7)
	inconsistent := tdFrame(1, 0, []byte{1, 2})[:12]
	srDelete := r.c
	srDelete.undo = 6
	malformedPost := append(slices.Clone(r.nB[:19]), 2)
	return []tdVariant{
		{"frame past body", pre, short, nil},
		{"non-minimal CompactSize", pre, tdFrameVariant(f, nonMinimal), nil},
		{"inconsistent CompactSize", pre, tdFrameVariant(f, inconsistent), nil},
		{"forward SPEND-first absent", tdDrop(pre, f.kA), wor, nil},
		{"forward CREATE-first present", append(slices.Clone(pre), tdMemRow{1, f.kB, f.nB}), wor, nil},
		{"inverse CREATE-last absent", append(tdDrop(post, r.kB), fam...), r.c, nil},
		{"inverse CREATE-last differs", append(tdReplace(post, r.kB, tdFlip(r.nB, 0)), fam...), r.c, nil},
		{"Compare family absent", pre, cmp, nil},
		{"Compare entry byte", append(slices.Clone(pre), tdReplace(fam, f.eA, tdFlip(f.vA, 3))...), cmp, nil},
		{"Compare manifest byte", append(slices.Clone(pre), tdReplace(fam, f.mK, tdFlip(f.man, 5))...), cmp, nil},
		{"Compare 1-byte entry (R-CMP-1)", append(slices.Clone(pre), tdReplace(fam, f.eD, []byte{1})...), cmp, nil},
		{"WriteOrReuse extra entry", append(slices.Clone(pre), append(slices.Clone(fam), tdMemRow{5, extra, f.vA})...), wor, nil},
		{"WriteOrReuse missing entry", append(slices.Clone(pre), tdDrop(fam, f.eD)...), wor, nil},
		{"WriteOrReuse entry byte", append(slices.Clone(pre), tdReplace(fam, f.eD, tdFlip(f.vD, 2))...), wor, nil},
		{"WriteOrReuse 1-byte manifest (R-WOR-1)", append(slices.Clone(pre), tdReplace(fam, f.mK, []byte{1})...), wor, nil},
		{"entry without manifest", append(slices.Clone(pre), tdDrop(fam, f.mK)...), wor, nil},
		{"SourceRetain missing entry", append(slices.Clone(post), tdDrop(fam, f.eA)...), r.c, nil},
		{"SourceRetain extra entry", append(slices.Clone(post), append(slices.Clone(fam), tdMemRow{5, extra, f.vA})...), r.c, nil},
		{"SourceRetain manifest height", append(slices.Clone(post), tdReplace(fam, f.mK, tdManifest(8, tdGen, 3, 2))...), r.c, nil},
		{"SourceRetain manifest txCount", append(slices.Clone(post), tdReplace(fam, f.mK, tdManifest(7, tdGen, 4, 2))...), r.c, nil},
		{"SourceRetain manifest spentCount", append(slices.Clone(post), tdReplace(fam, f.mK, tdManifest(7, tdGen, 3, 3))...), r.c, nil},
		{"SourceRetain 32-byte manifest", append(slices.Clone(post), tdReplace(fam, f.mK, f.man[:32])...), r.c, errSchema},
		{"SourceDelete 19-byte entry", append(slices.Clone(post), tdReplace(fam, f.eD, f.vD[:19])...), srDelete, errSchema},
		{"inverse malformed post value (D18)", append(tdReplace(post, i.kB, malformedPost), fam...), i.c, nil},
	}
}

// R4, R-WOR-1, R-CMP-1, M16-M19, M28, M54, M55, M-OLDV-INVERSE: integrity before any emission, cause per S10.
func TestTreeDeltaRejectedV1(t *testing.T) {
	for _, v := range tdRejected() {
		out := tdRunAt(t, tdStore(t, v.rows), v.c, treeWriterV1, tdOpt{})
		tdRefused(t, v.name, out, v.cause)
	}
}

// R6: a source error is returned unchanged by identity.
func TestTreeDeltaSourceErrorV1(t *testing.T) {
	s := tdA4(1, 1)
	store := tdStore(t, s.pre())
	for _, e := range []error{errors.New("sentinel"), treeSnapshotMismatchV1()} {
		out := tdRunAt(t, store, s.c, treeWriterV1, tdOpt{fail: func(_ int, method string) error {
			if method == "get" {
				return e
			}
			return nil
		}})
		if !sameError(out.err, e) || len(out.log) != 0 {
			t.Fatalf("R6 %v", out.err)
		}
	}
}

// R10, M39, M40, M41: the undo value check accepts exactly validateUndoValue's set; refusals carry errSchema.
func TestTreeDeltaUndoValueCheckV1(t *testing.T) {
	s := tdA4(2, 5)
	entries := tdValueVectors()
	for _, value := range entries {
		accept := validateUndoValue(s.eA, value) == nil
		if treeUndoValueOKV1(s.eA, value) != accept {
			t.Fatalf("entry len %d: accept %v", len(value), accept)
		}
		if accept {
			continue
		}
		out := tdRunAt(t, tdStore(t, s.post(), tdReplace(s.family(), s.eA, value)), s.c, treeWriterV1, tdOpt{})
		tdRefused(t, fmt.Sprintf("entry len %d", len(value)), out, errSchema)
	}
	for _, n := range []int{32, 33, 34} {
		for _, first := range []byte{0, 1, 2} {
			value := slices.Clone(s.man)
			value = append(value, 0)[:n]
			value[0] = first
			accept := validateUndoValue(s.mK, value) == nil
			if treeUndoValueOKV1(s.mK, value) != accept {
				t.Fatalf("manifest len %d first %d", n, first)
			}
			if accept {
				continue
			}
			out := tdRunAt(t, tdStore(t, s.post(), tdReplace(s.family(), s.mK, value)), s.c, treeWriterV1, tdOpt{})
			tdRefused(t, fmt.Sprintf("manifest len %d first %d", n, first), out, errSchema)
		}
	}
}

// tdValueVectors are the R10 / R-OLDV-5 entry-form boundary values: lengths 19, 20, 65,560, 65,561, a non-minimal
// CompactSize, a CompactSize end off by one in each direction, final byte 0, 1, 2.
func tdValueVectors() [][]byte {
	frame := tdFrame(1, 0, []byte{1, 2, 3})
	big := tdFormed(tdFrame(1, 0, make([]byte, 65_536)), 1, 0)
	return [][]byte{
		tdFormed(tdFrame(1, 0, nil), 1, 0)[:19], tdFormed(tdFrame(1, 0, nil), 1, 0), big, append(slices.Clone(big), 0),
		append(append([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0xfd, 3, 0, 1, 2, 3), make([]byte, 9)...),
		append(append(slices.Clone(frame), 0), make([]byte, 9)...), append(slices.Clone(frame[:len(frame)-1]), make([]byte, 9)...),
		tdFormed(frame, 1, 0), tdFormed(frame, 1, 1), tdFormed(frame, 1, 2),
	}
}

// tdTwo is a forward primitive with exactly two SPEND-first groups g1 (kA) and g2 (kD) and no CREATE.
func tdTwo(undo uint8) (tdScene, []tdMemRow) {
	s := tdA4(1, undo)
	s.c.txCount = 2
	s.c.events = []tdEv{tdSpend(tdTxid(0x0a), 0, 1, 0), tdSpend(tdTxid(0x0d), 0, 1, 1)}
	s.eD = tdEntryKey(s.c.block, tdTxid(0x0d), 1, 1, 0)
	s.man = tdManifest(7, tdGen, 2, 2)
	return s, []tdMemRow{{5, s.mK, s.man}, {5, s.eA, s.vA}, {5, s.eD, s.vD}}
}

// R-RO-1..R-RO-4, M50-M52, M53a, M53b: the fixed resolve order, first failure and single reads.
func TestTreeDeltaResolveOrderV1(t *testing.T) {
	mismatch := treeSnapshotMismatchV1()
	always := func(int, string) error { return mismatch }
	s := tdA4(1, 3)
	short := s.c
	short.body = short.body[:len(short.body)-1]
	out := tdRunAt(t, tdStore(t, s.pre(), s.family()), short, treeWriterV1, tdOpt{fail: always})
	tdRefused(t, "R-RO-1", out, nil)
	if len(out.reads) != 0 {
		t.Fatalf("R-RO-1 reads %v", out.reads)
	}
	r := tdA4(2, 5)
	out = tdRunAt(t, tdStore(t, tdDrop(r.post(), r.kB), tdReplace(r.family(), r.mK, r.man[:32])), r.c, treeWriterV1, tdOpt{})
	tdRefused(t, "R-RO-2", out, errSchema)
	tdLog(t, "R-RO-2 reads", out.reads, fmt.Sprintf("next 5 %x", r.mK))
	two, fam := tdTwo(3)
	g1Only := []tdMemRow{{4, two.c.block[:], two.c.body}, {1, two.kA, two.vA}}
	out = tdRunAt(t, tdStore(t, g1Only, fam), two.c, treeWriterV1, tdOpt{fail: func(n int, method string) error {
		if n == 2 && method == "next" {
			return mismatch
		}
		return nil
	}})
	if !sameError(out.err, mismatch) || len(out.log) != 0 {
		t.Fatalf("R-RO-3 %v", out.err)
	}
	tdLog(t, "R-RO-3 reads", out.reads, fmt.Sprintf("next 5 %x", two.mK), fmt.Sprintf("get 1 %x", two.kA), "next 5 failed")
	out = tdRunAt(t, tdStore(t, g1Only, []tdMemRow{{1, two.kD, two.vD}}, fam), two.c, treeWriterV1, tdOpt{})
	mustEnvironment(t, out.err)
	tdLog(t, "R-RO-4 reads", out.reads, fmt.Sprintf("next 5 %x", two.mK), fmt.Sprintf("get 1 %x", two.kA), fmt.Sprintf("next 5 %x", two.eA),
		fmt.Sprintf("get 1 %x", two.kD), fmt.Sprintf("next 5 %x", two.eD), "next 5 outside")
}

// tdMalformedOld is a 20-byte value whose final byte is 2, outside the DecodeUTXOValue accept set.
func tdMalformedOld() []byte { return tdFormed(tdFrame(1, 0, nil), 1, 2) }

// R-OLDV-1..R-OLDV-5, M-OLDV-*: the forward OLD value check (S13).
func TestTreeDeltaOldValueCheckV1(t *testing.T) {
	bad := tdMalformedOld()
	if _, err := DecodeUTXOValue(bad); err == nil {
		t.Fatal("oracle accepts the malformed value")
	}
	s := tdA4(1, 1)
	pre := tdReplace(s.pre(), s.kA, bad)
	getA := fmt.Sprintf("get 1 %x", s.kA)
	out := tdRunAt(t, tdStore(t, pre), s.c, treeWriterV1, tdOpt{})
	tdRefused(t, "R-OLDV-1", out, errSchema)
	if out.reads[len(out.reads)-1] != getA {
		t.Fatalf("R-OLDV-1 reads %v", out.reads)
	}
	cmp := s.c
	cmp.undo = 3
	out = tdRunAt(t, tdStore(t, pre, tdReplace(s.family(), s.eA, bad)), cmp, treeWriterV1, tdOpt{})
	tdRefused(t, "R-OLDV-2", out, errSchema)
	if out.reads[len(out.reads)-1] != getA {
		t.Fatalf("R-OLDV-2 reads %v", out.reads)
	}
	transient := s.c
	transient.undo = 2
	out = tdRunAt(t, tdStore(t, pre), transient, treeWriterV1, tdOpt{})
	mustEnvironment(t, out.err)
	if out.undo != 0 || !slices.Contains(out.log, tdDel(1, s.kA)) {
		t.Fatalf("R-OLDV-3 %v %v", out.reads, out.log)
	}
	out = tdRunAt(t, tdStore(t, pre, tdDrop(s.family(), s.eA)), s.c, treeWriterV1, tdOpt{})
	tdRefused(t, "R-OLDV-4", out, errSchema)
	if out.reads[len(out.reads)-1] != getA {
		t.Fatalf("R-OLDV-4 reads %v", out.reads)
	}
	vectors := tdValueVectors()
	for i, value := range vectors {
		_, oracle := DecodeUTXOValue(value)
		out = tdRunAt(t, tdStore(t, tdReplace(s.pre(), s.kA, value)), s.c, treeWriterV1, tdOpt{})
		if oracle == nil {
			mustEnvironment(t, out.err)
			continue
		}
		tdRefused(t, fmt.Sprintf("R-OLDV-5 vector %d", i), out, errSchema)
	}
}

// tdLW is the lifetime wrapper LW: one instance wraps the old and the emitter. utxo-v1 and undo-v1 images are
// returned as recorded test-owned copies; after an emitV1 or referV1 of an identity returns, its copies become 0xEE.
type tdLW struct {
	old    treeOldV1
	emit   treeEmitterV1
	copies map[string][][]byte
}

func (w *tdLW) keep(dbi DBI, key []byte, image treeImageV1) treeImageV1 {
	if !image.present || dbi.Rank != 1 && dbi.Rank != 5 {
		return image
	}
	held := slices.Clone(image.value)
	id := fmt.Sprintf("%d %x", dbi.Rank, key)
	w.copies[id] = append(w.copies[id], held)
	return treeImageV1{present: true, value: held}
}

func (w *tdLW) getV1(dbi DBI, key []byte) (treeImageV1, error) {
	image, err := w.old.getV1(dbi, key)
	return w.keep(dbi, key, image), err
}

func (w *tdLW) nextV1(dbi DBI, from []byte) ([]byte, treeImageV1, bool, error) {
	key, image, ok, err := w.old.nextV1(dbi, from)
	return key, w.keep(dbi, key, image), ok, err
}

func (w *tdLW) poison(dbi DBI, key []byte) {
	for _, held := range w.copies[fmt.Sprintf("%d %x", dbi.Rank, key)] {
		for i := range held {
			held[i] = 0xee
		}
	}
}

func (w *tdLW) emitV1(target treeTargetV1) error {
	err := w.emit.emitV1(target)
	w.poison(target.dbi, target.key)
	return err
}

func (w *tdLW) referV1(dbi DBI, key []byte) error {
	err := w.emit.referV1(dbi, key)
	w.poison(dbi, key)
	return err
}

// tdVF is the R-VF-1 primitive (LAG forward kind 6, WriteOrReuse, family absent): CREATE kB (tx 0); SPEND kA
// (tx 1); SPEND kD then CREATE kD (tx 2). vA, vD1 (s.vD), vD2 (s.nD) and kB's value are distinct and of one length.
func tdVF() (tdScene, []string) {
	s := tdA4(1, 1)
	s.fB, s.fD = tdFrame(501, 0, nil), tdFrame(701, 0, nil)
	s.c.kind = 6
	s.c.body = append(append([]byte(nil), s.fB...), s.fD...)
	s.c.events = []tdEv{tdCreate(tdTxid(0x0b), 0, 0, 0, 11), tdSpend(tdTxid(0x0a), 0, 1, 0), tdSpend(tdTxid(0x0d), 0, 2, 0), tdCreate(tdTxid(0x0d), 0, 2, 11, 11)}
	s.eD = tdEntryKey(s.c.block, tdTxid(0x0d), 2, 0, 0)
	s.vA, s.vD = tdFormed(tdFrame(301, 0, nil), 2, 0), tdFormed(tdFrame(401, 0, nil), 2, 0)
	s.nB, s.nD = tdFormed(s.fB, 7, 1), tdFormed(s.fD, 7, 0)
	return s, []string{
		tdRef(4, s.c.block[:]), tdPut(1, s.kB, s.nB), tdPut(5, s.eA, s.vA), tdDel(1, s.kA),
		tdPut(5, s.eD, s.vD), tdPut(1, s.kD, s.nD), tdPut(5, s.mK, s.man),
	}
}

// R-VF-1, R-VF-2, M-VF-STALE, M-VF-Va, M-VF-Vb: borrowed images are consumed before their own identity is emitted.
func TestTreeDeltaValueFlowForwardV1(t *testing.T) {
	s, want := tdVF()
	store := tdStore(t, []tdMemRow{{4, s.c.block[:], s.c.body}})
	mustEnvironment(t, fixtureTreeSectionV1(store, &tdLedger{}, func(section *treeSectionV1) error {
		w := section.writerV1()
		mustEnvironment(t, w.emitV1(treeTargetV1{dbi: schemaDBIs[1], key: s.kA, after: treeImageV1{present: true, value: s.vA}}))
		mustEnvironment(t, w.emitV1(treeTargetV1{dbi: schemaDBIs[1], key: s.kD, after: treeImageV1{present: true, value: s.vD}}))
		rec := &tdRec{next: w}
		lw := &tdLW{old: section.oldV1(true), emit: rec, copies: map[string][][]byte{}}
		_, d := s.c.delta(t, treeWriterV1, &tdLedger{})
		mustEnvironment(t, d.resolveV1(lw))
		mustEnvironment(t, d.applyV1(lw))
		tdLog(t, "R-VF-1", rec.log, want...)
		after := section.oldV1(false)
		for _, row := range []tdMemRow{{5, s.eA, s.vA}, {5, s.eD, s.vD}, {1, s.kD, s.nD}} {
			image, err := after.getV1(schemaDBIs[row.rank], row.key)
			if err != nil || !bytes.Equal(image.value, row.value) {
				t.Fatalf("R-VF-1 post %x: %v", row.key, image)
			}
		}
		return nil
	}))
	rec := &tdRec{}
	lw := &tdLW{old: tdMem(tdMemRow{1, s.kA, s.vA}, tdMemRow{1, s.kD, s.vD}), emit: rec, copies: map[string][][]byte{}}
	budget := &treeBudgetV1{held: 1 << 30}
	_, d := s.c.delta(t, treeReadbackV1, budget.ledgerV1())
	mustEnvironment(t, d.resolveV1(lw))
	mustEnvironment(t, d.applyV1(lw))
	tdLog(t, "R-VF-2", rec.log, want...)
}

// R-VF-3, M-UNDO-I: an inverse restore is consumed before its entry is deleted.
func TestTreeDeltaValueFlowInverseV1(t *testing.T) {
	s := tdA21(2, 6)
	post := []tdMemRow{{4, s.c.block[:], s.c.body}, {1, s.kB, s.nB}}
	store := tdStore(t, post, s.family())
	mustEnvironment(t, fixtureTreeSectionV1(store, &tdLedger{}, func(section *treeSectionV1) error {
		rec := &tdRec{next: section.writerV1()}
		lw := &tdLW{old: section.oldV1(true), emit: rec, copies: map[string][][]byte{}}
		_, d := s.c.delta(t, treeWriterV1, &tdLedger{})
		mustEnvironment(t, d.resolveV1(lw))
		mustEnvironment(t, d.applyV1(lw))
		tdLog(t, "R-VF-3", rec.log, tdRef(4, s.c.block[:]), tdDel(1, s.kB), tdPut(1, s.kA, s.vA), tdDel(5, s.eA),
			tdRef(1, s.kC), tdPut(1, s.kD, s.vD), tdDel(5, s.eD), tdDel(5, s.mK))
		return nil
	}))
}

// tdInsideV reports whether b's backing lies inside the V scratch.
func tdInsideV(d *treeDeltaV1, b []byte) bool {
	v := d.rec.value
	start, end := uintptr(unsafe.Pointer(unsafe.SliceData(v))), uintptr(unsafe.Pointer(unsafe.SliceData(v)))+uintptr(cap(v))
	p := uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	return p >= start && p+uintptr(len(b)) <= end
}

// tdDrain copies every leaf at call time and checks that each present newValue lies inside V.
func tdDrain(t *testing.T, d *treeDeltaV1) []string {
	t.Helper()
	var out []string
	it := d.leavesV1()
	for {
		leaf, ok, err := it.nextV1()
		mustEnvironment(t, err)
		if !ok {
			return out
		}
		if leaf.newPresent && !tdInsideV(d, leaf.newValue) {
			t.Fatalf("leaf %x newValue outside V", leaf.key)
		}
		out = append(out, tdLeaf(leaf.key[:], leaf.oldPresent, leaf.newPresent, leaf.newValue))
	}
}

// R-VF-4, M-LEAF-INV-V, M-LEAF-INV-OLD, M-LEAF-INV-ALIAS: inverse leaves copy the entry image into V.
func TestTreeDeltaInverseLeavesV1(t *testing.T) {
	s := tdA4(2, 5)
	s.vA, s.vD = tdFormed(tdFrame(31, 0, []byte{1, 2}), 2, 0), tdFormed(tdFrame(41, 0, []byte{3, 4}), 2, 0)
	want := []string{tdLeaf(s.kA, false, true, s.vA), tdLeaf(s.kB, true, false, nil), tdLeaf(s.kD, true, true, s.vD)}
	for sub, tc := range []struct {
		undo   uint8
		native bool
	}{{5, true}, {6, true}, {5, false}, {6, false}} {
		rows := [][]tdMemRow{s.post()}
		if tc.native {
			rows = append(rows, s.family())
		}
		store := tdStore(t, rows...)
		c := s.c
		c.undo = tc.undo
		mustEnvironment(t, fixtureTreeSectionV1(store, &tdLedger{}, func(section *treeSectionV1) error {
			if !tc.native {
				for _, row := range s.family() {
					mustEnvironment(t, section.writerV1().emitV1(treeTargetV1{dbi: schemaDBIs[5], key: row.key, after: treeImageV1{present: true, value: row.value}}))
				}
			}
			_, d := c.delta(t, treeWriterV1, &tdLedger{})
			mustEnvironment(t, d.resolveV1(section.oldV1(true)))
			first := tdDrain(t, d)
			mustEnvironment(t, d.applyV1(section.writerV1()))
			second := tdDrain(t, d)
			if !slices.Equal(first, want) || !slices.Equal(second, want) {
				t.Fatalf("sub-row %d:\n%q\n%q", sub+1, first, second)
			}
			if tc.undo == 6 {
				image, err := section.oldV1(false).getV1(schemaDBIs[5], s.eA)
				if err != nil || image.present {
					t.Fatalf("sub-row %d: entry still present", sub+1)
				}
			}
			return nil
		}))
	}
	// (v) L3 pin: a held P-served image survives emitV1 and referV1 of its own identity.
	store := tdStore(t, s.post())
	mustEnvironment(t, fixtureTreeSectionV1(store, &tdLedger{}, func(section *treeSectionV1) error {
		w := section.writerV1()
		mustEnvironment(t, w.emitV1(treeTargetV1{dbi: schemaDBIs[5], key: s.eA, after: treeImageV1{present: true, value: s.vA}}))
		held, err := section.oldV1(true).getV1(schemaDBIs[5], s.eA)
		mustEnvironment(t, err)
		mustEnvironment(t, w.emitV1(treeTargetV1{dbi: schemaDBIs[5], key: s.eA, after: treeImageV1{present: true, value: tdFlip(s.vA, 0)}}))
		mustEnvironment(t, w.emitV1(treeTargetV1{dbi: schemaDBIs[5], key: s.eA}))
		mustEnvironment(t, w.referV1(schemaDBIs[5], s.eA))
		if !bytes.Equal(held.value, s.vA) {
			t.Fatal("(v) held P image changed")
		}
		return nil
	}))
}
