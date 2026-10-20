//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unsafe"
)

type testTreeLog struct{ calls []string }

func (l *testTreeLog) add(s string) { l.calls = append(l.calls, s) }

type testTreeOld struct {
	rows     map[string][]byte
	log      *testTreeLog
	reads    []string
	failN    int
	fail     error
	scribble bool
	served   [][]byte
}

func (o *testTreeOld) getV1(dbi DBI, key []byte) (treeImageV1, error) {
	o.reads = append(o.reads, fmt.Sprintf("%d:%x", dbi.Rank, key))
	o.log.add("get")
	if o.failN == len(o.reads) {
		return treeImageV1{}, o.fail
	}
	v, ok := o.rows[fmt.Sprintf("%d:%x", dbi.Rank, key)]
	if !ok {
		return treeImageV1{}, nil
	}
	out := append([]byte(nil), v...)
	if o.scribble {
		o.served = append(o.served, out, append([]byte(nil), key...))
	}
	return treeImageV1{present: true, value: out}, nil
}

func testTreeOverwrite(b []byte) {
	for i := range b {
		b[i] = 0xEE
	}
}

func (o *testTreeOld) nextV1(DBI, []byte) ([]byte, treeImageV1, bool, error) {
	o.log.add("next")
	return nil, treeImageV1{}, false, errors.New("nextV1 must not be called")
}

type testTreeLeaves struct {
	items    []treeLeafV1
	i        int
	log      *testTreeLog
	failN    int
	fail     error
	scribble bool
	last     []byte
}

func (l *testTreeLeaves) nextV1() (treeLeafV1, bool, error) {
	l.log.add("leaves")
	testTreeOverwrite(l.last)
	l.i++
	if l.failN == l.i {
		return treeLeafV1{}, false, l.fail
	}
	if l.i > len(l.items) {
		return treeLeafV1{}, false, nil
	}
	item := l.items[l.i-1]
	if l.scribble && item.newValue != nil {
		item.newValue = append([]byte(nil), item.newValue...)
		l.last = item.newValue
	}
	return item, true, nil
}

type testTreeEmit struct {
	targets  []string
	values   [][]byte
	refers   []string
	log      *testTreeLog
	failAt   int
	fail     error
	scribble *testTreeOld
}

func (e *testTreeEmit) overwrite(bufs ...[]byte) {
	if e.scribble == nil {
		return
	}
	for _, b := range append(bufs, e.scribble.served...) {
		testTreeOverwrite(b)
	}
}

func (e *testTreeEmit) emitV1(t treeTargetV1) error {
	e.log.add("emit")
	e.targets = append(e.targets, fmt.Sprintf("%d:%x:%v", t.dbi.Rank, t.key, t.after.present))
	e.values = append(e.values, append([]byte(nil), t.after.value...))
	e.overwrite(t.key, t.after.value)
	if e.failAt == len(e.targets) {
		return e.fail
	}
	return nil
}

func (e *testTreeEmit) referV1(dbi DBI, key []byte) error {
	e.log.add("refer")
	e.refers = append(e.refers, fmt.Sprintf("%d:%x", dbi.Rank, key))
	e.overwrite(key)
	if e.failAt < 0 && -e.failAt == len(e.refers) {
		return e.fail
	}
	return nil
}

type testTreeLedger struct {
	log    *testTreeLog
	refuse error
}

func (l *testTreeLedger) chargeV1(n uint64) error {
	l.log.add(fmt.Sprintf("charge %d", n))
	return l.refuse
}

func (l *testTreeLedger) releaseV1(n uint64) { l.log.add(fmt.Sprintf("release %d", n)) }

// testTreeNodeKey spells u64be(g) || upper || u16be(288-depth) byte by byte.
func testTreeNodeKey(g uint64, depth int, key [36]byte) []byte {
	for bit := depth; bit < 288; bit++ {
		key[bit/8] |= 1 << (7 - bit%8)
	}
	out := binary.BigEndian.AppendUint64(nil, g)
	out = append(out, key[:]...)
	return binary.BigEndian.AppendUint16(out, uint16(288-depth))
}

type testTreeEntry struct {
	k [36]byte
	v []byte
}

type testTreeNode struct {
	depth  int
	key    [36]byte
	digest [32]byte
}

func testTreeBit(k [36]byte, i int) byte { return (k[i/8] >> (7 - i%8)) & 1 }

// testTreeBuild computes the CSM 2.6 canonical node set into rows (test-local recursion of ROOT).
func testTreeBuild(g uint64, entries []testTreeEntry, rows map[string][]byte) testTreeNode {
	if len(entries) == 1 {
		d := testTreeLeafPreimage(entries[0].k, entries[0].v)
		rows[fmt.Sprintf("8:%x", testTreeNodeKey(g, 288, entries[0].k))] = d[:]
		return testTreeNode{288, entries[0].k, d}
	}
	d := 0
	for testTreeBit(entries[0].k, d) == testTreeBit(entries[len(entries)-1].k, d) {
		d++
	}
	split := sort.Search(len(entries), func(i int) bool { return testTreeBit(entries[i].k, d) == 1 })
	z, o := testTreeBuild(g, entries[:split], rows), testTreeBuild(g, entries[split:], rows)
	var p [36]byte
	for i := 0; i < d; i++ {
		p[i/8] |= testTreeBit(entries[0].k, i) << (7 - i%8)
	}
	digest := testTreeBranchPreimage(uint16(d), p, z.digest, o.digest)
	v := append(testTreeNodeKey(1, z.depth, z.key)[8:], z.digest[:]...)
	v = append(v, testTreeNodeKey(1, o.depth, o.key)[8:]...)
	rows[fmt.Sprintf("8:%x", testTreeNodeKey(g, d, p))] = append(v, o.digest[:]...)
	return testTreeNode{d, p, digest}
}

func testTreeBindingKey(g uint64) string {
	return fmt.Sprintf("0:%x", binary.BigEndian.AppendUint64([]byte{0x11}, g))
}

func testTreeOldBinding(top *testTreeNode, endpoint TreeEndpointV1) RootBindingV1 {
	b := RootBindingV1{
		DatabaseID: [32]byte{0x44}, CommitmentVersion: 1, Endpoint: endpoint,
		Assurance: TreeAssuranceV1{Kind: TreeAssuranceFullHistoryV1},
	}
	for i := range b.DatabaseID {
		b.DatabaseID[i], b.ChainID[i], b.GenesisHash[i] = 0x44, 0x55, 0x66
	}
	b.RootDigest, b.Top = treeEmptyDigestV1(), TreeTopV1{Kind: TreeTopEmptyV1}
	if top != nil {
		id := TreeNodeIDV1{Kind: TreeNodeBranchV1, Depth: uint16(top.depth), Prefix: top.key}
		if top.depth == 288 {
			id = TreeNodeIDV1{Kind: TreeNodeLeafV1, Depth: 288, RoutingKey: top.key}
		}
		b.RootDigest, b.Top = top.digest, TreeTopV1{Kind: TreeTopKindV1(id.Kind), Node: &id}
	}
	return b
}

func testTreeHash(fill byte) [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = fill
	}
	return h
}

func testTreeApplied(height uint64, hash byte, work byte) TreeEndpointV1 {
	var w [40]byte
	w[39] = work
	return TreeEndpointV1{Kind: TreeEndpointAppliedV1, Height: height, BlockHash: testTreeHash(hash), CumulativeChainwork: w}
}

type testTreeCase struct {
	g          uint64
	oldEntries []testTreeEntry
	oldEP      TreeEndpointV1
	stream     []treeLeafV1
	endpoint   TreeEndpointV1
	databaseID [32]byte
	mutate     func(rows map[string][]byte, binding *RootBindingV1)
	preGenesis bool
	zeroGen    bool
}

func testTreeStreamLeaf(g uint64, k [36]byte, oldPresent bool, v []byte) treeLeafV1 {
	l := treeLeafV1{oldPresent: oldPresent, newPresent: v != nil, newValue: v}
	binary.BigEndian.PutUint64(l.key[:8], g)
	copy(l.key[8:], k[:])
	return l
}

type testTreeRun struct {
	err     error
	reads   []string
	emit    *testTreeEmit
	log     []string
	foldErr error
	foldRd  []string
	foldLog []string
	id      [32]byte
	newRows map[string][]byte
}

// newRows is the ROOT/ROWS node set of the NEW map (OLD entries with the stream applied), built by the test recursion.
func (c testTreeCase) newRows() map[string][]byte {
	byKey := map[[36]byte][]byte{}
	for _, e := range c.oldEntries {
		byKey[e.k] = e.v
	}
	for _, l := range c.stream {
		var k [36]byte
		copy(k[:], l.key[8:])
		delete(byKey, k)
		if l.newPresent {
			byKey[k] = l.newValue
		}
	}
	var entries []testTreeEntry
	for k, v := range byKey {
		entries = append(entries, testTreeEntry{k, v})
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].k[:], entries[j].k[:]) < 0 })
	rows := map[string][]byte{}
	if len(entries) > 0 {
		testTreeBuild(c.g, entries, rows)
	}
	return rows
}

// checkValues: every put node target carries the byte-spelled NEW value; every delete target is absent and empty.
func (r testTreeRun) checkValues(t *testing.T) {
	t.Helper()
	for i, tg := range r.emit.targets {
		if !strings.HasPrefix(tg, "8:") {
			continue
		}
		key := strings.TrimSuffix(strings.TrimSuffix(tg, ":true"), ":false")
		if strings.HasSuffix(tg, ":false") {
			if len(r.emit.values[i]) != 0 {
				t.Fatalf("delete %s carries a value", key)
			}
			continue
		}
		if want, ok := r.newRows[key]; !ok || !bytes.Equal(r.emit.values[i], want) {
			t.Fatalf("put %s value %x want %x", key, r.emit.values[i], want)
		}
	}
}

func (c testTreeCase) setup() (*testTreeOld, *testTreeLeaves, *testTreeLog) {
	log := &testTreeLog{}
	rows := map[string][]byte{}
	var top *testTreeNode
	if len(c.oldEntries) > 0 {
		n := testTreeBuild(c.g, c.oldEntries, rows)
		top = &n
	}
	ep := c.oldEP
	if top != nil && ep == (TreeEndpointV1{}) {
		ep = testTreeApplied(5, 0x77, 1)
	}
	b := testTreeOldBinding(top, ep)
	if c.mutate != nil {
		c.mutate(rows, &b)
	}
	if enc, err := b.Encode(); err == nil {
		rows[testTreeBindingKey(c.g)] = enc
	}
	if c.mutate != nil {
		c.mutate(rows, nil)
	}
	return &testTreeOld{rows: rows, log: log}, &testTreeLeaves{items: c.stream, log: log}, log
}

// testTreeRecover turns a panic into an error so the row's own assertion observes it.
func testTreeRecover(f func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return f()
}

func (c testTreeCase) run(t *testing.T, tweak func(*testTreeOld, *testTreeLeaves, *testTreeEmit, *testTreeLedger)) testTreeRun {
	t.Helper()
	if c.g == 0 && !c.zeroGen {
		c.g = 7
	}
	if !c.preGenesis {
		c.endpoint = testTreeApplied(6, 0x88, 2)
	}
	if c.databaseID == ([32]byte{}) {
		c.databaseID = testTreeHash(0x44)
	}
	old, leaves, log := c.setup()
	emit, ledger := &testTreeEmit{log: log}, &testTreeLedger{log: log}
	if tweak != nil {
		tweak(old, leaves, emit, ledger)
	}
	r := testTreeRun{emit: emit, id: c.databaseID, newRows: c.newRows()}
	r.err = testTreeRecover(func() error {
		return treeEmitNodesV1(old, c.g, c.endpoint, c.databaseID, leaves, emit, ledger)
	})
	r.reads, r.log = old.reads, log.calls
	old2, leaves2, log2 := c.setup()
	ledger2 := &testTreeLedger{log: log2}
	if tweak != nil {
		tweak(old2, leaves2, &testTreeEmit{log: log2}, ledger2)
	}
	r.foldErr = testTreeRecover(func() error {
		return treeFoldV1(old2, c.g, c.endpoint, c.databaseID, leaves2, ledger2)
	})
	r.foldRd, r.foldLog = old2.reads, log2.calls
	testTreeCheckLedger(t, r.log)
	testTreeCheckLedger(t, r.foldLog)
	return r
}

// testTreeCheckLedger is K1: the first call is chargeV1(147968), one charge, and one release last (when charged).
func testTreeCheckLedger(t *testing.T, log []string) {
	t.Helper()
	if len(log) == 0 || log[0] != "charge 147968" {
		t.Fatalf("K1: first call %v", log)
	}
	charges, releases := 0, 0
	for _, c := range log {
		if strings.HasPrefix(c, "charge") {
			charges++
		}
		if strings.HasPrefix(c, "release") {
			releases++
		}
	}
	if charges != 1 || releases != 1 || log[len(log)-1] != "release 147968" {
		t.Fatalf("K1: ledger log %v", log)
	}
}

func testTreeTarget(g uint64, depth int, k [36]byte, present bool) string {
	return fmt.Sprintf("8:%x:%v", testTreeNodeKey(g, depth, k), present)
}

func testTreeRef(g uint64, depth int, k [36]byte) string {
	return fmt.Sprintf("8:%x", testTreeNodeKey(g, depth, k))
}

func testTreeNodeRead(g uint64, depth int, k [36]byte) string { return testTreeRef(g, depth, k) }

func (r testTreeRun) accept(t *testing.T, g uint64, targets []string, refers []string, reads []string) RootBindingV1 {
	t.Helper()
	if r.err != nil || r.foldErr != nil {
		t.Fatalf("errors: emit %v fold %v", r.err, r.foldErr)
	}
	r.checkValues(t)
	got := r.emit.targets
	want := append(append([]string(nil), targets...), testTreeBindingKey(g)+":true")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets\n got %v\nwant %v", got, want)
	}
	if !reflect.DeepEqual(append([]string{}, r.emit.refers...), append([]string{}, refers...)) {
		t.Fatalf("refers got %v want %v", r.emit.refers, refers)
	}
	wantReads := append([]string{testTreeBindingKey(g)}, reads...)
	if !reflect.DeepEqual(r.reads, wantReads) || !reflect.DeepEqual(r.foldRd, wantReads) {
		t.Fatalf("A11 reads\n emit %v\n fold %v\n want %v", r.reads, r.foldRd, wantReads)
	}
	b, err := DecodeRootBindingV1(r.emit.values[len(r.emit.values)-1])
	if err != nil {
		t.Fatal(err)
	}
	if b.DatabaseID != r.id || b.ChainID != testTreeHash(0x55) || b.GenesisHash != testTreeHash(0x66) || b.CommitmentVersion != 1 {
		t.Fatalf("copied fields %+v", b)
	}
	return b
}

func testTreeABC() []testTreeEntry {
	e := testTreeE()
	return []testTreeEntry{{testKA, e}, {testKB, e}, {testKC, e}}
}

func testTreeA8Value() []byte { return testTreeValue(2, testTreeData(0x11), 0, 0) }

func TestTreeEmitV1A4InsertIntoEmpty(t *testing.T) {
	e := testTreeE()
	c := testTreeCase{stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, false, e), testTreeStreamLeaf(7, testKB, false, e), testTreeStreamLeaf(7, testKC, false, e)}}
	r := c.run(t, nil)
	b := r.accept(t, 7, []string{
		testTreeTarget(7, 288, testKA, true), testTreeTarget(7, 288, testKB, true), testTreeTarget(7, 287, [36]byte{}, true),
		testTreeTarget(7, 288, testKC, true), testTreeTarget(7, 0, [36]byte{}, true),
	}, nil, nil)
	c02 := testTreeHex(t, "14bd6311f35ed9534d8cd8a101bc09c5d289978e393e775271fd9e446c8cde8d")
	c03 := testTreeHex(t, "480f5e45ffbf5dbc0ec499ef7574c3379e26ab4ffb25220df9eb023b057526cc")
	if !bytes.Equal(r.emit.values[0], c02[:]) || !bytes.Equal(r.emit.values[1], c03[:]) {
		t.Fatal("leaf values")
	}
	want287 := append(testTreeNodeKey(1, 288, testKA)[8:], c02[:]...)
	want287 = append(append(want287, testTreeNodeKey(1, 288, testKB)[8:]...), c03[:]...)
	if !bytes.Equal(r.emit.values[2], want287) {
		t.Fatalf("branch 287 value %x", r.emit.values[2])
	}
	if b.RootDigest != testTreeHex(t, "0dbb5487445845169a856b31fe2877c6cb84df41cc170f6ae9c41d062164fd7d") || b.Top.Kind != TreeTopBranchV1 || b.Top.Node.Depth != 0 {
		t.Fatalf("binding %+v", b)
	}
	if b.Endpoint != testTreeApplied(6, 0x88, 2) {
		t.Fatal("endpoint")
	}
}

func TestTreeEmitV1A5Collapse(t *testing.T) {
	c := testTreeCase{oldEntries: testTreeABC(), stream: []treeLeafV1{testTreeStreamLeaf(7, testKB, true, nil)}}
	r := c.run(t, nil)
	b := r.accept(t, 7, []string{
		testTreeTarget(7, 288, testKB, false), testTreeTarget(7, 287, [36]byte{}, false), testTreeTarget(7, 0, [36]byte{}, true),
	}, []string{testTreeRef(7, 288, testKA), testTreeRef(7, 288, testKC)},
		[]string{testTreeNodeRead(7, 0, [36]byte{}), testTreeNodeRead(7, 287, [36]byte{}), testTreeNodeRead(7, 288, testKB)})
	if b.RootDigest != testTreeHex(t, "1f3304724f76317f55c881875e5bcb741c00b090e1e1c2204d3b276aff069ac2") {
		t.Fatal("C04")
	}
}

func TestTreeEmitV1A6Split(t *testing.T) {
	e := testTreeE()
	c := testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKC, false, e)}}
	b := c.run(t, nil).accept(t, 7, []string{testTreeTarget(7, 288, testKC, true), testTreeTarget(7, 0, [36]byte{}, true)},
		[]string{testTreeRef(7, 287, [36]byte{})}, nil)
	if b.RootDigest != testTreeHex(t, "0dbb5487445845169a856b31fe2877c6cb84df41cc170f6ae9c41d062164fd7d") {
		t.Fatal("C06")
	}
}

func TestTreeEmitV1A7DeleteDown(t *testing.T) {
	c := testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKB, true, nil)}}
	b := c.run(t, nil).accept(t, 7, []string{testTreeTarget(7, 288, testKB, false), testTreeTarget(7, 287, [36]byte{}, false)},
		[]string{testTreeRef(7, 288, testKA)}, []string{testTreeNodeRead(7, 287, [36]byte{}), testTreeNodeRead(7, 288, testKB)})
	if b.RootDigest != testTreeHex(t, "14bd6311f35ed9534d8cd8a101bc09c5d289978e393e775271fd9e446c8cde8d") || b.Top.Kind != TreeTopLeafV1 {
		t.Fatal("C02 top leaf")
	}
	c2 := testTreeCase{
		oldEntries: testTreeABC()[:1], oldEP: testTreeApplied(0, 0x77, 1), preGenesis: true,
		stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, nil)},
	}
	b = c2.run(t, nil).accept(t, 7, []string{testTreeTarget(7, 288, testKA, false)}, nil, []string{testTreeNodeRead(7, 288, testKA)})
	if b.RootDigest != treeEmptyDigestV1() || b.Top.Kind != TreeTopEmptyV1 || b.Endpoint.Kind != TreeEndpointPreGenesisV1 {
		t.Fatal("C01 empty")
	}
}

func TestTreeEmitV1A8Replace(t *testing.T) {
	c := testTreeCase{oldEntries: testTreeABC()[:1], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}}
	r := c.run(t, nil)
	b := r.accept(t, 7, []string{testTreeTarget(7, 288, testKA, true)}, nil, []string{testTreeNodeRead(7, 288, testKA)})
	c14 := testTreeHex(t, "d8ca4a9d2c487486e0dd12ea08862b0c8c0f87c292b2dab4010b85bce5c30fc9")
	if b.RootDigest != c14 || !bytes.Equal(r.emit.values[0], c14[:]) {
		t.Fatal("C14")
	}
}

func TestTreeEmitV1A9PrefixAndGeneration(t *testing.T) {
	e := testTreeE()
	for _, g := range []uint64{7, ^uint64(0)} {
		c := testTreeCase{g: g, stream: []treeLeafV1{testTreeStreamLeaf(g, testKX, false, e), testTreeStreamLeaf(g, testKY, false, e)}}
		b := c.run(t, nil).accept(t, g, []string{testTreeTarget(g, 288, testKX, true), testTreeTarget(g, 288, testKY, true), testTreeTarget(g, 3, [36]byte{0xa0}, true)}, nil, nil)
		if b.RootDigest != testTreeHex(t, "10a4199bd27aa176b2e1c052bd2a18cd961f1a861793796e4e6a594ae9073e01") {
			t.Fatal("C07")
		}
		k8, k9 := testTreeKey(0, 0, 255), testTreeKey(0, 0, 256)
		c = testTreeCase{g: g, stream: []treeLeafV1{testTreeStreamLeaf(g, k8, false, e), testTreeStreamLeaf(g, k9, false, e)}}
		b = c.run(t, nil).accept(t, g, []string{testTreeTarget(g, 288, k8, true), testTreeTarget(g, 288, k9, true), testTreeTarget(g, 279, [36]byte{}, true)}, nil, nil)
		if b.RootDigest != testTreeHex(t, "b9965ddde341cf712ffa9655cc85caf2da2608461248c8f0f2217d5e00c2b44e") {
			t.Fatal("C10")
		}
	}
}

func TestTreeEmitV1A10EmptyStream(t *testing.T) {
	c := testTreeCase{oldEntries: testTreeABC()[:2]}
	b := c.run(t, nil).accept(t, 7, nil, []string{testTreeRef(7, 287, [36]byte{})}, nil)
	if b.RootDigest != testTreeHex(t, "fc8c011e40853708f49a90759af0c9e5b738e3116dca9ed641539af0827cf9ac") || b.Endpoint != testTreeApplied(6, 0x88, 2) {
		t.Fatal("A10")
	}
}

func TestTreeEmitV1A12AssuranceCopy(t *testing.T) {
	ref := &TreeImportReferenceV1{OriginalDatabaseID: testTreeHash(0x99), OriginalCurrentID: 3, OriginalLagID: 4, OriginalRole: TreeOriginalCurrentV1, EvidenceID: testTreeHash(0xaa)}
	c := testTreeCase{
		oldEntries: testTreeABC()[:1], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())},
		mutate: func(_ map[string][]byte, b *RootBindingV1) {
			if b != nil {
				b.Assurance = TreeAssuranceV1{Kind: TreeAssuranceImportedBaseV1, Import: ref}
			}
		},
	}
	b := c.run(t, nil).accept(t, 7, []string{testTreeTarget(7, 288, testKA, true)}, nil, []string{testTreeNodeRead(7, 288, testKA)})
	if b.Assurance.Kind != TreeAssuranceImportedBaseV1 || *b.Assurance.Import != *ref {
		t.Fatal("A12")
	}
}

func TestTreeEmitV1A13ChangeOneOfTwo(t *testing.T) {
	c := testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}}
	r := c.run(t, nil)
	b := r.accept(t, 7, []string{testTreeTarget(7, 288, testKA, true), testTreeTarget(7, 287, [36]byte{}, true)},
		[]string{testTreeRef(7, 288, testKB)}, []string{testTreeNodeRead(7, 287, [36]byte{}), testTreeNodeRead(7, 288, testKA)})
	c14 := testTreeHex(t, "d8ca4a9d2c487486e0dd12ea08862b0c8c0f87c292b2dab4010b85bce5c30fc9")
	c03 := testTreeHex(t, "480f5e45ffbf5dbc0ec499ef7574c3379e26ab4ffb25220df9eb023b057526cc")
	if b.RootDigest != testTreeBranchPreimage(287, [36]byte{}, c14, c03) {
		t.Fatal("A13 root")
	}
}

// refusal checks the R1 integrity shape for both functions and that no binding is emitted.
func (r testTreeRun) refusal(t *testing.T, cause error, last string) {
	t.Helper()
	for _, log := range [][]string{r.log, r.foldLog} {
		if last != "" && (len(log) < 2 || log[len(log)-2] != last) {
			t.Fatalf("call before release is not the refusing %q: %v", last, log)
		}
	}
	for _, err := range []error{r.err, r.foldErr} {
		var ee *EngineError
		if !errors.As(err, &ee) || ee.Class != EngineIntegrity || ee.Code != codeCorrupted || ee.Diagnostic != "invalid tree native representation" || ee.ReopenRequired {
			t.Fatalf("not integrity: %v", err)
		}
		if cause == nil && errors.Unwrap(err) != nil || cause != nil && !errors.Is(err, cause) {
			t.Fatalf("cause %v want %v", errors.Unwrap(err), cause)
		}
	}
	for _, tg := range r.emit.targets {
		if strings.HasPrefix(tg, "0:") {
			t.Fatal("binding emitted on refusal")
		}
	}
	if !reflect.DeepEqual(r.reads, r.foldRd) {
		t.Fatalf("reads differ %v %v", r.reads, r.foldRd)
	}
}

func testTreeRemove(g uint64, depth int, k [36]byte) func(map[string][]byte, *RootBindingV1) {
	return func(rows map[string][]byte, b *RootBindingV1) {
		if b == nil {
			delete(rows, testTreeRef(g, depth, k))
		}
	}
}

func TestTreeEmitV1R1AbsentChild(t *testing.T) {
	c := testTreeCase{oldEntries: testTreeABC(), stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}, mutate: testTreeRemove(7, 287, [36]byte{})}
	r := c.run(t, nil)
	r.refusal(t, nil, "get")
	if want := []string{testTreeBindingKey(7), testTreeNodeRead(7, 0, [36]byte{}), testTreeNodeRead(7, 287, [36]byte{})}; !reflect.DeepEqual(r.reads, want) {
		t.Fatalf("reads %v", r.reads)
	}
}

func TestTreeEmitV1R2MalformedLeaf(t *testing.T) {
	c := testTreeCase{
		oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())},
		mutate: func(rows map[string][]byte, b *RootBindingV1) {
			if b == nil {
				rows[testTreeRef(7, 288, testKA)] = append(rows[testTreeRef(7, 288, testKA)], 0)
			}
		},
	}
	c.run(t, nil).refusal(t, errSchema, "get")
}

func TestTreeEmitV1R3Presence(t *testing.T) {
	c := testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}, mutate: testTreeRemove(7, 288, testKA)}
	r := c.run(t, nil)
	r.refusal(t, nil, "get")
	if want := []string{testTreeBindingKey(7), testTreeNodeRead(7, 287, [36]byte{}), testTreeNodeRead(7, 288, testKA)}; !reflect.DeepEqual(r.reads, want) {
		t.Fatalf("R3(i) reads %v", r.reads)
	}
	c = testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKB, false, testTreeE())}}
	r = c.run(t, nil)
	r.refusal(t, nil, "get")
	if want := []string{testTreeBindingKey(7), testTreeNodeRead(7, 287, [36]byte{}), testTreeNodeRead(7, 288, testKB)}; !reflect.DeepEqual(r.reads, want[:len(r.reads)]) || len(r.reads) < 2 {
		t.Fatalf("R3(ii) reads %v", r.reads)
	}
}

func TestTreeEmitV1R4R5R6Injected(t *testing.T) {
	sentinel := errors.New("sentinel")
	base := testTreeCase{oldEntries: testTreeABC(), stream: []treeLeafV1{testTreeStreamLeaf(7, testKB, true, nil)}}
	for _, n := range []int{1, 4} {
		r := base.run(t, func(o *testTreeOld, _ *testTreeLeaves, _ *testTreeEmit, _ *testTreeLedger) {
			o.failN, o.fail = n, sentinel
		})
		if !testTreeExact(r.err, sentinel) || !testTreeExact(r.foldErr, sentinel) || len(r.reads) != n || len(r.emit.targets) != 0 {
			t.Fatalf("R4 n=%d: %v %v %v", n, r.err, r.foldErr, r.reads)
		}
	}
	for _, n := range []int{1, 2} {
		r := base.run(t, func(_ *testTreeOld, l *testTreeLeaves, _ *testTreeEmit, _ *testTreeLedger) {
			l.failN, l.fail = n, sentinel
		})
		if !testTreeExact(r.err, sentinel) || !testTreeExact(r.foldErr, sentinel) || len(r.emit.targets)+len(r.emit.refers) != 0 ||
			r.log[len(r.log)-2] != "leaves" || r.foldLog[len(r.foldLog)-2] != "leaves" {
			t.Fatalf("R5 n=%d: %v %v %v", n, r.err, r.foldErr, r.log)
		}
	}
	r := base.run(t, func(_ *testTreeOld, _ *testTreeLeaves, e *testTreeEmit, _ *testTreeLedger) {
		e.failAt, e.fail = 1, sentinel
	})
	if !testTreeExact(r.err, sentinel) || len(r.emit.targets) != 1 || len(r.emit.refers) != 0 {
		t.Fatalf("R6 emit: %v %v", r.err, r.emit.targets)
	}
	r = base.run(t, func(_ *testTreeOld, _ *testTreeLeaves, e *testTreeEmit, _ *testTreeLedger) {
		e.failAt, e.fail = -1, sentinel
	})
	if !testTreeExact(r.err, sentinel) || len(r.emit.refers) != 1 || len(r.emit.targets) != 3 || r.log[len(r.log)-2] != "refer" {
		t.Fatalf("R6 refer: %v %v %v", r.err, r.emit.targets, r.emit.refers)
	}
}

func TestTreeEmitV1R7R8R9R10Binding(t *testing.T) {
	e := testTreeE()
	ins := []treeLeafV1{testTreeStreamLeaf(7, testKC, false, e)}
	c := testTreeCase{oldEntries: testTreeABC()[:2], stream: ins, mutate: func(rows map[string][]byte, b *RootBindingV1) {
		if b == nil {
			delete(rows, testTreeBindingKey(7))
		}
	}}
	c.run(t, nil).refusal(t, nil, "get")
	c.mutate = func(rows map[string][]byte, b *RootBindingV1) {
		if b == nil {
			rows[testTreeBindingKey(7)] = rows[testTreeBindingKey(7)][:132]
		}
	}
	_, cause := DecodeRootBindingV1(make([]byte, 132))
	c.run(t, nil).refusal(t, cause, "get")
	c = testTreeCase{oldEntries: testTreeABC()[:2], stream: ins, databaseID: testTreeHash(0x45)}
	c.run(t, nil).refusal(t, nil, "get")
	c.mutate = func(_ map[string][]byte, b *RootBindingV1) {
		if b != nil {
			b.DatabaseID = testTreeHash(0x45)
		}
	}
	c.run(t, nil).accept(t, 7, []string{testTreeTarget(7, 288, testKC, true), testTreeTarget(7, 0, [36]byte{}, true)}, []string{testTreeRef(7, 287, [36]byte{})}, nil)
	c = testTreeCase{
		oldEntries: testTreeABC()[:2], oldEP: testTreeApplied(0, 0x77, 1), preGenesis: true,
		stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, nil)},
	}
	// R10 is reached after the walk (Encode), where earlier node emits are permitted (D14-3).
	r := c.run(t, nil)
	r.refusal(t, errSchema, "")
	if want := []string{testTreeTarget(7, 288, testKA, false), testTreeTarget(7, 287, [36]byte{}, false)}; !reflect.DeepEqual(r.emit.targets, want) || len(r.emit.refers) != 0 {
		t.Fatalf("R10 targets %v refers %v", r.emit.targets, r.emit.refers)
	}
	wantLog := []string{"charge 147968", "get", "leaves", "get", "get", "leaves", "emit", "emit", "release 147968"}
	wantFold := []string{"charge 147968", "get", "leaves", "get", "get", "leaves", "release 147968"}
	if !reflect.DeepEqual(r.log, wantLog) || !reflect.DeepEqual(r.foldLog, wantFold) {
		t.Fatalf("R10 logs %v / %v", r.log, r.foldLog)
	}
}

func TestTreeEmitV1R13R14RootAndPath(t *testing.T) {
	c04 := testTreeHex(t, "1f3304724f76317f55c881875e5bcb741c00b090e1e1c2204d3b276aff069ac2")
	setRoot := func(rows map[string][]byte, b *RootBindingV1) {
		if b != nil {
			b.RootDigest = c04
		}
	}
	c := testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}, mutate: setRoot}
	r := c.run(t, nil)
	r.refusal(t, nil, "get")
	if r.reads[len(r.reads)-1] != testTreeNodeRead(7, 287, [36]byte{}) {
		t.Fatalf("R13 reads %v", r.reads)
	}
	// k = 0 control: R_j = {binding}; Top (287) is not read and its digest is the seeded RootDigest C04.
	b := testTreeCase{oldEntries: testTreeABC()[:2], mutate: setRoot}.run(t, nil).accept(t, 7, nil, []string{testTreeRef(7, 287, [36]byte{})}, nil)
	if b.RootDigest != c04 || b.Top.Kind != TreeTopBranchV1 || b.Top.Node.Depth != 287 || b.Top.Node.Prefix != ([36]byte{}) || b.Endpoint != testTreeApplied(6, 0x88, 2) {
		t.Fatalf("R13 control %+v", b)
	}
	emptyTop := testTreeCase{oldEP: testTreeApplied(5, 0x77, 1), mutate: func(_ map[string][]byte, b *RootBindingV1) {
		if b != nil {
			b.RootDigest = testTreeHash(0x01)
		}
	}}
	emptyTop.run(t, nil).refusal(t, nil, "get")
	stream := []treeLeafV1{testTreeStreamLeaf(7, testKC, true, testTreeE())}
	orphan := func(rows map[string][]byte, b *RootBindingV1) {
		if b == nil {
			d := testTreeLeafPreimage(testKC, testTreeE())
			rows[testTreeRef(7, 288, testKC)] = d[:]
		}
	}
	for _, m := range []func(map[string][]byte, *RootBindingV1){nil, orphan} {
		r = testTreeCase{oldEntries: testTreeABC()[:2], stream: stream, mutate: m}.run(t, nil)
		r.refusal(t, nil, "leaves")
		if !reflect.DeepEqual(r.reads, []string{testTreeBindingKey(7)}) {
			t.Fatalf("R14 reads %v", r.reads)
		}
	}
	ins := testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKC, false, testTreeE())}, mutate: orphan}
	ins.run(t, nil).accept(t, 7, []string{testTreeTarget(7, 288, testKC, true), testTreeTarget(7, 0, [36]byte{}, true)}, []string{testTreeRef(7, 287, [36]byte{})}, nil)
}

func TestTreeEmitV1R11R12TopAndChildDigest(t *testing.T) {
	replaceA := []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}
	r := testTreeCase{oldEntries: testTreeABC()[:2], stream: replaceA, mutate: testTreeRemove(7, 287, [36]byte{})}.run(t, nil)
	r.refusal(t, nil, "get")
	if r.reads[len(r.reads)-1] != testTreeNodeRead(7, 287, [36]byte{}) {
		t.Fatalf("R11 reads %v", r.reads)
	}
	e := testTreeE()
	c02, c03, cc := testTreeLeafPreimage(testKA, e), testTreeLeafPreimage(testKB, e), testTreeLeafPreimage(testKC, e)
	c05 := testTreeBranchPreimage(287, [36]byte{}, c02, c03)
	// Top variant: branch (0)'s zero digest is 0x01..; the binding commits to the modified (0) record.
	top := func(rows map[string][]byte, b *RootBindingV1) {
		if b != nil {
			b.RootDigest = testTreeBranchPreimage(0, [36]byte{}, testTreeHash(0x01), cc)
			return
		}
		v := rows[testTreeRef(7, 0, [36]byte{})]
		copy(v[38:70], bytes.Repeat([]byte{0x01}, 32))
	}
	r = testTreeCase{oldEntries: testTreeABC(), stream: replaceA, mutate: top}.run(t, nil)
	r.refusal(t, nil, "get")
	if r.reads[len(r.reads)-1] != testTreeNodeRead(7, 287, [36]byte{}) {
		t.Fatalf("R12 reads %v", r.reads)
	}
	_ = c05
	leaf := func(rows map[string][]byte, b *RootBindingV1) {
		if b != nil {
			b.RootDigest = testTreeBranchPreimage(287, [36]byte{}, testTreeHash(0x01), c03)
			return
		}
		v := rows[testTreeRef(7, 287, [36]byte{})]
		copy(v[38:70], bytes.Repeat([]byte{0x01}, 32))
	}
	r = testTreeCase{oldEntries: testTreeABC()[:2], stream: replaceA, mutate: leaf}.run(t, nil)
	r.refusal(t, nil, "get")
	if r.reads[len(r.reads)-1] != testTreeNodeRead(7, 288, testKA) {
		t.Fatalf("R12 leaf reads %v", r.reads)
	}
}

func TestTreeEmitV1R15GenerationZero(t *testing.T) {
	r := testTreeCase{
		zeroGen: true, oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(0, testKC, false, testTreeE())},
		mutate: func(rows map[string][]byte, b *RootBindingV1) {
			if b == nil {
				delete(rows, testTreeBindingKey(0))
			}
		},
	}.run(t, nil)
	r.refusal(t, nil, "get")
	if !reflect.DeepEqual(r.reads, []string{"0:110000000000000000"}) || len(r.emit.targets)+len(r.emit.refers) != 0 {
		t.Fatalf("R15 reads %v", r.reads)
	}
}

func TestTreeEmitV1K2LedgerRefusal(t *testing.T) {
	sentinel := errors.New("refused")
	log := &testTreeLog{}
	old, leaves := &testTreeOld{rows: map[string][]byte{}, log: log}, &testTreeLeaves{log: log}
	ledger := &testTreeLedger{log: log, refuse: sentinel}
	if err := treeEmitNodesV1(old, 7, TreeEndpointV1{}, [32]byte{}, leaves, &testTreeEmit{log: log}, ledger); !testTreeExact(err, sentinel) {
		t.Fatal(err)
	}
	if err := treeFoldV1(old, 7, TreeEndpointV1{}, [32]byte{}, leaves, ledger); !testTreeExact(err, sentinel) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(log.calls, []string{"charge 147968", "charge 147968"}) {
		t.Fatalf("K2 log %v", log.calls)
	}
}

func TestTreeEmitV1K3FrameGuards(t *testing.T) {
	var f treeFrameV1
	if 289*unsafe.Sizeof(f)+1024 > 147968 || treeFrameCapV1 > 289 || treeNodeWorkBytesV1 != 147968 {
		t.Fatalf("frame size %d cap %d", unsafe.Sizeof(f), treeFrameCapV1)
	}
	var walk func(reflect.Type)
	walk = func(ty reflect.Type) {
		switch ty.Kind() {
		case reflect.Array:
			walk(ty.Elem())
		case reflect.Struct:
			for i := 0; i < ty.NumField(); i++ {
				walk(ty.Field(i).Type)
			}
		case reflect.Pointer, reflect.Slice, reflect.Map, reflect.String, reflect.Interface, reflect.Chan, reflect.Func, reflect.UnsafePointer:
			t.Fatalf("frame holds %v", ty)
		default:
		}
	}
	walk(reflect.TypeOf(f))
}

// K4 harness: no allocation in the test old, leaves, emitter or ledger.
type testTreeFlatOld struct {
	keys   [][]byte
	values [][]byte
}

func (o *testTreeFlatOld) getV1(dbi DBI, key []byte) (treeImageV1, error) {
	i := sort.Search(len(o.keys), func(i int) bool { return bytes.Compare(o.keys[i], key) >= 0 })
	if i < len(o.keys) && bytes.Equal(o.keys[i], key) {
		return treeImageV1{present: true, value: o.values[i]}, nil
	}
	return treeImageV1{}, nil
}

func (o *testTreeFlatOld) nextV1(DBI, []byte) ([]byte, treeImageV1, bool, error) {
	return nil, treeImageV1{}, false, nil
}

type testTreeFlatLeaves struct {
	items []treeLeafV1
	i     int
}

func (l *testTreeFlatLeaves) nextV1() (treeLeafV1, bool, error) {
	if l.i >= len(l.items) {
		return treeLeafV1{}, false, nil
	}
	l.i++
	return l.items[l.i-1], true, nil
}

type testTreeFlatEmit struct {
	buf [1 << 16]byte
	n   int
}

func (e *testTreeFlatEmit) emitV1(t treeTargetV1) error {
	e.n += copy(e.buf[e.n%60000:], t.key)
	e.n += copy(e.buf[e.n%60000:], t.after.value)
	return nil
}

func (e *testTreeFlatEmit) referV1(_ DBI, key []byte) error {
	e.n += copy(e.buf[e.n%60000:], key)
	return nil
}

type testTreeFlatLedger struct{ held uint64 }

func (l *testTreeFlatLedger) chargeV1(n uint64) error { l.held += n; return nil }
func (l *testTreeFlatLedger) releaseV1(n uint64)      { l.held -= n }

func testTreeFlat(n int) (*testTreeFlatOld, []treeLeafV1) {
	e, v2 := testTreeE(), testTreeA8Value()
	var entries []testTreeEntry
	var stream []treeLeafV1
	for i := 0; i < n; i++ {
		k := testTreeKey(byte(i*4), 0, uint32(i))
		if n == 2 {
			k = [][36]byte{testKA, testKB}[i]
		}
		entries = append(entries, testTreeEntry{k, e})
		if n == 2 && i == 1 {
			continue
		}
		stream = append(stream, testTreeStreamLeaf(7, k, true, v2))
	}
	rows := map[string][]byte{}
	top := testTreeBuild(7, entries, rows)
	enc, _ := testTreeOldBinding(&top, testTreeApplied(5, 0x77, 1)).Encode()
	rows[testTreeBindingKey(7)] = enc
	old := &testTreeFlatOld{}
	var names []string
	for k := range rows {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		return bytes.Compare(testTreeRowKey(names[i]), testTreeRowKey(names[j])) < 0
	})
	for _, k := range names {
		old.keys, old.values = append(old.keys, testTreeRowKey(k)), append(old.values, rows[k])
	}
	return old, stream
}

func testTreeRowKey(name string) []byte {
	b, _ := hex.DecodeString(name[2:])
	return b
}

func TestTreeEmitV1K4AllocationIndependence(t *testing.T) {
	counts := [2][2]float64{}
	for i, n := range []int{2, 64} {
		old, stream := testTreeFlat(n)
		leaves, emit, ledger := &testTreeFlatLeaves{items: stream}, &testTreeFlatEmit{}, &testTreeFlatLedger{}
		ep, id := testTreeApplied(6, 0x88, 2), testTreeHash(0x44)
		if err := treeEmitNodesV1(old, 7, ep, id, leaves, emit, ledger); err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		counts[i][0] = testing.AllocsPerRun(20, func() {
			leaves.i = 0
			_ = treeFoldV1(old, 7, ep, id, leaves, ledger)
		})
		counts[i][1] = testing.AllocsPerRun(20, func() {
			leaves.i = 0
			_ = treeEmitNodesV1(old, 7, ep, id, leaves, emit, ledger)
		})
	}
	if counts[0] != counts[1] {
		t.Fatalf("K4 allocations differ: 1-leaf %v 64-leaf %v", counts[0], counts[1])
	}
	t.Logf("K4 allocations (fold, emit): %v", counts[0])
}

func testTreeSuffix(depth int, k [36]byte) []byte { return testTreeNodeKey(1, depth, k)[8:] }

func TestTreeEmitV1K5RecordCheck(t *testing.T) {
	replaceA := []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}
	type vec struct {
		name    string
		entries int
		depth   int
		k       [36]byte
		edit    func([]byte) []byte
	}
	set := func(off int, b []byte) func([]byte) []byte {
		return func(v []byte) []byte { w := append([]byte(nil), v...); copy(w[off:], b); return w }
	}
	bit0 := func(k [36]byte) [36]byte { k[0] |= 0x80; return k }
	code289 := append(testTreeSuffix(288, testKA)[:36], 0x01, 0x21)
	badMask := append(testTreeSuffix(288, testKA)[:36], 0x00, 0x02)
	vectors := []vec{
		{"leaf31", 1, 288, testKA, func(v []byte) []byte { return v[:31] }},
		{"leaf32", 1, 288, testKA, func(v []byte) []byte { return v }},
		{"leaf33", 1, 288, testKA, func(v []byte) []byte { return append(append([]byte(nil), v...), 0) }},
		{"branch139", 2, 287, [36]byte{}, func(v []byte) []byte { return v[:139] }},
		{"branch140", 2, 287, [36]byte{}, func(v []byte) []byte { return v }},
		{"branch141", 2, 287, [36]byte{}, func(v []byte) []byte { return append(append([]byte(nil), v...), 0) }},
		{"code289", 2, 287, [36]byte{}, set(0, code289)},
		{"mask", 2, 287, [36]byte{}, set(0, badMask)},
		{"depth-zero", 2, 287, [36]byte{}, set(0, testTreeSuffix(287, [36]byte{}))},
		{"depth-one", 2, 287, [36]byte{}, set(70, testTreeSuffix(287, [36]byte{}))},
		{"side-zero", 2, 287, [36]byte{}, set(0, testTreeSuffix(288, testKB))},
		{"side-one", 2, 287, [36]byte{}, set(70, testTreeSuffix(288, testKA))},
		{"prefix-zero", 2, 287, [36]byte{}, set(0, testTreeSuffix(288, bit0(testKA)))},
		{"prefix-one", 2, 287, [36]byte{}, set(70, testTreeSuffix(288, bit0(testKB)))},
	}
	for _, v := range vectors {
		var seeded []byte
		c := testTreeCase{oldEntries: testTreeABC()[:v.entries], stream: replaceA, mutate: func(rows map[string][]byte, b *RootBindingV1) {
			if b == nil {
				key := testTreeRef(7, v.depth, v.k)
				seeded = v.edit(rows[key])
				rows[key] = seeded
			}
		}}
		r := c.run(t, nil)
		id := TreeNodeIDV1{Kind: TreeNodeBranchV1, Depth: uint16(v.depth), Prefix: v.k}
		if v.depth == 288 {
			id = TreeNodeIDV1{Kind: TreeNodeLeafV1, Depth: 288, RoutingKey: v.k}
		}
		_, oracle := DecodeTreeNodeValue(id, seeded)
		if oracle == nil {
			if r.err != nil || r.foldErr != nil || len(r.emit.targets) != v.entries+1 {
				t.Fatalf("%s: oracle accepts, got %v %v %v", v.name, r.err, r.foldErr, r.emit.targets)
			}
			r.checkValues(t)
			continue
		}
		r.refusal(t, errSchema, "get")
	}
}

func TestTreeEmitV1H1BorrowedBuffers(t *testing.T) {
	cases := map[string]testTreeCase{
		"A4":  {stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, false, testTreeE()), testTreeStreamLeaf(7, testKB, false, testTreeE()), testTreeStreamLeaf(7, testKC, false, testTreeE())}},
		"A5":  {oldEntries: testTreeABC(), stream: []treeLeafV1{testTreeStreamLeaf(7, testKB, true, nil)}},
		"A8":  {oldEntries: testTreeABC()[:1], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}},
		"A10": {oldEntries: testTreeABC()[:2]},
		"A13": {oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}},
	}
	for name, c := range cases {
		plain := c.run(t, nil)
		h := c.run(t, func(o *testTreeOld, l *testTreeLeaves, e *testTreeEmit, _ *testTreeLedger) {
			o.scribble, l.scribble, e.scribble = true, true, o
		})
		plain.checkValues(t)
		h.checkValues(t)
		if !reflect.DeepEqual(plain.emit.targets, h.emit.targets) || !reflect.DeepEqual(plain.emit.values, h.emit.values) || !reflect.DeepEqual(plain.emit.refers, h.emit.refers) || h.err != nil {
			t.Fatalf("H1 %s differs: %v", name, h.err)
		}
	}
}

func TestTreeEmitV1H2MaximumValue(t *testing.T) {
	data := bytes.Repeat([]byte{0x33}, 65536)
	v := testTreeValue(1, data, 0, 0)
	r := testTreeCase{stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, false, v)}}.run(t, nil)
	b := r.accept(t, 7, []string{testTreeTarget(7, 288, testKA, true)}, nil, nil)
	want := testTreeLeafPreimage(testKA, v)
	if b.RootDigest != want || !bytes.Equal(r.emit.values[0], want[:]) {
		t.Fatal("H2")
	}
}

func TestTreeEmitV1H3DeepestBranchOrder(t *testing.T) {
	e := testTreeE()
	r := testTreeCase{stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, false, e), testTreeStreamLeaf(7, testKB, false, e), testTreeStreamLeaf(7, testKC, false, e)}}.run(t, nil)
	r.checkValues(t)
	if r.emit.targets[1] != testTreeTarget(7, 288, testKB, true) || r.emit.targets[2] != testTreeTarget(7, 287, [36]byte{}, true) {
		t.Fatalf("H3 order %v", r.emit.targets)
	}
	k8, k9 := testTreeKey(0, 0, 255), testTreeKey(0, 0, 256)
	r = testTreeCase{stream: []treeLeafV1{testTreeStreamLeaf(7, k8, false, e), testTreeStreamLeaf(7, k9, false, e)}}.run(t, nil)
	c8, c9 := testTreeLeafPreimage(k8, e), testTreeLeafPreimage(k9, e)
	want := append(append(append(testTreeSuffix(288, k8), c8[:]...), testTreeSuffix(288, k9)...), c9[:]...)
	if r.emit.targets[2] != testTreeTarget(7, 279, [36]byte{}, true) || !bytes.Equal(r.emit.values[2], want) {
		t.Fatalf("A9/H3 branch 279 value %x", r.emit.values[2])
	}
}

func TestTreeEmitV1R4R6Extended(t *testing.T) {
	sentinel := errors.New("sentinel")
	mismatch := &EngineError{Class: EngineStateMismatch, Operation: string(operationUpdate), Diagnostic: "OLD/write snapshot mismatch"}
	e := testTreeE()
	a4 := testTreeCase{stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, false, e), testTreeStreamLeaf(7, testKB, false, e), testTreeStreamLeaf(7, testKC, false, e)}}
	a5 := testTreeCase{oldEntries: testTreeABC(), stream: []treeLeafV1{testTreeStreamLeaf(7, testKB, true, nil)}}
	for _, inj := range []error{sentinel, mismatch} {
		for _, c := range []struct {
			tc testTreeCase
			n  int
		}{{a4, 1}, {a5, 1}, {a5, 4}} {
			r := c.tc.run(t, func(o *testTreeOld, _ *testTreeLeaves, _ *testTreeEmit, _ *testTreeLedger) {
				o.failN, o.fail = c.n, inj
			})
			if !testTreeExact(r.err, inj) || !testTreeExact(r.foldErr, inj) || len(r.reads) != c.n || len(r.foldRd) != c.n || len(r.emit.targets)+len(r.emit.refers) != 0 || r.log[len(r.log)-2] != "get" {
				t.Fatalf("R4 n=%d: %v %v", c.n, r.err, r.log)
			}
		}
	}
	r := a4.run(t, func(_ *testTreeOld, _ *testTreeLeaves, em *testTreeEmit, _ *testTreeLedger) {
		em.failAt, em.fail = 6, sentinel
	})
	if !testTreeExact(r.err, sentinel) || len(r.emit.targets) != 6 || r.log[len(r.log)-2] != "emit" {
		t.Fatalf("R6 binding emit: %v %v", r.err, r.log)
	}
	r = a4.run(t, func(_ *testTreeOld, _ *testTreeLeaves, em *testTreeEmit, _ *testTreeLedger) {
		em.failAt, em.fail = 1, sentinel
	})
	if !testTreeExact(r.err, sentinel) || len(r.emit.targets) != 1 || r.log[len(r.log)-2] != "emit" {
		t.Fatalf("R6 first emit: %v %v", r.err, r.log)
	}
}

// testTreeExact reports that err is want returned unchanged: same chain and same text, so no wrapper was added.
func testTreeExact(err, want error) bool {
	return errors.Is(err, want) && err.Error() == want.Error()
}
