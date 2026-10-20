//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
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
	rows  map[string][]byte
	log   *testTreeLog
	reads []string
	failN int
	fail  error
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
	return treeImageV1{present: true, value: append([]byte(nil), v...)}, nil
}

func (o *testTreeOld) nextV1(DBI, []byte) ([]byte, treeImageV1, bool, error) {
	o.log.add("next")
	return nil, treeImageV1{}, false, errors.New("nextV1 must not be called")
}

type testTreeLeaves struct {
	items []treeLeafV1
	i     int
	log   *testTreeLog
	failN int
	fail  error
}

func (l *testTreeLeaves) nextV1() (treeLeafV1, bool, error) {
	l.log.add("leaves")
	l.i++
	if l.failN == l.i {
		return treeLeafV1{}, false, l.fail
	}
	if l.i > len(l.items) {
		return treeLeafV1{}, false, nil
	}
	return l.items[l.i-1], true, nil
}

type testTreeEmit struct {
	targets []string
	values  [][]byte
	refers  []string
	log     *testTreeLog
	failAt  int
	fail    error
}

func (e *testTreeEmit) emitV1(t treeTargetV1) error {
	e.log.add("emit")
	e.targets = append(e.targets, fmt.Sprintf("%d:%x:%v", t.dbi.Rank, t.key, t.after.present))
	e.values = append(e.values, append([]byte(nil), t.after.value...))
	if e.failAt == len(e.targets) {
		return e.fail
	}
	return nil
}

func (e *testTreeEmit) referV1(dbi DBI, key []byte) error {
	e.log.add("refer")
	e.refers = append(e.refers, fmt.Sprintf("%d:%x", dbi.Rank, key))
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
	b := RootBindingV1{DatabaseID: [32]byte{0x44}, CommitmentVersion: 1, Endpoint: endpoint,
		Assurance: TreeAssuranceV1{Kind: TreeAssuranceFullHistoryV1}}
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

func (c testTreeCase) run(t *testing.T, tweak func(*testTreeOld, *testTreeLeaves, *testTreeEmit, *testTreeLedger)) testTreeRun {
	t.Helper()
	if c.g == 0 {
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
	r := testTreeRun{emit: emit}
	r.err = treeEmitNodesV1(old, c.g, c.endpoint, c.databaseID, leaves, emit, ledger)
	r.reads, r.log = old.reads, log.calls
	old2, leaves2, log2 := c.setup()
	ledger2 := &testTreeLedger{log: log2}
	if tweak != nil {
		tweak(old2, leaves2, &testTreeEmit{log: log2}, ledger2)
	}
	r.foldErr = treeFoldV1(old2, c.g, c.endpoint, c.databaseID, leaves2, ledger2)
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
	if b.DatabaseID != testTreeHash(0x44) || b.ChainID != testTreeHash(0x55) || b.GenesisHash != testTreeHash(0x66) || b.CommitmentVersion != 1 {
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
	c2 := testTreeCase{oldEntries: testTreeABC()[:1], oldEP: testTreeApplied(0, 0x77, 1), preGenesis: true,
		stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, nil)}}
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
	c := testTreeCase{oldEntries: testTreeABC()[:1], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())},
		mutate: func(_ map[string][]byte, b *RootBindingV1) {
			if b != nil {
				b.Assurance = TreeAssuranceV1{Kind: TreeAssuranceImportedBaseV1, Import: ref}
			}
		}}
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
func (r testTreeRun) refusal(t *testing.T, cause error) {
	t.Helper()
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
	r.refusal(t, nil)
	if want := []string{testTreeBindingKey(7), testTreeNodeRead(7, 0, [36]byte{}), testTreeNodeRead(7, 287, [36]byte{})}; !reflect.DeepEqual(r.reads, want) {
		t.Fatalf("reads %v", r.reads)
	}
}

func TestTreeEmitV1R2MalformedLeaf(t *testing.T) {
	c := testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())},
		mutate: func(rows map[string][]byte, b *RootBindingV1) {
			if b == nil {
				rows[testTreeRef(7, 288, testKA)] = append(rows[testTreeRef(7, 288, testKA)], 0)
			}
		}}
	c.run(t, nil).refusal(t, errSchema)
}

func TestTreeEmitV1R3Presence(t *testing.T) {
	c := testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}, mutate: testTreeRemove(7, 288, testKA)}
	c.run(t, nil).refusal(t, nil)
	c = testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKB, false, testTreeE())}}
	c.run(t, nil).refusal(t, nil)
}

func TestTreeEmitV1R4R5R6Injected(t *testing.T) {
	sentinel := errors.New("sentinel")
	base := testTreeCase{oldEntries: testTreeABC(), stream: []treeLeafV1{testTreeStreamLeaf(7, testKB, true, nil)}}
	for _, n := range []int{1, 4} {
		r := base.run(t, func(o *testTreeOld, _ *testTreeLeaves, _ *testTreeEmit, _ *testTreeLedger) {
			o.failN, o.fail = n, sentinel
		})
		if r.err != sentinel || r.foldErr != sentinel || len(r.reads) != n || len(r.emit.targets) != 0 {
			t.Fatalf("R4 n=%d: %v %v %v", n, r.err, r.foldErr, r.reads)
		}
	}
	for _, n := range []int{1, 2} {
		r := base.run(t, func(_ *testTreeOld, l *testTreeLeaves, _ *testTreeEmit, _ *testTreeLedger) {
			l.failN, l.fail = n, sentinel
		})
		if r.err != sentinel || r.foldErr != sentinel {
			t.Fatalf("R5 n=%d: %v %v", n, r.err, r.foldErr)
		}
	}
	r := base.run(t, func(_ *testTreeOld, _ *testTreeLeaves, e *testTreeEmit, _ *testTreeLedger) {
		e.failAt, e.fail = 1, sentinel
	})
	if r.err != sentinel || len(r.emit.targets) != 1 || len(r.emit.refers) != 0 {
		t.Fatalf("R6 emit: %v %v", r.err, r.emit.targets)
	}
	r = base.run(t, func(_ *testTreeOld, _ *testTreeLeaves, e *testTreeEmit, _ *testTreeLedger) {
		e.failAt, e.fail = -1, sentinel
	})
	if r.err != sentinel || len(r.emit.refers) != 1 || len(r.emit.targets) != 3 {
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
	c.run(t, nil).refusal(t, nil)
	c.mutate = func(rows map[string][]byte, b *RootBindingV1) {
		if b == nil {
			rows[testTreeBindingKey(7)] = rows[testTreeBindingKey(7)][:132]
		}
	}
	_, cause := DecodeRootBindingV1(make([]byte, 132))
	c.run(t, nil).refusal(t, cause)
	c = testTreeCase{oldEntries: testTreeABC()[:2], stream: ins, databaseID: testTreeHash(0x45)}
	c.run(t, nil).refusal(t, nil)
	c = testTreeCase{oldEntries: testTreeABC()[:2], oldEP: testTreeApplied(0, 0x77, 1), preGenesis: true,
		stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, nil)}}
	c.run(t, nil).refusal(t, errSchema)
}

func TestTreeEmitV1R13R14RootAndPath(t *testing.T) {
	c04 := testTreeHex(t, "1f3304724f76317f55c881875e5bcb741c00b090e1e1c2204d3b276aff069ac2")
	setRoot := func(rows map[string][]byte, b *RootBindingV1) {
		if b != nil {
			b.RootDigest = c04
		}
	}
	c := testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKA, true, testTreeA8Value())}, mutate: setRoot}
	c.run(t, nil).refusal(t, nil)
	b := testTreeCase{oldEntries: testTreeABC()[:2], mutate: setRoot}.run(t, nil).accept(t, 7, nil, []string{testTreeRef(7, 287, [36]byte{})}, nil)
	if b.RootDigest != c04 {
		t.Fatal("R13 control")
	}
	r := testTreeCase{oldEntries: testTreeABC()[:2], stream: []treeLeafV1{testTreeStreamLeaf(7, testKC, true, testTreeE())}}.run(t, nil)
	r.refusal(t, nil)
	if len(r.reads) != 1 {
		t.Fatalf("R14 reads %v", r.reads)
	}
}

func TestTreeEmitV1K2LedgerRefusal(t *testing.T) {
	sentinel := errors.New("refused")
	log := &testTreeLog{}
	old, leaves := &testTreeOld{rows: map[string][]byte{}, log: log}, &testTreeLeaves{log: log}
	ledger := &testTreeLedger{log: log, refuse: sentinel}
	if err := treeEmitNodesV1(old, 7, TreeEndpointV1{}, [32]byte{}, leaves, &testTreeEmit{log: log}, ledger); err != sentinel {
		t.Fatal(err)
	}
	if err := treeFoldV1(old, 7, TreeEndpointV1{}, [32]byte{}, leaves, ledger); err != sentinel {
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
		}
	}
	walk(reflect.TypeOf(f))
}
