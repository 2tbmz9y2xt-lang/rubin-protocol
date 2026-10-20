//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// Test-owned byte construction for the tree delta rows: keys, frames and stored values are built here from the
// schema layouts, never through the production function under test.

var tdSize = uint64(unsafe.Sizeof(treeDescV1{}))

const tdV = 65_560 // V = MAX_STATE_ENTRY_BYTES - 36

func tdTxid(b byte) [32]byte {
	var id [32]byte
	for i := range id {
		id[i] = b
	}
	return id
}

// tdFrame is one output frame: u64le value, u16le covenant_type, minimal CompactSize, covenant data.
func tdFrame(value uint64, covenant uint16, data []byte) []byte {
	b := binary.LittleEndian.AppendUint64(nil, value)
	b = binary.LittleEndian.AppendUint16(b, covenant)
	switch {
	case len(data) < 253:
		b = append(b, byte(len(data)))
	case len(data) <= 0xffff:
		b = append(b, 0xfd)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	default:
		b = append(b, 0xfe)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
	}
	return append(b, data...)
}

// tdFormed is frame || u64le(height) || coinbase.
func tdFormed(frame []byte, height uint64, coinbase byte) []byte {
	b := append(append([]byte(nil), frame...), make([]byte, 8)...)
	binary.LittleEndian.PutUint64(b[len(frame):], height)
	return append(b, coinbase)
}

func tdUTXOKey(gen uint64, txid [32]byte, vout uint32) []byte {
	b := binary.BigEndian.AppendUint64(nil, gen)
	b = append(b, txid[:]...)
	return binary.BigEndian.AppendUint32(b, vout)
}

func tdEntryKey(block, txid [32]byte, tx, in, vout uint32) []byte {
	b := append(append([]byte(nil), block[:]...), 1)
	b = binary.BigEndian.AppendUint32(b, tx)
	b = binary.BigEndian.AppendUint32(b, in)
	b = append(b, txid[:]...)
	return binary.BigEndian.AppendUint32(b, vout)
}

func tdManifestKey(block [32]byte) []byte { return append(append([]byte(nil), block[:]...), 0) }

func tdManifest(height uint64, generated [16]byte, txCount, spent uint32) []byte {
	b := binary.BigEndian.AppendUint64([]byte{1}, height)
	b = append(b, generated[:]...)
	b = binary.BigEndian.AppendUint32(b, txCount)
	return binary.BigEndian.AppendUint32(b, spent)
}

// tdEv is one provider event.
type tdEv struct {
	kind         uint8
	txid         [32]byte
	vout, tx, in uint32
	off          uint64
	n            uint32
}

func tdSpend(txid [32]byte, vout, tx, in uint32) tdEv {
	return tdEv{kind: 1, txid: txid, vout: vout, tx: tx, in: in}
}

func tdCreate(txid [32]byte, vout, tx uint32, off uint64, n uint32) tdEv {
	return tdEv{kind: 2, txid: txid, vout: vout, tx: tx, off: off, n: n}
}

func (e tdEv) feed(r *treeRecorderV1) error {
	return r.eventV1(e.kind, e.txid, e.vout, e.tx, e.in, e.off, e.n)
}

// tdLedger logs every call; limit 0 means unlimited. A non-nil gate blocks chargeV1 after it signals entered.
type tdLedger struct {
	mu      sync.Mutex
	limit   uint64
	used    uint64
	log     []string
	entered chan struct{}
	gate    chan struct{}
}

func (l *tdLedger) chargeV1(n uint64) error {
	if l.gate != nil {
		l.entered <- struct{}{}
		<-l.gate
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.log = append(l.log, fmt.Sprintf("charge %d", n))
	if l.limit != 0 && n > l.limit-l.used {
		return errOperationReservationCapacity
	}
	l.used += n
	return nil
}

func (l *tdLedger) releaseV1(n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.log = append(l.log, fmt.Sprintf("release %d", n))
	l.used -= n
}

func (l *tdLedger) logged() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.log, "|")
}

// tdNopLedger counts calls without allocating (H6, H7).
type tdNopLedger struct{ charges, releases int }

func (l *tdNopLedger) chargeV1(uint64) error { l.charges++; return nil }
func (l *tdNopLedger) releaseV1(uint64)      { l.releases++ }

// tdCase is one primitive: binding, BEGIN and events.
type tdCase struct {
	dir, undo uint8
	kind      uint8 // primitive kind; 0 means 1 (direct apply)
	height    uint64
	gen       uint64
	block     [32]byte
	generated [16]byte
	txCount   uint32
	events    []tdEv
	body      []byte
	pair      bool
}

func (c tdCase) prim() treePrimitiveV1 {
	kind := c.kind
	if kind == 0 {
		kind = 1
	}
	return treePrimitiveV1{direction: c.dir, kind: kind, undo: c.undo, generation: c.gen, height: c.height, block: c.block}
}

func (c tdCase) recorder(pos treePositionV1, ledger treeLedgerV1) *treeRecorderV1 {
	return newTreeRecorderV1(pos, c.prim(), treeBodyV1{bytes: c.body, pair: c.pair}, make([]byte, 65_536), ledger)
}

// delta runs BEGIN, every event and finishV1 at pos and fails the test on any refusal.
func (c tdCase) delta(t testing.TB, pos treePositionV1, ledger treeLedgerV1) (*treeRecorderV1, *treeDeltaV1) {
	t.Helper()
	r := c.recorder(pos, ledger)
	if err := r.beginV1(c.txCount, uint32(len(c.events)), c.generated); err != nil {
		t.Fatalf("beginV1: %v", err)
	}
	for i, e := range c.events {
		if err := e.feed(r); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	d, err := r.finishV1()
	if err != nil {
		t.Fatalf("finishV1: %v", err)
	}
	return r, d
}

func tdInvalid(t *testing.T, err error) {
	t.Helper()
	treeNativeError(t, err, operationUpdate, EngineInvalidInput, codeEINVAL, "invalid tree delta", nil)
}

func tdInactive(t *testing.T, err error) {
	t.Helper()
	treeNativeError(t, err, operationUpdate, EngineInvalidInput, codeEINVAL, "tree delta sink is not active", nil)
}

// tdMemRow and tdMemOld are a sorted in-memory treeOldV1 that never allocates.
type tdMemRow struct {
	rank       uint8
	key, value []byte
}

type tdMemOld struct{ rows []tdMemRow }

func tdMem(rows ...tdMemRow) *tdMemOld {
	old := &tdMemOld{rows: rows}
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && (rows[j].rank < rows[j-1].rank || rows[j].rank == rows[j-1].rank && bytes.Compare(rows[j].key, rows[j-1].key) < 0); j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	return old
}

func (m *tdMemOld) getV1(dbi DBI, key []byte) (treeImageV1, error) {
	for i := range m.rows {
		if m.rows[i].rank == dbi.Rank && bytes.Equal(m.rows[i].key, key) {
			return treeImageV1{present: true, value: m.rows[i].value}, nil
		}
	}
	return treeImageV1{}, nil
}

func (m *tdMemOld) nextV1(dbi DBI, from []byte) ([]byte, treeImageV1, bool, error) {
	for i := range m.rows {
		if m.rows[i].rank == dbi.Rank && bytes.Compare(m.rows[i].key, from) >= 0 {
			return m.rows[i].key, treeImageV1{present: true, value: m.rows[i].value}, true, nil
		}
	}
	return nil, treeImageV1{}, false, nil
}

// tdCountEmitter counts calls without allocating.
type tdCountEmitter struct{ emits, refers int }

func (e *tdCountEmitter) emitV1(treeTargetV1) error { e.emits++; return nil }
func (e *tdCountEmitter) referV1(DBI, []byte) error { e.refers++; return nil }

// tdGrammar is the A1 case: height 7, TxCount 3, five events with a vout gap.
func tdGrammar() tdCase {
	return tdCase{dir: 1, undo: 1, height: 7, gen: 9, txCount: 3, events: []tdEv{
		tdSpend(tdTxid(0xa1), 0, 1, 0), tdSpend(tdTxid(0xa2), 0, 1, 1),
		tdCreate(tdTxid(0x01), 0, 1, 0, 11), tdCreate(tdTxid(0x01), 2, 1, 11, 11), tdCreate(tdTxid(0x02), 0, 2, 22, 11),
	}, body: bytes.Repeat(tdFrame(5, 0, nil), 3)}
}

// A1: the closed grammar admits the stream; vout gaps are admitted.
func TestTreeDeltaGrammarV1(t *testing.T) {
	c := tdGrammar()
	r := c.recorder(treeWriterV1, &tdLedger{})
	if err := r.beginV1(3, 5, [16]byte{}); err != nil {
		t.Fatal(err)
	}
	for i, e := range c.events {
		if err := e.feed(r); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	if r.failureV1() != nil {
		t.Fatal("failure recorded")
	}
	if d, err := r.finishV1(); err != nil || d == nil {
		t.Fatalf("finishV1 %v %v", d, err)
	}
}

// A2, M9, M10: one charge of D_j + V before allocation at both positions; the constructor charges nothing.
func TestTreeDeltaChargeV1(t *testing.T) {
	if tdSize > 128 {
		t.Fatalf("descriptor size %d > 128", tdSize)
	}
	for _, count := range []uint32{0, 1, 1000} {
		want := uint64(count)*tdSize + tdV
		ledger := &tdLedger{}
		r := tdGrammar().recorder(treeWriterV1, ledger)
		if ledger.logged() != "" {
			t.Fatal("constructor made a ledger call")
		}
		if err := r.beginV1(3, count, [16]byte{}); err != nil {
			t.Fatal(err)
		}
		if got := ledger.logged(); got != fmt.Sprintf("charge %d", want) {
			t.Fatalf("count %d: ledger %s", count, got)
		}
		account := &tdLedger{}
		budget := &treeBudgetV1{held: 1 << 30, used: 5}
		rb := newTreeRecorderV1(treeReadbackV1, tdGrammar().prim(), treeBodyV1{}, nil, budget.ledgerV1())
		if err := rb.beginV1(3, count, [16]byte{}); err != nil {
			t.Fatal(err)
		}
		if budget.used != 5+want || account.logged() != "" {
			t.Fatalf("count %d: budget used %d", count, budget.used)
		}
	}
}

// A3 (in-memory sub-rows), M4: groups in native key order; CREATE, SPEND, CREATE of one key is OLD absent, NEW present.
func TestTreeDeltaGroupsV1(t *testing.T) {
	k, lo := tdTxid(0xc0), tdTxid(0x10)
	c := tdCase{dir: 1, undo: 2, height: 3, gen: 9, txCount: 4, body: bytes.Repeat(tdFrame(1, 0, nil), 3), events: []tdEv{
		tdCreate(k, 0, 1, 0, 11), tdSpend(k, 0, 2, 0), tdCreate(k, 0, 3, 11, 11), tdCreate(lo, 1, 3, 22, 11),
	}}
	r, _ := c.delta(t, treeWriterV1, &tdLedger{})
	var got []string
	for i := range r.descs {
		e := r.descs[i]
		got = append(got, fmt.Sprintf("%x/%d/%d/%d", e.txid[0], e.seq, e.group, e.flags&3))
	}
	if strings.Join(got, " ") != "10/3/0/2 c0/0/1/2 c0/1/1/0 c0/2/1/0" {
		t.Fatalf("groups %v", got)
	}
}

// A15 (a)-(e), M29, M35, M36, M-REL-NOEXP, M43: the recorder releases D_j + V once iff charged.
func TestTreeDeltaReleaseV1(t *testing.T) {
	want := fmt.Sprintf("charge %d|release %d", 3*tdSize+tdV, 3*tdSize+tdV)
	c := tdGrammar()
	c.events = c.events[:3]
	run := func(name string, steps func(r *treeRecorderV1), expect string) {
		ledger := &tdLedger{}
		r := c.recorder(treeWriterV1, ledger)
		steps(r)
		r.releaseV1()
		r.releaseV1()
		if got := ledger.logged(); got != expect {
			t.Fatalf("%s: ledger %s, want %s", name, got, expect)
		}
	}
	begin := func(r *treeRecorderV1) { mustEnvironment(t, r.beginV1(3, 3, [16]byte{})) }
	run("a", func(r *treeRecorderV1) {
		begin(r)
		for _, e := range c.events {
			mustEnvironment(t, e.feed(r))
		}
		if _, err := r.finishV1(); err != nil {
			t.Fatal(err)
		}
	}, want)
	run("b", func(r *treeRecorderV1) {
		begin(r)
		for _, e := range c.events[:2] {
			mustEnvironment(t, e.feed(r))
		}
		_, err := r.finishV1()
		tdInvalid(t, err)
	}, want)
	run("c", func(r *treeRecorderV1) { begin(r); r.expireV1() }, want)
	run("d never", func(r *treeRecorderV1) {}, "")
	run("d refused", func(r *treeRecorderV1) { tdInvalid(t, r.beginV1(0, 3, [16]byte{})) }, "")
	refusing := &tdLedger{limit: 1}
	rr := c.recorder(treeWriterV1, refusing)
	if err := rr.beginV1(3, 3, [16]byte{}); !sameError(err, errOperationReservationCapacity) {
		t.Fatalf("charge refusal %v", err)
	}
	rr.releaseV1()
	if got := refusing.logged(); got != fmt.Sprintf("charge %d", 3*tdSize+tdV) {
		t.Fatalf("d charge refused: %s", got)
	}
	// (e) D26: releaseV1 on a fresh recorder expires it.
	ledger := &tdLedger{}
	r := c.recorder(treeWriterV1, ledger)
	r.releaseV1()
	tdInactive(t, r.beginV1(3, 3, [16]byte{}))
	if ledger.logged() != "" || r.failureV1() != nil || r.windowV1() != nil {
		t.Fatalf("e: ledger %s", ledger.logged())
	}
	r.releaseV1()
	if ledger.logged() != "" {
		t.Fatal("e: second release")
	}
	// Readback (a): the budget gets the amount back.
	budget := &treeBudgetV1{held: 1 << 20, used: 7}
	rb := newTreeRecorderV1(treeReadbackV1, c.prim(), treeBodyV1{bytes: c.body}, nil, budget.ledgerV1())
	mustEnvironment(t, rb.beginV1(3, 3, [16]byte{}))
	for _, e := range c.events {
		mustEnvironment(t, e.feed(rb))
	}
	if _, err := rb.finishV1(); err != nil {
		t.Fatal(err)
	}
	rb.releaseV1()
	if budget.used != 7 {
		t.Fatalf("readback release: used %d", budget.used)
	}
}

// A19, M43: the readback release returns the bytes before the next primitive's draw.
func TestTreeDeltaReadbackReturnV1(t *testing.T) {
	five := tdGrammar()
	two := tdGrammar()
	two.events = two.events[:2]
	for _, release := range []bool{true, false} {
		budget := &treeBudgetV1{held: 5*tdSize + tdV}
		r1, _ := five.delta(t, treeReadbackV1, budget.ledgerV1())
		if release {
			r1.releaseV1()
		}
		r2 := two.recorder(treeReadbackV1, budget.ledgerV1())
		err := r2.beginV1(3, 2, [16]byte{})
		if release && err != nil || !release && !sameError(err, errOperationReservationCapacity) {
			t.Fatalf("release %v: second draw %v", release, err)
		}
	}
}

// R1, M1, M2, M6, M49: every grammar refusal is invalid tree delta, recorded, with no further charge.
func TestTreeDeltaGrammarRefusalsV1(t *testing.T) {
	a, k := tdTxid(0xa1), tdTxid(0x01)
	body := bytes.Repeat([]byte{0}, 70_000)
	cases := []struct {
		name   string
		before []tdEv
		begin  bool
		event  tdEv
	}{
		{"before BEGIN", nil, false, tdSpend(a, 0, 1, 0)},
		{"kind 0", nil, true, tdEv{kind: 0, txid: a, tx: 1}},
		{"kind 3", nil, true, tdEv{kind: 3, txid: a, tx: 1}},
		{"SPEND offset 1", nil, true, tdEv{kind: 1, txid: a, tx: 1, off: 1}},
		{"SPEND length 1", nil, true, tdEv{kind: 1, txid: a, tx: 1, n: 1}},
		{"CREATE input 1", nil, true, tdEv{kind: 2, txid: k, tx: 1, in: 1, n: 11}},
		{"CREATE length 10", nil, true, tdCreate(k, 0, 1, 0, 10)},
		{"CREATE length 65552", nil, true, tdCreate(k, 0, 1, 0, 65_552)},
		{"CREATE offset overflow", nil, true, tdCreate(k, 0, 1, ^uint64(0)-10, 11)},
		{"txIndex == TxCount", nil, true, tdSpend(a, 0, 3, 0)},
		{"duplicate", []tdEv{tdSpend(a, 0, 1, 0)}, true, tdSpend(a, 1, 1, 0)},
		{"smaller", []tdEv{tdSpend(a, 0, 2, 0)}, true, tdSpend(a, 1, 1, 5)},
		{"SPEND after CREATE", []tdEv{tdCreate(k, 0, 1, 0, 11)}, true, tdSpend(a, 0, 1, 9)},
		{"EventCount+1", []tdEv{tdSpend(a, 0, 1, 0), tdSpend(a, 1, 1, 1), tdSpend(a, 2, 1, 2), tdSpend(a, 3, 1, 3)}, true, tdSpend(a, 4, 1, 4)},
	}
	for _, tc := range cases {
		ledger := &tdLedger{}
		c := tdCase{dir: 1, undo: 1, height: 7, gen: 9, body: body}
		r := c.recorder(treeWriterV1, ledger)
		if tc.begin {
			mustEnvironment(t, r.beginV1(3, 4, [16]byte{}))
		}
		for _, e := range tc.before {
			mustEnvironment(t, e.feed(r))
		}
		calls := ledger.logged()
		err := tc.event.feed(r)
		tdInvalid(t, err)
		if !sameError(r.failureV1(), err) || ledger.logged() != calls || len(r.descs) != len(tc.before) {
			t.Fatalf("%s: not recorded or charged", tc.name)
		}
	}
	admitted := tdCase{dir: 1, undo: 1, height: 7, gen: 9, body: body}
	for _, n := range []uint32{11, 65_551} {
		r := admitted.recorder(treeWriterV1, &tdLedger{})
		mustEnvironment(t, r.beginV1(3, 1, [16]byte{}))
		mustEnvironment(t, tdCreate(k, 0, 1, 0, n).feed(r))
	}
	for _, second := range []string{"second BEGIN", "BEGIN after event"} {
		ledger := &tdLedger{}
		r := admitted.recorder(treeWriterV1, ledger)
		if second == "second BEGIN" {
			mustEnvironment(t, r.beginV1(3, 1, [16]byte{}))
		} else {
			tdInvalid(t, tdSpend(a, 0, 1, 0).feed(r))
		}
		calls, recorded := ledger.logged(), r.failureV1()
		err := r.beginV1(3, 1, [16]byte{})
		tdInvalid(t, err)
		if !sameError(r.failureV1(), err) || recorded != nil && !sameError(err, recorded) || ledger.logged() != calls {
			t.Fatalf("%s: not recorded", second)
		}
	}
	// finishV1 on a fresh recorder with no BEGIN (G6): returned, not recorded, no ledger call.
	fresh := &tdLedger{}
	rf := admitted.recorder(treeWriterV1, fresh)
	_, err0 := rf.finishV1()
	tdInvalid(t, err0)
	if rf.failureV1() != nil || fresh.logged() != "" {
		t.Fatal("finishV1 without BEGIN recorded or charged")
	}
	// finishV1 after EventCount-1 events: returned, not recorded, no charge.
	ledger := &tdLedger{}
	r := admitted.recorder(treeWriterV1, ledger)
	mustEnvironment(t, r.beginV1(3, 2, [16]byte{}))
	mustEnvironment(t, tdSpend(a, 0, 1, 0).feed(r))
	calls := ledger.logged()
	if r.failureV1() != nil {
		t.Fatal("failure before finishV1")
	}
	_, err := r.finishV1()
	tdInvalid(t, err)
	if r.failureV1() != nil || ledger.logged() != calls {
		t.Fatal("finishV1 count refusal recorded or charged")
	}
}

// R2, M5: two consecutive SPENDs or CREATEs of one key are refused by finishV1, not recorded.
func TestTreeDeltaGroupRefusalsV1(t *testing.T) {
	k := tdTxid(0x33)
	for name, events := range map[string][]tdEv{
		"double SPEND":  {tdSpend(k, 0, 3, 0), tdSpend(k, 0, 5, 0)},
		"double CREATE": {tdCreate(k, 0, 3, 0, 11), tdCreate(k, 0, 5, 11, 11)},
	} {
		c := tdCase{dir: 1, undo: 1, height: 7, gen: 9, txCount: 6, events: events, body: bytes.Repeat(tdFrame(1, 0, nil), 2)}
		r := c.recorder(treeWriterV1, &tdLedger{})
		mustEnvironment(t, r.beginV1(6, 2, [16]byte{}))
		for _, e := range events {
			mustEnvironment(t, e.feed(r))
		}
		if r.failureV1() != nil {
			t.Fatal(name)
		}
		_, err := r.finishV1()
		tdInvalid(t, err)
		if r.failureV1() != nil {
			t.Fatalf("%s: recorded", name)
		}
	}
}

// R5, M10: a refused charge returns the capacity singleton by identity, recorded, nothing allocated.
func TestTreeDeltaChargeRefusedV1(t *testing.T) {
	c := tdGrammar()
	need := 5*tdSize + tdV
	ledger := &tdLedger{limit: need - 1}
	r := c.recorder(treeWriterV1, ledger)
	err := r.beginV1(3, 5, [16]byte{})
	if !sameError(err, errOperationReservationCapacity) || !sameError(r.failureV1(), err) || r.descs != nil || r.value != nil {
		t.Fatalf("writer refusal %v", err)
	}
	if !sameError(c.events[0].feed(r), err) {
		t.Fatal("later eventV1 did not return the recorded object")
	}
	account := &tdLedger{}
	budget := &treeBudgetV1{held: need - 1, used: 0}
	rb := c.recorder(treeReadbackV1, budget.ledgerV1())
	if err := rb.beginV1(3, 5, [16]byte{}); !sameError(err, errOperationReservationCapacity) || budget.used != 0 || account.logged() != "" || rb.descs != nil {
		t.Fatalf("readback refusal %v used %d", err, budget.used)
	}
}

// R7, M25, M26, M27, M30: BEGIN constraints refuse before any charge; a height-0 SPEND is refused at eventV1.
func TestTreeDeltaBeginConstraintsV1(t *testing.T) {
	last := [16]byte{15: 1}
	for _, tc := range []struct {
		height    uint64
		txCount   uint32
		generated [16]byte
	}{{5, 0, [16]byte{}}, {0, 2, [16]byte{}}, {0, 1, last}} {
		ledger := &tdLedger{}
		r := tdCase{dir: 1, undo: 1, height: tc.height, gen: 9}.recorder(treeWriterV1, ledger)
		err := r.beginV1(tc.txCount, 1, tc.generated)
		tdInvalid(t, err)
		if !sameError(r.failureV1(), err) || ledger.logged() != "" {
			t.Fatalf("%+v: recorded %v ledger %s", tc, r.failureV1(), ledger.logged())
		}
	}
	ledger := &tdLedger{}
	r := tdCase{dir: 1, undo: 1, height: 0, gen: 9}.recorder(treeWriterV1, ledger)
	mustEnvironment(t, r.beginV1(1, 1, [16]byte{}))
	err := tdSpend(tdTxid(1), 0, 0, 0).feed(r)
	tdInvalid(t, err)
	if !sameError(r.failureV1(), err) {
		t.Fatal("height-0 SPEND not recorded")
	}
	// A13: the admitted height-0 coinbase BEGIN and the height-1 rules.
	ok := tdCase{dir: 1, undo: 1, height: 0, gen: 9, body: tdFrame(1, 0, nil)}.recorder(treeWriterV1, &tdLedger{})
	mustEnvironment(t, ok.beginV1(1, 1, [16]byte{}))
	mustEnvironment(t, tdCreate(tdTxid(1), 0, 0, 0, 11).feed(ok))
	one := tdCase{dir: 1, undo: 1, height: 1, gen: 9}.recorder(treeWriterV1, &tdLedger{})
	mustEnvironment(t, one.beginV1(1, 1, [16]byte{3: 9}))
	mustEnvironment(t, tdSpend(tdTxid(1), 0, 0, 0).feed(one))
}

// R8, M21, M37: after expiry sink calls are not active, unrecorded and uncharged; windowV1 is nil.
func TestTreeDeltaExpiryV1(t *testing.T) {
	c := tdGrammar()
	for _, failed := range []bool{false, true} {
		ledger := &tdLedger{}
		r := c.recorder(treeWriterV1, ledger)
		var first error
		if failed {
			first = r.beginV1(0, 1, [16]byte{})
		}
		r.expireV1()
		r.expireV1()
		calls := ledger.logged()
		tdInactive(t, r.beginV1(3, 5, [16]byte{}))
		if !sameError(r.failureV1(), first) {
			t.Fatal("beginV1 refusal changed failureV1")
		}
		tdInactive(t, c.events[0].feed(r))
		if !sameError(r.failureV1(), first) || ledger.logged() != calls || r.windowV1() != nil {
			t.Fatal("post-expiry eventV1 recorded, charged or window lent")
		}
	}
	r, _ := c.delta(t, treeWriterV1, &tdLedger{})
	tdInactive(t, c.events[0].feed(r))
	if r.failureV1() != nil {
		t.Fatal("finishV1 expiry recorded")
	}
}

// H1, M3: after a refusal every later call returns the first recorded object.
func TestTreeDeltaStickyFailureV1(t *testing.T) {
	c := tdGrammar()
	ledger := &tdLedger{}
	r := c.recorder(treeWriterV1, ledger)
	mustEnvironment(t, r.beginV1(3, 5, [16]byte{}))
	first := tdEv{kind: 3, txid: tdTxid(1), tx: 1}.feed(r)
	tdInvalid(t, first)
	calls := ledger.logged()
	if !sameError(c.events[0].feed(r), first) || !sameError(r.beginV1(3, 5, [16]byte{}), first) || !sameError(r.failureV1(), first) {
		t.Fatal("later call did not return the first object")
	}
	if _, err := r.finishV1(); !sameError(err, first) || ledger.logged() != calls {
		t.Fatal("finishV1 did not return the first object")
	}
}

// H2: the maximal count is charged in u64 without overflow and refused; nothing is allocated.
func TestTreeDeltaMaximalCountV1(t *testing.T) {
	ledger := &tdLedger{limit: 402_653_184}
	r := tdGrammar().recorder(treeWriterV1, ledger)
	err := r.beginV1(3, ^uint32(0), [16]byte{})
	want := uint64(^uint32(0))*tdSize + tdV
	if !sameError(err, errOperationReservationCapacity) || ledger.logged() != fmt.Sprintf("charge %d", want) || r.descs != nil || r.value != nil {
		t.Fatalf("maximal count %v %s", err, ledger.logged())
	}
}

// H3: windowV1 lends the same slice; provider writes into it change no descriptor.
func TestTreeDeltaWindowV1(t *testing.T) {
	c := tdGrammar()
	window := make([]byte, 65_536)
	r := newTreeRecorderV1(treeWriterV1, c.prim(), treeBodyV1{bytes: c.body}, window, &tdLedger{})
	mustEnvironment(t, r.beginV1(3, 5, [16]byte{}))
	for _, e := range c.events {
		mustEnvironment(t, e.feed(r))
	}
	before := append([]treeDescV1(nil), r.descs...)
	for i := 0; i < 3; i++ {
		w := r.windowV1()
		if len(w) != 65_536 || &w[0] != &window[0] {
			t.Fatal("window slice changed")
		}
		for j := range w {
			w[j] = 0xff
		}
	}
	for i := range before {
		if fmt.Sprint(before[i]) != fmt.Sprint(r.descs[i]) {
			t.Fatal("window write changed a descriptor")
		}
	}
}

// H4, M21: a retained sink call racing expiry is refused once expired, with no charge or descriptor change.
func TestTreeDeltaRetainedSinkV1(t *testing.T) {
	c := tdGrammar()
	ledger := &tdLedger{}
	r := c.recorder(treeWriterV1, ledger)
	mustEnvironment(t, r.beginV1(3, 5, [16]byte{}))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.expireV1() }()
	go func() { defer wg.Done(); _ = c.events[0].feed(r) }()
	wg.Wait()
	calls, events := ledger.logged(), len(r.descs)
	done := make(chan error)
	go func() { done <- c.events[1].feed(r) }()
	tdInactive(t, <-done)
	if ledger.logged() != calls || len(r.descs) != events {
		t.Fatal("expired sink charged or recorded")
	}
}

// tdBlocking returns a ledger whose chargeV1 signals entry and then blocks until gate is closed.
func tdBlocking() *tdLedger {
	return &tdLedger{entered: make(chan struct{}, 1), gate: make(chan struct{})}
}

// tdNotDone asserts that done stays open for a bounded wait while the charge is blocked (T8).
func tdNotDone(t *testing.T, done chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s completed while the charge was in flight", name)
	case <-time.After(100 * time.Millisecond):
	}
}

// H5, M38: expireV1 waits for an in-flight beginV1.
func TestTreeDeltaExpireWaitsV1(t *testing.T) {
	c := tdGrammar()
	ledger := tdBlocking()
	r := c.recorder(treeWriterV1, ledger)
	beginDone, expireDone := make(chan error, 1), make(chan struct{})
	go func() { beginDone <- r.beginV1(3, 5, [16]byte{}) }()
	<-ledger.entered
	go func() { r.expireV1(); close(expireDone) }()
	tdNotDone(t, expireDone, "expireV1")
	close(ledger.gate)
	mustEnvironment(t, <-beginDone)
	<-expireDone
	tdInactive(t, c.events[0].feed(r))
	if r.failureV1() != nil {
		t.Fatal("failure changed")
	}
}

// H9, M-REL-NOWAIT: releaseV1 waits for an in-flight charge, then releases it once.
func TestTreeDeltaReleaseWaitsV1(t *testing.T) {
	c := tdGrammar()
	ledger := tdBlocking()
	r := c.recorder(treeWriterV1, ledger)
	beginDone, releaseDone := make(chan error, 1), make(chan struct{})
	go func() { beginDone <- r.beginV1(3, 3, [16]byte{}) }()
	<-ledger.entered
	go func() { r.releaseV1(); close(releaseDone) }()
	tdNotDone(t, releaseDone, "releaseV1")
	close(ledger.gate)
	mustEnvironment(t, <-beginDone)
	<-releaseDone
	n := 3*tdSize + tdV
	if got := ledger.logged(); got != fmt.Sprintf("charge %d|release %d", n, n) {
		t.Fatalf("ledger %s", got)
	}
	tdInactive(t, r.beginV1(3, 3, [16]byte{}))
	tdInactive(t, c.events[0].feed(r))
	r.releaseV1()
	if r.failureV1() != nil || ledger.logged() != fmt.Sprintf("charge %d|release %d", n, n) {
		t.Fatal("after release")
	}
}

// tdAllocCase is the H6 primitive: CREATE kB (tx 0), SPEND kA and kD (tx 1), CREATE kE (tx 1); kA's OLD value
// carries covenant data, so S13 runs over a value whose decode would copy.
func tdAllocCase(undo uint8) (tdCase, *tdMemOld) {
	block, gen := tdTxid(0xbb), uint64(9)
	tx0, tx1, ka, kd := tdTxid(0x20), tdTxid(0x21), tdTxid(0x0a), tdTxid(0x0d)
	fb, fe := tdFrame(50, 0, nil), tdFrame(60, 0, []byte{7, 7})
	c := tdCase{dir: 1, undo: undo, height: 7, gen: gen, block: block, txCount: 2, body: append(append([]byte(nil), fb...), fe...), events: []tdEv{
		tdCreate(tx0, 0, 0, 0, uint32(len(fb))), tdSpend(ka, 0, 1, 0), tdSpend(kd, 0, 1, 1), tdCreate(tx1, 0, 1, uint64(len(fb)), uint32(len(fe))),
	}}
	va, vd := tdFormed(tdFrame(10, 0, []byte{1, 2, 3}), 2, 0), tdFormed(tdFrame(11, 0, nil), 2, 0)
	family := []tdMemRow{
		{5, tdManifestKey(block), tdManifest(7, [16]byte{}, 2, 2)},
		{5, tdEntryKey(block, ka, 1, 0, 0), va}, {5, tdEntryKey(block, kd, 1, 1, 0), vd},
	}
	rows := []tdMemRow{{4, block[:], c.body}}
	if undo >= 5 {
		c.dir = 2
		rows = append(rows, tdMemRow{1, tdUTXOKey(gen, tx0, 0), tdFormed(fb, 7, 1)}, tdMemRow{1, tdUTXOKey(gen, tx1, 0), tdFormed(fe, 7, 0)})
	} else {
		rows = append(rows, tdMemRow{1, tdUTXOKey(gen, ka, 0), va}, tdMemRow{1, tdUTXOKey(gen, kd, 0), vd})
	}
	if undo != 1 && undo != 2 {
		rows = append(rows, family...)
	}
	return c, tdMem(rows...)
}

func tdAllocs(t *testing.T, name string, f func()) {
	t.Helper()
	if n := testing.AllocsPerRun(1, f); n != 0 {
		t.Errorf("%s: %v allocations", name, n)
	}
}

// H6, M39, M42, M-OLDV-DECODE: the per-call paths make no heap allocation under each effect.
func TestTreeDeltaZeroAllocV1(t *testing.T) {
	for undo := uint8(1); undo <= 6; undo++ {
		c, old := tdAllocCase(undo)
		ledger := &tdNopLedger{}
		r := c.recorder(treeWriterV1, ledger)
		mustEnvironment(t, r.beginV1(c.txCount, 4, [16]byte{}))
		mustEnvironment(t, c.events[0].feed(r))
		mustEnvironment(t, c.events[1].feed(r))
		next := 2
		tdAllocs(t, "eventV1", func() { mustEnvironment(t, c.events[next].feed(r)); next++ })
		tdAllocs(t, "windowV1", func() { _ = r.windowV1() })
		tdAllocs(t, "failureV1", func() { _ = r.failureV1() })
		d, err := r.finishV1()
		mustEnvironment(t, err)
		tdAllocs(t, fmt.Sprintf("resolveV1 %d", undo), func() { mustEnvironment(t, d.resolveV1(old)) })
		emit := &tdCountEmitter{}
		tdAllocs(t, fmt.Sprintf("applyV1 %d", undo), func() { mustEnvironment(t, d.applyV1(emit)) })
		it := d.leavesV1()
		tdAllocs(t, "leaves nextV1", func() { _, _, _ = it.nextV1() })
		tdAllocs(t, "expireV1", r.expireV1)
		tdAllocs(t, "releaseV1", r.releaseV1)
	}
	entry := tdFormed(tdFrame(1, 0, make([]byte, 65_536)), 1, 0)
	key := tdEntryKey(tdTxid(1), tdTxid(2), 0, 0, 0)
	if len(entry) != tdV || !treeUndoValueOKV1(key, entry) {
		t.Fatalf("65,560-byte entry len %d", len(entry))
	}
	tdAllocs(t, "S6c check", func() { _ = treeUndoValueOKV1(key, entry) })
}

// tdSequence runs one primitive's full sequence over n coinbase CREATE events (H7).
func tdSequence(t testing.TB, c tdCase, old treeOldV1, n int) func() {
	return func() {
		ledger, emit := &tdNopLedger{}, &tdCountEmitter{}
		r := newTreeRecorderV1(treeWriterV1, c.prim(), treeBodyV1{bytes: c.body}, nil, ledger)
		tdMust(t, r.beginV1(1, uint32(n), [16]byte{}))
		for _, e := range c.events[:n] {
			tdMust(t, e.feed(r))
		}
		d, err := r.finishV1()
		tdMust(t, err)
		tdMust(t, d.resolveV1(old))
		for range 2 {
			it := d.leavesV1()
			for _, ok, _ := it.nextV1(); ok; _, ok, _ = it.nextV1() {
			}
		}
		tdMust(t, d.applyV1(emit))
		r.releaseV1()
	}
}

func tdMust(t testing.TB, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

// H7, M47: the allocation count of one primitive does not depend on EventCount.
func TestTreeDeltaAllocsPerEventV1(t *testing.T) {
	frame := tdFrame(1, 0, nil)
	c := tdCase{dir: 1, undo: 1, height: 7, gen: 9, block: tdTxid(0xbb), body: bytes.Repeat(frame, 64)}
	for i := 0; i < 64; i++ {
		c.events = append(c.events, tdCreate(tdTxid(0x30), uint32(i), 0, uint64(i*len(frame)), uint32(len(frame))))
	}
	old := tdMem()
	one := testing.AllocsPerRun(5, tdSequence(t, c, old, 1))
	many := testing.AllocsPerRun(5, tdSequence(t, c, old, 64))
	if one != many {
		t.Fatalf("allocations %v at 1, %v at 64", one, many)
	}
}

//go:noinline
func tdStoredBody(old treeOldV1, block [32]byte) (treeBodyV1, error) {
	return treeStoredBodyV1(old, block)
}

// H8, M-SB-COPY, M-SB-EXTRA, M-SB-WIDE: the stored body aliases the image; at most one 32-byte allocation.
func TestTreeDeltaStoredBodyAllocV1(t *testing.T) {
	block := tdTxid(0x44)
	v := []byte("stored block body bytes")
	old := tdMem(tdMemRow{4, block[:], v})
	body, err := tdStoredBody(old, block)
	if err != nil || body.pair || len(body.bytes) != len(v) || &body.bytes[0] != &v[0] {
		t.Fatalf("stored body %v %v", body, err)
	}
	if n := testing.AllocsPerRun(10, func() { _, _ = tdStoredBody(old, block) }); n > 1 {
		t.Fatalf("allocations %v", n)
	}
	result := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_, _ = tdStoredBody(old, block)
		}
	})
	if bytes := result.AllocedBytesPerOp(); bytes > 32 {
		t.Fatalf("allocated %d bytes per call", bytes)
	}
}

// BenchmarkTreeDeltaSequenceV1 measures one primitive's sequence over 64 coinbase CREATE events.
func BenchmarkTreeDeltaSequenceV1(b *testing.B) {
	frame := tdFrame(1, 0, nil)
	c := tdCase{dir: 1, undo: 1, height: 7, gen: 9, block: tdTxid(0xbb), body: bytes.Repeat(frame, 64)}
	for i := 0; i < 64; i++ {
		c.events = append(c.events, tdCreate(tdTxid(0x30), uint32(i), 0, uint64(i*len(frame)), uint32(len(frame))))
	}
	run := tdSequence(b, c, tdMem(), 64)
	b.ReportAllocs()
	for range b.N {
		run()
	}
}
