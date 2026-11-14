package consensus

import (
	"bytes"
	"errors"
	"maps"
	"math/big"
	"reflect"
	"testing"
)

// Both owners must implement mathematical inequalities rather than overflowing
// uint64 products. The literal admitted pair is pinned independently of them.
func TestLogicalStateMathematicalEnvelope(t *testing.T) {
	const height uint64 = 4294967295
	const count uint64 = 281217514386694
	const total uint64 = 15748180805654864
	product := new(big.Int).Mul(new(big.Int).SetUint64(count), big.NewInt(65596))
	if product.IsUint64() {
		t.Fatal("boundary fixture does not overflow the upper uint64 product")
	}
	for _, tc := range []struct {
		name    string
		bytes   uint64
		entries uint64
		valid   bool
	}{
		{"large-admitted", total, count, true},
		{"large-lower-minus-one", total - 1, count, false},
		{"lower", 112, 2, true},
		{"lower-minus-one", 111, 2, false},
		{"upper", 131192, 2, true},
		{"upper-plus-one", 131193, 2, false},
		{"empty", 0, 0, true},
		{"nonempty-zero-total", 0, 1, false},
		{"empty-nonzero-total", 1, 0, false},
		{"uint64-total", ^uint64(0), ^uint64(0) / 56, true},
		{"count-over-lower", 56, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lo := new(big.Int).Mul(new(big.Int).SetUint64(tc.entries), big.NewInt(56))
			hi := new(big.Int).Mul(new(big.Int).SetUint64(tc.entries), big.NewInt(65596))
			value := new(big.Int).SetUint64(tc.bytes)
			oracle := value.Cmp(lo) >= 0 && value.Cmp(hi) <= 0
			if oracle != tc.valid {
				t.Fatalf("independent mathematical oracle = %v, want %v", oracle, tc.valid)
			}
			if got := validLogicalStateResidualEnvelope(tc.bytes, tc.entries); got != oracle {
				t.Fatalf("residual mathematical envelope = %v, want %v", got, oracle)
			}
			bounded := oracle && tc.bytes <= height*86545430 && tc.entries <= height*1545454
			if got := validLogicalStateCounterEnvelope(logicalStateCounters{bytes: tc.bytes, entries: tc.entries}, height); got != bounded {
				t.Fatalf("record mathematical envelope = %v, want %v", got, bounded)
			}
		})
	}
	if validLogicalStateCounterEnvelope(logicalStateCounters{bytes: 56 * 1545455, entries: 1545455}, 1) {
		t.Fatal("per-height count guard was lost")
	}
	if validLogicalStateCounterEnvelope(logicalStateCounters{bytes: 86545431, entries: 2000}, 1) {
		t.Fatal("per-height byte guard was lost")
	}
}

type logicalStateTestView struct {
	counter      logicalStateCounterRead
	rows         map[Outpoint]logicalStateRowRead
	counterCalls int
	lookups      []Outpoint
}

func (v *logicalStateTestView) Counters() logicalStateCounterRead {
	v.counterCalls++
	return v.counter
}

func (v *logicalStateTestView) Lookup(op Outpoint) logicalStateRowRead {
	v.lookups = append(v.lookups, op)
	return v.rows[op]
}

type logicalStateRecordTestView struct {
	logicalStateTestView
	length      uint32
	present, ok bool
	recordCalls int
}

func (v *logicalStateRecordTestView) recordedV1(Outpoint) (uint32, bool, bool) {
	v.recordCalls++
	return v.length, v.present, v.ok
}

func TestLogicalStateRecordedPlanRows(t *testing.T) {
	op := Outpoint{Txid: filled32(17)}
	final := logicalStateTestEntry(1, 3)
	for _, tc := range []struct {
		name           string
		ok, present    bool
		finalPresent   bool
		parent, result logicalStateCounters
		deletes, puts  int
		lookups        int
	}{
		{"fallback", false, false, true, logicalStateCounters{}, logicalStateCounters{bytes: 57, entries: 1}, 0, 1, 1},
		{"absent-delete", true, false, false, logicalStateCounters{}, logicalStateCounters{}, 0, 0, 0},
		{"absent-put", true, false, true, logicalStateCounters{}, logicalStateCounters{bytes: 57, entries: 1}, 0, 1, 0},
		{"present-delete", true, true, false, logicalStateCounters{bytes: 311, entries: 1}, logicalStateCounters{}, 1, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := &logicalStateRecordTestView{present: tc.present, ok: tc.ok}
			if tc.present {
				view.length = 311
			}
			view.counter = logicalStateCounterRead{kind: logicalStateCountersPresent, counters: tc.parent}
			view.rows = map[Outpoint]logicalStateRowRead{op: {kind: logicalStateRowAbsent}}
			touch := logicalTouchedState{Outpoint: op, FinalPresent: tc.finalPresent}
			if tc.finalPresent {
				touch.Final = final
			}
			plan, failure := buildLogicalStatePlan(6, view, []logicalTouchedState{touch}, 19)
			if failure != nil || plan.Parent != tc.parent || plan.Result != tc.result || plan.Metadata != 19 || len(plan.Deletes) != tc.deletes || len(plan.Puts) != tc.puts || len(view.lookups) != tc.lookups || view.recordCalls != 1 {
				t.Fatalf("record plan %s: %+v/%v calls %+v/%d", tc.name, plan, failure, view.lookups, view.recordCalls)
			}
			if tc.deletes != 0 && plan.Deletes[0] != (logicalStateDelete{Outpoint: op, EntryBytes: 311}) {
				t.Fatalf("record deletion lost literal length: %+v", plan.Deletes)
			}
			if tc.puts != 0 && (plan.Puts[0].Outpoint != op || !reflect.DeepEqual(plan.Puts[0].Entry, final)) {
				t.Fatalf("record put lost final entry: %+v", plan.Puts)
			}
		})
	}
}

func TestLogicalStateRecordedRefusalPriority(t *testing.T) {
	op := Outpoint{Txid: filled32(18)}
	for _, tc := range []struct {
		name   string
		parent logicalStateCounters
		size   int
		kind   logicalStateFailureKind
		text   string
	}{
		{"comparison", logicalStateCounters{bytes: 57, entries: 1}, 1, logicalStateFailureLocalInvariant, "recorded parent row cannot be compared with its final entry"},
		{"parent-first", logicalStateCounters{bytes: 56, entries: 1}, 1, logicalStateFailureStoreIntegrity, "parent counters are insufficient for present rows"},
		{"final-first", logicalStateCounters{bytes: 57, entries: 1}, 65537, logicalStateFailureLocalInvariant, "invalid logical state plan mutation"},
		{"parent-before-invalid-final", logicalStateCounters{bytes: 56, entries: 1}, 65537, logicalStateFailureStoreIntegrity, "parent counters are insufficient for present rows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := &logicalStateRecordTestView{length: 57, present: true, ok: true}
			view.counter = logicalStateCounterRead{kind: logicalStateCountersPresent, counters: tc.parent}
			touch := logicalTouchedState{Outpoint: op, FinalPresent: true, Final: logicalStateTestEntry(tc.size, 1)}
			before := cloneUtxoEntry(touch.Final)
			plan, failure := buildLogicalStatePlan(6, view, []logicalTouchedState{touch}, 0)
			if failure == nil || failure.kind != tc.kind || failure.cause.Error() != tc.text || !reflect.DeepEqual(plan, logicalStatePlan[int]{}) || len(view.lookups) != 0 || view.recordCalls != 1 || !reflect.DeepEqual(before, touch.Final) {
				t.Fatalf("record refusal/order %s: %+v/%v", tc.name, plan, failure)
			}
		})
	}
	view := &logicalStateRecordTestView{ok: true}
	view.counter = logicalStateCounterRead{kind: logicalStateCountersPresent}
	if _, failure := buildLogicalStatePlan(6, view, []logicalTouchedState{{Outpoint: op}, {Outpoint: op}}, 0); failure == nil || failure.cause.Error() != "duplicate touched outpoint" || view.recordCalls != 0 || len(view.lookups) != 0 {
		t.Fatal("duplicate reached recorded or row lookup")
	}
	if _, failure := buildLogicalStatePlan(0, view, []logicalTouchedState{{Outpoint: op}}, 0); failure != nil || view.recordCalls != 0 || len(view.lookups) != 0 || view.counterCalls != 1 {
		t.Fatal("genesis reached a view row or counter")
	}
}

func logicalStateTestEntry(dataLen int, marker byte) UtxoEntry {
	return UtxoEntry{Value: uint64(marker), CovenantType: uint16(marker), CovenantData: bytes.Repeat([]byte{marker}, dataLen), CreationHeight: uint64(marker), CreatedByCoinbase: marker&1 != 0}
}

func logicalStateReferenceTotal(rows map[Outpoint]UtxoEntry) (total uint64) {
	for op, entry := range rows {
		total += uint64(len(logicalStateEntryBytes(op, entry)))
	}
	return total
}

func logicalStateSameErrorPointer(a, b error) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

func TestLogicalStateEntryBytes(t *testing.T) {
	op := Outpoint{Txid: filled32(0x11), Vout: 0x01020304}
	for _, tc := range []struct {
		n       int
		compact []byte
		wantLen int
	}{{0, []byte{0x00}, 56}, {252, []byte{0xfc}, 308}, {253, []byte{0xfd, 0xfd, 0x00}, 311}, {65535, []byte{0xfd, 0xff, 0xff}, 65593}, {65536, []byte{0xfe, 0x00, 0x00, 0x01, 0x00}, 65596}} {
		entry := logicalStateTestEntry(tc.n, 3)
		got := logicalStateEntryBytes(op, entry)
		if len(got) != tc.wantLen || !bytes.Equal(got[46:46+len(tc.compact)], tc.compact) || got[len(got)-1] != 1 {
			t.Fatalf("n=%d len/tail/compact mismatch", tc.n)
		}
		if tc.n > 0 {
			entry.CovenantData[0] ^= 0xff
			if got[46+len(tc.compact)] != 3 {
				t.Fatalf("n=%d result borrowed input", tc.n)
			}
		}
	}
	want := []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x04, 0x03, 0x02, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x03, 0xa1, 0xb2, 0xc3, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x00}
	if got := logicalStateEntryBytes(op, UtxoEntry{Value: 0x0807060504030201, CovenantType: 0x0a09, CovenantData: []byte{0xa1, 0xb2, 0xc3}, CreationHeight: 0x1211100f0e0d0c0b}); !bytes.Equal(got, want) || logicalStateEntriesEqual(UtxoEntry{Value: 1}, UtxoEntry{Value: 1, CreatedByCoinbase: true}, true) {
		t.Fatal("field order, endian, or false coinbase byte mismatch")
	}
}

func TestLogicalStateLimitLiterals(t *testing.T) {
	if maxLogicalStateBytes != 1649267441664 || MAX_BLOCK_NET_STATE_GROWTH_BYTES != 773120 || maxCreatedLogicalStateBytes != 86545430 {
		t.Fatal("logical state limit literal mismatch")
	}
}

func TestLogicalStateRegistryAndLazyEvaluation(t *testing.T) {
	id1, id2 := filled32(1), filled32(2)
	for i, rows := range [][]logicalStateCapRegistryRow{{{chainID: make([]byte, 31)}}, {{chainID: make([]byte, 33)}}, {{chainID: id1[:], activationHeight: 1 << 32}}, {{chainID: id1[:]}, {chainID: id1[:]}}, {{chainID: id2[:]}, {chainID: id1[:]}}} {
		if _, err := validateLogicalStateCapRegistry(rows); err == nil {
			t.Fatalf("invalid registry %d accepted", i)
		}
	}
	raw := []logicalStateCapRegistryRow{{chainID: append([]byte(nil), id1[:]...), activationHeight: 5}, {chainID: id2[:], activationHeight: 0xffffffff}}
	registry, err := validateLogicalStateCapRegistry(raw)
	raw[0].chainID[0] = 9
	empty, emptyErr := validateLogicalStateCapRegistry(nil)
	if err != nil || registry.active(id1, 4) || !registry.active(id1, 5) || !registry.active(id1, 6) || registry.active(id2, 0xfffffffe) || !registry.active(id2, 0xffffffff) || registry.active([32]byte{}, 9) || emptyErr != nil || empty.active(id1, 0) {
		t.Fatal("activation or registry deep copy mismatch")
	}
	view := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersUnavailable, cause: errors.New("unused")}}
	prior := &TxError{Code: TX_ERR_PARSE}
	if result, got := evaluateLogicalStateCap(prior, registry, id1, 5, view, nil, new(int)); !logicalStateSameErrorPointer(got, prior) || !reflect.DeepEqual(result, logicalStateCapResult[*int]{}) || view.counterCalls != 0 {
		t.Fatal("prior error was not exact and lazy")
	}
	touch := []logicalTouchedState{{Outpoint: Outpoint{Txid: id2}, FinalPresent: true, Final: logicalStateTestEntry(0, 1)}}
	present := logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{bytes: 56, entries: 1}}
	for _, tc := range []struct {
		name   string
		reg    validatedLogicalStateCapRegistry
		chain  [32]byte
		height uint64
		active bool
	}{{"empty", empty, id1, 5, false}, {"unmatched", registry, [32]byte{}, 5, false}, {"before", registry, id1, 4, false}, {"at", registry, id1, 5, true}, {"after", registry, id1, 6, true}} {
		inactive := &logicalStateTestView{counter: present, rows: map[Outpoint]logicalStateRowRead{{Txid: id2}: {kind: logicalStateRowAbsent}}}
		result, got := evaluateLogicalStateCap(nil, tc.reg, tc.chain, tc.height, inactive, touch, new(int))
		if got != nil || result.active != tc.active || result.plan.Parent != (logicalStateCounters{bytes: 56, entries: 1}) || result.plan.Result != (logicalStateCounters{bytes: 112, entries: 2}) || len(result.plan.Puts) != 1 || result.plan.Metadata == nil || inactive.counterCalls != 1 || len(inactive.lookups) != 1 {
			t.Fatalf("%s derivation mismatch: %#v %v counters=%d lookups=%d", tc.name, result, got, inactive.counterCalls, len(inactive.lookups))
		}
	}
	genesis, _ := validateLogicalStateCapRegistry([]logicalStateCapRegistryRow{{chainID: id1[:], activationHeight: 0}})
	result, got := evaluateLogicalStateCap(nil, genesis, id1, 0, nil, []logicalTouchedState{{Outpoint: Outpoint{Txid: id2}, FinalPresent: true, Final: logicalStateTestEntry(0, 1)}}, &id2)
	if got != nil || !result.active || result.plan.Parent != (logicalStateCounters{}) || len(result.plan.Puts) != 1 || result.plan.Metadata != &id2 {
		t.Fatal("active genesis plan mismatch")
	}
}

func TestBuildLogicalStatePlanDeltaOrderAndCopies(t *testing.T) {
	ops := []Outpoint{{Txid: filled32(1), Vout: 1}, {Txid: filled32(1), Vout: 256}, {Txid: filled32(2)}, {Txid: filled32(3)}, {Txid: filled32(4)}}
	old1, old2, same := logicalStateTestEntry(0, 1), logicalStateTestEntry(252, 2), logicalStateTestEntry(3, 3)
	new2, new3 := logicalStateTestEntry(253, 4), logicalStateTestEntry(1, 5)
	parent := logicalStateCounters{entries: 3, bytes: logicalStateEntryLength(old1) + logicalStateEntryLength(old2) + logicalStateEntryLength(same)}
	view := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: parent}, rows: map[Outpoint]logicalStateRowRead{
		ops[0]: {kind: logicalStateRowPresent, entry: old1}, ops[1]: {kind: logicalStateRowPresent, entry: old2},
		ops[2]: {kind: logicalStateRowAbsent}, ops[3]: {kind: logicalStateRowAbsent}, ops[4]: {kind: logicalStateRowPresent, entry: same},
	}}
	metadata := &struct{ value int }{7}
	touched := []logicalTouchedState{{Outpoint: ops[4], FinalPresent: true, Final: same}, {Outpoint: ops[3]}, {Outpoint: ops[2], FinalPresent: true, Final: new3}, {Outpoint: ops[1], FinalPresent: true, Final: new2}, {Outpoint: ops[0]}}
	result, err := evaluateLogicalStateCap(nil, validatedLogicalStateCapRegistry{rows: []validatedLogicalStateCapRegistryRow{{chainID: ops[0].Txid}}}, ops[0].Txid, 1, view, touched, metadata)
	if err != nil || result.plan.Parent != parent || result.plan.Result != (logicalStateCounters{entries: 3, bytes: parent.bytes - logicalStateEntryLength(old1) - logicalStateEntryLength(old2) + logicalStateEntryLength(new2) + logicalStateEntryLength(new3)}) || result.plan.Metadata != metadata || len(result.plan.Deletes) != 2 || len(result.plan.Puts) != 2 || view.counterCalls != 1 || !reflect.DeepEqual(view.lookups, ops) {
		t.Fatalf("plan mismatch: %#v %v", result.plan, err)
	}
	if result.plan.Deletes[0].Outpoint != ops[0] || result.plan.Deletes[1].Outpoint != ops[1] || result.plan.Puts[0].Outpoint != ops[1] || result.plan.Puts[1].Outpoint != ops[2] || result.plan.Deletes[1].EntryBytes != 308 {
		t.Fatal("DELETE-before-PUT delta or numeric-vout ordering mismatch")
	}
	new2.CovenantData[0] ^= 0xff
	view.rows[ops[1]] = logicalStateRowRead{kind: logicalStateRowAbsent}
	if result.plan.Puts[0].Entry.CovenantData[0] != 4 {
		t.Fatal("PUT borrowed source data")
	}
	if logicalStateReferenceTotal(nil) != 0 || logicalStateReferenceTotal(map[Outpoint]UtxoEntry{ops[0]: old1, ops[1]: old2}) != uint64(len(logicalStateEntryBytes(ops[0], old1))+len(logicalStateEntryBytes(ops[1], old2))) {
		t.Fatal("test-local mathematical reference is map-order dependent")
	}
}

func TestLogicalStatePlanFailuresAndPriority(t *testing.T) {
	op1, op2 := Outpoint{Txid: filled32(1)}, Outpoint{Txid: filled32(2)}
	cause := errors.New("source cause")
	for _, tc := range []struct {
		name     string
		height   uint64
		counters logicalStateCounters
	}{
		{"count_equality_h10", 10, logicalStateCounters{entries: 15454540, bytes: 865454240}},
		{"count_equality_h1", 1, logicalStateCounters{entries: 1545454, bytes: 86545424}},
		{"height_scaling_h11", 11, logicalStateCounters{entries: 16999994, bytes: 951999664}},
		{"below_count_ceiling", 10, logicalStateCounters{entries: 15454539, bytes: 865454184}},
		{"entry_lower_equality", 1, logicalStateCounters{entries: 1, bytes: 56}},
		{"entry_upper_equality", 1, logicalStateCounters{entries: 1, bytes: 65596}},
		{"positive_height_empty", 1, logicalStateCounters{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := &Outpoint{Txid: filled32(3), Vout: 7}
			view := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: tc.counters}}
			plan, failure := buildLogicalStatePlan(tc.height, view, nil, metadata)
			if failure != nil {
				t.Fatalf("%s: valid parent count equality rejected: %v", tc.name, failure)
			}
			want := logicalStatePlan[*Outpoint]{Parent: tc.counters, Result: tc.counters, Metadata: metadata}
			if !reflect.DeepEqual(plan, want) || plan.Metadata != metadata || view.counterCalls != 1 || len(view.lookups) != 0 {
				t.Fatalf("%s: parent envelope plan/read mismatch: %#v", tc.name, plan)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		touched []logicalTouchedState
	}{
		{"count_only", nil},
		{"count_before_duplicate", []logicalTouchedState{{Outpoint: op1}, {Outpoint: op1}}},
		{"count_before_unavailable", []logicalTouchedState{{Outpoint: op1, FinalPresent: true, Final: UtxoEntry{Value: 1}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counter := logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{entries: 15454541, bytes: 865454296}}
			row := logicalStateRowRead{kind: logicalStateRowUnavailable, cause: cause}
			view := &logicalStateTestView{counter: counter, rows: map[Outpoint]logicalStateRowRead{op1: row}}
			touchedBefore := append([]logicalTouchedState(nil), tc.touched...)
			metadata := &Outpoint{Txid: filled32(3), Vout: 7}
			metadataBefore := *metadata
			plan, failure := buildLogicalStatePlan(10, view, tc.touched, metadata)
			if failure == nil || failure.kind != logicalStateFailureStoreIntegrity || failure.cause == nil || failure.cause.Error() != "invalid logical state counters" {
				t.Fatalf("%s: count-only parent did not return STORE_INTEGRITY/invalid logical state counters: %v", tc.name, failure)
			}
			var txFailure *TxError
			if errors.As(failure, &txFailure) || !reflect.DeepEqual(plan, logicalStatePlan[*Outpoint]{}) || view.counterCalls != 1 || len(view.lookups) != 0 {
				t.Fatalf("%s: count refusal plan/read/result mismatch: %#v", tc.name, plan)
			}
			observedRow, rowPresent := view.rows[op1]
			if view.counter.kind != counter.kind || view.counter.counters != counter.counters || view.counter.cause != nil || len(view.rows) != 1 || !rowPresent || observedRow.kind != row.kind || observedRow.cause == nil || !logicalStateSameErrorPointer(observedRow.cause, cause) || !reflect.DeepEqual(observedRow.entry, UtxoEntry{}) || !reflect.DeepEqual(tc.touched, touchedBefore) || *metadata != metadataBefore {
				t.Fatalf("%s: count refusal changed source data", tc.name)
			}
			if tc.name != "count_only" {
				return
			}
			view.counter = logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{entries: 15454540, bytes: 865454240}}
			view.rows[op1] = logicalStateRowRead{kind: logicalStateRowAbsent}
			final := UtxoEntry{Value: 1}
			plan, failure = buildLogicalStatePlan(10, view, []logicalTouchedState{{Outpoint: op1, FinalPresent: true, Final: final}}, metadata)
			want := logicalStatePlan[*Outpoint]{
				Parent: logicalStateCounters{entries: 15454540, bytes: 865454240}, Result: logicalStateCounters{entries: 15454541, bytes: 865454296},
				Puts: []logicalStatePut{{Outpoint: op1, Entry: UtxoEntry{Value: 1}}}, Metadata: metadata,
			}
			if failure != nil || !reflect.DeepEqual(plan, want) || plan.Metadata != metadata || *metadata != metadataBefore || view.counterCalls != 2 || !reflect.DeepEqual(view.lookups, []Outpoint{op1}) {
				t.Fatalf("next call after count refusal lost valid PUT/metadata/counter reread: %#v %v", plan, failure)
			}
		})
	}
	for _, tc := range []struct {
		read logicalStateCounterRead
		want logicalStateFailureKind
		same bool
	}{{logicalStateCounterRead{kind: logicalStateCountersUnavailable, cause: cause}, logicalStateFailureUnavailable, true}, {logicalStateCounterRead{kind: logicalStateCountersStoreIntegrity, cause: cause}, logicalStateFailureStoreIntegrity, true}, {logicalStateCounterRead{kind: logicalStateCountersLocalInvariant, cause: cause}, logicalStateFailureLocalInvariant, true}, {logicalStateCounterRead{}, logicalStateFailureLocalInvariant, false}, {logicalStateCounterRead{kind: logicalStateCountersUnavailable}, logicalStateFailureLocalInvariant, false}, {logicalStateCounterRead{kind: logicalStateCountersUnavailable, counters: logicalStateCounters{bytes: 1}, cause: cause}, logicalStateFailureLocalInvariant, false}, {logicalStateCounterRead{kind: logicalStateCountersPresent, cause: cause}, logicalStateFailureStoreIntegrity, false}} {
		view := &logicalStateTestView{counter: tc.read}
		plan, failure := buildLogicalStatePlan(1, view, nil, new(int))
		if !reflect.DeepEqual(plan, logicalStatePlan[*int]{}) || failure == nil || failure.kind != tc.want || tc.same && (!logicalStateSameErrorPointer(failure.cause, cause) || failure.Error() != cause.Error()) || len(view.lookups) != 0 {
			t.Fatalf("counter failure %#v classification mismatch", tc.read)
		}
	}
	if _, failure := buildLogicalStatePlan(1, nil, nil, 0); failure == nil || failure.kind != logicalStateFailureLocalInvariant {
		t.Fatal("nil view did not fail locally")
	}
	var failure *logicalStateFailure
	for _, counters := range []logicalStateCounters{{bytes: 1}, {bytes: 55, entries: 1}, {bytes: 65597, entries: 1}, {bytes: ^uint64(0), entries: ^uint64(0)}, {bytes: maxCreatedLogicalStateBytes + 1, entries: (maxCreatedLogicalStateBytes + maxLogicalStateEntryBytes) / maxLogicalStateEntryBytes}} {
		v := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: counters}}
		if _, failure = buildLogicalStatePlan(1, v, []logicalTouchedState{{Outpoint: op1}, {Outpoint: op1}}, 0); failure == nil || failure.kind != logicalStateFailureStoreIntegrity {
			t.Fatalf("invalid counter envelope accepted: %#v", counters)
		}
	}
	for _, tc := range []struct {
		kind logicalStateRowReadKind
		want logicalStateFailureKind
	}{{logicalStateRowUnavailable, logicalStateFailureUnavailable}, {logicalStateRowStoreIntegrity, logicalStateFailureStoreIntegrity}, {logicalStateRowLocalInvariant, logicalStateFailureLocalInvariant}, {logicalStateRowPresent, logicalStateFailureStoreIntegrity}, {logicalStateRowAbsent, logicalStateFailureStoreIntegrity}} {
		view := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{bytes: 56, entries: 1}}, rows: map[Outpoint]logicalStateRowRead{op1: {kind: tc.kind, cause: cause}}}
		_, failure = buildLogicalStatePlan(1, view, []logicalTouchedState{{Outpoint: op1}}, 0)
		if failure == nil || failure.kind != tc.want || tc.kind >= logicalStateRowUnavailable && !logicalStateSameErrorPointer(failure.cause, cause) {
			t.Fatalf("row failure kind %d was not preserved", tc.kind)
		}
	}
	for i, row := range []logicalStateRowRead{{kind: logicalStateRowPresent, entry: logicalStateTestEntry(MAX_COVENANT_DATA_PER_OUTPUT+1, 1)}, {kind: logicalStateRowAbsent, entry: UtxoEntry{Value: 1}}, {kind: logicalStateRowUnavailable}, {kind: 99}, {kind: logicalStateRowUnavailable, entry: UtxoEntry{Value: 1}, cause: cause}, {kind: logicalStateRowStoreIntegrity, entry: UtxoEntry{Value: 1}, cause: cause}, {kind: logicalStateRowLocalInvariant, entry: UtxoEntry{Value: 1}, cause: cause}} {
		v := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{bytes: 56, entries: 1}}, rows: map[Outpoint]logicalStateRowRead{op1: row}}
		_, failure = buildLogicalStatePlan(1, v, []logicalTouchedState{{Outpoint: op1}}, 0)
		if failure == nil || (i <= 1 && failure.kind != logicalStateFailureStoreIntegrity) || (i > 1 && failure.kind != logicalStateFailureLocalInvariant) {
			t.Fatalf("malformed row %d classification mismatch", i)
		}
	}
	view := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{bytes: 112, entries: 2}}, rows: map[Outpoint]logicalStateRowRead{
		op1: {kind: logicalStateRowStoreIntegrity, cause: cause}, op2: {kind: logicalStateRowAbsent},
	}}
	_, failure = buildLogicalStatePlan(1, view, []logicalTouchedState{{Outpoint: op2, Final: UtxoEntry{Value: 1}}, {Outpoint: op1}}, 0)
	if failure == nil || failure.kind != logicalStateFailureStoreIntegrity || !logicalStateSameErrorPointer(failure.cause, cause) || !reflect.DeepEqual(view.lookups, []Outpoint{op1}) {
		t.Fatal("earlier sorted row failure did not win")
	}
	for _, tc := range []struct {
		name     string
		counters logicalStateCounters
		old      UtxoEntry
	}{{"zero_entries_nonzero_bytes", logicalStateCounters{bytes: 57, entries: 1}, logicalStateTestEntry(0, 1)}, {"below_minimum", logicalStateCounters{bytes: 112, entries: 2}, logicalStateTestEntry(1, 1)}, {"above_maximum", logicalStateCounters{bytes: 65653, entries: 2}, logicalStateTestEntry(0, 1)}} {
		v := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: tc.counters}, rows: map[Outpoint]logicalStateRowRead{op1: {kind: logicalStateRowPresent, entry: tc.old}, op2: {kind: logicalStateRowLocalInvariant, cause: cause}}}
		plan, failure := buildLogicalStatePlan(1, v, []logicalTouchedState{{Outpoint: op2}, {Outpoint: op1, Final: UtxoEntry{Value: 1}}}, new(int))
		if !reflect.DeepEqual(plan, logicalStatePlan[*int]{}) || failure == nil || failure.kind != logicalStateFailureStoreIntegrity || !reflect.DeepEqual(v.lookups, []Outpoint{op1}) {
			t.Fatalf("residual envelope %s did not fail first", tc.name)
		}
	}
	parent := logicalStateCounters{bytes: 2 * maxLogicalStateEntryBytes, entries: 2}
	work := logicalStatePlanWork{parent: parent, result: parent}
	for _, tc := range []struct {
		touch logicalTouchedState
		old   UtxoEntry
		want  logicalStatePlanWork
	}{{logicalTouchedState{Outpoint: op1}, logicalStateTestEntry(MAX_COVENANT_DATA_PER_OUTPUT, 1), logicalStatePlanWork{deletes: []logicalStateDelete{{Outpoint: op1, EntryBytes: 65596}}, parent: parent, result: logicalStateCounters{bytes: 65596, entries: 1}, oldBytes: 65596, oldCount: 1}}, {logicalTouchedState{Outpoint: op2}, logicalStateTestEntry(MAX_COVENANT_DATA_PER_OUTPUT, 2), logicalStatePlanWork{deletes: []logicalStateDelete{{Outpoint: op1, EntryBytes: 65596}, {Outpoint: op2, EntryBytes: 65596}}, parent: parent, result: logicalStateCounters{}, oldBytes: 131192, oldCount: 2}}} {
		if failure := work.apply(tc.touch, logicalStatePlanRow{entry: tc.old, entryBytes: 65596, present: true}); failure != nil || !reflect.DeepEqual(work, tc.want) {
			t.Fatalf("maximum old row retained in work: %#v %v", work, failure)
		}
	}
	insufficient := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{bytes: 56, entries: 1}}, rows: map[Outpoint]logicalStateRowRead{op1: {kind: logicalStateRowPresent, entry: logicalStateTestEntry(0, 1)}, op2: {kind: logicalStateRowPresent, entry: logicalStateTestEntry(0, 1)}}}
	if _, failure = buildLogicalStatePlan(1, insufficient, []logicalTouchedState{{Outpoint: op2, Final: UtxoEntry{Value: 1}}, {Outpoint: op1}}, 0); failure == nil || failure.kind != logicalStateFailureStoreIntegrity {
		t.Fatal("cumulative old-row insufficiency was not STORE_INTEGRITY")
	}
	byteInsufficient := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{bytes: 112, entries: 2}}, rows: map[Outpoint]logicalStateRowRead{op1: {kind: logicalStateRowPresent, entry: logicalStateTestEntry(0, 1)}, op2: {kind: logicalStateRowPresent, entry: logicalStateTestEntry(MAX_COVENANT_DATA_PER_OUTPUT, 1)}}}
	if _, failure = buildLogicalStatePlan(1, byteInsufficient, []logicalTouchedState{{Outpoint: op2, Final: UtxoEntry{Value: 1}}, {Outpoint: op1}}, 0); failure == nil || failure.kind != logicalStateFailureStoreIntegrity {
		t.Fatal("cumulative old-row byte insufficiency was not STORE_INTEGRITY")
	}
	for name, touched := range map[string][]logicalTouchedState{
		"duplicate": {{Outpoint: op1}, {Outpoint: op1}}, "absent_payload": {{Outpoint: op1, Final: UtxoEntry{Value: 1}}},
		"oversize_final": {{Outpoint: op1, FinalPresent: true, Final: logicalStateTestEntry(MAX_COVENANT_DATA_PER_OUTPUT+1, 1)}},
	} {
		v := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{}}, rows: map[Outpoint]logicalStateRowRead{op1: {kind: logicalStateRowAbsent}}}
		_, failure = buildLogicalStatePlan(1, v, touched, 0)
		if failure == nil || failure.kind != logicalStateFailureLocalInvariant {
			t.Fatalf("%s did not fail locally", name)
		}
	}
	overflowWork := logicalStatePlanWork{putBytes: maxCreatedLogicalStateBytes}
	if failure = overflowWork.apply(logicalTouchedState{Outpoint: op1, FinalPresent: true, Final: logicalStateTestEntry(0, 1)}, logicalStatePlanRow{}); failure == nil || failure.kind != logicalStateFailureLocalInvariant {
		t.Fatal("created logical-byte bound was not enforced")
	}
}

func TestEvaluateLogicalStateCapMathAndFailures(t *testing.T) {
	id := filled32(1)
	registry, _ := validateLogicalStateCapRegistry([]logicalStateCapRegistryRow{{chainID: id[:], activationHeight: 1}})
	entry := logicalStateTestEntry(0, 1)
	makeView := func(total uint64, row logicalStateRowRead) *logicalStateTestView {
		entries := (total+maxLogicalStateEntryBytes-1)/maxLogicalStateEntryBytes + 1
		return &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{bytes: total, entries: entries}}, rows: map[Outpoint]logicalStateRowRead{{Txid: id}: row}}
	}
	for _, tc := range []struct {
		name    string
		s0      uint64
		touched []logicalTouchedState
		row     logicalStateRowRead
		wantCap bool
	}{{"below_cross", maxLogicalStateBytes - 1, []logicalTouchedState{{Outpoint: Outpoint{Txid: id}, FinalPresent: true, Final: entry}}, logicalStateRowRead{kind: logicalStateRowAbsent}, true}, {"at_cap", maxLogicalStateBytes, nil, logicalStateRowRead{}, false}, {"cross_cap", maxLogicalStateBytes, []logicalTouchedState{{Outpoint: Outpoint{Txid: id}, FinalPresent: true, Final: entry}}, logicalStateRowRead{kind: logicalStateRowAbsent}, true}, {"drain_equal", maxLogicalStateBytes + 1, nil, logicalStateRowRead{}, false}, {"drain_down", maxLogicalStateBytes + logicalStateEntryLength(entry), []logicalTouchedState{{Outpoint: Outpoint{Txid: id}}}, logicalStateRowRead{kind: logicalStateRowPresent, entry: entry}, false}, {"grow_over_cap", maxLogicalStateBytes + 1, []logicalTouchedState{{Outpoint: Outpoint{Txid: id}, FinalPresent: true, Final: entry}}, logicalStateRowRead{kind: logicalStateRowAbsent}, true}} {
		result, err := evaluateLogicalStateCap(nil, registry, id, 20000, makeView(tc.s0, tc.row), tc.touched, tc.name)
		if tc.wantCap {
			if !reflect.DeepEqual(result, logicalStateCapResult[string]{}) || mustTxErrCode(t, err) != BLOCK_ERR_STATE_CAP_EXCEEDED || err.Error() != "BLOCK_ERR_STATE_CAP_EXCEEDED: logical state cap exceeded" {
				t.Fatalf("%s cap rejection mismatch", tc.name)
			}
		} else if err != nil || !result.active || result.plan.Result.bytes > tc.s0 && tc.s0 > maxLogicalStateBytes {
			t.Fatalf("%s acceptance mismatch: %#v %v", tc.name, result, err)
		}
	}
	for _, kind := range []logicalStateCounterReadKind{logicalStateCountersUnavailable, logicalStateCountersStoreIntegrity, logicalStateCountersLocalInvariant} {
		cause := errors.New("active builder failure")
		result, err := evaluateLogicalStateCap(nil, registry, id, 1, &logicalStateTestView{counter: logicalStateCounterRead{kind: kind, cause: cause}}, nil, new(int))
		var failure *logicalStateFailure
		if !reflect.DeepEqual(result, logicalStateCapResult[*int]{}) || !errors.As(err, &failure) || !logicalStateSameErrorPointer(err, failure) || failure.kind != logicalStateFailureKind(kind-logicalStateCountersUnavailable)+1 || !logicalStateSameErrorPointer(failure.cause, cause) {
			t.Fatal("active builder failure kind/cause/zero-result mismatch")
		}
	}
}

const (
	testLogicalCap    uint64 = 1649267441664
	testLogicalGrowth uint64 = 773120
	testLogicalBound  uint64 = 371709791468257280
)

const (
	testLogicalCapMsg    = "BLOCK_ERR_STATE_CAP_EXCEEDED: logical state cap exceeded"
	testLogicalGrowthMsg = "BLOCK_ERR_STATE_GROWTH_EXCEEDED: logical state growth exceeded"
)

func TestLogicalStateEntryLengthLiterals(t *testing.T) {
	for _, tc := range []struct {
		data int
		want uint64
	}{{0, 56}, {252, 308}, {253, 311}, {65535, 65593}, {65536, 65596}} {
		if got := logicalStateEntryLength(logicalStateTestEntry(tc.data, 1)); got != tc.want {
			t.Fatalf("data %d length %d, want %d", tc.data, got, tc.want)
		}
	}
}

func TestLogicalStateCapThenGrowthScalar(t *testing.T) {
	const c, g, b = testLogicalCap, testLogicalGrowth, testLogicalBound
	for _, tc := range []struct {
		s0, s1 uint64
		active bool
		want   string
	}{
		{1000000, 1773119, false, ""},
		{1000000, 1773120, false, ""},
		{1000000, 1000000, false, ""},
		{1000000, 999999, false, ""},
		{0, 773119, false, ""},
		{0, 773120, false, ""},
		{1000000, 1773121, false, testLogicalGrowthMsg},
		{0, 773121, false, testLogicalGrowthMsg},
		{1649266668544, c, true, ""},
		{c, c, true, ""},
		{c + 1, c + 1, true, ""},
		{c + 1, c, true, ""},
		{c - 1, c + 1, true, testLogicalCapMsg},
		{c, c + 56, true, testLogicalCapMsg},
		{c + 1, c + 57, true, testLogicalCapMsg},
		{1649266668544, c + 1, true, testLogicalCapMsg},
		{1000000, 1773121, true, testLogicalGrowthMsg},
		{c - 1, c + 1, false, ""},
		{c, c + g, false, ""},
		{c, c + g + 1, false, testLogicalGrowthMsg},
		{b, 0, false, ""},
		{b, 0, true, ""},
		{b, b - 1, true, ""},
		{b, b + g, false, ""},
		{b, b + g + 1, false, testLogicalGrowthMsg},
		{b, b + 1, true, testLogicalCapMsg},
		{^uint64(0), 0, false, ""},
		{0, ^uint64(0), false, testLogicalGrowthMsg},
	} {
		err := checkLogicalStateCapAndGrowth(tc.s0, tc.s1, tc.active)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || err.Error() != tc.want) {
			t.Fatalf("s0=%d s1=%d active=%v: %v, want %q", tc.s0, tc.s1, tc.active, err, tc.want)
		}
		if tc.want != "" {
			if _, ok := any(err).(*TxError); !ok {
				t.Fatalf("s0=%d s1=%d: not a bare TxError: %T", tc.s0, tc.s1, err)
			}
		}
	}
}

// logicalGrowthTouched creates exactly delta logical bytes of absent-parent puts,
// or stops the test when a nonzero final remainder is outside 311..65593, the entry
// lengths of data lengths 253..65535 whose CompactSize prefix is 3 bytes.
func logicalGrowthTouched(t *testing.T, delta uint64) ([]logicalTouchedState, map[Outpoint]logicalStateRowRead) {
	t.Helper()
	var touched []logicalTouchedState
	rows := map[Outpoint]logicalStateRowRead{}
	add := func(data int) {
		op := Outpoint{Txid: filled32(9), Vout: uint32(len(touched))}
		touched = append(touched, logicalTouchedState{Outpoint: op, FinalPresent: true, Final: logicalStateTestEntry(data, 1)})
		rows[op] = logicalStateRowRead{kind: logicalStateRowAbsent}
	}
	for ; delta >= 65596*2; delta -= 65596 {
		add(65536)
	}
	if delta > 65596 {
		add(65536)
		delta -= 65596
	}
	if delta == 0 {
		return touched, rows
	}
	if delta < 311 || delta > 65593 {
		t.Fatalf("delta remainder %d not representable by this helper", delta)
	}
	add(int(delta) - 58)
	return touched, rows
}

func TestEvaluateLogicalStateCapGrowthPlan(t *testing.T) {
	id := filled32(1)
	active, _ := validateLogicalStateCapRegistry([]logicalStateCapRegistryRow{{chainID: id[:], activationHeight: 1}})
	inactive, _ := validateLogicalStateCapRegistry(nil)
	const big = uint64(25200000)
	for _, tc := range []struct {
		name        string
		reg         validatedLogicalStateCapRegistry
		height      uint64
		s0, entries uint64
		delta       uint64
		wantActive  bool
		want        string
	}{
		{"inactive-below", inactive, 5000, 1000000, 100, 773119, false, ""},
		{"inactive-equal", inactive, 5000, 1000000, 100, 773120, false, ""},
		{"inactive-over", inactive, 5000, 1000000, 100, 773121, false, testLogicalGrowthMsg},
		{"genesis-equal", inactive, 0, 0, 0, 773120, false, ""},
		{"genesis-over", inactive, 0, 0, 0, 773121, false, testLogicalGrowthMsg},
		{"active-below-cap-over-growth", active, 5000, 1000000, 100, 773121, true, testLogicalGrowthMsg},
		{"active-equal-both", active, 20000, 1649266668544, big, 773120, true, ""},
		{"active-dual-cap-wins", active, 20000, 1649266668544, big, 773121, true, testLogicalCapMsg},
		{"inactive-crosses-cap", inactive, 20000, 1649266668544, big, 773121, false, testLogicalGrowthMsg},
		{"inactive-crosses-cap-within-growth", inactive, 20000, 1649267000000, big, 773120, false, ""},
	} {
		touched, rows := logicalGrowthTouched(t, tc.delta)
		view := &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{bytes: tc.s0, entries: tc.entries}}, rows: rows}
		result, err := evaluateLogicalStateCap(nil, tc.reg, id, tc.height, view, touched, tc.name)
		if tc.want != "" {
			if err == nil || err.Error() != tc.want || !reflect.DeepEqual(result, logicalStateCapResult[string]{}) {
				t.Fatalf("%s: %#v %v", tc.name, result.active, err)
			}
			continue
		}
		wantCalls := 1
		if tc.height == 0 {
			wantCalls = 0
		}
		if err != nil || result.active != tc.wantActive || result.plan.Parent.bytes != tc.s0 || result.plan.Result.bytes != tc.s0+tc.delta || len(result.plan.Puts) != len(touched) || result.plan.Metadata != tc.name || view.counterCalls != wantCalls || len(view.lookups) != wantCalls*len(touched) {
			t.Fatalf("%s: active=%v parent=%+v result=%+v err=%v", tc.name, result.active, result.plan.Parent, result.plan.Result, err)
		}
	}
}

func TestEvaluateLogicalStateCapBothStatesKeepAccountingFailure(t *testing.T) {
	id := filled32(1)
	active, _ := validateLogicalStateCapRegistry([]logicalStateCapRegistryRow{{chainID: id[:], activationHeight: 1}})
	cause := errors.New("accounting cause")
	touched, rows := logicalGrowthTouched(t, 773121)
	badRows := map[Outpoint]logicalStateRowRead{}
	for op := range rows {
		badRows[op] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: cause}
	}
	ok := logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{bytes: 1000000, entries: 100}}
	for _, reg := range []validatedLogicalStateCapRegistry{{}, active} {
		for _, tc := range []struct {
			name string
			view *logicalStateTestView
			kind logicalStateFailureKind
			text string
		}{
			{"counter-unavailable", &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersUnavailable, cause: cause}}, logicalStateFailureUnavailable, cause.Error()},
			{"counter-malformed", &logicalStateTestView{counter: logicalStateCounterRead{kind: logicalStateCountersPresent, counters: logicalStateCounters{bytes: 1, entries: 1}}}, logicalStateFailureStoreIntegrity, "invalid logical state counters"},
			{"row-unavailable", &logicalStateTestView{counter: ok, rows: badRows}, logicalStateFailureUnavailable, cause.Error()},
		} {
			result, err := evaluateLogicalStateCap(nil, reg, id, 5000, tc.view, touched, new(int))
			var failure *logicalStateFailure
			if !errors.As(err, &failure) || failure.kind != tc.kind || failure.Error() != tc.text || !reflect.DeepEqual(result, logicalStateCapResult[*int]{}) {
				t.Fatalf("%s active-rows=%d: %v", tc.name, len(reg.rows), err)
			}
		}
	}
	view := &logicalStateTestView{counter: ok, rows: rows}
	prior := &TxError{Code: TX_ERR_PARSE}
	if result, err := evaluateLogicalStateCap(prior, active, id, 5000, view, touched, new(int)); !logicalStateSameErrorPointer(err, prior) || !reflect.DeepEqual(result, logicalStateCapResult[*int]{}) || view.counterCalls != 0 || len(view.lookups) != 0 {
		t.Fatal("prior error must win with zero accounting work")
	}
}

func TestLogicalStateCompleteMapAccounting(t *testing.T) {
	row := func(data int) UtxoEntry { return logicalStateTestEntry(data, 1) }
	op := func(i uint32) Outpoint { return Outpoint{Txid: filled32(7), Vout: i} }
	bigRows := func(n uint32, from uint32) map[Outpoint]UtxoEntry {
		m := map[Outpoint]UtxoEntry{}
		for i := uint32(0); i < n; i++ {
			m[op(from+i)] = row(65536)
		}
		return m
	}
	parent := map[Outpoint]UtxoEntry{op(0): row(33)} // 89 bytes
	grown := func(extra uint32, tail int) map[Outpoint]UtxoEntry {
		m := bigRows(extra, 1)
		m[op(0)] = row(33)
		m[op(1000)] = row(tail)
		return m
	}
	// 11*65596 + (51564-58 data) = 773120 net over the kept 89-byte row.
	if err := checkCompleteMapLogicalState(200, parent, grown(11, 51564-58)); err != nil {
		t.Fatalf("equality: %v", err)
	}
	if err := checkCompleteMapLogicalState(200, parent, grown(11, 51565-58)); err == nil || err.Error() != testLogicalGrowthMsg {
		t.Fatalf("over: %v", err)
	}
	// A positive-height imported base counts: the same final map against an
	// empty parent is one 89-byte row further over.
	if err := checkCompleteMapLogicalState(200, map[Outpoint]UtxoEntry{}, grown(11, 51564-58)); err == nil || err.Error() != testLogicalGrowthMsg {
		t.Fatalf("imported base ignored: %v", err)
	}
	// Replacement uses final bytes: n rows of 89 bytes replaced in place by
	// 65596-byte rows. 11*(65596-89) = 720577 passes; 12*(65596-89) = 786084 does not.
	replaced := func(n uint32) (map[Outpoint]UtxoEntry, map[Outpoint]UtxoEntry) {
		before, after := map[Outpoint]UtxoEntry{}, map[Outpoint]UtxoEntry{}
		for i := uint32(0); i < n; i++ {
			before[op(i)], after[op(i)] = row(33), row(65536)
		}
		return before, after
	}
	before, after := replaced(11)
	if err := checkCompleteMapLogicalState(200, before, after); err != nil {
		t.Fatalf("replacement net 720577: %v", err)
	}
	before, after = replaced(12)
	if err := checkCompleteMapLogicalState(200, before, after); err == nil || err.Error() != testLogicalGrowthMsg {
		t.Fatalf("replacement net 786084 must be refused: %v", err)
	}
	// Decrease and empty final map never wrap.
	if err := checkCompleteMapLogicalState(200, bigRows(100, 0), map[Outpoint]UtxoEntry{}); err != nil {
		t.Fatalf("shrink: %v", err)
	}
	// Height 0 reads no parent row, including a structural malformed one.
	if err := checkCompleteMapLogicalState(0, map[Outpoint]UtxoEntry{op(0): row(65537)}, map[Outpoint]UtxoEntry{op(1): row(33)}); err != nil {
		t.Fatalf("genesis parent consulted: %v", err)
	}
	// A prior undergrowth supplies no credit to the next block.
	next := grown(11, 51564-58)
	over := maps.Clone(next)
	over[op(2000)] = row(65536)
	for i := uint32(0); i < 12; i++ {
		over[op(3000+i)] = row(65536)
	}
	if err := checkCompleteMapLogicalState(201, next, over); err == nil || err.Error() != testLogicalGrowthMsg {
		t.Fatalf("credit retained: %v", err)
	}
	// Row-domain and local-invariant classes.
	assertFailure := func(name string, err error, kind logicalStateFailureKind, text string) {
		t.Helper()
		failure, ok := any(err).(*logicalStateFailure)
		if !ok || failure.kind != kind || failure.Error() != text {
			t.Fatalf("%s: %T %v", name, err, err)
		}
	}
	assertFailure("parent-row", checkCompleteMapLogicalState(200, map[Outpoint]UtxoEntry{op(0): row(65537)}, grown(12, 1000)), logicalStateFailureStoreIntegrity, "invalid present logical state row")
	assertFailure("final-row", checkCompleteMapLogicalState(200, parent, map[Outpoint]UtxoEntry{op(0): row(65537)}), logicalStateFailureLocalInvariant, "invalid logical state plan mutation")
	if total, failure := addLogicalStateEntryBytes(^uint64(0)-55, row(0)); total != 0 || failure == nil || failure.kind != logicalStateFailureLocalInvariant {
		t.Fatalf("checked accumulation: %d %v", total, failure)
	}
	// CSM 2.5: a valid total is below 2^59 = 576460752303423488.
	if total, failure := addLogicalStateEntryBytes(576460752303423487-56, row(0)); total != 576460752303423487 || failure != nil {
		t.Fatalf("valid-total bound accepted side: %d %v", total, failure)
	}
	if total, failure := addLogicalStateEntryBytes(576460752303423488-56, row(0)); total != 0 || failure == nil || failure.kind != logicalStateFailureLocalInvariant || failure.Error() != "derived logical state counters exceed bounds" {
		t.Fatalf("valid-total bound refused side: %d %v", total, failure)
	}
}
