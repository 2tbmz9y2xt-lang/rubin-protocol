package consensus

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

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
	if maxLogicalStateBytes != 412316860416 || maxCreatedLogicalStateBytes != 86545430 {
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
	if result, got := evaluateLogicalStateCap[*int](nil, registry, id1, 4, view, []logicalTouchedState{{Final: UtxoEntry{Value: 1}}}, new(int)); got != nil || !reflect.DeepEqual(result, logicalStateCapResult[*int]{}) || view.counterCalls != 0 {
		t.Fatal("inactive path performed work")
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
		if failure := work.apply(tc.touch, tc.old, true); failure != nil || !reflect.DeepEqual(work, tc.want) {
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
	if failure = overflowWork.apply(logicalTouchedState{Outpoint: op1, FinalPresent: true, Final: logicalStateTestEntry(0, 1)}, UtxoEntry{}, false); failure == nil || failure.kind != logicalStateFailureLocalInvariant {
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
		result, err := evaluateLogicalStateCap(nil, registry, id, 5000, makeView(tc.s0, tc.row), tc.touched, tc.name)
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
