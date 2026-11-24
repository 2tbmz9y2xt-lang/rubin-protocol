//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"testing"
)

func TestTreeImageLifecycleV1(t *testing.T) {
	// OpenTreeV1 checks the meta 03 identity before it reads meta key 0x02.
	t.Run("OpenTreeV1 refuses meta 03 identity mismatch before one-byte key 0x02 decode", func(t *testing.T) {
		store, path, identity := treeNativeStore(t)
		treeNativeSeed(t, store, 0, []byte{2}, []byte{0})
		treeNativeSeed(t, store, 0, []byte{3}, bytes.Repeat([]byte{8}, 32))
		mustEnvironment(t, store.Close())
		for range 2 {
			got, err := OpenTreeV1(path, environmentConfig(), identity)
			if got != nil {
				t.Fatal("tree open published a Store")
			}
			treeNativeIntegrity(t, err, operationOpen, nil)
		}
	})
	for _, row := range tiDescriptorRows(t) {
		for _, mode := range row.modes {
			t.Run(fmt.Sprintf("publication with %s refuses before the meta key 0x02 read and %s", row.name, tiAbortName(mode, false)), func(t *testing.T) {
				tiSeededCase(t, row, mode)
			})
		}
	}
	t.Run("foreign meta 03 identity beside decodable meta key 0x02 returns invalid Update Batch with the Store OPEN", tiForeignIdentity)
	for _, row := range tiReadRows(t) {
		for _, mode := range row.modes {
			t.Run(fmt.Sprintf("meta key 0x02 read %s %s", row.name, tiAbortName(mode, true)), func(t *testing.T) {
				tiSeededCase(t, row, mode)
			})
		}
	}
	for _, row := range []struct {
		scenario SelectedDamageScenario
		class    EngineClass
		code     int
	}{{SelectedDamageBeginEIO, "IO", 5}, {SelectedDamageBeginTxnFull, "Transaction", -30788}} {
		t.Run(fmt.Sprintf("ORIGINAL OLD begin failure %d consumes the Store", row.code), func(t *testing.T) {
			tiBeginFailure(t, row.scenario, row.class, row.code)
		})
	}
	t.Run("NEW cached terminal returns truth 2", tiNewTerminal)
	for _, outcome := range []string{"nil", "error", "typed-nil", "wrapped", "panic", "panic-nil", "goexit"} {
		for _, mode := range []uint32{0, 9, 2, 10} {
			t.Run(fmt.Sprintf("planner outcome %s %s", outcome, tiAbortName(mode, false)), func(t *testing.T) { tiPlannerCase(t, outcome, mode) })
		}
	}
	for _, mode := range []string{"ignored", "returned", "wrapped", "other", "panic", "goexit"} {
		t.Run("Reader-recorded census failure with planner outcome "+mode+" consumes the Store", func(t *testing.T) { tiRecordedCase(t, mode) })
	}
}

// tiAbortName names the Store state that tiDisposition requires for mode and consumed.
func tiAbortName(mode uint32, consumed bool) string {
	switch {
	case mode == 0 && !consumed:
		return "keeps the Store OPEN"
	case mode == 0:
		return "consumes the Store"
	case mode == 9:
		return "consumes the Store on fault mode 9 abort EIO"
	}
	return fmt.Sprintf("leaves the Store POISONED_THREAD on fault mode %d abort THREAD_MISMATCH", mode)
}

// tiProbe runs call under SelectedDamageProbeOnly and requires one ORIGINAL OLD
// begin and abort with no write or read transaction, delete, commit or fault.
func tiProbe(t *testing.T, s *Store, o *OperationReservationOwner, call func()) SelectedDamageEvidence {
	t.Helper()
	evidence, err := FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 0, nil, call)
	mustEnvironment(t, err)
	if evidence.BeginOld != 1 || evidence.BeginWrite != 0 || evidence.BeginRead != 0 || evidence.Deletes != 0 || evidence.Commits != 0 || evidence.Faults != 0 || evidence.OldAborts != 1 {
		t.Fatalf("native evidence %+v", evidence)
	}
	return evidence
}

// tiNative runs call under SelectedDamageProbeOnly for mode 0 and under
// fixtureLargeFault mode at rank and key otherwise, requiring no commit and one
// ORIGINAL OLD abort.
func tiNative(t *testing.T, s *Store, o *OperationReservationOwner, mode uint32, rank uint8, key []byte, call func()) {
	t.Helper()
	if mode == 0 {
		tiProbe(t, s, o, call)
		return
	}
	evidence := ctxTreeFault(t, s, mode, rank, key, call)
	if evidence.commits != 0 || evidence.aborts != 1 {
		t.Fatalf("fault mode %d evidence %+v", mode, evidence)
	}
}

// tiDisposition requires the Store state for mode (0 no abort fault, 9 abort
// EIO, 2 or 10 abort THREAD_MISMATCH) with err returned or cached, consumed
// telling whether the call consumes the Store under mode 0. It returns the
// primary that the result carries (nil when there is none).
func tiDisposition(t *testing.T, s *Store, mode uint32, consumed bool, err error, hasPrimary bool) error {
	t.Helper()
	switch {
	case mode == 0 && !consumed:
		if s.state != storeOPEN || s.terminal != nil {
			t.Fatalf("Store %s terminal %v, want OPEN", s.state, s.terminal)
		}
		return err
	case mode == 0:
		if s.state != storeCLOSED || any(s.terminal) != any(err) || err == nil {
			t.Fatalf("Store %s terminal %v, want CLOSED with %v", s.state, s.terminal, err)
		}
		return err
	case mode == 9:
		if s.state != storeCLOSED || any(s.terminal) != any(err) {
			t.Fatalf("Store %s terminal %v, want CLOSED with %v", s.state, s.terminal, err)
		}
		if !hasPrimary {
			requireEnvironmentError(t, err, "IO", operationAbort, 5, "error 5")
			return nil
		}
		parts, ok := err.(interface{ Unwrap() []error })
		if !ok || len(parts.Unwrap()) != 2 {
			t.Fatalf("primary and abort EIO join %v", err)
		}
		if requireEnvironmentError(t, parts.Unwrap()[1], "IO", operationAbort, 5, "error 5").Cause != nil {
			t.Fatal("abort EIO carries a cause")
		}
		return parts.Unwrap()[0]
	}
	if s.state != storePOISONEDTHREAD || any(s.terminal) != any(err) {
		t.Fatalf("Store %s terminal %v, want POISONED_THREAD with %v", s.state, s.terminal, err)
	}
	engine := requireEnvironmentError(t, err, "LocalInvariant", operationAbort, -30416, expectedNativeDiagnostic(-30416))
	if !engine.ReopenRequired || (engine.Cause != nil) != hasPrimary {
		t.Fatalf("retained abort reopen %v cause %v", engine.ReopenRequired, engine.Cause)
	}
	return engine.Cause
}

// tiAfter observes the next public calls: the repeated call and the Store
// operations for an OPEN Store, the cached terminal otherwise, then releases a
// retained transaction.
func tiAfter(t *testing.T, s *Store, o *OperationReservationOwner, kind OperationKind, p *tiPlanner, check func(tiOutcome)) {
	t.Helper()
	if s.state == storeOPEN {
		tiOpenNext(t, s, o, kind, p, check)
		return
	}
	retained := s.state == storePOISONEDTHREAD
	tiTerminal(t, s, o, 1, s.terminal)
	if retained {
		mustEnvironment(t, fixtureLargeRelease(s))
	}
}

// tiRow is one publication on a seeded Store: seed prepares the Store, edit
// changes the Tag 1 publication, want checks the returned primary and consumed
// tells whether a successful abort consumes the Store.
type tiRow struct {
	name     string
	kind     OperationKind
	seed     func(*testing.T, *Store)
	edit     func(*TreeImagePublicationV1)
	modes    []uint32
	fault    uint32
	faultKey []byte
	want     func(*testing.T, error)
	consumed bool
}

func tiRankOne(t *testing.T, s *Store) { treeNativeSeed(t, s, 1, []byte{0xfe}, []byte{1}) }

func tiDescriptorRows(t *testing.T) []tiRow {
	t.Helper()
	oversized := append(bytes.Clone(tiAuthorityAtBound(t)), 0)
	rows := []tiRow{
		{name: "Tag 0", edit: func(p *TreeImagePublicationV1) { p.Tag = 0 }, modes: []uint32{0, 9, 10}},
		{name: "Tag 5", edit: func(p *TreeImagePublicationV1) { p.Tag = 5 }},
		{name: "nil Replay", edit: func(p *TreeImagePublicationV1) { p.Replay = nil }},
		{name: "RecordLimit 0", edit: func(p *TreeImagePublicationV1) { p.RecordLimit = 0 }},
		{name: "a TreeOperation account", kind: TreeOperation},
		{name: "nil Authority", edit: func(p *TreeImagePublicationV1) { p.Authority = nil }},
		{name: "an Authority of 1048577 bytes", edit: func(p *TreeImagePublicationV1) { p.Authority = oversized }},
		{name: "a PRUNED B 1 U 0 Authority", edit: func(p *TreeImagePublicationV1) { p.Authority = tiPrunedB1U0(t) }},
	}
	for i := range rows {
		rows[i].seed, rows[i].want = tiRankOne, tiInvalidBatch
		if rows[i].modes == nil {
			rows[i].modes = []uint32{0}
		}
	}
	if len(oversized) != 1048577 {
		t.Fatalf("oversized Authority %d bytes", len(oversized))
	}
	return rows
}

// tiAuthorityAtBound encodes a valid NONE-phase envelope of exactly
// MaxMetadataBytes by padding ExcludedInvalidBranch.ExactConsensusError.
func tiAuthorityAtBound(t *testing.T) []byte {
	t.Helper()
	a := prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 18561)
	a.Authority.ExcludedInvalidBranch = &InvalidBranchV1{FirstInvalidHeight: 20001, FirstInvalidBlockHash: modelHash(9), ExactConsensusError: bytes.Repeat([]byte{1}, MaxMetadataBytes-27-84)}
	encoded, err := a.Encode()
	mustEnvironment(t, err)
	if len(encoded) != MaxMetadataBytes {
		t.Fatalf("bound Authority %d bytes", len(encoded))
	}
	return encoded
}

// tiPrunedB1U0 is the tsEntry envelope (PRUNED, B 0, U 0) with B set to 1 in
// envelope bytes 24..31; with U 13681 in bytes 32..39 the same bytes decode.
func tiPrunedB1U0(t *testing.T) []byte {
	t.Helper()
	b := bytes.Clone(tsEntry(t).Pair.Mutations[0].Literal)
	if b[22] != 1 || b[23] != byte(StorageProfilePrunedV1) || !bytes.Equal(b[24:40], make([]byte, 16)) {
		t.Fatalf("envelope layout %x", b[:40])
	}
	b[31] = 1
	if _, err := DecodeTreeAuthorityV1(b); !errors.Is(err, errSchema) {
		t.Fatalf("B 1 U 0 decode %v", err)
	}
	fixed := bytes.Clone(b)
	fixed[38], fixed[39] = 0x35, 0x71
	if _, err := DecodeTreeAuthorityV1(fixed); err != nil {
		t.Fatalf("B 1 U 13681 decode %v", err)
	}
	return b
}

// tiSeededCase runs the row on a fresh exact-empty tree Store after its seed.
func tiSeededCase(t *testing.T, row tiRow, mode uint32) {
	s, _, _ := treeNativeStore(t)
	row.seed(t, s)
	tiPublicationCase(t, s, reservationOwner(t, MinReservationLimit), row, mode)
}

// tiPublicationCase runs the row's publication once, under the row's fault at its key when it
// has one, under SelectedDamageProbeOnly for mode 0 and under fault mode at rank 0 key 0x00
// otherwise, and checks the result against mode, the planner, Replay and Reader, then the next
// public calls.
func tiPublicationCase(t *testing.T, s *Store, o *OperationReservationOwner, row tiRow, mode uint32) {
	t.Helper()
	replays := 0
	publication := tiPublication(t, &replays)
	if row.edit != nil {
		row.edit(&publication)
	}
	kind := row.kind
	if kind == 0 {
		kind = LaneOperation
	}
	p := &tiPlanner{outcome: func(*Reader) (TreeImagePublicationV1, error) { return publication, nil }}
	check := func(out tiOutcome) {
		err := tiReturned(t, out)
		row.want(t, tiDisposition(t, s, mode, row.consumed, err, true))
	}
	var out tiOutcome
	fault, rank, key := mode, uint8(0), []byte{0}
	if row.fault != 0 {
		fault, key = row.fault, row.faultKey
	}
	tiNative(t, s, o, fault, rank, key, func() { out = tiCall(s, o, kind, p.imagePlan) })
	check(out)
	if p.calls != 1 || replays != 0 || reservationLive(o) != 0 {
		t.Fatalf("planner %d replay %d live %d", p.calls, replays, reservationLive(o))
	}
	tsExpiredReader(t, p.kept)
	tiAfter(t, s, o, kind, p, check)
}

func tiForeignIdentity(t *testing.T) {
	envelope := prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0)
	s, _, o := prunedTreeSeed(t, envelope)
	treeNativeSeed(t, s, 0, []byte{3}, bytes.Repeat([]byte{8}, 32))
	encoded, err := envelope.Encode()
	mustEnvironment(t, err)
	want, err := DecodeTreeAuthorityV1(encoded)
	mustEnvironment(t, err)
	replays := 0
	publication := tiPublication(t, &replays)
	p := &tiPlanner{outcome: func(*Reader) (TreeImagePublicationV1, error) { return publication, nil }}
	check := func(out tiOutcome) { tiInvalidBatch(t, tiDisposition(t, s, 0, false, tiReturned(t, out), true)) }
	var out tiOutcome
	tiProbe(t, s, o, func() { out = tiCall(s, o, LaneOperation, p.imagePlan) })
	check(out)
	mustEnvironment(t, s.View(func(r *Reader) error {
		got, present, err := r.ReadTreeAuthorityV1()
		if err != nil || !present || !reflect.DeepEqual(got, want) || !r.usable() {
			t.Fatalf("seeded authority after the refusal = %+v, %v, %v usable %v", got, present, err, r.usable())
		}
		return nil
	}))
	if p.calls != 1 || replays != 0 {
		t.Fatalf("planner %d replay %d", p.calls, replays)
	}
	tiAfter(t, s, o, LaneOperation, p, check)
}

func tiCensusFailure(t *testing.T, err error) { treeNativeIntegrity(t, err, operationUpdate, nil) }

func tiSchemaFailure(t *testing.T, err error) {
	treeNativeIntegrity(t, err, operationUpdate, errSchema)
}

func tiReadRows(t *testing.T) []tiRow {
	t.Helper()
	bound := tiAuthorityAtBound(t)
	foreign := func(t *testing.T, s *Store) { treeNativeSeed(t, s, 0, []byte{3}, bytes.Repeat([]byte{8}, 32)) }
	empty := func(*testing.T, *Store) {}
	rows := []tiRow{
		{name: "census failure from a rank-1 row", seed: tiRankOne, modes: []uint32{0, 9, 10}, want: tiCensusFailure},
		{name: "census failure from a rank-1 row after Tag 4 and a 1048576-byte Authority pass", seed: tiRankOne, edit: func(p *TreeImagePublicationV1) { p.Tag, p.RecordLimit, p.Authority = 4, 1, bound }, want: tiCensusFailure},
		{name: "census failure from a foreign meta 03", seed: foreign, want: tiCensusFailure},
		{name: "get EIO at key 0x02", seed: empty, fault: 28, faultKey: []byte{2}, want: func(t *testing.T, err error) {
			treeNativeError(t, err, operationUpdate, "IO", 5, "error 5", nil)
		}},
		{name: "invalid get result shape at census key 0x00", seed: empty, fault: 17, faultKey: []byte{0}, want: func(t *testing.T, err error) {
			treeNativeError(t, err, operationUpdate, "LocalInvariant", -30779, "mdbx_get returned invalid result shape", nil)
		}},
		{name: "decode failure of a one-byte key 0x02", seed: func(t *testing.T, s *Store) { treeNativeSeed(t, s, 0, []byte{2}, []byte{0}) }, want: tiSchemaFailure},
		{name: "width failure of a 1048577-byte key 0x02", seed: func(t *testing.T, s *Store) { treeNativeSeed(t, s, 0, []byte{2}, make([]byte, 1048577)) }, want: tiSchemaFailure},
	}
	for i := range rows {
		rows[i].consumed = true
		if rows[i].modes == nil {
			rows[i].modes = []uint32{0}
		}
	}
	return rows
}

func tiBeginFailure(t *testing.T, scenario SelectedDamageScenario, class EngineClass, code int) {
	s, _, _ := treeNativeStore(t)
	o := reservationOwner(t, MinReservationLimit)
	calls := 0
	var out tiOutcome
	evidence, err := FixtureSelectedDamage(s, o, scenario, 0, []byte{0}, func() {
		out = tiCall(s, o, LaneOperation, func(*Reader) (TreeImagePublicationV1, error) { calls++; return TreeImagePublicationV1{}, nil })
	})
	mustEnvironment(t, err)
	result := tiReturned(t, out)
	treeNativeError(t, result, operationUpdate, class, code, expectedNativeDiagnostic(code), nil)
	if calls != 0 || evidence.BeginOld != 1 || evidence.Faults != 1 || evidence.BeginWrite != 0 || evidence.BeginRead != 0 || evidence.OldAborts != 0 {
		t.Fatalf("begin evidence %+v planner %d", evidence, calls)
	}
	tiDisposition(t, s, 0, true, result, true)
	tiTerminal(t, s, o, 1, result)
}

func tiNewTerminal(t *testing.T) {
	s, o, w := ctxTreePairScene(t)
	var r tsResult
	evidence := ctxTreeFault(t, s, 12, 0, []byte{9}, func() { r = tsRun(t, s, o, TreeOperation, ctxTreeOp(60, w)) })
	r.tuple(t, 2, 3, -1)
	if evidence.commits != 1 || evidence.drift != 0 {
		t.Fatalf("crossed producer evidence %+v err %v", evidence, r.err)
	}
	if s.state != storeCLOSED || any(s.terminal) != any(r.err) || s.terminalTruth != 2 {
		t.Fatalf("crossed producer left %s terminal %v truth %d", s.state, s.terminal, s.terminalTruth)
	}
	calls := 0
	out := tiCall(s, o, LaneOperation, func(*Reader) (TreeImagePublicationV1, error) { calls++; return TreeImagePublicationV1{}, nil })
	if !out.returned || out.live != 0 {
		t.Fatalf("NEW terminal call returned %v recovered %v live %d", out.returned, out.recovered, out.live)
	}
	out.r.tuple(t, 2, 1, -1)
	if any(out.r.err) != any(r.err) || calls != 0 {
		t.Fatalf("NEW terminal returned %v planner %d", out.r.err, calls)
	}
	tsConsumed(t, s, o, 2, r.err)
	tiTerminal(t, s, o, 2, r.err)
}

// tiPlannerCase runs one planner outcome under SelectedDamageProbeOnly for mode 0 and under mode
// at rank 0 key 0x00 otherwise, then checks the end, the planner, Replay and Reader and the next
// public calls.
func tiPlannerCase(t *testing.T, outcome string, mode uint32) {
	s, _, _ := treeNativeStore(t)
	o := reservationOwner(t, MinReservationLimit)
	replays := 0
	publication := tiPublication(t, &replays)
	value, marker := new(int), errors.New("planner error")
	var nilValue any
	var application error = marker
	switch outcome {
	case "wrapped":
		application = fmt.Errorf("planner context: %w", marker)
	case "typed-nil":
		var typed *nilPointerError
		application = typed
	}
	if outcome != "nil" {
		tiRankOne(t, s)
	}
	p := &tiPlanner{outcome: func(*Reader) (TreeImagePublicationV1, error) {
		switch outcome {
		case "nil":
			return publication, nil
		case "panic":
			panic(value)
		case "panic-nil":
			panic(nilValue)
		case "goexit":
			runtime.Goexit()
		}
		return TreeImagePublicationV1{}, application
	}}
	check := func(out tiOutcome) { tiPlannerEnd(t, s, outcome, mode, out, value, application) }
	var out tiOutcome
	tiNative(t, s, o, mode, 0, []byte{0}, func() { out = tiCall(s, o, LaneOperation, p.imagePlan) })
	check(out)
	if p.calls != 1 || replays != 0 || reservationLive(o) != 0 {
		t.Fatalf("planner %d replay %d live %d", p.calls, replays, reservationLive(o))
	}
	tsExpiredReader(t, p.kept)
	tiAfter(t, s, o, LaneOperation, p, check)
}

// tiPlannerEnd checks how the call ended for outcome and the primary the abort of mode carries.
func tiPlannerEnd(t *testing.T, s *Store, outcome string, mode uint32, out tiOutcome, value *int, application error) {
	t.Helper()
	switch outcome {
	case "panic", "panic-nil", "goexit":
		if out.returned {
			t.Fatal("unwinding planner returned")
		}
		tiDisposition(t, s, mode, false, s.terminal, false)
	}
	switch outcome {
	case "nil":
		tiInvalidBatch(t, tiDisposition(t, s, mode, false, tiReturned(t, out), true))
	case "panic":
		if out.recovered != value {
			t.Fatalf("panic value %v", out.recovered)
		}
	case "panic-nil":
		if _, ok := out.recovered.(*runtime.PanicNilError); !ok {
			t.Fatalf("nil panic resumed as %T", out.recovered)
		}
	case "goexit":
		if out.recovered != nil {
			t.Fatalf("Goexit resumed as panic %v", out.recovered)
		}
	default:
		if primary := tiDisposition(t, s, mode, false, tiReturned(t, out), true); any(primary) != any(application) {
			t.Fatalf("planner error identity %T", primary)
		}
	}
}

// tiRecordedCase: the planner's ReadTreeAuthorityV1 records the census failure f
// on a Store with a rank-1 row; readPrimary composes f with the error the planner returns,
// nil when it returns nil, panics or calls Goexit.
func tiRecordedCase(t *testing.T, mode string) {
	s, _, _ := treeNativeStore(t)
	tiRankOne(t, s)
	o := reservationOwner(t, MinReservationLimit)
	var f, application error
	value := new(int)
	p := &tiPlanner{outcome: func(r *Reader) (TreeImagePublicationV1, error) {
		_, _, f = r.ReadTreeAuthorityV1()
		switch mode {
		case "panic":
			panic(value)
		case "goexit":
			runtime.Goexit()
		case "returned":
			application = f
		case "wrapped":
			application = fmt.Errorf("planner: %w", f)
		case "other":
			application = errors.New("planner error")
		}
		return TreeImagePublicationV1{}, application
	}}
	var out tiOutcome
	evidence := tiProbe(t, s, o, func() { out = tiCall(s, o, LaneOperation, p.imagePlan) })
	if evidence.OldGets[0] != 1 {
		t.Fatalf("meta gets on ORIGINAL OLD %d, want the planner read only", evidence.OldGets[0])
	}
	treeNativeIntegrity(t, f, operationGet, nil)
	terminal := f
	switch mode {
	case "panic", "goexit":
		if out.returned || (mode == "panic") != (out.recovered == any(value)) || (mode == "goexit") != (out.recovered == nil) {
			t.Fatalf("unwind %v returned %v", out.recovered, out.returned)
		}
	case "ignored", "returned":
		if any(tiReturned(t, out)) != any(f) {
			t.Fatalf("recorded failure identity %v", out.r.err)
		}
	default:
		terminal = tiReturned(t, out)
		joined, ok := terminal.(interface{ Unwrap() []error })
		if !ok || len(joined.Unwrap()) != 2 || any(joined.Unwrap()[0]) != any(application) || any(joined.Unwrap()[1]) != any(f) {
			t.Fatalf("planner error and recorded failure order %v", terminal)
		}
	}
	tiDisposition(t, s, 0, true, terminal, true)
	if p.calls != 1 || reservationLive(o) != 0 {
		t.Fatalf("planner %d live %d", p.calls, reservationLive(o))
	}
	tsExpiredReader(t, p.kept)
	tiTerminal(t, s, o, 1, terminal)
}
