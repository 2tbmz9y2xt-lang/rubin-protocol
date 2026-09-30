//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// newSSQFixtureWorld compares committed rows natively, so seeded malformed widths are observed without Reader.Get.
func newSSQFixtureWorld(t *testing.T, spec ssqSpec) *ssqWorld {
	t.Helper()
	w := newSSQWorld(t, spec)
	w.rawEqual = func(rank uint8, key, want []byte) (bool, error) { return mdbx.FixtureRawRowEqual(w.store, rank, key, want) }
	return w
}

// seed writes one raw row of any width and tracks it as the expected image.
func (w *ssqWorld) seed(rank uint8, key, value []byte) {
	w.t.Helper()
	if err := mdbx.FixtureSeedRawRow(w.store, rank, key, value); err != nil {
		w.t.Fatalf("seed %d/%x: %v", rank, key, err)
	}
	w.rows[string(append([]byte{rank}, key...))] = ssqRow{rank: rank, key: key, value: value}
}

// own pairs a new canonical forward entry at free height k with an owner row for hash whose entry parent is prev.
func (w *ssqWorld) own(hash, prev [32]byte, k uint64) {
	w.apply([]mdbx.Mutation{
		w.literal(2, ssqMust(mdbx.HeightKey(1, k)), mdbx.ChainValue(hash, prev, ssqWork(k+1)), false),
		w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, hash)), mdbx.CanonicalOwnerValue(k), false),
	})
}

// fixture qualifies raw in one armed no-write Update that stops with a private sentinel after observation. Every
// scenario writes, deletes and commits nothing and ends OLD/Prewrite; the image is then compared natively.
func (w *ssqWorld) fixture(scenario mdbx.SelectedDamageScenario, rank uint8, key, raw []byte) (selectedSideQualification, error, mdbx.SelectedDamageEvidence) {
	w.t.Helper()
	defer w.wantRaw(raw, bytes.Clone(raw))
	sentinel := errors.New("qualification observed")
	var got selectedSideQualification
	var err error
	truth, stage := mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite
	evidence, fixtureErr := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() {
		truth, stage, err = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
			var qerr error
			got, qerr = qualifySelectedSideMDBX(r, raw)
			if qerr != nil {
				return mdbx.Batch{}, qerr
			}
			return mdbx.Batch{}, sentinel
		})
	})
	if fixtureErr != nil {
		w.t.Fatalf("fixture scenario %d: %v (%+v)", scenario, fixtureErr, evidence)
	}
	if err == sentinel { //nolint:errorlint // Only the exact sentinel with no infrastructure cause is success.
		err = nil
	}
	if truth != mdbx.CommitTruthOld || stage != mdbx.UpdateStagePrewrite || evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.Deletes != 0 {
		w.t.Fatalf("scenario %d: truth/stage %v/%v evidence %+v", scenario, truth, stage, evidence)
	}
	if evidence.BeginOld == 1 && scenario != mdbx.SelectedDamageBeginTxnFull && scenario != mdbx.SelectedDamageBeginEIO && evidence.OldAborts != 1 {
		w.t.Fatalf("scenario %d: %d OLD aborts", scenario, evidence.OldAborts)
	}
	w.wantImage("after armed qualification")
	return got, err, evidence
}

func (w *ssqWorld) probe(raw []byte) (selectedSideQualification, error, mdbx.SelectedDamageEvidence) {
	return w.fixture(mdbx.SelectedDamageProbeOnly, 0, nil, raw)
}

func ssqWantGets(t *testing.T, label string, evidence mdbx.SelectedDamageEvidence, want [8]uint64) {
	t.Helper()
	if evidence.OldGets != want {
		t.Fatalf("%s: per-rank Gets %v, want %v", label, evidence.OldGets, want)
	}
}

// ssqEngines walks the joined and wrapped error tree in order and returns each distinct EngineError once (the
// qualifier's classified wrapper and the Store's recorded infrastructure cause may name the same object).
func ssqEngines(err error) []*mdbx.EngineError {
	var out []*mdbx.EngineError
	var walk func(error)
	walk = func(err error) {
		if engine, ok := err.(*mdbx.EngineError); ok && !slices.Contains(out, engine) { //nolint:errorlint // The walk inspects each node directly.
			out = append(out, engine)
		}
		switch e := err.(type) { //nolint:errorlint // The walk inspects each node directly.
		case interface{ Unwrap() []error }:
			for _, part := range e.Unwrap() {
				walk(part)
			}
		case interface{ Unwrap() error }:
			walk(e.Unwrap())
		}
	}
	walk(err)
	return out
}

// ssqNative is one expected EngineError tuple. Unchanged mdbx.h: MDBX_TXN_FULL=-30788 (EngineTransaction);
// Darwin/Linux MDBX_EIO is errno EIO=5 (EngineIO).
type ssqNative struct {
	operation string
	class     mdbx.EngineClass
	code      int
}

var (
	ssqGetEIO   = ssqNative{"get", mdbx.EngineIO, 5}
	ssqAbortEIO = ssqNative{"abort", mdbx.EngineIO, 5}
)

// ssqWantNative requires exactly the ordered distinct EngineError tuples, each still reachable by errors.Is/As.
func ssqWantNative(t *testing.T, label string, err error, want ...ssqNative) {
	t.Helper()
	engines := ssqEngines(err)
	if len(engines) != len(want) {
		t.Fatalf("%s: %d native causes, want %v (%v)", label, len(engines), want, err)
	}
	for i, engine := range engines {
		var as *mdbx.EngineError
		if (ssqNative{engine.Operation, engine.Class, engine.Code}) != want[i] || !errors.Is(err, engine) || !errors.As(err, &as) {
			t.Fatalf("%s: cause %d is %s/%s/%d, want %v", label, i, engine.Operation, engine.Class, engine.Code, want[i])
		}
	}
}

func TestSelectedSideQualificationEvidenceFixture(t *testing.T) {
	w := newSSQFixtureWorld(t, ssqSpec{tip: 5, side: &ssqSideSpec{f: 5, tip: 6, rows: 1, work: 3}})
	c5, tip := w.canonical[5], w.side[6]
	raw := w.child(c5, 6, nil)
	got, err, evidence := w.probe(raw)
	ssqWantOK(t, "comparison-only tip", got, err, w.want(raw, c5, 5, 5, ssqWork(6), ssqWork(7), true, append(w.canonicalIDs(5, 6), w.comparatorIDs()...)))
	ssqWantGets(t, "comparison-only tip", evidence, [8]uint64{1, 0, 1, 7, 0, 0, 1, 2})
	raw = w.child(tip, 7, nil)
	got, err, evidence = w.probe(raw)
	ssqWantOK(t, "actual linking parent", got, err, w.want(raw, tip, 6, 5, ssqWork(7), ssqWork(8), true, w.selectedIDs(7)))
	ssqWantGets(t, "actual linking parent", evidence, [8]uint64{1, 0, 1, 7, 1, 0, 1, 2})
	// A corrupt comparator body is unobserved.
	w.seed(4, bytes.Clone(tip[:]), []byte{1, 2, 3})
	raw = w.child(c5, 6, nil)
	got, err, evidence = w.probe(raw)
	ssqWantOK(t, "corrupt comparator body", got, err, w.want(raw, c5, 5, 5, ssqWork(6), ssqWork(7), true, append(w.canonicalIDs(5, 6), w.comparatorIDs()...)))
	ssqWantGets(t, "corrupt comparator body", evidence, [8]uint64{1, 0, 1, 7, 0, 0, 1, 2})
}

// ssqAuthorityBytes encodes a legal authority. In the None-phase encoding the SelectedSide descriptor starts at 39
// (generation), then F at 47, tip at 55 and the row count at 135; in the PRUNE_GC encoding the first cleanup span's
// generation is at 38 and its last height at 54 (authority_encode.go field order).
func ssqAuthorityBytes(t *testing.T, a mdbx.StorageAuthorityV1) []byte {
	t.Helper()
	encoded, err := a.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return encoded
}

func TestSelectedSideQualificationControlFixture(t *testing.T) {
	// Refused cells read only the authority, even with a raw candidate above M.
	for _, c := range []struct {
		name   string
		edit   func(*mdbx.StorageAuthorityV1)
		result string
	}{{"NONE/RECOVERY_REQUIRED", ssqPendingNone, ssqRequired}, {"ORDINARY_APPLY/RECOVERY_REQUIRED", ssqOrdinary, ssqRecovery}} {
		w := newSSQFixtureWorld(t, ssqSpec{tip: 5, authority: c.edit})
		got, err, evidence := w.probe(make([]byte, mdbx.MaxBlockBytes+1))
		ssqWantResult(t, c.name, got, err, c.result)
		ssqWantGets(t, c.name, evidence, [8]uint64{1})
	}
	// Malformed selected/phase payloads fail strict authority legality before the table, raw bound or any other read.
	w := newSSQFixtureWorld(t, ssqSpec{tip: 0, side: &ssqSideSpec{f: 0, tip: 1_440, from: 1_430, rows: 1_439}})
	legal := w.rows[string([]byte{0, 2})].value
	span := w.authorityValue()
	first := span.SelectedSide.TipHeight - uint64(span.SelectedSide.RowCount) + 1
	span.Phase = mdbx.StoragePhasePruneGCV1
	span.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 2, FirstHeight: first - 1, LastHeight: first - 1, NextHeight: first - 1}}}
	withSpan := ssqAuthorityBytes(t, span)
	mutate := func(base []byte, offset int, value []byte) []byte {
		out := bytes.Clone(base)
		copy(out[offset:], value)
		return out
	}
	u64 := func(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }
	for _, c := range []struct {
		name  string
		value []byte
	}{
		{"tip <= F", mutate(legal, 47, u64(1_440))},
		{"C>=1440 count 1438", mutate(legal, 135, []byte{0x05, 0x9e})},
		{"SIDE different generation", mutate(withSpan, 38, u64(3))},
		{"SIDE overlapping selected rows", mutate(withSpan, 54, u64(first))},
	} {
		w.seed(0, []byte{2}, c.value)
		// The recorded Integrity consumes the handle; wantImage reopens it and authority legality still decides first.
		for _, raw := range [][]byte{w.child(w.side[1_440], 1_441, nil), make([]byte, mdbx.MaxBlockBytes+1)} {
			got, err, evidence := w.probe(raw)
			ssqWantEngine(t, c.name, got, err, mdbx.EngineIntegrity, "get", 0, "invalid storage authority")
			ssqWantGets(t, c.name, evidence, [8]uint64{1})
		}
	}
	// An authority native failure also precedes the table and the raw bound.
	w = newSSQFixtureWorld(t, ssqSpec{tip: 5, authority: ssqPendingNone})
	got, err, evidence := w.fixture(mdbx.SelectedDamageGetEIO, 0, []byte{2}, make([]byte, mdbx.MaxBlockBytes+1))
	ssqWantNative(t, "authority GetEIO", err, ssqGetEIO)
	ssqWantZero(t, "authority GetEIO", got)
	if errors.As(err, new(*selectedSideQualificationError)) {
		t.Fatalf("authority GetEIO was classified: %v", err)
	}
	ssqWantGets(t, "authority GetEIO", evidence, [8]uint64{1})
}

func TestSelectedSideQualificationCanonicalEvidenceFixture(t *testing.T) {
	var zeroWork [40]byte
	for _, c := range []struct {
		name string
		seed func(w *ssqWorld)
	}{
		{"inverse width", func(w *ssqWorld) { w.seed(7, ssqMust(mdbx.CanonicalOwnerKey(1, w.canonical[5])), make([]byte, 7)) }},
		{"forward width", func(w *ssqWorld) {
			w.seed(2, ssqMust(mdbx.HeightKey(1, 5)), mdbx.ChainValue(w.canonical[5], w.canonical[4], ssqWork(6))[:103])
		}},
		{"forward work outside domain", func(w *ssqWorld) {
			w.seed(2, ssqMust(mdbx.HeightKey(1, 5)), mdbx.ChainValue(w.canonical[5], w.canonical[4], zeroWork))
		}},
		{"missing forward", func(w *ssqWorld) {
			w.seed(7, ssqMust(mdbx.CanonicalOwnerKey(1, w.canonical[5])), mdbx.CanonicalOwnerValue(9))
		}},
		{"conflicting forward", func(w *ssqWorld) {
			w.seed(2, ssqMust(mdbx.HeightKey(1, 5)), mdbx.ChainValue([32]byte{0x31}, w.canonical[4], ssqWork(6)))
		}},
		{"wrong header hash", func(w *ssqWorld) { w.seed(3, bytes.Clone(w.canonical[5][:]), w.headers[w.canonical[4]]) }},
	} {
		w := newSSQFixtureWorld(t, ssqSpec{tip: 5})
		raw := w.child(w.canonical[5], 6, nil)
		c.seed(w)
		got, err, _ := w.probe(raw)
		ssqWantResult(t, c.name, got, err, ssqIntegrity)
	}
}

// ssqOwnedWorld is a selected side (F 2, tip 4) whose tip hash is also canonically Owned at height k under promise B.
func ssqOwnedWorld(t *testing.T, b, k uint64, bare bool) (*ssqWorld, [32]byte, []byte) {
	t.Helper()
	w := newSSQFixtureWorld(t, ssqSpec{tip: 2, b: b, side: &ssqSideSpec{f: 2, tip: 4, rows: 2, bare: bare}})
	tip := w.side[4]
	if k != 0 {
		w.own(tip, w.side[3], k)
	}
	return w, tip, w.child(tip, 5, nil)
}

func TestSelectedSideQualificationSelectedEvidenceFixture(t *testing.T) {
	var zeroWork [40]byte
	request := selectedSideDamageRequest{Generation: 2, Tip: 4, Height: 4}
	linkKey := ssqMust(mdbx.HeightKey(2, 4))
	for _, c := range []struct {
		name string
		seed func(w *ssqWorld, tip [32]byte)
	}{
		{"missing link", func(w *ssqWorld, _ [32]byte) { w.apply([]mdbx.Mutation{w.absentRow(6, linkKey)}) }},
		{"link width", func(w *ssqWorld, tip [32]byte) { w.seed(6, linkKey, mdbx.ChainValue(tip, w.side[3], ssqWork(5))[:103]) }},
		{"link work outside domain", func(w *ssqWorld, tip [32]byte) { w.seed(6, linkKey, mdbx.ChainValue(tip, w.side[3], zeroWork)) }},
	} {
		w, tip, raw := ssqOwnedWorld(t, 0, 0, false)
		c.seed(w, tip)
		got, err, _ := w.probe(raw)
		ssqWantResult(t, c.name, got, err, ssqIntegrity)
	}
	// Body defects: NONE and Owned k=B-1 (reference 4 >= B=4) are optional requests; Owned k=B (reference 4 < B=5)
	// is required canonical integrity with no locator.
	defects := []struct {
		name  string
		apply func(w *ssqWorld, tip [32]byte, body []byte)
	}{
		{"absent", func(w *ssqWorld, tip [32]byte, _ []byte) { w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))}) }},
		{"invalid width", func(w *ssqWorld, tip [32]byte, body []byte) { w.seed(4, bytes.Clone(tip[:]), body[:50]) }},
		{"trailing bytes", func(w *ssqWorld, tip [32]byte, body []byte) { w.seed(4, bytes.Clone(tip[:]), append(bytes.Clone(body), 0)) }},
		{"merkle", func(w *ssqWorld, tip [32]byte, body []byte) {
			w.seed(4, bytes.Clone(tip[:]), append(append(bytes.Clone(body[:consensus.BLOCK_HEADER_BYTES]), 1), ssqTx(true)...))
		}},
		{"different commitment-valid header", func(w *ssqWorld, tip [32]byte, body []byte) {
			// A copy of the healthy body with only the header nonce changed: root and witness commitment stay valid.
			seeded := bytes.Clone(body)
			seeded[108] ^= 0x01
			if ssqHash(seeded) == tip || !bytes.Equal(seeded[4:108], body[4:108]) || !bytes.Equal(seeded[consensus.BLOCK_HEADER_BYTES:], body[consensus.BLOCK_HEADER_BYTES:]) {
				t.Fatal("nonce-changed body must differ from its key and keep every root-bearing byte")
			}
			w.seed(4, bytes.Clone(tip[:]), seeded)
		}},
	}
	for _, owner := range []struct {
		name     string
		b, k     uint64
		required bool
	}{{"NONE", 0, 0, false}, {"k=B-1 reference>=B", 4, 3, false}, {"k=B reference<B", 5, 5, true}} {
		for _, d := range defects {
			w, tip, raw := ssqOwnedWorld(t, owner.b, owner.k, false)
			d.apply(w, tip, w.rows[string(append([]byte{4}, tip[:]...))].value)
			got, err, _ := w.probe(raw)
			if owner.required {
				ssqWantResult(t, owner.name+" "+d.name, got, err, ssqIntegrity)
			} else {
				ssqWantRequest(t, owner.name+" "+d.name, got, err, request)
			}
		}
		w, _, raw := ssqOwnedWorld(t, owner.b, owner.k, true)
		got, err, _ := w.probe(raw)
		if owner.required {
			ssqWantResult(t, owner.name+" witness", got, err, ssqIntegrity)
		} else {
			ssqWantRequest(t, owner.name+" witness", got, err, request)
		}
	}
	// The earlier canonical header/index defect wins over an optional body defect of the same Owned tip.
	w := newSSQFixtureWorld(t, ssqSpec{tip: 2, b: 4, side: &ssqSideSpec{f: 2, tip: 4, rows: 2}})
	tip := w.side[4]
	w.own(tip, [32]byte{0x44}, 3)
	raw := w.child(tip, 5, nil)
	w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
	got, err, _ := w.probe(raw)
	ssqWantResult(t, "header defect before body damage", got, err, ssqIntegrity)
}

func TestSelectedSideQualificationHistoryFixture(t *testing.T) {
	w := newSSQFixtureWorld(t, ssqSpec{owned: 8_639, tip: 8_639, side: &ssqSideSpec{f: 8_639, tip: 10_079, rows: 1_439}})
	raw := w.child(w.side[10_079], 10_080, nil)
	// Unowned malformed-width and well-width wrong-hash headers at first-1 and first, all preceding evidence healthy.
	wrong := w.headers[w.side[8_642]]
	for _, c := range []struct {
		height, reads      uint64
		request, wrongHash bool
	}{{8_640, 1_440, false, false}, {8_641, 1_439, true, false}, {8_640, 1_440, false, true}, {8_641, 1_439, true, true}} {
		hash := w.side[c.height]
		header := w.headers[hash]
		bad := header[:50]
		if c.wrongHash {
			bad = wrong
			if ssqHash(bad) == hash || len(bad) != consensus.BLOCK_HEADER_BYTES {
				t.Fatal("wrong-hash header must be well-width and hash elsewhere")
			}
		}
		w.seed(3, bytes.Clone(hash[:]), bad)
		got, err, evidence := w.probe(raw)
		if c.request {
			ssqWantRequest(t, "malformed first", got, err, selectedSideDamageRequest{Generation: 2, Tip: 10_079, Height: 8_641})
		} else {
			ssqWantResult(t, "malformed first-1", got, err, ssqBranch)
		}
		ssqWantGets(t, "malformed header stop", evidence, [8]uint64{1, 0, 0, c.reads, 1, 0, 1, c.reads})
		w.seed(3, bytes.Clone(hash[:]), header)
	}
	// An Owned header defect keeps canonical integrity at first-1 and at first, before any range decision.
	for _, height := range []uint64{8_640, 8_641} {
		hash := w.side[height]
		w.own(hash, [32]byte{0x44}, 9_000)
		got, err, _ := w.probe(raw)
		ssqWantResult(t, "Owned header defect", got, err, ssqIntegrity)
		w.apply([]mdbx.Mutation{w.absentRow(2, ssqMust(mdbx.HeightKey(1, 9_000))), w.absentRow(7, ssqMust(mdbx.CanonicalOwnerKey(1, hash)))})
	}
	// A healthy Owned header read transiently at first-1 or first is canonical_artifact_read, not branch data. Each
	// fault consumes its verified handle, so each height uses its own fresh public setup (never a reopened handle).
	for _, height := range []uint64{8_640, 8_641} {
		if height != 8_640 {
			w = newSSQFixtureWorld(t, ssqSpec{owned: 8_639, tip: 8_639, side: &ssqSideSpec{f: 8_639, tip: 10_079, rows: 1_439}})
			raw = w.child(w.side[10_079], 10_080, nil)
		}
		hash := w.side[height]
		w.own(hash, [32]byte(w.headers[hash][4:36]), 9_000)
		got, err, _ := w.fixture(mdbx.SelectedDamageGetEIO, 3, bytes.Clone(hash[:]), raw)
		ssqWantResult(t, "Owned header transient", got, err, ssqCanonical)
		ssqWantNative(t, "Owned header transient", err, ssqGetEIO)
	}
}

func TestSelectedSideQualificationCapacityFixture(t *testing.T) {
	w := newSSQFixtureWorld(t, ssqSpec{tip: 5})
	got, err, evidence := w.probe(make([]byte, mdbx.MaxBlockBytes+1))
	ssqWantResult(t, "raw above M", got, err, ssqBranch)
	ssqWantGets(t, "raw above M", evidence, [8]uint64{1})
	// Full descriptors at tip 10079 with child h10080: F3780 needs exactly 16384 identities, F3779 needs 16385 and
	// stops before the height-0 header, F0 stops at the two-slot owner preflight after 8190 optional heights.
	for _, c := range []struct {
		f    uint64
		gets [8]uint64
	}{
		{3_780, [8]uint64{1, 0, 1, 10_080, 1, 0, 1, 6_300}},
		{3_779, [8]uint64{1, 0, 1, 10_079, 1, 0, 1, 6_301}},
		{0, [8]uint64{1, 0, 0, 8_190, 1, 0, 1, 8_190}},
	} {
		w := newSSQFixtureWorld(t, ssqSpec{owned: c.f, tip: c.f, side: &ssqSideSpec{f: c.f, tip: 10_079, rows: 1_440}})
		tip := w.side[10_079]
		raw := w.child(tip, 10_080, nil)
		got, err, evidence := w.probe(raw)
		if c.f == 3_780 {
			ssqWantOK(t, "F3780", got, err, w.want(raw, tip, 10_079, c.f, ssqWork(10_080), ssqWork(10_081), true, w.selectedIDs(10_080)))
			if len(got.Consulted) != 16_384 {
				t.Fatalf("F3780 evidence %d identities", len(got.Consulted))
			}
		} else {
			ssqWantResult(t, "identity ceiling", got, err, ssqBranch)
		}
		ssqWantGets(t, "identity ceiling stop", evidence, c.gets)
	}
}

func TestSelectedSideQualificationNative(t *testing.T) {
	// Transaction begin failures never reach the qualifier.
	for _, scenario := range []mdbx.SelectedDamageScenario{mdbx.SelectedDamageBeginTxnFull, mdbx.SelectedDamageBeginEIO} {
		w := newSSQFixtureWorld(t, ssqSpec{tip: 5})
		got, err, evidence := w.fixture(scenario, 0, nil, w.child(w.canonical[5], 6, nil))
		if errors.As(err, new(*selectedSideQualificationError)) || evidence.BeginOld != 1 || evidence.OldAborts != 0 || evidence.OldGets != [8]uint64{} {
			t.Fatalf("begin scenario %d: %v (%+v)", scenario, err, evidence)
		}
		want := ssqNative{"update", mdbx.EngineTransaction, -30_788}
		if scenario == mdbx.SelectedDamageBeginEIO {
			want = ssqNative{"update", mdbx.EngineIO, 5}
		}
		ssqWantNative(t, "begin failure", err, want)
		ssqWantZero(t, "begin failure", got)
	}
	// Exact Get faults: each read keeps its native cause and takes its read's resource class.
	canonicalWorld := func() (*ssqWorld, []byte) {
		w := newSSQFixtureWorld(t, ssqSpec{tip: 5})
		return w, w.child(w.canonical[5], 6, nil)
	}
	sideWorld := func(b, k uint64) func() (*ssqWorld, []byte) {
		return func() (*ssqWorld, []byte) { w, _, raw := ssqOwnedWorld(t, b, k, false); return w, raw }
	}
	// A canonical-parent candidate (parent c2, h3) whose comparison-only selected tip link is read after the window.
	comparatorWorld := func() (*ssqWorld, []byte) {
		w, _, _ := ssqOwnedWorld(t, 0, 0, false)
		return w, w.child(w.canonical[2], 3, nil)
	}
	linkKey := func(*ssqWorld) []byte { return ssqMust(mdbx.HeightKey(2, 4)) }
	get, getAbort := []ssqNative{ssqGetEIO}, []ssqNative{ssqGetEIO, ssqAbortEIO}
	for _, c := range []struct {
		name     string
		scenario mdbx.SelectedDamageScenario
		world    func() (*ssqWorld, []byte)
		rank     uint8
		key      func(w *ssqWorld) []byte
		result   string
		causes   []ssqNative
		gets     *[8]uint64
	}{
		{"inverse", mdbx.SelectedDamageGetEIO, canonicalWorld, 7, func(w *ssqWorld) []byte { return ssqMust(mdbx.CanonicalOwnerKey(1, w.canonical[5])) }, ssqCanonical, get, nil},
		{"forward", mdbx.SelectedDamageGetEIO, canonicalWorld, 2, func(*ssqWorld) []byte { return ssqMust(mdbx.HeightKey(1, 5)) }, ssqCanonical, get, nil},
		{"required header", mdbx.SelectedDamageGetEIO, canonicalWorld, 3, func(w *ssqWorld) []byte { return bytes.Clone(w.canonical[5][:]) }, ssqCanonical, get, nil},
		{"required header get and abort", mdbx.SelectedDamageGetAbortEIO, canonicalWorld, 3, func(w *ssqWorld) []byte { return bytes.Clone(w.canonical[5][:]) }, ssqCanonical, getAbort, nil},
		{"optional header", mdbx.SelectedDamageGetEIO, sideWorld(0, 0), 3, func(w *ssqWorld) []byte { return bytes.Clone(w.side[3][:]) }, ssqBranch, get, nil},
		{"body NONE", mdbx.SelectedDamageGetEIO, sideWorld(0, 0), 4, func(w *ssqWorld) []byte { return bytes.Clone(w.side[4][:]) }, ssqBranch, get, nil},
		{"body k=B-1 reference>=B", mdbx.SelectedDamageGetEIO, sideWorld(4, 3), 4, func(w *ssqWorld) []byte { return bytes.Clone(w.side[4][:]) }, ssqBranch, get, nil},
		{"body k=B reference<B", mdbx.SelectedDamageGetEIO, sideWorld(5, 5), 4, func(w *ssqWorld) []byte { return bytes.Clone(w.side[4][:]) }, ssqCanonical, get, nil},
		// SideLink transients stop before any owner/header/body read of the tip.
		{"actual-parent SideLink", mdbx.SelectedDamageGetEIO, sideWorld(0, 0), 6, linkKey, ssqBranch, get, &[8]uint64{1, 0, 0, 0, 0, 0, 1, 0}},
		{"actual-parent SideLink get and abort", mdbx.SelectedDamageGetAbortEIO, sideWorld(0, 0), 6, linkKey, ssqBranch, getAbort, &[8]uint64{1, 0, 0, 0, 0, 0, 1, 0}},
		{"comparison-tip SideLink", mdbx.SelectedDamageGetEIO, comparatorWorld, 6, linkKey, ssqBranch, get, &[8]uint64{1, 0, 1, 3, 0, 0, 1, 1}},
		{"comparison-tip SideLink get and abort", mdbx.SelectedDamageGetAbortEIO, comparatorWorld, 6, linkKey, ssqBranch, getAbort, &[8]uint64{1, 0, 1, 3, 0, 0, 1, 1}},
	} {
		w, raw := c.world()
		got, err, evidence := w.fixture(c.scenario, c.rank, c.key(w), raw)
		ssqWantResult(t, c.name, got, err, c.result)
		ssqWantNative(t, c.name, err, c.causes...)
		if c.gets != nil {
			ssqWantGets(t, c.name, evidence, *c.gets)
		}
	}
	// The authority read is not classified by the qualifier.
	w, raw := canonicalWorld()
	got, err, _ := w.fixture(mdbx.SelectedDamageGetEIO, 0, []byte{2}, raw)
	ssqWantZero(t, "authority", got)
	ssqWantNative(t, "authority", err, ssqGetEIO)
	if errors.As(err, new(*selectedSideQualificationError)) {
		t.Fatalf("authority GetEIO was classified: %v", err)
	}
	// An OLD abort failure after a healthy observation outranks the success sentinel.
	w, raw = canonicalWorld()
	_, err, _ = w.fixture(mdbx.SelectedDamageAbortEIO, 0, nil, raw)
	ssqWantNative(t, "abort after healthy observation", err, ssqAbortEIO)
}

func TestSelectedSideQualificationReservation(t *testing.T) {
	w := newSSQFixtureWorld(t, ssqSpec{tip: 5})
	c5 := w.canonical[5]
	raw := w.child(c5, 6, nil)
	sentinel := errors.New("qualification observed")
	qualify := func(stop error) func(*mdbx.Reader) (mdbx.Batch, error) {
		return func(r *mdbx.Reader) (mdbx.Batch, error) {
			if _, err := qualifySelectedSideMDBX(r, raw); err != nil {
				return mdbx.Batch{}, err
			}
			return mdbx.Batch{}, stop
		}
	}
	fullLane := func(label string) {
		ran := 0
		if err := w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { ran++; return nil }); err != nil || ran != 1 {
			t.Fatalf("%s: full lane err=%v ran=%d", label, err, ran)
		}
	}
	// One caller grant encloses the whole no-write Update, including both OLD-abort probes.
	var held error
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() {
		held = w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error {
			_, _, updateErr := w.store.Update(qualify(sentinel))
			return updateErr
		})
	})
	if err != nil || !errors.Is(held, sentinel) || evidence.Probes != 2 || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 {
		t.Fatalf("held grant: %v/%v %+v", err, held, evidence)
	}
	fullLane("after return")
	application := errors.New("application")
	if err := w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		_, _, _ = w.store.Update(qualify(sentinel))
		return application
	}); !errors.Is(err, application) {
		t.Fatalf("error unwind: %v", err)
	}
	fullLane("after error")
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic unwind did not panic")
			}
		}()
		_ = w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error {
			_, _, _ = w.store.Update(qualify(sentinel))
			panic("unwind")
		})
	}()
	fullLane("after panic")
	w.wantImage("after reservation adapter")
}
