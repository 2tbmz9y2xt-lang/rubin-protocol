//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Each body is independently derived from the published genesis fixture. The
// descriptor is descending; the active canonical F row is never a drain target.
func detachedFixture(t *testing.T, count int) (mdbx.StorageAuthorityV1, []mdbx.Mutation) {
	t.Helper()
	a := generationAuthority()
	parent := [32]byte{0xf0}
	rows := generationCanonical(parent, 9)
	entries := make([]mdbx.DetachedSuffixEntryV1, count)
	for i := 0; i < count; i++ {
		body := sideWorldBlock(parent, uint64(100+i))
		logicalMDBXAssert(t, len(body) == 266, "published fixture body width: %d", len(body))
		hash := sha3_256(body[:116])
		entries[count-1-i] = mdbx.DetachedSuffixEntryV1{Height: uint64(10+i), Hash: hash, BlockBytesLen: 266}
		rows = append(rows, generationRow(3, bytes.Clone(hash[:]), bytes.Clone(body[:116])), generationRow(4, bytes.Clone(hash[:]), body))
		parent = hash
	}
	a.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: entries, Cursor: mdbx.AuthorityPointV1{Height: entries[0].Height, BlockHash: entries[0].Hash}, EntryCount: uint16(count), LogicalBytes: uint64(count) * 266}
	return a, rows
}

func detachedAfter(a mdbx.StorageAuthorityV1, count uint16, sum uint64) mdbx.StorageAuthorityV1 {
	d := a.DetachedSuffix
	a.DetachedSuffix = nil
	if count != 0 {
		e := d.Entries[1]
		a.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: slices.Clone(d.Entries[1:]), Cursor: mdbx.AuthorityPointV1{Height: e.Height, BlockHash: e.Hash}, EntryCount: count, LogicalBytes: sum}
	}
	return a
}

func detachedRun(t *testing.T, w *generationWorld) selectedSideOutcome {
	t.Helper()
	out := DrainDetachedMDBX(w.s, w.owner)
	sideWantReleased(t, w.owner, "detached")
	return out
}

func detachedCommitted(t *testing.T, out selectedSideOutcome, damage bool) {
	t.Helper()
	result, canonical := "", "NEW"
	if damage {
		result, canonical = "LOCAL_STORE_ERROR(noncanonical)", "NOT_APPLICABLE"
	}
	sideWantOutcome(t, out, result, canonical, 2, 3, "detached commit")
	logicalMDBXAssert(t, out.Err == nil, "normally committed raw error: %v", out.Err)
}

func detachedGone(rows []mdbx.Mutation) []mdbx.Mutation {
	want := slices.Clone(rows)
	want[len(want)-2].Literal, want[len(want)-1].Literal = nil, nil
	return want
}

func TestDrainDetachedMDBX(t *testing.T) {
	t.Run("P11-A1a", func(t *testing.T) {
		a, rows := detachedFixture(t, 3)
		w := generationNew(t, a, rows...)
		detachedCommitted(t, detachedRun(t, w), false)
		w.image(detachedAfter(a, 2, 532), detachedGone(rows)...)
	})
	t.Run("P11-A1b", func(t *testing.T) {
		// The ordinary mutation selector owns recorded arithmetic independently
		// of physical length. The tagged A1b additionally proves actual short bytes.
		a, rows := detachedFixture(t, 2)
		a.DetachedSuffix.Entries[0].Height, a.DetachedSuffix.Entries[1].Height, a.DetachedSuffix.Cursor.Height = 12, 11, 12
		a.DetachedSuffix.Entries[0].BlockBytesLen, a.DetachedSuffix.Entries[1].BlockBytesLen, a.DetachedSuffix.LogicalBytes = 100, 50, 150
		w := generationNew(t, a, rows...)
		detachedCommitted(t, detachedRun(t, w), true)
		w.image(detachedAfter(a, 1, 50), detachedGone(rows)...)
	})
	for _, name := range []string{"P11-A2a", "P11-A2b"} {
		t.Run(name, func(t *testing.T) {
			a, rows := detachedFixture(t, 1)
			if name == "P11-A2b" {
				pending := mdbx.StorageProfileV1(1)
				a.Lifecycle, a.PendingTargetProfile, a.NextGenerationID = 2, &pending, ^uint64(0)
				a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 7, FirstInvalidBlockHash: [32]byte{7}, ExactConsensusError: []byte{9}}
			}
			w := generationNew(t, a, rows...)
			detachedCommitted(t, detachedRun(t, w), false)
			want := detachedAfter(a, 0, 0)
			w.image(want, detachedGone(rows)...)
			generationClean(t, detachedRun(t, w), 1)
			w.image(want, detachedGone(rows)...)
		})
	}
	for _, name := range []string{"P11-A3a", "P11-A3c", "P11-A3d", "P11-A3j", "P11-A3e", "P11-A3g", "P11-A3h", "P11-A3i"} {
		t.Run(name, func(t *testing.T) { detachedDamage(t, name) })
	}
	t.Run("P11-A4", func(t *testing.T) { detachedSide(t, true) })
	t.Run("H8", func(t *testing.T) { detachedSide(t, false) })
	t.Run("P11-A6", detachedCanonicalKeeps)
	t.Run("P11-A5", detachedContinuation)
	t.Run("P11-A8", detachedGenesis)
	t.Run("X1", detachedRoutes)
	t.Run("X3", detachedCapacity)
	t.Run("boundaries", detachedBoundaries)
	t.Run("R5", func(t *testing.T) {
		w := generationNew(t, generationAuthority(), generationData(2, 1)...)
		generationClean(t, detachedRun(t, w), 1)
		w.image(w.a, w.rows...)
	})
	t.Run("R18b", func(t *testing.T) {
		// The strict codec excludes SelectedSide+DetachedSuffix; there is no
		// eligible selected consumer path in an admitted detached invocation.
		a, _ := detachedFixture(t, 1)
		a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 9, TipHeight: 10, TipHash: [32]byte{3}, CumulativeChainwork: sideWorldWork(1), RowCount: 1, LogicalBytes: 266}
		_, err := a.Encode()
		logicalMDBXAssert(t, err != nil, "illegal selected+detached owner encoded")
	})
}

func detachedDamage(t *testing.T, name string) {
	count := 2
	if name == "P11-A3j" {
		count = 1
	}
	a, rows := detachedFixture(t, count)
	header, body := len(rows)-2, len(rows)-1
	switch name {
	case "P11-A3a":
		remnant := rows[body]
		rows = rows[:header+1]
		rows[header] = remnant
	case "P11-A3c":
		rows[header].Literal = make([]byte, 116)
	case "P11-A3d", "P11-A3j":
		value := sideWorldBlock([32]byte{0xb0}, 999)
		hash := sha3_256(value[:116])
		a.DetachedSuffix.Entries[0].Hash, a.DetachedSuffix.Cursor.BlockHash = hash, hash
		rows[header], rows[body] = generationRow(3, bytes.Clone(hash[:]), bytes.Clone(value[:116])), generationRow(4, bytes.Clone(hash[:]), value)
	case "P11-A3e":
		rows = rows[:body]
	case "P11-A3g":
		a.DetachedSuffix.Entries[0].BlockBytesLen = 267
		a.DetachedSuffix.LogicalBytes++
	case "P11-A3h":
		rows[body].Literal = bytes.Clone(rows[body].Literal)
		rows[body].Literal[108] ^= 1
	case "P11-A3i":
		rows[body].Literal = append(bytes.Clone(rows[body].Literal), 0)
		a.DetachedSuffix.Entries[0].BlockBytesLen = 267
		a.DetachedSuffix.LogicalBytes++
	}
	w := generationNew(t, a, rows...)
	detachedCommitted(t, detachedRun(t, w), true)
	want := slices.Clone(rows)
	hash := a.DetachedSuffix.Entries[0].Hash
	for i := range want {
		if want[i].DBI.Rank >= 3 && bytes.Equal(want[i].Key, hash[:]) {
			want[i].Literal = nil
		}
	}
	if count == 1 {
		w.image(detachedAfter(a, 0, 0), want...)
	} else {
		w.image(detachedAfter(a, 1, 266), want...)
	}
	// Assert both remnant absences even when the pre-state lacked one.
	w.image(detachedAfter(a, uint16(count-1), uint64(count-1)*266), generationRow(3, hash[:], nil), generationRow(4, hash[:], nil))
}

func detachedSide(t *testing.T, differentHeight bool) {
	a, rows := detachedFixture(t, 2)
	hash := a.DetachedSuffix.Entries[0].Hash
	height := uint64(11)
	if differentHeight {
		height = 7
	}
	a.Cleanup.Spans = []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, FirstHeight: height, LastHeight: height, NextHeight: height}}
	key, _ := mdbx.HeightKey(3, height)
	rows = append(rows, generationRow(6, key, mdbx.ChainValue(hash, [32]byte{9}, sideWorldWork(1))))
	w := generationNew(t, a, rows...)
	detachedCommitted(t, detachedRun(t, w), false)
	want := slices.Clone(rows)
	want[len(want)-3].Literal = nil
	w.image(detachedAfter(a, 1, 266), want...)
}

func detachedCanonicalKeeps(t *testing.T) {
	for _, k := range []uint64{8, 10, 11, 19} {
		for _, deferBody := range []bool{false, true} {
			t.Run(fmt.Sprintf("k%d-defer%t", k, deferBody), func(t *testing.T) {
				a, rows := detachedFixture(t, 2)
				a.B, a.U = 10, 13690
				e := a.DetachedSuffix.Entries[0]
				parent := a.DetachedSuffix.Entries[1].Hash
				key, _ := mdbx.HeightKey(1, k)
				inverse, _ := mdbx.CanonicalOwnerKey(1, e.Hash)
				rows = append(rows, generationRow(2, key, mdbx.ChainValue(e.Hash, parent, sideWorldWork(1))), generationRow(7, inverse, mdbx.CanonicalOwnerValue(k)))
				if deferBody {
					a.Cleanup.Spans = []mdbx.CleanupSpanV1{{Kind: 2, GenerationID: 1, LastHeight: 9, NextHeight: 8}}
				}
				w := generationNew(t, a, rows...)
				detachedCommitted(t, detachedRun(t, w), false)
				want := slices.Clone(rows)
				if k < 10 && !deferBody {
					want[5].Literal = nil
				}
				w.image(detachedAfter(a, 1, 266), want...)
			})
		}
	}
}

func detachedContinuation(t *testing.T) {
	a, rows := detachedFixture(t, 3)
	w := generationNew(t, a, rows...)
	want := slices.Clone(rows)
	for _, count := range []uint16{2, 1, 0} {
		detachedCommitted(t, detachedRun(t, w), false)
		want[2+int(count)*2].Literal, want[3+int(count)*2].Literal = nil, nil
		a = detachedAfter(a, count, uint64(count)*266)
		w.image(a, want...)
	}
	logicalMDBXAssert(t, w.s.Close() == nil, "close actual drained database")
	var err error
	w.s, err = mdbx.Open(w.path, w.cfg)
	logicalMDBXAssert(t, err == nil, "Open actual drained database: %v", err)
	w.image(a, want...)
	// Open -> strict startup verification -> continuation is PENDING RUB-1513/
	// RUB-1502. This proves persistence, never gives Open a verified-owner bit.
}

func detachedGenesis(t *testing.T) {
	store, owner, _ := genesisMDBXBoot(t, 1)
	genesisMDBXReturned(t, genesisMDBXRun(store, owner), "ACCEPTED", 2, 3, "published genesis")
	body, _, hash := genesisMDBXFixture()
	a := generationAuthority()
	a.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: []mdbx.DetachedSuffixEntryV1{{Height: 0, Hash: hash, BlockBytesLen: 266}}, Cursor: mdbx.AuthorityPointV1{Height: 0, BlockHash: hash}, EntryCount: 1, LogicalBytes: 266}
	logicalMDBXAssert(t, len(body) == 266, "published genesis recorded length")
	encoded, err := a.Encode()
	logicalMDBXAssert(t, err == nil, "genesis detached authority: %v", err)
	logicalMDBXSeed(t, store, mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: 2, Literal: encoded})
	before := genesisMDBXSnapshot(t, store, 1)
	detachedCommitted(t, DrainDetachedMDBX(store, owner), false)
	sideWantReleased(t, owner, "genesis detached")
	a.DetachedSuffix = nil
	encoded, err = a.Encode()
	logicalMDBXAssert(t, err == nil, "genesis detached successor: %v", err)
	for i := range before {
		if bytes.Equal(before[i].Key, []byte{0, 2}) {
			before[i].Value = bytes.Clone(encoded)
		}
	}
	genesisMDBXExpected(t, store, 1, encoded, "canonical genesis retained")
	logicalMDBXAssert(t, reflect.DeepEqual(before, genesisMDBXSnapshot(t, store, 1)), "genesis canonical/logical image changed")
	generationClean(t, DrainDetachedMDBX(store, owner), 1)
	sideWantReleased(t, owner, "genesis no-work")
	genesisMDBXExpected(t, store, 1, encoded, "genesis no-work canonical owner retained")
	logicalMDBXAssert(t, reflect.DeepEqual(before, genesisMDBXSnapshot(t, store, 1)), "genesis no-work image changed")
}

func detachedRoutes(t *testing.T) {
	for _, row := range generationRouteAuthorities() {
		if row.name == "descriptor" {
			continue // P11-A1a is the real descriptor work branch.
		}
		t.Run(row.name, func(t *testing.T) {
			w := generationNew(t, row.a, generationData(2, 1)...)
			generationClean(t, detachedRun(t, w), 1)
			w.image(row.a, w.rows...)
		})
	}
	t.Run("GENERATION", func(t *testing.T) {
		w := generationNew(t, generationAuthority(), generationData(2, 1)...)
		generationClean(t, detachedRun(t, w), 1)
		w.image(w.a, w.rows...)
	})
}

func detachedCapacity(t *testing.T) {
	for _, work := range []bool{false, true} {
		t.Run(fmt.Sprint(work), func(t *testing.T) {
			a, rows := detachedFixture(t, 2)
			if !work {
				a.DetachedSuffix = nil
			}
			w := generationNew(t, a, rows...)
			var refused error
			logicalMDBXAssert(t, w.owner.WithReservation(1, func() error {
				refused = w.owner.WithReservation(154611151, func() error {
					t.Fatal("denied grant ran")
					return nil
				})
				copied := *w.owner
				out := DrainDetachedMDBX(w.s, &copied)
				result := ""
				if work {
					result = "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"
					logicalMDBXAssert(t, any(out.Err) == any(refused), "capacity error identity replaced")
				} else {
					logicalMDBXAssert(t, out.Err == nil, "denied no-work: %v", out.Err)
				}
				sideWantOutcome(t, out, result, "OLD", 1, 1, "capacity")
				w.image(a, rows...)
				return nil
			}) == nil, "outer grant")
			sideWantReleased(t, w.owner, "capacity")
		})
	}
	for _, owner := range []*mdbx.OperationReservationOwner{nil, {}} {
		a, rows := detachedFixture(t, 2)
		w := generationNew(t, a, rows...)
		out := DrainDetachedMDBX(w.s, owner)
		sideWantOutcome(t, out, "", "", 1, 1, "owner input")
		logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "invalid storage operation reservation input", "owner input: %v", out.Err)
		w.image(a, rows...)
	}
	out := DrainDetachedMDBX(nil, nil)
	sideWantOutcome(t, out, "", "", 1, 1, "nil Store")
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, errors.As(out.Err, &engine) && string(engine.Class) == "InvalidInput" && engine.Operation == "update" && engine.Code == 22 && engine.Diagnostic == "nil Store", "nil Store before grant: %v", out.Err)
}

func TestDrainDetachedProjectionIdentity(t *testing.T) {
	noWork := errors.New("own no work")
	p := &detachedDrainPlan{cleanupGenerationPlan: cleanupGenerationPlan{noWork: noWork}}
	var typedNil *mdbx.EngineError
	for _, row := range []struct {
		name   string
		err    error
		stage  mdbx.UpdateStage
		result string
	}{
		{"direct", noWork, 1, ""},
		{"wrapped", fmt.Errorf("wrapped: %w", noWork), 1, "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{"joined", errors.Join(noWork, errors.New("second")), 1, "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{"typed-nil", typedNil, 1, "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{"write-started", noWork, 2, "LOCAL_PERSISTENCE_ERROR(precommit)"},
	} {
		t.Run(row.name, func(t *testing.T) {
			out := p.project(selectedSideOutcome{Truth: 1, Stage: row.stage, Err: row.err})
			sideWantOutcome(t, out, row.result, "OLD", 1, row.stage, row.name)
			want := row.err
			if row.name == "direct" {
				want = nil
			}
			logicalMDBXAssert(t, any(out.Err) == any(want), "sentinel/cause identity changed")
		})
	}
}

func detachedBoundaries(t *testing.T) {
	for _, count := range []int{1, 1440} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, rows := detachedFixture(t, count)
			w := generationNew(t, a, rows...)
			detachedCommitted(t, detachedRun(t, w), false)
			w.image(detachedAfter(a, uint16(count-1), uint64(count-1)*266), detachedGone(rows)...)
		})
	}
	t.Run("height-ffffffff", func(t *testing.T) {
		a, rows := detachedFixture(t, 2)
		a.DetachedSuffix.Entries[0].Height, a.DetachedSuffix.Entries[1].Height, a.DetachedSuffix.Cursor.Height = 0xffffffff, 0xfffffffe, 0xffffffff
		w := generationNew(t, a, rows...)
		detachedCommitted(t, detachedRun(t, w), false)
		w.image(detachedAfter(a, 1, 266), detachedGone(rows)...)
	})
}
