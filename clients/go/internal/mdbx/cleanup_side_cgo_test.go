//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"math"
	"slices"
	"testing"
)

func sideAuthority(first, last uint64) StorageAuthorityV1 {
	a := modelBase(1, 0, 0)
	a.NextGenerationID, a.Phase = 3, StoragePhaseV1(2)
	a.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 4, GenerationID: 2, FirstHeight: first, LastHeight: last, NextHeight: first}}}
	return a
}

func sideRows(generation, height uint64) ([32]byte, []byte, []Mutation) {
	header := make([]byte, 116)
	binary.LittleEndian.PutUint32(header, uint32(height))
	binary.BigEndian.PutUint64(header[36:44], generation)
	hash := sha3.Sum256(header)
	body := append(bytes.Clone(header), 0)
	key, _ := HeightKey(generation, height)
	return hash, body, []Mutation{
		{DBI: readDBIsLiteral()[4], Key: hash[:], AfterKind: AfterKind(2), Literal: body},
		{DBI: readDBIsLiteral()[6], Key: key, AfterKind: AfterKind(2), Literal: ChainValue(hash, [32]byte{}, [40]byte{39: 1})},
	}
}

func sideStore(t *testing.T, a StorageAuthorityV1, rows ...Mutation) (*Store, string) {
	t.Helper()
	s, path, _ := consultedStore(t)
	encoded, err := a.Encode()
	mustEnvironment(t, err)
	rows = slices.Clone(rows)
	rows = append(rows, Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, AfterKind: AfterKind(2), Literal: encoded})
	slices.SortFunc(rows, func(x, y Mutation) int {
		if x.DBI.Rank != y.DBI.Rank {
			return int(x.DBI.Rank) - int(y.DBI.Rank)
		}
		return bytes.Compare(x.Key, y.Key)
	})
	consultedRequireCommit(t, s, "SIDE fixture seed", Batch{Mutations: rows})
	return s, path
}

func sideTuple(t *testing.T, truth CommitTruth, stage UpdateStage, err error, want CommitTruth) {
	t.Helper()
	wantStage := UpdateStage(1)
	if want == CommitTruth(2) {
		wantStage = 3
	}
	if truth != want || stage != wantStage || err != nil {
		t.Fatalf("SIDE tuple: got %s/%d/%v, want %s/%d/nil", truth, stage, err, want, wantStage)
	}
}

func sideRun(t *testing.T, s *Store, want CommitTruth) {
	t.Helper()
	owner := bootstrapOwner(t)
	truth, stage, err := s.CleanupSideV1(owner)
	sideTuple(t, truth, stage, err, want)
	prunedReleased(t, owner)
}

func sideImage(t *testing.T, s *Store, generation, height uint64, bodyPresent, linkPresent bool) {
	t.Helper()
	hash, body, rows := sideRows(generation, height)
	if !bodyPresent {
		body = nil
	}
	link := rows[1].Literal
	if !linkPresent {
		link = nil
	}
	consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], body, bodyPresent, "SIDE body disposition")
	consultedRequireImage(t, s, readDBIsLiteral()[6], rows[1].Key, link, linkPresent, "SIDE link disposition")
}

func sideSelected(t *testing.T, first, last uint64) (StorageAuthorityV1, []Mutation) {
	t.Helper()
	a := sideAuthority(first-1, first-1)
	rows := make([]Mutation, 0, 2880)
	for h := first - 1; h <= last; h++ {
		hash, _, pair := sideRows(2, h)
		rows = append(rows, pair...)
		if h == last {
			a.SelectedSide = &SelectedSideV1{GenerationID: 2, F: first - 2, TipHeight: last, TipHash: hash, CumulativeChainwork: [40]byte{39: 1}, RowCount: 1439, LogicalBytes: 1439 * 117}
		}
	}
	return a, rows
}

func TestCleanupSideV1(t *testing.T) {
	t.Run("P09-A1", func(t *testing.T) {
		a, rows := sideSelected(t, 2, 1440)
		a.SelectedSide.F = 0
		s, _ := sideStore(t, a, rows...)
		sideRun(t, s, CommitTruth(2))
		a.Cleanup, a.Phase = nil, StoragePhaseV1(1)
		cleanupWantAuthority(t, s, a)
		sideImage(t, s, 2, 1, false, false)
		for h := uint64(2); h <= 1440; h++ {
			sideImage(t, s, 2, h, true, true)
		}
	})
	t.Run("P09-A2", func(t *testing.T) {
		a := sideAuthority(5, 9)
		var rows []Mutation
		for h := uint64(5); h <= 9; h++ {
			_, _, pair := sideRows(2, h)
			rows = append(rows, pair...)
		}
		s, path := sideStore(t, a, rows...)
		input, _ := a.Encode()
		sideRun(t, s, CommitTruth(2))
		if got, _ := a.Encode(); !bytes.Equal(got, input) {
			t.Fatal("SIDE mutated caller authority alias")
		}
		a.Cleanup.Spans[0].NextHeight = 6
		cleanupWantAuthority(t, s, a)
		sideImage(t, s, 2, 5, false, false)
		for h := uint64(6); h <= 9; h++ {
			sideImage(t, s, 2, h, true, true)
		}
		for h := uint64(6); h <= 9; h++ {
			sideRun(t, s, CommitTruth(2))
			sideImage(t, s, 2, h, false, false)
			if h == 9 {
				a.Cleanup, a.Phase = nil, 1
			} else {
				a.Cleanup.Spans[0].NextHeight = h + 1
			}
			cleanupWantAuthority(t, s, a)
		}
		a.Cleanup, a.Phase = nil, StoragePhaseV1(1)
		cleanupWantAuthority(t, s, a)
		cfg := s.config
		mustEnvironment(t, s.Close())
		reopened, err := Open(path, cfg)
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, reopened.Close()) }()
		cleanupWantAuthority(t, reopened, a)
		sideRun(t, reopened, CommitTruth(1))
	})
	t.Run("P09-A3a", func(t *testing.T) {
		a := sideAuthority(5, 5)
		pending := StorageProfileV1(1)
		a.Lifecycle, a.PendingTargetProfile, a.NextGenerationID = 2, &pending, math.MaxUint64
		a.ExcludedInvalidBranch = &InvalidBranchV1{FirstInvalidHeight: 1, FirstInvalidBlockHash: modelHash(9), ExactConsensusError: []byte("invalid")}
		_, _, rows := sideRows(2, 5)
		s, _ := sideStore(t, a, rows...)
		sideRun(t, s, CommitTruth(2))
		a.Phase, a.Cleanup = 1, nil
		cleanupWantAuthority(t, s, a)
		sideImage(t, s, 2, 5, false, false)
	})
	t.Run("P09-A3b", func(t *testing.T) {
		a := sideAuthority(10, 20)
		pending := StorageProfileV1(2)
		a.B, a.U, a.Lifecycle, a.PendingTargetProfile = 1, 13681, 2, &pending
		var rows []Mutation
		for h := uint64(10); h <= 20; h++ {
			_, _, pair := sideRows(2, h)
			rows = append(rows, pair...)
		}
		s, _ := sideStore(t, a, rows...)
		for h := uint64(10); h <= 20; h++ {
			sideRun(t, s, CommitTruth(2))
			sideImage(t, s, 2, h, false, false)
		}
		a.Phase, a.Cleanup = 1, nil
		cleanupWantAuthority(t, s, a)
	})
	for _, row := range []struct {
		name    string
		heights []uint64
	}{{"P09-A4", []uint64{11}}, {"P09-A5", []uint64{9}}, {"H5", []uint64{9, 11}}} {
		t.Run(row.name, func(t *testing.T) {
			for _, k := range row.heights {
				a := sideAuthority(5, 5)
				a.B, a.U = 10, 13690
				hash, body, rows := sideRows(2, 5)
				key, _ := HeightKey(1, k)
				rows = append(rows, Mutation{DBI: readDBIsLiteral()[2], Key: key, AfterKind: 2, Literal: ChainValue(hash, [32]byte{}, [40]byte{39: 1})}, canonicalOwnerLiteral(1, k, hash))
				s, _ := sideStore(t, a, rows...)
				sideRun(t, s, CommitTruth(2))
				keep := k == 11
				if !keep {
					body = nil
				}
				consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], body, keep, "actual-k canonical body")
				consultedRequireImage(t, s, readDBIsLiteral()[2], key, rows[2].Literal, true, "canonical forward proof changed")
				consultedRequireImage(t, s, readDBIsLiteral()[7], rows[3].Key, rows[3].Literal, true, "canonical inverse proof changed")
				a.Phase, a.Cleanup = 1, nil
				cleanupWantAuthority(t, s, a)
				sideImage(t, s, 2, 5, keep, false)
			}
		})
	}
	t.Run("P09-A6", func(t *testing.T) {
		a := sideAuthority(5, 5)
		hash, body, rows := sideRows(2, 5)
		undo := UndoManifestValue(5, [16]byte{}, 1, 0)
		rows = append(rows, Mutation{DBI: readDBIsLiteral()[3], Key: hash[:], AfterKind: 2, Literal: body[:116]}, Mutation{DBI: readDBIsLiteral()[5], Key: UndoManifestKey(hash), AfterKind: 2, Literal: undo})
		s, _ := sideStore(t, a, rows...)
		sideRun(t, s, CommitTruth(2))
		sideImage(t, s, 2, 5, false, false)
		consultedRequireImage(t, s, readDBIsLiteral()[3], hash[:], body[:116], true, "SIDE deleted stray header")
		consultedRequireImage(t, s, readDBIsLiteral()[5], UndoManifestKey(hash), undo, true, "SIDE deleted undo")
		a.Phase, a.Cleanup = 1, nil
		cleanupWantAuthority(t, s, a)
	})
	t.Run("P09-A7", func(t *testing.T) {
		a, rows := sideSelected(t, 2, 1440)
		x, body, _ := sideRows(2, 1)
		rows[3].Literal = ChainValue(x, [32]byte{}, [40]byte{39: 1})
		s, _ := sideStore(t, a, rows...)
		sideRun(t, s, CommitTruth(2))
		consultedRequireImage(t, s, readDBIsLiteral()[4], x[:], body, true, "selected j!=h keep")
		consultedRequireImage(t, s, readDBIsLiteral()[6], rows[1].Key, nil, false, "owed link remained")
		for _, row := range rows[2:] {
			consultedRequireImage(t, s, row.DBI, row.Key, row.Literal, true, "selected image changed")
		}
		a.Phase, a.Cleanup = 1, nil
		cleanupWantAuthority(t, s, a)
	})
	t.Run("P09-A8", func(t *testing.T) {
		a := sideAuthority(5, 5)
		_, _, rows := sideRows(2, 5)
		s, _ := sideStore(t, a, rows[1])
		sideRun(t, s, CommitTruth(2))
		sideImage(t, s, 2, 5, false, false)
		a.Phase, a.Cleanup = 1, nil
		cleanupWantAuthority(t, s, a)
	})
	for _, row := range sideRouteCases() {
		t.Run(row.name, func(t *testing.T) {
			_, _, rows := sideRows(2, 5)
			s, _ := sideStore(t, row.a, rows...)
			sideRun(t, s, CommitTruth(1))
			cleanupWantAuthority(t, s, row.a)
			sideImage(t, s, 2, 5, true, true)
		})
	}
	t.Run("R6a", func(t *testing.T) {
		a := sideAuthority(5, 5)
		_, _, rows := sideRows(2, 5)
		s, _ := sideStore(t, a, rows...)
		owner := bootstrapOwner(t)
		mustEnvironment(t, owner.WithReservation(1, func() error {
			truth, stage, err := s.CleanupSideV1(owner)
			if truth != CommitTruth(1) || stage != 1 || !sameError(err, errOperationReservationCapacity) {
				t.Fatalf("SIDE Q-1 refusal: %s/%d/%v", truth, stage, err)
			}
			if owner.shared.live != 1 {
				t.Fatal("SIDE capacity changed the pre-call charge")
			}
			return nil
		}))
		prunedReleased(t, owner)
		cleanupWantAuthority(t, s, a)
		sideImage(t, s, 2, 5, true, true)
		truth, stage, err := s.CleanupSideV1(owner)
		sideTuple(t, truth, stage, err, CommitTruth(2))
		prunedReleased(t, owner)
	})
	t.Run("API", func(t *testing.T) {
		truth, stage, err := (*Store)(nil).CleanupSideV1(bootstrapOwner(t))
		if truth != CommitTruth(1) || stage != 1 {
			t.Fatalf("SIDE nil Store tuple: %s/%d/%v", truth, stage, err)
		}
		requireEnvironmentError(t, err, EngineClass("InvalidInput"), operationUpdate, 22, "nil Store")
		a := sideAuthority(5, 5)
		_, _, rows := sideRows(2, 5)
		s, _ := sideStore(t, a, rows...)
		for _, owner := range []*OperationReservationOwner{nil, {}} {
			truth, stage, err = s.CleanupSideV1(owner)
			if truth != CommitTruth(1) || stage != 1 || !sameError(err, errOperationReservationInput) {
				t.Fatalf("SIDE nil/zero owner tuple: %s/%d/%v", truth, stage, err)
			}
		}
		cleanupWantAuthority(t, s, a)
		sideImage(t, s, 2, 5, true, true)
	})
	t.Run("R18d", sideOpenRefusal)
	t.Run("ownership", func(t *testing.T) {
		a := sideAuthority(5, 6)
		want, _ := a.Encode()
		_, body, rows := sideRows(2, 5)
		before := bytes.Clone(body)
		s, _ := sideStore(t, a, rows...)
		sideRun(t, s, CommitTruth(2))
		got, _ := a.Encode()
		if !bytes.Equal(got, want) || !bytes.Equal(body, before) {
			t.Fatal("SIDE caller alias changed")
		}
	})
}

func sideRouteCases() []authorityCase {
	noneRecovery := modelBase(1, 0, 0)
	profile := StorageProfileV1(1)
	noneRecovery.Lifecycle, noneRecovery.PendingTargetProfile = 2, &profile
	noneArchive := modelBase(1, 0, 0)
	archive := StorageProfileV1(2)
	noneArchive.Lifecycle, noneArchive.PendingTargetProfile = 2, &archive
	detached := sideAuthority(5, 5)
	detached.DetachedSuffix = modelDetached(1, 117)
	undo := sideAuthority(5, 5)
	undo.U = 10
	undo.Cleanup.Spans = append([]CleanupSpanV1{{Kind: 3, GenerationID: 1, FirstHeight: 0, LastHeight: 9, NextHeight: 0}}, undo.Cleanup.Spans...)
	blocks := cleanupAuthority(2, 0, false)
	generation := sideAuthority(5, 5)
	generation.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 1, GenerationID: 2}}}
	ordinary := modelOrdinary(2, 1, 2, 15120, 1, 1, 13681)
	carried := modelOrdinary(2, 1, 2, 15120, 1, 1, 13681)
	carried.Ordinary.CarriedCleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 4, GenerationID: 2, FirstHeight: 3, LastHeight: 3, NextHeight: 3}}}
	return []authorityCase{{"X1/NONE-STABLE", modelBase(1, 0, 0)}, {"X1/NONE-RECOVERY_REQUIRED-PRUNED", noneRecovery}, {"X1/NONE-RECOVERY_REQUIRED-ARCHIVE", noneArchive}, {"X1/GENERATION", generation}, {"X1/BLOCKS", blocks}, {"X1/UNDO", undo}, {"X1/REPLAY", modelReplay(1)}, {"X1/ORDINARY_APPLY", ordinary}, {"R2", detached}, {"R3", undo}, {"R17a", carried}}
}

func sideOpenRefusal(t *testing.T) {
	a := sideAuthority(5, 9)
	_, _, rows := sideRows(2, 5)
	_, _, next := sideRows(2, 6)
	s, path := sideStore(t, a, append(rows, next...)...)
	sideRun(t, s, CommitTruth(2))
	a.Cleanup.Spans[0].NextHeight = 6
	cfg := s.config
	mustEnvironment(t, s.Close())
	reopened, err := Open(path, cfg)
	mustEnvironment(t, err)
	defer func() { mustEnvironment(t, reopened.Close()) }()
	cleanupWantAuthority(t, reopened, a)
	owner := bootstrapOwner(t)
	truth, stage, err := reopened.CleanupSideV1(owner)
	if truth != CommitTruth(1) || stage != 1 {
		t.Fatalf("unverified Open tuple: %s/%d/%v", truth, stage, err)
	}
	requireEnvironmentError(t, err, EngineInvalidInput, operationGet, 22, "canonical owner index is not verified")
	prunedReleased(t, owner)
	cleanupWantAuthority(t, reopened, a)
	sideImage(t, reopened, 2, 6, true, true)
}

func TestCleanupSideV1NoCallback(t *testing.T) {
	a := sideAuthority(5, 5)
	_, _, rows := sideRows(2, 5)
	s, _ := sideStore(t, a, rows[0])
	truth, stage, err := s.CleanupSideV1(bootstrapOwner(t))
	if truth != CommitTruth(1) || stage != 1 || err == nil {
		t.Fatalf("missing link tuple: %s/%d/%v", truth, stage, err)
	}
	again, nextStage, got := s.CleanupSideV1(bootstrapOwner(t))
	if again != truth || nextStage != stage || !sameError(got, err) {
		t.Fatalf("cached tuple changed: %s/%d/%v", again, nextStage, got)
	}
}
