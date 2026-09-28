//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"slices"
	"testing"
)

func cleanupAuthority(kind CleanupSpanKindV1, height uint64, recovery bool) StorageAuthorityV1 {
	a := modelBase(1, 0, 1)
	if kind == CleanupSpanBlocksV1 {
		a.B, a.U = height+1, height+13681
	}
	a.ActiveGenerationID, a.NextGenerationID = 7, 9
	a.Phase = StoragePhasePruneGCV1
	a.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: kind, GenerationID: 7, FirstHeight: height, LastHeight: height, NextHeight: height}}}
	if recovery {
		pending := StorageProfileArchiveV1
		a.Lifecycle, a.PendingTargetProfile = StorageLifecycleRecoveryRequiredV1, &pending
	}
	return a
}

func cleanupTestStore(t *testing.T, a StorageAuthorityV1, height uint64, spent int) (*Store, string, [32]byte, []byte) {
	t.Helper()
	s, path, _ := consultedStore(t)
	dbis := readDBIsLiteral()
	encoded, err := a.Encode()
	mustEnvironment(t, err)
	rows := []Mutation{{DBI: dbis[0], Key: []byte{2}, AfterKind: AfterLiteral, Literal: encoded}}
	utxoKey, keyErr := UTXOKey(7, modelHash(42), 0)
	mustEnvironment(t, keyErr)
	utxoValue, valueErr := (UTXOValue{Value: 7}).Encode()
	mustEnvironment(t, valueErr)
	rows = append(rows, Mutation{DBI: dbis[1], Key: utxoKey, AfterKind: AfterLiteral, Literal: utxoValue})
	header := make([]byte, 116)
	work := [40]byte{39: 1}
	if height > 0 {
		previous := make([]byte, 116)
		previousHash := sha3.Sum256(previous)
		copy(header[4:36], previousHash[:])
		previousKey, keyErr := HeightKey(7, height-1)
		mustEnvironment(t, keyErr)
		rows = append(rows, Mutation{DBI: dbis[2], Key: previousKey, AfterKind: AfterLiteral, Literal: ChainValue(previousHash, [32]byte{}, work)})
		work[39] = 2
	}
	hash := sha3.Sum256(header)
	key, err := HeightKey(7, height)
	mustEnvironment(t, err)
	rows = append(rows,
		Mutation{DBI: dbis[2], Key: key, AfterKind: AfterLiteral, Literal: ChainValue(hash, [32]byte(header[4:36]), work)},
		Mutation{DBI: dbis[3], Key: hash[:], AfterKind: AfterLiteral, Literal: header})
	body := append(bytes.Clone(header), 0)
	otherHeader := make([]byte, 116)
	otherHeader[0] = 1
	otherHash := sha3.Sum256(otherHeader)
	rows = append(rows,
		Mutation{DBI: dbis[3], Key: otherHash[:], AfterKind: AfterLiteral, Literal: otherHeader},
		Mutation{DBI: dbis[4], Key: otherHash[:], AfterKind: AfterLiteral, Literal: append(bytes.Clone(otherHeader), 0)})
	manifest := UndoManifestValue(height, [16]byte{}, 1, uint32(spent))
	if a.Cleanup != nil && a.Cleanup.Spans[0].Kind == CleanupSpanBlocksV1 {
		rows = append(rows, Mutation{DBI: dbis[4], Key: hash[:], AfterKind: AfterLiteral, Literal: body})
	} else if a.Cleanup != nil && a.Cleanup.Spans[0].Kind == CleanupSpanUndoV1 {
		rows = append(rows,
			Mutation{DBI: dbis[4], Key: hash[:], AfterKind: AfterLiteral, Literal: body},
			Mutation{DBI: dbis[5], Key: UndoManifestKey(hash), AfterKind: AfterLiteral, Literal: manifest})
	}
	slices.SortFunc(rows, func(x, y Mutation) int {
		if x.DBI.Rank != y.DBI.Rank {
			return int(x.DBI.Rank) - int(y.DBI.Rank)
		}
		return bytes.Compare(x.Key, y.Key)
	})
	consultedRequireCommit(t, s, "cleanup seed", Batch{Mutations: rows})
	if spent > 0 {
		entry, entryErr := (UTXOValue{Value: 1}).Encode()
		mustEnvironment(t, entryErr)
		for first := 0; first < spent; first += 8_000 {
			end := min(first+8_000, spent)
			family := make([]Mutation, 0, end-first)
			for i := first; i < end; i++ {
				var txid [32]byte
				binary.BigEndian.PutUint32(txid[28:], uint32(i+1))
				family = append(family, Mutation{DBI: dbis[5], Key: UndoEntryKey(hash, txid, 0, uint32(i), 0), AfterKind: AfterLiteral, Literal: entry})
			}
			consultedRequireCommit(t, s, "cleanup undo seed", Batch{Mutations: family})
		}
	}
	return s, path, hash, body
}

func cleanupWantAuthority(t *testing.T, s *Store, want StorageAuthorityV1) {
	t.Helper()
	encoded, err := want.Encode()
	mustEnvironment(t, err)
	consultedRequireImage(t, s, readDBIsLiteral()[0], []byte{2}, encoded, true, "cleanup artifact-progress atomicity drifted")
}

func cleanupAuthorityOnly(t *testing.T, a StorageAuthorityV1) *Store {
	t.Helper()
	s, _, _ := consultedStore(t)
	encoded, err := a.Encode()
	mustEnvironment(t, err)
	consultedRequireCommit(t, s, "cleanup authority seed", Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}, AfterKind: AfterLiteral, Literal: encoded}}})
	return s
}

func TestCleanupBU(t *testing.T) {
	t.Run("blocks", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		s, _, hash, body := cleanupTestStore(t, a, 0, 0)
		otherHeader := make([]byte, 116)
		otherHeader[0] = 1
		otherHash := sha3.Sum256(otherHeader)
		otherBody := append(bytes.Clone(otherHeader), 0)
		undo := UndoManifestValue(0, [16]byte{}, 1, 0)
		consultedRequireCommit(t, s, "unrelated undo seed", Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[5], Key: UndoManifestKey(hash), AfterKind: AfterLiteral, Literal: undo}}})
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("cleanup exact canonical artifact drifted: %s/%d/%v", truth, stage, err)
		}
		consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], nil, false, "cleanup exact canonical artifact drifted")
		consultedRequireImage(t, s, readDBIsLiteral()[4], otherHash[:], otherBody, true, "cleanup preserved row drifted")
		consultedRequireImage(t, s, readDBIsLiteral()[3], hash[:], body[:116], true, "cleanup preserved row drifted")
		consultedRequireImage(t, s, readDBIsLiteral()[3], otherHash[:], otherHeader, true, "cleanup preserved row drifted")
		consultedRequireImage(t, s, readDBIsLiteral()[5], UndoManifestKey(hash), undo, true, "cleanup preserved row drifted")
		index, indexErr := HeightKey(7, 0)
		mustEnvironment(t, indexErr)
		consultedRequireImage(t, s, readDBIsLiteral()[2], index, ChainValue(hash, [32]byte{}, [40]byte{39: 1}), true, "cleanup preserved row drifted")
		utxo, utxoErr := UTXOKey(7, modelHash(42), 0)
		mustEnvironment(t, utxoErr)
		utxoValue, utxoValueErr := (UTXOValue{Value: 7}).Encode()
		mustEnvironment(t, utxoValueErr)
		consultedRequireImage(t, s, readDBIsLiteral()[1], utxo, utxoValue, true, "cleanup preserved row drifted")
		a.Cleanup, a.Phase = nil, StoragePhaseNoneV1
		cleanupWantAuthority(t, s, a)
		truth, stage, err = s.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || err != nil {
			t.Fatalf("cleanup repeated no-work drifted: %s/%d/%v", truth, stage, err)
		}
		progressed := cleanupAuthority(CleanupSpanBlocksV1, 1, false)
		progressed.Cleanup.Spans[0].FirstHeight = 0
		progressedStore, _, progressedHash, _ := cleanupTestStore(t, progressed, 1, 0)
		truth, stage, err = progressedStore.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("cleanup progressed height drifted: %s/%d/%v", truth, stage, err)
		}
		consultedRequireImage(t, progressedStore, readDBIsLiteral()[4], progressedHash[:], nil, false, "cleanup exact canonical artifact drifted")
		progressed.Cleanup, progressed.Phase = nil, StoragePhaseNoneV1
		cleanupWantAuthority(t, progressedStore, progressed)
	})
	t.Run("order", func(t *testing.T) {
		for _, a := range []StorageAuthorityV1{modelBase(1, 0, 0), modelReplay(1), modelOrdinary(2, 1, 2, 15120, 1, 1, 13681)} {
			s := cleanupAuthorityOnly(t, a)
			truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
			if truth != CommitTruthOld || stage != UpdateStagePrewrite || err != nil {
				t.Fatalf("cleanup nonselected phase drifted: %d %s/%d/%v", a.Phase, truth, stage, err)
			}
			cleanupWantAuthority(t, s, a)
		}
		for _, kind := range []CleanupSpanKindV1{CleanupSpanGenerationV1, CleanupSpanSideV1} {
			a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
			first := CleanupSpanV1{Kind: kind, GenerationID: 8}
			if kind == CleanupSpanSideV1 {
				first.LastHeight = 0
				a.Cleanup.Spans = []CleanupSpanV1{first}
			} else {
				a.Cleanup.Spans = append([]CleanupSpanV1{first}, a.Cleanup.Spans...)
			}
			s := cleanupAuthorityOnly(t, a)
			truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
			if truth != CommitTruthOld || stage != UpdateStagePrewrite || err != nil {
				t.Fatalf("cleanup first-span progress drifted: %d %s/%d/%v", kind, truth, stage, err)
			}
			cleanupWantAuthority(t, s, a)
		}
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		a.DetachedSuffix = modelDetached(1, 1)
		s := cleanupAuthorityOnly(t, a)
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || err != nil {
			t.Fatalf("cleanup detached precedence drifted: %s/%d/%v", truth, stage, err)
		}
		cleanupWantAuthority(t, s, a)
		a = cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		a.Cleanup.Spans = append(a.Cleanup.Spans, CleanupSpanV1{Kind: CleanupSpanUndoV1, GenerationID: 7, LastHeight: 0})
		s, _, hash, _ := cleanupTestStore(t, a, 0, 0)
		truth, stage, err = s.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("cleanup first-span progress drifted: %s/%d/%v", truth, stage, err)
		}
		a.Cleanup.Spans = a.Cleanup.Spans[1:]
		cleanupWantAuthority(t, s, a)
		consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], nil, false, "cleanup exact canonical artifact drifted")
		progress := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		progress.B, progress.U = 2, 13682
		progress.Cleanup.Spans[0].LastHeight = 1
		progressStore, _, _, _ := cleanupTestStore(t, progress, 0, 0)
		truth, stage, err = progressStore.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("cleanup first-span progress drifted: %s/%d/%v", truth, stage, err)
		}
		progress.Cleanup.Spans[0].NextHeight = 1
		cleanupWantAuthority(t, progressStore, progress)
	})
	t.Run("stable_terminal", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		s, _, hash, _ := cleanupTestStore(t, a, 0, 0)
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("cleanup stable terminal drifted: %s/%d/%v", truth, stage, err)
		}
		a.Cleanup, a.Phase = nil, StoragePhaseNoneV1
		cleanupWantAuthority(t, s, a)
		consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], nil, false, "cleanup stable artifact drifted")
	})
	t.Run("promise", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		span, err := cleanupBUSelect(&Reader{}, a, fmt.Errorf("unexpected no-work"))
		if err != nil || span.NextHeight != 0 || span.GenerationID != 7 {
			t.Fatalf("cleanup bound-minus-one drifted: %+v/%v", span, err)
		}
		for _, row := range []struct {
			name string
			edit func(*StorageAuthorityV1)
		}{
			{"bound", func(v *StorageAuthorityV1) { v.B = 0 }},
			{"generation", func(v *StorageAuthorityV1) { v.ActiveGenerationID = 8 }},
			{"overwidth", func(v *StorageAuthorityV1) { v.Cleanup.Spans[0].NextHeight = math.MaxUint64 }},
		} {
			t.Run(row.name, func(t *testing.T) {
				candidate := a
				candidate.Cleanup = &CleanupV1{Spans: slices.Clone(a.Cleanup.Spans)}
				row.edit(&candidate)
				_, err := cleanupBUSelect(&Reader{}, candidate, nil)
				engine, ok := err.(*EngineError)
				if !ok || engine.Class != EngineLocalInvariant || engine.Operation != "update" || engine.Diagnostic != "cleanup promises disagree with authority" {
					t.Fatalf("cleanup promise recheck drifted: %s: %v", row.name, err)
				}
			})
		}
	})
	t.Run("terminal_boundaries", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, true)
		a.NextGenerationID = math.MaxUint64
		s, _, hash, _ := cleanupTestStore(t, a, 0, 0)
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("cleanup terminal allocation independence drifted: %s/%d/%v", truth, stage, err)
		}
		a.Cleanup, a.Phase = nil, StoragePhaseNoneV1
		cleanupWantAuthority(t, s, a)
		consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], nil, false, "cleanup terminal artifact drifted")
	})
	t.Run("ownership", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		s, _, hash, body := cleanupTestStore(t, a, 0, 0)
		stored := bytes.Clone(body)
		body[len(body)-1] ^= 1
		consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], stored, true, "cleanup source buffer ownership drifted")
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		inFlight := fmt.Errorf("held update callback")
		go func() {
			_, _, err := s.Update(func(*Reader) (Batch, error) {
				close(entered)
				<-release
				return Batch{}, inFlight
			})
			done <- err
		}()
		<-entered
		busyTruth, busyStage, busyErr := s.CleanupBUV1(bootstrapOwner(t))
		busy, ok := busyErr.(*EngineError)
		close(release)
		heldErr := <-done
		if busyTruth != CommitTruthOld || busyStage != UpdateStagePrewrite || !ok || busy.Class != EngineConcurrency {
			t.Fatalf("cleanup overlapping callback admitted: %s/%d/%v", busyTruth, busyStage, busyErr)
		}
		if heldErr != inFlight {
			t.Fatalf("held callback cause drifted: %v", heldErr)
		}
		before := a
		truth, _, err := s.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthNew || err != nil || !reflect.DeepEqual(a, before) {
			t.Fatalf("cleanup caller buffer ownership drifted: %s/%v", truth, err)
		}
	})
	t.Run("undo", func(t *testing.T) {
		for _, count := range []int{0, 1, 65, 1_440, 1_441, 16_385, 414_634} {
			t.Run(fmt.Sprint(count), func(t *testing.T) {
				a := cleanupAuthority(CleanupSpanUndoV1, 0, false)
				s, _, hash, body := cleanupTestStore(t, a, 0, count)
				truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
				if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
					t.Fatalf("cleanup admitted undo family drifted: %s/%d/%v", truth, stage, err)
				}
				consultedRequireImage(t, s, readDBIsLiteral()[5], UndoManifestKey(hash), nil, false, "cleanup complete undo family drifted")
				consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], body, true, "cleanup preserved row drifted")
				consultedRequireImage(t, s, readDBIsLiteral()[3], hash[:], body[:116], true, "cleanup preserved row drifted")
				otherHeader := make([]byte, 116)
				otherHeader[0] = 1
				otherHash := sha3.Sum256(otherHeader)
				consultedRequireImage(t, s, readDBIsLiteral()[4], otherHash[:], append(bytes.Clone(otherHeader), 0), true, "cleanup preserved row drifted")
				consultedRequireImage(t, s, readDBIsLiteral()[3], otherHash[:], otherHeader, true, "cleanup preserved row drifted")
				index, indexErr := HeightKey(7, 0)
				mustEnvironment(t, indexErr)
				consultedRequireImage(t, s, readDBIsLiteral()[2], index, ChainValue(hash, [32]byte{}, [40]byte{39: 1}), true, "cleanup preserved row drifted")
				utxo, utxoErr := UTXOKey(7, modelHash(42), 0)
				mustEnvironment(t, utxoErr)
				utxoValue, valueErr := (UTXOValue{Value: 7}).Encode()
				mustEnvironment(t, valueErr)
				consultedRequireImage(t, s, readDBIsLiteral()[1], utxo, utxoValue, true, "cleanup preserved row drifted")
				if count > 0 {
					var txid [32]byte
					binary.BigEndian.PutUint32(txid[28:], uint32(count))
					consultedRequireImage(t, s, readDBIsLiteral()[5], UndoEntryKey(hash, txid, 0, uint32(count-1), 0), nil, false, "cleanup complete undo family drifted")
				}
				a.Cleanup, a.Phase = nil, StoragePhaseNoneV1
				cleanupWantAuthority(t, s, a)
			})
		}
	})
	t.Run("recovery_terminal", func(t *testing.T) {
		for _, pending := range []StorageProfileV1{StorageProfilePrunedV1, StorageProfileArchiveV1} {
			t.Run(fmt.Sprint(pending), func(t *testing.T) {
				a := cleanupAuthority(CleanupSpanBlocksV1, 0, true)
				a.NextGenerationID = math.MaxUint64
				*a.PendingTargetProfile = pending
				a.ExcludedInvalidBranch = &InvalidBranchV1{FirstInvalidHeight: 4, FirstInvalidBlockHash: modelHash(50), ExactConsensusError: []byte{1}}
				s, _, hash, _ := cleanupTestStore(t, a, 0, 0)
				truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
				if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
					t.Fatalf("cleanup terminal allocation independence drifted: %s/%d/%v", truth, stage, err)
				}
				a.Cleanup, a.Phase = nil, StoragePhaseNoneV1
				cleanupWantAuthority(t, s, a)
				consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], nil, false, "cleanup terminal pending image drifted")
				truth, stage, err = s.CleanupBUV1(bootstrapOwner(t))
				if truth != CommitTruthOld || stage != UpdateStagePrewrite || err != nil {
					t.Fatalf("cleanup pending no-work drifted: %s/%d/%v", truth, stage, err)
				}
			})
		}
	})
	t.Run("capacity", func(t *testing.T) {
		owner := bootstrapOwner(t)
		truth, stage, err := (*Store)(nil).CleanupBUV1(owner)
		nilStore, ok := err.(*EngineError)
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || nilStore.Class != EngineInvalidInput || nilStore.Operation != "update" || nilStore.Code != codeEINVAL || nilStore.Diagnostic != "nil Store" {
			t.Fatalf("cleanup nil Store tuple drifted: %s/%d/%v", truth, stage, err)
		}
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		s, _, _, _ := cleanupTestStore(t, a, 0, 0)
		for _, refused := range []*OperationReservationOwner{nil, {}} {
			truth, stage, err = s.CleanupBUV1(refused)
			if truth != CommitTruthOld || stage != UpdateStagePrewrite || err != errOperationReservationInput {
				t.Fatalf("cleanup reservation boundary drifted: %s/%d/%v", truth, stage, err)
			}
		}
		qMinusOne, ownerErr := NewOperationReservationOwner(MaxOperationDataBytes)
		mustEnvironment(t, ownerErr)
		mustEnvironment(t, qMinusOne.WithReservation(1, func() error {
			truth, stage, err = s.CleanupBUV1(qMinusOne)
			if truth != CommitTruthOld || stage != UpdateStagePrewrite || err != errOperationReservationCapacity {
				t.Fatalf("cleanup reservation boundary drifted: %s/%d/%v", truth, stage, err)
			}
			return nil
		}))
		cleanupWantAuthority(t, s, a)
		prunedReleased(t, qMinusOne)
		truth, stage, err = s.CleanupBUV1(qMinusOne)
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("cleanup exact-Q readmission drifted: %s/%d/%v", truth, stage, err)
		}
		prunedReleased(t, qMinusOne)
	})
	t.Run("restart", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, true)
		a.B, a.U = 2, 13682
		a.Cleanup.Spans[0].LastHeight = 1
		s, path, hash, _ := cleanupTestStore(t, a, 0, 0)
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("cleanup restart progress drifted: %s/%d/%v", truth, stage, err)
		}
		a.Cleanup.Spans[0].NextHeight = 1
		cleanupWantAuthority(t, s, a)
		consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], nil, false, "cleanup restart artifact drifted")
		cfg := s.config
		mustEnvironment(t, s.Close())
		reopened, openErr := Open(path, cfg)
		mustEnvironment(t, openErr)
		defer func() {
			if reopened.state == storeOPEN {
				mustEnvironment(t, reopened.Close())
			}
		}()
		truth, stage, err = reopened.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || err == nil {
			t.Fatalf("cleanup restart uncommitted height skipped: %s/%d/%v", truth, stage, err)
		}
		final := cleanupAuthority(CleanupSpanBlocksV1, 0, true)
		finished, finalPath, _, _ := cleanupTestStore(t, final, 0, 0)
		truth, stage, err = finished.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("cleanup final restart commit drifted: %s/%d/%v", truth, stage, err)
		}
		final.Cleanup, final.Phase = nil, StoragePhaseNoneV1
		finalCfg := finished.config
		mustEnvironment(t, finished.Close())
		resumed, resumeErr := Open(finalPath, finalCfg)
		mustEnvironment(t, resumeErr)
		defer func() { mustEnvironment(t, resumed.Close()) }()
		cleanupWantAuthority(t, resumed, final)
		truth, stage, err = resumed.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || err != nil {
			t.Fatalf("cleanup final restart repeated work: %s/%d/%v", truth, stage, err)
		}
	})
	t.Run("outcome", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		s, _, hash, _ := cleanupTestStore(t, a, 0, 0)
		consultedRequireCommit(t, s, "remove owed body", Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[4], Key: hash[:], BeforePresent: true, AfterKind: AfterAbsent}}})
		owner := bootstrapOwner(t)
		truth, stage, err := s.CleanupBUV1(owner)
		engine, ok := err.(*EngineError)
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Class != EngineIntegrity || engine.Operation != "get" || engine.Code != codeInvalid || engine.Diagnostic != "invalid cleanup owed artifact" {
			t.Fatalf("cleanup stage or cause provenance drifted: %s/%d/%v", truth, stage, err)
		}
		prunedReleased(t, owner)
		againTruth, againStage, againErr := s.CleanupBUV1(owner)
		if againTruth != truth || againStage != stage || againErr != err {
			t.Fatalf("cleanup cached terminal truth drifted: %s/%d/%v", againTruth, againStage, againErr)
		}
	})
	t.Run("mixed", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		s, _, hash, _ := cleanupTestStore(t, a, 0, 0)
		key, err := HeightKey(7, 0)
		mustEnvironment(t, err)
		consultedRequireCommit(t, s, "mixed missing rows", Batch{Mutations: []Mutation{
			{DBI: readDBIsLiteral()[2], Key: key, BeforePresent: true, AfterKind: AfterAbsent},
			{DBI: readDBIsLiteral()[4], Key: hash[:], BeforePresent: true, AfterKind: AfterAbsent},
		}})
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		engine, ok := err.(*EngineError)
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Diagnostic != "invalid cleanup canonical evidence" {
			t.Fatalf("cleanup precedence drifted: %s/%d/%v", truth, stage, err)
		}
	})
}

func TestCleanupBUMalformed(t *testing.T) {
	t.Run("index", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		s, path, hash, body := cleanupTestStore(t, a, 0, 0)
		cfg := s.config
		key, keyErr := HeightKey(7, 0)
		mustEnvironment(t, keyErr)
		consultedRequireCommit(t, s, "remove required index", Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[2], Key: key, BeforePresent: true, AfterKind: AfterAbsent}}})
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		engine, ok := err.(*EngineError)
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Class != EngineIntegrity || engine.Operation != "get" || engine.Diagnostic != "invalid cleanup canonical evidence" {
			t.Fatalf("cleanup required index provenance drifted: %s/%d/%v", truth, stage, err)
		}
		reopened, openErr := Open(path, cfg)
		mustEnvironment(t, openErr)
		defer func() { mustEnvironment(t, reopened.Close()) }()
		consultedRequireImage(t, reopened, readDBIsLiteral()[4], hash[:], body, true, "cleanup invalid index changed artifact")
		maximum := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		maxStore, _, maxHash, _ := cleanupTestStore(t, maximum, 0, 0)
		maxKey, maxKeyErr := HeightKey(7, 0)
		mustEnvironment(t, maxKeyErr)
		maxWork := [40]byte{3: 1}
		consultedRequireCommit(t, maxStore, "maximum work seed", Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[2], Key: maxKey, BeforePresent: true, AfterKind: AfterLiteral, Literal: ChainValue(maxHash, [32]byte{}, maxWork)}}})
		maxTruth, maxStage, maxErr := maxStore.CleanupBUV1(bootstrapOwner(t))
		if maxTruth != CommitTruthNew || maxStage != UpdateStageCommitMayHaveCrossed || maxErr != nil {
			t.Fatalf("cleanup 40-byte maximum work drifted: %s/%d/%v", maxTruth, maxStage, maxErr)
		}
		consultedRequireImage(t, maxStore, readDBIsLiteral()[2], maxKey, ChainValue(maxHash, [32]byte{}, maxWork), true, "cleanup work representation drifted")
		mismatched := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
		mismatchStore, _, mismatchHash, _ := cleanupTestStore(t, mismatched, 0, 0)
		mismatchKey, mismatchKeyErr := HeightKey(7, 0)
		mustEnvironment(t, mismatchKeyErr)
		consultedRequireCommit(t, mismatchStore, "index/header mismatch seed", Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[2], Key: mismatchKey, BeforePresent: true, AfterKind: AfterLiteral, Literal: ChainValue(mismatchHash, modelHash(9), [40]byte{39: 1})}}})
		mismatchTruth, mismatchStage, mismatchErr := mismatchStore.CleanupBUV1(bootstrapOwner(t))
		mismatchEngine, mismatchOK := mismatchErr.(*EngineError)
		if mismatchTruth != CommitTruthOld || mismatchStage != UpdateStagePrewrite || !mismatchOK || mismatchEngine.Diagnostic != "invalid cleanup canonical evidence" {
			t.Fatalf("cleanup index/header link mismatch accepted: %s/%d/%v", mismatchTruth, mismatchStage, mismatchErr)
		}
	})
	t.Run("artifact", func(t *testing.T) {
		for _, count := range []int{0, 1} {
			a := cleanupAuthority(CleanupSpanUndoV1, 0, false)
			s, _, hash, _ := cleanupTestStore(t, a, 0, count)
			if count == 0 {
				consultedRequireCommit(t, s, "remove owed manifest", Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[5], Key: UndoManifestKey(hash), BeforePresent: true, AfterKind: AfterAbsent}}})
			} else {
				var txid [32]byte
				binary.BigEndian.PutUint32(txid[28:], 1)
				consultedRequireCommit(t, s, "remove owed entry", Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[5], Key: UndoEntryKey(hash, txid, 0, 0, 0), BeforePresent: true, AfterKind: AfterAbsent}}, Reverse: true})
			}
			truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
			engine, ok := err.(*EngineError)
			if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Class != EngineIntegrity || engine.Operation != "get" || engine.Diagnostic != "invalid cleanup owed artifact" {
				t.Fatalf("cleanup missing artifact provenance drifted: %s/%d/%v", truth, stage, err)
			}
		}
		for _, row := range []struct {
			name   string
			height uint64
			count  uint32
		}{
			{"manifest height", 1, 0},
			{"manifest count", 0, 1},
			{"manifest overcount", 0, 414_635},
		} {
			t.Run(row.name, func(t *testing.T) {
				a := cleanupAuthority(CleanupSpanUndoV1, 0, false)
				s, _, hash, _ := cleanupTestStore(t, a, 0, 0)
				value := UndoManifestValue(row.height, [16]byte{}, 1, row.count)
				consultedRequireCommit(t, s, "manifest mismatch seed", Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[5], Key: UndoManifestKey(hash), BeforePresent: true, AfterKind: AfterLiteral, Literal: value}}})
				truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
				engine, ok := err.(*EngineError)
				if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Diagnostic != "invalid cleanup owed artifact" {
					t.Fatalf("cleanup manifest mismatch accepted: %s/%d/%v", truth, stage, err)
				}
			})
		}
	})
	t.Run("duplicate outpoint", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanUndoV1, 0, false)
		s, _, hash, _ := cleanupTestStore(t, a, 0, 1)
		var spent [32]byte
		binary.BigEndian.PutUint32(spent[28:], 1)
		entry, entryErr := (UTXOValue{Value: 1}).Encode()
		mustEnvironment(t, entryErr)
		consultedRequireCommit(t, s, "duplicate outpoint seed", Batch{Mutations: []Mutation{
			{DBI: readDBIsLiteral()[5], Key: UndoManifestKey(hash), BeforePresent: true, AfterKind: AfterLiteral, Literal: UndoManifestValue(0, [16]byte{}, 2, 2)},
			{DBI: readDBIsLiteral()[5], Key: UndoEntryKey(hash, spent, 1, 0, 0), AfterKind: AfterLiteral, Literal: entry},
		}})
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		engine, ok := err.(*EngineError)
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Diagnostic != "invalid cleanup owed artifact" {
			t.Fatalf("cleanup duplicate outpoint accepted: %s/%d/%v", truth, stage, err)
		}
	})
	t.Run("extra entry", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanUndoV1, 0, false)
		s, _, hash, _ := cleanupTestStore(t, a, 0, 0)
		var spent [32]byte
		spent[31] = 1
		entry, entryErr := (UTXOValue{Value: 1}).Encode()
		mustEnvironment(t, entryErr)
		consultedRequireCommit(t, s, "extra undo entry seed", Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[5], Key: UndoEntryKey(hash, spent, 0, 0, 0), AfterKind: AfterLiteral, Literal: entry}}})
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		engine, ok := err.(*EngineError)
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Diagnostic != "invalid cleanup owed artifact" {
			t.Fatalf("cleanup extra undo entry accepted: %s/%d/%v", truth, stage, err)
		}
	})
}
