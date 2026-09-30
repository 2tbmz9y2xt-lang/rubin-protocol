//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"
	"unsafe"
)

// Public operation tests own persisted-image and lifecycle behavior. Private
// composition rows below cover native dispositions unavailable to the public API.
func archiveSeed(t *testing.T, a StorageAuthorityV1, height int, work [40]byte) (*Store, string, ConfigV1, []Mutation) {
	t.Helper()
	s, path, cfg, rows := prunedStore(t, a, nil, work)
	if height >= 0 {
		var extra []Mutation
		heights := []uint64{0}
		if height > 0 {
			heights = append(heights, 1)
		}
		if height > 1 {
			// Structural requested-tip witness; the operation observes only h0/h1.
			heights = append(heights, uint64(height))
		}
		for _, h := range heights {
			key, err := HeightKey(a.ActiveGenerationID, h)
			mustEnvironment(t, err)
			hash := modelHash(h + 71)
			extra = append(extra, Mutation{DBI: readDBIsLiteral()[2], Key: key, AfterKind: AfterLiteral, Literal: ChainValue(hash, [32]byte{}, work)}, canonicalOwnerLiteral(a.ActiveGenerationID, h, hash))
		}
		sort.Slice(extra, func(i, j int) bool {
			if extra[i].DBI.Rank != extra[j].DBI.Rank {
				return extra[i].DBI.Rank < extra[j].DBI.Rank
			}
			return bytes.Compare(extra[i].Key, extra[j].Key) < 0
		})
		consultedRequireCommit(t, s, "archive canonical fixture", Batch{Mutations: extra})
		rows = append(rows, extra...)
	}
	return s, path, cfg, rows
}

// This is an exact literal published-genesis image, not a new producer chain.
func archiveGenesis(t *testing.T) (*Store, string, ConfigV1, []Mutation) {
	t.Helper()
	s, path, cfg := consultedStore(t)
	truth, stage, err := s.BootstrapStorageV1(1, bootstrapOwner(t))
	if truth != 2 || stage != 3 || err != nil {
		t.Fatalf("genesis bootstrap: %s/%d/%v", truth, stage, err)
	}
	data, err := os.ReadFile("../../../../conformance/fixtures/CV-DEVNET-GENESIS.json")
	mustEnvironment(t, err)
	var fixture struct {
		Vectors []struct {
			Block string `json:"block_hex"`
			Hash  string `json:"block_hash"`
			Txid  string `json:"coinbase_txid"`
		}
	}
	mustEnvironment(t, json.Unmarshal(data, &fixture))
	if len(fixture.Vectors) != 1 {
		t.Fatal("genesis fixture cardinality")
	}
	v := fixture.Vectors[0]
	block, hash, txid := mustCodecHex(t, v.Block), mustCodecHex(t, v.Hash), mustCodecHex(t, v.Txid)
	chain := append(append([]byte(nil), hash...), make([]byte, 72)...)
	chain[103] = 1
	manifest := make([]byte, 33)
	manifest[0], manifest[28] = 1, 1
	dbis := readDBIsLiteral()
	rows := []Mutation{
		{DBI: dbis[0], Key: []byte{2}, Literal: bootstrapImage(1)},
		{DBI: dbis[0], Key: bootstrapCounterKey(), BeforePresent: true, AfterKind: AfterLiteral, Literal: []byte{0, 0, 0, 0, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0, 0, 1}},
		{DBI: dbis[1], Key: append(append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, txid...), 0, 0, 0, 0), AfterKind: AfterLiteral, Literal: mustCodecHex(t, "00407a10f35a0000000021018448b91b88d1a6fbb65e872b72c381b2a9f3ce286a232f56309667f639dd7279000000000000000001")},
		{DBI: dbis[2], Key: []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, AfterKind: AfterLiteral, Literal: chain},
		{DBI: dbis[3], Key: hash, AfterKind: AfterLiteral, Literal: block[:116]},
		{DBI: dbis[4], Key: hash, AfterKind: AfterLiteral, Literal: block},
		{DBI: dbis[5], Key: append(append([]byte(nil), hash...), 0), AfterKind: AfterLiteral, Literal: manifest},
		{DBI: dbis[7], Key: append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, hash...), AfterKind: AfterLiteral, Literal: make([]byte, 8)},
	}
	consultedRequireCommit(t, s, "complete genesis literal", Batch{Mutations: rows[1:]})
	if bootstrapCounts(t, s, "complete genesis") != [8]uint64{4, 1, 1, 1, 1, 1, 0, 1} {
		t.Fatal("complete genesis census")
	}
	return s, path, cfg, rows
}

func archiveSide(progress uint64) StorageAuthorityV1 {
	a := modelBase(1, 0, 0)
	a.NextGenerationID, a.Phase = 3, 2
	a.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 4, GenerationID: 2, FirstHeight: 1, LastHeight: 3, NextHeight: progress}}}
	return a
}

func archiveEmptyPayload(t *testing.T, out ArchiveProfileOutcome) {
	t.Helper()
	if out.Authority != nil || out.Decision != "" {
		t.Fatalf("unexpected archive payload: %+v", out)
	}
}

func archiveCached(t *testing.T, s *Store, out ArchiveProfileOutcome, owner *OperationReservationOwner) {
	t.Helper()
	again := s.SelectArchiveProfileV1(owner)
	if again.Truth != out.Truth || again.Stage != 1 || !sameError(again.Err, out.Err) {
		t.Fatalf("archive cached tuple: %+v vs %+v", again, out)
	}
	archiveEmptyPayload(t, again)
	prunedReleased(t, owner)
}

func archiveSuccess(t *testing.T, s *Store, rows []Mutation, a StorageAuthorityV1, reopen bool, path string, cfg ConfigV1) {
	t.Helper()
	before, counts := prunedImage(t, s, rows), bootstrapCounts(t, s, "archive before")
	old := append([]byte(nil), before[0]...)
	want := append([]byte(nil), old...)
	want[1] = 2
	owner := bootstrapOwner(t)
	out := s.SelectArchiveProfileV1(owner)
	a.ActiveProfile = 2
	if out.Truth != 2 || out.Stage != 3 || out.Err != nil || out.Decision != "" || !reflect.DeepEqual(out.Authority, &a) {
		t.Fatalf("archive exact success: %+v", out)
	}
	after := prunedImage(t, s, rows)
	if !bytes.Equal(after[0], want) || bytes.Equal(after[0], old) || !reflect.DeepEqual(before[1:], after[1:]) || bootstrapCounts(t, s, "archive after") != counts {
		t.Fatal("archive profile-only image")
	}
	bootstrapOpenUnchanged(t, s, "archive success")
	prunedReleased(t, owner)
	// The returned decoded object cannot alias durable bytes or later invocations.
	out.Authority.ActiveProfile = 1
	if out.Authority.Cleanup != nil {
		out.Authority.Cleanup.Spans[0].NextHeight = 1
	}
	prunedDecision(t, s.SelectArchiveProfileV1(owner), "PROFILE_NOOP", "archive next noop")
	if !reflect.DeepEqual(prunedImage(t, s, rows), after) {
		t.Fatal("archive payload leaked")
	}
	if reopen {
		mustEnvironment(t, s.Close())
		r, err := Open(path, cfg)
		mustEnvironment(t, err)
		defer func() { _ = r.Close() }()
		prunedDecision(t, r.SelectArchiveProfileV1(owner), "PROFILE_NOOP", "archive reopened noop")
		if !reflect.DeepEqual(prunedImage(t, r, rows), after) || bootstrapCounts(t, r, "reopen") != counts {
			t.Fatal("archive reopen image")
		}
	}
}

func TestArchiveProfile(t *testing.T) {
	t.Run("A1", func(t *testing.T) {
		s, path, cfg := consultedStore(t)
		truth, stage, err := s.BootstrapStorageV1(1, bootstrapOwner(t))
		if truth != 2 || stage != 3 || err != nil {
			t.Fatal("archive bootstrap")
		}
		rows := []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}}, {DBI: readDBIsLiteral()[0], Key: bootstrapCounterKey()}}
		bootstrapRequireRow(t, s, []byte{2}, bootstrapImage(1), "A1 old")
		bootstrapRequireRow(t, s, bootstrapCounterKey(), make([]byte, 16), "A1 counter")
		archiveSuccess(t, s, rows, modelBase(1, 0, 0), true, path, cfg)
	})
	t.Run("A2", func(t *testing.T) {
		s, path, cfg, rows := archiveGenesis(t)
		archiveSuccess(t, s, rows, modelBase(1, 0, 0), true, path, cfg)
	})
	selected := modelBase(1, 0, 0)
	selected.NextGenerationID, selected.SelectedSide = 3, modelSide(2, 0, 3, 3, 3)
	exclusion := modelBase(1, 0, 0)
	exclusion.ExcludedInvalidBranch = &InvalidBranchV1{FirstInvalidHeight: 4, FirstInvalidBlockHash: modelHash(33), ExactConsensusError: []byte{0, 255, 128}}
	for _, row := range []struct {
		name string
		a    StorageAuthorityV1
	}{{"A3", selected}, {"A4", exclusion}, {"A5", archiveSide(2)}} {
		t.Run(row.name, func(t *testing.T) {
			s, path, cfg, rows := archiveSeed(t, row.a, 0, modelWork(false))
			if row.name == "A3" {
				var extra []Mutation
				for h := uint64(1); h <= 3; h++ {
					k, _ := HeightKey(2, h)
					value := ChainValue(modelHash(h), [32]byte{}, modelWork(false))
					extra = append(extra, Mutation{DBI: readDBIsLiteral()[6], Key: k, AfterKind: AfterLiteral, Literal: value})
				}
				consultedRequireCommit(t, s, "selected rows", Batch{Mutations: extra})
				rows = append(rows, extra...)
			}
			archiveSuccess(t, s, rows, row.a, row.name == "A5", path, cfg)
		})
	}
	for _, maximum := range []bool{false, true} {
		t.Run(fmt.Sprintf("A13/%v", maximum), func(t *testing.T) {
			a := modelBase(1, 0, 0)
			a.NextGenerationID = ^uint64(0)
			s, path, cfg, rows := archiveSeed(t, a, 0, modelWork(maximum))
			archiveSuccess(t, s, rows, a, false, path, cfg)
		})
	}
	for _, row := range []struct {
		name string
		a    StorageAuthorityV1
		h    int
	}{
		{"A8", modelBase(2, 0, 0), 5},
		{"A9", func() StorageAuthorityV1 { a := archiveSide(2); a.ActiveProfile = 2; return a }(), 0},
		{"A10", func() StorageAuthorityV1 {
			a := modelBase(2, 0, 18561)
			a.Phase = 2
			a.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 3, GenerationID: 1, FirstHeight: 18560, LastHeight: 18560, NextHeight: 18560}}}
			return a
		}(), 20000},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, _, _, rows := archiveSeed(t, row.a, row.h, modelWork(false))
			before := prunedImage(t, s, rows)
			owner := bootstrapOwner(t)
			prunedDecision(t, s.SelectArchiveProfileV1(owner), "PROFILE_NOOP", row.name)
			prunedUnchanged(t, s, rows, before, row.name)
			prunedReleased(t, owner)
		})
	}
	t.Run("A12", func(t *testing.T) {
		s, _, _ := consultedStore(t)
		truth, stage, err := s.BootstrapStorageV1(2, bootstrapOwner(t))
		if truth != 2 || stage != 3 || err != nil {
			t.Fatal("archive bootstrap")
		}
		prunedDecision(t, s.SelectArchiveProfileV1(bootstrapOwner(t)), "PROFILE_NOOP", "A12")
		bootstrapRequireInitialized(t, s, s.config, 2, "A12")
	})
	t.Run("A11", testArchivePlan)
	t.Run("H14", testArchiveProjection)
	t.Run("H12", testArchiveAbort)
	t.Run("H8", testArchiveReservation)
	t.Run("H8_headroom511", func(t *testing.T) { testArchiveHeadroom(t, 511) })
	t.Run("H17c", func(t *testing.T) {
		s, _, _, _ := archiveSeed(t, modelBase(1, 0, 0), -1, modelWork(false))
		owner := bootstrapOwner(t)
		mustEnvironment(t, owner.WithReservation(154611151, func() error {
			s.operations.Lock()
			defer s.operations.Unlock()
			out := s.SelectArchiveProfileV1(owner)
			if !sameError(out.Err, errOperationReservationCapacity) || out.Truth != 1 || out.Stage != 1 {
				t.Fatal("capacity before lock")
			}
			archiveEmptyPayload(t, out)
			return nil
		}))
		if out := s.SelectArchiveProfileV1(owner); out.Err != nil || out.Truth != 2 {
			t.Fatal("same owner after denial")
		}
	})
	t.Run("H9", func(t *testing.T) {
		s, _, _, rows := archiveSeed(t, modelBase(1, 0, 0), -1, modelWork(false))
		before := prunedImage(t, s, rows)
		owner := bootstrapOwner(t)
		s.operations.Lock()
		out := s.SelectArchiveProfileV1(owner)
		s.operations.Unlock()
		bootstrapRefusal(t, "held lock", out.Truth, out.Err, EngineConcurrency, operationUpdate, codeBusy, "store operation in progress", nil, false)
		if out.Stage != 1 {
			t.Fatal("lock stage")
		}
		archiveEmptyPayload(t, out)
		prunedUnchanged(t, s, rows, before, "lock")
		prunedReleased(t, owner)
		if next := s.SelectArchiveProfileV1(owner); next.Truth != 2 || next.Err != nil {
			t.Fatal("reuse after lock")
		}
	})
	t.Run("H13", func(t *testing.T) {
		for _, owner := range []*OperationReservationOwner{nil, {}} {
			out := (*Store)(nil).SelectArchiveProfileV1(owner)
			bootstrapRefusal(t, "nil store first", out.Truth, out.Err, EngineInvalidInput, operationUpdate, codeEINVAL, "nil Store", nil, false)
			if out.Stage != 1 {
				t.Fatal("nil stage")
			}
			archiveEmptyPayload(t, out)
		}
	})
	t.Run("H7", testArchiveReadComposition)
	testArchiveRefusals(t)
}

func testArchivePlan(t *testing.T) {
	for _, row := range []struct {
		name string
		a    StorageAuthorityV1
		h    int
	}{{"PRE_GENESIS", modelBase(1, 0, 0), -1}, {"H0", modelBase(1, 0, 0), 0}, {"SIDE", archiveSide(2), 0}} {
		t.Run(row.name, func(t *testing.T) {
			s, _, _, rows := archiveSeed(t, row.a, row.h, modelWork(false))
			before := prunedImage(t, s, rows)
			mustEnvironment(t, s.View(func(r *Reader) error {
				decision := ""
				batch, plan, err := archiveProfileBatch(r, &decision, errors.New("decision"))
				if err != nil || decision != "" || plan == nil {
					t.Fatal("archive plan result")
				}
				want := append([]byte(nil), before[0]...)
				want[1] = 2
				wantBatch := Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: AfterLiteral, Literal: want}}, Consulted: []ConsultedRow{{DBI: readDBIsLiteral()[2], Key: []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}}, {DBI: readDBIsLiteral()[2], Key: []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}}}}
				if !reflect.DeepEqual(batch, wantBatch) {
					t.Fatalf("archive plan exact mutation/consulted: %+v", batch)
				}
				a := row.a
				a.ActiveProfile = 2
				if !reflect.DeepEqual(plan, &a) {
					t.Fatal("archive plan fields")
				}
				return nil
			}))
			prunedUnchanged(t, s, rows, before, "borrowed plan")
		})
	}
}

func testArchiveRefusals(t *testing.T) {
	pArchive, pPruned := StorageProfileV1(2), StorageProfileV1(1)
	recovery := modelBase(1, 0, 0)
	recovery.Lifecycle, recovery.PendingTargetProfile = 2, &pArchive
	pruneRecovery := archiveSide(1)
	pruneRecovery.Lifecycle, pruneRecovery.PendingTargetProfile = 2, &pPruned
	archiveRecovery := recovery
	archiveRecovery.ActiveProfile = 2
	archivePruneRecovery := archiveSide(1)
	archivePruneRecovery.ActiveProfile, archivePruneRecovery.Lifecycle, archivePruneRecovery.PendingTargetProfile = 2, 2, &pArchive
	busySide := archiveSide(1)
	busySide.Cleanup.Spans[0].LastHeight = 1
	for _, row := range []struct {
		name      string
		a         StorageAuthorityV1
		h         int
		decision  string
		integrity bool
	}{
		{"R1", recovery, -1, "RECOVERY_REQUIRED", false},
		{"R2", pruneRecovery, 0, "RECOVERY_REQUIRED", false},
		{"R3", modelReplay(1), -1, "RECOVERY_REQUIRED", false},
		{"R4", modelOrdinary(1, 2, 2, 2, 1, 0, 0), 0, "RECOVERY_REQUIRED", false},
		{"R5", archiveRecovery, 0, "RECOVERY_REQUIRED", false},
		{"R6", busySide, 1, "LOCAL_BUSY", false},
		{"R7", modelPrune(false), 15120, "LOCAL_BUSY", false},
		{"R8", modelBase(1, 0, 0), 1, "", false},
		{"R9", func() StorageAuthorityV1 {
			a := modelBase(1, 0, 0)
			a.NextGenerationID = 3
			a.SelectedSide = modelSide(2, 0, 3, 3, 3)
			return a
		}(), 1439, "", false},
		{"R10", modelBase(1, 0, 1), 0, "", true},
		{"R11", modelBase(1, 1, 13681), 0, "", true},
		{"R12", modelBase(1, 0, 1), -1, "", true},
		{"R13", func() StorageAuthorityV1 { a := archiveSide(2); a.U = 1; return a }(), 0, "", true},
		{"R14", archivePruneRecovery, 0, "RECOVERY_REQUIRED", false},
		{"R15", archiveSide(1), -1, "LOCAL_BUSY", false},
		{"H17d", func() StorageAuthorityV1 { a := archiveSide(2); a.U = 1; return a }(), 1, "LOCAL_BUSY", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, path, cfg, rows := archiveSeed(t, row.a, row.h, modelWork(false))
			before := prunedImage(t, s, rows)
			owner := bootstrapOwner(t)
			out := s.SelectArchiveProfileV1(owner)
			if row.decision != "" {
				prunedDecision(t, out, row.decision, row.name)
			} else {
				class, op, diagnostic, reopen := EngineStateMismatch, operationUpdate, "archive above genesis is owned by the selected-side and replay-entry leaves", false
				if row.integrity {
					class, op, diagnostic, reopen = EngineIntegrity, operationGet, "archive profile promises disagree with tip", true
				}
				code := codeProblem
				if row.integrity {
					code = codeInvalid
				}
				bootstrapRefusal(t, row.name, out.Truth, out.Err, class, op, code, diagnostic, nil, reopen)
				if out.Stage != 1 {
					t.Fatal("refusal stage")
				}
				archiveEmptyPayload(t, out)
			}
			if row.integrity {
				if s.state != storeCLOSED || s.env != nil || s.writer != nil || s.txn != nil {
					t.Fatal("integrity consumption")
				}
				archiveCached(t, s, out, owner)
				r, e := Open(path, cfg)
				mustEnvironment(t, e)
				defer func() { _ = r.Close() }()
				if !reflect.DeepEqual(prunedImage(t, r, rows), before) {
					t.Fatal("integrity old image")
				}
			} else {
				prunedUnchanged(t, s, rows, before, row.name)
				next := s.SelectArchiveProfileV1(owner)
				if next.Truth != out.Truth || next.Stage != out.Stage || next.Decision != out.Decision || next.Authority != nil {
					t.Fatal("refusal reuse")
				}
				if out.Err != nil {
					bootstrapRefusal(t, "staged next tuple", next.Truth, next.Err, EngineStateMismatch, operationUpdate, codeProblem, "archive above genesis is owned by the selected-side and replay-entry leaves", nil, false)
				} else if next.Err != nil {
					t.Fatal("clean refusal next error")
				}
				prunedUnchanged(t, s, rows, before, row.name)
			}
			prunedReleased(t, owner)
		})
	}
	for _, row := range []struct {
		name       string
		h          uint64
		work       [40]byte
		diagnostic string
	}{{"H3", 1, modelWork(false), "archive canonical index does not start at genesis"}, {"H4", 0, [40]byte{}, "invalid archive profile genesis work"}, {"H5", 0, func() [40]byte { w := modelWork(true); w[39] = 1; return w }(), "invalid archive profile genesis work"}} {
		t.Run(row.name, func(t *testing.T) {
			s, path, cfg, rows := prunedStore(t, modelBase(1, 0, 0), &AuthorityPointV1{Height: row.h, BlockHash: modelHash(71)}, row.work)
			before := prunedImage(t, s, rows)
			owner := bootstrapOwner(t)
			out := s.SelectArchiveProfileV1(owner)
			bootstrapRefusal(t, row.name, out.Truth, out.Err, EngineIntegrity, operationGet, codeInvalid, row.diagnostic, nil, true)
			archiveEmptyPayload(t, out)
			if out.Stage != 1 || s.state != storeCLOSED {
				t.Fatal("canonical failure disposition")
			}
			archiveCached(t, s, out, owner)
			r, e := Open(path, cfg)
			mustEnvironment(t, e)
			defer func() { _ = r.Close() }()
			if !reflect.DeepEqual(prunedImage(t, r, rows), before) {
				t.Fatal("canonical old image")
			}
		})
	}
	t.Run("H1", func(t *testing.T) {
		s, path, cfg := consultedStore(t)
		before := bootstrapCounts(t, s, "absent")
		owner := bootstrapOwner(t)
		out := s.SelectArchiveProfileV1(owner)
		bootstrapRefusal(t, "absent authority", out.Truth, out.Err, EngineIntegrity, operationGet, codeInvalid, "invalid storage authority", errSchema, true)
		archiveEmptyPayload(t, out)
		if out.Stage != 1 || s.state != storeCLOSED {
			t.Fatal("absent disposition")
		}
		archiveCached(t, s, out, owner)
		r, e := Open(path, cfg)
		mustEnvironment(t, e)
		defer func() { _ = r.Close() }()
		if bootstrapCounts(t, r, "absent unchanged") != before {
			t.Fatal("absent image census")
		}
		bootstrapRequireRow(t, r, []byte{2}, nil, "absent remains")
	})
}

func testArchiveHeadroom(t *testing.T, headroom uint64) {
	s, _, _, rows := archiveSeed(t, modelBase(1, 0, 0), -1, modelWork(false))
	before := prunedImage(t, s, rows)
	owner := bootstrapOwner(t)
	mustEnvironment(t, owner.WithReservation(154611151-headroom, func() error {
		live := owner.shared.live
		out := s.SelectArchiveProfileV1(owner)
		if headroom < 512 {
			if !sameError(out.Err, errOperationReservationCapacity) || out.Truth != 1 || out.Stage != 1 {
				t.Fatalf("512-byte reservation: %+v", out)
			}
			archiveEmptyPayload(t, out)
			prunedUnchanged(t, s, rows, before, "headroom refusal")
		} else if out.Err != nil || out.Truth != 2 || out.Stage != 3 || out.Authority == nil || out.Decision != "" {
			t.Fatalf("headroom success: %+v", out)
		}
		if owner.shared.live != live {
			t.Fatal("headroom grant not restored")
		}
		return nil
	}))
	if headroom < 512 {
		out := s.SelectArchiveProfileV1(owner)
		if out.Err != nil || out.Truth != 2 {
			t.Fatal("headroom same owner next")
		}
	}
	prunedReleased(t, owner)
}

func testArchiveReservation(t *testing.T) {
	t.Run("terminal", func(t *testing.T) {
		s, _, _, _ := archiveSeed(t, modelBase(1, 0, 0), -1, modelWork(false))
		mustEnvironment(t, s.Close())
		owner := bootstrapOwner(t)
		terminal, truth := s.terminal, s.terminalTruth
		mustEnvironment(t, owner.WithReservation(154611151, func() error {
			out := s.SelectArchiveProfileV1(owner)
			if !sameError(out.Err, errOperationReservationCapacity) || out.Truth != 1 || out.Stage != 1 {
				t.Fatal("capacity before terminal")
			}
			archiveEmptyPayload(t, out)
			if s.state != storeCLOSED || !sameError(s.terminal, terminal) || s.terminalTruth != truth {
				t.Fatal("capacity changed terminal")
			}
			return nil
		}))
		prunedReleased(t, owner)
	})
	for _, headroom := range []uint64{0, 512, 1024} {
		t.Run(fmt.Sprint(headroom), func(t *testing.T) { testArchiveHeadroom(t, headroom) })
	}
	for _, owner := range []*OperationReservationOwner{nil, {}} {
		s, _, _, rows := archiveSeed(t, modelBase(1, 0, 0), -1, modelWork(false))
		before := prunedImage(t, s, rows)
		out := s.SelectArchiveProfileV1(owner)
		if !sameError(out.Err, errOperationReservationInput) || out.Truth != 1 || out.Stage != 1 {
			t.Fatal("reservation input")
		}
		archiveEmptyPayload(t, out)
		prunedUnchanged(t, s, rows, before, "input")
		mustEnvironment(t, s.Close())
		out = s.SelectArchiveProfileV1(owner)
		if !sameError(out.Err, errOperationReservationInput) {
			t.Fatal("input before terminal")
		}
	}
}

func testArchiveProjection(t *testing.T) {
	a := modelBase(2, 0, 0)
	sentinel := errors.New("decision")
	primary := nativeError(operationUpdate, codeENOSPC)
	cleanup := nativeError(operationAbort, codeEIO)
	var typedNil *EngineError
	caused := &CommitError{Truth: 2, Cause: primary, ReadbackCause: cleanup}
	for _, row := range []struct {
		name      string
		truth     CommitTruth
		stage     UpdateStage
		plan      *StorageAuthorityV1
		err       error
		decision  string
		authority *StorageAuthorityV1
	}{
		{"new_crossed_ok", 2, 3, &a, nil, "", &a},
		{"new_crossed_commit_error", 2, 3, &a, caused, "", &a},
		{"new_crossed_no_plan", 2, 3, nil, primary, "", nil},
		{"unknown_crossed", 3, 3, &a, fmt.Errorf("wrapped: %w", primary), "", nil},
		{"old_write_started", 1, 2, &a, nil, "", nil},
		{"invalid_typed_nil", 1, 0, &a, typedNil, "", nil},
		{"sentinel_new_prewrite", 2, 1, &a, sentinel, "", nil},
		{"sentinel_old_prewrite", 1, 1, &a, sentinel, "PROFILE_NOOP", nil},
		{"sentinel_old_crossed", 1, 3, &a, sentinel, "", nil},
		{"sentinel_wrapped", 1, 1, &a, fmt.Errorf("wrapped: %w", sentinel), "", nil},
		{"sentinel_join_first", 1, 1, &a, errors.Join(sentinel, cleanup), "", nil},
		{"sentinel_join_last", 1, 1, &a, errors.Join(cleanup, sentinel), "", nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			raw := ArchiveProfileOutcome{Truth: row.truth, Stage: row.stage, Err: row.err}
			out := archiveProfileOutcome(raw, row.plan, "PROFILE_NOOP", sentinel)
			wantErr := row.err
			if row.decision != "" {
				wantErr = nil
			}
			if out.Truth != row.truth || out.Stage != row.stage || !sameError(out.Err, wantErr) || out.Decision != row.decision || out.Authority != row.authority {
				t.Fatalf("archive projection %s: %+v", row.name, out)
			}
		})
	}
}

func testArchiveAbort(t *testing.T) {
	for _, code := range []int{codeSuccess, codeEIO, codeCorrupted} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			s, _, _, _ := archiveSeed(t, modelBase(2, 0, 0), -1, modelWork(false))
			sentinel := errors.New("decision")
			err := s.applyReadAbort(nil, sentinel, false, code)
			out := archiveProfileOutcome(ArchiveProfileOutcome{Truth: 1, Stage: 1, Err: err}, nil, "PROFILE_NOOP", sentinel)
			owner := bootstrapOwner(t)
			if code == codeSuccess {
				prunedDecision(t, out, "PROFILE_NOOP", "abort success")
				bootstrapOpenUnchanged(t, s, "abort success")
				next := s.SelectArchiveProfileV1(owner)
				if next.Stage != 1 || next.Err != nil || next.Decision != "PROFILE_NOOP" || next.Truth != 1 || next.Authority != nil || s.state != storeOPEN {
					t.Fatal("abort reusable reader")
				}
			} else {
				parts := err.(interface{ Unwrap() []error }).Unwrap()
				if len(parts) != 2 || !sameError(parts[0], sentinel) || !sameError(out.Err, err) {
					t.Fatal("sentinel abort join order")
				}
				class := EngineIO
				if code == codeCorrupted {
					class = EngineIntegrity
				}
				requireEnvironmentError(t, parts[1], class, operationAbort, code, expectedNativeDiagnostic(code))
				archiveEmptyPayload(t, out)
				if s.state != storeCLOSED {
					t.Fatal("abort consumption")
				}
				archiveCached(t, s, out, owner)
			}
			prunedReleased(t, owner)
		})
	}
	t.Run("synthetic_thread_identity", func(t *testing.T) {
		s := newUpdateStore(t)
		cfg, dbis := s.config, s.dbis
		txn := s.txn
		mustEnvironment(t, s.View(func(r *Reader) error { txn = r.txn; return nil }))
		sentinel := errors.New("decision")
		err := s.applyReadAbort(txn, sentinel, false, codeThreadMismatch)
		engine := requireEnvironmentError(t, err, EngineLocalInvariant, operationAbort, codeThreadMismatch, expectedNativeDiagnostic(codeThreadMismatch))
		if !sameError(engine.Cause, sentinel) || s.state != storePOISONEDTHREAD || s.txn != txn {
			t.Fatal("synthetic abort identity")
		}
		out := archiveProfileOutcome(ArchiveProfileOutcome{Truth: 1, Stage: 1, Err: err}, nil, "PROFILE_NOOP", sentinel)
		archiveEmptyPayload(t, out)
		archiveCached(t, s, out, bootstrapOwner(t))
		s.state, s.txn, s.config, s.dbis, s.terminal, s.terminalTruth = storeOPEN, nil, cfg, dbis, nil, 0
		mustEnvironment(t, s.Close())
	})
}

func testArchiveReadComposition(t *testing.T) {
	for _, row := range []struct {
		name       string
		rc         int
		length     int
		class      EngineClass
		code       int
		diagnostic string
	}{{"EIO", codeEIO, 0, EngineIO, codeEIO, expectedNativeDiagnostic(codeEIO)}, {"pointer", codeSuccess, 1, EngineLocalInvariant, codeProblem, "mdbx_get returned invalid result shape"}, {"length", codeNotFound, 1, EngineLocalInvariant, codeProblem, "mdbx_get returned invalid result shape"}, {"width", codeSuccess, 1048577, EngineIntegrity, codeInvalid, "stored value width outside SchemaV2 bound"}} {
		t.Run(row.name, func(t *testing.T) {
			var err error
			switch row.length {
			case 1:
				_, _, err = copiedGetResult(readDBIsLiteral()[0], []byte{2}, row.rc, unsafe.Pointer(nil), 1)
			case 1048577:
				buffer := [1]byte{0}
				_, _, err = copiedGetResult(readDBIsLiteral()[0], []byte{2}, row.rc, unsafe.Pointer(&buffer[0]), 1048577)
			default:
				_, _, err = copiedGetResult(readDBIsLiteral()[0], []byte{2}, row.rc, nil, 0)
			}
			requireEnvironmentError(t, err, row.class, operationGet, row.code, row.diagnostic)
			s := newUpdateStore(t)
			terminal := s.applyReadAbort(nil, err, true, codeSuccess)
			out := archiveProfileOutcome(ArchiveProfileOutcome{Truth: 1, Stage: 1, Err: terminal}, nil, "", errors.New("decision"))
			if !sameError(out.Err, err) || s.state != storeCLOSED {
				t.Fatal("read composition raw identity")
			}
			archiveEmptyPayload(t, out)
			archiveCached(t, s, out, bootstrapOwner(t))
		})
	}
}
