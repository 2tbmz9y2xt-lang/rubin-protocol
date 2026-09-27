//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func prunedStore(t *testing.T, a StorageAuthorityV1, tip *AuthorityPointV1, work [40]byte) (*Store, string, ConfigV1, []Mutation) {
	t.Helper()
	s, path, cfg := consultedStore(t)
	encoded, err := a.Encode()
	mustEnvironment(t, err)
	rows := []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}, AfterKind: AfterLiteral, Literal: encoded}, consultedCounter(t, 99)}
	fixture := updatePlanBatch(t).Mutations
	rows = append(rows, fixture[3]) // A live UTXO survives every profile decision.
	if tip != nil {
		key, keyErr := HeightKey(a.ActiveGenerationID, tip.Height)
		mustEnvironment(t, keyErr)
		rows = append(rows, Mutation{DBI: readDBIsLiteral()[2], Key: key, AfterKind: AfterLiteral, Literal: ChainValue(tip.BlockHash, [32]byte{}, work)})
	}
	rows = append(rows, fixture[5], fixture[6], fixture[7], fixture[9])
	consultedRequireCommit(t, s, "pruned fixture", Batch{Mutations: rows})
	return s, path, cfg, rows
}

func prunedImage(t *testing.T, s *Store, rows []Mutation) [][]byte {
	t.Helper()
	image := make([][]byte, len(rows)+2)
	mustEnvironment(t, s.View(func(r *Reader) error {
		for i, row := range append(append([]Mutation(nil), rows...), Mutation{DBI: readDBIsLiteral()[0], Key: []byte{0}}, Mutation{DBI: readDBIsLiteral()[0], Key: []byte{1}}) {
			value, present, err := r.Get(row.DBI, row.Key)
			if err != nil || !present {
				return fmt.Errorf("pruned snapshot row %d: present=%v: %w", i, present, err)
			}
			image[i] = value
		}
		return nil
	}))
	return image
}

func prunedUnchanged(t *testing.T, s *Store, rows []Mutation, before [][]byte, marker string) {
	t.Helper()
	if !reflect.DeepEqual(prunedImage(t, s, rows), before) {
		t.Fatal(marker + ": old image changed")
	}
	bootstrapOpenUnchanged(t, s, marker)
}

func prunedDecision(t *testing.T, out PrunedProfileOutcome, want, marker string) {
	t.Helper()
	if out.Decision != want || out.Authority != nil || out.Truth != 1 || out.Stage != 1 || out.Err != nil {
		t.Fatalf("%s: %+v", marker, out)
	}
}

func prunedReleased(t *testing.T, owner *OperationReservationOwner) {
	t.Helper()
	mustEnvironment(t, owner.WithReservation(154611151, func() error { return nil }))
}

func TestPrunedProfile(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		for _, row := range []struct {
			name      string
			height, u uint64
			empty     bool
		}{
			{"PRE_GENESIS", 0, 0, true}, {"H0", 0, 0, false}, {"H1", 1, 0, false}, {"H1439", 1439, 0, false}, {"H1440", 1440, 1, false}, {"H15119", 15119, 13680, false},
		} {
			t.Run(row.name, func(t *testing.T) {
				tip := &AuthorityPointV1{Height: row.height, BlockHash: modelHash(41)}
				if row.empty {
					tip = nil
				}
				a := modelBase(2, 0, row.u)
				s, _, _, rows := prunedStore(t, a, tip, modelWork(false))
				before, counts := prunedImage(t, s, rows), bootstrapCounts(t, s, "zero")
				owner := bootstrapOwner(t)
				out := s.SelectPrunedProfileV1(true, tip, owner)
				a.ActiveProfile = 1
				if out.Err != nil || out.Decision != "" || out.Truth != 2 || out.Stage != 3 || !reflect.DeepEqual(out.Authority, &a) {
					t.Fatalf("pruned profile promise drifted: %+v", out)
				}
				before[0][1] = 1
				if !reflect.DeepEqual(prunedImage(t, s, rows), before) || bootstrapCounts(t, s, "zero") != counts {
					t.Fatal("pruned profile zero image drifted")
				}
				prunedReleased(t, owner)
			})
		}
	})
	t.Run("positive", func(t *testing.T) {
		for _, row := range []struct{ h, b, u, last uint64 }{{15120, 1, 13681, 0}, {15121, 2, 13682, 1}, {0xffffffff, 4294952176, 4294965856, 4294952175}} {
			t.Run(fmt.Sprint(row.h), func(t *testing.T) {
				tip := &AuthorityPointV1{Height: row.h, BlockHash: modelHash(71)}
				a := modelBase(2, 0, row.u)
				s, _, _, rows := prunedStore(t, a, tip, modelWork(false))
				before := prunedImage(t, s, rows)
				out := s.SelectPrunedProfileV1(true, tip, bootstrapOwner(t))
				if out.Err != nil || out.Truth != 2 || out.Stage != 3 || out.Authority == nil {
					t.Fatalf("pruned profile exact span drifted: %+v", out)
				}
				if out.Authority.B != row.b || out.Authority.U != row.u || out.Authority.ActiveProfile != 1 {
					t.Fatalf("pruned profile promise drifted: %+v", out.Authority)
				}
				a.ActiveProfile, a.B, a.Phase = 1, row.b, 2
				a.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 2, GenerationID: 1, FirstHeight: 0, LastHeight: row.last, NextHeight: 0}}}
				if !reflect.DeepEqual(out.Authority, &a) {
					t.Fatalf("pruned profile exact span drifted: %+v", out.Authority)
				}
				after := prunedImage(t, s, rows)
				if !reflect.DeepEqual(before[1:], after[1:]) {
					t.Fatal("pruned profile positive data changed")
				}
				decoded, err := DecodeStorageAuthorityV1(after[0])
				mustEnvironment(t, err)
				if !reflect.DeepEqual(decoded, a) {
					t.Fatal("pruned profile durable span drifted")
				}
			})
		}
	})
	t.Run("confirmation", func(t *testing.T) {
		for _, h := range []uint64{0, 0x100000000, ^uint64(0)} {
			s, _, _, rows := prunedStore(t, modelBase(2, 0, 0), nil, modelWork(false))
			before := prunedImage(t, s, rows)
			owner, tip := bootstrapOwner(t), &AuthorityPointV1{Height: h}
			prunedDecision(t, s.SelectPrunedProfileV1(false, tip, owner), "PROFILE_CONFIRMATION_REQUIRED", "pruned profile confirmation order drifted")
			prunedUnchanged(t, s, rows, before, "pruned profile confirmation order drifted")
			out := s.SelectPrunedProfileV1(true, tip, owner)
			if h == 0 {
				prunedDecision(t, out, "STALE_LOCAL_PLAN", "pruned profile confirmation order drifted")
			} else {
				bootstrapRefusal(t, "pruned profile confirmation order drifted", out.Truth, out.Err, EngineInvalidInput, operationUpdate, codeEINVAL, "invalid pruned profile tip", nil, false)
			}
			prunedUnchanged(t, s, rows, before, "pruned profile confirmation order drifted")
			prunedReleased(t, owner)
		}
	})
	t.Run("phase_order", testPrunedPhaseOrder)
	t.Run("preservation", testPrunedPreservation)
	t.Run("tip", testPrunedTip)
	t.Run("integrity", testPrunedIntegrity)
	t.Run("reopen", func(t *testing.T) {
		tip := &AuthorityPointV1{Height: 15120, BlockHash: modelHash(13)}
		s, path, cfg, rows := prunedStore(t, modelBase(2, 0, 13681), tip, modelWork(false))
		before := prunedImage(t, s, rows)
		prunedDecision(t, s.SelectPrunedProfileV1(false, tip, bootstrapOwner(t)), "PROFILE_CONFIRMATION_REQUIRED", "reopen refusal")
		prunedUnchanged(t, s, rows, before, "reopen refusal")
		out := s.SelectPrunedProfileV1(true, tip, bootstrapOwner(t))
		if out.Err != nil || out.Truth != 2 || out.Authority == nil {
			t.Fatalf("reopen conversion: %+v", out)
		}
		after := prunedImage(t, s, rows)
		mustEnvironment(t, s.Close())
		reopened, err := Open(path, cfg)
		mustEnvironment(t, err)
		defer func() { _ = reopened.Close() }()
		if !reflect.DeepEqual(prunedImage(t, reopened, rows), after) {
			t.Fatal("pruned profile reopen image drifted")
		}
		prunedDecision(t, reopened.SelectPrunedProfileV1(false, nil, bootstrapOwner(t)), "PROFILE_NOOP", "reopen noop")
		prunedUnchanged(t, reopened, rows, after, "reopen noop")
	})
	t.Run("capacity", testPrunedCapacity)
	t.Run("outcome", testPrunedOutcome)
}

func testPrunedPhaseOrder(t *testing.T) {
	bad := &AuthorityPointV1{Height: ^uint64(0)}
	check := func(name string, a StorageAuthorityV1, want string) {
		t.Run(name, func(t *testing.T) {
			s, _, _, rows := prunedStore(t, a, nil, modelWork(false))
			before, owner := prunedImage(t, s, rows), bootstrapOwner(t)
			prunedDecision(t, s.SelectPrunedProfileV1(false, bad, owner), want, "pruned profile phase order drifted")
			prunedUnchanged(t, s, rows, before, "pruned profile phase order drifted")
			prunedReleased(t, owner)
		})
	}
	check("NONE", modelBase(1, 0, 0), "PROFILE_NOOP")
	// Every nonempty ordered subset; ARCHIVE has no legal BLOCKS span because B=0.
	for _, profile := range []byte{1, 2} {
		for mask := 1; mask < 16; mask++ {
			if profile == 2 && mask&2 != 0 {
				continue
			}
			for _, progress := range []uint64{0, 1, 2} {
				a := modelBase(profile, 0, 13683)
				if profile == 1 {
					a.B = 3
				}
				a.NextGenerationID, a.Phase = 4, 2
				a.Cleanup = &CleanupV1{}
				for i, span := range []CleanupSpanV1{{Kind: 1, GenerationID: 3}, {Kind: 2, GenerationID: 1, LastHeight: 2, NextHeight: progress}, {Kind: 3, GenerationID: 1, LastHeight: 2, NextHeight: progress}, {Kind: 4, GenerationID: 2, LastHeight: 2, NextHeight: progress}} {
					if mask&(1<<i) != 0 {
						a.Cleanup.Spans = append(a.Cleanup.Spans, span)
					}
				}
				want := "PROFILE_NOOP"
				if profile == 2 {
					want = "LOCAL_BUSY"
				}
				check(fmt.Sprintf("profile%d/spans%d/progress%d", profile, mask, progress), a, want)
			}
		}
		for _, pending := range []StorageProfileV1{1, 2} {
			a := modelBase(profile, 0, 0)
			a.NextGenerationID, a.Phase, a.Lifecycle = 3, 2, 2
			a.Cleanup, a.PendingTargetProfile = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 1, GenerationID: 2}}}, &pending
			check(fmt.Sprintf("profile%d/PRUNE_RECOVERY/pending%d", profile, pending), a, "RECOVERY_REQUIRED")
			a.DetachedSuffix = modelDetached(1, 1)
			check(fmt.Sprintf("profile%d/PRUNE_RECOVERY/pending%d/detached", profile, pending), a, "RECOVERY_REQUIRED")
		}
		a := modelBase(profile, 0, 0)
		a.NextGenerationID, a.Phase = 3, 2
		a.Cleanup, a.DetachedSuffix = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 1, GenerationID: 2}}}, modelDetached(1, 1)
		want := "PROFILE_NOOP"
		if profile == 2 {
			want = "LOCAL_BUSY"
		}
		check(fmt.Sprintf("profile%d/PRUNE_STABLE/detached", profile), a, want)
		for _, cursor := range []byte{1, 2} {
			for _, target := range []StorageProfileV1{1, 2} {
				a := modelReplay(cursor)
				a.ActiveProfile, a.Replay.TargetProfile = StorageProfileV1(profile), target
				check(fmt.Sprintf("profile%d/REPLAY/cursor%d/target%d", profile, cursor, target), a, "RECOVERY_REQUIRED")
			}
		}
		for _, stage := range []byte{1, 2, 3, 4} {
			a := modelOrdinary(stage, 2, 2, 2, profile, 0, 0)
			check(fmt.Sprintf("profile%d/ORDINARY/stage%d", profile, stage), a, "RECOVERY_REQUIRED")
		}
	}
}

func testPrunedPreservation(t *testing.T) {
	a := modelBase(2, 0, 13682)
	a.ActiveGenerationID, a.NextGenerationID = 7, 9
	a.SelectedSide = modelSide(8, 9, 11, 2, 3)
	a.ExcludedInvalidBranch = &InvalidBranchV1{FirstInvalidHeight: 4, FirstInvalidBlockHash: modelHash(33), ExactConsensusError: []byte{0, 0xff, 0x80}}
	tip := &AuthorityPointV1{Height: 15121, BlockHash: modelHash(67)}
	s, _, _, rows := prunedStore(t, a, tip, modelWork(false))
	other, err := HeightKey(8, 99)
	mustEnvironment(t, err)
	extra := []Mutation{{DBI: readDBIsLiteral()[2], Key: other, AfterKind: AfterLiteral, Literal: ChainValue(modelHash(77), [32]byte{}, modelWork(false))}, {DBI: readDBIsLiteral()[3], Key: make([]byte, 32), AfterKind: AfterLiteral, Literal: make([]byte, 116)}}
	consultedRequireCommit(t, s, "preservation extras", Batch{Mutations: extra})
	rows = append(rows, extra...)
	before, counts := prunedImage(t, s, rows), bootstrapCounts(t, s, "preservation")
	out := s.SelectPrunedProfileV1(true, tip, bootstrapOwner(t))
	a.ActiveProfile, a.B, a.Phase = 1, 2, 2
	a.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 2, GenerationID: 7, LastHeight: 1}}}
	if out.Err != nil || !reflect.DeepEqual(out.Authority, &a) {
		t.Fatalf("pruned profile preserved authority drifted: %+v", out)
	}
	after := prunedImage(t, s, rows)
	if !reflect.DeepEqual(before[1:], after[1:]) || bootstrapCounts(t, s, "preservation") != counts {
		t.Fatal("pruned profile preserved authority drifted")
	}
	want, err := a.Encode()
	mustEnvironment(t, err)
	if !bytes.Equal(after[0], want) {
		t.Fatal("pruned profile preserved authority drifted")
	}
	tip.Height, tip.BlockHash = 3, [32]byte{}
	out.Authority.ActiveGenerationID = 99
	out.Authority.SelectedSide.TipHeight = 500
	out.Authority.ExcludedInvalidBranch.ExactConsensusError[0] ^= 1
	out.Authority.Cleanup.Spans[0].NextHeight = 1
	if !reflect.DeepEqual(prunedImage(t, s, rows), after) {
		t.Fatal("pruned profile output alias drifted")
	}
}

func testPrunedTip(t *testing.T) {
	for _, name := range []string{"nil-nonempty", "missing", "lower-later", "hash", "zero-mismatch", "over32", "max64"} {
		t.Run(name, func(t *testing.T) {
			actual := &AuthorityPointV1{Height: 0, BlockHash: modelHash(5)}
			s, _, _, rows := prunedStore(t, modelBase(2, 0, 0), actual, modelWork(false))
			expected := *actual
			tip := &expected
			switch name {
			case "nil-nonempty":
				tip = nil
			case "missing":
				expected.Height = 1
			case "lower-later":
				key, err := HeightKey(1, 1)
				mustEnvironment(t, err)
				extra := Mutation{DBI: readDBIsLiteral()[2], Key: key, AfterKind: AfterLiteral, Literal: ChainValue(modelHash(6), actual.BlockHash, modelWork(false))}
				consultedRequireCommit(t, s, "later tip", Batch{Mutations: []Mutation{extra}})
				rows = append(rows, extra)
			case "hash":
				expected.BlockHash = modelHash(9)
			case "zero-mismatch":
				expected.BlockHash = [32]byte{}
			case "over32":
				expected.Height = 0x100000000
			case "max64":
				expected.Height = ^uint64(0)
			}
			before, owner := prunedImage(t, s, rows), bootstrapOwner(t)
			out := s.SelectPrunedProfileV1(true, tip, owner)
			if name == "over32" || name == "max64" {
				bootstrapRefusal(t, "pruned profile committed tip drifted", out.Truth, out.Err, EngineInvalidInput, operationUpdate, codeEINVAL, "invalid pruned profile tip", nil, false)
				if out.Authority != nil || out.Decision != "" || out.Stage != 1 {
					t.Fatal("pruned profile committed tip drifted")
				}
			} else {
				prunedDecision(t, out, "STALE_LOCAL_PLAN", "pruned profile committed tip drifted")
			}
			prunedUnchanged(t, s, rows, before, "pruned profile committed tip drifted")
			prunedReleased(t, owner)
		})
	}
	t.Run("zero-exact", func(t *testing.T) {
		tip := &AuthorityPointV1{}
		s, _, _, _ := prunedStore(t, modelBase(2, 0, 0), tip, modelWork(false))
		out := s.SelectPrunedProfileV1(true, tip, bootstrapOwner(t))
		if out.Err != nil || out.Truth != 2 || out.Authority == nil {
			t.Fatal("pruned profile committed tip drifted")
		}
	})
}

func testPrunedIntegrity(t *testing.T) {
	for _, name := range []string{"work0", "work1", "work-max", "work-over", "work0-wrong-hash", "work-over-wrong-hash", "old-U"} {
		t.Run(name, func(t *testing.T) {
			work, a := modelWork(false), modelBase(2, 0, 0)
			switch name {
			case "work0", "work0-wrong-hash":
				work = [40]byte{}
			case "work-max":
				work = modelWork(true)
			case "work-over", "work-over-wrong-hash":
				work = modelWork(true)
				work[39] = 1
			case "old-U":
				a.U = 1
			}
			tip := &AuthorityPointV1{BlockHash: modelHash(15)}
			s, path, cfg, rows := prunedStore(t, a, tip, work)
			before, owner := prunedImage(t, s, rows), bootstrapOwner(t)
			if strings.Contains(name, "wrong-hash") {
				tip.BlockHash = modelHash(20)
			}
			out := s.SelectPrunedProfileV1(true, tip, owner)
			if name == "work1" || name == "work-max" {
				if out.Err != nil || out.Truth != 2 || out.Authority == nil {
					t.Fatalf("pruned profile tip work drifted: %+v", out)
				}
			} else {
				diagnostic, marker := "invalid pruned profile tip work", "pruned profile tip work drifted"
				if name == "old-U" {
					diagnostic, marker = "pruned profile promises disagree with tip", "pruned profile old promise integrity drifted"
				}
				bootstrapRefusal(t, marker, out.Truth, out.Err, EngineIntegrity, operationGet, codeInvalid, diagnostic, nil, false)
				if out.Authority != nil || out.Decision != "" || out.Stage != 1 || s.state != storeCLOSED {
					t.Fatal(marker)
				}
				again := s.SelectPrunedProfileV1(true, nil, owner)
				if !sameError(again.Err, out.Err) || again.Truth != 1 || again.Stage != 1 {
					t.Fatal(marker + ": terminal reuse")
				}
				reopened, err := Open(path, cfg)
				mustEnvironment(t, err)
				defer func() { _ = reopened.Close() }()
				if !reflect.DeepEqual(prunedImage(t, reopened, rows), before) {
					t.Fatal(marker + ": durable old changed")
				}
			}
			prunedReleased(t, owner)
		})
	}
}

func testPrunedCapacity(t *testing.T) {
	for _, large := range []bool{false, true} {
		for _, remaining := range []uint64{343, 344} {
			t.Run(fmt.Sprintf("reservation/%v/%d", large, remaining), func(t *testing.T) {
				a := modelBase(2, 0, 0)
				if large {
					a.ExcludedInvalidBranch = &InvalidBranchV1{ExactConsensusError: bytes.Repeat([]byte{1}, 1048492)}
				}
				s, _, _, rows := prunedStore(t, a, nil, modelWork(false))
				before := prunedImage(t, s, rows)
				owner := bootstrapOwner(t)
				mustEnvironment(t, owner.WithReservation(154611151-remaining, func() error {
					out := s.SelectPrunedProfileV1(true, nil, owner)
					if remaining == 343 {
						if !sameError(out.Err, errOperationReservationCapacity) || out.Truth != 1 || out.Stage != 1 || out.Authority != nil || out.Decision != "" {
							t.Fatal("pruned profile reservation boundary drifted")
						}
						prunedUnchanged(t, s, rows, before, "pruned profile reservation boundary drifted")
					} else if out.Err != nil || out.Truth != 2 || out.Authority == nil {
						t.Fatalf("pruned profile reservation boundary drifted: %+v", out)
					}
					return nil
				}))
				prunedReleased(t, owner)
			})
		}
	}
	for _, size := range []int{1048576, 1048577} {
		t.Run(fmt.Sprintf("encoded/%d", size), func(t *testing.T) {
			a := modelBase(2, 0, 13681)
			a.ExcludedInvalidBranch = &InvalidBranchV1{ExactConsensusError: bytes.Repeat([]byte{1}, size-118)}
			tip := &AuthorityPointV1{Height: 15120}
			s, _, _, rows := prunedStore(t, a, tip, modelWork(false))
			before := prunedImage(t, s, rows)
			owner := bootstrapOwner(t)
			out := s.SelectPrunedProfileV1(true, tip, owner)
			if size == 1048576 {
				if out.Err != nil || out.Authority == nil || out.Truth != 2 || len(prunedImage(t, s, rows)[0]) != 1048576 {
					t.Fatalf("pruned profile codec capacity drifted: %+v", out)
				}
			} else {
				bootstrapRefusal(t, "pruned profile codec capacity drifted", out.Truth, out.Err, EngineCapacity, operationUpdate, codeTooLarge, "Update Batch exceeds bound", nil, false)
				if out.Authority != nil || out.Decision != "" || out.Stage != 1 {
					t.Fatal("pruned profile codec capacity drifted")
				}
				prunedUnchanged(t, s, rows, before, "pruned profile codec capacity drifted")
			}
			prunedReleased(t, owner)
		})
	}
	t.Run("entry", func(t *testing.T) {
		out := (*Store)(nil).SelectPrunedProfileV1(true, nil, nil)
		bootstrapRefusal(t, "nil store", out.Truth, out.Err, EngineInvalidInput, operationUpdate, codeEINVAL, "nil Store", nil, false)
		s := newUpdateStore(t)
		defer func() { _ = s.Close() }()
		for _, owner := range []*OperationReservationOwner{nil, {}} {
			out = s.SelectPrunedProfileV1(true, &AuthorityPointV1{Height: ^uint64(0)}, owner)
			if !sameError(out.Err, errOperationReservationInput) || out.Truth != 1 || out.Stage != 1 || out.Authority != nil || out.Decision != "" {
				t.Fatal("pruned profile reservation input order drifted")
			}
			bootstrapOpenUnchanged(t, s, "reservation before reader")
		}
	})
}

func testPrunedOutcome(t *testing.T) {
	a, sentinel := modelBase(1, 0, 0), errors.New("invocation decision")
	primary := nativeError(operationUpdate, codeENOSPC)
	for _, truth := range []CommitTruth{1, 2, 3} {
		for _, stage := range []UpdateStage{0, 1, 2, 3} {
			for _, complete := range []bool{false, true} {
				for _, err := range []error{nil, primary, &CommitError{Truth: truth, Cause: primary}} {
					var plan *StorageAuthorityV1
					if complete {
						plan = &a
					}
					raw := PrunedProfileOutcome{Truth: truth, Stage: stage, Err: err}
					out := prunedProfileOutcome(raw, plan, "", sentinel)
					if out.Stage != stage || out.Truth != truth || !sameError(out.Err, err) {
						t.Fatal("pruned profile stage drifted")
					}
					want := truth == 2 && stage == 3 && complete
					if (out.Authority != nil) != want || out.Decision != "" || want && out.Authority != plan {
						t.Fatal("pruned profile outcome ownership drifted")
					}
				}
			}
		}
	}
	for _, err := range []error{sentinel, errors.Join(sentinel, primary), fmt.Errorf("wrapped: %w", sentinel), errors.Join(primary, sentinel)} {
		out := prunedProfileOutcome(PrunedProfileOutcome{Truth: 1, Stage: 1, Err: err}, nil, "PROFILE_NOOP", sentinel)
		if sameError(err, sentinel) {
			prunedDecision(t, out, "PROFILE_NOOP", "pruned profile cleanup provenance drifted")
		} else if !sameError(out.Err, err) || out.Decision != "" || out.Authority != nil {
			t.Fatal("pruned profile cleanup provenance drifted")
		}
	}
	for _, initiating := range []error{sentinel, updateBoundError(), adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "invalid pruned profile replacement", errSchema), nativeError(operationGet, codeEIO)} {
		for _, abortCode := range []int{codeSuccess, codeEIO, codeCorrupted} {
			s := newUpdateStore(t)
			infrastructure := false // No public callback or fault seam.
			engine, isEngine := directTestEngineError(initiating)
			if isEngine {
				infrastructure = engine.Operation == "get"
			}
			err := s.applyReadAbort(nil, initiating, infrastructure, abortCode)
			out := prunedProfileOutcome(PrunedProfileOutcome{Truth: 1, Stage: 1, Err: err}, nil, "PROFILE_NOOP", sentinel)
			if sameError(err, sentinel) {
				prunedDecision(t, out, "PROFILE_NOOP", "pruned profile cleanup provenance drifted")
			} else if !sameError(out.Err, err) || out.Decision != "" || out.Authority != nil {
				t.Fatal("pruned profile cleanup provenance drifted")
			}
			if abortCode != codeSuccess {
				parts, joined := err.(interface{ Unwrap() []error })
				if !joined || len(parts.Unwrap()) != 2 || !sameError(parts.Unwrap()[0], initiating) {
					t.Fatal("pruned profile cleanup provenance drifted")
				}
				wantClass := EngineIO
				if abortCode == codeCorrupted {
					wantClass = EngineIntegrity
				}
				requireEngineError(t, parts.Unwrap()[1], wantClass, operationAbort, abortCode)
			}
			if abortCode == codeSuccess && !infrastructure {
				bootstrapOpenUnchanged(t, s, "pruned profile cleanup reuse")
				mustEnvironment(t, s.Close())
			} else {
				if s.state != storeCLOSED {
					t.Fatal("pruned profile cleanup consumption drifted")
				}
				again := s.SelectPrunedProfileV1(true, nil, bootstrapOwner(t))
				if !sameError(again.Err, err) || again.Authority != nil || again.Stage != 1 {
					t.Fatal("pruned profile cleanup cached error drifted")
				}
			}
		}
	}
	t.Run("invalid-native", func(t *testing.T) {
		s := newUpdateStore(t)
		cleanup := nativeError(operationAbort, codeEIO)
		truth, stage, err := s.applyUpdateOutcome(updateNativeOutcome{}, nil, cleanup, false)
		out := prunedProfileOutcome(PrunedProfileOutcome{Truth: truth, Stage: stage, Err: err}, &a, "", sentinel)
		parts := err.(interface{ Unwrap() []error }).Unwrap()
		if out.Truth != 1 || out.Stage != 0 || out.Authority != nil || !sameError(out.Err, err) || len(parts) != 2 || !sameError(parts[1], cleanup) || s.state != storeCLOSED {
			t.Fatal("pruned profile invalid native shape drifted")
		}
		requireEngineError(t, parts[0], EngineLocalInvariant, operationUpdate, codeProblem)
		again := s.SelectPrunedProfileV1(true, nil, bootstrapOwner(t))
		if !sameError(again.Err, err) || again.Authority != nil || again.Stage != 1 {
			t.Fatal("pruned profile invalid cached shape drifted")
		}
	})
	// Existing Store projection is exercised separately from the public method: no fault injector.
	for _, truth := range []CommitTruth{1, 2, 3} {
		s := newUpdateStore(t)
		native := updateNativeConsumed(truth, true, primary, nil, 3)
		got, stage, err := s.applyUpdateOutcome(native, nil, nil, false)
		out := prunedProfileOutcome(PrunedProfileOutcome{Truth: got, Stage: stage, Err: err}, &a, "", sentinel)
		if out.Truth != truth || out.Stage != 3 || !sameError(out.Err, err) || (out.Authority != nil) != (truth == 2) || s.state != storeCLOSED {
			t.Fatal("pruned profile outcome ownership drifted")
		}
		owner := bootstrapOwner(t)
		again := s.SelectPrunedProfileV1(true, nil, owner)
		if again.Truth != truth || again.Stage != 1 || !sameError(again.Err, err) || again.Authority != nil || again.Decision != "" {
			t.Fatal("pruned profile outcome ownership drifted")
		}
		prunedReleased(t, owner)
	}
}

// prunedResolve follows local function/value aliases, including parenthesized forms.
// It is deliberately limited to this producer's finite source ownership test.
func prunedResolve(expr ast.Expr, seen map[any]bool) ast.Expr {
	switch value := expr.(type) {
	case *ast.ParenExpr:
		return prunedResolve(value.X, seen)
	case *ast.UnaryExpr:
		if value.Op == token.AND {
			return prunedResolve(value.X, seen)
		}
	case *ast.StarExpr:
		return prunedResolve(value.X, seen)
	case *ast.Ident:
		if value.Obj == nil || seen[value.Obj] {
			return expr
		}
		seen[value.Obj] = true
		switch decl := value.Obj.Decl.(type) {
		case *ast.AssignStmt:
			for i, lhs := range decl.Lhs {
				id, ok := lhs.(*ast.Ident)
				if ok && id.Obj == value.Obj && len(decl.Lhs) == len(decl.Rhs) {
					return prunedResolve(decl.Rhs[i], seen)
				}
			}
		case *ast.ValueSpec:
			for i, id := range decl.Names {
				if id.Obj == value.Obj && len(decl.Names) == len(decl.Values) {
					return prunedResolve(decl.Values[i], seen)
				}
			}
		}
	}
	return expr
}

func prunedSourceGuard(source []byte) string {
	file, err := parser.ParseFile(token.NewFileSet(), "pruned_profile_cgo.go", source, 0)
	if err != nil {
		return "pruned profile effect ownership drifted"
	}
	allowed := map[string]string{
		"SelectPrunedProfileV1":    "adapterError|errors.New|reservations.WithReservation|s.Update|reader.Get|SchemaV1DBIs|DecodeStorageAuthorityV1|bootstrapFailure|integrityError|prunedProfileBatch|prunedProfileOutcome",
		"prunedProfileBatch":       "prunedProfileTip|prunedProfileReplacement|SchemaV1DBIs",
		"prunedProfileTip":         "binary.BigEndian.PutUint64|adapterError|HeightKey|reader.Get|SchemaV1DBIs|validWork|bootstrapFailure|integrityError|reader.PrefixPage|len",
		"prunedProfileReplacement": "uint64|laggedPromise|bootstrapFailure|integrityError|ValidateStorageAuthorityV1|adapterError|authoritySize|a.Encode|updateBoundError",
		"prunedProfileOutcome":     "",
	}
	var reservation, update *ast.CallExpr
	var reservationCount, updateCount, mutationSinks, consultedSinks int
	problem := ""
	returned := map[ast.Expr]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "prunedProfileBatch" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			ret, ok := node.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 2 {
				return true
			}
			value := prunedResolve(ret.Results[0], map[any]bool{})
			literal, ok := value.(*ast.CompositeLit)
			if !ok {
				problem = "pruned profile effect ownership drifted"
				return true
			}
			if len(literal.Elts) == 0 {
				return true
			}
			if !returned[value] {
				returned[value] = true
				mutationSinks++
				if !prunedMutationLiteral(literal) {
					problem = "pruned profile effect ownership drifted"
				}
			}
			return true
		})
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			if general, yes := decl.(*ast.GenDecl); yes && general.Tok == token.VAR {
				return "pruned profile effect ownership drifted"
			}
			continue
		}
		calls, known := allowed[fn.Name.Name]
		if !known {
			return "pruned profile effect ownership drifted"
		}
		delete(allowed, fn.Name.Name)
		positions := map[string]token.Pos{}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if _, yes := node.(*ast.GoStmt); yes {
				problem = "pruned profile effect ownership drifted"
			}
			if call, yes := node.(*ast.CallExpr); yes {
				resolved := prunedResolve(call.Fun, map[any]bool{})
				name := updateNativeCallName(resolved)
				if positions[name] == token.NoPos {
					positions[name] = call.Pos()
				}
				if _, literal := resolved.(*ast.FuncLit); literal {
					return true
				}
				if _, conversion := resolved.(*ast.ArrayType); conversion {
					return true
				}
				if !strings.Contains("|"+calls+"|", "|"+name+"|") {
					problem = "pruned profile effect ownership drifted"
				}
				if name == "reservations.WithReservation" {
					reservation, reservationCount = call, reservationCount+1
				}
				if name == "s.Update" {
					update, updateCount = call, updateCount+1
				}
			}
			assignment, yes := node.(*ast.AssignStmt)
			if !yes {
				return true
			}
			for _, lhs := range assignment.Lhs {
				root := lhs
				for {
					switch value := root.(type) {
					case *ast.SelectorExpr:
						root = value.X
					case *ast.IndexExpr:
						root = value.X
					case *ast.ParenExpr:
						root = value.X
					case *ast.StarExpr:
						root = value.X
					default:
						goto rooted
					}
				}
			rooted:
				if !returned[prunedResolve(root, map[any]bool{})] {
					continue
				}
				if _, binding := lhs.(*ast.Ident); binding && assignment.Tok == token.DEFINE {
					continue
				}
				selector, selected := lhs.(*ast.SelectorExpr)
				if !selected || selector.Sel.Name != "Consulted" || fn.Name.Name != "prunedProfileBatch" || len(assignment.Rhs) != 1 {
					problem = "pruned profile effect ownership drifted"
					continue
				}
				consultedSinks++
				rhs := prunedResolve(assignment.Rhs[0], map[any]bool{})
				if !prunedConsultedLiteral(rhs) {
					problem = "pruned profile consulted owner drifted"
				}
			}
			return true
		})
		var order []string
		switch fn.Name.Name {
		case "SelectPrunedProfileV1":
			order = []string{"reservations.WithReservation", "s.Update", "reader.Get", "DecodeStorageAuthorityV1", "prunedProfileBatch"}
		case "prunedProfileBatch":
			order = []string{"prunedProfileTip", "prunedProfileReplacement"}
		case "prunedProfileTip":
			order = []string{"reader.Get", "validWork", "reader.PrefixPage"}
		case "prunedProfileReplacement":
			order = []string{"laggedPromise", "ValidateStorageAuthorityV1", "authoritySize", "a.Encode"}
		}
		previous := token.NoPos
		for _, name := range order {
			if positions[name] <= previous {
				problem = "pruned profile effect ownership drifted"
			}
			previous = positions[name]
		}
	}
	if problem != "" {
		return problem
	}
	if len(allowed) != 0 || reservationCount != 1 || updateCount != 1 || mutationSinks != 1 || reservation == nil || update == nil {
		return "pruned profile effect ownership drifted"
	}
	if update.Pos() < reservation.Pos() || update.End() > reservation.End() {
		return "pruned profile effect ownership drifted"
	}
	if consultedSinks != 1 {
		return "pruned profile consulted owner drifted"
	}
	return ""
}

func prunedMutationLiteral(literal *ast.CompositeLit) bool {
	// Only the expression flowing into the returned Batch is a mutation sink;
	// unrelated composite literals in the same function carry no authority.
	if len(literal.Elts) != 1 {
		return false
	}
	field, ok := literal.Elts[0].(*ast.KeyValueExpr)
	if !ok || updateNativeCallName(field.Key) != "Mutations" {
		return false
	}
	rows, ok := prunedResolve(field.Value, map[any]bool{}).(*ast.CompositeLit)
	if !ok || len(rows.Elts) != 1 {
		return false
	}
	row, ok := rows.Elts[0].(*ast.CompositeLit)
	if !ok {
		return false
	}
	return prunedFields(row, map[string]string{"DBI": "SchemaV1DBIs()[0]", "Key": "[]byte{2}", "BeforePresent": "true", "AfterKind": "AfterLiteral", "Literal": "encoded"})
}

func prunedConsultedLiteral(expr ast.Expr) bool {
	rows, ok := expr.(*ast.CompositeLit)
	if !ok || len(rows.Elts) != 1 {
		return false
	}
	row, ok := rows.Elts[0].(*ast.CompositeLit)
	return ok && prunedFields(row, map[string]string{"DBI": "SchemaV1DBIs()[2]", "Key": "key"})
}

func prunedFields(row *ast.CompositeLit, want map[string]string) bool {
	if len(row.Elts) != len(want) {
		return false
	}
	for _, elt := range row.Elts {
		field, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		name := updateNativeCallName(field.Key)
		value := field.Value
		for {
			paren, ok := value.(*ast.ParenExpr)
			if !ok {
				break
			}
			value = paren.X
		}
		// Resolve local aliases until the operation-owned key/encoded binding.
		if id, ok := value.(*ast.Ident); ok && id.Name != "key" && id.Name != "encoded" {
			value = prunedResolve(value, map[any]bool{})
		}
		// The key and encoded bytes are operation-owned outputs, not aliases to data inputs.
		var out bytes.Buffer
		if err := format.Node(&out, token.NewFileSet(), value); err != nil {
			return false
		}
		if want[name] != out.String() {
			return false
		}
		delete(want, name)
	}
	return len(want) == 0
}

func TestPrunedProfileSourceOwnership(t *testing.T) {
	source, err := os.ReadFile("pruned_profile_cgo.go")
	mustEnvironment(t, err)
	if !bytes.HasPrefix(source, []byte("//go:build cgo && (darwin || linux) && (amd64 || arm64)\n")) {
		t.Fatal("pruned profile effect ownership drifted")
	}
	if problem := prunedSourceGuard(source); problem != "" {
		t.Fatal(problem)
	}
	// Selected and ignored files are both scanned, including node/cmd consumers.
	err = filepath.WalkDir("../..", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || filepath.Base(path) == "pruned_profile_cgo.go" {
			return nil
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.Ident:
				if value.Name == "SelectPrunedProfileV1" || strings.HasPrefix(value.Name, "prunedProfile") {
					t.Errorf("pruned profile effect ownership drifted: caller %s", path)
				}
			}
			return true
		})
		return nil
	})
	mustEnvironment(t, err)
	// These are structural fixtures, never runtime-mutation evidence.
	for _, row := range []struct{ old, replacement, want string }{
		{"batch.Consulted = []ConsultedRow{{DBI: SchemaV1DBIs()[2], Key: key}}", "batch.Consulted = nil", "pruned profile consulted owner drifted"},
		{"return batch, nil", "s := new(Store); s.Update(nil); return batch, nil", "pruned profile effect ownership drifted"},
		{"return batch, nil", "f := reader.Get; f(SchemaV1DBIs()[0], nil); return batch, nil", "pruned profile effect ownership drifted"},
		{"return batch, nil", "func() { reader.Get(SchemaV1DBIs()[0], nil) }(); return batch, nil", "pruned profile effect ownership drifted"},
		{"return batch, nil", "_ = Batch{Mutations: []Mutation{{AfterKind: AfterAbsent}}}; return batch, nil", ""},
		{"return batch, nil", "other := Batch{Mutations: []Mutation{{AfterKind: AfterAbsent}}}; return other, nil", "pruned profile effect ownership drifted"},
		{"return batch, nil", "alias := &batch; alias.Mutations = nil; return batch, nil", "pruned profile effect ownership drifted"},
		{"return batch, nil", "alias := &batch; *alias = Batch{}; return batch, nil", "pruned profile effect ownership drifted"},
		{"return batch, nil", "alias := batch; return alias, nil", ""},
		{"Key: key", "Key: (key)", ""},
		{"return batch, nil", "helper(); return batch, nil", "pruned profile effect ownership drifted"},
	} {
		changed := bytes.Replace(source, []byte(row.old), []byte(row.replacement), 1)
		if bytes.Equal(changed, source) || prunedSourceGuard(changed) != row.want {
			t.Fatalf("pruned profile source fixture drifted: %s", row.replacement)
		}
	}
	wrapped := bytes.Replace(source, []byte("out.Truth, out.Stage, err = s.Update("), []byte("go func() { out.Truth, out.Stage, err = s.Update("), 1)
	async := bytes.Replace(wrapped, []byte("\n\t\treturn err\n\t})"), []byte("\n\t\t}()\n\t\treturn err\n\t})"), 1)
	if bytes.Equal(wrapped, source) || bytes.Equal(async, wrapped) || prunedSourceGuard(async) != "pruned profile effect ownership drifted" {
		t.Fatal("pruned profile source fixture drifted: asynchronous Update")
	}
	alias := bytes.Replace(source, []byte("batch := Batch"), []byte("data := encoded; batch := Batch"), 1)
	alias = bytes.Replace(alias, []byte("Literal: encoded"), []byte("Literal: data"), 1)
	if problem := prunedSourceGuard(alias); problem != "" {
		t.Fatal("pruned profile alias fixture drifted: " + problem)
	}
	alias = bytes.Replace(source, []byte("batch.Consulted ="), []byte("identity := key; batch.Consulted ="), 1)
	alias = bytes.Replace(alias, []byte("Key: key"), []byte("Key: identity"), 1)
	if problem := prunedSourceGuard(alias); problem != "" {
		t.Fatal("pruned profile consulted alias fixture drifted: " + problem)
	}
}
