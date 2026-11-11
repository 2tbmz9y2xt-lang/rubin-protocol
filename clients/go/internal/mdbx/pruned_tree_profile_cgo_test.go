//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"testing"
)

// prunedTreeEnvelope is a STABLE-or-not format-3 envelope with LAG generation 2.
func prunedTreeEnvelope(profile StorageProfileV1, phase StoragePhaseV1, lifecycle StorageLifecycleV1, u uint64) TreeAuthorityV1 {
	return TreeAuthorityV1{Authority: StorageAuthorityV1{Version: 1, ActiveProfile: profile, U: u, ActiveGenerationID: 1, NextGenerationID: 5, Phase: phase, Lifecycle: lifecycle}, LagGenerationID: 2}
}

// prunedTreeSeed creates a format-3 store and inserts the envelope through a pair-only UpdateTreeV1.
func prunedTreeSeed(t *testing.T, a TreeAuthorityV1) (*Store, string, *OperationReservationOwner) {
	t.Helper()
	s, path, _ := treeNativeStore(t)
	o := reservationOwner(t, MinReservationLimit)
	encoded, err := a.Encode()
	mustEnvironment(t, err)
	op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: []byte{2}, AfterKind: AfterLiteral, Literal: encoded}}}}
	r := tsRun(t, s, o, LaneOperation, op)
	r.tuple(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	mustEnvironment(t, r.err)
	return s, path, o
}

func prunedTreeBytes(t *testing.T, s *Store) []byte {
	t.Helper()
	var out []byte
	mustEnvironment(t, s.View(func(r *Reader) error {
		value, present, err := r.Get(TreeSchemaV1DBIs()[0], []byte{2})
		if present {
			out = append([]byte(nil), value...)
		}
		return err
	}))
	return out
}

func prunedTreeLow(t *testing.T) *OperationReservationOwner {
	t.Helper()
	return reservationOwner(t, MinReservationLimit-1)
}

func prunedTreeDecision(t *testing.T, out PrunedTreeProfileOutcomeV1, want, marker string) {
	t.Helper()
	if out.Decision != want || out.Authority != nil || out.Truth != CommitTruthOld || out.Stage != UpdateStagePrewrite || out.Err != nil {
		t.Fatalf("%s: %+v, want decision %q", marker, out, want)
	}
}

func prunedTreeRefusal(t *testing.T, out PrunedTreeProfileOutcomeV1, marker string) {
	t.Helper()
	if out.Decision != "" || out.Authority != nil || out.Truth != CommitTruthOld || out.Stage != UpdateStagePrewrite || out.Err == nil {
		t.Fatalf("%s: %+v", marker, out)
	}
}

// prunedTreeLatched asserts the consumed-Store integrity route of R7, R8, R10, X1 and X2.
func prunedTreeLatched(t *testing.T, s *Store, path string, out PrunedTreeProfileOutcomeV1, before []byte, diagnostic string, owner *OperationReservationOwner) {
	t.Helper()
	if diagnostic != "" {
		bootstrapRefusal(t, diagnostic, out.Truth, out.Err, EngineIntegrity, operationGet, codeInvalid, diagnostic, nil, true)
	}
	prunedTreeRefusal(t, out, "latched tuple")
	if s.state != storeCLOSED {
		t.Fatalf("latched store state %s", s.state)
	}
	again := s.SelectPrunedTreeProfileV1(true, nil, owner)
	if !sameError(again.Err, out.Err) || again.Truth != CommitTruthOld || again.Stage != UpdateStagePrewrite {
		t.Fatalf("latched reuse: %+v", again)
	}
	reopened, err := OpenTreeV1(path, environmentConfig(), [32]byte{7})
	mustEnvironment(t, err)
	defer func() { _ = reopened.Close() }()
	if !bytes.Equal(prunedTreeBytes(t, reopened), before) {
		t.Fatal("latched durable envelope changed")
	}
}

func TestPrunedTreeProfileExactEmpty(t *testing.T) {
	for _, low := range []bool{false, true} {
		s, _, _ := treeNativeStore(t)
		owner := reservationOwner(t, MinReservationLimit)
		if low {
			owner = prunedTreeLow(t)
		}
		before := reservationLive(owner)
		prunedTreeDecision(t, s.SelectPrunedTreeProfileV1(true, nil, owner), "not eligible", "A1 exact empty")
		if reservationLive(owner) != before {
			t.Fatal("A1 owner live changed")
		}
		mustEnvironment(t, s.View(func(r *Reader) error {
			_, present, err := r.ReadTreeAuthorityV1()
			if present {
				t.Fatal("A1 envelope created")
			}
			return err
		}))
	}
}

func TestPrunedTreeProfileControl(t *testing.T) {
	recovery := prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleRecoveryRequiredV1, 0)
	pending := StorageProfilePrunedV1
	recovery.Authority.PendingTargetProfile = &pending
	prunedRecovery := prunedTreeEnvelope(StorageProfilePrunedV1, StoragePhaseNoneV1, StorageLifecycleRecoveryRequiredV1, 0)
	prunedRecovery.Authority.PendingTargetProfile = &pending
	busyArchive := prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhasePruneGCV1, StorageLifecycleStableV1, 0)
	busyArchive.Authority.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: CleanupSpanGenerationV1, GenerationID: 3, FirstHeight: 0, LastHeight: 0, NextHeight: 0}}}
	busyPruned := busyArchive
	busyPruned.Authority.ActiveProfile = StorageProfilePrunedV1
	high := &AuthorityPointV1{Height: 0x100000000}
	for _, row := range []struct {
		name      string
		a         TreeAuthorityV1
		confirmed bool
		tip       *AuthorityPointV1
		want      string
	}{
		{"A2 archive recovery", recovery, false, nil, "RECOVERY_REQUIRED"},
		{"A2 pruned recovery", prunedRecovery, false, nil, "RECOVERY_REQUIRED"},
		{"A3 pruned none", prunedTreeEnvelope(StorageProfilePrunedV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0), false, nil, "PROFILE_NOOP"},
		{"A3 pruned gc", busyPruned, false, nil, "PROFILE_NOOP"},
		{"A4 busy confirmed", busyArchive, true, nil, "LOCAL_BUSY"},
		{"A4 busy unconfirmed", busyArchive, false, nil, "LOCAL_BUSY"},
		{"A5 unconfirmed high tip", prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0), false, high, "PROFILE_CONFIRMATION_REQUIRED"},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, _, _ := prunedTreeSeed(t, row.a)
			before := prunedTreeBytes(t, s)
			for _, owner := range []*OperationReservationOwner{reservationOwner(t, MinReservationLimit), prunedTreeLow(t)} {
				live := reservationLive(owner)
				prunedTreeDecision(t, s.SelectPrunedTreeProfileV1(row.confirmed, row.tip, owner), row.want, row.name)
				if reservationLive(owner) != live || !bytes.Equal(prunedTreeBytes(t, s), before) {
					t.Fatal(row.name + ": owner or envelope changed")
				}
			}
		})
	}
}

func TestPrunedTreeProfileStaticRefusals(t *testing.T) {
	var nilStore *Store
	out := nilStore.SelectPrunedTreeProfileV1(true, nil, nil)
	treeNativeError(t, out.Err, operationUpdate, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	prunedTreeRefusal(t, out, "R1 nil Store")

	archive := prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0)
	s, _, o := prunedTreeSeed(t, archive)
	for _, owner := range []*OperationReservationOwner{nil, {}} {
		out = s.SelectPrunedTreeProfileV1(true, nil, owner)
		if !sameError(out.Err, errOperationReservationInput) {
			t.Fatalf("R2 owner refusal: %+v", out)
		}
		prunedTreeRefusal(t, out, "R2 owner")
	}
	prunedTreeDecision(t, s.SelectPrunedTreeProfileV1(false, nil, o), "PROFILE_CONFIRMATION_REQUIRED", "R2 reusable")

	v2, _, _, _ := prunedStore(t, modelBase(2, 0, 0), nil, modelWork(false))
	v2Before := prunedImage(t, v2, nil)
	out = v2.SelectPrunedTreeProfileV1(true, nil, o)
	treeNativeError(t, out.Err, operationUpdate, EngineStateMismatch, -30779, "typed tree operation requires tree store", nil)
	prunedTreeRefusal(t, out, "R3 format 2")
	prunedUnchanged(t, v2, nil, v2Before, "R3 format 2")
	prunedDecision(t, v2.SelectPrunedProfileV1(false, nil, o), "PROFILE_CONFIRMATION_REQUIRED", "R3 format-2 owner")

	closed, _, _ := prunedTreeSeed(t, archive)
	mustEnvironment(t, closed.Close())
	out = closed.SelectPrunedTreeProfileV1(true, nil, o)
	var direct tsResult
	mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		direct = tsInvoke(closed, a, func(*Reader) (TreeOperationV1, error) { return TreeOperationV1{}, nil })
		return nil
	}))
	if !sameError(out.Err, direct.err) && (out.Err == nil || direct.err == nil || out.Err.Error() != direct.err.Error()) {
		t.Fatalf("R3 closed: %+v vs %+v", out, direct)
	}
	if out.Truth != direct.truth || out.Stage != direct.stage || out.Decision != "" || out.Authority != nil {
		t.Fatalf("R3 closed tuple: %+v vs %+v", out, direct)
	}
}

func TestPrunedTreeProfileTipInput(t *testing.T) {
	s, _, o := prunedTreeSeed(t, prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0))
	before := prunedTreeBytes(t, s)
	out := s.SelectPrunedTreeProfileV1(true, &AuthorityPointV1{Height: 0x100000000}, prunedTreeLow(t))
	treeNativeError(t, out.Err, operationUpdate, EngineInvalidInput, codeEINVAL, "invalid pruned tree profile tip", nil)
	prunedTreeRefusal(t, out, "R4 tip")
	bootstrapOpenUnchanged(t, s, "R4 tip")
	if !bytes.Equal(prunedTreeBytes(t, s), before) {
		t.Fatal("R4 envelope changed")
	}
	prunedTreeDecision(t, s.SelectPrunedTreeProfileV1(true, &AuthorityPointV1{BlockHash: modelHash(1)}, o), "STALE_LOCAL_PLAN", "R4 reusable")
}

func TestPrunedTreeProfileCapacity(t *testing.T) {
	// The absent-tip-row case separates a charge placed after the first index read.
	for _, tip := range []*AuthorityPointV1{nil, {BlockHash: modelHash(1)}} {
		s, path, o := prunedTreeSeed(t, prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0))
		before := prunedTreeBytes(t, s)
		out := s.SelectPrunedTreeProfileV1(true, tip, prunedTreeLow(t))
		if !IsOperationReservationCapacity(out.Err) {
			t.Fatalf("R5 capacity: %+v", out)
		}
		prunedTreeRefusal(t, out, "R5 capacity")
		bootstrapOpenUnchanged(t, s, "R5 capacity")
		if !bytes.Equal(prunedTreeBytes(t, s), before) {
			t.Fatal("R5 envelope changed")
		}
		out = s.SelectPrunedTreeProfileV1(true, tip, o)
		if tip != nil {
			prunedTreeDecision(t, out, "STALE_LOCAL_PLAN", "R5 follow-up stale")
			continue
		}
		prunedTreeLatched(t, s, path, out, before, "missing pruned tree profile root binding", o)
	}
}

func TestPrunedTreeProfileMissingBinding(t *testing.T) {
	s, path, o := prunedTreeSeed(t, prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0))
	before := prunedTreeBytes(t, s)
	out := s.SelectPrunedTreeProfileV1(true, nil, o)
	prunedTreeLatched(t, s, path, out, before, "missing pruned tree profile root binding", o)
}
