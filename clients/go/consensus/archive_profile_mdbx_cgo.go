//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Dormant PROFILE-origin selected-side ARCHIVE transition P06-2a (RUBIN_MEMPOOL_POLICY.md Sections 6.4.1.4, 6.4.1.5,
// 6.4.1.8 and 6.4.1.9, RUBIN_COMPACT_BLOCKS.md Section 1.2). SelectArchiveSelectedSideMDBX has no production caller.
// One full-lane grant encloses its sole Store.Update. In that Reader: strict authority, the control table (non-STABLE is
// RECOVERY_REQUIRED, active ARCHIVE is PROFILE_NOOP), then the finite canonical identity PRE_GENESIS/H0/H>0 from one
// bounded prefix page. PRE_GENESIS/H0 and H>0 without a selected side are other leaves' exact API refusals; H>0 under any
// cleanup phase is LOCAL_BUSY; only H>0 NONE/STABLE PRUNED with a selected side clears that side into its SIDE span
// (unkept leaving headers deleted, bodies and links kept) with PRUNE_GC/RECOVERY_REQUIRED and pending ARCHIVE. B, U,
// generations, next, exclusion and every canonical row stay; no replay target, cursor, candidate or qualification.

const (
	// archiveSelectedSideWrongLeaf marks, in the invocation-local decision, that the callback returned its own
	// wrong-leaf API refusal (bound as an empty-result leaf by the projection).
	archiveSelectedSideWrongLeaf = "archive selected side wrong leaf"
	// archiveSelectedSideProblem is MDBX_PROBLEM (third_party/libmdbx/mdbx.h), the existing wrong-leaf update API code.
	archiveSelectedSideProblem = -30779
)

// SelectArchiveSelectedSideMDBX is the PROFILE-origin selected-side ARCHIVE selection. Clean NEW has an empty Result
// and CanonicalTruth NEW; a crossed error is TERMINAL_PERSISTENCE(old|new|neither_or_unreadable) with that logical
// truth; the exact no-write decisions RECOVERY_REQUIRED, PROFILE_NOOP and LOCAL_BUSY are OLD/Prewrite with nil Err; a
// wrong-leaf API refusal keeps its raw error with an empty Result; anything else uncrossed is classified.
func SelectArchiveSelectedSideMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner) selectedSideOutcome {
	out := selectedSideOutcome{CanonicalTruth: "OLD", Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite}
	sentinel := errors.New("archive selected side decision")
	var decision string
	var leaf error
	ran, called := false, false
	err := reservations.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		ran = true
		out.Truth, out.Stage, out.Err = store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
			called = true
			batch, _, planErr := archiveSelectedSideBatch(reader, &decision, sentinel)
			if decision == archiveSelectedSideWrongLeaf {
				leaf = planErr
			}
			return batch, planErr
		})
		return out.Err
	})
	if !called { // An owner input refusal, nil Store or no-callback/cached native outcome: raw tuple, empty fields.
		if !ran {
			out.Err = err
		}
		out.CanonicalTruth = ""
		return out
	}
	return archiveSelectedSideProject(out, decision, sentinel, leaf)
}

// archiveSelectedSideBatch borrows only the caller's Reader. decision is invocation-local: a no-write decision with
// the sentinel, the wrong-leaf marker with its API refusal, or the in-flight artifact read class for classification.
// The planned authority pointer is returned only after its valid encoding.
func archiveSelectedSideBatch(reader *mdbx.Reader, decision *string, sentinel error) (mdbx.Batch, *mdbx.StorageAuthorityV1, error) {
	a, err := reader.ReadStorageAuthorityV1()
	if err != nil {
		return mdbx.Batch{}, nil, err
	}
	if result := archiveSelectedSideControl(a); result != "" {
		*decision = result
		return mdbx.Batch{}, nil, sentinel
	}
	*decision = selectedSideCanonical
	identity, err := archiveSelectedSideIdentity(reader, a.ActiveGenerationID)
	if err != nil {
		return mdbx.Batch{}, nil, err
	}
	*decision = ""
	switch {
	case identity < 2:
		return archiveSelectedSideLeaf(decision, "archive at or before genesis belongs to SelectArchiveProfileV1")
	case a.Phase != mdbx.StoragePhaseNoneV1:
		*decision = "LOCAL_BUSY"
		return mdbx.Batch{}, nil, sentinel
	case a.SelectedSide == nil:
		return archiveSelectedSideLeaf(decision, "archive without selected side belongs to replay entry")
	}
	return archiveSelectedSideClear(reader, a, decision)
}

// archiveSelectedSideControl is the control table after strict authority: non-STABLE (ORDINARY_APPLY included) is
// RECOVERY_REQUIRED before an active ARCHIVE PROFILE_NOOP.
func archiveSelectedSideControl(a mdbx.StorageAuthorityV1) string {
	switch {
	case a.Lifecycle != mdbx.StorageLifecycleStableV1:
		return "RECOVERY_REQUIRED"
	case a.ActiveProfile == mdbx.StorageProfileArchiveV1:
		return "PROFILE_NOOP"
	}
	return ""
}

// archiveSelectedSideIdentity is PRE_GENESIS=0, H0=1 or H>0=2 from one page of at most one row (plus the page's own
// lookahead) under the active generation prefix; the first row must be height 0 with a legal work.
func archiveSelectedSideIdentity(reader *mdbx.Reader, generation uint64) (uint8, error) {
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], generation)
	page, err := reader.PrefixPage(mdbx.SchemaV2DBIs()[2], prefix[:], nil, 1, 120)
	switch {
	case err != nil:
		return 0, err
	case len(page.Rows) == 0:
		return 0, nil
	case binary.BigEndian.Uint64(page.Rows[0].Key[8:]) != 0:
		return 0, selectedSideDefect("archive canonical index does not start at genesis")
	case !archiveSelectedSideWork(page.Rows[0].Value[64:104]):
		return 0, selectedSideDefect("invalid archive profile genesis work")
	case page.Stop == mdbx.PrefixPageExhausted:
		return 1, nil
	}
	return 2, nil
}

// archiveSelectedSideWork is the legal cumulative work domain 0 < w <= 2^288 of a 40-byte big-endian value.
func archiveSelectedSideWork(work []byte) bool {
	var zero, limit [40]byte
	limit[3] = 1
	return bytes.Compare(work, zero[:]) > 0 && bytes.Compare(work, limit[:]) <= 0
}

// archiveSelectedSideLeaf is another leaf's exact update API refusal, marked as this invocation's own wrong leaf.
func archiveSelectedSideLeaf(decision *string, diagnostic string) (mdbx.Batch, *mdbx.StorageAuthorityV1, error) {
	*decision = archiveSelectedSideWrongLeaf
	return mdbx.Batch{}, nil, &mdbx.EngineError{Class: mdbx.EngineStateMismatch, Operation: "update", Code: archiveSelectedSideProblem, Diagnostic: diagnostic}
}

// archiveSelectedSideClear reuses the healthy selected-side clear plan in this Reader and changes only its authority
// literal: RECOVERY_REQUIRED with a pending ARCHIVE target. The canonical identity rows g0 and g1 join Consulted.
func archiveSelectedSideClear(reader *mdbx.Reader, a mdbx.StorageAuthorityV1, decision *string) (mdbx.Batch, *mdbx.StorageAuthorityV1, error) {
	plan, err := PlanSelectedSideClearMDBX(reader)
	if err != nil {
		*decision = plan.ReadResource
		return mdbx.Batch{}, nil, err
	}
	cleared, err := mdbx.DecodeStorageAuthorityV1(plan.Batch.Mutations[0].Literal)
	if err != nil {
		return mdbx.Batch{}, nil, selectedSideIllegal()
	}
	archive := mdbx.StorageProfileArchiveV1
	cleared.Lifecycle, cleared.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &archive
	encoded, err := selectedSideEncode(cleared)
	if err != nil {
		return mdbx.Batch{}, nil, err
	}
	plan.Batch.Mutations[0].Literal = encoded
	g0, _ := mdbx.HeightKey(a.ActiveGenerationID, 0) // Legal authority proved the generation nonzero.
	g1, _ := mdbx.HeightKey(a.ActiveGenerationID, 1)
	dbi := mdbx.SchemaV2DBIs()[2]
	consulted := append(plan.Batch.Consulted, mdbx.ConsultedRow{DBI: dbi, Key: g0}, mdbx.ConsultedRow{DBI: dbi, Key: g1})
	plan.Batch.Consulted = selectedSideReadback(consulted, plan.Batch.Mutations)
	return plan.Batch, &cleared, nil
}

// archiveSelectedSideProject keeps the raw tuple. Crossed is the PROFILE persistence projection; the exact sentinel
// alone (mutual errors.Is with a plain sentinel) normalizes to its decision; otherwise the existing ordered cause walk
// classifies with the in-flight read class, skipping the sentinel and the bound wrong-leaf refusal.
func archiveSelectedSideProject(out selectedSideOutcome, decision string, sentinel, leaf error) selectedSideOutcome {
	if out.Stage == mdbx.UpdateStageCommitMayHaveCrossed {
		return archiveSelectedSideCrossed(out)
	}
	if out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && errors.Is(out.Err, sentinel) && errors.Is(sentinel, out.Err) {
		out.Result, out.Err = decision, nil
		return out
	}
	p := &selectedSideDamagePlan{healthy: sentinel, bound: leaf}
	if strings.HasPrefix(decision, "LOCAL_RESOURCE_UNAVAILABLE(") {
		p.step = decision
	}
	if out.Stage == mdbx.UpdateStageWriteStartedDefinitelyPrecommit {
		out.Result = selectedSidePrecommitResult(out.Err, p)
		return out
	}
	out.Result = selectedSideResult(out.Err, p)
	return out
}

// archiveSelectedSideCrossed maps the raw truth: clean NEW is an empty Result with logical NEW; an error is
// TERMINAL_PERSISTENCE(old|new|neither_or_unreadable) with logical OLD, NEW or UNKNOWN.
func archiveSelectedSideCrossed(out selectedSideOutcome) selectedSideOutcome {
	switch out.Truth {
	case mdbx.CommitTruthOld:
		out.Result, out.CanonicalTruth = "TERMINAL_PERSISTENCE(old)", "OLD"
	case mdbx.CommitTruthNew:
		out.Result, out.CanonicalTruth = "TERMINAL_PERSISTENCE(new)", "NEW"
	default:
		out.Result, out.CanonicalTruth = "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN"
	}
	if out.Err == nil {
		out.Result = ""
	}
	return out
}