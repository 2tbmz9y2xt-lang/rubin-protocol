//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"encoding/binary"
	"errors"
)

// PrunedTreeProfileOutcomeV1 is OLD/Prewrite with the refusal for a nil Store or a
// WithOperation refusal before its callback; otherwise it carries the UpdateTreeV1
// truth and stage, and its error except that a decision clears Err.
// Decision is set only with Err nil at OLD/Prewrite; Authority is set only at
// NEW/CommitMayHaveCrossed and is the planned envelope owned by this call.
type PrunedTreeProfileOutcomeV1 struct {
	Decision  string
	Authority *TreeAuthorityV1
	Truth     CommitTruth
	Stage     UpdateStage
	Err       error
}

// SelectPrunedTreeProfileV1 is the dormant format-3 explicit pruned request. It
// has no production caller, deletes no artifact and does not parse operator tokens.
//
// Static order: a nil Store returns InvalidInput/update/EINVAL "nil Store"; then
// reservations.WithOperation(LaneOperation) returns its nil or zero owner refusal
// unchanged; then one UpdateTreeV1 call returns its own refusals (busy, closed or
// terminal, format 2 StateMismatch) unchanged with their own truth and stage.
// The nil Store and owner refusals are OLD/Prewrite. An UpdateTreeV1 refusal is
// at Prewrite and OLD, except that a state refusal of a closed or terminal Store
// carries that Store's retained truth. Each has empty Decision and nil Authority.
//
// Inside the callback a ReadTreeAuthorityV1 error is returned unchanged and an
// exact-empty store returns Decision "not eligible". On
// the decoded envelope, in order: Lifecycle not STABLE is "RECOVERY_REQUIRED",
// ActiveProfile PRUNED is "PROFILE_NOOP", Phase PRUNE_GC is "LOCAL_BUSY", and
// confirmed false is "PROFILE_CONFIRMATION_REQUIRED". A tip above 0xffffffff
// then returns InvalidInput/update/EINVAL "invalid pruned tree profile tip".
// Only then is 1000 bytes charged to the operation account (the 344-byte index
// evidence plus 656 bytes for the LAG root binding); a capacity refusal of this
// charge is returned unchanged before any index or binding read. The charge is
// held through the tip witness and suffix page, the binding read, the promise and
// replacement checks and Encode, and is released when that one reservation
// callback returns, before UpdateTreeV1 takes its own hold. That engine hold for
// the Pair copies is separate: UpdateTreeV1 charges it after the callback, and
// its refusal is a tuple of the projection below.
//
// The tip witness reads the rank-2 canonical index of ActiveGenerationID. For a
// non-nil tip, an absent tip row is "STALE_LOCAL_PLAN"; a present row's work is
// checked first, and invalid work is the latched "invalid pruned tree profile tip
// work" below; then a BlockHash mismatch or any row above the tip is
// "STALE_LOCAL_PLAN". A nil tip requires an empty index, otherwise
// "STALE_LOCAL_PLAN". Index read errors are returned unchanged.
//
// The LAG root binding is read with ReadTreeRootBindingV1(LagGenerationID); its
// read error is returned unchanged.
//
// Inside the callback the method reads with at most four Reader reads, in this
// order and each only when the path reaches it: ReadTreeAuthorityV1 for the envelope,
// then, after the decision, tip input and charge checks, Get for the tip row
// (non-nil tip only), PrefixPage for the index suffix, and ReadTreeRootBindingV1
// for the binding. It returns each read's error unchanged and stops at the
// first one. The tip row's HeightKey cannot fail because the decoded envelope
// has nonzero generations. A replacement Encode refusal is the same
// LocalInvariant "invalid pruned tree profile replacement" with the Encode error
// as cause, not recorded on the Reader. Before it can record, each read
// refuses without recording an unusable Reader and a request it rejects, and the
// two tree reads also a non-format-3 Reader; on this method's path none of those
// can occur, because the callback Reader is active and format 3, no read follows
// a failed one, and the method builds every request itself. Every
// other error a read returns is recorded on the Reader, so the Store is consumed:
// a native failure, an invalid result shape, a stored key or value outside its
// domain or width bound, an absence-census or decode failure, or a binding whose
// DatabaseID differs from the store. An absent binding is not a read error; it is
// the latched "missing pruned tree profile root binding" route below.
//
// Three routes return Integrity/get/MDBX_INVALID with the named diagnostic and
// no cause, latched on the Reader so the Store is consumed:
// "invalid pruned tree profile tip work", "missing pruned tree profile root
// binding" (no binding at LagGenerationID), and "pruned tree profile promises
// disagree with tip" (U differs from the tip's promise).
//
// The replacement sets ActiveProfile PRUNED and B to the PRUNED promise of the
// tip. L_body is 0 for a PRE_GENESIS LAG endpoint, otherwise its height plus one;
// a positive L_body sets Phase PRUNE_GC and one BLOCKS span over 0..L_body-1 of
// ActiveGenerationID. Every other field is unchanged. The LAG/CURRENT pair
// relation is not re-validated; a span the codec refuses is LocalInvariant
// "invalid pruned tree profile replacement", an oversized envelope is the Update
// bound error, and neither is recorded on the Reader. The pair-only plan writes
// meta key 2 and consults the LAG binding row and, for a non-nil tip, the tip row.
//
// Only this call's decision sentinel at OLD/Prewrite becomes Decision with Err
// nil; NEW/CommitMayHaveCrossed sets Authority; every other tuple is returned
// unchanged with Decision empty and Authority nil.
func (s *Store) SelectPrunedTreeProfileV1(confirmed bool, expectedTip *AuthorityPointV1, reservations *OperationReservationOwner) PrunedTreeProfileOutcomeV1 {
	out := PrunedTreeProfileOutcomeV1{Truth: CommitTruthOld, Stage: UpdateStagePrewrite}
	if s == nil {
		out.Err = adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "nil Store", nil)
		return out
	}
	var tip *AuthorityPointV1
	if expectedTip != nil {
		copied := *expectedTip
		tip = &copied
	}
	sentinel := errors.New("pruned tree profile decision")
	var run prunedTreeRun
	out.Err = reservations.WithOperation(LaneOperation, func(account *OperationAccount) error {
		var err error
		out.Truth, out.Stage, _, err = s.UpdateTreeV1(account, prunedTreePlan(account, confirmed, tip, &run, sentinel))
		return err
	})
	return prunedTreeOutcome(out, run.planned, run.decision, sentinel)
}

// prunedTreeRun holds the decision and planned envelope one call's callback sets.
type prunedTreeRun struct {
	decision string
	planned  *TreeAuthorityV1
}

// prunedTreePlan returns the callback SelectPrunedTreeProfileV1 passes to
// UpdateTreeV1 unwrapped, so the operation it returns is the one the engine receives.
func prunedTreePlan(account *OperationAccount, confirmed bool, tip *AuthorityPointV1, run *prunedTreeRun, sentinel error) func(*Reader) (TreeOperationV1, error) {
	return func(reader *Reader) (op TreeOperationV1, err error) {
		op, run.planned, err = prunedTreeCompose(reader, account, confirmed, tip, &run.decision, sentinel)
		return op, err
	}
}

func prunedTreeCompose(reader *Reader, account *OperationAccount, confirmed bool, tip *AuthorityPointV1, decision *string, sentinel error) (TreeOperationV1, *TreeAuthorityV1, error) {
	a, present, err := reader.ReadTreeAuthorityV1()
	if err != nil {
		return TreeOperationV1{}, nil, err
	}
	*decision = prunedTreeControl(present, &a.Authority, confirmed)
	if *decision != "" {
		return TreeOperationV1{}, nil, sentinel
	}
	if tip != nil && tip.Height > 0xffffffff {
		return TreeOperationV1{}, nil, adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "invalid pruned tree profile tip", nil)
	}
	var op TreeOperationV1
	err = account.WithReservation(1000, func() error {
		var planErr error
		op, planErr = prunedTreeOperation(reader, &a, tip, decision, sentinel)
		return planErr
	})
	return op, &a, err
}

func prunedTreeControl(present bool, a *StorageAuthorityV1, confirmed bool) string {
	switch {
	case !present:
		return "not eligible"
	case a.Lifecycle != StorageLifecycleStableV1:
		return "RECOVERY_REQUIRED"
	case a.ActiveProfile == StorageProfilePrunedV1:
		return "PROFILE_NOOP"
	case a.Phase == StoragePhasePruneGCV1:
		return "LOCAL_BUSY"
	case !confirmed:
		return "PROFILE_CONFIRMATION_REQUIRED"
	}
	return ""
}

func prunedTreeOperation(reader *Reader, a *TreeAuthorityV1, tip *AuthorityPointV1, decision *string, sentinel error) (TreeOperationV1, error) {
	key, err := prunedTreeTip(reader, a.Authority.ActiveGenerationID, tip, sentinel)
	if err != nil {
		*decision = "STALE_LOCAL_PLAN"
		return TreeOperationV1{}, err
	}
	lbody, err := prunedTreeBodyLimit(reader, a.LagGenerationID)
	if err != nil {
		return TreeOperationV1{}, err
	}
	encoded, err := prunedTreeReplacement(reader, a, tip, lbody)
	if err != nil {
		return TreeOperationV1{}, err
	}
	dbis := TreeSchemaV1DBIs()
	consulted := []ConsultedRow{{DBI: dbis[0], Key: binary.BigEndian.AppendUint64([]byte{0x11}, a.LagGenerationID)}}
	if key != nil {
		consulted = append(consulted, ConsultedRow{DBI: dbis[2], Key: key})
	}
	mutations := []Mutation{{DBI: dbis[0], Key: []byte{2}, BeforePresent: true, AfterKind: AfterLiteral, Literal: encoded}}
	return TreeOperationV1{Pair: TreePairV1{Mutations: mutations, Consulted: consulted}}, nil
}

func prunedTreeTip(reader *Reader, generation uint64, tip *AuthorityPointV1, stale error) ([]byte, error) {
	var key []byte
	if tip != nil {
		var err error
		key, err = prunedTreeTipRow(reader, generation, tip, stale)
		if err != nil {
			return nil, err
		}
	}
	page, err := reader.PrefixPage(TreeSchemaV1DBIs()[2], binary.BigEndian.AppendUint64(nil, generation), key, 1, 120)
	if err != nil {
		return nil, err
	}
	if len(page.Rows) != 0 || page.Stop != PrefixPageExhausted {
		return nil, stale
	}
	return key, nil
}

// prunedTreeTipRow checks membership and work before the hash comparison.
func prunedTreeTipRow(reader *Reader, generation uint64, tip *AuthorityPointV1, stale error) ([]byte, error) {
	key, err := HeightKey(generation, tip.Height)
	if err != nil {
		return nil, err
	}
	value, present, err := reader.Get(TreeSchemaV1DBIs()[2], key)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, stale
	}
	if !validWork([40]byte(value[64:104])) {
		return nil, bootstrapFailure(reader, integrityError(operationGet, "invalid pruned tree profile tip work", nil))
	}
	if [32]byte(value[:32]) != tip.BlockHash {
		return nil, stale
	}
	return key, nil
}

func prunedTreeBodyLimit(reader *Reader, lag uint64) (uint64, error) {
	root, present, err := reader.ReadTreeRootBindingV1(lag)
	if err != nil {
		return 0, err
	}
	if !present {
		return 0, bootstrapFailure(reader, integrityError(operationGet, "missing pruned tree profile root binding", nil))
	}
	if root.Endpoint.Kind == TreeEndpointPreGenesisV1 {
		return 0, nil
	}
	return root.Endpoint.Height + 1, nil
}

func prunedTreeReplacement(reader *Reader, a *TreeAuthorityV1, tip *AuthorityPointV1, lbody uint64) ([]byte, error) {
	height := uint64(0)
	if tip != nil {
		height = tip.Height
	}
	if a.Authority.U != laggedPromise(height, 1440) {
		return nil, bootstrapFailure(reader, integrityError(operationGet, "pruned tree profile promises disagree with tip", nil))
	}
	a.Authority.ActiveProfile, a.Authority.B = StorageProfilePrunedV1, laggedPromise(height, 15120)
	if lbody > 0 {
		a.Authority.Phase = StoragePhasePruneGCV1
		a.Authority.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: CleanupSpanBlocksV1, GenerationID: a.Authority.ActiveGenerationID, FirstHeight: 0, LastHeight: lbody - 1, NextHeight: 0}}}
	}
	if !validTreeAuthority(*a) {
		return nil, adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "invalid pruned tree profile replacement", nil)
	}
	if n, fits := authoritySize(a.Authority); !fits || n > MaxMetadataBytes-27 {
		return nil, updateBoundError()
	}
	encoded, err := a.Encode()
	if err != nil {
		return nil, adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "invalid pruned tree profile replacement", err)
	}
	return encoded, nil
}

func prunedTreeOutcome(out PrunedTreeProfileOutcomeV1, planned *TreeAuthorityV1, decision string, sentinel error) PrunedTreeProfileOutcomeV1 {
	// Exact identity: a sentinel wrapped or joined with a cleanup error is not a decision.
	if any(out.Err) == any(sentinel) && out.Truth == CommitTruthOld && out.Stage == UpdateStagePrewrite {
		out.Decision, out.Err = decision, nil
		return out
	}
	if out.Truth == CommitTruthNew && out.Stage == UpdateStageCommitMayHaveCrossed {
		out.Authority = planned
	}
	return out
}
