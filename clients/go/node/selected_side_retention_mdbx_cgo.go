//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Dormant selected-side retention (RUBIN_MEMPOOL_POLICY.md Sections 6.4.1.3, 6.4.1.5, 6.4.1.6 and 6.4.1.9,
// RUBIN_COMPACT_BLOCKS.md Sections 10-10.2, RUBIN_L1_CANONICAL.md Sections 23 and 25). RetainSelectedSideMDBX has no
// production caller. Each attempt holds one full-lane grant around its own same-Reader qualification, every live
// buffer, its sole Store.Update and that Update's cleanup. A clean damage locator is rechecked by the existing damage
// operation after that grant is released and permits exactly one fresh attempt. Only N1, N2, the separate N3
// replacement, RA (the fresh append to a cleaned one-slot side) and the separate RP preparation
// (selected_side_rolling_mdbx_cgo.go) write here; every other selected-side
// transition is routed or refused without a write.

const (
	selectedRetainBusy         = "LOCAL_BUSY"
	selectedRetainCapacity     = "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"
	selectedRetainStale        = "STALE_LOCAL_PLAN"
	selectedRetainStored       = "STORED_NONCANONICAL"
	selectedRetainCleared      = "LOCAL_STORE_ERROR(noncanonical)"
	selectedRetainKnown        = "KNOWN_BLOCK_NOOP(CANONICAL)"
	selectedRetainDuplicate    = "KNOWN_BLOCK_NOOP(STORED_NONCANONICAL)"
	selectedRetainCapacityText = "storage operation reservation capacity unavailable"
	// selectedRetainWorkspace is the fixed term of Qqual(n)=n+M+7223040; selectedRetainOwnerTip is the candidate-owner
	// and expected-tip allowance of two identities and 1024 bytes each.
	selectedRetainWorkspace uint64 = 7_223_040
	selectedRetainOwnerTip  uint64 = 2_048
	// selectedRetainExtra is E of the shared N1/N2 write: four authority images (decoded, Batch literal, Update clone,
	// native OLD), the sorted and Update-cloned 16384-identity union (64 bytes per descriptor and key, twice) and 131072
	// bytes of fixed keys, header/link literals, mutation arrays and control structs.
	selectedRetainExtra uint64 = 4*mdbx.MaxMetadataBytes + 2*selectedQualIdentities*64 + 131_072
	// selectedRetainClear is Pclear, the planner's whole charge (transfer arrays, keys, headers, owners, authority images,
	// Batch and native OLD); selectedRetainOutside is N3's Eoutside, charged beside it once: this attempt's decoded
	// authority, the Update-cloned union, the candidate-owner and expected-tip allowance and fixed bookkeeping.
	selectedRetainClear   uint64 = 8_388_608
	selectedRetainOutside uint64 = mdbx.MaxMetadataBytes + 2*selectedQualIdentities*64 + selectedRetainOwnerTip + 131_072
)

// Qqual(n)+2048 and the matched-duplicate envelope n+M+7223040+262144 fit G for every admitted n<=M, so neither is a
// runtime refusal; a violation does not compile.
const _ = mdbx.MaxOperationDataBytes - (2*mdbx.MaxBlockBytes + selectedRetainWorkspace + 262_144 + selectedRetainOwnerTip)

// selectedSideMode is the invocation's fixed transition owner: Retain (N1/N2/RA and routing), the separate RF refill,
// the separate N3 Replace or the separate RP preparation. Only Retain owns the duplicate fallback and the admitted
// first-row probe. The modes whose clean crossed NEW is a stored noncanonical row (Retain, Refill) come first, so
// that projection is the single ordered test mode <= selectedRefillMode; the zero mode is Retain. Every other use
// compares for equality.
type selectedSideMode uint8

const (
	selectedRetainMode selectedSideMode = iota
	selectedRefillMode
	selectedReplaceMode
	selectedPrepareMode
)

// selectedRetainResults is the finite set of qualifier refusal results one attempt may bind for classification.
var selectedRetainResults = []string{selectedQualIntegrity, selectedQualBranch, selectedQualCanonical, selectedQualRecovery, selectedQualRecoveryRequired, selectedRetainStale}

// SelectedSideMutationOutcome is one invocation's logical result beside the exact raw Update tuple of the attempt that
// terminated it. Result, Decision and CanonicalTruth stay empty when no callback of that attempt ran.
type SelectedSideMutationOutcome struct {
	Result, Decision, CanonicalTruth string
	Truth                            mdbx.CommitTruth
	Stage                            mdbx.UpdateStage
	Err                              error
}

// selectedRetainAttempt is one attempt's private state: the tip locator copied inside its grant, its clean decision,
// the exact callback leaf bound for classification and the in-flight read class. Nothing crosses attempts.
type selectedRetainAttempt struct {
	raw                         []byte
	tip                         *mdbx.AuthorityPointV1
	request                     *selectedSideDamageRequest
	sentinel, bound             error
	result, decision, canonical string
	boundResult, resource       string
	retry, ran                  bool
	mode                        selectedSideMode
	// positive is the consumed plan's PositiveDamageClear: an actual complete positive-damage clear.
	positive bool
	// linking is L, the exact length of the one successfully checked exact-tip linking body; 0 for a canonical parent.
	linking uint64
}

// selectedRetention plans one attempt over that attempt's own qualifier state.
type selectedRetention struct {
	*selectedSideQualifier
	attempt *selectedRetainAttempt
}

// selectedRetainTip is the re-proved current canonical tip; empty is a proved empty generation (PRE_GENESIS).
type selectedRetainTip struct {
	empty bool
	hash  [32]byte
	work  [40]byte
}

// RetainSelectedSideMDBX retains one raw candidate under an untrusted expected canonical tip locator. It returns the
// terminating attempt's whole tuple: the first attempt, a non-healthy recheck of its clean damage locator, or the
// single fresh attempt a healthy recheck permits.
func RetainSelectedSideMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, raw []byte, expectedTip *mdbx.AuthorityPointV1) SelectedSideMutationOutcome {
	return selectedRetainRun(store, reservations, raw, expectedTip, selectedRetainMode)
}

// ReplaceSelectedSideMDBX is the separate N3 replacement: a freshly qualified winning canonical-parent child clears the
// live selected side into its SIDE span without storing the candidate. It shares Retain's attempts and tuple rules.
func ReplaceSelectedSideMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, raw []byte, expectedTip *mdbx.AuthorityPointV1) SelectedSideMutationOutcome {
	return selectedRetainRun(store, reservations, raw, expectedTip, selectedReplaceMode)
}

func selectedRetainRun(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, raw []byte, expectedTip *mdbx.AuthorityPointV1, mode selectedSideMode) SelectedSideMutationOutcome {
	out, request := selectedRetainOnce(store, reservations, raw, expectedTip, false, mode)
	if request == nil {
		return out
	}
	recheck := consensus.RecheckSelectedSideMDBX(store, reservations, request.Generation, request.Tip, request.Height)
	if recheck.Result != "" || recheck.Err != nil || recheck.Truth != mdbx.CommitTruthOld || recheck.Stage != mdbx.UpdateStagePrewrite {
		return SelectedSideMutationOutcome{Result: recheck.Result, CanonicalTruth: recheck.CanonicalTruth, Truth: recheck.Truth, Stage: recheck.Stage, Err: recheck.Err}
	}
	out, _ = selectedRetainOnce(store, reservations, raw, expectedTip, true, mode)
	return out
}

// selectedRetainOnce runs one attempt. A nil Store or an oversize candidate takes a grant-free control-only Update, except
// that a non-nil Store with a nil or zero owner returns that owner's own exact input refusal with no Update; a refused
// full-lane charge takes the same control-only Update ending in storage_capacity; any other owner refusal is returned
// unchanged with no Update.
func selectedRetainOnce(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, raw []byte, expectedTip *mdbx.AuthorityPointV1, retry bool, mode selectedSideMode) (SelectedSideMutationOutcome, *selectedSideDamageRequest) {
	a := &selectedRetainAttempt{raw: raw, retry: retry, mode: mode, sentinel: errors.New("selected side retention decision")}
	out := SelectedSideMutationOutcome{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite}
	if store == nil || len(raw) > mdbx.MaxBlockBytes {
		// cmp.Or maps a nil owner to the zero owner, so one comparison covers both invalid owners.
		if store != nil && *cmp.Or(reservations, &mdbx.OperationReservationOwner{}) == (mdbx.OperationReservationOwner{}) {
			out.Err = reservations.WithReservation(mdbx.MaxOperationDataBytes, nil) // The owner's exact input sentinel.
			return out, nil
		}
		out.Truth, out.Stage, out.Err = store.Update(a.control)
		return a.project(out)
	}
	granted := false
	err := reservations.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		granted = true
		if expectedTip != nil {
			tip := *expectedTip
			a.tip = &tip
		}
		out.Truth, out.Stage, out.Err = store.Update(a.batch)
		return out.Err
	})
	switch {
	case granted:
	case err.Error() == selectedRetainCapacityText:
		out.Truth, out.Stage, out.Err = store.Update(a.control)
	default:
		out.Err = err
	}
	return a.project(out)
}

// control is the control-only callback: strict authority and the control table precede the raw bound, and a refused
// charge then ends with storage_capacity before any candidate, context or artifact read.
func (a *selectedRetainAttempt) control(reader *mdbx.Reader) (mdbx.Batch, error) {
	a.ran = true
	if _, err := selectedQualAuthority(reader, len(a.raw)); err != nil {
		return mdbx.Batch{}, a.bind(err)
	}
	return mdbx.Batch{}, a.decide(selectedRetainCapacity, "", "OLD")
}

// batch is the attempt's Update callback; a complete Batch leaves no binding and no in-flight read class.
func (a *selectedRetainAttempt) batch(reader *mdbx.Reader) (mdbx.Batch, error) {
	a.ran = true
	batch, err := a.plan(reader)
	if err != nil {
		return mdbx.Batch{}, a.bind(err)
	}
	a.bound, a.boundResult, a.resource = nil, "", ""
	return batch, nil
}

// plan composes the qualifier's own order (authority/control/raw, header, parent evidence, context, steps 1-12,
// selection and domain) so a NONE canonical parent beside a live side stays an explicit owner outcome.
func (a *selectedRetainAttempt) plan(reader *mdbx.Reader) (mdbx.Batch, error) {
	if a.mode == selectedRefillMode { // RF has its own qualification (selected_side_rolling_mdbx_cgo.go).
		return a.refill(reader)
	}
	authority, err := selectedQualAuthority(reader, len(a.raw))
	if err != nil {
		return mdbx.Batch{}, err
	}
	q := &selectedSideQualifier{reader: reader, authority: authority, side: authority.SelectedSide, slots: 1}
	q.consulted = make([]mdbx.ConsultedRow, 0, selectedQualIdentities)
	q.consult(0, []byte{2})
	header, err := consensus.ParseBlockHeaderBytes(a.raw)
	if err != nil {
		return mdbx.Batch{}, &consensus.TxError{Code: consensus.BLOCK_ERR_PARSE, Msg: "invalid block header"}
	}
	r := &selectedRetention{selectedSideQualifier: q, attempt: a}
	parent, err := r.parent(header.PrevBlockHash)
	if err != nil {
		return mdbx.Batch{}, err
	}
	qual, err := q.qualifyChild(a.raw, header, parent)
	if err != nil {
		return mdbx.Batch{}, err
	}
	q.consulted = qual.Consulted
	return r.admitted(qual, parent)
}

// decide records this attempt's clean no-write decision and returns its sentinel.
func (a *selectedRetainAttempt) decide(result, decision, canonical string) error {
	a.result, a.decision, a.canonical = result, decision, canonical
	return a.sentinel
}

// bind is the producer-side proof of the classifier binding: only this attempt's own direct leaf binds (see
// selectedRetainLeaf). An empty-result binding (sentinel or locator) clears the in-flight read class first; the
// retry's locator is converted to typed branch_data before it is returned.
func (a *selectedRetainAttempt) bind(err error) error {
	if request, ok := err.(*selectedSideDamageRequest); ok && request != nil && a.retry { //nolint:errorlint // Direct leaf only.
		return a.bind(&selectedSideQualificationError{Result: selectedQualBranch, Cause: request})
	}
	a.boundResult, a.bound = selectedRetainLeaf(err, a.sentinel)
	if request, ok := a.bound.(*selectedSideDamageRequest); ok { //nolint:errorlint // The bound leaf itself.
		a.request = request
	}
	if a.bound != nil && a.boundResult == "" {
		a.resource = ""
	}
	return err
}

// selectedRetainLeaf proves one returned value is this attempt's own direct leaf: a non-nil damage locator or the
// exact sentinel (empty skip), a non-nil qualifier refusal with a cause and a finite result, or a non-nil TxError
// (its own code). Wrapped, foreign or arbitrary EngineError values bind nothing.
func selectedRetainLeaf(err, sentinel error) (string, error) {
	switch e := err.(type) { //nolint:errorlint // Only the direct returned leaf binds.
	case *selectedSideDamageRequest:
		if e != nil {
			return "", e
		}
	case *selectedSideQualificationError:
		if selectedRetainQualLeaf(e) {
			return e.Result, e
		}
	case *consensus.TxError:
		if e != nil {
			return "CONSENSUS_INVALID(" + string(e.Code) + ")", e
		}
	}
	if err == sentinel { //nolint:errorlint // The exact invocation-local sentinel.
		return "", err
	}
	return "", nil
}

func selectedRetainQualLeaf(e *selectedSideQualificationError) bool {
	return e != nil && e.Cause != nil && slices.Contains(selectedRetainResults, e.Result)
}

// project derives the logical fields without rereading the Store and never changes the raw tuple, except that the
// exact sentinel at OLD/Prewrite becomes its clean decision with a nil Err. A clean exact locator is returned for the
// recheck; anything else uncrossed goes to the shared classifier.
func (a *selectedRetainAttempt) project(out SelectedSideMutationOutcome) (SelectedSideMutationOutcome, *selectedSideDamageRequest) {
	switch {
	case !a.ran:
		return out, nil
	case out.Stage == mdbx.UpdateStageCommitMayHaveCrossed:
		return selectedRetainCrossed(out, a.mode <= selectedRefillMode, a.positive), nil
	case out.Truth != mdbx.CommitTruthOld || out.Stage != mdbx.UpdateStagePrewrite:
	case out.Err == a.sentinel: //nolint:errorlint // Only the exact sentinel with no cleanup cause is clean.
		out.Result, out.Decision, out.CanonicalTruth, out.Err = a.result, a.decision, a.canonical, nil
		return out, nil
	case a.request != nil && out.Err == error(a.request): //nolint:errorlint // Only the exact clean locator rechecks.
		return out, a.request
	}
	out.CanonicalTruth = "OLD"
	out.Result = consensus.ClassifySelectedSideFailureMDBX(out.Err, out.Stage, a.resource, a.bound, a.boundResult)
	return out, nil
}

// selectedRetainCrossed is the optional-cache projection of a crossed N1, N2, N3 or RP attempt: an actual complete
// positive-damage clear is a noncanonical store error for every truth; otherwise clean NEW is stored noncanonical for
// N1/N2 (stored) and an empty Result for the healthy N3 clear or RP, UNKNOWN is a noncanonical store error, and OLD or
// NEW with an error keeps an empty Result.
func selectedRetainCrossed(out SelectedSideMutationOutcome, stored, positive bool) SelectedSideMutationOutcome {
	out.CanonicalTruth = "NOT_APPLICABLE"
	switch {
	case positive || out.Truth == mdbx.CommitTruthUnknown:
		out.Result = selectedRetainCleared
	case out.Truth == mdbx.CommitTruthNew && out.Err == nil && stored:
		out.Result = selectedRetainStored
	}
	return out
}

// parent keeps the qualifier's parent order; a NONE canonical parent beside a live side enters the explicit duplicate
// fallback instead of the qualifier's branch_data refusal.
func (r *selectedRetention) parent(hash [32]byte) (selectedQualParent, error) {
	switch {
	case r.side == nil || r.attempt.mode != selectedRetainMode && hash != r.side.TipHash: // Only Retain has the duplicate fallback.
		return r.canonicalParent(hash)
	case hash == r.side.TipHash:
		return r.tipParent()
	}
	owner, err := r.canonicalOwnerOf(hash)
	if err != nil {
		return selectedQualParent{}, err
	}
	if !owner.Owned {
		return selectedQualParent{}, r.duplicate()
	}
	header, err := r.ownedHeader(hash, owner)
	if err != nil {
		return selectedQualParent{}, err
	}
	parsed, _ := consensus.ParseBlockHeaderBytes(header) // A 116-byte header always decodes.
	return selectedQualParent{hash: hash, height: owner.Height, f: owner.Height, work: [40]byte(owner.Entry[64:104]), header: parsed}, nil
}

// tipParent is the qualifier's exact-tip parent (selectedTip, then linkingBody's one keyed-owner body read and checks)
// composed here so the checked body's exact length L is kept for the append preflight; the body itself is not kept.
// The read's own resource class stays set only while it is in flight.
func (r *selectedRetention) tipParent() (selectedQualParent, error) {
	tip, err := r.selectedTip()
	if err != nil {
		return selectedQualParent{}, err
	}
	required := tip.owner.Owned && tip.owner.Height >= r.authority.B
	read, resource := r.optionalRow, selectedQualBranch
	if required {
		read, resource = r.requiredRow, selectedQualCanonical
	}
	r.attempt.resource = resource
	body, err := read(4, r.side.TipHash)
	if err != nil {
		return selectedQualParent{}, err
	}
	r.attempt.resource = ""
	if !selectedRetainLinkingHealthy(body, tip.header) {
		if required {
			return selectedQualParent{}, selectedQualFailure(selectedQualIntegrity, "required canonical body does not match its header or commitments")
		}
		return selectedQualParent{}, r.request(r.side.TipHeight)
	}
	r.attempt.linking = uint64(len(body))
	header, _ := consensus.ParseBlockHeaderBytes(tip.header) // A 116-byte header always decodes.
	return selectedQualParent{hash: r.side.TipHash, height: r.side.TipHeight, f: r.side.F, work: [40]byte(tip.link[64:104]), header: header, selected: true}, nil
}

// selectedRetainLinkingHealthy is linkingBody's body predicate: a present body whose header bytes equal the verified
// tip header and whose commitments verify; it short-circuits on an absent body before any slice or validation.
func selectedRetainLinkingHealthy(body, header []byte) bool {
	return body != nil && bytes.Equal(body[:consensus.BLOCK_HEADER_BYTES], header) && consensus.ValidateBlockBodyCommitments(body) == nil
}

// admitted orders the fresh qualification's consumers: candidate owner, the re-proved expected tip, K23 against the
// persisted canonical tip, the restricted first-row probe before NOT_SELECTED, then the selected route.
func (r *selectedRetention) admitted(qual selectedSideQualification, parent selectedQualParent) (mdbx.Batch, error) {
	owner, err := r.canonicalOwnerOf(qual.Summary.BlockHash)
	if err != nil {
		return mdbx.Batch{}, err
	}
	if owner.Owned {
		return mdbx.Batch{}, r.attempt.decide(selectedRetainKnown, "", "NOT_APPLICABLE")
	}
	tip, err := r.tipProof()
	if err != nil {
		return mdbx.Batch{}, err
	}
	switch {
	case tip.outranked(qual.Work, qual.Summary.BlockHash):
		return mdbx.Batch{}, r.attempt.decide("", "ORDINARY", "OLD")
	case !qual.Selected && r.attempt.mode != selectedRetainMode: // Only Retain has the admitted first-row probe.
		return mdbx.Batch{}, r.attempt.decide("", "NOT_SELECTED", "OLD")
	case !qual.Selected:
		return mdbx.Batch{}, r.notSelected(qual)
	}
	return r.route(qual, parent)
}

// route sends a selected candidate to its transition: N1 without a side, the separate replacement for a winning
// canonical-parent child, the separate rolling preparation for a count-1440 side, N2 for an exact-tip child of a full
// side below 1440 rows (F+count = tip, C1439 included), and RA for an exact-tip child of the cleaned one-slot side. The
// separate Replace and Prepare invocations go only to their own transition.
func (r *selectedRetention) route(qual selectedSideQualification, parent selectedQualParent) (mdbx.Batch, error) {
	switch {
	case r.attempt.mode == selectedReplaceMode:
		return r.replace(parent)
	case r.attempt.mode == selectedPrepareMode:
		return r.prepare(parent)
	case r.side == nil:
		return r.create(qual)
	case !parent.selected:
		return mdbx.Batch{}, r.attempt.decide(selectedQualBranch, "REPLACE", "OLD")
	case r.side.RowCount == 1440:
		return mdbx.Batch{}, r.attempt.decide(selectedQualBranch, "PREPARE_ROLLING", "OLD")
	case r.side.TipHeight-uint64(r.side.RowCount) != r.side.F:
		return r.ra(qual)
	}
	return r.n2(qual)
}

// ra is the fresh append to a cleaned one-slot side (C >= 1440, count 1439; legal authority admits no other shape with
// first > F+1 and no detached suffix beside a side). The aggregate counts the live rows, every row still owed by a
// pending SIDE span from its next_height, and the incoming row; above 1440 (a Prepared side) it is typed branch_data.
// Otherwise the N2 effect: tip/hash/work advance, count 1440, bytes+n, first, g, F and next unchanged, no SIDE or delete.
func (r *selectedRetention) ra(qual selectedSideQualification) (mdbx.Batch, error) {
	owed := uint64(0)
	if c := r.authority.Cleanup; c != nil {
		for _, span := range c.Spans {
			if span.Kind == mdbx.CleanupSpanSideV1 {
				owed += span.LastHeight - span.NextHeight + 1
			}
		}
	}
	if uint64(r.side.RowCount)+owed+1 > 1440 {
		return mdbx.Batch{}, selectedQualFailure(selectedQualBranch, "selected side append exceeds the retention aggregate")
	}
	return r.n2(qual)
}

// replace is N3: a winning canonical-parent child beside a live side clears that side, in this Reader, through the
// consensus clear planner; the candidate is never stored and no generation is allocated. No side or an exact-tip child is
// typed branch_data. The conservative preflight 2n+W+Eoutside+Pclear <= G (L is 0 for a canonical parent) precedes every
// planner read and allocation; Eoutside is this attempt's decoded authority, the Update-cloned union, the owner/tip
// allowance and fixed state.
func (r *selectedRetention) replace(parent selectedQualParent) (mdbx.Batch, error) {
	switch {
	case r.side == nil || parent.selected:
		return mdbx.Batch{}, selectedQualFailure(selectedQualBranch, "selected side replacement needs a winning canonical-parent child")
	case 2*uint64(len(r.attempt.raw))+selectedRetainWorkspace+selectedRetainOutside+selectedRetainClear > mdbx.MaxOperationDataBytes:
		return mdbx.Batch{}, r.attempt.decide(selectedRetainCapacity, "", "OLD")
	}
	plan, err := consensus.PlanSelectedSideClearMDBX(r.reader)
	if err != nil {
		r.attempt.resource = plan.ReadResource
		return mdbx.Batch{}, err
	}
	plan.Batch.Consulted = selectedRetainUnion(append(r.consulted, plan.Batch.Consulted...), plan.Batch.Mutations)
	return plan.Batch, nil
}

// create is N1's admission tail in the fixed order: descriptor busy, the SIDE wait, the checked generation sequence
// and the step-10 byte preflight. With no side, no SIDE and no detached suffix the aggregate is one row, and a fourth
// generation identity cannot arise because spans are kind-ordered and a SIDE span already waited.
func (r *selectedRetention) create(qual selectedSideQualification) (mdbx.Batch, error) {
	a := r.authority
	switch {
	case a.DetachedSuffix != nil:
		return mdbx.Batch{}, r.attempt.decide(selectedRetainBusy, "", "OLD")
	case a.Cleanup != nil && slices.ContainsFunc(a.Cleanup.Spans, func(s mdbx.CleanupSpanV1) bool { return s.Kind == mdbx.CleanupSpanSideV1 }):
		return mdbx.Batch{}, selectedQualFailure(selectedQualBranch, "selected side creation waits for its SIDE cleanup")
	case a.NextGenerationID == math.MaxUint64:
		return mdbx.Batch{}, errors.New("selected side generation sequence is exhausted")
	case !selectedRetainFits(uint64(len(r.attempt.raw)), 0):
		return mdbx.Batch{}, r.attempt.decide(selectedRetainCapacity, "", "OLD")
	}
	g := r.authority.NextGenerationID
	return r.write(qual, g+1, mdbx.SelectedSideV1{
		GenerationID: g, F: qual.ParentHeight, TipHeight: qual.Height, TipHash: qual.Summary.BlockHash, CumulativeChainwork: qual.Work, RowCount: 1,
		LogicalBytes: uint64(len(r.attempt.raw)),
	})
}

// n2 appends the exact-tip child to a full side below 1440 rows: g, F and next stay (no identity is allocated, so an
// exhausted sequence still appends), the tip advances and count and logical bytes grow by one row and n. A legal full
// side excludes a detached suffix and a pending SIDE, so its admission tail is the step-10 preflight alone. The legal
// descriptor bounds LogicalBytes by 1439*M, so adding n<=M cannot wrap; the written authority is still validated.
func (r *selectedRetention) n2(qual selectedSideQualification) (mdbx.Batch, error) {
	n := uint64(len(r.attempt.raw))
	if !selectedRetainFits(n, r.attempt.linking) {
		return mdbx.Batch{}, r.attempt.decide(selectedRetainCapacity, "", "OLD")
	}
	side := *r.side
	side.TipHeight, side.TipHash, side.CumulativeChainwork = qual.Height, qual.Summary.BlockHash, qual.Work
	side.RowCount, side.LogicalBytes = side.RowCount+1, side.LogicalBytes+n
	return r.write(qual, r.authority.NextGenerationID, side)
}

// selectedRetainFits is the checked write preflight max(Qqual(n)+2048, 3n+L+7223040+E) <= G: L is 0 for the canonical
// parent and the successfully checked linking body length (still live as Update's native consulted OLD image) for an
// exact-tip parent, and 3n covers both body paths. An absent body holds the caller's raw candidate, the Batch body
// literal clone and its Update-owned clone. A byte-identical present body holds the caller's raw candidate, the
// GetOptionalSide Go body copy and Update's native consulted OLD body image, and is reused with no body mutation. The
// Qqual term always fits (see the compile-time bound above).
func selectedRetainFits(n, l uint64) bool {
	return 3*n+l+selectedRetainWorkspace+selectedRetainExtra <= mdbx.MaxOperationDataBytes
}

// write is the shared N1/N2 effect: the expected header and body are inserted when absent and reused when
// byte-identical, the authority takes next and side and every other field and span stay unchanged, and SideLink
// (side g, new tip) is inserted.
func (r *selectedRetention) write(qual selectedSideQualification, next uint64, side mdbx.SelectedSideV1) (mdbx.Batch, error) {
	raw, hash := r.attempt.raw, qual.Summary.BlockHash
	header, err := r.expected(3, hash, raw[:consensus.BLOCK_HEADER_BYTES])
	if err != nil {
		return mdbx.Batch{}, err
	}
	body, err := r.expected(4, hash, raw)
	if err != nil {
		return mdbx.Batch{}, err
	}
	a := r.authority
	a.NextGenerationID, a.SelectedSide = next, &side
	if err := mdbx.ValidateStorageAuthorityV1(a); err != nil {
		return mdbx.Batch{}, fmt.Errorf("selected side write produced illegal authority: %w", err)
	}
	encoded, err := a.Encode()
	if err != nil {
		return mdbx.Batch{}, r.attempt.decide(selectedRetainCapacity, "", "OLD")
	}
	key, _ := mdbx.HeightKey(side.GenerationID, qual.Height) // A legal selected generation is nonzero.
	dbis := mdbx.SchemaV2DBIs()
	mutations := []mdbx.Mutation{{DBI: dbis[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: encoded}}
	mutations = append(append(mutations, header...), body...)
	mutations = append(mutations, mdbx.Mutation{DBI: dbis[6], Key: key, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(hash, qual.ParentHash, qual.Work)})
	return mdbx.Batch{Mutations: mutations, Consulted: selectedRetainUnion(r.consulted, mutations)}, nil
}

// expected observes one hash-global expected row: absent is inserted, byte-identical is reused unwritten, a differing
// row of a live selected hash is that row's recheck locator, and any other differing image is a terminal conflict.
func (r *selectedRetention) expected(rank uint8, hash [32]byte, want []byte) ([]mdbx.Mutation, error) {
	if err := r.reserve(1); err != nil {
		return nil, err
	}
	r.attempt.resource = selectedQualBranch
	row, err := r.reader.GetOptionalSide(mdbx.SchemaV2DBIs()[rank], hash[:])
	if err != nil {
		return nil, selectedQualRead(err, selectedQualBranch)
	}
	r.consult(rank, bytes.Clone(hash[:]))
	switch {
	case !row.Present:
		return []mdbx.Mutation{{DBI: mdbx.SchemaV2DBIs()[rank], Key: bytes.Clone(hash[:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(want)}}, nil
	case row.Value != nil && bytes.Equal(row.Value, want):
		return nil, nil
	case r.side != nil:
		if err := r.member(hash); err != nil {
			return nil, err
		}
	}
	return nil, selectedQualFailure(selectedQualIntegrity, "unowned expected selected side row differs from the candidate")
}

// member locates the live selected row named by hash (links ascending, then the tip proved in this Reader) for recheck.
func (r *selectedRetention) member(hash [32]byte) error {
	for h := r.side.TipHeight - uint64(r.side.RowCount) + 1; h < r.side.TipHeight; h++ {
		link, err := r.link(h)
		if err != nil || [32]byte(link[:32]) == hash {
			return cmp.Or(err, r.request(h))
		}
	}
	if r.side.TipHash == hash {
		return r.request(r.side.TipHeight)
	}
	return nil
}

// selectedRetainUnion orders the relied-on rows by (DBI.Rank, key), keeps each identity once and drops every identity
// the Batch itself targets, whose OLD image Update captures.
func selectedRetainUnion(rows []mdbx.ConsultedRow, targets []mdbx.Mutation) []mdbx.ConsultedRow {
	slices.SortFunc(rows, func(a, b mdbx.ConsultedRow) int {
		return cmp.Or(cmp.Compare(a.DBI.Rank, b.DBI.Rank), bytes.Compare(a.Key, b.Key))
	})
	rows = slices.CompactFunc(rows, func(a, b mdbx.ConsultedRow) bool { return a.DBI == b.DBI && bytes.Equal(a.Key, b.Key) })
	return slices.DeleteFunc(rows, func(row mdbx.ConsultedRow) bool {
		return slices.ContainsFunc(targets, func(m mdbx.Mutation) bool { return m.DBI == row.DBI && bytes.Equal(m.Key, row.Key) })
	})
}

// tipProof re-proves the attempt's copied untrusted locator in this Reader: entry presence and its persisted work
// domain before the hash, then an empty in-generation suffix. Nil proves only an empty generation (PRE_GENESIS).
func (r *selectedRetention) tipProof() (selectedRetainTip, error) {
	tip := r.attempt.tip
	if tip != nil && tip.Height > 0xffffffff {
		return selectedRetainTip{}, &mdbx.EngineError{Class: mdbx.EngineInvalidInput, Operation: "update", Code: int(syscall.EINVAL), Diagnostic: "invalid selected retention tip"}
	}
	if err := r.reserve(2); err != nil {
		return selectedRetainTip{}, err
	}
	r.attempt.resource = selectedQualCanonical
	g := r.authority.ActiveGenerationID
	proved, after, next := selectedRetainTip{empty: true}, []byte(nil), uint64(0)
	if tip != nil {
		var err error
		if proved, after, err = r.tipEntry(g, *tip); err != nil {
			return selectedRetainTip{}, err
		}
		next = tip.Height + 1
	}
	if err := r.tipSuffix(g, after, next); err != nil {
		return selectedRetainTip{}, err
	}
	return proved, nil
}

func (r *selectedRetention) tipEntry(g uint64, tip mdbx.AuthorityPointV1) (selectedRetainTip, []byte, error) {
	key, _ := mdbx.HeightKey(g, tip.Height) // Legal authority proved the generation nonzero.
	value, present, err := r.reader.Get(mdbx.SchemaV2DBIs()[2], key)
	if err != nil {
		return selectedRetainTip{}, nil, selectedQualRead(err, selectedQualCanonical)
	}
	r.consult(2, key)
	if !present {
		return selectedRetainTip{}, nil, selectedRetainStaleTip()
	}
	work := [40]byte(value[64:104])
	if work == [40]byte{} || !selectedQualDomain(0, work) {
		return selectedRetainTip{}, nil, selectedQualFailure(selectedQualIntegrity, "expected selected retention tip work is outside its domain")
	}
	if [32]byte(value[:32]) != tip.BlockHash {
		return selectedRetainTip{}, nil, selectedRetainStaleTip()
	}
	return selectedRetainTip{hash: tip.BlockHash, work: work}, key, nil
}

// tipSuffix requires no canonical row of generation g after the locator and consults the absent next height.
func (r *selectedRetention) tipSuffix(g uint64, after []byte, next uint64) error {
	page, err := r.reader.PrefixPage(mdbx.SchemaV2DBIs()[2], binary.BigEndian.AppendUint64(nil, g), after, 1, 120)
	if err != nil {
		return selectedQualRead(err, selectedQualCanonical)
	}
	if len(page.Rows) != 0 || page.Stop != mdbx.PrefixPageExhausted {
		return selectedRetainStaleTip()
	}
	key, _ := mdbx.HeightKey(g, next) // Legal authority proved the generation nonzero.
	r.consult(2, key)
	return nil
}

func selectedRetainStaleTip() error {
	return selectedQualFailure(selectedRetainStale, "expected selected retention tip is not the current canonical tip")
}

// outranked reports the persisted canonical tip losing K23 to (work, hash): greater work, or equal work and a bytewise
// smaller hash. A proved PRE_GENESIS generation has no tip to keep.
func (t selectedRetainTip) outranked(work [40]byte, hash [32]byte) bool {
	order := bytes.Compare(work[:], t.work[:])
	return t.empty || order > 0 || order == 0 && bytes.Compare(hash[:], t.hash[:]) < 0
}

// notSelected keeps NOT_SELECTED except for Retain's restricted canonical-F first-row entrance (parent at the
// descriptor's F, first row at F+1), where a matching stored row is the known duplicate.
func (r *selectedRetention) notSelected(qual selectedSideQualification) error {
	if qual.ParentHeight != r.side.F || r.side.TipHeight-uint64(r.side.RowCount) != r.side.F {
		return r.attempt.decide("", "NOT_SELECTED", "OLD")
	}
	matched, err := r.firstMatch(qual)
	if err != nil {
		return err
	}
	if !matched {
		return r.attempt.decide("", "NOT_SELECTED", "OLD")
	}
	return r.firstBody(qual)
}

// firstMatch decides membership of the first row F+1. Count 1 reuses the tip link this qualification already proved
// equal to the descriptor; count > 1 reads only SideLink(g,F+1) and its hash-bound optional header.
func (r *selectedRetention) firstMatch(qual selectedSideQualification) (bool, error) {
	if r.side.RowCount == 1 {
		return r.firstTip(qual)
	}
	link, err := r.link(r.side.F + 1)
	if err != nil || [32]byte(link[:32]) != qual.Summary.BlockHash {
		return false, err
	}
	header, err := r.header(qual.Summary.BlockHash, false)
	if err != nil {
		return false, err
	}
	if header == nil || [32]byte(link[32:64]) != qual.ParentHash || [40]byte(link[64:104]) != qual.Work {
		return false, r.request(r.side.F + 1)
	}
	return true, nil
}

// firstTip is count 1: the proved descriptor tip is the first row; its work must equal the fresh qualification's.
func (r *selectedRetention) firstTip(qual selectedSideQualification) (bool, error) {
	if qual.Summary.BlockHash != r.side.TipHash {
		return false, nil
	}
	if r.side.CumulativeChainwork != qual.Work {
		return false, r.request(r.side.F + 1)
	}
	return true, nil
}

// firstBody reads the matched optional body once. Identical bytes reuse this attempt's successful steps 1-12; a
// differing body gets only the commitment check: invalid stored bytes are the row's locator, healthy ones branch_data.
func (r *selectedRetention) firstBody(qual selectedSideQualification) error {
	first := r.side.F + 1
	body, err := r.storedBody(first, qual.Summary.BlockHash, false)
	if err != nil {
		return err
	}
	if bytes.Equal(body, r.attempt.raw) {
		return r.attempt.decide(selectedRetainDuplicate, "", "NOT_APPLICABLE")
	}
	if consensus.ValidateBlockBodyCommitments(body) != nil {
		return r.request(first)
	}
	return selectedQualFailure(selectedQualBranch, "stored selected row differs from the supplied block")
}

// storedBody reads a matched body once by its keyed owner: positive absence, invalid width or a header that does not
// hash to the key is that height's locator (canonical integrity when required).
func (r *selectedRetention) storedBody(h uint64, hash [32]byte, required bool) ([]byte, error) {
	read := r.optionalRow
	if required {
		read = r.requiredRow
	}
	body, err := read(4, hash)
	if err != nil {
		return nil, err
	}
	if len(body) >= consensus.BLOCK_HEADER_BYTES {
		if got, hashErr := consensus.BlockHash(body[:consensus.BLOCK_HEADER_BYTES]); hashErr == nil && got == hash {
			return body, nil
		}
	}
	if required {
		return nil, selectedQualFailure(selectedQualIntegrity, "required canonical body does not match its header")
	}
	return nil, r.request(h)
}

// duplicate is the parent-NONE fallback: it scans the live links first..tip ascending and stops at the first hash
// match; a matched current-tip link must name the descriptor tip (canonical integrity), and no match keeps the
// original branch_data refusal.
func (r *selectedRetention) duplicate() error {
	hash, _ := consensus.BlockHash(r.attempt.raw[:consensus.BLOCK_HEADER_BYTES]) // The header already parsed.
	for h := r.side.TipHeight - uint64(r.side.RowCount) + 1; h <= r.side.TipHeight; h++ {
		link, err := r.link(h)
		if err != nil {
			return err
		}
		if [32]byte(link[:32]) != hash {
			continue
		}
		if h == r.side.TipHeight && hash != r.side.TipHash {
			return selectedQualFailure(selectedQualIntegrity, "selected side link does not name the descriptor tip")
		}
		return r.matched(h, link, hash)
	}
	return selectedQualFailure(selectedQualBranch, "candidate parent is neither an active canonical block nor the selected tip")
}

// link reads the required SideLink (g,h): a missing or malformed identity is canonical integrity, a transient read
// branch_data.
func (r *selectedRetention) link(h uint64) ([]byte, error) {
	if err := r.reserve(1); err != nil {
		return nil, err
	}
	r.attempt.resource = selectedQualBranch
	link, err := r.reader.ReadRequiredSideLink(r.side.GenerationID, h)
	if err != nil {
		return nil, selectedQualRead(err, selectedQualBranch)
	}
	key, _ := mdbx.HeightKey(r.side.GenerationID, h) // Legal authority proved the generation nonzero.
	r.consult(6, key)
	return link, nil
}

// matched proves the matched stored row before the supplied block: keyed owner, hash-bound header, predecessor,
// derived and descriptor work, then one stored body with its framing and commitments; only then fresh steps 1-12 at
// the actual height h.
func (r *selectedRetention) matched(h uint64, link []byte, hash [32]byte) error {
	owner, err := r.canonicalOwnerOf(hash)
	if err != nil {
		return err
	}
	header, err := r.matchedHeader(h, hash, owner)
	if err != nil {
		return err
	}
	parent, err := r.matchedParent(h, link, header)
	if err != nil {
		return err
	}
	body, err := r.matchedBody(h, hash, owner.Owned && owner.Height >= r.authority.B)
	if err != nil {
		return err
	}
	if err := r.suppliedValid(parent); err != nil {
		return err
	}
	if !bytes.Equal(body, r.attempt.raw) {
		return selectedQualFailure(selectedQualBranch, "stored selected row differs from the supplied block")
	}
	return r.storedDecision(owner, [40]byte(link[64:104]), hash)
}

func (r *selectedRetention) matchedHeader(h uint64, hash [32]byte, owner mdbx.CanonicalOwnerResultV1) ([]byte, error) {
	if owner.Owned {
		return r.ownedHeader(hash, owner)
	}
	header, err := r.header(hash, false)
	if err == nil && header == nil {
		return nil, r.request(h)
	}
	return header, err
}

// matchedParent supplies the parent at h-1 from the matched row's own evidence: its link parent and the work left after
// subtracting its header work, checked against the physical predecessor link of an interior row; a matched current
// tip's link work must then equal the descriptor. The parent header above F comes through its keyed owner, and below
// the retained rows its absence is unusable branch data.
func (r *selectedRetention) matchedParent(h uint64, link, header []byte) (selectedQualParent, error) {
	hash := [32]byte(link[32:64])
	blockWork, err := consensus.WorkFromTarget([32]byte(header[76:108]))
	if !bytes.Equal(header[4:36], link[32:64]) || err != nil {
		return selectedQualParent{}, r.request(h)
	}
	work := new(big.Int).Sub(new(big.Int).SetBytes(link[64:104]), blockWork)
	if work.Sign() <= 0 {
		return selectedQualParent{}, r.request(h)
	}
	if err := r.predecessor(h, hash, work); err != nil {
		return selectedQualParent{}, err
	}
	if h == r.side.TipHeight && [40]byte(link[64:104]) != r.side.CumulativeChainwork {
		return selectedQualParent{}, r.request(h)
	}
	raw, err := r.sideHeader(hash, h-1)
	if err != nil {
		return selectedQualParent{}, err
	}
	parsed, _ := consensus.ParseBlockHeaderBytes(raw) // A 116-byte header always decodes.
	var parentWork [40]byte
	work.FillBytes(parentWork[:]) // 0 < work < link work <= 2^288.
	return selectedQualParent{hash: hash, height: h - 1, f: r.side.F, work: parentWork, header: parsed, selected: true}, nil
}

// predecessor requires an interior row's physical predecessor link to name the parent and hold the derived work.
func (r *selectedRetention) predecessor(h uint64, hash [32]byte, work *big.Int) error {
	if h == r.side.TipHeight-uint64(r.side.RowCount)+1 {
		return nil
	}
	prev, err := r.link(h - 1)
	if err != nil {
		return err
	}
	if [32]byte(prev[:32]) != hash || new(big.Int).SetBytes(prev[64:104]).Cmp(work) != 0 {
		return r.request(h)
	}
	return nil
}

// matchedBody is the fallback's stored body: framing first, then its own commitments before any supplied validity.
func (r *selectedRetention) matchedBody(h uint64, hash [32]byte, required bool) ([]byte, error) {
	body, err := r.storedBody(h, hash, required)
	if err != nil || consensus.ValidateBlockBodyCommitments(body) == nil {
		return body, err
	}
	if required {
		return nil, selectedQualFailure(selectedQualIntegrity, "required canonical body commitments do not verify")
	}
	return nil, r.request(h)
}

// suppliedValid runs fresh steps 1-12 of the supplied block at the matched height over the matched row's context.
func (r *selectedRetention) suppliedValid(parent selectedQualParent) error {
	height, target, timestamps, err := r.childContext(parent)
	if err != nil {
		return err
	}
	_, err = consensus.ValidateBlockSteps1To12(r.attempt.raw, parent.hash, target, height, timestamps)
	if errors.Is(err, consensus.ErrBlockSteps1To12Context) {
		return &selectedSideQualificationError{Result: selectedQualBranch, Cause: err}
	}
	return err
}

// storedDecision reuses the matched row's owner: canonical-known, then a verified K23 winner routes ORDINARY,
// otherwise the stored duplicate is known and not applicable.
func (r *selectedRetention) storedDecision(owner mdbx.CanonicalOwnerResultV1, work [40]byte, hash [32]byte) error {
	if owner.Owned {
		return r.attempt.decide(selectedRetainKnown, "", "NOT_APPLICABLE")
	}
	tip, err := r.tipProof()
	if err != nil {
		return err
	}
	if tip.outranked(work, hash) {
		return r.attempt.decide("", "ORDINARY", "OLD")
	}
	return r.attempt.decide(selectedRetainDuplicate, "", "NOT_APPLICABLE")
}
