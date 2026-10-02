//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"cmp"
	"errors"
	"math/big"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Dormant selected-side rolling preparation RP (RUBIN_MEMPOOL_POLICY.md Sections 6.4.1.3, 6.4.1.5 and 6.4.1.9,
// RUBIN_COMPACT_BLOCKS.md Section 10.2). PrepareSelectedSideRollingMDBX has no production caller. It shares Retain's
// attempts, grant, Update, recheck/retry and raw tuple rules; through the consensus rolling planner it writes either the
// move of a healthy oldest row of a full 1440-row side into SIDE(g,first,first,first) or, on positive oldest damage,
// the complete side clear. The incoming candidate is never stored.

const (
	// selectedRetainRoll is Proll, the rolling planner's whole charge: Pclear plus the oldest body's Go copy and native
	// OLD image (2M) and its commitment workspace (two 1024-element Tx input/output/witness arrays and two 64-level
	// frontiers of 32-byte nodes): 144720634.
	selectedRetainRoll uint64 = selectedRetainClear + 2*mdbx.MaxBlockBytes + 2*1024*(64+40+56) + 2*64*32
	// selectedRetainRollOutside is RP's Eoutside beside Proll: the merged union backing array and its Update clone (64
	// bytes per identity and key, twice), the candidate-owner/expected-tip allowance and fixed bookkeeping. The
	// qualifier's own authority and Consulted rows are inside the workspace term.
	selectedRetainRollOutside uint64 = 2*selectedQualIdentities*64 + selectedRetainOwnerTip + 131_072
)

// PrepareSelectedSideRollingMDBX prepares the rolling of a full 1440-row selected side for one raw exact-tip child under
// an untrusted expected canonical tip locator. A healthy oldest row leaves into SIDE(g,first,first,first) with count
// 1439; positive oldest damage is the complete clear instead. It returns the terminating attempt's whole tuple, like
// RetainSelectedSideMDBX.
func PrepareSelectedSideRollingMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, raw []byte, expectedTip *mdbx.AuthorityPointV1) SelectedSideMutationOutcome {
	return selectedRetainRun(store, reservations, raw, expectedTip, selectedPrepareMode)
}

// prepare is RP's admission tail: only an exact-tip child of a full 1440-row side (which excludes a pending SIDE and a
// detached suffix) is prepared; anything else is typed branch_data with no automatic append. The conservative preflight
// 2n+L+W+Eoutside+Proll <= G precedes every planner read and allocation; L is the checked linking body's length.
func (r *selectedRetention) prepare(parent selectedQualParent) (mdbx.Batch, error) {
	switch {
	case r.side == nil || !parent.selected || r.side.RowCount != 1440:
		return mdbx.Batch{}, selectedQualFailure(selectedQualBranch, "selected side rolling preparation needs an exact-tip child of a full side")
	case !selectedRetainRollFits(uint64(len(r.attempt.raw)), r.attempt.linking):
		return mdbx.Batch{}, r.attempt.decide(selectedRetainCapacity, "", "OLD")
	}
	plan, err := consensus.PlanSelectedSideRollingMDBX(r.reader)
	if err != nil {
		r.attempt.resource = plan.ReadResource
		return mdbx.Batch{}, err
	}
	// The planner's Consulted is already sorted, unique and target-disjoint. Drop the qualifier's target overlaps, then
	// only the qualifier's identities from the planner's list, and admit the exact final union (Consulted plus every
	// unique target, authority included) before any append, callback Batch or native OLD. This refusal reads nothing.
	r.consulted = selectedRetainUnion(r.consulted, plan.Batch.Mutations)
	planned := slices.DeleteFunc(plan.Batch.Consulted, func(row mdbx.ConsultedRow) bool {
		_, found := slices.BinarySearchFunc(r.consulted, row, selectedRetainOrder)
		return found
	})
	if len(r.consulted)+len(planned)+len(plan.Batch.Mutations) > selectedQualIdentities {
		r.attempt.resource = ""
		return mdbx.Batch{}, selectedQualFailure(selectedQualBranch, "selected side rolling union exceeds its identity bound")
	}
	r.attempt.positive = plan.PositiveDamageClear
	plan.Batch.Consulted = selectedRetainUnion(append(r.consulted, planned...), plan.Batch.Mutations)
	return plan.Batch, nil
}

// selectedRetainOrder is selectedRetainUnion's exact (DBI.Rank, key) order.
func selectedRetainOrder(a, b mdbx.ConsultedRow) int {
	return cmp.Or(cmp.Compare(a.DBI.Rank, b.DBI.Rank), bytes.Compare(a.Key, b.Key))
}

// selectedRetainRollFits is the checked RP preflight; n <= M and L <= M, so the sum cannot wrap.
func selectedRetainRollFits(n, l uint64) bool {
	return 2*n+l+selectedRetainWorkspace+selectedRetainRollOutside+selectedRetainRoll <= mdbx.MaxOperationDataBytes
}

// RefillSelectedSideMDBX is RF: a fresh raw candidate at first-1 of a cleaned one-slot selected side (C >= 1440,
// count 1439, no pending SIDE) whose hash is the first retained header's parent restores that row: count 1440, first-1,
// bytes+n, exact header/body/SideLink(g,first-1) with work = first-link work minus first-header work; the incumbent
// tip/hash/work, g, F and next stay and no new-tip comparison is made. It shares Retain's attempts, grant, Update,
// recheck/retry and raw tuple rules and takes no expected-tip locator.
func RefillSelectedSideMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, raw []byte) SelectedSideMutationOutcome {
	return selectedRetainRun(store, reservations, raw, nil, selectedRefillMode)
}

// selectedSideRefillQualification is RF's invocation-owned same-Reader result: current authority, candidate summary,
// exact height/parent and restored link work, the successful first-retained body length and sorted unique Consulted.
type selectedSideRefillQualification struct {
	Authority  mdbx.StorageAuthorityV1
	Summary    consensus.BlockBasicSummary
	Height     uint64
	ParentHash [32]byte
	Work       [40]byte
	Linking    uint64
	Consulted  []mdbx.ConsultedRow
}

// selectedRefillFirst is the verified first retained row: its hash-bound header and SideLink.
type selectedRefillFirst struct {
	header consensus.BlockHeader
	link   []byte
}

// qualifySelectedRefillMDBX runs, in one Reader: authority/control/raw, candidate header, the cleaned one-slot domain,
// first-row evidence (link, keyed header, link parent, body by keyed owner height), the candidate hash against the
// first header's parent, absence of SideLink(g,first-1), restored link work, parent evidence, the existing context
// (target, MTP), steps 1-12 and the work recurrence/domain. Every error returns the zero qualification.
func qualifySelectedRefillMDBX(reader *mdbx.Reader, raw []byte) (selectedSideRefillQualification, error) {
	authority, err := selectedQualAuthority(reader, len(raw))
	if err != nil {
		return selectedSideRefillQualification{}, err
	}
	header, err := consensus.ParseBlockHeaderBytes(raw)
	if err != nil {
		return selectedSideRefillQualification{}, &consensus.TxError{Code: consensus.BLOCK_ERR_PARSE, Msg: "invalid block header"}
	}
	if !selectedRefillDomain(authority) {
		return selectedSideRefillQualification{}, selectedQualFailure(selectedQualBranch, "selected side refill needs a cleaned one-slot side without a pending SIDE")
	}
	q := &selectedSideQualifier{reader: reader, authority: authority, side: authority.SelectedSide, slots: 1}
	q.consulted = make([]mdbx.ConsultedRow, 0, selectedQualIdentities)
	q.consult(0, []byte{2})
	return q.refill(raw, header)
}

// selectedRefillDomain is the cleaned one-slot side (count 1439 with first above F+1) and no SIDE span.
func selectedRefillDomain(a mdbx.StorageAuthorityV1) bool {
	s := a.SelectedSide
	if s == nil || s.RowCount != 1439 || s.TipHeight-uint64(s.RowCount) == s.F {
		return false
	}
	return a.Cleanup == nil || !slices.ContainsFunc(a.Cleanup.Spans, func(span mdbx.CleanupSpanV1) bool { return span.Kind == mdbx.CleanupSpanSideV1 })
}

func (q *selectedSideQualifier) refill(raw []byte, header consensus.BlockHeader) (selectedSideRefillQualification, error) {
	first := q.side.TipHeight - 1438
	row, linking, err := q.refillFirst(first)
	if err != nil {
		return selectedSideRefillQualification{}, err
	}
	if hash, _ := consensus.BlockHash(raw[:consensus.BLOCK_HEADER_BYTES]); hash != row.header.PrevBlockHash {
		return selectedSideRefillQualification{}, selectedQualFailure(selectedQualBranch, "refill candidate is not the first retained row's parent")
	}
	if err := q.refillLinkAbsent(first - 1); err != nil {
		return selectedSideRefillQualification{}, err
	}
	work, err := selectedRefillWork([40]byte(row.link[64:104]), row.header.Target)
	if _, stored := err.(*consensus.TxError); stored { //nolint:errorlint // The helper's direct WorkFromTarget leaf only.
		return selectedSideRefillQualification{}, q.request(first) // The first stored header's target is outside its domain.
	}
	if err != nil {
		return selectedSideRefillQualification{}, err
	}
	parent, err := q.refillParent(header.PrevBlockHash, first-2)
	if err != nil {
		return selectedSideRefillQualification{}, err
	}
	return q.refillChild(raw, header, parent, work, linking)
}

// refillFirst verifies the first retained row: required SideLink, keyed header, header parent equal to the link
// parent, and its body by keyed owner height (Owned at k>=B required, else optional) with header and commitments.
// An optional defect is that row's recheck locator. The body's exact length is kept.
func (q *selectedSideQualifier) refillFirst(first uint64) (selectedRefillFirst, uint64, error) {
	if err := q.reserve(1); err != nil {
		return selectedRefillFirst{}, 0, err
	}
	link, err := q.reader.ReadRequiredSideLink(q.side.GenerationID, first)
	if err != nil {
		return selectedRefillFirst{}, 0, selectedQualRead(err, selectedQualBranch)
	}
	key, _ := mdbx.HeightKey(q.side.GenerationID, first) // Legal authority proved the generation nonzero.
	q.consult(6, key)
	owner, raw, err := q.keyedHeader([32]byte(link[:32]))
	if err != nil {
		return selectedRefillFirst{}, 0, err
	}
	if raw == nil || !bytes.Equal(raw[4:36], link[32:64]) {
		return selectedRefillFirst{}, 0, q.request(first)
	}
	body, err := q.refillBody([32]byte(link[:32]), raw, owner.Owned && owner.Height >= q.authority.B, first)
	if err != nil {
		return selectedRefillFirst{}, 0, err
	}
	header, _ := consensus.ParseBlockHeaderBytes(raw) // A 116-byte header always decodes.
	return selectedRefillFirst{header: header, link: link}, uint64(len(body)), nil
}

func (q *selectedSideQualifier) refillBody(hash [32]byte, header []byte, required bool, first uint64) ([]byte, error) {
	read := q.optionalRow
	if required {
		read = q.requiredRow
	}
	body, err := read(4, hash)
	switch {
	case err != nil:
		return nil, err
	case selectedRetainLinkingHealthy(body, header):
		return body, nil
	case required:
		return nil, selectedQualFailure(selectedQualIntegrity, "required canonical body does not match its header or commitments")
	}
	return nil, q.request(first)
}

// refillLinkAbsent reads the exact SideLink(g,first-1) key: a present row (identical included) is branch_data, an
// invalid width is the Reader's recorded integrity, a transient read is branch_data and absence is consulted.
func (q *selectedSideQualifier) refillLinkAbsent(height uint64) error {
	if err := q.reserve(1); err != nil {
		return err
	}
	key, _ := mdbx.HeightKey(q.side.GenerationID, height) // Legal authority proved the generation nonzero.
	_, present, err := q.reader.Get(mdbx.SchemaV2DBIs()[6], key)
	if err != nil {
		return selectedQualRead(err, selectedQualBranch)
	}
	q.consult(6, key)
	if present {
		return selectedQualFailure(selectedQualBranch, "selected side refill height already has a SideLink")
	}
	return nil
}

// selectedRefillWork is the restored link work: first-link work minus the first header's own block work, which must
// stay positive (checked subtraction).
func selectedRefillWork(firstWork [40]byte, target [32]byte) ([40]byte, error) {
	block, err := consensus.WorkFromTarget(target)
	if err != nil {
		return [40]byte{}, err
	}
	rest := new(big.Int).Sub(new(big.Int).SetBytes(firstWork[:]), block)
	if rest.Sign() <= 0 {
		return [40]byte{}, selectedQualFailure(selectedQualBranch, "selected side refill work underflows")
	}
	var work [40]byte
	rest.FillBytes(work[:]) // rest < first-link work < 2^320.
	return work, nil
}

// refillParent proves the candidate's parent at height first-2: an Owned canonical block at exactly that height, or a
// hash-bound unowned historical header (whose context below is then the existing ancestry rules); a missing header is
// unpromised history, branch_data.
func (q *selectedSideQualifier) refillParent(hash [32]byte, height uint64) (selectedQualParent, error) {
	owner, raw, err := q.keyedHeader(hash)
	switch {
	case err != nil:
		return selectedQualParent{}, err
	case owner.Owned && owner.Height != height:
		return selectedQualParent{}, selectedQualFailure(selectedQualBranch, "refill parent is canonical at another height")
	case raw == nil:
		return selectedQualParent{}, selectedQualFailure(selectedQualBranch, "selected side refill parent history is unavailable")
	case height == q.side.F && !owner.Owned:
		// The parent occupies the ancestry's slot 0, which never reaches anchorHeader: at F it must be the Owned anchor.
		return selectedQualParent{}, selectedQualFailure(selectedQualBranch, "selected side anchor is not the canonical block at F")
	}
	header, _ := consensus.ParseBlockHeaderBytes(raw) // A 116-byte header always decodes.
	parent := selectedQualParent{hash: hash, height: height, f: q.side.F, header: header}
	if owner.Owned {
		parent.f, parent.work = height, [40]byte(owner.Entry[64:104])
	}
	return parent, nil
}

// refillChild runs the existing context (expected target and newest-first MTP window), steps 1-12, then the work
// recurrence against an Owned parent and the height/work domain; no selection against the incumbent tip.
func (q *selectedSideQualifier) refillChild(raw []byte, header consensus.BlockHeader, parent selectedQualParent, work [40]byte, linking uint64) (selectedSideRefillQualification, error) {
	height, target, timestamps, err := q.childContext(parent)
	if err != nil {
		return selectedSideRefillQualification{}, err
	}
	summary, err := consensus.ValidateBlockSteps1To12(raw, parent.hash, target, height, timestamps)
	if errors.Is(err, consensus.ErrBlockSteps1To12Context) {
		return selectedSideRefillQualification{}, &selectedSideQualificationError{Result: selectedQualBranch, Cause: err}
	}
	if err != nil {
		return selectedSideRefillQualification{}, err
	}
	if err := selectedRefillRecurrence(parent, header.Target, work); err != nil {
		return selectedSideRefillQualification{}, err
	}
	if !selectedQualDomain(height, work) {
		return selectedSideRefillQualification{}, selectedQualFailure(selectedQualBranch, "refill row is outside the height or chainwork domain")
	}
	qual := q.result(summary, false, parent, height, work)
	return selectedSideRefillQualification{
		Authority: qual.Authority, Summary: summary, Height: height, ParentHash: parent.hash, Work: work, Linking: linking, Consulted: qual.Consulted,
	}, nil
}

// selectedRefillRecurrence requires an Owned parent's verified work plus the candidate's block work to equal the
// restored link work. An unowned historical parent has no independently verified cumulative work: the restored work is
// anchored only on the retained first link, so the parent's implied work (restored minus the candidate's block work)
// must merely stay positive, as every real chainwork is; no full historical work equality is claimed.
func selectedRefillRecurrence(parent selectedQualParent, target [32]byte, work [40]byte) error {
	if parent.work == ([40]byte{}) {
		_, err := selectedRefillWork(work, target)
		return err
	}
	block, err := consensus.WorkFromTarget(target)
	if err != nil {
		return err
	}
	var sum [40]byte
	block.Add(block, new(big.Int).SetBytes(parent.work[:])).FillBytes(sum[:]) // <= 2^288 + 2^256 < 2^320.
	if sum != work {
		return selectedQualFailure(selectedQualBranch, "refill work does not extend its canonical parent")
	}
	return nil
}

// refill is RF's node consumer: the frozen same-Reader qualification, the candidate CanonicalOwnerV1 (Owned is the
// canonical no-op), the 3n+L preflight with L the first retained body, then the shared expected-row/authority write
// with count 1440, bytes+n and every other descriptor field unchanged.
func (a *selectedRetainAttempt) refill(reader *mdbx.Reader) (mdbx.Batch, error) {
	qual, err := qualifySelectedRefillMDBX(reader, a.raw)
	if err != nil {
		return mdbx.Batch{}, err
	}
	q := &selectedSideQualifier{reader: reader, authority: qual.Authority, side: qual.Authority.SelectedSide, consulted: qual.Consulted, slots: len(qual.Consulted)}
	r := &selectedRetention{selectedSideQualifier: q, attempt: a}
	owner, err := r.canonicalOwnerOf(qual.Summary.BlockHash)
	if err != nil {
		return mdbx.Batch{}, err
	}
	n := uint64(len(a.raw))
	switch {
	case owner.Owned:
		return mdbx.Batch{}, a.decide(selectedRetainKnown, "", "NOT_APPLICABLE")
	case !selectedRetainFits(n, qual.Linking):
		return mdbx.Batch{}, a.decide(selectedRetainCapacity, "", "OLD")
	}
	side := *r.side
	side.RowCount, side.LogicalBytes = 1440, side.LogicalBytes+n
	return r.write(selectedSideQualification{Summary: qual.Summary, Height: qual.Height, ParentHash: qual.ParentHash, Work: qual.Work, Authority: qual.Authority}, qual.Authority.NextGenerationID, side)
}
