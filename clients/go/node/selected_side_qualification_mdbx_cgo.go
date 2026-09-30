//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Dormant same-Reader qualification of one direct child of an Owned active canonical parent or of the exact selected
// tip (RUBIN_MEMPOOL_POLICY.md Sections 6.4.1.3-6.4.1.6 and 6.4.1.9, RUBIN_COMPACT_BLOCKS.md Section 10.2,
// RUBIN_L1_CANONICAL.md Section 25 steps 1-12). qualifySelectedSideMDBX has no production caller: it reads through the
// caller's Reader inside the caller's single enclosing reservation, writes nothing, builds no Batch, owns no grant,
// callback, goroutine or retry, and returns no transferable certificate.

const (
	selectedQualIntegrity        = "TERMINAL_STORE_INTEGRITY(canonical)"
	selectedQualBranch           = "LOCAL_RESOURCE_UNAVAILABLE(branch_data)"
	selectedQualCanonical        = "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"
	selectedQualRecovery         = "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)"
	selectedQualRecoveryRequired = "RECOVERY_REQUIRED"
	// selectedQualIdentities is N, the distinct relied-on identity ceiling; slots are preflighted before every read.
	selectedQualIdentities = 16_384
	// selectedQualWindow is K, the retarget window of hash-linked headers read newest-first at h%10080 == 0.
	selectedQualWindow = 10_080
)

// selectedSideQualification is one invocation-owned result. Work values are 40-byte big-endian; Consulted holds each
// relied-on identity once in (DBI.Rank, key) order. No field aliases raw, a Tx, a body or a Reader buffer.
type selectedSideQualification struct {
	Summary      consensus.BlockBasicSummary
	Selected     bool
	ParentHash   [32]byte
	ParentHeight uint64
	F            uint64
	Height       uint64
	ParentWork   [40]byte
	Work         [40]byte
	Authority    mdbx.StorageAuthorityV1
	Consulted    []mdbx.ConsultedRow
}

// selectedSideQualificationError is a classified refusal; Cause keeps the original EngineError or diagnostic.
type selectedSideQualificationError struct {
	Result string
	Cause  error
}

func (e *selectedSideQualificationError) Error() string { return e.Result + ": " + e.Cause.Error() }
func (e *selectedSideQualificationError) Unwrap() error { return e.Cause }

func selectedQualFailure(result, diagnostic string) error {
	return &selectedSideQualificationError{Result: result, Cause: errors.New(diagnostic)}
}

// selectedSideDamageRequest asks a later owner for a fresh recheck of one selected height after the callback ends. It
// proves neither physical selected-side membership nor authority to clear, shrink or transition anything.
type selectedSideDamageRequest struct {
	Generation, Tip, Height uint64
}

func (r *selectedSideDamageRequest) Error() string {
	return fmt.Sprintf("selected side damage recheck requested: generation %d tip %d height %d", r.Generation, r.Tip, r.Height)
}

// selectedQualRead classifies a Reader failure: Integrity is canonical integrity, a transient class takes the read's
// resource class, and every other class (InvalidInput included) is returned unchanged.
func selectedQualRead(err error, transient string) error {
	var engine *mdbx.EngineError
	if !errors.As(err, &engine) {
		return err
	}
	switch engine.Class {
	case mdbx.EngineIntegrity:
		return &selectedSideQualificationError{Result: selectedQualIntegrity, Cause: err}
	case mdbx.EngineIO, mdbx.EngineTransaction, mdbx.EngineConcurrency:
		return &selectedSideQualificationError{Result: transient, Cause: err}
	case mdbx.EngineInvalidInput, mdbx.EngineCapacity, mdbx.EngineStateMismatch, mdbx.EngineLocalInvariant:
	}
	return err
}

// selectedQualParent is the proved parent: identity, key-bound height, F, verified work and verified header.
type selectedQualParent struct {
	hash     [32]byte
	height   uint64
	f        uint64
	work     [40]byte
	header   consensus.BlockHeader
	selected bool
}

// selectedQualTip is the verified selected tip evidence: its link, keyed owner and hash-bound header.
type selectedQualTip struct {
	link, header []byte
	owner        mdbx.CanonicalOwnerResultV1
}

// selectedSideQualifier is the private per-invocation state. hashes and times are the fixed newest-first ancestry
// identity and timestamp windows (both charged in K*(32+8) of Q).
type selectedSideQualifier struct {
	reader    *mdbx.Reader
	authority mdbx.StorageAuthorityV1
	side      *mdbx.SelectedSideV1
	consulted []mdbx.ConsultedRow
	slots     int
	hashes    [selectedQualWindow][32]byte
	times     [selectedQualWindow]uint64
}

// qualifySelectedSideMDBX runs authority/control, raw bound, candidate header, eligible parent evidence, context,
// steps 1-12, B102 selection and the selected domain in that order. Every error returns the zero qualification; the
// evidence workspace is allocated only after the authority prefix passes.
func qualifySelectedSideMDBX(reader *mdbx.Reader, raw []byte) (selectedSideQualification, error) {
	authority, err := selectedQualAuthority(reader, len(raw))
	if err != nil {
		return selectedSideQualification{}, err
	}
	q := &selectedSideQualifier{reader: reader, authority: authority, side: authority.SelectedSide, slots: 1}
	q.consulted = make([]mdbx.ConsultedRow, 0, selectedQualIdentities)
	q.consult(0, []byte{2})
	header, err := consensus.ParseBlockHeaderBytes(raw)
	if err != nil {
		return selectedSideQualification{}, &consensus.TxError{Code: consensus.BLOCK_ERR_PARSE, Msg: "invalid block header"}
	}
	parent, err := q.parentEvidence(header.PrevBlockHash)
	if err != nil {
		return selectedSideQualification{}, err
	}
	return q.qualifyChild(raw, header, parent)
}

// selectedQualAuthority reads the strict authority (its failures unchanged), applies the control table and then the
// raw bound, before any candidate or parent read or workspace allocation.
func selectedQualAuthority(reader *mdbx.Reader, n int) (mdbx.StorageAuthorityV1, error) {
	authority, err := reader.ReadStorageAuthorityV1()
	if err != nil {
		return mdbx.StorageAuthorityV1{}, err
	}
	if err := selectedQualControl(authority); err != nil {
		return mdbx.StorageAuthorityV1{}, err
	}
	if n > mdbx.MaxBlockBytes {
		return mdbx.StorageAuthorityV1{}, selectedQualFailure(selectedQualBranch, "candidate block exceeds MaxBlockBytes")
	}
	return authority, nil
}

// selectedQualControl is the control table over a legal authority: STABLE (only NONE or PRUNE_GC) proceeds,
// ORDINARY_APPLY/RECOVERY_REQUIRED is a competing invocation, every other RECOVERY_REQUIRED cell is RECOVERY_REQUIRED.
func selectedQualControl(a mdbx.StorageAuthorityV1) error {
	switch {
	case a.Lifecycle == mdbx.StorageLifecycleStableV1:
		return nil
	case a.Phase == mdbx.StoragePhaseOrdinaryApplyV1:
		return selectedQualFailure(selectedQualRecovery, "ordinary apply recovery is in progress")
	default:
		return selectedQualFailure(selectedQualRecoveryRequired, "storage lifecycle requires recovery")
	}
}

func (q *selectedSideQualifier) reserve(n int) error {
	if q.slots > selectedQualIdentities-n {
		return selectedQualFailure(selectedQualBranch, "selected side qualification exceeds 16384 identities")
	}
	q.slots += n
	return nil
}

func (q *selectedSideQualifier) consult(rank uint8, key []byte) {
	q.consulted = append(q.consulted, mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[rank], Key: key})
}

func (q *selectedSideQualifier) request(height uint64) error {
	return &selectedSideDamageRequest{Generation: q.side.GenerationID, Tip: q.side.TipHeight, Height: height}
}

// canonicalOwnerOf preflights two slots, resolves the keyed CanonicalOwnerV1 and releases the slot a NONE result leaves
// unused.
func (q *selectedSideQualifier) canonicalOwnerOf(hash [32]byte) (mdbx.CanonicalOwnerResultV1, error) {
	if err := q.reserve(2); err != nil {
		return mdbx.CanonicalOwnerResultV1{}, err
	}
	owner, err := q.reader.CanonicalOwnerV1(q.authority.ActiveGenerationID, hash)
	if err != nil {
		return mdbx.CanonicalOwnerResultV1{}, selectedQualRead(err, selectedQualCanonical)
	}
	q.slots -= 2 - len(owner.Rows)
	q.consulted = append(q.consulted, owner.Rows...)
	return owner, nil
}

// requiredRow reads a canonical header or body with Get; positive absence is canonical integrity.
func (q *selectedSideQualifier) requiredRow(rank uint8, hash [32]byte) ([]byte, error) {
	if err := q.reserve(1); err != nil {
		return nil, err
	}
	value, present, err := q.reader.Get(mdbx.SchemaV2DBIs()[rank], hash[:])
	if err != nil {
		return nil, selectedQualRead(err, selectedQualCanonical)
	}
	q.consult(rank, bytes.Clone(hash[:]))
	if !present {
		return nil, selectedQualFailure(selectedQualIntegrity, "required canonical row is absent")
	}
	return value, nil
}

// optionalRow reads a non-canonical header or body with GetOptionalSide; nil with a nil error is positive absence or
// a proved invalid width.
func (q *selectedSideQualifier) optionalRow(rank uint8, hash [32]byte) ([]byte, error) {
	if err := q.reserve(1); err != nil {
		return nil, err
	}
	row, err := q.reader.GetOptionalSide(mdbx.SchemaV2DBIs()[rank], hash[:])
	if err != nil {
		return nil, selectedQualRead(err, selectedQualBranch)
	}
	q.consult(rank, bytes.Clone(hash[:]))
	return row.Value, nil
}

// header returns a header that hashes to its key; an optional positive defect is nil with a nil error.
func (q *selectedSideQualifier) header(hash [32]byte, required bool) ([]byte, error) {
	read := q.optionalRow
	if required {
		read = q.requiredRow
	}
	value, err := read(3, hash)
	if err != nil || value == nil {
		return nil, err
	}
	if got, hashErr := consensus.BlockHash(value); hashErr == nil && got == hash {
		return value, nil
	}
	if required {
		return nil, selectedQualFailure(selectedQualIntegrity, "required canonical header does not hash to its key")
	}
	return nil, nil
}

// ownedHeader is the canonical keep evidence of an Owned hash: required header whose parent is the index entry's parent.
func (q *selectedSideQualifier) ownedHeader(hash [32]byte, owner mdbx.CanonicalOwnerResultV1) ([]byte, error) {
	header, err := q.header(hash, true)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(header[4:36], owner.Entry[32:64]) {
		return nil, selectedQualFailure(selectedQualIntegrity, "canonical header does not link to its index entry")
	}
	return header, nil
}

// keyedHeader resolves the hash-keyed owner before any header diagnosis; Owned keeps the stronger canonical path.
func (q *selectedSideQualifier) keyedHeader(hash [32]byte) (mdbx.CanonicalOwnerResultV1, []byte, error) {
	owner, err := q.canonicalOwnerOf(hash)
	if err != nil {
		return mdbx.CanonicalOwnerResultV1{}, nil, err
	}
	if owner.Owned {
		header, err := q.ownedHeader(hash, owner)
		return owner, header, err
	}
	header, err := q.header(hash, false)
	return owner, header, err
}

// parentEvidence uses the selected procedure exactly when the candidate names the descriptor tip.
func (q *selectedSideQualifier) parentEvidence(hash [32]byte) (selectedQualParent, error) {
	if q.side != nil && hash == q.side.TipHash {
		return q.selectedParent()
	}
	return q.canonicalParent(hash)
}

func (q *selectedSideQualifier) canonicalParent(hash [32]byte) (selectedQualParent, error) {
	owner, err := q.canonicalOwnerOf(hash)
	if err != nil {
		return selectedQualParent{}, err
	}
	if !owner.Owned {
		return selectedQualParent{}, selectedQualFailure(selectedQualBranch, "candidate parent is neither an active canonical block nor the selected tip")
	}
	raw, err := q.ownedHeader(hash, owner)
	if err != nil {
		return selectedQualParent{}, err
	}
	header, _ := consensus.ParseBlockHeaderBytes(raw) // A 116-byte header always decodes.
	return selectedQualParent{hash: hash, height: owner.Height, f: owner.Height, work: [40]byte(owner.Entry[64:104]), header: header}, nil
}

func (q *selectedSideQualifier) selectedParent() (selectedQualParent, error) {
	tip, err := q.selectedTip()
	if err != nil {
		return selectedQualParent{}, err
	}
	if err := q.linkingBody(tip); err != nil {
		return selectedQualParent{}, err
	}
	header, _ := consensus.ParseBlockHeaderBytes(tip.header) // A 116-byte header always decodes.
	return selectedQualParent{hash: q.side.TipHash, height: q.side.TipHeight, f: q.side.F, work: [40]byte(tip.link[64:104]), header: header, selected: true}, nil
}

// selectedTip is link -> keyed owner -> header -> link parent and descriptor work agreement; it never reads a body.
func (q *selectedSideQualifier) selectedTip() (selectedQualTip, error) {
	link, err := q.sideLink()
	if err != nil {
		return selectedQualTip{}, err
	}
	owner, header, err := q.keyedHeader(q.side.TipHash)
	if err != nil {
		return selectedQualTip{}, err
	}
	if header == nil || !bytes.Equal(header[4:36], link[32:64]) || [40]byte(link[64:104]) != q.side.CumulativeChainwork {
		return selectedQualTip{}, q.request(q.side.TipHeight)
	}
	return selectedQualTip{link: link, header: header, owner: owner}, nil
}

// sideLink reads the key-bound tip SideLink; a link naming another hash is canonical integrity, never a request.
func (q *selectedSideQualifier) sideLink() ([]byte, error) {
	if err := q.reserve(1); err != nil {
		return nil, err
	}
	link, err := q.reader.ReadRequiredSideLink(q.side.GenerationID, q.side.TipHeight)
	if err != nil {
		return nil, selectedQualRead(err, selectedQualBranch)
	}
	key, _ := mdbx.HeightKey(q.side.GenerationID, q.side.TipHeight) // Legal authority proved the generation nonzero.
	q.consult(6, key)
	if [32]byte(link[:32]) != q.side.TipHash {
		return nil, selectedQualFailure(selectedQualIntegrity, "selected side link does not name the descriptor tip")
	}
	return link, nil
}

// linkingBody requires the actual parent body by its keyed owner height: Owned at k>=B is canonical, otherwise optional.
func (q *selectedSideQualifier) linkingBody(tip selectedQualTip) error {
	required := tip.owner.Owned && tip.owner.Height >= q.authority.B
	read := q.optionalRow
	if required {
		read = q.requiredRow
	}
	body, err := read(4, q.side.TipHash)
	if err != nil {
		return err
	}
	if body != nil && bytes.Equal(body[:consensus.BLOCK_HEADER_BYTES], tip.header) && consensus.ValidateBlockBodyCommitments(body) == nil {
		return nil
	}
	if required {
		return selectedQualFailure(selectedQualIntegrity, "required canonical body does not match its header or commitments")
	}
	return q.request(q.side.TipHeight)
}

// qualifyChild runs context, steps 1-12, selection and the winner's domain.
func (q *selectedSideQualifier) qualifyChild(raw []byte, header consensus.BlockHeader, parent selectedQualParent) (selectedSideQualification, error) {
	height, target, timestamps, err := q.childContext(parent)
	if err != nil {
		return selectedSideQualification{}, err
	}
	summary, err := consensus.ValidateBlockSteps1To12(raw, parent.hash, target, height, timestamps)
	if errors.Is(err, consensus.ErrBlockSteps1To12Context) {
		return selectedSideQualification{}, &selectedSideQualificationError{Result: selectedQualBranch, Cause: err}
	}
	if err != nil {
		return selectedSideQualification{}, err
	}
	work, selected, err := q.selection(parent, header.Target, summary.BlockHash)
	if err != nil {
		return selectedSideQualification{}, err
	}
	if selected && !selectedQualDomain(height, work) {
		return selectedSideQualification{}, selectedQualFailure(selectedQualBranch, "selected path is outside the height or chainwork domain")
	}
	return q.result(summary, selected, parent, height, work), nil
}

// childContext computes the checked child height, reads the same-branch ancestry and derives the expected target and
// the newest-first min(h,11) MTP window.
func (q *selectedSideQualifier) childContext(parent selectedQualParent) (uint64, [32]byte, []uint64, error) {
	height := parent.height + 1
	if height == 0 {
		return 0, [32]byte{}, nil, selectedQualFailure(selectedQualBranch, "candidate height overflows")
	}
	boundary := height%selectedQualWindow == 0
	count := min(height, 11)
	if boundary {
		count = selectedQualWindow
	}
	if err := q.ancestry(parent, int(count)); err != nil { //nolint:gosec // count <= 10080.
		return 0, [32]byte{}, nil, err
	}
	timestamps := slices.Clone(q.times[:min(height, 11)])
	if !boundary {
		return height, parent.header.Target, timestamps, nil
	}
	slices.Reverse(q.times[:])
	target, err := consensus.RetargetV1Clamped(parent.header.Target, q.times[:])
	if err != nil {
		return 0, [32]byte{}, nil, &selectedSideQualificationError{Result: selectedQualBranch, Cause: err}
	}
	return height, target, timestamps, nil
}

// ancestry fills hashes/times newest-first with count hash-linked headers ending at the parent. Before each read the
// requested identity is linearly searched among the visited ones (at most 10080*10079/2 comparisons, no map); a repeat
// would need a hash cycle and is refused as unusable branch data.
func (q *selectedSideQualifier) ancestry(parent selectedQualParent, count int) error {
	q.hashes[0], q.times[0] = parent.hash, parent.header.Timestamp
	prev := parent.header.PrevBlockHash
	for i := 1; i < count; i++ {
		if slices.Contains(q.hashes[:i], prev) {
			return selectedQualFailure(selectedQualBranch, "selected side ancestry repeats an identity")
		}
		q.hashes[i] = prev
		header, err := q.ancestor(parent, parent.height-uint64(i), prev)
		if err != nil {
			return err
		}
		q.times[i], prev = header.Timestamp, header.PrevBlockHash
	}
	return nil
}

// ancestor reads the header at reference height r: below F from the inherited verified canonical prefix, at F through
// the paired Owned anchor, above F through its keyed owner first.
func (q *selectedSideQualifier) ancestor(parent selectedQualParent, r uint64, hash [32]byte) (consensus.BlockHeader, error) {
	var raw []byte
	var err error
	switch {
	case r < parent.f:
		raw, err = q.header(hash, true)
	case r == parent.f:
		raw, err = q.anchorHeader(hash)
	default:
		raw, err = q.sideHeader(hash, r)
	}
	if err != nil {
		return consensus.BlockHeader{}, err
	}
	header, _ := consensus.ParseBlockHeaderBytes(raw) // A 116-byte header always decodes.
	return header, nil
}

// anchorHeader requires the F identity to be Owned at exactly height F; anything else is unproved F.
func (q *selectedSideQualifier) anchorHeader(hash [32]byte) ([]byte, error) {
	owner, err := q.canonicalOwnerOf(hash)
	if err != nil {
		return nil, err
	}
	if !owner.Owned || owner.Height != q.side.F {
		return nil, selectedQualFailure(selectedQualBranch, "selected side anchor is not the canonical block at F")
	}
	return q.ownedHeader(hash, owner)
}

// sideHeader diagnoses an unusable unowned header above F: inside the retained rows it is a recheck request for that
// height, below them it is unusable branch data with no locator.
func (q *selectedSideQualifier) sideHeader(hash [32]byte, r uint64) ([]byte, error) {
	_, header, err := q.keyedHeader(hash)
	if err != nil || header != nil {
		return header, err
	}
	if r >= q.side.TipHeight-uint64(q.side.RowCount)+1 {
		return nil, q.request(r)
	}
	return nil, selectedQualFailure(selectedQualBranch, "selected side ancestry below the retained rows is unusable")
}

// selection sums the checked 320-bit work and applies B102 against the selected tip, verifying a comparison-only tip
// for a canonical-parent candidate; without a selected side the candidate is selected.
func (q *selectedSideQualifier) selection(parent selectedQualParent, target, hash [32]byte) ([40]byte, bool, error) {
	blockWork, err := consensus.WorkFromTarget(target)
	if err != nil {
		return [40]byte{}, false, err
	}
	var work [40]byte
	blockWork.Add(blockWork, new(big.Int).SetBytes(parent.work[:])).FillBytes(work[:]) // <= 2^288 + 2^256 < 2^320.
	if q.side == nil {
		return work, true, nil
	}
	if !parent.selected {
		if _, err := q.selectedTip(); err != nil {
			return [40]byte{}, false, err
		}
	}
	order := bytes.Compare(work[:], q.side.CumulativeChainwork[:])
	return work, order > 0 || order == 0 && bytes.Compare(hash[:], q.side.TipHash[:]) < 0, nil
}

// selectedQualDomain is 0 < height <= 0xffffffff and 0 < work <= 2^288; both lower bounds hold by construction.
func selectedQualDomain(height uint64, work [40]byte) bool {
	var limit [40]byte
	limit[3] = 1
	return height <= 0xffffffff && bytes.Compare(work[:], limit[:]) <= 0
}

// result orders Consulted in place by (DBI.Rank, key) and keeps each identity once.
func (q *selectedSideQualifier) result(summary consensus.BlockBasicSummary, selected bool, parent selectedQualParent, height uint64, work [40]byte) selectedSideQualification {
	slices.SortFunc(q.consulted, func(a, b mdbx.ConsultedRow) int {
		return cmp.Or(cmp.Compare(a.DBI.Rank, b.DBI.Rank), bytes.Compare(a.Key, b.Key))
	})
	consulted := slices.CompactFunc(q.consulted, func(a, b mdbx.ConsultedRow) bool {
		return a.DBI.Rank == b.DBI.Rank && bytes.Equal(a.Key, b.Key)
	})
	return selectedSideQualification{
		Summary: summary, Selected: selected, ParentHash: parent.hash, ParentHeight: parent.height, F: parent.f, Height: height,
		ParentWork: parent.work, Work: work, Authority: q.authority, Consulted: consulted,
	}
}
