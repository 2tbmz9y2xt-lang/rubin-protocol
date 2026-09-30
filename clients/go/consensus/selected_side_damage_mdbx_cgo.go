//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"cmp"
	"errors"
	"math/big"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Dormant one-height selected-side damage handling (RUBIN_MEMPOOL_POLICY.md Sections 6.4.1.3, 6.4.1.5, 6.4.1.6 and
// 6.4.1.9). selectedSideDamageMDBX has no production caller. Each valid-owner invocation performs one outer full-lane
// reservation attempt and exactly one Store.Update, and reports its logical classification beside the unmodified raw
// tuple. No ChainState latch, publication or wakeup is performed here; those consumers belong to later runtime owners.

const (
	selectedSideIntegrity = "TERMINAL_STORE_INTEGRITY(canonical)"
	selectedSideInvariant = "TERMINAL_LOCAL_INVARIANT(evidence)"
	selectedSideCleared   = "LOCAL_STORE_ERROR(noncanonical)"
	selectedSidePrecommit = "LOCAL_PERSISTENCE_ERROR(precommit)"
	selectedSideBranch    = "LOCAL_RESOURCE_UNAVAILABLE(branch_data)"
	selectedSideCanonical = "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"
	selectedSideCapacity  = "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"
	// selectedSideTransferBytes is the checked sublimit for transfer keys, rows, retained headers/links/owner entries,
	// Consulted, targets and Batch literals.
	selectedSideTransferBytes uint64 = 8_388_608
	selectedSideConsultedRows int    = 16_384
	// selectedSideBodyCharge is the contract-named body subtotal: one owned body copy and one borrowed Consulted OLD
	// body image of at most MaxBlockBytes each, the first and current Tx element arrays (1024 inputs, outputs and
	// witness items of at most 64, 40 and 56 bytes) and two 64-level frontiers of 32-byte nodes.
	selectedSideBodyCharge uint64 = 2*68_000_125 + 2*1024*(64+40+56) + 2*64*32
	// Transfer charge, charged up front after granted qualification plus H. Per leaving height at most 2208 bytes are
	// owned or captured: links slot 24 + cached record 128, two owner ConsultedRows 96, held link/entry/header copies
	// 352, source and Update-cloned keys 288, original and sorted consulted descriptors 384, delete/Batch/Update
	// Mutation arrays 384, Update consulted array 288, two target image arrays 48, borrowed SideLink/entry/owner OLD
	// images 216 — under the 2304 charged. 4*MaxMetadataBytes covers every concurrently held or captured authority
	// buffer (decoded exclusion, Batch literal, Update clone, native OLD image); 131072 covers the anchor, body key,
	// spans, fixed Tx/DA/hash/work values, control structs and rounding. H is the actual native length of each
	// distinct observed header. At n=1440 with legal headers the total is 7810176 <= selectedSideTransferBytes.
	selectedSideAuthorityCharge uint64 = 4 * 1_048_576
	selectedSideFixedCharge     uint64 = 131_072
	selectedSideHeightCharge    uint64 = 2_304
	// selectedSideCapacityText is the frozen reservation owner's direct capacity refusal; any other no-callback error
	// (its input refusal included) is returned unchanged as API failure.
	selectedSideCapacityText string = "storage operation reservation capacity unavailable"
)

// The named body subtotal plus the transfer sublimit fit the full lane; a violation does not compile.
const _ = mdbx.MaxOperationDataBytes - (selectedSideBodyCharge + selectedSideTransferBytes)

var errSelectedSideRequest = errors.New("selected side damage request does not match committed authority")

// selectedSideOutcome is the logical result beside the raw Update tuple. Result "" with nil Err is the healthy no-op;
// Result "" with a non-nil Err is an API refusal that carries no damage/clear classification.
type selectedSideOutcome struct {
	Result         string
	CanonicalTruth string // "OLD", or "NOT_APPLICABLE" once the side-only clear reached its possible commit point
	Truth          mdbx.CommitTruth
	Stage          mdbx.UpdateStage
	Err            error
}

// selectedSideFailure is a consensus-detected callback result; it never claims that the Store was consumed.
type selectedSideFailure struct {
	result string
	cause  error
}

func (f *selectedSideFailure) Error() string { return f.result + ": " + f.cause.Error() }
func (f *selectedSideFailure) Unwrap() error { return f.cause }

func selectedSideDefect(message string) error {
	return &selectedSideFailure{result: selectedSideIntegrity, cause: errors.New(message)}
}

// selectedSideDamagePlan is one invocation's private callback state. step names the resource class of the artifact read in
// flight; it is unset during authority/metadata qualification and cleared once the callback returns a Batch or the
// healthy sentinel, so infrastructure errors outside an artifact read keep their native storage class.
type selectedSideDamagePlan struct {
	generation, tip, height uint64
	healthy, denied         error
	step                    string
}

func selectedSideDamageMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, generation, tip, height uint64) selectedSideOutcome {
	plan := &selectedSideDamagePlan{generation: generation, tip: tip, height: height, healthy: errors.New("selected side row is healthy")}
	out := selectedSideOutcome{CanonicalTruth: "OLD", Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite}
	ran := false
	err := reservations.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		ran = true
		out.Truth, out.Stage, out.Err = store.Update(plan.batch)
		return out.Err
	})
	if ran {
		return selectedSideDamageProject(out, plan)
	}
	if err.Error() != selectedSideCapacityText {
		out.Err = err
		return out
	}
	plan.denied = err
	out.Truth, out.Stage, out.Err = store.Update(plan.batch)
	return selectedSideDamageProject(out, plan)
}

func (p *selectedSideDamagePlan) batch(reader *mdbx.Reader) (mdbx.Batch, error) {
	p.step = ""
	authority, err := reader.ReadStorageAuthorityV1()
	if err != nil {
		return mdbx.Batch{}, err
	}
	if err := p.qualify(authority); err != nil {
		return mdbx.Batch{}, err
	}
	e := newSelectedSideEvidence(reader, authority)
	damaged, err := e.health(p)
	if err != nil {
		return mdbx.Batch{}, err
	}
	if !damaged {
		p.step = ""
		return mdbx.Batch{}, p.healthy
	}
	batch, err := e.transfer(p)
	if err == nil {
		p.step = ""
	}
	return batch, err
}

// qualify is the complete authority/control qualification; a denied reservation returns its exact capacity refusal
// only after it, before any artifact read or data allocation.
func (p *selectedSideDamagePlan) qualify(a mdbx.StorageAuthorityV1) error {
	side := a.SelectedSide
	if side == nil || side.GenerationID != p.generation || side.TipHeight != p.tip {
		return errSelectedSideRequest
	}
	if p.height > side.TipHeight || p.height < selectedSideFirst(side) {
		return errSelectedSideRequest
	}
	return p.denied
}

func selectedSideFirst(side *mdbx.SelectedSideV1) uint64 {
	return side.TipHeight - uint64(side.RowCount) + 1
}

// selectedSideCachedRow is the one observation record of a distinct leaving hash. ownerRead distinguishes a cached
// NONE; headerRead records that the header was observed (present, absent, invalid width or wrong hash), while header
// keeps bytes only when they hash to the key.
type selectedSideCachedRow struct {
	hash                                 [32]byte
	owner                                mdbx.CanonicalOwnerResultV1
	header                               []byte
	ownerRead, headerRead, headerPresent bool
}

// selectedSideEvidence holds the observations of one committed pre-state; every relied-on row enters consulted. All
// collections are preallocated to their proved bounds for n leaving rows: n link slots (nil is an unread slot; a link is
// cached only once read and valid), at most n distinct hash records, and at most 4n+2 consulted rows.
type selectedSideEvidence struct {
	reader     *mdbx.Reader
	authority  mdbx.StorageAuthorityV1
	side       *mdbx.SelectedSideV1
	first      uint64
	links      [][]byte
	rows       []selectedSideCachedRow
	consulted  []mdbx.ConsultedRow
	charge     uint64 // saturating transfer charge
	bodyNative uint64 // actual native length of the one relied-on body, captured again by Update as Consulted OLD
}

// newSelectedSideEvidence runs only after granted qualification and charges the fixed transfer terms up front.
func newSelectedSideEvidence(reader *mdbx.Reader, a mdbx.StorageAuthorityV1) *selectedSideEvidence {
	n := int(a.SelectedSide.RowCount)
	e := &selectedSideEvidence{
		reader: reader, authority: a, side: a.SelectedSide, first: selectedSideFirst(a.SelectedSide),
		links: make([][]byte, n), rows: make([]selectedSideCachedRow, 0, n), consulted: make([]mdbx.ConsultedRow, 0, 4*n+2),
	}
	e.add(selectedSideAuthorityCharge + selectedSideFixedCharge + uint64(a.SelectedSide.RowCount)*selectedSideHeightCharge)
	return e
}

// consult records one relied-on exact row; its cost is inside the fixed per-height and fixed transfer terms.
func (e *selectedSideEvidence) consult(rank uint8, key []byte) {
	e.consulted = append(e.consulted, mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[rank], Key: key})
}

// row returns the record of hash, appending its first record; every hash comes from one of the n leaving SideLinks,
// so the preallocated capacity never grows.
func (e *selectedSideEvidence) row(hash [32]byte) *selectedSideCachedRow {
	for i := range e.rows {
		if e.rows[i].hash == hash {
			return &e.rows[i]
		}
	}
	e.rows = append(e.rows, selectedSideCachedRow{hash: hash})
	return &e.rows[len(e.rows)-1]
}

// add charges n transfer bytes and saturates above the sublimit, so clearBatch refuses before any Batch exists.
func (e *selectedSideEvidence) add(n uint64) {
	if n > selectedSideTransferBytes || e.charge > selectedSideTransferBytes-n {
		e.charge = selectedSideTransferBytes + 1
		return
	}
	e.charge += n
}

func (e *selectedSideEvidence) link(p *selectedSideDamagePlan, height uint64) ([]byte, error) {
	if value := e.links[height-e.first]; value != nil {
		return value, nil
	}
	p.step = selectedSideBranch
	value, err := e.reader.ReadRequiredSideLink(e.side.GenerationID, height)
	if err != nil {
		return nil, err
	}
	key, _ := mdbx.HeightKey(e.side.GenerationID, height) // Legal authority proved the generation nonzero.
	e.links[height-e.first] = value
	e.consult(6, key)
	return value, nil
}

// owner resolves the hash-keyed CanonicalOwnerV1 once per distinct hash (a cached NONE included); its height k, not
// the reference height, decides every keep. The frozen owner already proves the returned entry's legal work domain.
func (e *selectedSideEvidence) owner(p *selectedSideDamagePlan, hash [32]byte) (mdbx.CanonicalOwnerResultV1, error) {
	r := e.row(hash)
	if r.ownerRead {
		return r.owner, nil
	}
	p.step = selectedSideCanonical
	result, err := e.reader.CanonicalOwnerV1(e.authority.ActiveGenerationID, hash)
	if err != nil {
		return mdbx.CanonicalOwnerResultV1{}, err
	}
	r.owner, r.ownerRead = result, true
	for _, row := range result.Rows {
		e.consult(row.DBI.Rank, row.Key)
	}
	return result, nil
}

// readNamed reads a required row through Reader.Get, whose width failure is the Reader's recorded integrity failure,
// and an optional row through GetOptionalSide, whose proved invalid width is reported without a copy.
func (e *selectedSideEvidence) readNamed(p *selectedSideDamagePlan, rank uint8, hash [32]byte, required bool) ([]byte, bool, uint64, error) {
	dbi := mdbx.SchemaV2DBIs()[rank]
	if required {
		p.step = selectedSideCanonical
		value, present, err := e.reader.Get(dbi, hash[:])
		return value, present, uint64(len(value)), err
	}
	p.step = selectedSideBranch
	row, err := e.reader.GetOptionalSide(dbi, hash[:])
	return row.Value, row.Present, row.Length, err
}

// namedRow reads the header (rank 3) or body (rank 4) named by hash. A nil row with a nil error is positive damage of
// an optional row; a required row that is absent or does not hash to its key is a callback-only canonical integrity
// defect, never optional damage.
func (e *selectedSideEvidence) namedRow(p *selectedSideDamagePlan, rank uint8, hash [32]byte, required bool) ([]byte, error) {
	value, present, length, err := e.readNamed(p, rank, hash, required)
	if err != nil {
		return nil, err
	}
	e.observe(rank, hash, present, length)
	if value != nil && sha3_256(value[:BLOCK_HEADER_BYTES]) == hash {
		if rank == 3 {
			e.row(hash).header = value
		}
		return value, nil
	}
	if required {
		return nil, selectedSideDefect("required canonical row is absent or does not hash to its key")
	}
	return nil, nil
}

// observe consults the read row. A distinct header is observed once and adds its actual native length to H (its Go
// copy and the borrowed OLD image Update captures as a target or Consulted row, even when the width is invalid and no
// copy exists); the body copy and its borrowed Consulted OLD image belong to the named body subtotal, so only the
// body's actual native length is kept.
func (e *selectedSideEvidence) observe(rank uint8, hash [32]byte, present bool, length uint64) {
	if rank == 3 {
		r := e.row(hash)
		r.headerRead, r.headerPresent = true, present
		e.add(length)
	} else {
		e.bodyNative = length
	}
	e.consult(rank, bytes.Clone(hash[:]))
}

// health checks the one required height in the fixed order SideLink, CanonicalOwnerV1, header/link, BlockBytes.
func (e *selectedSideEvidence) health(p *selectedSideDamagePlan) (bool, error) {
	link, err := e.link(p, p.height)
	if err != nil {
		return false, err
	}
	hash := [32]byte(link[:32])
	owner, err := e.owner(p, hash)
	if err != nil {
		return false, err
	}
	damaged, err := e.headerHealth(p, p.height, link, owner)
	if err != nil || damaged {
		return damaged, err
	}
	return e.bodyHealth(p, hash, owner.Owned && owner.Height >= e.authority.B)
}

// headerHealth reads the named header as required when CanonicalOwnerV1 owns its hash, and for an owned hash first
// requires the canonical keep evidence (header parent equals the owner entry's parent) before any optional
// SideLink/predecessor/work diagnosis; the cached observation is reused, so nothing is read or charged twice.
func (e *selectedSideEvidence) headerHealth(p *selectedSideDamagePlan, height uint64, link []byte, owner mdbx.CanonicalOwnerResultV1) (bool, error) {
	hash := [32]byte(link[:32])
	header, err := e.namedRow(p, 3, hash, owner.Owned)
	if err != nil || header == nil {
		return err == nil, err
	}
	if owner.Owned {
		if err := e.keptHeader(p, hash, owner.Entry); err != nil {
			return false, err
		}
	}
	if !bytes.Equal(header[4:36], link[32:64]) {
		return true, nil
	}
	return e.predecessor(p, height, link, header)
}

func (e *selectedSideEvidence) bodyHealth(p *selectedSideDamagePlan, hash [32]byte, required bool) (bool, error) {
	body, err := e.namedRow(p, 4, hash, required)
	if err != nil || body == nil {
		return err == nil, err
	}
	if verifyStoredBlockCommitmentsStream(body) == nil {
		return false, nil
	}
	if required {
		return false, selectedSideDefect("required canonical body commitments do not verify")
	}
	return true, nil
}

// predecessor checks parent linkage and cumulative work against the preceding selected link, or against canonical F
// when first=F+1; the first row of a one-slot descriptor has no in-descriptor predecessor.
func (e *selectedSideEvidence) predecessor(p *selectedSideDamagePlan, height uint64, link, header []byte) (bool, error) {
	parent, err := e.parentEntry(p, height)
	if err != nil || parent == nil {
		return false, err
	}
	if !bytes.Equal(parent[:32], link[32:64]) {
		return true, nil
	}
	work, err := WorkFromTarget([32]byte(header[76:108]))
	if err != nil { //nolint:nilerr // An undecodable stored target is positive optional damage of this row, not an error.
		return true, nil
	}
	work.Add(work, new(big.Int).SetBytes(parent[64:104]))
	return work.Cmp(new(big.Int).SetBytes(link[64:104])) != 0, nil
}

func (e *selectedSideEvidence) parentEntry(p *selectedSideDamagePlan, height uint64) ([]byte, error) {
	if height > e.first {
		return e.link(p, height-1)
	}
	if e.first == e.side.F+1 {
		return e.anchor(p)
	}
	return nil, nil
}

// anchor reads the promised active canonical entry at F; Get owns its width, and its absence or chainwork outside
// 0 < work <= 2^288 (RUBIN_MEMPOOL_POLICY.md 6.4.1.2) is a callback-only canonical integrity defect.
func (e *selectedSideEvidence) anchor(p *selectedSideDamagePlan) ([]byte, error) {
	p.step = selectedSideCanonical
	key, _ := mdbx.HeightKey(e.authority.ActiveGenerationID, e.side.F) // Legal authority proved the generation nonzero.
	value, present, err := e.reader.Get(mdbx.SchemaV2DBIs()[2], key)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, selectedSideDefect("canonical anchor entry is absent")
	}
	work := new(big.Int).SetBytes(value[64:104])
	if work.Sign() == 0 || work.Cmp(new(big.Int).Lsh(big.NewInt(1), 288)) > 0 {
		return nil, selectedSideDefect("canonical anchor chainwork is outside its domain")
	}
	e.consult(2, key)
	return value, nil
}

// transfer resolves every leaving SideLink identity and header keep/delete decision from the same pre-state before
// any Batch exists; any required failure returns before mutation.
func (e *selectedSideEvidence) transfer(p *selectedSideDamagePlan) (mdbx.Batch, error) {
	deletes := make([]mdbx.Mutation, 0, len(e.links))
	for height := e.first; height <= e.side.TipHeight; height++ {
		target, err := e.leaving(p, height)
		if err != nil {
			return mdbx.Batch{}, err
		}
		if target != nil && !slices.ContainsFunc(deletes, func(m mdbx.Mutation) bool { return bytes.Equal(m.Key, target.Key) }) {
			deletes = append(deletes, *target)
		}
	}
	return e.clearBatch(deletes)
}

// leaving returns the header deletion for one leaving row, or nil when CanonicalOwnerV1 keeps its header by hash or no
// header is present.
func (e *selectedSideEvidence) leaving(p *selectedSideDamagePlan, height uint64) (*mdbx.Mutation, error) {
	link, err := e.link(p, height)
	if err != nil {
		return nil, err
	}
	hash := [32]byte(link[:32])
	owner, err := e.owner(p, hash)
	if err != nil {
		return nil, err
	}
	if owner.Owned {
		return nil, e.keptHeader(p, hash, owner.Entry)
	}
	present, err := e.headerPresent(p, hash)
	if err != nil || !present {
		return nil, err
	}
	return &mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[3], Key: bytes.Clone(hash[:]), BeforePresent: true, AfterKind: mdbx.AfterAbsent}, nil
}

// keptHeader requires the canonical-kept header: present at legal width, hashing to its key, and naming the owner
// entry's parent. An owned hash is only ever read as required, so a recorded observation always retains its bytes.
func (e *selectedSideEvidence) keptHeader(p *selectedSideDamagePlan, hash [32]byte, entry []byte) error {
	header := e.row(hash).header
	if !e.row(hash).headerRead {
		var err error
		if header, err = e.namedRow(p, 3, hash, true); err != nil {
			return err
		}
	}
	if !bytes.Equal(header[4:36], entry[32:64]) {
		return selectedSideDefect("kept canonical header does not link to its index entry")
	}
	return nil
}

func (e *selectedSideEvidence) headerPresent(p *selectedSideDamagePlan, hash [32]byte) (bool, error) {
	if r := e.row(hash); r.headerRead {
		return r.headerPresent, nil
	}
	if _, err := e.namedRow(p, 3, hash, false); err != nil {
		return false, err
	}
	return e.row(hash).headerPresent, nil
}

// clearBatch refuses with storage_capacity before any Batch exists when the relied-on body's borrowed Consulted OLD
// image exceeds its named MaxBlockBytes share, or when Consulted or the transfer sublimit would be exceeded.
func (e *selectedSideEvidence) clearBatch(deletes []mdbx.Mutation) (mdbx.Batch, error) {
	encoded, err := e.cleared()
	if err != nil {
		return mdbx.Batch{}, err
	}
	slices.SortFunc(deletes, func(a, b mdbx.Mutation) int { return bytes.Compare(a.Key, b.Key) })
	mutations := make([]mdbx.Mutation, 1+len(deletes))
	mutations[0] = mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: encoded}
	copy(mutations[1:], deletes)
	consulted := selectedSideReadback(e.consulted, mutations)
	if e.bodyNative > mdbx.MaxBlockBytes || len(consulted) > selectedSideConsultedRows || e.charge > selectedSideTransferBytes {
		return mdbx.Batch{}, &selectedSideFailure{result: selectedSideCapacity, cause: errors.New("selected side transfer exceeds its checked lane share")}
	}
	return mdbx.Batch{Mutations: mutations, Consulted: consulted}, nil
}

// cleared clears selected_side and inserts SIDE(g,first,tip,first), or extends the only legal predecessor singleton
// SIDE(g,first-1,first-1,first-1) to tip keeping its progress; every other authority field is unchanged.
func (e *selectedSideEvidence) cleared() ([]byte, error) {
	a := e.authority
	var spans []mdbx.CleanupSpanV1
	if a.Cleanup != nil {
		spans = slices.Clone(a.Cleanup.Spans)
	}
	if n := len(spans); n > 0 && spans[n-1].Kind == mdbx.CleanupSpanSideV1 {
		spans[n-1].LastHeight = e.side.TipHeight
	} else {
		spans = append(spans, mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: e.side.GenerationID, FirstHeight: e.first, LastHeight: e.side.TipHeight, NextHeight: e.first})
	}
	a.SelectedSide, a.Cleanup, a.Phase = nil, &mdbx.CleanupV1{Spans: spans}, mdbx.StoragePhasePruneGCV1
	if mdbx.ValidateStorageAuthorityV1(a) != nil {
		return nil, &selectedSideFailure{result: selectedSideInvariant, cause: errors.New("selected side clear produced illegal authority")}
	}
	encoded, err := a.Encode()
	if err != nil {
		return nil, &selectedSideFailure{result: selectedSideCapacity, cause: err}
	}
	return encoded, nil
}

// selectedSideReadback sorts and deduplicates relied-on rows and removes every mutation target from them.
func selectedSideReadback(rows []mdbx.ConsultedRow, targets []mdbx.Mutation) []mdbx.ConsultedRow {
	slices.SortFunc(rows, func(a, b mdbx.ConsultedRow) int {
		return cmp.Or(cmp.Compare(a.DBI.Rank, b.DBI.Rank), bytes.Compare(a.Key, b.Key))
	})
	out := make([]mdbx.ConsultedRow, 0, len(rows))
	for _, row := range rows {
		if len(out) > 0 && out[len(out)-1].DBI == row.DBI && bytes.Equal(out[len(out)-1].Key, row.Key) {
			continue
		}
		if slices.ContainsFunc(targets, func(m mdbx.Mutation) bool { return m.DBI == row.DBI && bytes.Equal(m.Key, row.Key) }) {
			continue
		}
		out = append(out, row)
	}
	return out
}

// selectedSideDamageProject derives the logical result without rereading the Store and never changes the raw tuple, except
// that this invocation's exact healthy sentinel at OLD/Prewrite becomes nil.
func selectedSideDamageProject(out selectedSideOutcome, p *selectedSideDamagePlan) selectedSideOutcome {
	switch {
	case out.Stage == mdbx.UpdateStageCommitMayHaveCrossed:
		out.Result, out.CanonicalTruth = selectedSideCleared, "NOT_APPLICABLE"
	case out.Err == p.healthy && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite: //nolint:errorlint // Only the direct invocation-local sentinel normalizes.
		out.Err = nil
	case out.Stage == mdbx.UpdateStageWriteStartedDefinitelyPrecommit:
		out.Result = selectedSidePrecommitResult(out.Err, p)
	default:
		out.Result = selectedSideResult(out.Err, p)
	}
	return out
}

func selectedSidePrecommitResult(err error, p *selectedSideDamagePlan) string {
	result := selectedSideResult(err, p)
	if result == selectedSideIntegrity || result == selectedSideInvariant {
		return result
	}
	return selectedSidePrecommit
}

// selectedSideResult walks primary, readback and cleanup causes in their existing order; a terminal cause wins,
// otherwise the first classified cause decides.
func selectedSideResult(err error, p *selectedSideDamagePlan) string {
	result, found := "", false
	for _, part := range genesisMDBXCauses(err) {
		if part == p.healthy { //nolint:errorlint // Only the direct invocation-local sentinel is skipped.
			continue
		}
		next := selectedSidePart(part, p)
		if next == selectedSideIntegrity || next == selectedSideInvariant {
			return next
		}
		if !found {
			result, found = next, true
		}
	}
	return result
}

func selectedSidePart(part error, p *selectedSideDamagePlan) string {
	if p.denied != nil && part == p.denied { //nolint:errorlint // The owner's exact returned capacity refusal.
		return selectedSideCapacity
	}
	switch e := part.(type) { //nolint:errorlint // Classify only this direct cause.
	case *selectedSideFailure:
		if e != nil {
			return e.result
		}
	case *mdbx.EngineError:
		return selectedSideEngine(e, p.step)
	}
	if part == errSelectedSideRequest { //nolint:errorlint // Direct request refusal.
		return ""
	}
	return selectedSideInvariant
}

func selectedSideEngine(e *mdbx.EngineError, step string) string {
	if e == nil {
		return selectedSideInvariant
	}
	switch e.Class {
	case mdbx.EngineIntegrity:
		return selectedSideIntegrity
	case mdbx.EngineInvalidInput:
		return ""
	case mdbx.EngineCapacity:
		return selectedSideCapacity
	case mdbx.EngineConcurrency, mdbx.EngineTransaction, mdbx.EngineIO, mdbx.EngineStateMismatch, mdbx.EngineLocalInvariant:
		// Classified below by resource class and in-flight step.
	}
	resource := selectedSideResource(e.Class)
	if resource == "" {
		return selectedSideInvariant
	}
	if step != "" {
		return step
	}
	return "LOCAL_RESOURCE_UNAVAILABLE(" + resource + ")"
}

func selectedSideResource(class mdbx.EngineClass) string {
	switch class {
	case mdbx.EngineConcurrency:
		return "storage_concurrency"
	case mdbx.EngineTransaction:
		return "storage_transaction"
	case mdbx.EngineIO:
		return "storage_io"
	case mdbx.EngineInvalidInput, mdbx.EngineIntegrity, mdbx.EngineCapacity, mdbx.EngineStateMismatch, mdbx.EngineLocalInvariant:
		return ""
	}
	return ""
}
