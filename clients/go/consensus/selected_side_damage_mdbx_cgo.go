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
// 6.4.1.9). selectedSideDamageMDBX has no active or public caller; its sole non-test caller is the dormant recheck
// adapter RecheckSelectedSideMDBX, and its direct tests remain. The non-damage PlanSelectedSideClearMDBX reuses the same
// evidence/transfer owner inside the caller's Reader for the node's N3 ReplaceSelectedSideMDBX, and the RP
// PlanSelectedSideRollingMDBX reuses its oldest-row health and leaving decision for PrepareSelectedSideRollingMDBX; the
// node owns each grant, Update and projection. Each valid-owner damage invocation performs one outer full-lane
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

// selectedSideBindings is the finite nonempty producer result set a node callback leaf may bind
// (ClassifySelectedSideFailureMDBX); a TxError binds only its own CONSENSUS_INVALID(code).
var selectedSideBindings = []string{selectedSideIntegrity, selectedSideBranch, selectedSideCanonical, "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)", "RECOVERY_REQUIRED", "STALE_LOCAL_PLAN"}

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
// flight: set before each artifact method and cleared as soon as that method returns successfully, so it remains only
// after a failed artifact invocation and infrastructure errors outside a read keep their native storage class.
// bound/boundResult are set only by the node classifier: one exact callback leaf and its finite result ("" skips it).
type selectedSideDamagePlan struct {
	generation, tip, height uint64
	healthy, denied, bound  error
	step, boundResult       string
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

// SelectedSideDamageOutcome is the damage operation's logical result beside its unmodified raw Update tuple.
type SelectedSideDamageOutcome = selectedSideOutcome

// RecheckSelectedSideMDBX is the node's fresh recheck of one damage locator after that node attempt released its
// grant: exactly the existing damage operation with its own reservation, Update and fresh evidence.
func RecheckSelectedSideMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, generation, tip, height uint64) SelectedSideDamageOutcome {
	return selectedSideDamageMDBX(store, reservations, generation, tip, height)
}

// SelectedSidePlanV1 is one side-only plan built in the caller's Reader for that caller's sole Update: the complete
// Batch (mutations and relied-on Consulted rows), whether it is an actual complete positive-damage clear, and the
// artifact read class that failed (empty on a complete plan). An error carries no Batch and no positive flag.
type SelectedSidePlanV1 struct {
	Batch               mdbx.Batch
	PositiveDamageClear bool
	ReadResource        string
}

// PlanSelectedSideClearMDBX plans the healthy complete clear of the committed selected side with the existing transfer
// owner: strict authority first, then every leaving identity and header keep/delete decision, SIDE(g,first,tip,first)
// or the extended prepared singleton, and PRUNE_GC. It owns no grant or Update and claims no damage.
func PlanSelectedSideClearMDBX(reader *mdbx.Reader) (SelectedSidePlanV1, error) {
	authority, err := reader.ReadStorageAuthorityV1()
	if err != nil {
		return SelectedSidePlanV1{}, err
	}
	if authority.SelectedSide == nil {
		return SelectedSidePlanV1{}, errSelectedSideRequest
	}
	p := &selectedSideDamagePlan{}
	batch, err := newSelectedSideEvidence(reader, authority).transfer(p)
	if err != nil {
		// Each artifact read clears its class once its method returns, so only a failed artifact invocation leaves it set.
		return SelectedSidePlanV1{ReadResource: p.step}, err
	}
	return SelectedSidePlanV1{Batch: batch}, nil
}

// PlanSelectedSideRollingMDBX plans RP in the caller's Reader: strict authority, a full 1440-row side, then the
// existing health of its oldest row. A healthy oldest row leaves into SIDE(g,first,first,first): count 1439 and logical
// bytes minus that row's actual body length, its header deleted unless CanonicalOwnerV1 or a hash in the remaining
// selected interval first+1..tip keeps it, its body and link kept; tip, work, g, F, next and every other field and span stay. Positive oldest damage plans the complete clear
// instead, the only PositiveDamageClear plan. It owns no grant or Update; an error carries no Batch, no positive flag
// and the failed artifact read class.
func PlanSelectedSideRollingMDBX(reader *mdbx.Reader) (SelectedSidePlanV1, error) {
	authority, err := reader.ReadStorageAuthorityV1()
	if err != nil {
		return SelectedSidePlanV1{}, err
	}
	if authority.SelectedSide == nil || authority.SelectedSide.RowCount != 1440 {
		return SelectedSidePlanV1{}, errSelectedSideRequest
	}
	p := &selectedSideDamagePlan{height: selectedSideFirst(authority.SelectedSide)}
	batch, positive, err := newSelectedSideEvidence(reader, authority).roll(p)
	if err != nil {
		return SelectedSidePlanV1{ReadResource: p.step}, err
	}
	return SelectedSidePlanV1{Batch: batch, PositiveDamageClear: positive}, nil
}

// ClassifySelectedSideFailureMDBX classifies one dormant node attempt's uncrossed raw error with the existing ordered
// cause walk; it never projects a crossed stage and owns no effects. The node producer owns the concrete direct type
// and current-invocation ownership of callbackErr and its result. This consumer only refuses a binding whose leaf has
// a nil descendant or whose result is outside the finite domain (a TxError binds only its own CONSENSUS_INVALID(code)),
// and then substitutes exactly that occurrence ("" skips it). readResource is the attempt's in-flight read class.
func ClassifySelectedSideFailureMDBX(err error, stage mdbx.UpdateStage, readResource string, callbackErr error, callbackResult string) string {
	p := &selectedSideDamagePlan{step: readResource}
	if callbackErr != nil && !genesisMDBXNilError(callbackErr) && selectedSideFiniteResult(callbackErr, callbackResult) {
		p.bound, p.boundResult = callbackErr, callbackResult
	}
	if stage == mdbx.UpdateStageWriteStartedDefinitelyPrecommit {
		return selectedSidePrecommitResult(err, p)
	}
	return selectedSideResult(err, p)
}

func selectedSideFiniteResult(err error, result string) bool {
	if tx, ok := err.(*TxError); ok { //nolint:errorlint // The bound leaf itself; nil was refused above.
		return result == "CONSENSUS_INVALID("+string(tx.Code)+")"
	}
	return result == "" || slices.Contains(selectedSideBindings, result)
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
// collections are preallocated to their proved bounds for the n pre-state selected rows (all leaving in a clear, the
// RP remaining-keep scan reading the other n-1): n link slots (nil is an unread slot; a link is
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
	p.step = ""
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
	p.step = ""
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
		if err == nil {
			p.step = ""
		}
		return value, present, uint64(len(value)), err
	}
	p.step = selectedSideBranch
	row, err := e.reader.GetOptionalSide(dbi, hash[:])
	if err == nil {
		p.step = ""
	}
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
// At the descriptor tip it adds the bounded current-tip predicates tipLink and tipWork.
func (e *selectedSideEvidence) health(p *selectedSideDamagePlan) (bool, error) {
	link, err := e.link(p, p.height)
	if err != nil {
		return false, err
	}
	hash := [32]byte(link[:32])
	if err := e.tipLink(p.height, hash); err != nil {
		return false, err
	}
	owner, err := e.owner(p, hash)
	if err != nil {
		return false, err
	}
	damaged, err := e.headerHealth(p, p.height, link, owner)
	if err != nil || damaged {
		return damaged, err
	}
	if e.tipWork(p.height, link) {
		return true, nil
	}
	return e.bodyHealth(p, hash, owner.Owned && owner.Height >= e.authority.B)
}

// tipLink is the current-tip identity predicate: after the required SideLink, a tip link naming another hash than the
// descriptor is canonical integrity, never optional damage.
func (e *selectedSideEvidence) tipLink(height uint64, hash [32]byte) error {
	if height == e.side.TipHeight && hash != e.side.TipHash {
		return selectedSideDefect("selected side tip link does not name the descriptor tip")
	}
	return nil
}

// tipWork is the current-tip work predicate: after the owner, header and keep checks, a tip link whose cumulative work
// differs from the descriptor is positive optional damage.
func (e *selectedSideEvidence) tipWork(height uint64, link []byte) bool {
	return height == e.side.TipHeight && [40]byte(link[64:104]) != e.side.CumulativeChainwork
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
	if damaged, err := e.firstTarget(height, header, owner.Owned); damaged || err != nil {
		return damaged, err
	}
	if !bytes.Equal(header[4:36], link[32:64]) {
		return true, nil
	}
	return e.predecessor(p, height, link, header)
}

// firstTarget checks only the first row of a legal cleaned one-slot side, whose predecessor check has no parent, for
// a stored-header target inside the work domain, reusing the already read header: outside it, an Owned header is
// canonical integrity and an unowned header is positive optional damage.
func (e *selectedSideEvidence) firstTarget(height uint64, header []byte, owned bool) (bool, error) {
	if height != e.first || e.side.RowCount != 1439 || e.first <= e.side.F+1 {
		return false, nil
	}
	if _, err := WorkFromTarget([32]byte(header[76:108])); err == nil {
		return false, nil
	}
	if owned {
		return false, selectedSideDefect("required canonical header target is outside its domain")
	}
	return true, nil
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
	if err != nil {
		return true, nil //nolint:nilerr // An undecodable stored target is positive optional damage of this row, not an error.
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
	p.step = ""
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

// roll diagnoses the oldest row with the existing health; positive damage is the complete clear (positive only once
// that plan is complete), otherwise only the oldest row leaves.
func (e *selectedSideEvidence) roll(p *selectedSideDamagePlan) (mdbx.Batch, bool, error) {
	damaged, err := e.health(p)
	if err != nil {
		return mdbx.Batch{}, false, err
	}
	if damaged {
		batch, err := e.transfer(p)
		return batch, err == nil, err
	}
	target, err := e.shrinking(p)
	if err != nil {
		return mdbx.Batch{}, false, err
	}
	encoded, err := e.rolled()
	if err != nil {
		return mdbx.Batch{}, false, err
	}
	var deletes []mdbx.Mutation
	if target != nil {
		deletes = append(deletes, *target)
	}
	batch, err := e.authorityBatch(encoded, deletes)
	return batch, false, err
}

// shrinking returns RP's header deletion for the healthy leaving oldest row. A CanonicalOwnerV1 keep is sufficient and
// reads no remaining link. Otherwise every remaining selected SideLink first+1..tip is read ascending through link (its
// cache, charge and Consulted), even after a hash match, so a later absent, undecodable or transient identity still
// refuses before any Batch; a match anywhere in that interval keeps the header.
func (e *selectedSideEvidence) shrinking(p *selectedSideDamagePlan) (*mdbx.Mutation, error) {
	target, err := e.leaving(p, p.height)
	if err != nil || target == nil {
		return target, err
	}
	kept := false
	for height := e.first + 1; height <= e.side.TipHeight; height++ {
		link, err := e.link(p, height)
		if err != nil {
			return nil, err
		}
		kept = kept || bytes.Equal(link[:32], target.Key)
	}
	if kept {
		target = nil
	}
	return target, nil
}

func (e *selectedSideEvidence) clearBatch(deletes []mdbx.Mutation) (mdbx.Batch, error) {
	encoded, err := e.cleared()
	if err != nil {
		return mdbx.Batch{}, err
	}
	return e.authorityBatch(encoded, deletes)
}

// authorityBatch refuses with storage_capacity before any Batch exists when the relied-on body's borrowed Consulted
// OLD image exceeds its named MaxBlockBytes share, or when Consulted or the transfer sublimit would be exceeded.
func (e *selectedSideEvidence) authorityBatch(encoded []byte, deletes []mdbx.Mutation) (mdbx.Batch, error) {
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
	return selectedSideEncode(a)
}

// rolled shrinks the side to count 1439 and logical bytes minus the oldest body's actual length (bodyNative, read by
// the healthy oldest health) and appends SIDE(g,first,first,first) after every existing span under PRUNE_GC; every other
// authority field is unchanged. A descriptor holding fewer bytes than that body is an illegal plan, never a wrap.
func (e *selectedSideEvidence) rolled() ([]byte, error) {
	a, side := e.authority, *e.side
	if e.bodyNative > side.LogicalBytes {
		return nil, selectedSideIllegal()
	}
	var spans []mdbx.CleanupSpanV1
	if a.Cleanup != nil {
		spans = slices.Clone(a.Cleanup.Spans)
	}
	spans = append(spans, mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: side.GenerationID, FirstHeight: e.first, LastHeight: e.first, NextHeight: e.first})
	side.RowCount, side.LogicalBytes = side.RowCount-1, side.LogicalBytes-e.bodyNative
	a.SelectedSide, a.Cleanup, a.Phase = &side, &mdbx.CleanupV1{Spans: spans}, mdbx.StoragePhasePruneGCV1
	return selectedSideEncode(a)
}

func selectedSideIllegal() error {
	return &selectedSideFailure{result: selectedSideInvariant, cause: errors.New("selected side plan produced illegal authority")}
}

// selectedSideEncode validates and encodes a planned authority: illegal is a local invariant, unencodable capacity.
func selectedSideEncode(a mdbx.StorageAuthorityV1) ([]byte, error) {
	if mdbx.ValidateStorageAuthorityV1(a) != nil {
		return nil, selectedSideIllegal()
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
		if p.skip(part) {
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

// skip reports an exact empty-result leaf: this invocation's healthy sentinel or a bound callback leaf of empty result.
func (p *selectedSideDamagePlan) skip(part error) bool {
	return p.healthy != nil && part == p.healthy || p.bound != nil && part == p.bound && p.boundResult == "" //nolint:errorlint // Exact leaf identities only.
}

// identity classifies an exact owned leaf: the owner's returned capacity refusal or the bound callback leaf.
func (p *selectedSideDamagePlan) identity(part error) (string, bool) {
	switch {
	case p.denied != nil && part == p.denied: //nolint:errorlint // The owner's exact returned capacity refusal.
		return selectedSideCapacity, true
	case p.bound != nil && part == p.bound: //nolint:errorlint // The exact bound callback leaf.
		return p.boundResult, true
	}
	return "", false
}

func selectedSidePart(part error, p *selectedSideDamagePlan) string {
	if result, ok := p.identity(part); ok {
		return result
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
