//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"cmp"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Dormant replay-target entry, sources (b), (d), (e): RUBIN_MEMPOOL_POLICY.md L2510-2615. No production caller.

const (
	replayEntryRecovery = "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)"
	replayEntryStale    = "STALE_LOCAL_PLAN"
	// ReplayEntry decisions are dormant values of this leaf, never spec tokens.
	replayEntryGenesisFirst = "genesis first"
	replayEntryNotEligible  = "not eligible"
	replayEntryResume       = "resume"
	// replayEntryIdentityBytes is the identity envelope of the one-row step-1 page (archiveSelectedSideIdentityBytes).
	replayEntryIdentityBytes uint64 = 512
	replayEntryPageRows      uint32 = 1_440
	// replayEntryWalkBytes is the RUB-1506 capacity_boundary walk term (CB 1935-1951).
	replayEntryWalkBytes uint64 = 2*8*WINDOW_SIZE + 2*8*11 + uint64(replayEntryPageRows)*(16+104+48) + 78 + 2*116 + 2*32 + 8*40
	replayEntryPlanBytes uint64 = 3*mdbx.MaxMetadataBytes + 512
	// replayEntryDerivedBytes per returned header (D_h): one replayNode and one replayKid, sizes pinned by a test.
	replayEntryDerivedBytes   uint64 = 128
	replayEntryInventoryLimit        = (mdbx.MaxOperationDataBytes - replayEntryIdentityBytes - replayEntryWalkBytes - replayEntryPlanBytes) * 116 / (116 + replayEntryDerivedBytes)
)

// Compiles only if LANE_MAX >= identity + walk + plan + limit (the largest accepted Bytes) + D_h * floor(limit/116) (its most headers).
const _ = mdbx.MaxOperationDataBytes - (replayEntryIdentityBytes + replayEntryWalkBytes + replayEntryPlanBytes + replayEntryInventoryLimit + replayEntryInventoryLimit/116*replayEntryDerivedBytes)

// HeaderCandidateStatusV1 is the inventory status of a header-candidate view.
type HeaderCandidateStatusV1 uint8

const (
	HeaderCandidateCompleteV1 HeaderCandidateStatusV1 = iota + 1
	HeaderCandidateIncompleteV1
	HeaderCandidateCapacityRefusedV1
)

// HeaderCandidateInventoryV1 is one finite inventory. Complete: Tips holds every admitted received candidate tip hash
// and Headers every received header on each tip's path down to the lowest received ancestor, as raw 116-byte headers
// in no relied-on order, with Bytes = 32*len(Tips) + 116*len(Headers) <= limit. A path's lowest header attaches to a
// durable canonical parent of the active generation (empty active index: the Fork F anchor) or, for the pre-activation
// recomputation, to an accepted target-generation entry at a height at or below the cursor; otherwise the evidence is
// incomplete. An inventory above limit is CapacityRefused, never a truncated Complete. Incomplete and CapacityRefused
// carry empty Tips and Headers and Bytes 0. Version identifies the admitted-candidate set: it advances on every
// admitted-membership change and producer update, never on derived cache eviction, and is opaque to the consumer.
type HeaderCandidateInventoryV1 struct {
	Status  HeaderCandidateStatusV1
	Version uint64
	Tips    [][32]byte
	Headers [][116]byte
	Bytes   uint64
}

// HeaderCandidateViewV1 is the process-local, versioned, never-persisted candidate view (RUBIN_MEMPOOL_POLICY.md
// Section 6.4.1.8). InventoryV1 returns Complete, Incomplete or CapacityRefused. ProtectV1 acquires the producer guard
// and returns whether version is still current and a non-nil release that the caller runs exactly once.
// InventoryV1 hands the returned Tips and Headers to the caller: the producer neither retains nor modifies them after
// it returns, so the caller may reorder and deduplicate them in place and read them without the producer guard.
type HeaderCandidateViewV1 interface {
	InventoryV1(limit uint64) HeaderCandidateInventoryV1
	ProtectV1(version uint64) (current bool, release func())
}

// PublishedGenesisContextV1 is the node's chain-instance genesis: Published holds the complete 266-byte published
// genesis block when configured and is nil for an identity-only context.
type PublishedGenesisContextV1 struct {
	ChainID, GenesisHash [32]byte
	Published            []byte
}

// ReplayEntryOwnerV1 fixes one view handle and one immutable genesis context at construction.
type ReplayEntryOwnerV1 struct {
	view    HeaderCandidateViewV1
	genesis PublishedGenesisContextV1
}

// NewReplayEntryOwnerV1 copies Published; the context check runs in every operation.
func NewReplayEntryOwnerV1(view HeaderCandidateViewV1, genesis PublishedGenesisContextV1) *ReplayEntryOwnerV1 {
	if genesis.Published != nil {
		genesis.Published = bytes.Clone(genesis.Published)
	}
	return &ReplayEntryOwnerV1{view: view, genesis: genesis}
}

// ReplayEntryOutcomeV1 is the logical result beside the raw Store.Update tuple. Result is a spec token or empty;
// Decision is a dormant decision of this leaf or empty; Replay is the persisted ReplayV1 of a resume or the planned
// ReplayV1 of a NEW entry commit.
type ReplayEntryOutcomeV1 struct {
	Result, Decision, CanonicalTruth string
	Truth                            mdbx.CommitTruth
	Stage                            mdbx.UpdateStage
	Err                              error
	Replay                           *mdbx.ReplayV1
}

// ReplayExpectedTargetV1 is the CANONICAL Section 15 expected target at height > 0: the parent target off a retarget
// boundary, otherwise RetargetV1Clamped over exactly WINDOW_SIZE timestamps of B_{h-WINDOW_SIZE}..B_{h-1}.
func ReplayExpectedTargetV1(height uint64, parentTarget [32]byte, window []uint64) ([32]byte, error) {
	if height == 0 {
		return [32]byte{}, errors.New("replay expected target: height zero")
	}
	if height%WINDOW_SIZE != 0 {
		return parentTarget, nil
	}
	return RetargetV1Clamped(parentTarget, window)
}

// replayEntryContext mirrors the published-genesis commitment check of ConnectPublishedGenesisMDBX.
func replayEntryContext(g PublishedGenesisContextV1) error {
	if !replayEntryContextShape(g) {
		return errors.New("invalid published genesis context")
	}
	if g.Published == nil {
		return nil
	}
	hash, err := BlockHash(g.Published[:BLOCK_HEADER_BYTES])
	chainID := sha3.Sum256(append([]byte("RUBIN-GENESIS-v1"), g.Published...))
	if err != nil || hash != g.GenesisHash || chainID != g.ChainID {
		return errors.New("published genesis context commitment mismatch")
	}
	return nil
}

func replayEntryContextShape(g PublishedGenesisContextV1) bool {
	return g.ChainID != ([32]byte{}) && g.GenesisHash != ([32]byte{}) && (g.Published == nil || len(g.Published) == 266)
}

// replayEntryCall is one invocation's callback state; step is the in-flight read class (SD L88-90).
type replayEntryCall struct {
	owner        *ReplayEntryOwnerV1
	reservations *mdbx.OperationReservationOwner
	sentinel     error
	result       string
	decision     string
	step         string
	planned      bool
	census       bool // The third leaf's BS census read is in flight (dormant in this leaf).
	denied       bool
	lane         uint64 // A Reader-scoped planner's lane share; zero is the full lane (replayEntryInventoryLimit).
	replay       *mdbx.ReplayV1
	release      func()
}

// EnterReplayTargetMDBX runs sources (b), (d) and (e), selected by the persisted authority, under one full-lane grant
// around one Store.Update; on the owner's exact capacity refusal one grant-free control-only Update evaluates the
// step-1 gates. The release ProtectV1 returned runs exactly once after Store.Update returns, panic included.
func (o *ReplayEntryOwnerV1) EnterReplayTargetMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner) ReplayEntryOutcomeV1 {
	out := ReplayEntryOutcomeV1{CanonicalTruth: "OLD", Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite}
	if err := replayEntryContext(o.genesis); err != nil {
		out.Result, out.Err = selectedSideInvariant, err
		return out
	}
	if store == nil {
		out.Truth, out.Stage, out.Err = store.Update(nil)
		out.CanonicalTruth = ""
		return out
	}
	call := &replayEntryCall{owner: o, reservations: reservations, sentinel: errors.New("replay entry decision")}
	defer call.runRelease()
	ran := false
	err := reservations.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		ran = true
		out.Truth, out.Stage, out.Err = store.Update(call.plan)
		return out.Err
	})
	if !ran {
		if err.Error() != selectedSideCapacityText {
			out.Err, out.CanonicalTruth = err, ""
			return out
		}
		call.denied = true
		out.Truth, out.Stage, out.Err = store.Update(call.plan)
	}
	call.runRelease()
	return replayEntryProject(out, call)
}

func (c *replayEntryCall) runRelease() {
	if release := c.release; release != nil {
		c.release = nil
		release()
	}
}

// decide records a zero-mutation outcome the callback decides itself and returns the exact sentinel.
func (c *replayEntryCall) decide(result, decision string) (mdbx.Batch, error) {
	c.result, c.decision = result, decision
	return mdbx.Batch{}, c.sentinel
}

// plan is the shared entry sequence of RUBIN_MEMPOOL_POLICY.md L2594-2604; the denied path stops after the gates.
func (c *replayEntryCall) plan(reader *mdbx.Reader) (mdbx.Batch, error) {
	a, err := reader.ReadStorageAuthorityV1()
	if err != nil {
		return mdbx.Batch{}, err
	}
	if a.Phase == mdbx.StoragePhaseReplayV1 {
		resumed := *a.Replay
		c.replay = &resumed
		return c.decide("", replayEntryResume)
	}
	source, decided, err := c.gates(reader, a)
	if err != nil || decided {
		return mdbx.Batch{}, err
	}
	if c.denied {
		return c.decide(selectedSideCapacity, "")
	}
	return c.qualifyAndPlan(reader, a, source)
}

// gates is source legality and the source (b) step-1 identity page and genesis-first gate (MP L1941-1947, L2608).
func (c *replayEntryCall) gates(reader *mdbx.Reader, a mdbx.StorageAuthorityV1) (byte, bool, error) {
	switch {
	case a.Phase != mdbx.StoragePhaseNoneV1:
		_, err := c.decide("", replayEntryNotEligible)
		return 0, true, err
	case a.Lifecycle == mdbx.StorageLifecycleRecoveryRequiredV1:
		return 'd', false, nil
	case a.SelectedSide != nil:
		_, err := c.decide("", replayEntryNotEligible)
		return 0, true, err
	}
	identity, err := c.identityCharged(reader, a.ActiveGenerationID)
	if err != nil {
		return 0, true, err
	}
	switch {
	case identity != 0:
		_, err = c.decide("", replayEntryNotEligible)
		return 0, true, err
	case c.owner.genesis.Published != nil:
		_, err = c.decide("", replayEntryGenesisFirst)
		return 0, true, err
	}
	return 'b', false, nil
}

// identityCharged reads the identity page in the lane, or under a nested 512-byte control charge when denied.
func (c *replayEntryCall) identityCharged(reader *mdbx.Reader, generation uint64) (uint8, error) {
	if !c.denied {
		identity, site, err := replayEntryIdentity(reader, generation)
		c.step = site
		return identity, err
	}
	var identity uint8
	var readErr error
	// The callback returns nil, so a non-nil result is the owner's refusal of the control charge.
	if c.reservations.WithReservation(replayEntryIdentityBytes, func() error {
		var site string
		identity, site, readErr = replayEntryIdentity(reader, generation)
		c.step = site
		return nil
	}) != nil {
		_, err := c.decide(selectedSideCapacity, "")
		return 0, err
	}
	return identity, readErr
}

// replayEntryIdentity is the step-1 identity-page read; on error it returns the identity-page read-site label.
func replayEntryIdentity(reader *mdbx.Reader, generation uint64) (uint8, string, error) {
	identity, err := archiveSelectedSideIdentity(reader, generation)
	if err != nil {
		return 0, selectedSideCanonical, err
	}
	return identity, "", nil
}

// qualifyAndPlan runs inventory, walk, selection, protection, sequence and plan in that order (MP L2976-2993).
func (c *replayEntryCall) qualifyAndPlan(reader *mdbx.Reader, a mdbx.StorageAuthorityV1, source byte) (mdbx.Batch, error) {
	inv, result := replayEntryInventory(c.owner.view, replayInvLimit(c.lane))
	if result != "" {
		return c.decide(result, "")
	}
	q := newReplayQualifier(c.owner.genesis, inv, a.ExcludedInvalidBranch)
	tipHeight, err := q.walk(reader, a.ActiveGenerationID, &c.step)
	if err != nil {
		return mdbx.Batch{}, err
	}
	target, ok, result := q.selectTarget()
	if result != "" || !ok {
		return c.decide(replayEntryRecovery, "")
	}
	current, release := c.owner.view.ProtectV1(inv.Version)
	if release == nil {
		return c.decide(selectedSideInvariant, "")
	}
	c.release = release
	if !current {
		return c.decide(replayEntryStale, "")
	}
	if a.NextGenerationID == math.MaxUint64 {
		return c.decide(selectedSideInvariant, "")
	}
	return c.entryBatch(a, source, target, tipHeight)
}

// replayEntryInventory is view_contract with CC-7 at limit; Bytes is zero exactly when Tips and Headers are empty.
func replayEntryInventory(view HeaderCandidateViewV1, limit uint64) (HeaderCandidateInventoryV1, string) {
	if view == nil {
		return HeaderCandidateInventoryV1{}, replayEntryRecovery
	}
	inv := view.InventoryV1(limit)
	if inv.Bytes != 32*uint64(len(inv.Tips))+116*uint64(len(inv.Headers)) || inv.Bytes > limit {
		return inv, selectedSideInvariant
	}
	switch {
	case inv.Status == HeaderCandidateCompleteV1:
		return inv, ""
	case inv.Bytes != 0:
		return inv, selectedSideInvariant
	case inv.Status == HeaderCandidateIncompleteV1:
		return inv, replayEntryRecovery
	case inv.Status == HeaderCandidateCapacityRefusedV1:
		return inv, selectedSideCapacity
	}
	return inv, selectedSideInvariant
}

// entryBatch is the REPLAY_PROGRESS plan; no target canonical-index or owner row is written (MP L1899-1901).
func (c *replayEntryCall) entryBatch(a mdbx.StorageAuthorityV1, source byte, target mdbx.RecoveryTargetV1, tipHeight uint64) (mdbx.Batch, error) {
	profile := a.ActiveProfile
	if source == 'd' {
		profile = *a.PendingTargetProfile
	}
	next := a.NextGenerationID
	replay := mdbx.ReplayV1{TargetProfile: profile, TargetGenerationID: next, Target: target, Cursor: mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorPreGenesisV1}}
	planned := a
	planned.Phase, planned.Lifecycle, planned.Replay = mdbx.StoragePhaseReplayV1, mdbx.StorageLifecycleRecoveryRequiredV1, &replay
	planned.NextGenerationID, planned.PendingTargetProfile = next+1, nil
	literal, err := selectedSideEncode(planned)
	if err != nil {
		return mdbx.Batch{}, err
	}
	meta := mdbx.SchemaV2DBIs()[0]
	counterKey := binary.BigEndian.AppendUint64([]byte{0x10}, next)
	c.replay, c.planned, c.step = &replay, true, ""
	return mdbx.Batch{
		Mutations: []mdbx.Mutation{
			{DBI: meta, Key: []byte{0x02}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: literal},
			{DBI: meta, Key: counterKey, AfterKind: mdbx.AfterLiteral, Literal: mdbx.LogicalCounterValue(0, 0)},
		},
		Consulted: replayEntryConsulted(a.ActiveGenerationID, tipHeight),
	}, nil
}

// replayEntryConsulted is {g0, g1} at tip 0, else {g0, g1, gH, gH+1} deduplicated; the generation is nonzero.
func replayEntryConsulted(generation, tip uint64) []mdbx.ConsultedRow {
	dbi := mdbx.SchemaV2DBIs()[2]
	heights := []uint64{0, 1}
	if tip > 1 {
		heights = append(heights, tip, tip+1)
	} else if tip == 1 {
		heights = append(heights, 2)
	}
	rows := make([]mdbx.ConsultedRow, len(heights))
	for i, h := range heights {
		key, _ := mdbx.HeightKey(generation, h)
		rows[i] = mdbx.ConsultedRow{DBI: dbi, Key: key}
	}
	return rows
}

// replayEntryCrossed maps a possibly crossed commit by archiveSelectedSideCrossed; NEW carries the planned ReplayV1.
func replayEntryCrossed(out ReplayEntryOutcomeV1, call *replayEntryCall) ReplayEntryOutcomeV1 {
	crossed := archiveSelectedSideCrossed(selectedSideOutcome{Truth: out.Truth, Stage: out.Stage, Err: out.Err})
	out.Result, out.CanonicalTruth = crossed.Result, crossed.CanonicalTruth
	if out.Truth == mdbx.CommitTruthNew {
		out.Replay = call.replay
	}
	return out
}

// replayEntryProject is result_map: the raw tuple is kept; only the exact sentinel normalizes to a nil Err.
func replayEntryProject(out ReplayEntryOutcomeV1, call *replayEntryCall) ReplayEntryOutcomeV1 {
	out.CanonicalTruth = "OLD"
	switch {
	case out.Stage == mdbx.UpdateStageCommitMayHaveCrossed:
		return replayEntryCrossed(out, call)
	case out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && errors.Is(out.Err, call.sentinel) && errors.Is(call.sentinel, out.Err):
		out.Result, out.Decision, out.Err = call.result, call.decision, nil
		if call.decision == replayEntryResume {
			out.Replay = call.replay
		}
		return out
	case out.Stage == mdbx.UpdateStageWriteStartedDefinitelyPrecommit:
		out.Result = replayEntryPrecommit(replayEntryCauses(out.Err, &replayEntryCall{}))
		return out
	}
	out.Result = replayEntryCauses(out.Err, call)
	out.Decision = replayEntryCensusDecision(out.Result, call)
	return out
}

// replayEntryCensusDecision is the BS census refusal cell (R18; BS L72-76): not eligible, empty Result, raw Err kept.
func replayEntryCensusDecision(result string, call *replayEntryCall) string {
	if result == "" && call.census {
		return replayEntryNotEligible
	}
	return ""
}

// replayEntryPrecommit is the stage-2 row: integrity or invariant kept, else LOCAL_PERSISTENCE_ERROR(precommit).
func replayEntryPrecommit(result string) string {
	if result == selectedSideIntegrity || result == selectedSideInvariant {
		return result
	}
	return selectedSidePrecommit
}

// replayEntryCauses walks the merged cause order: an integrity or invariant cause wins, otherwise the first classified.
func replayEntryCauses(err error, call *replayEntryCall) string {
	result := ""
	for _, part := range genesisMDBXCauses(err) {
		next := replayEntryPart(part, call)
		if next == selectedSideIntegrity || next == selectedSideInvariant {
			return next
		}
		if result == "" {
			result = next
		}
	}
	return result
}

func replayEntryPart(part error, call *replayEntryCall) string {
	if call.sentinel != nil && part == call.sentinel { //nolint:errorlint // This invocation's exact sentinel leaf (SD L788-800).
		return call.result // Empty is skipped by the walk; otherwise the decided Result.
	}
	switch e := part.(type) { //nolint:errorlint // Classify only this direct cause.
	case *selectedSideFailure:
		if e != nil {
			return e.result
		}
	case *mdbx.EngineError:
		if e != nil {
			return replayEntryEngine(e, call)
		}
	}
	return selectedSideInvariant
}

// replayEntryEngine is the stage-1 engine-class cell; a never-run callback classifies at the Update-begin site.
func replayEntryEngine(e *mdbx.EngineError, call *replayEntryCall) string {
	switch e.Class {
	case mdbx.EngineIntegrity:
		return selectedSideIntegrity
	case mdbx.EngineCapacity:
		return selectedSideCapacity
	case mdbx.EngineStateMismatch:
		return replayEntryMismatch(call)
	case mdbx.EngineConcurrency, mdbx.EngineTransaction, mdbx.EngineIO:
		if call.step != "" {
			return call.step
		}
		return "LOCAL_RESOURCE_UNAVAILABLE(" + selectedSideResource(e.Class) + ")"
	case mdbx.EngineInvalidInput, mdbx.EngineLocalInvariant:
	}
	return selectedSideInvariant
}

// replayEntryMismatch is the StateMismatch cell: the BS census refusal, the write snapshot, else an invariant.
func replayEntryMismatch(call *replayEntryCall) string {
	switch {
	case call.census:
		return ""
	case call.planned:
		return replayEntryStale
	}
	return selectedSideInvariant
}

// replayEntryWork encodes a chainwork of at most 320 bits as 40 bytes big-endian (callers: BitLen guard or (0, 2^288]).
func replayEntryWork(work *big.Int) [40]byte {
	var out [40]byte
	work.FillBytes(out[:])
	return out
}

var replayEntryWorkLimit = new(big.Int).Lsh(big.NewInt(1), 288)

func replayEntryWorkOK(work *big.Int) bool {
	return work.Sign() > 0 && work.Cmp(replayEntryWorkLimit) <= 0
}

func replayEntryHeightOK(height uint64) bool {
	return height > 0 && height <= 0xffffffff
}

const (
	replayNodeE3      uint8 = 1 << iota // a supplied copy of a durable canonical header or the Fork F anchor
	replayNodeReached                   // reached by qualification: attached, E3 copy, anchor or foreign zero-parent root
	replayNodeBad                       // every path through it is ineligible (E5, D10 ancestry, exclusion)
)

// replayNode is the derived per-header record of the hash-sorted array.
type replayNode struct {
	hash   [32]byte
	height uint64
	work   [40]byte
	pos    uint32
	flags  uint8
}

// replayKid is one entry of the parent-sorted array (parent hash, then own hash).
type replayKid struct {
	parent [32]byte
	pos    int
}

// replayQualifier is the streaming qualification walk state; it holds no canonical header chain.
type replayQualifier struct {
	genesis    PublishedGenesisContextV1
	excluded   *[32]byte
	headers    [][116]byte
	tips       [][32]byte
	nodes      []replayNode
	kids       []replayKid
	ring       []uint64 // canonical timestamps by height % WINDOW_SIZE
	scratch    []uint64 // the one window copy
	mtp        [11]uint64
	count      uint64 // canonical heights walked (H+1), or 1 for the Fork F anchor
	hash       [32]byte
	target     [32]byte
	work       big.Int
	badFrom    uint64
	attachK    uint64
	canonTips  int
	best       replayCandidate
	indexEmpty bool
	atC        uint64 // the recomputation's cursor height c (MaxUint64 for the entry) and the active hash recorded there
	hashAtC    [32]byte
	hasAtC     bool
	comparand  replayCandidate // the published prefix tip markBad considers (the recomputation's published OLD comparand)
	workKey    [32]byte        // blockWork's one-entry cache: the exact target and its never-mutated work
	workVal    *big.Int
}

// blockWork is WorkFromTarget through a one-entry cache keyed on the exact target bytes; callers only read the value.
func (q *replayQualifier) blockWork(target [32]byte) (*big.Int, error) {
	if q.workVal != nil && q.workKey == target {
		return q.workVal, nil
	}
	work, err := WorkFromTarget(target)
	if err == nil {
		q.workKey, q.workVal = target, work
	}
	return work, err
}

type replayCandidate struct {
	ok     bool
	hash   [32]byte
	height uint64
	work   [40]byte
}

func newReplayQualifier(g PublishedGenesisContextV1, inv HeaderCandidateInventoryV1, excluded *mdbx.InvalidBranchV1) *replayQualifier {
	q := &replayQualifier{genesis: g, headers: inv.Headers, badFrom: math.MaxUint64, atC: math.MaxUint64}
	if excluded != nil {
		q.excluded = &excluded.FirstInvalidBlockHash
	}
	q.ring, q.scratch = make([]uint64, WINDOW_SIZE), make([]uint64, WINDOW_SIZE)
	q.nodes = make([]replayNode, len(inv.Headers))
	for i := range inv.Headers {
		hash, _ := BlockHash(inv.Headers[i][:]) // A 116-byte header always hashes.
		q.nodes[i] = replayNode{hash: hash, pos: uint32(i)}
	}
	slices.SortFunc(q.nodes, func(a, b replayNode) int { return bytes.Compare(a.hash[:], b.hash[:]) })
	q.nodes = slices.CompactFunc(q.nodes, func(a, b replayNode) bool { return a.hash == b.hash })
	q.kids = make([]replayKid, len(q.nodes))
	for i := range q.nodes {
		q.kids[i] = replayKid{parent: q.parentOf(i), pos: i}
	}
	slices.SortFunc(q.kids, replayKidCompare)
	slices.SortFunc(inv.Tips, replayHashCompare)
	q.tips = slices.Compact(inv.Tips)
	return q
}

func replayHashCompare(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) }

// parentOf is the PrevBlockHash of node i's header bytes.
func (q *replayQualifier) parentOf(i int) [32]byte {
	var parent [32]byte
	copy(parent[:], q.headers[q.nodes[i].pos][4:36])
	return parent
}

func (q *replayQualifier) header(i int) []byte { return q.headers[q.nodes[i].pos][:] }

func (q *replayQualifier) find(hash [32]byte) int {
	i, ok := slices.BinarySearchFunc(q.nodes, hash, func(n replayNode, h [32]byte) int { return bytes.Compare(n.hash[:], h[:]) })
	if !ok {
		return -1
	}
	return i
}

// walk streams the canonical index ascending (D1-D10, E3) or sets the Fork F anchor; it returns the tip height.
func (q *replayQualifier) walk(reader *mdbx.Reader, generation uint64, step *string) (uint64, error) {
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], generation)
	var after []byte
	for {
		*step = replayEntryRecovery
		page, err := reader.PrefixPage(mdbx.SchemaV2DBIs()[2], prefix[:], after, replayEntryPageRows, uint64(replayEntryPageRows)*120)
		if err != nil {
			return 0, err
		}
		*step = ""
		if err := q.rows(reader, page.Rows, step); err != nil {
			return 0, err
		}
		if page.Stop == mdbx.PrefixPageExhausted || len(page.Rows) == 0 {
			break
		}
		after = page.Rows[len(page.Rows)-1].Key
	}
	if q.count == 0 {
		q.indexEmpty = true
		q.anchor()
		return 0, nil
	}
	q.attach(q.hash, [32]byte{})
	return q.count - 1, nil
}

func (q *replayQualifier) rows(reader *mdbx.Reader, rows []mdbx.PrefixRow, step *string) error {
	for _, row := range rows {
		if err := q.canonical(reader, row, step); err != nil {
			return err
		}
	}
	return nil
}

// canonical runs D1-D9 for height h, then qualifies received branches attached at h-1, then advance applies D10.
func (q *replayQualifier) canonical(reader *mdbx.Reader, row mdbx.PrefixRow, step *string) error {
	h := binary.BigEndian.Uint64(row.Key[8:])
	var hash, parent [32]byte
	copy(hash[:], row.Value[:32])
	copy(parent[:], row.Value[32:64])
	switch {
	case h != q.count:
		return selectedSideDefect("replay canonical index height gap")
	case !archiveSelectedSideWork(row.Value[64:104]):
		return selectedSideDefect("replay canonical index work outside domain")
	}
	*step = replayEntryRecovery
	raw, present, err := reader.Get(mdbx.SchemaV2DBIs()[3], hash[:])
	if err != nil {
		return err
	}
	*step = ""
	if !present {
		return selectedSideDefect("replay canonical header absent")
	}
	header, work, err := q.canonicalHeader(h, hash, parent, raw, row.Value[64:104])
	if err != nil {
		return err
	}
	if h > 0 {
		q.attach(q.hash, hash)
	}
	q.advance(h, hash, raw, header, work)
	return nil
}

// canonicalHeader is D5-D9 for one canonical header; D9 compares the CAN23L sum at every height, the genesis included.
func (q *replayQualifier) canonicalHeader(h uint64, hash, parent [32]byte, raw, stored []byte) (BlockHeader, *big.Int, error) {
	header, err := q.canonicalIdentity(h, hash, parent, raw)
	if err != nil {
		return header, nil, err
	}
	blockWork, err := q.blockWork(header.Target)
	if err != nil {
		return header, nil, selectedSideDefect("replay canonical header target zero")
	}
	work := new(big.Int).Add(blockWork, &q.work)
	if h == 0 {
		work.Set(blockWork)
	}
	if work.BitLen() > 320 || replayEntryWork(work) != [40]byte(stored) {
		return header, nil, selectedSideDefect("replay canonical chainwork mismatch")
	}
	return header, work, nil
}

// canonicalIdentity is D5 (hash), D6 (stored parent vs header and previous entry) and D7 (height-0 genesis identity).
func (q *replayQualifier) canonicalIdentity(h uint64, hash, parent [32]byte, raw []byte) (BlockHeader, error) {
	header, err := ParseBlockHeaderBytes(raw)
	blockHash, hashErr := BlockHash(raw)
	if err != nil || hashErr != nil || blockHash != hash {
		return header, selectedSideDefect("replay canonical header hash mismatch")
	}
	return header, q.canonicalLink(h, header, hash, parent)
}

// canonicalLink is D6 (stored parent equals PrevBlockHash at every height, and q.hash above 0) and D7 at height 0.
func (q *replayQualifier) canonicalLink(h uint64, header BlockHeader, hash, parent [32]byte) error {
	switch {
	case parent != header.PrevBlockHash || h > 0 && parent != q.hash:
		return selectedSideDefect("replay canonical header linkage mismatch")
	case h == 0 && hash != q.genesis.GenesisHash:
		return selectedSideDefect("replay canonical genesis mismatch")
	}
	return nil
}

// advance records canonical height h: D10 and exclusion ineligibility, E3 copies, canonical-hash tips and the window.
func (q *replayQualifier) advance(h uint64, hash [32]byte, raw []byte, header BlockHeader, work *big.Int) {
	if !q.canonicalOK(h, raw, header) || q.isExcluded(hash) {
		q.markBad(h)
	}
	if h == q.atC {
		q.hashAtC, q.hasAtC = hash, true
	}
	q.hash, q.target, q.count = hash, header.Target, h+1
	q.work.Set(work)
	q.ring[h%WINDOW_SIZE] = header.Timestamp
	encoded := replayEntryWork(work)
	if i := q.find(hash); i >= 0 {
		q.nodes[i].flags |= replayNodeE3 | replayNodeReached
		q.nodes[i].height, q.nodes[i].work = h, encoded
	}
	if q.countIdentityTip(hash) {
		q.consider(hash, h, encoded, q.badFrom <= h)
	}
}

// markBad records disqualified or excluded canonical height h before advance overwrites q.hash and q.work: the first
// such height (the walk ascends) makes the identity at h-1 the published prefix tip candidate (MP 2544-2561) and
// records it as the recomputation's published OLD comparand.
func (q *replayQualifier) markBad(h uint64) {
	if q.badFrom == math.MaxUint64 && h > 0 {
		q.comparand = replayCandidate{ok: true, hash: q.hash, height: h - 1, work: replayEntryWork(&q.work)}
		q.consider(q.hash, h-1, q.comparand.work, false)
	}
	q.badFrom = min(q.badFrom, h)
}

// countIdentityTip reports whether hash, a canonical or Fork F anchor identity, is a listed tip, and counts it when no
// header supplies it, so unknownTips does not take it for E1 (MP 2529-2535).
func (q *replayQualifier) countIdentityTip(hash [32]byte) bool {
	_, tip := slices.BinarySearchFunc(q.tips, hash, replayHashCompare)
	if tip && q.find(hash) < 0 {
		q.canonTips++
	}
	return tip
}

// canonicalOK is D10: PoW at height 0 (CANONICAL L1802, L2232); CAN15 target, PoW and CAN22 above it.
func (q *replayQualifier) canonicalOK(h uint64, raw []byte, header BlockHeader) bool {
	if h == 0 {
		return PowCheck(raw, header.Target) == nil
	}
	return q.headerOK(h, raw, header, -1, q.target)
}

// headerOK is CAN15, PoW and CAN22 for a header whose parent is node parent (-1: canonical at q.attachK or tip).
func (q *replayQualifier) headerOK(h uint64, raw []byte, header BlockHeader, parent int, parentTarget [32]byte) bool {
	expected := parentTarget
	if h%WINDOW_SIZE == 0 {
		q.gather(parent, h, int(WINDOW_SIZE), q.scratch)
		slices.Reverse(q.scratch)
		target, err := ReplayExpectedTargetV1(h, parentTarget, q.scratch)
		if err != nil {
			return false
		}
		expected = target
	}
	if header.Target != expected || PowCheck(raw, expected) != nil {
		return false
	}
	k := int(min(h, 11))
	q.gather(parent, h, k, q.mtp[:k])
	return validateTimestampRules(header.Timestamp, h, q.mtp[:k]) == nil
}

// gather fills dst newest-first with n ancestor timestamps: received ancestors, then the canonical ring.
func (q *replayQualifier) gather(parent int, h uint64, n int, dst []uint64) {
	i, height := 0, h-1
	for cur := parent; cur >= 0 && i < n; i++ {
		header, _ := ParseBlockHeaderBytes(q.header(cur))
		dst[i], height = header.Timestamp, height-1
		cur = q.receivedParent(cur)
	}
	for ; i < n; i++ {
		dst[i] = q.ring[height%WINDOW_SIZE]
		height--
	}
}

// receivedParent is the supplied non-canonical parent node of node i, -1 when the parent is canonical.
func (q *replayQualifier) receivedParent(i int) int {
	p := q.find(q.parentOf(i))
	if p < 0 || q.nodes[p].flags&replayNodeE3 != 0 {
		return -1
	}
	return p
}

// kidStart is the first parent-sorted index whose parent is >= parent.
func (q *replayQualifier) kidStart(parent [32]byte) int {
	i, _ := slices.BinarySearchFunc(q.kids, parent, func(k replayKid, p [32]byte) int { return bytes.Compare(k.parent[:], p[:]) })
	return i
}

// kidIndex is node i's own parent-sorted index.
func (q *replayQualifier) kidIndex(i int) int {
	j, _ := slices.BinarySearchFunc(q.kids, replayKid{parent: q.parentOf(i), pos: i}, replayKidCompare)
	return j
}

// replayKidCompare orders by parent hash, then own hash: nodes are hash-sorted and unique, so pos order is hash order.
func replayKidCompare(a, b replayKid) int {
	if c := bytes.Compare(a.parent[:], b.parent[:]); c != 0 {
		return c
	}
	return cmp.Compare(a.pos, b.pos)
}

// attach qualifies, stacklessly in preorder, every received branch rooted on canonical parent except successor.
func (q *replayQualifier) attach(parent, successor [32]byte) {
	q.attachK = q.count - 1
	for j := q.kidStart(parent); j < len(q.kids) && q.kids[j].parent == parent; j++ {
		root := q.kids[j].pos
		if q.nodes[root].hash != successor && q.nodes[root].flags&replayNodeE3 == 0 {
			q.subtree(root, q.badFrom <= q.attachK)
		}
	}
}

// subtree qualifies root and its received descendants; a parent-sorted sibling scan replaces a stack.
func (q *replayQualifier) subtree(root int, rootBad bool) {
	q.qualify(root, -1, rootBad)
	cur := root
	for {
		if j := q.kidStart(q.nodes[cur].hash); j < len(q.kids) && q.kids[j].parent == q.nodes[cur].hash {
			child := q.kids[j].pos
			q.qualify(child, cur, false)
			cur = child
			continue
		}
		next, done := q.climb(cur, root)
		if done {
			return
		}
		cur = next
	}
}

// climb moves to the next unvisited sibling of cur or of an ancestor below root, qualifying it; done at root.
func (q *replayQualifier) climb(cur, root int) (int, bool) {
	for cur != root {
		parent := q.find(q.parentOf(cur))
		if j := q.kidIndex(cur) + 1; j < len(q.kids) && q.kids[j].parent == q.parentOf(cur) {
			sibling := q.kids[j].pos
			q.qualify(sibling, parent, false)
			return sibling, false
		}
		cur = parent
	}
	return 0, true
}

// qualify is the E5 predicate set of one received header under its parent (-1: canonical height q.attachK).
func (q *replayQualifier) qualify(i, parent int, parentBad bool) {
	n := &q.nodes[i]
	n.flags |= replayNodeReached
	height, target, work, bad := q.parentState(parent, parentBad)
	n.height = height
	header, _ := ParseBlockHeaderBytes(q.header(i))
	blockWork, err := q.blockWork(header.Target)
	if err == nil {
		work.Add(work, blockWork)
	}
	ok := err == nil && !bad && replayEntryHeightOK(height) && replayEntryWorkOK(work) &&
		!q.isExcluded(n.hash) && q.headerOK(height, q.header(i), header, parent, target)
	if !ok {
		n.flags |= replayNodeBad
		return
	}
	n.work = replayEntryWork(work)
}

// parentState is the child height and the parent target, chainwork and ineligibility (-1: canonical attach).
func (q *replayQualifier) parentState(parent int, canonicalBad bool) (uint64, [32]byte, *big.Int, bool) {
	if parent < 0 {
		return q.attachK + 1, q.target, new(big.Int).Set(&q.work), canonicalBad
	}
	p := q.nodes[parent]
	ph, _ := ParseBlockHeaderBytes(q.header(parent))
	return p.height + 1, ph.Target, new(big.Int).SetBytes(p.work[:]), p.flags&replayNodeBad != 0
}

func (q *replayQualifier) isExcluded(hash [32]byte) bool {
	return q.excluded != nil && *q.excluded == hash
}

// anchor is the Fork F height-0 anchor: Published[:116], else the supplied GenesisHash header; decode, PoW and exclusion.
func (q *replayQualifier) anchor() {
	raw := q.genesis.Published
	i := q.find(q.genesis.GenesisHash)
	if i >= 0 {
		q.nodes[i].flags |= replayNodeE3 | replayNodeReached
	}
	if raw == nil && i >= 0 {
		raw = q.header(i)
	}
	if raw == nil {
		return
	}
	header, _ := ParseBlockHeaderBytes(raw[:BLOCK_HEADER_BYTES])
	work, err := WorkFromTarget(header.Target)
	if err != nil || PowCheck(raw[:BLOCK_HEADER_BYTES], header.Target) != nil {
		q.badFrom, work = 0, big.NewInt(1)
	}
	if q.isExcluded(q.genesis.GenesisHash) {
		q.badFrom = 0
	}
	q.hash, q.target, q.count = q.genesis.GenesisHash, header.Target, 1
	q.work.Set(work)
	q.ring[0] = header.Timestamp
	q.countIdentityTip(q.hash)
	q.attach(q.hash, [32]byte{})
}

// consider keeps the best eligible positive-height candidate: greater chainwork, then the smaller tip hash.
func (q *replayQualifier) consider(hash [32]byte, height uint64, work [40]byte, bad bool) {
	if bad || !replayEntryHeightOK(height) {
		return
	}
	if q.best.ok {
		c := bytes.Compare(work[:], q.best.work[:])
		if c < 0 || c == 0 && bytes.Compare(hash[:], q.best.hash[:]) > 0 {
			return
		}
	}
	q.best = replayCandidate{ok: true, hash: hash, height: height, work: work}
}

// selectTarget runs H5, E2 and E1, adds the canonical tip and returns the selected RecoveryTargetV1.
func (q *replayQualifier) selectTarget() (mdbx.RecoveryTargetV1, bool, string) {
	q.markForeign()
	if !q.allReached() || q.unknownTips() {
		return mdbx.RecoveryTargetV1{}, false, replayEntryRecovery
	}
	if !q.indexEmpty {
		q.consider(q.hash, q.count-1, replayEntryWork(&q.work), q.badFrom < q.count)
	}
	if !q.best.ok {
		return mdbx.RecoveryTargetV1{}, false, ""
	}
	return mdbx.RecoveryTargetV1{ChainID: q.genesis.ChainID, GenesisHash: q.genesis.GenesisHash, TipHash: q.best.hash, TipHeight: q.best.height, CumulativeChainwork: q.best.work}, true, ""
}

// markForeign makes supplied zero-parent non-anchor headers and their descendants ineligible (H5).
func (q *replayQualifier) markForeign() {
	var zero [32]byte
	for j := q.kidStart(zero); j < len(q.kids) && q.kids[j].parent == zero; j++ {
		if root := q.kids[j].pos; q.nodes[root].flags&replayNodeReached == 0 {
			q.subtree(root, true)
		}
	}
}

// allReached is false on E2: a supplied header never reached (a foreign zero-parent root counts as reached).
func (q *replayQualifier) allReached() bool {
	for i := range q.nodes {
		if q.nodes[i].flags&replayNodeReached == 0 {
			return false
		}
	}
	return true
}

// unknownTips is E1; supplied non-canonical tips become candidates here.
func (q *replayQualifier) unknownTips() bool {
	missing := 0
	for _, tip := range q.tips {
		i := q.find(tip)
		if i < 0 {
			missing++
			continue
		}
		if n := q.nodes[i]; n.flags&replayNodeE3 == 0 {
			q.consider(tip, n.height, n.work, n.flags&replayNodeBad != 0)
		}
	}
	return missing != q.canonTips
}
