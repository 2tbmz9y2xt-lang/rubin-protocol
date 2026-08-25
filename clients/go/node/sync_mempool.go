package node

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type mempoolSnapshot struct {
	entries []mempoolEntry
	// pending is the same-owner pending-outpoint image captured with the
	// entries: every live claim, the stable tip, and both high-waters.
	pending           pendingOutpointSnapshot
	lastAdmissionSeq  uint64
	currentMinFeeRate uint64
}

// snapshotMempool captures the exact rollback image: cloned entries with their
// exact tokens plus the owner's claims, stable tip and high-waters. Lock order
// is Mempool.mu then owner.mu.
func snapshotMempool(m *Mempool) (mempoolSnapshot, error) {
	if m == nil {
		return mempoolSnapshot{}, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := make([]mempoolEntry, 0, len(m.txs))
	for _, entry := range m.txs {
		entries = append(entries, cloneMempoolEntry(entry))
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].txid[:], entries[j].txid[:]) < 0
	})
	currentMinFeeRate := m.currentMinFeeRate
	if currentMinFeeRate < DefaultMempoolMinFeeRate {
		currentMinFeeRate = DefaultMempoolMinFeeRate
	}
	pending, err := snapshotCanonicalMempoolOwner(m.pendingOutpoints)
	if err != nil {
		return mempoolSnapshot{}, err
	}
	return mempoolSnapshot{
		entries:           entries,
		pending:           pending,
		lastAdmissionSeq:  m.lastAdmissionSeq,
		currentMinFeeRate: currentMinFeeRate,
	}, nil
}

func snapshotCanonicalMempoolOwner(owner *PendingOutpointOwner) (pendingOutpointSnapshot, error) {
	if owner == nil {
		return pendingOutpointSnapshot{}, terminalCanonicalMempoolError(errors.New("nil pending-outpoint owner"))
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	claims := make([]pendingOutpointClaim, 0, len(owner.byToken))
	for _, claim := range owner.byToken {
		if claim == nil {
			return pendingOutpointSnapshot{}, terminalCanonicalMempoolError(errors.New("nil pending-outpoint owner claim"))
		}
		copied := *claim
		copied.inputs = append([]consensus.Outpoint(nil), claim.inputs...)
		claims = append(claims, copied)
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].token.seq < claims[j].token.seq })
	return pendingOutpointSnapshot{
		claims:              claims,
		stableTip:           owner.stableTip,
		tokenHighWater:      owner.tokenHighWater,
		generationHighWater: owner.generation,
	}, nil
}

// validateRestoredClaimBinding proves the bijection between the records about to
// be installed and the CANDIDATE finalized standard claims that would be
// published alongside them: every record with inputs holds exactly one finalized
// standard claim carrying its exact token, txid, domain and ordered inputs, and
// no finalized standard claim is left without a record. Both sides are still
// unpublished, so a rejection leaves live owner and records untouched.
func validateRestoredClaimBinding(txs map[[32]byte]*mempoolEntry, candidate pendingOutpointIndex) error {
	finalized := 0
	for _, claim := range candidate.byToken {
		if claim.domain == PendingOutpointStandardMempool && claim.finalized {
			finalized++
		}
	}
	claimed := 0
	for _, entry := range txs {
		if err := candidate.validateEntryClaim(entry.txid, entry.inputs, entry.token, true); err != nil {
			return err
		}
		if len(entry.inputs) > 0 {
			claimed++
		}
	}
	if claimed != finalized {
		return pendingOutpointInternal(fmt.Sprintf("mempool snapshot claim count mismatch: records=%d finalized_claims=%d", claimed, finalized))
	}
	return nil
}

func validateMempoolSnapshotEntry(entry mempoolEntry) (*consensus.Tx, error) {
	if entry.size <= 0 {
		return nil, fmt.Errorf("invalid mempool snapshot entry size for txid %x: size=%d raw_len=%d", entry.txid, entry.size, len(entry.raw))
	}
	if entry.weight == 0 {
		return nil, fmt.Errorf("invalid mempool snapshot entry weight for txid %x: weight=0", entry.txid)
	}
	if entry.size != len(entry.raw) {
		return nil, fmt.Errorf("mempool snapshot entry size mismatch for txid %x: size=%d raw_len=%d", entry.txid, entry.size, len(entry.raw))
	}
	tx, err := parseMempoolEntryRaw(entry)
	if err != nil {
		return nil, err
	}
	if err := validateMempoolEntryParsedTx(entry, tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func cloneMempoolEntry(entry *mempoolEntry) mempoolEntry {
	if entry == nil {
		return mempoolEntry{}
	}
	return mempoolEntry{
		raw:          append([]byte(nil), entry.raw...),
		txid:         entry.txid,
		wtxid:        entry.wtxid,
		inputs:       append([]consensus.Outpoint(nil), entry.inputs...),
		token:        entry.token,
		fee:          entry.fee,
		weight:       entry.weight,
		size:         entry.size,
		admissionSeq: entry.admissionSeq,
		source:       entry.source,
	}
}

// buildMempoolRestoreMaps builds txid/wtxid/admission maps from snapshot
// entries. Outpoint uniqueness is no longer checked here: the owner's
// restoreLocked rejects a duplicate outpoint across claims, and
// validateRestoredClaimBinding then binds every record to its exact claim.
func buildMempoolRestoreMaps(snapshotEntries []mempoolEntry, maxTxs int, maxBytes int) (
	txs map[[32]byte]*mempoolEntry,
	wtxids map[[32]byte][32]byte,
	maxAdmissionSeq uint64,
	usedBytes int,
	err error,
) {
	txs = make(map[[32]byte]*mempoolEntry, len(snapshotEntries))
	wtxids = make(map[[32]byte][32]byte, len(snapshotEntries))
	admissionSeqs := make(map[uint64][32]byte, len(snapshotEntries))
	for _, item := range snapshotEntries {
		entry := cloneMempoolEntry(&item)
		if _, err := validateMempoolRestoreEntry(entry, txs, wtxids, admissionSeqs, len(txs), usedBytes, maxTxs, maxBytes); err != nil {
			return nil, nil, 0, 0, err
		}
		entryCopy := entry
		txs[entryCopy.txid] = &entryCopy
		wtxids[entryCopy.wtxid] = entryCopy.txid
		admissionSeqs[entryCopy.admissionSeq] = entryCopy.txid
		usedBytes += entryCopy.size
		if entryCopy.admissionSeq > maxAdmissionSeq {
			maxAdmissionSeq = entryCopy.admissionSeq
		}
	}
	return
}

func validateMempoolRestoreEntry(
	entry mempoolEntry,
	txs map[[32]byte]*mempoolEntry,
	wtxids map[[32]byte][32]byte,
	admissionSeqs map[uint64][32]byte,
	txCount int,
	usedBytes int,
	maxTxs int,
	maxBytes int,
) (*consensus.Tx, error) {
	if _, exists := txs[entry.txid]; exists {
		return nil, fmt.Errorf("duplicate mempool snapshot txid %x", entry.txid)
	}
	if existing, exists := wtxids[entry.wtxid]; exists {
		return nil, fmt.Errorf("duplicate mempool snapshot wtxid %x existing=%x new=%x", entry.wtxid, existing, entry.txid)
	}
	tx, err := validateMempoolSnapshotEntry(entry)
	if err != nil {
		return nil, err
	}
	if existing, exists := admissionSeqs[entry.admissionSeq]; exists {
		return nil, fmt.Errorf("duplicate mempool snapshot admission_seq %d existing=%x new=%x", entry.admissionSeq, existing, entry.txid)
	}
	if txCount >= maxTxs {
		return nil, fmt.Errorf("mempool snapshot exceeds transaction cap: count=%d max=%d", txCount+1, maxTxs)
	}
	if entry.size > maxBytes || usedBytes > maxBytes-entry.size {
		return nil, fmt.Errorf("mempool snapshot exceeds byte cap: used=%d entry=%d max=%d", usedBytes, entry.size, maxBytes)
	}
	return tx, nil
}

// validateMempoolEntryParsed parses raw tx bytes inside a mempool entry and validates consistency.
func validateMempoolEntryParsed(entry mempoolEntry) error {
	tx, err := parseMempoolEntryRaw(entry)
	if err != nil {
		return err
	}
	return validateMempoolEntryParsedTx(entry, tx)
}

func parseMempoolEntryRaw(entry mempoolEntry) (*consensus.Tx, error) {
	tx, txid, wtxid, consumed, err := consensus.ParseTx(entry.raw)
	if err != nil {
		return nil, fmt.Errorf("invalid mempool snapshot entry raw for txid %x: %w", entry.txid, err)
	}
	if consumed != len(entry.raw) {
		return nil, fmt.Errorf("mempool snapshot entry has trailing bytes for txid %x: consumed=%d raw_len=%d", entry.txid, consumed, len(entry.raw))
	}
	if txid != entry.txid {
		return nil, fmt.Errorf("mempool snapshot entry txid mismatch: entry=%x raw=%x", entry.txid, txid)
	}
	if wtxid != entry.wtxid {
		return nil, fmt.Errorf("mempool snapshot entry wtxid mismatch: entry=%x raw=%x", entry.wtxid, wtxid)
	}
	return tx, nil
}

func validateMempoolEntryParsedTx(entry mempoolEntry, tx *consensus.Tx) error {
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		return fmt.Errorf("invalid mempool snapshot entry weight for txid %x: %w", entry.txid, err)
	}
	if entry.weight != weight {
		return fmt.Errorf("mempool snapshot entry weight mismatch: entry=%d computed=%d txid=%x", entry.weight, weight, entry.txid)
	}
	if entry.admissionSeq == 0 {
		return fmt.Errorf("invalid mempool snapshot entry admission_seq for txid %x: seq=0", entry.txid)
	}
	if !validMempoolTxSource(entry.source) {
		return fmt.Errorf("invalid mempool snapshot entry source for txid %x: source=%q", entry.txid, entry.source)
	}
	if len(entry.inputs) != len(tx.Inputs) {
		return fmt.Errorf("mempool snapshot entry input count mismatch for txid %x: entry=%d tx=%d", entry.txid, len(entry.inputs), len(tx.Inputs))
	}
	for i, in := range tx.Inputs {
		want := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		if entry.inputs[i] != want {
			return fmt.Errorf("mempool snapshot entry input mismatch for txid %x at index=%d", entry.txid, i)
		}
	}
	return nil
}

// canonicalMempoolPlan is the complete standard-record/owner-claim image installed before C mutation.
type canonicalMempoolPlan struct {
	owner             *PendingOutpointOwner
	snapshot          mempoolSnapshot
	snapshotUsedBytes int
	txs               map[[32]byte]*mempoolEntry
	wtxids            map[[32]byte][32]byte
	usedBytes         int
	lastAdmissionSeq  uint64
	currentMinFeeRate uint64
	pending           pendingOutpointSnapshot
	ownerIndex        pendingOutpointIndex
}

type canonicalMempoolPlanContext struct {
	owner      *PendingOutpointOwner
	chainState *ChainState
	policy     MempoolConfig
	chainID    [32]byte
	sigCache   *consensus.SigCache
	maxTxs     int
	maxBytes   int
	lowWater   int
	feeFloor   uint64
	lastSeq    uint64
}

type canonicalMempoolFinalState struct {
	utxos      map[consensus.Outpoint]consensus.UtxoEntry
	nextHeight uint64
	mtp        uint64
}

type canonicalMOTerminalError struct{ detail string }

func (e *canonicalMOTerminalError) Error() string {
	return "canonical mempool invariant: " + e.detail
}

type canonicalMOPlanError struct{ detail string }

func (e *canonicalMOPlanError) Error() string {
	return "canonical mempool plan: " + e.detail
}

func terminalCanonicalMempoolError(err error) error {
	return &canonicalMOTerminalError{detail: err.Error()}
}

func localCanonicalMempoolPlanError(err error) error {
	return &canonicalMOPlanError{detail: err.Error()}
}

func isCanonicalMOTerminalError(err error) bool {
	var terminal *canonicalMOTerminalError
	return errors.As(err, &terminal)
}

func canonicalMempoolPlanContextOf(m *Mempool) (canonicalMempoolPlanContext, error) {
	if m == nil {
		return canonicalMempoolPlanContext{}, errors.New("nil mempool")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.pendingOutpoints == nil {
		return canonicalMempoolPlanContext{}, errors.New("nil pending-outpoint owner")
	}
	if m.maxTxs <= 0 || m.maxBytes <= 0 {
		return canonicalMempoolPlanContext{}, fmt.Errorf("invalid mempool limits: max_txs=%d max_bytes=%d", m.maxTxs, m.maxBytes)
	}
	return canonicalMempoolPlanContext{
		owner:      m.pendingOutpoints,
		chainState: m.chainState,
		policy:     m.policy,
		chainID:    m.chainID,
		sigCache:   m.sigCache,
		maxTxs:     m.maxTxs,
		maxBytes:   m.maxBytes,
		lowWater:   m.effectiveLowWaterBytesLocked(),
		feeFloor:   m.currentMinFeeRateLocked(),
		lastSeq:    m.lastAdmissionSeq,
	}, nil
}

func canonicalMempoolFinalStateOf(final *ChainState, mtp uint64, inputs []consensus.Outpoint) (canonicalMempoolFinalState, error) {
	if final == nil {
		return canonicalMempoolFinalState{}, errors.New("nil final chainstate")
	}
	snapshot := final.admissionSnapshotForInputs(inputs)
	if snapshot == nil {
		return canonicalMempoolFinalState{}, errors.New("nil final chainstate snapshot")
	}
	nextHeight, _, err := nextBlockContextFromFields(snapshot.hasTip, snapshot.height, snapshot.tipHash)
	if err != nil {
		return canonicalMempoolFinalState{}, err
	}
	return canonicalMempoolFinalState{utxos: snapshot.utxos, nextHeight: nextHeight, mtp: mtp}, nil
}

func prepareCanonicalMempoolPlan(
	m *Mempool,
	snapshot mempoolSnapshot,
	final *ChainState,
	mtp uint64,
	decayRows int,
	chainID [32]byte,
) (canonicalMempoolPlan, error) {
	if decayRows < 0 {
		return canonicalMempoolPlan{}, terminalCanonicalMempoolError(errors.New("negative canonical fee-decay rows"))
	}
	ctx, err := canonicalMempoolPlanContextForChain(m, chainID)
	if err != nil {
		return canonicalMempoolPlan{}, terminalCanonicalMempoolError(err)
	}
	snapshot, usedBytes, err := canonicalMempoolPlanSnapshot(m, snapshot, ctx)
	if err != nil {
		return canonicalMempoolPlan{}, terminalCanonicalMempoolError(err)
	}
	finalState, err := canonicalMempoolFinalStateOf(final, mtp, canonicalMempoolInputUnion(snapshot.entries))
	if err != nil {
		return canonicalMempoolPlan{}, terminalCanonicalMempoolError(err)
	}
	retained, err := selectCanonicalMempoolEntries(snapshot.entries, finalState, ctx)
	if err != nil {
		return canonicalMempoolPlan{}, err
	}
	return buildCanonicalMempoolPlan(retained, snapshot, ctx, decayRows, usedBytes)
}

func canonicalMempoolPlanContextForChain(m *Mempool, chainID [32]byte) (canonicalMempoolPlanContext, error) {
	ctx, err := canonicalMempoolPlanContextOf(m)
	if err != nil {
		return canonicalMempoolPlanContext{}, err
	}
	if ctx.chainID != chainID {
		return canonicalMempoolPlanContext{}, errors.New("mempool chain ID does not match canonical transition")
	}
	return ctx, nil
}

func canonicalMempoolPlanSnapshot(m *Mempool, snapshot mempoolSnapshot, ctx canonicalMempoolPlanContext) (mempoolSnapshot, int, error) {
	snapshot = canonicalMempoolSnapshotInRawOrder(snapshot)
	utxos, err := canonicalMempoolSnapshotUtxos(ctx.chainState, snapshot.entries)
	if err != nil {
		return mempoolSnapshot{}, 0, err
	}
	maxSeq, usedBytes, err := validateCanonicalMempoolStructuralImage(snapshot, ctx.owner, ctx.maxTxs, ctx.maxBytes, utxos)
	if err != nil {
		return mempoolSnapshot{}, 0, err
	}
	if err := validateCanonicalMempoolSnapshotScalars(snapshot, ctx, maxSeq); err != nil {
		return mempoolSnapshot{}, 0, err
	}
	if err := validateCanonicalMempoolLiveImage(m, snapshot, usedBytes, ctx.owner); err != nil {
		return mempoolSnapshot{}, 0, err
	}
	return snapshot, usedBytes, nil
}

func canonicalMempoolSnapshotUtxos(state *ChainState, entries []mempoolEntry) (map[consensus.Outpoint]consensus.UtxoEntry, error) {
	snapshot := state.admissionSnapshotForInputs(canonicalMempoolInputUnion(entries))
	if snapshot == nil {
		return nil, errors.New("nil mempool chainstate snapshot")
	}
	return snapshot.utxos, nil
}

func validateCanonicalMempoolSnapshotScalars(snapshot mempoolSnapshot, ctx canonicalMempoolPlanContext, maxSeq uint64) error {
	if snapshot.lastAdmissionSeq < maxSeq || ctx.lastSeq != snapshot.lastAdmissionSeq {
		return errors.New("mempool admission sequence high-water mismatch")
	}
	if snapshot.currentMinFeeRate != ctx.feeFloor {
		return errors.New("mempool fee-floor snapshot mismatch")
	}
	return nil
}

func canonicalMempoolInputUnion(entries []mempoolEntry) []consensus.Outpoint {
	seen := make(map[consensus.Outpoint]struct{})
	inputs := make([]consensus.Outpoint, 0)
	for i := range entries {
		for _, input := range entries[i].inputs {
			if _, ok := seen[input]; !ok {
				seen[input] = struct{}{}
				inputs = append(inputs, input)
			}
		}
	}
	return inputs
}

// canonicalMempoolSnapshotInRawOrder orders standard records/claims by raw txid,
// then other claims by raw txid and token; the rollback snapshot stays untouched.
func canonicalMempoolSnapshotInRawOrder(snapshot mempoolSnapshot) mempoolSnapshot {
	snapshot.entries = append([]mempoolEntry(nil), snapshot.entries...)
	sort.Slice(snapshot.entries, func(i, j int) bool {
		return bytes.Compare(snapshot.entries[i].txid[:], snapshot.entries[j].txid[:]) < 0
	})
	claims := append([]pendingOutpointClaim(nil), snapshot.pending.claims...)
	sort.Slice(claims, func(i, j int) bool {
		left, right := claims[i], claims[j]
		leftStandard := left.domain == PendingOutpointStandardMempool
		rightStandard := right.domain == PendingOutpointStandardMempool
		if leftStandard != rightStandard {
			return leftStandard
		}
		if order := bytes.Compare(left.txid[:], right.txid[:]); order != 0 {
			return order < 0
		}
		return left.token.seq < right.token.seq
	})
	snapshot.pending.claims = claims
	return snapshot
}

func validateCanonicalMempoolStructuralImage(snapshot mempoolSnapshot, owner *PendingOutpointOwner, maxTxs int, maxBytes int, utxos map[consensus.Outpoint]consensus.UtxoEntry) (uint64, int, error) {
	if owner == nil {
		return 0, 0, errors.New("nil canonical mempool or pending-outpoint owner")
	}
	claims := canonicalMempoolClaimsByToken(snapshot.pending)
	bound, maxSeq, usedBytes, err := validateCanonicalMempoolStructuralRecords(owner, snapshot.entries, snapshot.pending, claims, maxTxs, maxBytes, utxos)
	if err != nil {
		return 0, 0, err
	}
	if err := validateCanonicalMempoolRemainingClaims(owner, snapshot.pending, claims, bound); err != nil {
		return 0, 0, err
	}
	return maxSeq, usedBytes, nil
}

func canonicalMempoolClaimsByToken(pending pendingOutpointSnapshot) map[PendingOutpointToken][]*pendingOutpointClaim {
	claims := make(map[PendingOutpointToken][]*pendingOutpointClaim, len(pending.claims))
	for i := range pending.claims {
		claim := &pending.claims[i]
		claims[claim.token] = append(claims[claim.token], claim)
	}
	return claims
}

func validateCanonicalMempoolStructuralRecords(
	owner *PendingOutpointOwner,
	entries []mempoolEntry,
	pending pendingOutpointSnapshot,
	claims map[PendingOutpointToken][]*pendingOutpointClaim,
	maxTxs int,
	maxBytes int,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
) (map[PendingOutpointToken]struct{}, uint64, int, error) {
	bound := make(map[PendingOutpointToken]struct{}, len(entries))
	txs := make(map[[32]byte]*mempoolEntry, len(entries))
	wtxids := make(map[[32]byte][32]byte, len(entries))
	admissionSeqs := make(map[uint64][32]byte, len(entries))
	var maxSeq uint64
	usedBytes := 0
	for i := range entries {
		entry := entries[i]
		tx, err := validateMempoolRestoreEntry(entry, txs, wtxids, admissionSeqs, len(txs), usedBytes, maxTxs, maxBytes)
		if err != nil {
			return nil, 0, 0, err
		}
		if err := validateCanonicalMempoolStoredFee(entry, tx, utxos); err != nil {
			return nil, 0, 0, err
		}
		_, err = canonicalMempoolBoundClaim(owner, entry, pending, claims[entry.token])
		if err != nil {
			return nil, 0, 0, err
		}
		entryCopy := entry
		txs[entryCopy.txid] = &entryCopy
		wtxids[entryCopy.wtxid] = entryCopy.txid
		admissionSeqs[entryCopy.admissionSeq] = entryCopy.txid
		usedBytes += entryCopy.size
		if entryCopy.admissionSeq > maxSeq {
			maxSeq = entryCopy.admissionSeq
		}
		if len(entry.inputs) != 0 {
			bound[entry.token] = struct{}{}
		}
	}
	return bound, maxSeq, usedBytes, nil
}

func validateCanonicalMempoolStoredFee(entry mempoolEntry, tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry) error {
	fee, err := computeFeeNoVerify(tx, utxos)
	if err != nil {
		return fmt.Errorf("cannot recompute mempool snapshot fee for txid %x: %w", entry.txid, err)
	}
	if fee != entry.fee {
		return fmt.Errorf("mempool snapshot entry fee mismatch: entry=%v computed=%v txid=%x", entry.fee, fee, entry.txid)
	}
	return nil
}

func canonicalMempoolBoundClaim(
	owner *PendingOutpointOwner,
	entry mempoolEntry,
	pending pendingOutpointSnapshot,
	candidates []*pendingOutpointClaim,
) (pendingOutpointClaim, error) {
	if len(entry.inputs) == 0 {
		return pendingOutpointClaim{}, checkInputLessEntryToken(entry.txid, entry.token)
	}
	if len(candidates) != 1 {
		return pendingOutpointClaim{}, pendingOutpointInternal(fmt.Sprintf("pending-outpoint claim count mismatch for entry %x", entry.txid))
	}
	claim := *candidates[0]
	if err := validateCanonicalMempoolClaimShape(owner, claim, pending); err != nil {
		return pendingOutpointClaim{}, fmt.Errorf("pending-outpoint claim mismatch for entry %x: %w", entry.txid, err)
	}
	if !canonicalMempoolBoundClaimShapeMatches(entry, claim) {
		return pendingOutpointClaim{}, pendingOutpointInternal(fmt.Sprintf("pending-outpoint claim mismatch for entry %x", entry.txid))
	}
	if err := canonicalMempoolBoundClaimInputs(entry, claim); err != nil {
		return pendingOutpointClaim{}, err
	}
	return claim, nil
}

func canonicalMempoolBoundClaimShapeMatches(entry mempoolEntry, claim pendingOutpointClaim) bool {
	return claim.domain == PendingOutpointStandardMempool && claim.txid == entry.txid && claim.finalized && len(claim.inputs) == len(entry.inputs)
}

func canonicalMempoolBoundClaimInputs(entry mempoolEntry, claim pendingOutpointClaim) error {
	if slices.Equal(entry.inputs, claim.inputs) {
		return nil
	}
	return pendingOutpointInternal(fmt.Sprintf("pending-outpoint claim input mismatch for entry %x", entry.txid))
}

func validateCanonicalMempoolClaimShape(owner *PendingOutpointOwner, claim pendingOutpointClaim, pending pendingOutpointSnapshot) error {
	if err := owner.checkSnapshotClaim(claim, pending.tokenHighWater); err != nil {
		return err
	}
	if claim.generation > pending.generationHighWater {
		return pendingOutpointInternal(fmt.Sprintf("pending-outpoint claim generation above high-water for %x", claim.txid))
	}
	return validatePendingOutpointRequest(claim.domain, claim.txid, claim.inputs)
}

func validateCanonicalMempoolRemainingClaims(
	owner *PendingOutpointOwner,
	pending pendingOutpointSnapshot,
	claims map[PendingOutpointToken][]*pendingOutpointClaim,
	bound map[PendingOutpointToken]struct{},
) error {
	if err := validateCanonicalMempoolOrphanStandardClaims(owner, pending, claims, bound); err != nil {
		return err
	}
	if err := validateCanonicalMempoolNonStandardClaims(owner, pending, claims); err != nil {
		return err
	}
	return nil
}

func validateCanonicalMempoolOrphanStandardClaims(owner *PendingOutpointOwner, pending pendingOutpointSnapshot, claims map[PendingOutpointToken][]*pendingOutpointClaim, bound map[PendingOutpointToken]struct{}) error {
	for i := range pending.claims {
		claim := pending.claims[i]
		if claim.domain != PendingOutpointStandardMempool {
			continue
		}
		if _, ok := bound[claim.token]; ok {
			continue
		}
		if len(claims[claim.token]) != 1 {
			return pendingOutpointInternal(fmt.Sprintf("duplicate pending-outpoint token claim for %x", claim.txid))
		}
		if err := validateCanonicalMempoolClaimShape(owner, claim, pending); err != nil {
			return err
		}
		return pendingOutpointInternal(fmt.Sprintf("orphan standard pending-outpoint claim for %x", claim.txid))
	}
	return nil
}

func validateCanonicalMempoolNonStandardClaims(owner *PendingOutpointOwner, pending pendingOutpointSnapshot, claims map[PendingOutpointToken][]*pendingOutpointClaim) error {
	for i := range pending.claims {
		claim := pending.claims[i]
		if claim.domain == PendingOutpointStandardMempool {
			continue
		}
		if len(claims[claim.token]) != 1 {
			return pendingOutpointInternal(fmt.Sprintf("duplicate pending-outpoint token claim for %x", claim.txid))
		}
		if err := validateCanonicalMempoolClaimShape(owner, claim, pending); err != nil {
			return err
		}
	}
	return nil
}

func validateCanonicalMempoolLiveClaimLocked(owner *PendingOutpointOwner, claim pendingOutpointClaim) error {
	live := owner.byToken[claim.token]
	if !samePendingOutpointClaim(live, claim) {
		return fmt.Errorf("pending-outpoint token index mismatch for txid %x", claim.txid)
	}
	for _, input := range claim.inputs {
		row, ok := owner.byOutpoint[input]
		if !ok || row.token != claim.token || row.txid != claim.txid {
			return fmt.Errorf("pending-outpoint outpoint index mismatch for txid %x", claim.txid)
		}
	}
	return nil
}

func validateCanonicalMempoolLiveImage(
	m *Mempool,
	snapshot mempoolSnapshot,
	wantUsedBytes int,
	wantOwner *PendingOutpointOwner,
) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	wantOwner.mu.Lock()
	defer wantOwner.mu.Unlock()
	return validateCanonicalMempoolLiveImageLocked(m, snapshot, wantUsedBytes, wantOwner)
}

func validateCanonicalMempoolLiveImageLocked(
	m *Mempool,
	snapshot mempoolSnapshot,
	wantUsedBytes int,
	wantOwner *PendingOutpointOwner,
) error {
	if err := validateCanonicalMempoolLiveHeaderLocked(m, snapshot, wantUsedBytes, wantOwner); err != nil {
		return err
	}
	wantOutpoints, err := validateCanonicalMempoolLiveRecordsAndClaimsLocked(m, wantOwner, snapshot)
	if err != nil {
		return err
	}
	if len(wantOwner.byOutpoint) != wantOutpoints {
		return errors.New("pending-outpoint outpoint index cardinality mismatch")
	}
	return nil
}

func validateCanonicalMempoolLiveHeaderLocked(m *Mempool, snapshot mempoolSnapshot, wantUsedBytes int, wantOwner *PendingOutpointOwner) error {
	if wantOwner == nil {
		return errors.New("nil pending-outpoint owner")
	}
	if !canonicalMempoolLiveIndexCardinalityMatches(m, snapshot, wantOwner) {
		return errors.New("mempool live index cardinality mismatch")
	}
	if m.usedBytes != wantUsedBytes {
		return fmt.Errorf("mempool used-bytes mismatch: live=%d snapshot=%d", m.usedBytes, wantUsedBytes)
	}
	if !canonicalMempoolLiveScalarsMatch(m, snapshot) {
		return errors.New("mempool scalar image mismatch")
	}
	if !canonicalOwnerLiveHeaderMatches(wantOwner, snapshot.pending) {
		return errors.New("pending-outpoint owner high-water or claim mismatch")
	}
	return nil
}

func canonicalMempoolLiveScalarsMatch(m *Mempool, snapshot mempoolSnapshot) bool {
	return m.lastAdmissionSeq == snapshot.lastAdmissionSeq && m.currentMinFeeRate == snapshot.currentMinFeeRate
}

func canonicalMempoolLiveIndexCardinalityMatches(m *Mempool, snapshot mempoolSnapshot, owner *PendingOutpointOwner) bool {
	return m.pendingOutpoints == owner && len(m.txs) == len(snapshot.entries) && len(m.wtxids) == len(snapshot.entries)
}

func validateCanonicalMempoolLiveEntryLocked(m *Mempool, entry mempoolEntry) error {
	live, ok := m.txs[entry.txid]
	if !ok || !sameMempoolEntry(live, entry) {
		return fmt.Errorf("mempool txid index mismatch for %x", entry.txid)
	}
	if txid, ok := m.wtxids[entry.wtxid]; !ok || txid != entry.txid {
		return fmt.Errorf("mempool wtxid index mismatch for %x", entry.txid)
	}
	return nil
}

type canonicalMempoolEntryFields struct {
	txid, wtxid  [32]byte
	token        PendingOutpointToken
	fee          consensus.Uint128
	weight       uint64
	size         int
	admissionSeq uint64
	source       mempoolTxSource
}

func canonicalMempoolEntryFieldsOf(entry mempoolEntry) canonicalMempoolEntryFields {
	return canonicalMempoolEntryFields{entry.txid, entry.wtxid, entry.token, entry.fee, entry.weight, entry.size, entry.admissionSeq, entry.source}
}

func sameMempoolEntry(live *mempoolEntry, snapshot mempoolEntry) bool {
	return live != nil && canonicalMempoolEntryFieldsOf(*live) == canonicalMempoolEntryFieldsOf(snapshot) && bytes.Equal(live.raw, snapshot.raw) && slices.Equal(live.inputs, snapshot.inputs)
}

func canonicalOwnerLiveHeaderMatches(owner *PendingOutpointOwner, snapshot pendingOutpointSnapshot) bool {
	return owner.inTransition && owner.tokenHighWater == snapshot.tokenHighWater && owner.generation == snapshot.generationHighWater && owner.stableTip == snapshot.stableTip && len(owner.byToken) == len(snapshot.claims)
}

func validateCanonicalMempoolLiveRecordsAndClaimsLocked(m *Mempool, owner *PendingOutpointOwner, snapshot mempoolSnapshot) (int, error) {
	claimIndex, standardOutpoints, err := validateCanonicalMempoolLiveStandardRowsLocked(m, owner, snapshot)
	if err != nil {
		return 0, err
	}
	remainingOutpoints, err := validateCanonicalMempoolLiveRemainingClaimsLocked(owner, snapshot.pending.claims[claimIndex:])
	if err != nil {
		return 0, err
	}
	return standardOutpoints + remainingOutpoints, nil
}

func validateCanonicalMempoolLiveStandardRowsLocked(m *Mempool, owner *PendingOutpointOwner, snapshot mempoolSnapshot) (int, int, error) {
	claimIndex, wantOutpoints := 0, 0
	for i := range snapshot.entries {
		entry := snapshot.entries[i]
		if err := validateCanonicalMempoolLiveEntryLocked(m, entry); err != nil {
			return 0, 0, err
		}
		if len(entry.inputs) == 0 {
			continue
		}
		if claimIndex >= len(snapshot.pending.claims) {
			return 0, 0, pendingOutpointInternal(fmt.Sprintf("missing standard pending-outpoint claim for %x", entry.txid))
		}
		claim := snapshot.pending.claims[claimIndex]
		if !canonicalMempoolClaimBindsEntry(claim, entry) {
			return 0, 0, pendingOutpointInternal(fmt.Sprintf("pending-outpoint claim order mismatch for %x", entry.txid))
		}
		if err := validateCanonicalMempoolLiveClaimLocked(owner, claim); err != nil {
			return 0, 0, err
		}
		claimIndex++
		wantOutpoints += len(claim.inputs)
	}
	return claimIndex, wantOutpoints, nil
}

func canonicalMempoolClaimBindsEntry(claim pendingOutpointClaim, entry mempoolEntry) bool {
	return claim.domain == PendingOutpointStandardMempool && claim.token == entry.token
}

func validateCanonicalMempoolLiveRemainingClaimsLocked(owner *PendingOutpointOwner, claims []pendingOutpointClaim) (int, error) {
	wantOutpoints := 0
	for i := range claims {
		claim := claims[i]
		if claim.domain == PendingOutpointStandardMempool {
			return 0, pendingOutpointInternal(fmt.Sprintf("orphan standard pending-outpoint claim for %x", claim.txid))
		}
		if err := validateCanonicalMempoolLiveClaimLocked(owner, claim); err != nil {
			return 0, err
		}
		wantOutpoints += len(claim.inputs)
	}
	return wantOutpoints, nil
}

type canonicalPendingClaimFields struct {
	token      PendingOutpointToken
	domain     PendingOutpointDomain
	txid       [32]byte
	generation uint64
	finalized  bool
}

func canonicalPendingClaimFieldsOf(claim pendingOutpointClaim) canonicalPendingClaimFields {
	return canonicalPendingClaimFields{claim.token, claim.domain, claim.txid, claim.generation, claim.finalized}
}

func samePendingOutpointClaim(live *pendingOutpointClaim, snapshot pendingOutpointClaim) bool {
	return live != nil && canonicalPendingClaimFieldsOf(*live) == canonicalPendingClaimFieldsOf(snapshot) && slices.Equal(live.inputs, snapshot.inputs)
}

func buildCanonicalOwnerIndex(owner *PendingOutpointOwner, snapshot pendingOutpointSnapshot) pendingOutpointIndex {
	index := pendingOutpointIndex{owner: owner, byOutpoint: make(map[consensus.Outpoint]pendingOutpointRow, len(snapshot.claims)), byToken: make(map[PendingOutpointToken]*pendingOutpointClaim, len(snapshot.claims)), tokenHighWater: snapshot.tokenHighWater}
	for i := range snapshot.claims {
		claim, restored := snapshot.claims[i], snapshot.claims[i]
		restored.inputs = append([]consensus.Outpoint(nil), claim.inputs...)
		index.byToken[claim.token] = &restored
		for _, input := range claim.inputs {
			index.byOutpoint[input] = pendingOutpointRow{token: claim.token, txid: claim.txid}
		}
	}
	return index
}

func selectCanonicalMempoolEntries(
	entries []mempoolEntry,
	final canonicalMempoolFinalState,
	ctx canonicalMempoolPlanContext,
) ([]mempoolEntry, error) {
	rotation := newCanonicalMempoolRotationCache(ctx.policy.RotationProvider)
	policy := ctx.policy
	policy.RotationProvider = rotation
	retained := make([]mempoolEntry, 0, len(entries))
	for i := range entries {
		keep, err := canonicalMempoolEntryFinalValid(entries[i], final, ctx.chainID, policy, rotation, ctx.sigCache)
		if err != nil {
			return nil, err
		}
		if keep {
			retained = append(retained, cloneMempoolEntry(&entries[i]))
		}
	}
	return retained, nil
}

func canonicalMempoolEntryFinalValid(
	entry mempoolEntry,
	final canonicalMempoolFinalState,
	chainID [32]byte,
	policy MempoolConfig,
	rotation consensus.RotationProvider,
	sigCache *consensus.SigCache,
) (bool, error) {
	tx, err := parseMempoolEntryRaw(entry)
	if err != nil {
		return false, terminalCanonicalMempoolError(err)
	}
	checked, err := consensus.CheckParsedTransactionWithOwnedUtxoSetAndSuiteContext(
		entry.raw,
		tx,
		consensus.ParsedTxIDs{TxID: entry.txid, WTxID: entry.wtxid},
		copySelectedUtxoSet(final.utxos, entry.inputs),
		final.nextHeight,
		final.mtp,
		chainID,
		consensus.SuiteValidationContext{Rotation: rotation, Registry: policy.SuiteRegistry, SigCache: sigCache},
	)
	if err != nil {
		if canonicalMempoolValidationAbortsPlan(err) {
			return false, localCanonicalMempoolPlanError(err)
		}
		return false, nil
	}
	if err := validateCanonicalCheckedEntry(entry, checked); err != nil {
		return false, terminalCanonicalMempoolError(err)
	}
	return canonicalMempoolChainPolicyValid(tx, final.utxos, final.nextHeight, chainID, policy, rotation)
}

func canonicalMempoolValidationAbortsPlan(err error) bool {
	txErr, ok := err.(*consensus.TxError) //nolint:errorlint // Only a direct, nonnil TxError may exclude; wrapped errors abort the plan.
	return !ok || txErr == nil || canonicalMempoolCauseAbortsPlan(txErr.Cause())
}

func canonicalMempoolCauseAbortsPlan(cause consensus.TxErrorCause) bool {
	switch cause {
	case consensus.TxErrorCauseUnspecified,
		consensus.TxErrorCauseSimplicityDeploymentInactiveProvider,
		consensus.TxErrorCauseSimplicityDeploymentInactiveFrozen,
		consensus.TxErrorCauseSimplicityWitnessSuiteInvalid:
		return false
	default:
		return true
	}
}

func validateCanonicalCheckedEntry(entry mempoolEntry, checked *consensus.CheckedTransaction) error {
	if checked == nil || checked.Tx == nil {
		return errors.New("nil checked mempool transaction")
	}
	if !canonicalCheckedMempoolEntryMatches(entry, checked) {
		return fmt.Errorf("checked mempool record mismatch for txid %x", entry.txid)
	}
	return nil
}

func canonicalCheckedMempoolEntryMatches(entry mempoolEntry, checked *consensus.CheckedTransaction) bool {
	return checked.TxID == entry.txid && checked.WTxID == entry.wtxid && checked.Fee == entry.fee && checked.Weight == entry.weight && checked.SerializedSize == entry.size && bytes.Equal(checked.Bytes, entry.raw)
}

func canonicalMempoolChainPolicyValid(
	tx *consensus.Tx,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	nextHeight uint64,
	chainID [32]byte,
	policy MempoolConfig,
	rotation consensus.RotationProvider,
) (bool, error) {
	if tx == nil {
		return false, terminalCanonicalMempoolError(errors.New("nil canonical mempool transaction"))
	}
	if uint64(tx.Locktime) > nextHeight {
		return false, nil
	}
	if !policy.PolicyRejectSimplicityPreActivation {
		return true, nil
	}
	policyUtxos, err := policyInputSnapshot(tx, utxos)
	if err != nil {
		return false, terminalCanonicalMempoolError(err)
	}
	reject, _, err := rejectCoreSimplicityPreActivation(tx, policyUtxos, chainID, nextHeight, rotation)
	if err != nil {
		if reject {
			return false, localCanonicalMempoolPlanError(err)
		}
		return false, nil
	}
	return !reject, nil
}

func buildCanonicalMempoolPlan(
	entries []mempoolEntry,
	snapshot mempoolSnapshot,
	ctx canonicalMempoolPlanContext,
	decayRows int,
	snapshotUsedBytes int,
) (canonicalMempoolPlan, error) {
	txs, wtxids, maxSeq, usedBytes, err := buildMempoolRestoreMaps(entries, ctx.maxTxs, ctx.maxBytes)
	if err != nil {
		return canonicalMempoolPlan{}, terminalCanonicalMempoolError(err)
	}
	if snapshot.lastAdmissionSeq < maxSeq {
		return canonicalMempoolPlan{}, terminalCanonicalMempoolError(errors.New("retained admission sequence exceeds high-water"))
	}
	pending := canonicalMempoolPendingSnapshot(snapshot.pending, entries)
	ownerIndex := buildCanonicalOwnerIndex(ctx.owner, pending)
	if err := validateRestoredClaimBinding(txs, ownerIndex); err != nil {
		return canonicalMempoolPlan{}, terminalCanonicalMempoolError(err)
	}
	return canonicalMempoolPlan{
		owner:             ctx.owner,
		snapshot:          snapshot,
		snapshotUsedBytes: snapshotUsedBytes,
		txs:               txs,
		wtxids:            wtxids,
		usedBytes:         usedBytes,
		lastAdmissionSeq:  snapshot.lastAdmissionSeq,
		currentMinFeeRate: canonicalMempoolFeeFloor(snapshot.currentMinFeeRate, usedBytes, ctx.lowWater, decayRows),
		pending:           pending,
		ownerIndex:        ownerIndex,
	}, nil
}

func canonicalMempoolPendingSnapshot(old pendingOutpointSnapshot, entries []mempoolEntry) pendingOutpointSnapshot {
	retained := make(map[[32]byte]struct{}, len(entries))
	for i := range entries {
		retained[entries[i].txid] = struct{}{}
	}
	pending := old
	pending.claims = make([]pendingOutpointClaim, 0, len(old.claims))
	for i := range old.claims {
		claim := old.claims[i]
		if claim.domain == PendingOutpointStandardMempool {
			if _, ok := retained[claim.txid]; !ok {
				continue
			}
		}
		claim.inputs = append([]consensus.Outpoint(nil), claim.inputs...)
		pending.claims = append(pending.claims, claim)
	}
	return pending
}

// publishCanonicalMempoolPlan is the postcommit M1/O1 assignment. It runs ONLY
// after the canonical-index commit selected NEW and performs no allocation,
// clone, I/O, validation, callback or fallible step: every one of those already
// ran under the admission fence, which is still held, so the live image cannot
// have moved since the preflight proved it.
//
// Lock order is Mempool.mu then PendingOutpointOwner.mu, and both are released
// together. clearTransition is true for an ordinary COMMITTED outcome, which
// clears owner.inTransition in the SAME owner hold as the image; it is false for
// TERMINAL_PERSISTENCE(new), which publishes the identical image but keeps the
// owner transition latched with admission.
func (m *Mempool) publishCanonicalMempoolPlan(plan canonicalMempoolPlan, clearTransition bool) {
	m.mu.Lock()
	owner := plan.owner
	owner.mu.Lock()
	m.publishCanonicalMempoolPlanLocked(plan, owner)
	if clearTransition {
		owner.inTransition = false
	}
	owner.mu.Unlock()
	m.mu.Unlock()
}

func (m *Mempool) publishCanonicalMempoolPlanLocked(plan canonicalMempoolPlan, owner *PendingOutpointOwner) {
	owner.publishRestoreLocked(plan.pending, plan.ownerIndex)
	m.txs = plan.txs
	m.wtxids = plan.wtxids
	m.usedBytes = plan.usedBytes
	m.lastAdmissionSeq = plan.lastAdmissionSeq
	m.currentMinFeeRate = plan.currentMinFeeRate
}

type canonicalMempoolRotationCache struct {
	source consensus.RotationProvider
	create map[uint64]*consensus.NativeSuiteSet
	spend  map[uint64]*consensus.NativeSuiteSet
}

func newCanonicalMempoolRotationCache(source consensus.RotationProvider) consensus.RotationProvider {
	base := &canonicalMempoolRotationCache{
		source: source,
		create: make(map[uint64]*consensus.NativeSuiteSet),
		spend:  make(map[uint64]*consensus.NativeSuiteSet),
	}
	if provider, ok := source.(consensus.SimplicityDeploymentProvider); ok {
		return &canonicalMempoolDeploymentCache{canonicalMempoolRotationCache: base, source: provider}
	}
	return base
}

func (c *canonicalMempoolRotationCache) NativeCreateSuites(height uint64) *consensus.NativeSuiteSet {
	if suites, ok := c.create[height]; ok {
		return suites.Clone()
	}
	var suites *consensus.NativeSuiteSet
	if c.source == nil {
		suites = consensus.DefaultRotationProvider{}.NativeCreateSuites(height)
	} else {
		suites = c.source.NativeCreateSuites(height)
	}
	c.create[height] = suites.Clone()
	return suites.Clone()
}

func (c *canonicalMempoolRotationCache) NativeSpendSuites(height uint64) *consensus.NativeSuiteSet {
	if suites, ok := c.spend[height]; ok {
		return suites.Clone()
	}
	var suites *consensus.NativeSuiteSet
	if c.source == nil {
		suites = consensus.DefaultRotationProvider{}.NativeSpendSuites(height)
	} else {
		suites = c.source.NativeSpendSuites(height)
	}
	c.spend[height] = suites.Clone()
	return suites.Clone()
}

type canonicalMempoolDeploymentCache struct {
	*canonicalMempoolRotationCache
	source      consensus.SimplicityDeploymentProvider
	observed    bool
	descriptors []consensus.SimplicityDeploymentDescriptor
	anchor      [32]byte
	ok          bool
	err         error
}

func (c *canonicalMempoolDeploymentCache) PublishedSimplicityDeployments() ([]consensus.SimplicityDeploymentDescriptor, [32]byte, bool, error) {
	if !c.observed {
		c.descriptors, c.anchor, c.ok, c.err = c.source.PublishedSimplicityDeployments()
		c.descriptors = append([]consensus.SimplicityDeploymentDescriptor(nil), c.descriptors...)
		c.observed = true
	}
	return append([]consensus.SimplicityDeploymentDescriptor(nil), c.descriptors...), c.anchor, c.ok, c.err
}
