package node

import (
	"errors"
	"fmt"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// canonicalArtifactRead is the OBSERVATION class MP641 classifies a precommit
// recovery-proof read on. It is derived from what the reader observed, never
// from a platform error name or a wrapper this package happens to use.
type canonicalArtifactRead uint8

const (
	// canonicalArtifactValid: a complete value satisfying every applicable bound
	// was read and passed its identity/binding check.
	canonicalArtifactValid canonicalArtifactRead = iota
	// canonicalArtifactUnavailable: an open, metadata read, or byte read failed
	// BEFORE a complete bound-satisfying value or a definitive absence was
	// observed — including partial bytes followed by a non-EOF error, which are
	// discarded. LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read): OLD, open.
	canonicalArtifactUnavailable
	// canonicalArtifactInvalid: definitive required absence, a stat- or
	// read-PROVEN over-bound representation, a clean (possibly short) EOF that
	// establishes an invalid representation, or complete malformed / checksum /
	// hash / binding / state-reversal integrity evidence.
	// TERMINAL_STORE_INTEGRITY(canonical): OLD, latched.
	canonicalArtifactInvalid
)

// classifyCanonicalArtifactAcquisition maps ONE byte-acquisition outcome to its
// observation class. Acquisition means open, stat and read: an error here is
// unavailability unless the observation is itself positive evidence — the file
// definitively is not there, or its size is proven to exceed the applicable
// bound. Every post-acquisition failure is the caller's to classify, because by
// then a complete value was in hand and any failure is integrity evidence.
func classifyCanonicalArtifactAcquisition(err error) canonicalArtifactRead {
	switch {
	case err == nil:
		return canonicalArtifactValid
	case errors.Is(err, os.ErrNotExist), errors.Is(err, errStoreFileTooLarge):
		return canonicalArtifactInvalid
	default:
		return canonicalArtifactUnavailable
	}
}

// proveCanonicalArtifacts strict-reads ONE precommit suffix row in the MP641
// order — header, block, then the state-reversal artifact — and STOPS at the
// first non-valid observation without inspecting a later artifact to look for
// terminal evidence. It writes nothing and repairs nothing.
//
// Each rule it applies lives in exactly one place and is shared with the startup
// scan: validateBlockHeaderHash, storedBlockHeaderHash and unmarshalUndoEnvelope.
// Only the SEQUENCING differs, and it must: the startup scan visits every row's
// every artifact so a structural error behind a gap is not masked, while this
// one is required to stop at the first non-valid observation.
func (bs *BlockStore) proveCanonicalArtifacts(blockHash [32]byte) (canonicalArtifactRead, error) {
	if bs == nil {
		return canonicalArtifactInvalid, errors.New("nil blockstore")
	}
	headerBytes, err := bs.GetHeaderByHash(blockHash)
	if class := classifyCanonicalArtifactAcquisition(err); class != canonicalArtifactValid {
		return class, fmt.Errorf("canonical header artifact %x: %w", blockHash, err)
	}
	if err := validateBlockHeaderHash(headerBytes, blockHash); err != nil {
		return canonicalArtifactInvalid, fmt.Errorf("canonical header artifact %x: %w: %w", blockHash, errCanonicalArtifactUnbound, err)
	}

	blockBytes, err := bs.GetBlockByHash(blockHash)
	if class := classifyCanonicalArtifactAcquisition(err); class != canonicalArtifactValid {
		return class, fmt.Errorf("canonical block artifact %x: %w", blockHash, err)
	}
	observed, step, err := storedBlockHeaderHash(blockBytes)
	if err != nil || observed != blockHash {
		return canonicalArtifactInvalid, fmt.Errorf("canonical block artifact %x: %w: %s observed=%x: %v", blockHash, errCanonicalArtifactUnbound, step, observed, err) //nolint:errorlint // %v keeps local corruption out of p2p's consensus-error chain.
	}

	undoRaw, err := bs.getUndoRawPinned(blockHash)
	if class := classifyCanonicalArtifactAcquisition(err); class != canonicalArtifactValid {
		return class, fmt.Errorf("canonical undo artifact %x: %w", blockHash, err)
	}
	if _, err := unmarshalUndoEnvelope(blockHash, undoRaw); err != nil {
		return canonicalArtifactInvalid, fmt.Errorf("canonical undo artifact %x: %w", blockHash, err)
	}
	return canonicalArtifactValid, nil
}

func cloneChainState(src *ChainState) *ChainState {
	if src == nil {
		return nil
	}
	src.mu.RLock()
	defer src.mu.RUnlock()
	return &ChainState{
		Utxos:            copyUtxoSet(src.Utxos),
		Height:           src.Height,
		AlreadyGenerated: src.AlreadyGenerated,
		TipHash:          src.TipHash,
		HasTip:           src.HasTip,
		Rotation:         src.Rotation,
		Registry:         src.Registry,
	}
}

// errCanonicalIndexZeroCompletePrefix: the canonical index claims blocks but not
// even height 0 has a complete header/block/undo set. Discarding the rows would
// silently destroy the operator's whole chain, so this is fatal. Raised AFTER the
// scan's structural/IO/corruption errors (they keep precedence) and BEFORE
// any chainstate reset/replay/save and any service start.
// Cross-client literal — the EXACT message, never a prefix: the Rust mirror
// CANONICAL_INDEX_ZERO_COMPLETE_PREFIX_ERR is asserted by equality, so nothing
// may be appended to it here.
var errCanonicalIndexZeroCompletePrefix = errors.New("persisted canonical index has zero complete prefix")

// errCanonicalIndexIncompleteSuffix: the canonical index declares committed entries
// whose header/block/undo set is incomplete. Committed canonical rows are never
// truncated or repaired to hide that, so startup fails closed and the operator
// decides. Go-primary; the Rust mirror is RUB-897.
var errCanonicalIndexIncompleteSuffix = errors.New("persisted canonical index has an incomplete committed suffix")

// errCanonicalArtifactUnbound: a canonical artifact is present but does not belong to
// the row that indexes it — its identity does not re-derive, or its header links to a
// parent the index does not name. Go-only evidence (the Rust mirror is RUB-897),
// deliberately NOT ErrStoreIntegrity: that identity is the pinned cross-client
// ENVELOPE class, and undo keeps its own ErrUndoIntegrity. Plain read/IO failures stay
// unwrapped — they prove nothing about binding.
var errCanonicalArtifactUnbound = errors.New("canonical artifact is not bound to its indexed hash")

// requireCompleteCanonicalPrefix proves every entry the canonical index already
// declares committed has a complete header/block/undo set. It WRITES NOTHING:
// its domain is store.CanonicalIndexSnapshot(), so every state it can reach is
// index-declared-committed and dropping the suffix would discard committed
// chain to hide corruption. Precedence: structural/IO/corruption errors first, then
// the zero-complete-prefix literal, then the incomplete-suffix refusal. That is why
// the scan is FULL, not stop-at-the-first-gap: every artifact of every declared row
// is checked until the first structural error, so a structural error BEHIND a gap now
// outranks both fail-closed classes instead of being reported as a missing suffix —
// the scan this replaces broke at the first gap and never reached it.
//
// The scan proves both §6.4.1 restart rules over the same pass: every indexed
// row resolves to a header whose block_hash IS the indexed value (identity),
// and every later header's prev_block_hash equals the preceding INDEXED hash
// (linkage). Rust checks neither — its mirror still stops at the first
// incomplete row and still truncates (Go-primary, sibling RUB-897).
//
// Cost, accepted for strictness: every boot READS AND FULLY PARSES every
// canonical block (up to consensus.MAX_BLOCK_BYTES each), READS and JSON-decodes
// every canonical undo record (up to undoFileMaxBytes = 2 GB each) and SHA3s
// every canonical header, twice per block on a replay boot.
func requireCompleteCanonicalPrefix(store *BlockStore) error {
	if store == nil {
		return errors.New("nil blockstore")
	}
	canonical, err := store.CanonicalIndexSnapshot()
	if err != nil {
		return err
	}
	validCount, err := countCompleteCanonicalPrefix(store, canonical)
	if err != nil {
		return err
	}
	if validCount == uint64(len(canonical)) {
		return nil
	}
	if validCount == 0 {
		return errCanonicalIndexZeroCompletePrefix
	}
	return fmt.Errorf("%w: index declares %d entries; the complete header/block/undo prefix ends after %d; datadir reset and full resync required",
		errCanonicalIndexIncompleteSuffix, len(canonical), validCount)
}

// countCompleteCanonicalPrefix returns the index of the FIRST incomplete row
// (len(canonical) when every row is complete), after visiting every row: a structural
// error in a later row must not be masked by an earlier gap. It also enforces the
// §6.4.1 linkage MUST. The predecessor is the INDEXED hash of row i-1, not that row's
// header: the index is the identity, so an absent header at i-1 leaves its own row
// unlinked but still anchors row i. Row 0 has no predecessor — the genesis anchor is
// VerifyGenesisAnchor's job — and a row whose header is absent carries no prev to
// compare. Within a row the artifact scan runs FIRST, so an unbound artifact outranks
// that row's linkage violation.
func countCompleteCanonicalPrefix(store *BlockStore, canonical []string) (uint64, error) {
	validCount := uint64(len(canonical))
	var previous [32]byte
	for i, hashHex := range canonical {
		row, err := store.canonicalArtifactsComplete(hashHex)
		if err != nil {
			return 0, err
		}
		if i > 0 && row.hasHeader && row.prev != previous {
			return 0, fmt.Errorf("canonical header artifact %x links to %x, expected %x: %w",
				row.hash, row.prev, previous, errCanonicalArtifactUnbound)
		}
		if !row.complete {
			validCount = min(validCount, uint64(i))
		}
		previous = row.hash
	}
	return validCount, nil
}

// canonicalRowArtifacts is what one row's strict scan observed: whether all
// three artifacts are present and bound, the row's own indexed hash, and — only
// when the header is present and bound — the parent that header names.
type canonicalRowArtifacts struct {
	complete  bool
	hasHeader bool
	hash      [32]byte
	prev      [32]byte
}

// canonicalArtifactsComplete checks header, then block, then undo — ALL three, in
// that fixed statement order, because an absent artifact must not hide a corrupt one
// behind it in the same row. That order is a precedence choice, not a snapshot
// concern like InspectBlockPresence's reverse-order leaves: reconcile runs before any
// service or artifact writer exists, so nothing can write between two of these reads.
// It stamps every propagated structural error with the artifact kind and the indexed
// hash: the operator reads this as "chainstate reconcile failed: <err>", so a leaf
// reason like "header hash mismatch" that names no artifact and no row is
// unactionable. Only os.ErrNotExist is absence, and only absence feeds the
// complete-prefix count.
//
// All three leaves are STRICT: an artifact that is merely present is not a complete
// canonical artifact. They apply the same identity rules as InspectBlockPresence's
// leaves — validateBlockHeaderHash for the header, storedBlockHeaderHash for the
// block, GetUndo's hash binding for the undo — so startup and presence can never
// disagree on what "complete" means. A present but unbound artifact propagates as a
// structural error with FIRST precedence, exactly like the corrupt-undo path. The
// header and block leaves carry the errCanonicalArtifactUnbound identity alongside
// their own detail, so a caller can tell "present but not bound to this row" from a
// plain read failure without matching on text; the sentinel marks IDENTITY failures
// only, and a read-class refusal — absence, or the RUB-1057 size bound — propagates
// unwrapped and carries neither.
func (bs *BlockStore) canonicalArtifactsComplete(hashHex string) (canonicalRowArtifacts, error) {
	blockHash, err := parseHex32("canonical hash", hashHex)
	if err != nil {
		return canonicalRowArtifacts{}, err
	}
	row := canonicalRowArtifacts{complete: true, hash: blockHash}

	prev, err := bs.canonicalHeaderPrev(blockHash)
	switch {
	case errors.Is(err, os.ErrNotExist):
		row.complete = false
	case err != nil:
		return canonicalRowArtifacts{}, fmt.Errorf("canonical header artifact %x: %w", blockHash, err)
	default:
		row.hasHeader, row.prev = true, prev
	}

	switch err := bs.verifyCanonicalBlock(blockHash); {
	case errors.Is(err, os.ErrNotExist):
		row.complete = false
	case err != nil:
		return canonicalRowArtifacts{}, fmt.Errorf("canonical block artifact %x: %w", blockHash, err)
	}

	switch err := bs.verifyCanonicalUndo(blockHash); {
	case errors.Is(err, os.ErrNotExist):
		row.complete = false
	case err != nil:
		return canonicalRowArtifacts{}, fmt.Errorf("canonical undo artifact %x: %w", blockHash, err)
	}
	return row, nil
}

// canonicalHeaderPrev validates the row's header and returns the parent it
// names, so the linkage rule is proved from the bytes this read already holds
// instead of a second read of the same file.
func (bs *BlockStore) canonicalHeaderPrev(blockHash [32]byte) ([32]byte, error) {
	var prev [32]byte
	headerBytes, err := bs.GetHeaderByHash(blockHash)
	if err != nil {
		return prev, err
	}
	if err := validateBlockHeaderHash(headerBytes, blockHash); err != nil {
		return prev, fmt.Errorf("%w: %w", errCanonicalArtifactUnbound, err)
	}
	// Fixed-length and already hashed above, so this parse has no failure the
	// identity check could have missed; it is still propagated, never assumed.
	header, err := consensus.ParseBlockHeaderBytes(headerBytes)
	if err != nil {
		return prev, err
	}
	return header.PrevBlockHash, nil
}

// verifyCanonicalBlock: the stored block bytes must parse and re-derive the
// indexed hash.
func (bs *BlockStore) verifyCanonicalBlock(blockHash [32]byte) error {
	blockBytes, err := bs.GetBlockByHash(blockHash)
	if err != nil {
		return err
	}
	observed, step, err := storedBlockHeaderHash(blockBytes)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", errCanonicalArtifactUnbound, step, err)
	}
	if observed != blockHash {
		return fmt.Errorf("%w: hashes to %x", errCanonicalArtifactUnbound, observed)
	}
	return nil
}

// verifyCanonicalUndo: the stored undo record must decode and carry the indexed
// hash (RUB-1132).
func (bs *BlockStore) verifyCanonicalUndo(blockHash [32]byte) error {
	_, err := bs.GetUndo(blockHash)
	return err
}

// ReconcileChainStateWithBlockStore replays any canonical blocks that are present
// in the blockstore but missing from the persisted chainstate snapshot. When the
// loaded snapshot disagrees with the canonical chain at its claimed height, the
// canonical blockstore view wins and replay restarts from an empty state.
//
// It fails closed on canonical corruption before anything else: an incomplete
// committed canonical prefix returns an error rather than being truncated or
// repaired, so this function performs no durable write of its own on any path.
func ReconcileChainStateWithBlockStore(state *ChainState, store *BlockStore, cfg SyncConfig) (bool, error) {
	if state == nil {
		return false, errors.New("nil chainstate")
	}
	if store == nil {
		return false, errors.New("nil blockstore")
	}
	if err := requireCompleteCanonicalPrefix(store); err != nil {
		return false, err
	}
	tipHeight, _, ok, err := store.Tip()
	if err != nil {
		return false, err
	}
	if !ok {
		return reconcileEmptyBlockStore(state), nil
	}

	replayFrom, changed, replayNeeded, err := reconcileReplayStart(state, store, tipHeight)
	if err != nil || !replayNeeded {
		return changed, err
	}
	return replayCanonicalBlocks(state, store, cfg, replayFrom, tipHeight, changed)
}

func reconcileEmptyBlockStore(state *ChainState) bool {
	view := state.view()
	dirty := view.hasTip || view.utxoCount != 0 || !view.alreadyGenerated.IsZero() || view.height != 0 || view.tipHash != ([32]byte{})
	if dirty {
		state.replaceFrom(NewChainState())
		return true
	}
	return false
}

func reconcileReplayStart(state *ChainState, store *BlockStore, tipHeight uint64) (uint64, bool, bool, error) {
	view := state.view()
	if !view.hasTip || view.height > tipHeight {
		state.replaceFrom(NewChainState())
		return 0, true, true, nil
	}
	canonicalHash, hasHeight, err := store.CanonicalHash(view.height)
	if err != nil {
		return 0, false, false, err
	}
	if !hasHeight || canonicalHash != view.tipHash {
		state.replaceFrom(NewChainState())
		return 0, true, true, nil
	}
	if view.height == tipHeight {
		return 0, false, false, nil
	}
	return view.height + 1, false, true, nil
}

func replayCanonicalBlocks(state *ChainState, store *BlockStore, cfg SyncConfig, replayFrom uint64, tipHeight uint64, changed bool) (bool, error) {
	for height := replayFrom; height <= tipHeight; height++ {
		blockHash, ok, err := store.CanonicalHash(height)
		if err != nil {
			return false, err
		}
		if !ok {
			// Suffix `at height N (tip_height=N')` is part of the
			// cross-client error literal — Rust mirror in
			// `clients/rust/crates/rubin-node/src/chainstate_recovery.rs`
			// emits the bit-identical wording. Operators searching
			// logs for canonical-index corruption get the exact
			// height instead of having to reconstruct the loop state.
			return false, fmt.Errorf("missing canonical block hash during chainstate replay at height %d (tip_height=%d)", height, tipHeight)
		}
		expectedTarget, err := replayExpectedTarget(store, cfg, height, tipHeight)
		if err != nil {
			return false, err
		}
		blockBytes, prevTimestamps, err := replayBlockInputs(store, blockHash, height)
		if err != nil {
			return false, err
		}
		if _, err := state.ConnectBlockWithSuiteContext(
			blockBytes,
			expectedTarget,
			prevTimestamps,
			cfg.ChainID,
			cfg.RotationProvider,
			cfg.SuiteRegistry,
		); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

// replayExpectedTarget resolves the expected target per replayed block: the
// selected parent is the canonical index entry at height-1. Only the
// free-function form of the primitive is callable here — this runs before the
// sync engine exists.
//
// Failure contract (RUB-655 done_when): the error returns unchanged through
// replayCanonicalBlocks and ReconcileChainStateWithBlockStore to
// cmd/rubin-node/main.go, which exits 2 BEFORE chainState.Save, before
// newSyncEngineFn, and before the mempool, peer manager and every service
// start. This helper writes nothing, and neither does any other step of the
// reconcile, so a failed recovery leaves the datadir byte-identical. The
// in-memory reset reconcileReplayStart may have done is not durable —
// chainState.Save is never reached.
func replayExpectedTarget(store *BlockStore, cfg SyncConfig, height uint64, tipHeight uint64) (*[32]byte, error) {
	if height == 0 {
		return cfg.ExpectedTarget, nil
	}
	if !StockDevnetTargetSchedule(cfg.Network, cfg.ChainID) {
		return cfg.ExpectedTarget, nil
	}
	parentHash, ok, err := store.CanonicalHash(height - 1)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("missing canonical parent hash for target context during chainstate replay at height %d (tip_height=%d)", height, tipHeight)
	}
	target, err := deriveExpectedTargetFn(store, parentHash, height)
	if err != nil {
		return nil, err
	}
	return &target, nil
}

func replayBlockInputs(store *BlockStore, blockHash [32]byte, height uint64) ([]byte, []uint64, error) {
	blockBytes, err := store.GetBlockByHash(blockHash)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyReplayBlockHash(blockBytes, blockHash, height); err != nil {
		return nil, nil, err
	}
	prevTimestamps, err := prevTimestampsFromStore(store, height)
	if err != nil {
		return nil, nil, err
	}
	return blockBytes, prevTimestamps, nil
}

func verifyReplayBlockHash(blockBytes []byte, blockHash [32]byte, height uint64) error {
	// Defense-in-depth: re-hash the loaded block's header before ConnectBlock.
	observedHash, step, err := storedBlockHeaderHash(blockBytes)
	if err != nil {
		return fmt.Errorf("%s during chainstate replay at height %d: %w", step, height, err)
	}
	if observedHash != blockHash {
		return fmt.Errorf(
			"canonical artifact corruption during chainstate replay at height %d: expected %x, on-disk header hashes to %x",
			height, blockHash, observedHash,
		)
	}
	return nil
}
