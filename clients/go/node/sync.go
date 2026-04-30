package node

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const defaultIBDLagSeconds = 24 * 60 * 60

const defaultPVShadowMaxSamples = 3

var ErrParentNotFound = errors.New("parent block not found")

type SyncConfig struct {
	ExpectedTarget   *[32]byte
	ChainStatePath   string
	HeaderBatchLimit uint64
	IBDLagSeconds    uint64
	ChainID          [32]byte
	Network          string
	CoreExtProfiles  consensus.CoreExtProfileProvider
	RotationProvider consensus.RotationProvider
	SuiteRegistry    *consensus.SuiteRegistry

	ParallelValidationMode string // off|shadow|on
	PVShadowMaxSamples     uint64 // bounded mismatch diagnostics; 0 => default
}

type parallelValidationMode uint8

const (
	pvModeOff parallelValidationMode = iota
	pvModeShadow
	pvModeOn
)

func (m parallelValidationMode) String() string {
	switch m {
	case pvModeShadow:
		return "shadow"
	case pvModeOn:
		return "on"
	default:
		return "off"
	}
}

func parseParallelValidationMode(s string) (parallelValidationMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off":
		return pvModeOff, nil
	case "shadow":
		return pvModeShadow, nil
	case "on":
		return pvModeOn, nil
	default:
		return pvModeOff, fmt.Errorf("invalid parallel_validation_mode: %q (want off|shadow|on)", s)
	}
}

type HeaderRequest struct {
	FromHash [32]byte
	HasFrom  bool
	Limit    uint64
}

// BlockApplyCounts is the bounded canonical block-apply outcome metric state.
type BlockApplyCounts struct {
	Accepted uint64
	Rejected uint64
}

type blockApplyMetricOutcome uint8

const (
	blockApplyMetricNone blockApplyMetricOutcome = iota
	blockApplyMetricAccepted
	blockApplyMetricRejected
)

type SyncEngine struct {
	chainState      *ChainState
	blockStore      *BlockStore
	mempool         *Mempool
	cfg             SyncConfig
	stderr          io.Writer
	mu              sync.RWMutex
	tipTimestamp    uint64
	bestKnownHeight uint64
	lastReorgDepth  uint64
	reorgCount      uint64
	blockApply      BlockApplyCounts

	pvMode             parallelValidationMode
	pvShadowMax        uint64
	pvShadowMismatches uint64
	pvShadowSamples    []string
	pvTelemetry        *PVTelemetry
}

func DefaultSyncConfig(expectedTarget *[32]byte, chainID [32]byte, chainStatePath string) SyncConfig {
	return SyncConfig{
		HeaderBatchLimit:       512,
		IBDLagSeconds:          defaultIBDLagSeconds,
		ExpectedTarget:         expectedTarget,
		ChainID:                chainID,
		ChainStatePath:         chainStatePath,
		Network:                "devnet",
		ParallelValidationMode: "off",
		PVShadowMaxSamples:     defaultPVShadowMaxSamples,
	}
}

func NewSyncEngine(chainState *ChainState, blockStore *BlockStore, cfg SyncConfig) (*SyncEngine, error) {
	if chainState == nil {
		return nil, errors.New("nil chainstate")
	}
	cfg = normalizeSyncConfig(cfg)
	if err := validateMainnetGenesisGuard(cfg); err != nil {
		return nil, err
	}
	mode, err := parseParallelValidationMode(cfg.ParallelValidationMode)
	if err != nil {
		return nil, err
	}
	engine := &SyncEngine{
		chainState:  chainState,
		blockStore:  blockStore,
		cfg:         cfg,
		stderr:      io.Discard,
		pvMode:      mode,
		pvShadowMax: cfg.PVShadowMaxSamples,
		pvTelemetry: NewPVTelemetry(mode.String()),
	}
	if engine.pvShadowMax == 0 {
		engine.pvShadowMax = defaultPVShadowMaxSamples
	}
	return engine, nil
}

func normalizeSyncConfig(cfg SyncConfig) SyncConfig {
	if cfg.HeaderBatchLimit == 0 {
		cfg.HeaderBatchLimit = 512
	}
	if cfg.IBDLagSeconds == 0 {
		cfg.IBDLagSeconds = defaultIBDLagSeconds
	}
	cfg.Network = normalizedNetworkName(cfg.Network)
	if strings.TrimSpace(cfg.ParallelValidationMode) == "" {
		cfg.ParallelValidationMode = "off"
	}
	return cfg
}

func (s *SyncEngine) recordPVShadowMismatch(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pvShadowMismatches++
	if s.pvShadowMax == 0 || uint64(len(s.pvShadowSamples)) >= s.pvShadowMax {
		return
	}
	s.pvShadowSamples = append(s.pvShadowSamples, line)
}

// PVTelemetry returns the PV telemetry instance for metrics export.
func (s *SyncEngine) PVTelemetry() *PVTelemetry {
	if s == nil {
		return nil
	}
	return s.pvTelemetry
}

func (s *SyncEngine) PVShadowStats() (mismatches uint64, samples []string) {
	if s == nil {
		return 0, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]string(nil), s.pvShadowSamples...)
	return s.pvShadowMismatches, out
}

func normalizedNetworkName(network string) string {
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		return "devnet"
	}
	return network
}

// ValidateMainnetGenesisGuard exposes the mainnet genesis / target
// guard so cmd/rubin-node/main.go can run it BEFORE reconcile (mirror
// of Rust main.rs validate_mainnet_genesis_guard call). Devnet / test
// networks no-op. Defense-in-depth: NewSyncEngine still runs the same
// guard internally for callers that construct an engine directly
// (tests, embedded uses).
func ValidateMainnetGenesisGuard(cfg SyncConfig) error {
	return validateMainnetGenesisGuard(cfg)
}

func validateMainnetGenesisGuard(cfg SyncConfig) error {
	if normalizedNetworkName(cfg.Network) != "mainnet" {
		return nil
	}
	if cfg.ExpectedTarget == nil {
		return errors.New("mainnet requires explicit expected_target")
	}
	if *cfg.ExpectedTarget == consensus.POW_LIMIT {
		return errors.New("mainnet expected_target must not equal devnet POW_LIMIT (all-ff)")
	}
	return nil
}

// ValidateDevnetGenesisIdentity reports whether a parsed genesis-pack
// identity (chain_id, genesis_hash) matches the published canonical
// devnet pack. It is intended to run at startup AFTER the genesis file
// is parsed and BEFORE any filesystem mutation (datadir create,
// chainstate load, blockstore open, reconcile, save, sync engine
// construction). On mismatch returns *consensus.TxError with
// BLOCK_ERR_LINKAGE_INVALID and the same Msg strings as the runtime
// height-0 guards in applyCanonicalParsedBlock so log / ban-score /
// debugging correlate boot-time and runtime rejects under the same
// class. Callers MUST only invoke this for cfg.Network == "devnet";
// for other networks the canonical pack identity is undefined here.
//
// This helper is intentionally NOT integrated into NewSyncEngine:
// SyncConfig does not carry the parsed genesis_hash, so a guard there
// would observe only ChainID and could not actually detect a mismatched
// hash in an embedded caller. The boot-time call site in
// cmd/rubin-node/main.go is the only place that has both inputs.
func ValidateDevnetGenesisIdentity(chainID, genesisHash [32]byte) error {
	if chainID != devnetGenesisChainID {
		return &consensus.TxError{
			Code: consensus.BLOCK_ERR_LINKAGE_INVALID,
			Msg:  "genesis chain_id mismatch",
		}
	}
	if genesisHash != devnetGenesisBlockHash {
		return &consensus.TxError{
			Code: consensus.BLOCK_ERR_LINKAGE_INVALID,
			Msg:  "genesis_hash mismatch",
		}
	}
	return nil
}

// BootstrapCanonicalGenesisIfEmpty applies the published canonical genesis
// block to an empty chainstate when the configured network has one, so the
// chain always starts from the published bytes rather than from a miner-
// synthesized height-0 block. The height-0 genesis-identity guard in
// applyCanonicalParsedBlock rejects any block at height 0 whose hash
// differs from devnetGenesisBlockHash under a devnet ChainID; without
// this bootstrap the miner-driven empty-chain path would always produce
// a non-canonical height-0 block (current timestamp / freshly mined
// nonce) and fail under that guard.
//
// Idempotent. No-op when:
//   - the chainstate already has a tip (HasTip is true), or
//   - the configured SyncConfig.ChainID does not identify a network with
//     a published canonical genesis (currently only devnetGenesisChainID
//     is recognized; the all-zero ChainID used by ephemeral unit tests
//     is skipped on purpose to preserve those tests' synthetic genesis
//     fixtures, mirroring the chain_id guard's zero-ChainID skip clause
//     in applyCanonicalParsedBlock).
//
// On success, the chainstate's tip is the published devnet genesis at
// height 0 and the canonical genesis bytes are persisted to the block
// store via the normal ApplyBlock path. Returns the ApplyBlock error
// directly on failure; callers wrap if they want a function-prefix.
//
// Defensive nil-receiver guard mirrors the pattern used by other exported
// SyncEngine methods (HeaderSyncRequest, RecordBestKnownHeight, ...). Other
// exported methods are nil-safe and there are existing tests that exercise
// the nil-receiver path; this method joins that contract for consistency.
func (s *SyncEngine) BootstrapCanonicalGenesisIfEmpty() error {
	if s == nil || s.chainState == nil {
		return errors.New("sync engine is not initialized")
	}
	if s.chainState.view().hasTip || s.cfg.ChainID != devnetGenesisChainID {
		return nil
	}
	_, applyErr := s.ApplyBlock(devnetGenesisBlockBytes, nil)
	return raceTolerantBootstrapResult(applyErr, s.chainState.view().hasTip)
}

// raceTolerantBootstrapResult absorbs the TOCTOU window between the hasTip
// check at the start of BootstrapCanonicalGenesisIfEmpty and the ApplyBlock
// call below it. If another goroutine installs a tip in that window — for
// example a P2P inbound block path racing a /mine_next request that both
// observe an empty chain — our ApplyBlock will fail (typically with a
// linkage error because nextBlockContextFromFields now sees a non-zero
// next height) even though the chain is no longer empty. In that case the
// failure is benign: the chain has the tip we wanted to install, and the
// caller (e.g. Miner.MineOne) can proceed with normal post-genesis mining.
//
// Returns:
//   - nil when ApplyBlock succeeded (applyErr == nil), regardless of hasTip.
//   - nil when ApplyBlock failed AND hasTip is true at recheck (race-recovery).
//   - applyErr when ApplyBlock failed AND hasTip is still false (real failure
//     unrelated to concurrent tip installation, e.g. blockstore I/O error).
func raceTolerantBootstrapResult(applyErr error, hasTip bool) error {
	if applyErr != nil && hasTip {
		return nil
	}
	return applyErr
}

func (s *SyncEngine) ApplyBlock(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	return s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps)
}

func (s *SyncEngine) SetMempool(mempool *Mempool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if mempool != nil {
		mempool.mu.Lock()
		if mempool.policy.CoreExtProfiles == nil {
			mempool.policy.CoreExtProfiles = s.cfg.CoreExtProfiles
		}
		if mempool.policy.RotationProvider == nil {
			mempool.policy.RotationProvider = s.cfg.RotationProvider
		}
		if mempool.policy.SuiteRegistry == nil {
			mempool.policy.SuiteRegistry = s.cfg.SuiteRegistry
		}
		mempool.mu.Unlock()
	}
	s.mempool = mempool
}

// SetStderr sets the writer for non-fatal error diagnostics (e.g. mempool
// post-acceptance failures). Defaults to io.Discard when not explicitly set.
func (s *SyncEngine) SetStderr(w io.Writer) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if w == nil {
		w = io.Discard
	}
	s.stderr = w
}

func (s *SyncEngine) HeaderSyncRequest() HeaderRequest {
	if s == nil || s.chainState == nil {
		return HeaderRequest{}
	}
	view := s.chainState.view()
	if !view.hasTip {
		return HeaderRequest{Limit: s.cfg.HeaderBatchLimit}
	}
	return HeaderRequest{
		FromHash: view.tipHash,
		HasFrom:  true,
		Limit:    s.cfg.HeaderBatchLimit,
	}
}

func (s *SyncEngine) RecordBestKnownHeight(height uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if height > s.bestKnownHeight {
		s.bestKnownHeight = height
	}
}

func (s *SyncEngine) BestKnownHeight() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bestKnownHeight
}

func (s *SyncEngine) LastReorgDepth() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastReorgDepth
}

func (s *SyncEngine) ReorgCount() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reorgCount
}

func (s *SyncEngine) BlockApplyCounts() BlockApplyCounts {
	if s == nil {
		return BlockApplyCounts{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blockApply
}

// isInIBDUnchecked returns true if the engine appears to be in IBD based on
// the recorded tip timestamp and the configured IBD lag threshold. Unlike
// IsInIBD, it does not require a nowUnix argument — it uses time.Now().
//
// This is an internal helper for the block connection path where we need to
// choose between sequential and parallel signature verification.
func (s *SyncEngine) isInIBDUnchecked() bool {
	if s == nil || s.chainState == nil {
		return true
	}
	if !s.chainState.view().hasTip {
		return true
	}
	s.mu.RLock()
	tipTimestamp := s.tipTimestamp
	ibdLag := s.cfg.IBDLagSeconds
	s.mu.RUnlock()
	if tipTimestamp == 0 {
		return true
	}
	nowUnixSigned := time.Now().Unix()
	if nowUnixSigned < 0 {
		return true
	}
	nowUnix := uint64(nowUnixSigned) // #nosec G115 -- guarded against negative Unix timestamps above.
	if nowUnix < tipTimestamp {
		return true
	}
	return nowUnix-tipTimestamp > ibdLag
}

func (s *SyncEngine) IsInIBD(nowUnix uint64) bool {
	if s == nil || s.chainState == nil {
		return true
	}
	if !s.chainState.view().hasTip {
		return true
	}
	s.mu.RLock()
	tipTimestamp := s.tipTimestamp
	ibdLag := s.cfg.IBDLagSeconds
	s.mu.RUnlock()
	if nowUnix < tipTimestamp {
		return true
	}
	return nowUnix-tipTimestamp > ibdLag
}

type syncRollbackState struct {
	chainState      *ChainState
	canonicalIndex  []string
	mempool         mempoolSnapshot
	tipTimestamp    uint64
	bestKnownHeight uint64
	lastReorgDepth  uint64
	reorgCount      uint64
}

func (s *SyncEngine) captureRollbackState() (syncRollbackState, error) {
	snapshot := cloneChainState(s.chainState)
	if snapshot == nil {
		return syncRollbackState{}, errors.New("nil chainstate")
	}
	var err error
	var canonicalIndex []string
	if s.blockStore != nil {
		canonicalIndex, err = s.blockStore.CanonicalIndexSnapshot()
		if err != nil {
			return syncRollbackState{}, err
		}
	}
	mempoolState, err := snapshotMempool(s.mempool)
	if err != nil {
		return syncRollbackState{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return syncRollbackState{
		chainState:      snapshot,
		canonicalIndex:  canonicalIndex,
		mempool:         mempoolState,
		tipTimestamp:    s.tipTimestamp,
		bestKnownHeight: s.bestKnownHeight,
		lastReorgDepth:  s.lastReorgDepth,
		reorgCount:      s.reorgCount,
	}, nil
}

func (s *SyncEngine) rollbackApplyBlock(cause error, state syncRollbackState) error {
	restoreErr := func() error {
		if s.chainState == nil {
			return errors.New("nil chainstate destination")
		}
		recovered := cloneChainState(state.chainState)
		if recovered == nil {
			return errors.New("nil rollback chainstate")
		}
		s.chainState.replaceFrom(recovered)
		return nil
	}()
	if s.blockStore != nil {
		if bsErr := s.blockStore.RestoreCanonicalIndex(state.canonicalIndex); bsErr != nil && restoreErr == nil {
			restoreErr = bsErr
		}
	}
	if mpErr := restoreMempoolSnapshot(s.mempool, state.mempool); mpErr != nil && restoreErr == nil {
		restoreErr = mpErr
	}
	if restoreErr == nil && s.cfg.ChainStatePath != "" {
		if saveErr := s.chainState.Save(s.cfg.ChainStatePath); saveErr != nil {
			restoreErr = saveErr
		}
	}
	s.mu.Lock()
	s.tipTimestamp = state.tipTimestamp
	s.bestKnownHeight = state.bestKnownHeight
	s.lastReorgDepth = state.lastReorgDepth
	s.reorgCount = state.reorgCount
	s.mu.Unlock()
	if restoreErr != nil {
		return fmt.Errorf("%w (rollback failed: %v)", cause, restoreErr)
	}
	return cause
}

func (s *SyncEngine) applyCanonicalParsedBlock(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
) (*ChainStateConnectSummary, error) {
	summary, outcome, err := s.applyCanonicalParsedBlockTracked(pb, blockBytes, prevTimestamps)
	s.noteBlockApplyOutcome(outcome)
	return summary, err
}

func (s *SyncEngine) applyCanonicalParsedBlockTracked(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
) (*ChainStateConnectSummary, blockApplyMetricOutcome, error) {
	if s == nil || s.chainState == nil {
		return nil, blockApplyMetricNone, errors.New("sync engine is not initialized")
	}
	if pb == nil {
		return nil, blockApplyMetricNone, errors.New("nil parsed block")
	}
	blockHeight, _, err := nextBlockContext(s.chainState)
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	var zeroID [32]byte
	if blockHeight == 0 && s.cfg.ChainID != zeroID && s.cfg.ChainID != devnetGenesisChainID {
		// Both genesis-identity rejects on the height-0 admission path are
		// consensus-invalid block classes from a peer's perspective: a
		// peer-relayed wrong-identity block must escalate ban score in the
		// P2P handler (clients/go/node/p2p/handlers_block.go gates ban
		// escalation via `var txErr *consensus.TxError; errors.As(err, &txErr)`).
		// Wrap with a TxError so peer attribution is class-closed for both
		// genesis-identity classes (chain_id mismatch and genesis_hash
		// mismatch below).
		return nil, blockApplyMetricRejected, &consensus.TxError{
			Code: consensus.BLOCK_ERR_LINKAGE_INVALID,
			Msg:  "genesis chain_id mismatch",
		}
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	// Defense in depth on top of the chain_id guard above: at height 0 on a
	// devnet runtime, the block must be the published devnet genesis. Without
	// this, a malformed or relayed block whose ChainID matches devnet but
	// whose contents differ (different timestamp, txs, merkle root, etc.)
	// would otherwise be admitted as the local genesis and lock the chain
	// onto a wrong identity. Test mode (zero ChainID) skip-checks to mirror
	// the chain_id guard pattern above; non-devnet ChainID is already
	// rejected by that guard. TxError wrap matches the chain_id guard so
	// the P2P inbound block path can hard-ban peers relaying either flavor
	// of wrong-genesis block via the standard
	// `var txErr *consensus.TxError; errors.As(err, &txErr)` pattern in
	// p2p/handlers_block.go.
	if blockHeight == 0 && s.cfg.ChainID == devnetGenesisChainID && blockHash != devnetGenesisBlockHash {
		return nil, blockApplyMetricRejected, &consensus.TxError{
			Code: consensus.BLOCK_ERR_LINKAGE_INVALID,
			Msg:  "genesis_hash mismatch",
		}
	}

	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	prevState := cloneChainState(rollbackState.chainState)

	var summary *ChainStateConnectSummary
	// Q-PV-12 shadow rollout: sequential truth path. Parallel validation runs on a
	// cloned state and is used for bounded diagnostics only (never changes verdict).
	pvActive := (s.pvMode == pvModeShadow || s.pvMode == pvModeOn) && s.isInIBDUnchecked()
	summary, err = s.chainState.ConnectBlockWithCoreExtProfilesAndSuiteContext(
		blockBytes,
		s.cfg.ExpectedTarget,
		prevTimestamps,
		s.cfg.ChainID,
		s.cfg.CoreExtProfiles,
		s.cfg.RotationProvider,
		s.cfg.SuiteRegistry,
	)
	if err != nil {
		if pvActive {
			s.pvTelemetry.RecordBlockValidated()
			validateStart := time.Now()
			shadowState := cloneChainState(prevState)
			_, parErr := shadowState.ConnectBlockParallelSigsWithSuiteContext(
				blockBytes,
				s.cfg.ExpectedTarget,
				prevTimestamps,
				s.cfg.ChainID,
				s.cfg.CoreExtProfiles,
				s.cfg.RotationProvider,
				s.cfg.SuiteRegistry,
				0,
			)
			s.pvTelemetry.RecordValidateLatency(time.Since(validateStart))
			seqCode, parCode := txErrCode(err), txErrCode(parErr)
			if seqCode != parCode {
				s.recordPVShadowMismatch(fmt.Sprintf("pv_shadow mismatch(height=%d): seq_err=%s par_err=%s", blockHeight, seqCode, parCode))
				_, _ = fmt.Fprintf(s.stderr, "pv_shadow: mismatch height=%d seq_err=%s par_err=%s\n", blockHeight, seqCode, parCode)
				if parErr == nil {
					// seq reject vs par accept = verdict divergence
					s.pvTelemetry.RecordMismatchVerdict()
				} else {
					s.pvTelemetry.RecordMismatchError()
				}
			}
		} else {
			s.pvTelemetry.RecordBlockSkipped()
		}
		return nil, blockApplyMetricRejected, err
	}
	if pvActive {
		s.pvTelemetry.RecordBlockValidated()
		validateStart := time.Now()
		shadowState := cloneChainState(prevState)
		parSummary, parErr := shadowState.ConnectBlockParallelSigsWithSuiteContext(
			blockBytes,
			s.cfg.ExpectedTarget,
			prevTimestamps,
			s.cfg.ChainID,
			s.cfg.CoreExtProfiles,
			s.cfg.RotationProvider,
			s.cfg.SuiteRegistry,
			0,
		)
		s.pvTelemetry.RecordValidateLatency(time.Since(validateStart))
		if parSummary != nil {
			s.pvTelemetry.RecordWorkerTasks(parSummary.SigTaskCount)
			for i := uint64(0); i < parSummary.WorkerPanics; i++ {
				s.pvTelemetry.RecordWorkerPanic()
			}
		}
		if parErr != nil {
			s.recordPVShadowMismatch(fmt.Sprintf("pv_shadow mismatch(height=%d): seq_ok par_err=%s", blockHeight, txErrCode(parErr)))
			_, _ = fmt.Fprintf(s.stderr, "pv_shadow: mismatch height=%d seq_ok par_err=%s\n", blockHeight, txErrCode(parErr))
			s.pvTelemetry.RecordMismatchVerdict()
		} else if parSummary.PostStateDigest != summary.PostStateDigest {
			s.recordPVShadowMismatch(fmt.Sprintf("pv_shadow mismatch(height=%d): post_state_digest", blockHeight))
			_, _ = fmt.Fprintf(s.stderr, "pv_shadow: mismatch height=%d post_state_digest\n", blockHeight)
			s.pvTelemetry.RecordMismatchState()
		}
	} else {
		s.pvTelemetry.RecordBlockSkipped()
	}
	commitStart := time.Now()
	if err := s.persistAppliedBlock(summary, blockHash, pb, blockBytes, prevState); err != nil {
		return nil, blockApplyMetricNone, s.rollbackApplyBlock(err, rollbackState)
	}
	s.pvTelemetry.RecordCommitLatency(time.Since(commitStart))

	s.recordAppliedBlock(summary.BlockHeight, pb.Header.Timestamp)
	if s.mempool != nil {
		if err := s.mempool.applyConnectedBlockParsed(pb); err != nil {
			_, _ = fmt.Fprintf(s.stderr, "mempool: apply-connected-block: %v\n", err)
		}
	}
	return summary, blockApplyMetricAccepted, nil
}

// txErrCode extracts the consensus.TxError code string from err for
// telemetry and event labeling. It uses errors.As so that a wrapped
// *consensus.TxError (e.g. produced by fmt.Errorf("...: %w", inner)) is
// still classified correctly instead of falling through to "ERR". A nil
// error reports "OK"; any non-TxError reports "ERR".
func txErrCode(err error) string {
	if err == nil {
		return "OK"
	}
	var te *consensus.TxError
	if errors.As(err, &te) {
		return string(te.Code)
	}
	return "ERR"
}

func (s *SyncEngine) persistAppliedBlock(summary *ChainStateConnectSummary, blockHash [32]byte, pb *consensus.ParsedBlock, blockBytes []byte, prevState *ChainState) error {
	if s.blockStore != nil {
		undo, err := buildBlockUndo(prevState, pb, summary.BlockHeight)
		if err != nil {
			return err
		}
		if err := s.blockStore.CommitCanonicalBlock(summary.BlockHeight, blockHash, pb.HeaderBytes, blockBytes, undo); err != nil {
			return err
		}
	}
	if s.cfg.ChainStatePath != "" && (s.blockStore == nil || shouldPersistChainStateSnapshot(s.chainState, summary)) {
		if err := s.chainState.Save(s.cfg.ChainStatePath); err != nil {
			return err
		}
	}
	return nil
}

func (s *SyncEngine) recordAppliedBlock(height uint64, timestamp uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tipTimestamp = timestamp
	if height > s.bestKnownHeight {
		s.bestKnownHeight = height
	}
	s.lastReorgDepth = 0
}

func (s *SyncEngine) noteBlockApplyAccepted() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockApply.Accepted++
}

func (s *SyncEngine) noteBlockApplyAcceptedN(count uint64) {
	if s == nil || count == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockApply.Accepted += count
}

func (s *SyncEngine) noteBlockApplyRejected() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockApply.Rejected++
}

func (s *SyncEngine) noteBlockApplyOutcome(outcome blockApplyMetricOutcome) {
	switch outcome {
	case blockApplyMetricNone:
		return
	case blockApplyMetricAccepted:
		s.noteBlockApplyAccepted()
	case blockApplyMetricRejected:
		s.noteBlockApplyRejected()
	}
}

func (s *SyncEngine) noteReorg(depth uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReorgDepth = depth
	if depth > 0 {
		s.reorgCount++
	}
}

func (s *SyncEngine) currentCanonicalTip() (uint64, [32]byte, error) {
	height, tipHash, ok, err := s.blockStore.Tip()
	if err != nil {
		return 0, [32]byte{}, err
	}
	if !ok {
		return 0, [32]byte{}, errors.New("blockstore has no canonical tip")
	}
	return height, tipHash, nil
}
