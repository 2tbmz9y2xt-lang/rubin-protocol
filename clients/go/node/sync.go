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

var (
	ErrParentNotFound          = errors.New("parent block not found")
	errStoragePersistenceFault = errors.New("storage persistence fault; restart required")
)

type SyncConfig struct {
	ExpectedTarget   *[32]byte
	ChainStatePath   string
	HeaderBatchLimit uint64
	IBDLagSeconds    uint64
	ChainID          [32]byte
	Network          string
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

// ValidateParallelValidationMode reports whether s names a valid
// parallel-validation mode. It accepts exactly the values the canonical
// parser used by NewSyncEngine accepts: "off", "shadow", "on"
// (case-insensitive, surrounding whitespace ignored) plus "" (the
// documented default, resolving to "off"). Validation-only: it performs
// no filesystem, chainstate, blockstore, or service side effect, and a
// nil return guarantees NewSyncEngine cannot later reject the same value
// on mode parsing. rubin-node startup calls it so an invalid operator
// mode exits before datadir creation, chainstate load/save, blockstore
// open, reconcile, the legacy-exposure-scan chainstate read, or any
// service start (RUB-665). NewSyncEngine keeps its own internal parse as
// defense in depth for embedded callers.
func ValidateParallelValidationMode(s string) error {
	_, err := parseParallelValidationMode(s)
	return err
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
	chainState         *ChainState
	blockStore         *BlockStore
	mempool            *Mempool
	cfg                SyncConfig
	stderr             io.Writer
	mu                 sync.RWMutex
	tipTimestamp       uint64
	bestKnownHeight    uint64
	lastReorgDepth     uint64
	reorgCount         uint64
	blockApply         BlockApplyCounts
	mutationMu         sync.Mutex
	persistenceFaultMu sync.Mutex
	persistenceFault   *storagePersistenceFault

	pvMode             parallelValidationMode
	pvShadowMax        uint64
	pvShadowMismatches uint64
	pvShadowSamples    []string
	pvTelemetry        *PVTelemetry
}

type storagePersistenceFault struct {
	cause     error
	reloadErr error
}

func (e *storagePersistenceFault) Error() string {
	if e.reloadErr == nil {
		return fmt.Sprintf("storage persistence fault: %v", e.cause)
	}
	return fmt.Sprintf("storage persistence fault: %v (reload failed: %v)", e.cause, e.reloadErr)
}

func (e *storagePersistenceFault) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
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
	if s == nil {
		return errors.New("sync engine is not initialized")
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationAllowed(); err != nil {
		return err
	}
	if s.chainState.view().hasTip || s.cfg.ChainID != devnetGenesisChainID {
		return nil
	}
	_, applyErr := s.applyBlock(devnetGenesisBlockBytes, nil)
	if errors.Is(applyErr, errStoragePersistenceFault) || isAtomicWritePostCommit(applyErr) {
		return applyErr
	}
	return raceTolerantBootstrapResult(applyErr, s.chainState.view().hasTip)
}

// raceTolerantBootstrapResult tolerates a directly changed shared ChainState:
// if apply fails after an external tip appears, bootstrap is already satisfied.
//
// Returns:
//   - nil when ApplyBlock succeeded (applyErr == nil), regardless of hasTip.
//   - nil when a non-persistence ApplyBlock failure finds a tip at recheck
//     (race-recovery).
//   - applyErr when ApplyBlock failed AND hasTip is still false (real failure
//     unrelated to concurrent tip installation, e.g. blockstore I/O error).
func raceTolerantBootstrapResult(applyErr error, hasTip bool) error {
	if applyErr != nil && hasTip {
		return nil
	}
	return applyErr
}

func (s *SyncEngine) ApplyBlock(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	if s == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	return s.applyBlock(blockBytes, prevTimestamps)
}

func (s *SyncEngine) applyBlock(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	if err := s.mutationAllowed(); err != nil {
		return nil, err
	}
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	return s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps, nil)
}

// StockDevnetTargetSchedule reports whether the exact stock Phase-0 devnet
// predicate holds: a candidate's expected target MUST then come from the
// derived schedule, not from the static SyncConfig.ExpectedTarget.
//
// This is the SINGLE formula for that rule in the Go tree, and every layer —
// including node/p2p — MUST call it rather than replicate it, so no layer can
// select a different rule than the one the apply path enforces. It normalizes
// the network itself (blank and any case/whitespace variant of "devnet" count
// as devnet) because callers may hold the operator's RAW SyncConfig:
// NewSyncEngine normalizes only its own copy.
//
// Stateless by contract: it takes startup identity only, reads no chain state,
// performs no derivation, and cannot fail. It confers no derivation capability
// — the schedule helper, its ancestry walk and the retarget entry stay
// unexported.
//
// Exactly TWO immutable startup terms, and deliberately no chain-state term.
// A genesis-hash term would add no guarantee: the chain id IS the SHA3-256
// commitment over the published genesis bytes (deriveGenesisChainID, re-derived
// and panic-checked at init in chainstate.go), so chain-id equality already
// implies the published genesis identity. What such a term did add was rule
// selection that depends on chain state — an empty or recovering store flipped
// it — a canonical-index read per untrusted peer message, and no single
// realizable form across layers. The genesis hash is still verified at startup
// by ValidateDevnetGenesisIdentity; that is where it belongs.
//
// Being a pure function of startup identity, this cannot fail, so it returns no
// error and reads nothing.
func StockDevnetTargetSchedule(network string, chainID [32]byte) bool {
	return normalizedNetworkName(network) == "devnet" && chainID == devnetGenesisChainID
}

// StockDevnetTargetSchedule reports the predicate for THIS engine, from the
// engine's OWN normalized configuration. Every layer that defers a target
// decision to an engine MUST ask that engine rather than consult a separate
// SyncConfig copy: a layer holding its own copy could otherwise select a
// different rule than the engine it hands the block to, which is a
// same-process accept/reject divergence. Mirrors Rust's
// SyncEngine::stock_devnet_target_schedule.
//
// Nil-receiver safe, like the other exported SyncEngine methods: a nil engine
// reports false, which keeps the caller on its pre-existing static behavior
// instead of panicking on a validity path.
func (s *SyncEngine) StockDevnetTargetSchedule() bool {
	if s == nil {
		return false
	}
	return StockDevnetTargetSchedule(s.cfg.Network, s.cfg.ChainID)
}

// canonicalApplyTarget carries an expected target already resolved by a caller
// that owns the (selected parent, candidate height) pair. Nil means "resolve at
// the choke point"; non-nil is used verbatim, so a boundary candidate is never
// walked twice. Its expected field is nil exactly when no derivation ran — a
// height-0 candidate (including the production genesis bootstrap, where the
// predicate DOES hold) or a non-stock identity — and the configured static
// target is itself nil. A derivation failure is always an error and can never
// reach a validation call as a nil expected target.
type canonicalApplyTarget struct {
	expected *[32]byte
}

// targetContextForCandidate resolves the expected target for one candidate. The
// CALLER owns both inputs: parentHash MUST be the authoritative selected parent
// and candidateHeight the caller's own height. Height 0 is the
// published-genesis path and keeps the configured static target.
func targetContextForCandidate(store *BlockStore, cfg SyncConfig, parentHash [32]byte, candidateHeight uint64) (*canonicalApplyTarget, error) {
	if candidateHeight == 0 || !StockDevnetTargetSchedule(cfg.Network, cfg.ChainID) {
		return &canonicalApplyTarget{expected: cfg.ExpectedTarget}, nil
	}
	// Fail closed, with or without a configured static target. Once the
	// predicate holds the derived target is the ONLY binding rule, so falling
	// back to the static field when derivation is impossible would silently
	// restore the very hole this issue closes. Mirrors the Rust
	// UNBOUND_DEVNET_TARGET_ERR refusal byte-for-byte in wording and category
	// (a plain error, not a consensus TxError), so neither client can accept
	// what the other refuses.
	if store == nil {
		return nil, errors.New("target schedule context: stock devnet predicate holds but there is no block store")
	}
	target, err := deriveExpectedTargetFn(store, parentHash, candidateHeight)
	if err != nil {
		return nil, err
	}
	return &canonicalApplyTarget{expected: &target}, nil
}

// deriveExpectedTargetFn indirects the merged derivation primitive so tests can
// count how many times the CALLERS invoke it. Production always holds
// expectedTargetForCandidate; the read count inside the primitive is the
// primitive's own property and is pinned by its own tests. Mirrors the existing
// readFileByPathFn / writeFileAtomicFn seams in blockstore.go.
var deriveExpectedTargetFn = expectedTargetForCandidate

func (s *SyncEngine) targetContextForCandidate(parentHash [32]byte, candidateHeight uint64) (*canonicalApplyTarget, error) {
	if s == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	return targetContextForCandidate(s.blockStore, s.cfg, parentHash, candidateHeight)
}

// SetMempool binds, EXACTLY ONCE, the mempool whose pending-outpoint owner this
// engine drives, serializing on mutationMu so a canonical transition can never
// observe the pointer set change under it. Initialization-only is the contract,
// not a convenience: a pool detached at tip A, held while the engine advances,
// and handed back at an apparently equal tip carries records and claims bound to
// a canonical history this engine no longer has, and a pointer comparison cannot
// see that. So only a fresh empty pool at the guarded live tip binds, and
// afterwards only the exact same pointer is accepted; a rejection mutates
// neither the engine nor the candidate's policy, records, indexes, owner state
// or high-waters.
func (s *SyncEngine) SetMempool(mempool *Mempool) {
	if s == nil {
		return
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationAllowed(); err != nil {
		s.reportMempoolBindingRejected(err)
		return
	}
	if err := s.bindMempoolUnderMutation(mempool); err != nil {
		s.reportMempoolBindingRejected(err)
	}
}

// bindMempoolUnderMutation performs the initialization-only binding under the
// caller's mutationMu, holding the live admission read guard CONTINUOUSLY from
// the live tip read through the install. Lock order is mutationMu,
// admissionMu.RLock, then s.mu before Mempool.mu before owner.mu — never the
// reverse; the candidate's context is read with owner.mu released, before
// Mempool.mu is taken.
func (s *SyncEngine) bindMempoolUnderMutation(mempool *Mempool) error {
	s.chainState.admissionMu.RLock()
	defer s.chainState.admissionMu.RUnlock()
	settled, err := s.checkMempoolRebinding(mempool)
	if settled || err != nil {
		return err
	}
	if mempool.chainState != s.chainState {
		return errors.New("mempool candidate is bound to a different chainstate")
	}
	liveTip := pendingOutpointTipOf(s.chainState)
	admission, ok := mempool.PendingOutpointOwner().AdmissionContext()
	if !ok {
		return errors.New("mempool candidate owner has no available admission context")
	}
	if admission.StableTip != liveTip {
		return errors.New("mempool candidate owner is bound to a different canonical tip")
	}
	return s.installInitialMempool(mempool, admission)
}

// checkMempoolRebinding resolves every already-decided case, reporting
// settled=true for a call that must do nothing: an exact same-pointer rebind, or
// a nil call before anything was bound. Every other post-binding call — a nil
// unbind, or ANY different pointer — is an error.
func (s *SyncEngine) checkMempoolRebinding(mempool *Mempool) (bool, error) {
	s.mu.RLock()
	bound := s.mempool
	s.mu.RUnlock()
	if bound == nil {
		return mempool == nil, nil
	}
	if mempool == bound {
		return true, nil
	}
	if mempool == nil {
		return false, errors.New("mempool unbinding is not supported after the initial binding")
	}
	return false, errors.New("mempool replacement is not supported after the initial binding")
}

// installInitialMempool rechecks the candidate's emptiness and its admission
// context under s.mu, Mempool.mu and owner.mu — in that order — and only then
// fills the missing policy providers and installs the pointer. Everything
// fallible runs before the first write, so a refused candidate is unchanged.
func (s *SyncEngine) installInitialMempool(mempool *Mempool, admission PendingOutpointAdmissionContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mempool.mu.Lock()
	defer mempool.mu.Unlock()
	if err := mempool.checkEmptyForBindingLocked(); err != nil {
		return err
	}
	owner := mempool.pendingOutpointOwnerLocked()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.checkNoClaimsLocked(); err != nil {
		return err
	}
	if current, ok := owner.admissionContextLocked(); !ok || current != admission {
		return errors.New("mempool candidate admission context moved during binding")
	}
	if mempool.policy.RotationProvider == nil {
		mempool.policy.RotationProvider = s.cfg.RotationProvider
	}
	if mempool.policy.SuiteRegistry == nil {
		mempool.policy.SuiteRegistry = s.cfg.SuiteRegistry
	}
	s.mempool = mempool
	return nil
}

// reportMempoolBindingRejected makes a refused binding visible: the engine keeps
// its previous binding, otherwise indistinguishable from an unwired caller.
func (s *SyncEngine) reportMempoolBindingRejected(err error) {
	_, _ = fmt.Fprintf(s.stderr, "sync: mempool binding rejected, engine binding unchanged: %v\n", err)
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

// canonicalIndexPreflight performs the FALLIBLE half of the rollback snapshot —
// reading the canonical index — while the caller holds mutationMu and BEFORE any
// clone, ConnectBlock or preferred-branch consensus validation. That order keeps
// a corrupt local index reported ahead of a candidate's consensus error.
// mutationMu serializes canonical mutation and admission never touches the
// canonical index, so the value stays exact until the transition begins.
func (s *SyncEngine) canonicalIndexPreflight() ([]string, error) {
	if s == nil || s.blockStore == nil {
		return nil, nil
	}
	return s.blockStore.CanonicalIndexSnapshot()
}

// captureRollbackState is the standalone form: it runs the preflight itself and
// then captures the rest. Canonical transitions do NOT use it — they run
// canonicalIndexPreflight up front and pass the result to
// captureRollbackStateWithIndex.
func (s *SyncEngine) captureRollbackState() (syncRollbackState, error) {
	canonicalIndex, err := s.canonicalIndexPreflight()
	if err != nil {
		return syncRollbackState{}, err
	}
	return s.captureRollbackStateWithIndex(canonicalIndex)
}

func (s *SyncEngine) captureRollbackStateWithIndex(canonicalIndex []string) (syncRollbackState, error) {
	snapshot := cloneChainState(s.chainState)
	if snapshot == nil {
		return syncRollbackState{}, errors.New("nil chainstate")
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

// canonicalTransition is one canonical state transition. It owns
// ChainState.admissionMu continuously from generation begin through stable
// commit or exact abort, so neither admission nor a public terminal removal can
// escape the rollback snapshot captured inside it.
//
// The ChainState, Mempool and owner pointers are captured ONCE at begin. Helpers
// the transition calls (captureRollbackStateWithIndex, restoreRollbackChainState)
// still read s.chainState / s.mempool; that is safe ONLY because SetMempool and
// every canonical mutation serialize on mutationMu, which the entry point holds
// throughout, so no reread can observe a different pointer set.
type canonicalTransition struct {
	engine           *SyncEngine
	chainState       *ChainState
	mempool          *Mempool
	owner            *PendingOutpointOwner
	generation       uint64
	rollback         syncRollbackState
	appliedHeight    uint64
	appliedTimestamp uint64
	applied          bool
}

// beginCanonicalTransition takes the live admission guard, binds the pointer
// set, advances the owner generation, and captures the exact rollback snapshot
// under the guard. The caller holds mutationMu and MUST already have run
// canonicalIndexPreflight, whose result it passes here: the fallible index read
// belongs before any clone or consensus validation, not inside the guard.
func (s *SyncEngine) beginCanonicalTransition(canonicalIndex []string) (*canonicalTransition, error) {
	if err := s.mutationAllowed(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	mempool := s.mempool
	s.mu.RUnlock()
	chainState := s.chainState
	if mempool != nil && mempool.chainState != chainState {
		return nil, errors.New("mempool is bound to a different chainstate")
	}
	owner := mempool.PendingOutpointOwner()
	chainState.admissionMu.Lock()
	generation, err := owner.beginTransition()
	if err != nil {
		chainState.admissionMu.Unlock()
		return nil, err
	}
	rollback, err := s.captureRollbackStateWithIndex(canonicalIndex)
	if err != nil {
		owner.endTransitionAborted()
		chainState.admissionMu.Unlock()
		return nil, err
	}
	return &canonicalTransition{
		engine:     s,
		chainState: chainState,
		mempool:    mempool,
		owner:      owner,
		generation: generation,
		rollback:   rollback,
	}, nil
}

// finish commits the owner stable tip from the live ChainState as the LAST
// state change of the transition, reopens admission, and only then records the
// runtime accepted-tip metrics.
func (t *canonicalTransition) finish() error {
	err := t.owner.commitStableTip(pendingOutpointTipOf(t.chainState))
	t.chainState.admissionMu.Unlock()
	if err != nil {
		return err
	}
	if t.applied {
		t.engine.recordAppliedBlock(t.appliedHeight, t.appliedTimestamp)
	}
	return nil
}

// abort reopens admission after the caller has proven the exact restore. The
// stable tip keeps its pre-transition value; high-waters stay advanced.
func (t *canonicalTransition) abort() {
	t.owner.endTransitionAborted()
	t.chainState.admissionMu.Unlock()
}

// end closes the transition for cause, and is the ONLY place that decides
// between reopening admission and latching it shut.
//
// cause == nil commits the stable tip and reopens admission.
//
// TWO causes are terminal and fail-closed, because neither leaves the live and
// persistent states both provable: an already-latched ambiguous atomic
// POST-COMMIT persistence fault, and a rollback whose exact restore FAILED
// (*rollbackRestoreFault). Either leaves the owner transition-active,
// AdmissionContext unavailable and admissionMu deliberately NOT released, and
// latches the engine fault so later mutators fail closed too. Waiters block
// until the required restart, which beats reopening over an unproven state.
//
// admissionMu is the ONLY lock retained across that terminal state. mutationMu
// is released by the calling entry point's own deferred unlock as this returns,
// so a later SyncEngine mutator acquires it and gets the latched fault from
// mutationAllowed instead of waiting forever.
//
// Any other cause is an ordinary abort: the caller has already proven the exact
// restore, so admission reopens with high-waters left advanced.
func (t *canonicalTransition) end(cause error) error {
	if cause == nil {
		return t.finish()
	}
	if t.engine.persistenceFaulted() {
		t.engine.reportTerminalTransition("post-commit persistence fault", cause)
		return cause
	}
	var restoreFault *rollbackRestoreFault
	if errors.As(cause, &restoreFault) {
		t.engine.latchTerminalFault(cause)
		t.engine.reportTerminalTransition("rollback restore failed", cause)
		return cause
	}
	t.abort()
	return cause
}

// latchTerminalFault installs cause as the engine's terminal storage-persistence
// fault when none is latched yet. It is the SAME latch handlePersistenceError
// installs — no new recovery mechanism, no new state machine — so mutationAllowed
// returns it to every later mutator exactly as after an ambiguous write.
func (s *SyncEngine) latchTerminalFault(cause error) {
	s.persistenceFaultMu.Lock()
	defer s.persistenceFaultMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.persistenceFault == nil {
		s.persistenceFault = &storagePersistenceFault{cause: cause}
	}
}

// reportTerminalTransition makes the fail-closed latch visible to an operator:
// without it a latched node is indistinguishable from a merely hung one.
func (s *SyncEngine) reportTerminalTransition(reason string, cause error) {
	_, _ = fmt.Fprintf(s.stderr, "sync: canonical transition terminal (%s), admission stays closed until restart: %v\n", reason, cause)
}

// rollbackRestoreFault marks a transition failure whose EXACT restore could not
// be proven. It keeps the historical "cause (rollback failed: ...)" message; the
// type exists so end() can route it into the fail-closed terminal latch.
type rollbackRestoreFault struct {
	cause      error
	restoreErr error
}

func (e *rollbackRestoreFault) Error() string {
	return fmt.Sprintf("%v (rollback failed: %v)", e.cause, e.restoreErr)
}

func (e *rollbackRestoreFault) Unwrap() error { return e.cause }

// publishPreparedChainState copies a fully prepared chain state onto the live
// ChainState under ChainState.mu only.
//
// The canonical transition already owns ChainState.admissionMu, and
// ChainState.replaceFrom reacquires that same non-reentrant lock, so calling it
// from under the guard would self-deadlock. Every restore and publication that
// can run under the guard MUST use this helper instead.
func publishPreparedChainState(dst *ChainState, src *ChainState) error {
	snapshot := cloneChainState(src)
	if dst == nil || snapshot == nil {
		return errors.New("nil chainstate publication")
	}
	dst.mu.Lock()
	defer dst.mu.Unlock()
	dst.Utxos = snapshot.Utxos
	dst.Height = snapshot.Height
	dst.AlreadyGenerated = snapshot.AlreadyGenerated
	dst.TipHash = snapshot.TipHash
	dst.HasTip = snapshot.HasTip
	dst.Rotation = snapshot.Rotation
	dst.Registry = snapshot.Registry
	return nil
}

func (s *SyncEngine) rollbackApplyBlock(cause error, state syncRollbackState) error {
	if s.persistenceFaulted() {
		return cause
	}
	var restoreFault *rollbackRestoreFault
	if errors.As(cause, &restoreFault) {
		// An inner restore already failed: retrying cannot make the state
		// provable, and would mask the original fault. Propagate it to end().
		return cause
	}
	restoreErr := s.restoreRollbackPersistentState(state)
	if isAtomicWritePostCommit(restoreErr) {
		var atomicErr *atomicWriteError
		reloadStore := errors.As(restoreErr, &atomicErr) && s.blockStore != nil && atomicErr.destination == s.blockStore.indexPath
		return s.handlePersistenceError(restoreErr, reloadStore, !reloadStore)
	}
	s.restoreRollbackRuntimeState(state)
	if restoreErr != nil {
		return &rollbackRestoreFault{cause: cause, restoreErr: restoreErr}
	}
	return cause
}

func (s *SyncEngine) mutationAllowed() error {
	if s == nil || s.chainState == nil {
		return errors.New("sync engine is not initialized")
	}
	if s.persistenceFaulted() {
		return errStoragePersistenceFault
	}
	return nil
}

func (s *SyncEngine) persistenceFaulted() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.persistenceFault != nil
}

func (s *SyncEngine) handlePersistenceError(err error, reloadStore, reloadState bool) error {
	if !isAtomicWritePostCommit(err) {
		return err
	}
	s.persistenceFaultMu.Lock()
	defer s.persistenceFaultMu.Unlock()
	s.mu.Lock()
	stable := s.persistenceFault
	if stable == nil {
		stable = &storagePersistenceFault{cause: err}
		s.persistenceFault = stable
	}
	s.mu.Unlock()

	reloadErr := s.reloadVisiblePersistenceState(reloadStore, reloadState)
	if reloadErr == nil {
		return stable
	}
	completed := &storagePersistenceFault{cause: stable.cause, reloadErr: errors.Join(stable.reloadErr, reloadErr)}
	s.mu.Lock()
	s.persistenceFault = completed
	s.mu.Unlock()
	return completed
}

func (s *SyncEngine) reloadVisiblePersistenceState(reloadStore, reloadState bool) error {
	if s == nil {
		return errors.New("nil sync engine")
	}
	s.mu.RLock()
	store := s.blockStore
	state := s.chainState
	chainStatePath := s.cfg.ChainStatePath
	s.mu.RUnlock()
	var reloadErr error
	if reloadStore && store != nil {
		reloadErr = firstRollbackRestoreErr(reloadErr, store.reloadFromDisk())
	}
	if !reloadState || chainStatePath == "" {
		return reloadErr
	}
	if err := reloadVisibleChainState(state, chainStatePath); err != nil {
		return firstRollbackRestoreErr(reloadErr, err)
	}
	return reloadErr
}

// reloadVisibleChainState re-reads the persisted chainstate from path and
// republishes it into state, carrying the live rotation and registry fields
// across. It touches no Mempool and no pending-outpoint owner.
func reloadVisibleChainState(state *ChainState, path string) error {
	loaded, err := LoadChainState(path)
	if err != nil {
		return err
	}
	if state == nil {
		return errors.New("nil chainstate destination")
	}
	state.mu.RLock()
	loaded.Rotation = state.Rotation
	loaded.Registry = state.Registry
	state.mu.RUnlock()
	return publishPreparedChainState(state, loaded)
}

func (s *SyncEngine) restoreRollbackPersistentState(state syncRollbackState) error {
	restoreErr := s.restoreRollbackChainState(state)
	if s.blockStore != nil {
		indexErr := s.blockStore.RestoreCanonicalIndex(state.canonicalIndex)
		if isAtomicWritePostCommit(indexErr) {
			return indexErr
		}
		restoreErr = firstRollbackRestoreErr(restoreErr, indexErr)
	}
	restoreErr = firstRollbackRestoreErr(restoreErr, restoreMempoolSnapshot(s.mempool, state.mempool))
	if restoreErr == nil && s.cfg.ChainStatePath != "" {
		restoreErr = s.chainState.Save(s.cfg.ChainStatePath)
	}
	return restoreErr
}

func firstRollbackRestoreErr(current error, next error) error {
	if isAtomicWritePostCommit(next) {
		return next
	}
	if current != nil {
		return current
	}
	return next
}

func (s *SyncEngine) restoreRollbackRuntimeState(state syncRollbackState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tipTimestamp = state.tipTimestamp
	s.bestKnownHeight = state.bestKnownHeight
	s.lastReorgDepth = state.lastReorgDepth
	s.reorgCount = state.reorgCount
}

func (s *SyncEngine) restoreRollbackChainState(state syncRollbackState) error {
	if s.chainState == nil {
		return errors.New("nil chainstate destination")
	}
	recovered := cloneChainState(state.chainState)
	if recovered == nil {
		return errors.New("nil rollback chainstate")
	}
	return publishPreparedChainState(s.chainState, recovered)
}

func (s *SyncEngine) applyCanonicalParsedBlock(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
	target *canonicalApplyTarget,
) (*ChainStateConnectSummary, error) {
	if err := s.mutationAllowed(); err != nil {
		return nil, err
	}
	summary, outcome, err := s.applyCanonicalParsedBlockTracked(pb, blockBytes, prevTimestamps, target)
	s.noteBlockApplyOutcome(outcome)
	return summary, err
}

type canonicalBlockApplyContext struct {
	blockHeight    uint64
	blockHash      [32]byte
	expectedTarget *[32]byte
	prevState      *ChainState
	// canonicalIndex is the rollback preflight result, read before the clone
	// below was connected so a local index fault outranks a consensus one.
	canonicalIndex []string
}

// applyCanonicalParsedBlockTracked fully validates one direct-connect candidate
// against a PRIVATE cloned ChainState — the live ChainState, BlockStore
// canonical state, Mempool and owner are untouched until the block is proven —
// and only then opens a canonical transition and commits it. A preferred-branch
// reorg does not come through here: it prepares every row the same way in
// preparePreferredBranch and commits them all inside ONE transition.
func (s *SyncEngine) applyCanonicalParsedBlockTracked(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
	target *canonicalApplyTarget,
) (*ChainStateConnectSummary, blockApplyMetricOutcome, error) {
	ctx, outcome, err := s.prepareCanonicalBlockApply(pb, target)
	if err != nil {
		return nil, outcome, err
	}
	prepared := cloneChainState(ctx.prevState)
	if prepared == nil {
		return nil, blockApplyMetricNone, errors.New("nil prepared chainstate")
	}
	summary, err := prepared.ConnectBlockWithSuiteContext(
		blockBytes,
		ctx.expectedTarget,
		prevTimestamps,
		s.cfg.ChainID,
		s.cfg.RotationProvider,
		s.cfg.SuiteRegistry,
	)
	s.runPVShadowIfActive(blockBytes, prevTimestamps, ctx, err, summary)
	if err != nil {
		return nil, blockApplyMetricRejected, err
	}
	// This is the ONLY site that reports a block as canonical-applied, so the
	// distinction between "connected to some chain state" and "made canonical"
	// lives in exactly one place. Extraction runs on the already-parsed block —
	// no re-parse, no retained bytes — and only AFTER the connect succeeded, so
	// an over-cap or malformed DA layout is rejected by consensus with its own
	// public error code before this ever runs. Any error here is therefore a
	// defensive assertion; it happens before the transition begins, so nothing
	// has been mutated and there is nothing to roll back.
	daIDs, err := CompleteDASetIDsFromParsedBlock(pb)
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	summary.CanonicalAppliedBlocks = []CanonicalAppliedBlock{{Hash: ctx.blockHash, CompleteDAIDs: daIDs}}
	if err := s.commitPreparedBlock(prepared, summary, ctx, pb, blockBytes); err != nil {
		return nil, blockApplyMetricNone, err
	}
	return summary, blockApplyMetricAccepted, nil
}

// commitPreparedBlock opens the transition for a direct connect and runs the
// mutating half of the apply inside it.
func (s *SyncEngine) commitPreparedBlock(
	prepared *ChainState,
	summary *ChainStateConnectSummary,
	ctx canonicalBlockApplyContext,
	pb *consensus.ParsedBlock,
	blockBytes []byte,
) error {
	tr, err := s.beginCanonicalTransition(ctx.canonicalIndex)
	if err != nil {
		return err
	}
	err = s.commitPreparedBlockUnderGuard(tr, prepared, summary, ctx, pb, blockBytes)
	if err == nil {
		tr.appliedHeight, tr.appliedTimestamp, tr.applied = summary.BlockHeight, pb.Header.Timestamp, true
	}
	return tr.end(err)
}

// commitPreparedBlockUnderGuard commits one already-validated block under an
// open transition: live tip recheck, standard cleanup BEFORE any observable
// canonical tip change, prepared-state publication, then persistence. No parse,
// ConnectBlock, signature verification or consensus validation runs here, and
// every error it returns has already been through rollback.
func (s *SyncEngine) commitPreparedBlockUnderGuard(
	tr *canonicalTransition,
	prepared *ChainState,
	summary *ChainStateConnectSummary,
	ctx canonicalBlockApplyContext,
	pb *consensus.ParsedBlock,
	blockBytes []byte,
) error {
	if err := s.recheckLiveTipIdentity(tr, chainTipScalarsOf(ctx.prevState)); err != nil {
		return s.rollbackApplyBlock(err, tr.rollback)
	}
	// Cleanup precedes publication: the standard records and their exact
	// claims are gone before any observer can see the new canonical tip.
	if tr.mempool != nil {
		if err := tr.mempool.applyConnectedBlockParsed(pb); err != nil {
			_, _ = fmt.Fprintf(s.stderr, "sync: standard mempool cleanup failed at height %d, rolling back: %v\n", ctx.blockHeight, err)
			return s.rollbackApplyBlock(err, tr.rollback)
		}
	}
	if err := publishPreparedChainState(tr.chainState, prepared); err != nil {
		return s.rollbackApplyBlock(err, tr.rollback)
	}
	return s.finalizeAppliedBlock(summary, ctx.blockHash, pb, blockBytes, ctx.prevState, tr.rollback)
}

// canonicalTipScalars is the exact tip identity a prepared candidate was
// validated against, and the identity its commit publishes. It is the ONLY
// chain-state data a prepared preferred-branch row keeps.
type canonicalTipScalars struct {
	hasTip           bool
	height           uint64
	tipHash          [32]byte
	alreadyGenerated uint64
}

func chainTipScalarsOf(state *ChainState) canonicalTipScalars {
	view := state.view()
	return canonicalTipScalars{hasTip: view.hasTip, height: view.height, tipHash: view.tipHash, alreadyGenerated: view.alreadyGenerated}
}

// recheckLiveTipIdentity proves, under the transition guard, that the live
// ChainState AND the live BlockStore canonical tip are still exactly the state
// the candidate was prepared against. mutationMu already serializes canonical
// mutation in-process, so both halves are defense in depth.
func (s *SyncEngine) recheckLiveTipIdentity(tr *canonicalTransition, prior canonicalTipScalars) error {
	live := tr.chainState.view()
	if live.hasTip != prior.hasTip || live.height != prior.height || live.tipHash != prior.tipHash {
		return errors.New("live chainstate tip moved during canonical apply")
	}
	return s.recheckLiveStoreTipIdentity(prior)
}

// recheckLiveStoreTipIdentity is the BlockStore half of recheckLiveTipIdentity.
// An engine with no store has no second tip to disagree with, so it passes. The
// check only reads the store and mutates nothing.
func (s *SyncEngine) recheckLiveStoreTipIdentity(prior canonicalTipScalars) error {
	if s.blockStore == nil {
		return nil
	}
	storeHeight, storeHash, storeHasTip, err := s.blockStore.Tip()
	if err != nil {
		return err
	}
	if storeHasTip != prior.hasTip || (storeHasTip && (storeHeight != prior.height || storeHash != prior.tipHash)) {
		return errors.New("live blockstore tip moved during canonical apply")
	}
	return nil
}

func (s *SyncEngine) prepareCanonicalBlockApply(pb *consensus.ParsedBlock, target *canonicalApplyTarget) (canonicalBlockApplyContext, blockApplyMetricOutcome, error) {
	if err := s.validateCanonicalBlockApplyReady(pb); err != nil {
		return canonicalBlockApplyContext{}, blockApplyMetricNone, err
	}
	blockHeight, canonicalTip, err := nextBlockContext(s.chainState)
	if err != nil {
		return canonicalBlockApplyContext{}, blockApplyMetricNone, err
	}
	expectedTarget, err := s.resolveCanonicalApplyTarget(target, canonicalTip, blockHeight)
	if err != nil {
		return canonicalBlockApplyContext{}, blockApplyMetricNone, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return canonicalBlockApplyContext{}, blockApplyMetricNone, err
	}
	if outcome, err := s.validateGenesisIdentity(blockHeight, blockHash); err != nil {
		return canonicalBlockApplyContext{}, outcome, err
	}
	// The fallible canonical-index rollback preflight sits exactly where it sat
	// before the transition existed: after the genesis-identity guard and BEFORE
	// the clone below is connected, so a corrupt local index is reported ahead of
	// the candidate's consensus error rather than behind it.
	canonicalIndex, err := s.canonicalIndexPreflight()
	if err != nil {
		return canonicalBlockApplyContext{}, blockApplyMetricNone, err
	}
	prevState := cloneChainState(s.chainState)
	if prevState == nil {
		return canonicalBlockApplyContext{}, blockApplyMetricNone, errors.New("nil chainstate")
	}
	return canonicalBlockApplyContext{
		blockHeight:    blockHeight,
		blockHash:      blockHash,
		expectedTarget: expectedTarget,
		prevState:      prevState,
		canonicalIndex: canonicalIndex,
	}, blockApplyMetricNone, nil
}

// resolveCanonicalApplyTarget is the choke point for every apply that runs
// through applyCanonicalParsedBlockTracked, so no such path can reach
// ConnectBlock with an unbound target. Two paths deliberately do NOT pass
// through it and resolve their own context instead: the reorg preview in
// preparePreferredBranch, and startup replay in replayCanonicalBlocks.
//
// A caller that already resolved the context — because it had to acquire the
// target BEFORE its own MTP window, or because it owns a branch-relative height
// the chainstate does not yet reflect — supplies it, keeping a boundary
// candidate to one WINDOW_SIZE walk instead of two. Otherwise the selected
// parent is the canonical tip from nextBlockContext; at height 0 nothing is
// derived and the published-genesis path is unchanged. All of it is read-only
// and runs before the canonical transition opens, therefore before any mutation.
func (s *SyncEngine) resolveCanonicalApplyTarget(target *canonicalApplyTarget, canonicalTip *[32]byte, blockHeight uint64) (*[32]byte, error) {
	if target != nil {
		return target.expected, nil
	}
	var parentHash [32]byte
	if canonicalTip != nil {
		parentHash = *canonicalTip
	}
	resolved, err := s.targetContextForCandidate(parentHash, blockHeight)
	if err != nil {
		return nil, err
	}
	return resolved.expected, nil
}

func (s *SyncEngine) validateCanonicalBlockApplyReady(pb *consensus.ParsedBlock) error {
	if s == nil || s.chainState == nil {
		return errors.New("sync engine is not initialized")
	}
	if pb == nil {
		return errors.New("nil parsed block")
	}
	return nil
}
