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
	daRelay            *DARelayState
	daRelayClaimed     bool
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
	cause error
}

func (e *storagePersistenceFault) Error() string {
	return fmt.Sprintf("storage persistence fault: %v", e.cause)
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
	// Deferred BEFORE the mutationMu unlock so it runs AFTER it: the writer is
	// invoked with no engine lock held. Every entry point repeats this order.
	diag := &diagnosticBatch{}
	defer s.flushDiagnostics(diag)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationAllowed(); err != nil {
		return err
	}
	if s.chainState.view().hasTip || s.cfg.ChainID != devnetGenesisChainID {
		return nil
	}
	_, applyErr := s.applyBlock(devnetGenesisBlockBytes, nil, diag)
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
//   - nil when a nonterminal ApplyBlock failure finds a tip at recheck
//     (race-recovery).
//   - applyErr for a terminal canonical M/O or already-latched engine fault.
//   - applyErr when ApplyBlock failed AND hasTip is still false (real failure
//     unrelated to concurrent tip installation, e.g. blockstore I/O error).
func raceTolerantBootstrapResult(applyErr error, hasTip bool) error {
	if isCanonicalMOTerminalError(applyErr) || errors.Is(applyErr, errStoragePersistenceFault) {
		return applyErr
	}
	if applyErr != nil && hasTip {
		return nil
	}
	return applyErr
}

func (s *SyncEngine) ApplyBlock(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	if s == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	diag := &diagnosticBatch{}
	defer s.flushDiagnostics(diag)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	// A summary is returned WITH an error only for TERMINAL_PERSISTENCE(new):
	// that truth is NEW, so its complete image, summary and accepted delta are
	// published even though the engine latches. Every other failure returns no
	// summary.
	return s.applyBlock(blockBytes, prevTimestamps, diag)
}

func (s *SyncEngine) applyBlock(blockBytes []byte, prevTimestamps []uint64, diag *diagnosticBatch) (*ChainStateConnectSummary, error) {
	if err := s.mutationAllowed(); err != nil {
		return nil, err
	}
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	return s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps, nil, diag)
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
// see that. So only a NEVER-USED pool at the guarded live tip binds — emptiness
// is not enough, because a pool admitted at tip A and drained back to zero is
// index-identical to a fresh one and only its history-bearing state (admission
// sequence, rolling fee floor, cumulative counters, owner high-waters) still
// says otherwise — and afterwards only the exact same pointer is accepted. A
// rejection mutates neither the engine nor the candidate's policy, records,
// indexes, owner state or high-waters, and is reported only through the existing
// bounded stderr diagnostic; no new public error kind is introduced.
func (s *SyncEngine) SetMempool(mempool *Mempool) {
	if s == nil {
		return
	}
	diag := &diagnosticBatch{}
	defer s.flushDiagnostics(diag)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationAllowed(); err != nil {
		s.reportMempoolBindingRejected(diag, err)
		return
	}
	if err := s.bindMempoolUnderMutation(mempool); err != nil {
		s.reportMempoolBindingRejected(diag, err)
	}
}

// DARelayState returns the read-only relay-state pointer bound with the
// engine's initial mempool. It never consumes the lifetime Service claim.
func (s *SyncEngine) DARelayState() *DARelayState {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.daRelay
}

// ClaimDARelayState atomically returns the sole lifetime Service claim.
func (s *SyncEngine) ClaimDARelayState() (*DARelayState, error) {
	if s == nil {
		return nil, errors.New("sync engine DA relay state is not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.daRelay == nil {
		return nil, errors.New("sync engine DA relay state is not initialized")
	}
	if s.daRelayClaimed {
		return nil, errors.New("sync engine DA relay state is already claimed")
	}
	s.daRelayClaimed = true
	return s.daRelay, nil
}

// bindMempoolUnderMutation performs the initialization-only binding under the
// caller's mutationMu, holding the live admission guard EXCLUSIVELY and
// CONTINUOUSLY from the live tip read through the install. Lock order is
// unchanged — mutationMu, admissionMu, then s.mu before Mempool.mu before
// owner.mu, never the reverse; the candidate's context is read with owner.mu
// released, before Mempool.mu is taken.
//
// The guard is a WRITE lock; a read lock would be unsound. Read locks do not
// exclude each other, so an in-flight admission runs concurrently with the
// freshness decision — validated against the PRE-binding policy, inserting after
// the pointer is installed, counting its outcome later still. Only exclusion
// across the whole span makes "never used" a decision rather than a sample,
// leaving two serializations: admission-then-binding (refused, the pool now has
// history) and binding-then-admission (admitted into a bound pool).
//
// Blocking indefinitely on a terminally latched engine is unchanged: the read
// lock blocked there too, because the latch retains admissionMu.
func (s *SyncEngine) bindMempoolUnderMutation(mempool *Mempool) error {
	s.chainState.admissionMu.Lock()
	defer s.chainState.admissionMu.Unlock()
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

// installInitialMempool rechecks that the candidate is never-used, together with
// its admission context, under s.mu, Mempool.mu and owner.mu — in that order —
// and only then fills the missing policy providers and installs the pointer.
// Everything fallible runs before the first write, so a refused candidate is
// unchanged.
func (s *SyncEngine) installInitialMempool(mempool *Mempool, admission PendingOutpointAdmissionContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mempool.mu.Lock()
	defer mempool.mu.Unlock()
	if err := mempool.checkNeverUsedForBindingLocked(); err != nil {
		return err
	}
	owner := mempool.pendingOutpointOwnerLocked()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := checkInitialMempoolOwnerLocked(owner, admission); err != nil {
		return err
	}
	daRelay, err := newDARelayState(mempool, defaultDARelayCaps())
	if err != nil {
		return err
	}
	if mempool.policy.RotationProvider == nil {
		mempool.policy.RotationProvider = s.cfg.RotationProvider
	}
	if mempool.policy.SuiteRegistry == nil {
		mempool.policy.SuiteRegistry = s.cfg.SuiteRegistry
	}
	s.mempool = mempool
	s.daRelay = daRelay
	return nil
}

func checkInitialMempoolOwnerLocked(owner *PendingOutpointOwner, admission PendingOutpointAdmissionContext) error {
	if err := owner.checkNoClaimsLocked(); err != nil {
		return err
	}
	if err := checkOwnerNeverUsedLocked(owner); err != nil {
		return err
	}
	if current, ok := owner.admissionContextLocked(); !ok || current != admission {
		return errors.New("mempool candidate admission context moved during binding")
	}
	return nil
}

// checkOwnerNeverUsedLocked proves the candidate's owner never issued a
// reservation and never entered a canonical transition, which the claim census
// alone cannot see: a claim reserved and released leaves both indexes empty
// while the token high-water stays advanced, and an aborted transition leaves
// the generation advanced. Both high-waters are monotonic by contract, so zero
// is exactly "never used". It reads owner state only; the caller holds owner.mu.
//
// This is a read of existing fields from the binding path, NOT an owner API,
// lifecycle or invariant change: the owner keeps every rule it already had.
func checkOwnerNeverUsedLocked(owner *PendingOutpointOwner) error {
	if owner.inTransition {
		return errors.New("mempool candidate owner has an active canonical transition")
	}
	if owner.tokenHighWater != 0 || owner.generation != 0 {
		return fmt.Errorf("mempool candidate owner carries reservation history: token_high_water=%d generation=%d", owner.tokenHighWater, owner.generation)
	}
	return nil
}

// reportMempoolBindingRejected makes a refused binding visible: the engine keeps
// its previous binding, otherwise indistinguishable from an unwired caller. The
// record is retained by the caller's batch and emitted after mutationMu is
// released; the rejection itself mutates nothing.
func (s *SyncEngine) reportMempoolBindingRejected(diag *diagnosticBatch, err error) {
	s.diagnose(diag, "sync: mempool binding rejected, engine binding unchanged: %v\n", err)
}

// SetStderr sets the writer for non-fatal error diagnostics (e.g. mempool
// post-acceptance failures). A nil writer maps to io.Discard, which is also the
// default when SetStderr is never called.
//
// The writer MUST be safe for concurrent use — the conventional io.Writer
// property that os.Stderr and *os.File already hold. Flushes deliberately run
// outside mutationMu, so two mutations' flush windows may overlap; serializing
// them behind a flush lock was rejected because a wedged writer would then stall
// another mutator's return, which is the very class this design removes.
//
// What the engine ENFORCES rather than assumes: the writer is never invoked
// while mutationMu, s.mu, or any ChainState / Mempool / PendingOutpointOwner
// lock is held, so it may block or re-enter a non-diagnostic SyncEngine mutation
// without stalling or deadlocking a mutator. Write errors are ignored: a
// diagnostic never changes a consensus, persistence, rollback or mempool result.
//
// ONE carve-out: the terminal fail-closed latch (canonicalTransition.end)
// retains the ChainState admission guard until restart, so that single flush
// runs with that guard held. A writer that blocks or re-enters there must not
// expect an admission-taking call to complete — nothing can pass that guard
// again in this process either way, and every mutation entry point refuses at
// mutationAllowed before touching it.
//
// The replacement is a race-free pointer store under s.mu; a flush already in
// progress keeps the writer it snapshotted.
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

// diagnosticWriter is the SINGLE synchronized read of the diagnostic writer, and
// every SyncEngine diagnostic site MUST go through it rather than touch s.stderr
// directly: the field is written by SetStderr under s.mu, so an unsynchronized
// read of it races a caller that rewires stderr while the node runs.
//
// It snapshots the writer under the lock and RETURNS it, deliberately leaving the
// I/O to the caller with no lock held. Holding s.mu across a write would put an
// arbitrary caller-supplied io.Writer — which may block, or itself call back into
// the engine — inside the engine's own mutex. Nil-safe on both the receiver and
// the field so a diagnostic can never panic on a path that is already failing.
func (s *SyncEngine) diagnosticWriter() io.Writer {
	if s == nil {
		return io.Discard
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.stderr == nil {
		return io.Discard
	}
	return s.stderr
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
	nowUnixSigned := time.Now().Unix()
	if nowUnixSigned < 0 {
		return true
	}
	nowUnix := uint64(nowUnixSigned) // #nosec G115 -- guarded against negative Unix timestamps above.
	return nowUnix >= tipTimestamp && nowUnix-tipTimestamp > ibdLag
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
	return nowUnix >= tipTimestamp && nowUnix-tipTimestamp > ibdLag
}

// canonicalIndexPreflight reads the complete old canonical identity while the
// caller holds mutationMu and BEFORE any clone, ConnectBlock or preferred-branch
// consensus validation. That order keeps a corrupt local index reported ahead of
// a candidate's consensus error. mutationMu serializes canonical mutation and
// admission never touches the canonical index, so the value stays exact until
// the transition's fence rechecks it.
func (s *SyncEngine) canonicalIndexPreflight() ([]string, error) {
	if s == nil || s.blockStore == nil {
		return nil, nil
	}
	return s.blockStore.CanonicalIndexSnapshot()
}

// canonicalTransition is one canonical state transition. It owns
// ChainState.admissionMu continuously from the owner generation advance through
// classification and the complete fixed publication, so no admission, removal or
// public terminal effect can interleave with the proof the plan was built on.
//
// The ChainState, Mempool and owner pointers are captured ONCE at begin; that is
// safe ONLY because SetMempool and every canonical mutation serialize on
// mutationMu, which the entry point holds throughout, so nothing can observe a
// different pointer set inside the transition.
type canonicalTransition struct {
	engine     *SyncEngine
	chainState *ChainState
	mempool    *Mempool
	owner      *PendingOutpointOwner
	// diag is the entry point's bounded diagnostic batch. Producers under the
	// guard append to it; nothing under the guard invokes the writer.
	diag       *diagnosticBatch
	generation uint64
}

// beginCanonicalTransition takes the live admission guard, binds the pointer set
// and advances the owner generation. The caller holds mutationMu and has already
// completed every fallible plan, staging, proof and checkpoint step: nothing
// inside the fence may fail for a reason the plan could have found earlier.
func (s *SyncEngine) beginCanonicalTransition(diag *diagnosticBatch) (*canonicalTransition, error) {
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
	return &canonicalTransition{
		engine:     s,
		chainState: chainState,
		mempool:    mempool,
		owner:      owner,
		diag:       diag,
		generation: generation,
	}, nil
}

// abort reopens admission for a transition that published nothing. The stable
// tip keeps its pre-transition value; high-waters stay advanced.
func (t *canonicalTransition) abort() {
	t.owner.endTransitionAborted()
	t.chainState.admissionMu.Unlock()
}

// end is the closeout for a failure BEFORE the index commit: a terminal M/O
// invariant latches the engine and RETAINS admission, every other cause aborts
// the owner transition and reopens admission. A post-commit outcome never comes
// here — publishCanonicalTransition owns that closeout.
func (t *canonicalTransition) end(cause error) error {
	if isCanonicalMOTerminalError(cause) {
		t.engine.latchTerminalFault(cause)
		t.engine.reportTerminalTransition(t.diag, "canonical mempool invariant", cause)
		return cause
	}
	t.abort()
	return cause
}

// latchTerminalFault installs the existing terminal fail-closed mutation latch.
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
//
// The record is retained by the entry point's batch and emitted once mutationMu
// is released, so a blocked writer cannot stop a later mutator from acquiring
// mutationMu and receiving the latched fault. The admission guard that the
// terminal state retains until restart is NOT released — that is the latch
// itself, and no mutation path re-acquires it after this point.
//
// It is also the one record the batch caps may not evict (diagnoseTerminal):
// losing it would leave an operator with shadow noise and a content-free
// truncation marker as the only stderr trace of a node that latched shut.
func (s *SyncEngine) reportTerminalTransition(diag *diagnosticBatch, reason string, cause error) {
	s.diagnoseTerminal(diag, "sync: canonical transition terminal (%s), admission stays closed until restart: %v\n", reason, cause)
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

func (s *SyncEngine) applyCanonicalParsedBlock(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
	target *canonicalApplyTarget,
	diag *diagnosticBatch,
) (*ChainStateConnectSummary, error) {
	if err := s.mutationAllowed(); err != nil {
		return nil, err
	}
	summary, outcome, err := s.applyCanonicalParsedBlockTracked(pb, blockBytes, prevTimestamps, target, diag)
	s.noteBlockApplyOutcome(outcome)
	return summary, err
}

type canonicalBlockApplyContext struct {
	blockHeight    uint64
	blockHash      [32]byte
	expectedTarget *[32]byte
	prevState      *ChainState
	// canonicalIndex is the complete old canonical identity, read before the
	// clone below was connected so a local index fault outranks a consensus one.
	canonicalIndex []string
	// diag is the owning public mutation's bounded diagnostic batch, or nil for
	// a caller outside a mutation (which holds no engine lock and may write
	// directly). The PV shadow producers read it from here.
	diag *diagnosticBatch
}

// applyCanonicalParsedBlockTracked fully validates one direct-connect candidate
// against a PRIVATE cloned ChainState — the live ChainState, BlockStore
// canonical state, Mempool and owner are untouched until the block is proven —
// and only then derives its one recovery-ready plan and runs the shared
// commit/classify/publish driver. A preferred-branch reorg does not come through
// here: it prepares every row the same way in preparePreferredBranch and commits
// them all inside ONE transition.
//
// Only commit truth NEW exposes A1, the summary and the accepted delta; every
// other truth returns no summary and no canonical counter.
func (s *SyncEngine) applyCanonicalParsedBlockTracked(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
	target *canonicalApplyTarget,
	diag *diagnosticBatch,
) (*ChainStateConnectSummary, blockApplyMetricOutcome, error) {
	ctx, outcome, err := s.prepareCanonicalBlockApply(pb, target, diag)
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
	// has been mutated.
	daIDs, err := CompleteDASetIDsFromParsedBlock(pb)
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	finalMTP, err := s.finalMempoolMTP(ctx.blockHeight, pb.Header.Timestamp, prevTimestamps)
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	plan, err := s.planDirectCanonicalConnect(ctx, prepared, pb, blockBytes, daIDs, finalMTP)
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	truth, err := s.commitCanonicalTransition(plan, diag)
	if truth != canonicalTruthNew {
		return nil, blockApplyMetricNone, err
	}
	summary.CanonicalAppliedBlocks = plan.applied
	s.recordAppliedBlock(summary.BlockHeight, pb.Header.Timestamp)
	return summary, blockApplyMetricAccepted, err
}

// planDirectCanonicalConnect derives the complete C1/A1 plan for a direct connect
// or bootstrap. The candidate extends the canonical tip, so the old identity's
// last row IS the highest common row and the old suffix is empty; the new suffix
// is this one block. The checkpoint is the pre-apply image the candidate was
// validated against and C1 is the connected clone, so the path holds exactly the
// two private images it already had.
func (s *SyncEngine) planDirectCanonicalConnect(
	ctx canonicalBlockApplyContext,
	final *ChainState,
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	daIDs [][32]byte,
	finalMTP uint64,
) (*canonicalTransitionPlan, error) {
	row := canonicalRowDescriptor{height: ctx.blockHeight, hash: ctx.blockHash}
	plan := &canonicalTransitionPlan{
		oldSequence: ctx.canonicalIndex,
		connect:     []canonicalRowDescriptor{row},
		applied:     []CanonicalAppliedBlock{{Hash: ctx.blockHash, CompleteDAIDs: daIDs}},
		checkpoint:  ctx.prevState,
		final:       final,
		priorTip:    chainTipScalarsOf(ctx.prevState),
		finalMTP:    finalMTP,
	}
	if s.blockStore == nil {
		return plan, nil
	}
	// The store and the chainstate must already agree on the tip, or the
	// candidate does not extend the identity it was planned against.
	if ctx.blockHeight != uint64(len(ctx.canonicalIndex)) {
		return nil, fmt.Errorf("direct canonical connect at height %d does not extend a %d-row canonical identity", ctx.blockHeight, len(ctx.canonicalIndex))
	}
	plan.newSequence = canonicalSequenceWithSuffix(ctx.canonicalIndex, ctx.blockHeight, [][32]byte{ctx.blockHash})
	undo, err := buildBlockUndo(ctx.prevState, pb, ctx.blockHeight)
	if err != nil {
		return nil, err
	}
	plan.staged = []canonicalStagedRow{{descriptor: row, headerBytes: pb.HeaderBytes, blockBytes: blockBytes, undo: undo}}
	return plan, nil
}

func (s *SyncEngine) finalMempoolMTP(height, timestamp uint64, fallback []uint64) (uint64, error) {
	prev := fallback
	if s.blockStore != nil {
		var err error
		prev, err = prevTimestampsFromStore(s.blockStore, height)
		if err != nil {
			return 0, err
		}
	}
	return mtpMedian(height+1, advancePrevTimestamps(prev, timestamp)), nil
}

// canonicalTipScalars is the exact tip identity a prepared candidate was
// validated against, and the identity its commit publishes. It is the ONLY
// chain-state data a prepared preferred-branch row keeps.
type canonicalTipScalars struct {
	hasTip           bool
	height           uint64
	tipHash          [32]byte
	alreadyGenerated consensus.Uint128
}

func chainTipScalarsOf(state *ChainState) canonicalTipScalars {
	view := state.view()
	return canonicalTipScalars{hasTip: view.hasTip, height: view.height, tipHash: view.tipHash, alreadyGenerated: view.alreadyGenerated}
}

func (s *SyncEngine) prepareCanonicalBlockApply(pb *consensus.ParsedBlock, target *canonicalApplyTarget, diag *diagnosticBatch) (canonicalBlockApplyContext, blockApplyMetricOutcome, error) {
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
		diag:           diag,
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
