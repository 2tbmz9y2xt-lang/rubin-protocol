package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math/bits"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node/p2p"
)

var nowUnix = func() int64 { return time.Now().Unix() }

var mustTipFn = mustTip

var newMinerFn = node.NewMiner

var newSyncEngineFn = node.NewSyncEngine

var newMempoolFn = node.NewMempoolWithConfig

var newP2PServiceFn = p2p.NewService

func applySuiteContextToSyncConfig(cfg *node.SyncConfig, rotation consensus.RotationProvider, registry *consensus.SuiteRegistry) {
	if cfg == nil {
		return
	}
	cfg.RotationProvider = rotation
	cfg.SuiteRegistry = registry
}

const legacyExposureReportVersion = 1

type legacyExposureSuiteReport struct {
	SuiteID           uint64    `json:"suite_id"`
	UtxoExposureCount uint64    `json:"utxo_exposure_count"`
	OutpointCount     uint64    `json:"outpoint_count"`
	Outpoints         *[]string `json:"outpoints,omitempty"`
}

type legacyExposureReport struct {
	ReportVersion         uint64                      `json:"report_version"`
	MeasurementScope      string                      `json:"measurement_scope"`
	Network               string                      `json:"network"`
	DataDir               string                      `json:"data_dir"`
	ChainstateHeight      uint64                      `json:"chainstate_height"`
	ChainstateHasTip      bool                        `json:"chainstate_has_tip"`
	IndexedSuiteIDs       []uint64                    `json:"indexed_suite_ids"`
	WatchedLegacySuiteIDs []uint64                    `json:"watched_legacy_suite_ids"`
	LegacyExposureTotal   uint64                      `json:"legacy_exposure_total"`
	SunsetReadiness       string                      `json:"sunset_readiness"`
	WarningHook           string                      `json:"warning_hook"`
	GraceHook             string                      `json:"grace_hook"`
	IncludeOutpoints      bool                        `json:"include_outpoints"`
	LegacySuiteReports    []legacyExposureSuiteReport `json:"legacy_suite_reports"`
}

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	if m == nil {
		return ""
	}
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func parseLegacySuiteID(value string) (uint8, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, fmt.Errorf("legacy suite_id is required")
	}
	base := 10
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		trimmed = trimmed[2:]
		base = 16
	}
	if trimmed == "" {
		return 0, fmt.Errorf("legacy suite_id is required")
	}
	parsed, err := strconv.ParseUint(trimmed, base, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid legacy suite_id %q", value)
	}
	return uint8(parsed), nil
}

func normalizeLegacySuiteIDs(raw []string) ([]uint8, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("legacy exposure scan requires at least one --legacy-suite-id")
	}
	seen := make(map[uint8]struct{}, len(raw))
	ids := make([]uint8, 0, len(raw))
	for _, value := range raw {
		suiteID, err := parseLegacySuiteID(value)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[suiteID]; ok {
			continue
		}
		seen[suiteID] = struct{}{}
		ids = append(ids, suiteID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func formatLegacyExposureOutpoint(op consensus.Outpoint) string {
	return fmt.Sprintf("%x:%d", op.Txid[:], op.Vout)
}

func legacyExposureHooks(hasTip bool, total uint64) (string, string, string) {
	if !hasTip {
		return "invalid_no_chainstate_tip", "none", "not_applicable_no_chainstate_tip"
	}
	if total == 0 {
		return "ready_for_operator_defined_grace_window", "none", "start_operator_defined_grace_window"
	}
	return "not_ready_legacy_exposure_present", "legacy_exposure_present_notify_operator_and_council", "not_applicable_legacy_exposure_present"
}

func saturatingAddUint64(total, value uint64) uint64 {
	sum, carry := bits.Add64(total, value, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return sum
}

func suiteIDsToJSONNumbers(ids []uint8) []uint64 {
	if len(ids) == 0 {
		return []uint64{}
	}
	values := make([]uint64, 0, len(ids))
	for _, id := range ids {
		values = append(values, uint64(id))
	}
	return values
}

func buildLegacyExposureReport(network, dataDir string, chainState *node.ChainState, legacySuiteIDs []uint8, includeOutpoints bool) legacyExposureReport {
	reports := make([]legacyExposureSuiteReport, 0, len(legacySuiteIDs))
	var total uint64
	for _, suiteID := range legacySuiteIDs {
		if includeOutpoints {
			outpoints := chainState.UtxoOutpointsBySuiteID(suiteID)
			reportCount := uint64(len(outpoints))
			reportOutpoints := make([]string, 0, len(outpoints))
			for _, op := range outpoints {
				reportOutpoints = append(reportOutpoints, formatLegacyExposureOutpoint(op))
			}
			total = saturatingAddUint64(total, reportCount)
			reports = append(reports, legacyExposureSuiteReport{
				SuiteID:           uint64(suiteID),
				UtxoExposureCount: reportCount,
				OutpointCount:     reportCount,
				Outpoints:         &reportOutpoints,
			})
			continue
		}
		reportCount := chainState.UtxoExposureCountBySuiteID(suiteID)
		total = saturatingAddUint64(total, reportCount)
		reports = append(reports, legacyExposureSuiteReport{
			SuiteID:           uint64(suiteID),
			UtxoExposureCount: reportCount,
			OutpointCount:     reportCount,
		})
	}
	indexedSuiteIDs := chainState.IndexedSuiteIDs()
	sunsetReadiness, warningHook, graceHook := legacyExposureHooks(chainState.HasTip, total)
	return legacyExposureReport{
		ReportVersion:         legacyExposureReportVersion,
		MeasurementScope:      "explicit_suite_id_utxos",
		Network:               network,
		DataDir:               dataDir,
		ChainstateHeight:      chainState.Height,
		ChainstateHasTip:      chainState.HasTip,
		IndexedSuiteIDs:       suiteIDsToJSONNumbers(indexedSuiteIDs),
		WatchedLegacySuiteIDs: suiteIDsToJSONNumbers(legacySuiteIDs),
		LegacyExposureTotal:   total,
		SunsetReadiness:       sunsetReadiness,
		WarningHook:           warningHook,
		GraceHook:             graceHook,
		IncludeOutpoints:      includeOutpoints,
		LegacySuiteReports:    reports,
	}
}

func printLegacyExposureReport(w io.Writer, report legacyExposureReport) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// requireCheckpointAtCanonicalTip proves the loaded checkpoint is exactly the
// canonical index tip — has-tip, height and tip hash — using the same strict
// read-only open the dry-run path uses, so it takes no datadir lock and creates
// nothing. A stale or divergent snapshot exits 2 and emits no report.
func requireCheckpointAtCanonicalTip(dataDir, chainStatePath string, chainState *node.ChainState, stderr io.Writer) int {
	blockStore, _, exit := createOrOpenBlockStore(dataDir, chainStatePath, false, true, stderr)
	if exit != 0 {
		return exit
	}
	height, hash, hasTip, err := blockStore.Tip()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "legacy exposure scan canonical tip read failed: %v\n", err)
		return 2
	}
	if !hasTip || !chainState.HasTip || chainState.Height != height || chainState.TipHash != hash {
		_, _ = fmt.Fprintf(
			stderr,
			"legacy exposure scan requires a chainstate snapshot at the canonical tip: snapshot=(has_tip=%v,height=%d,tip=%x) canonical=(has_tip=%v,height=%d,tip=%x)\n",
			chainState.HasTip, chainState.Height, chainState.TipHash, hasTip, height, hash,
		)
		return 2
	}
	return 0
}

func loadLegacyExposureScanChainState(path string) (*node.ChainState, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("legacy exposure scan requires an existing chainstate file with a tip: %s", path)
		}
		return nil, fmt.Errorf("legacy exposure scan chainstate stat failed for %s: %w", path, err)
	}
	chainState, err := node.LoadChainState(path)
	if err != nil {
		return nil, fmt.Errorf("chainstate load failed for %s: %w", path, err)
	}
	if !chainState.HasTip {
		return nil, fmt.Errorf("legacy exposure scan requires a chainstate with a tip: %s", path)
	}
	return chainState, nil
}

// createOrOpenBlockStore selects the explicit create path or the strict
// open-existing path. Mutating paths return their held datadir lock; dry-run
// preserves the strict open without acquiring or creating that lock.
func createOrOpenBlockStore(dataDir, chainStatePath string, createStore, dryRun bool, stderr io.Writer) (*node.BlockStore, *filelock.Handle, int) {
	rootPath := node.BlockStorePath(dataDir)
	if !createStore {
		if dryRun {
			blockStore, exit := openBlockStore(rootPath, stderr)
			return blockStore, nil, exit
		}
		if err := missingBlockStoreOpenError(dataDir, rootPath); err != nil {
			_, _ = fmt.Fprintf(stderr, "blockstore open failed: %v\n", err)
			return nil, nil, 2
		}
		lock, lockExit := acquireDatadirLock(dataDir, stderr)
		if lockExit != 0 {
			return nil, nil, lockExit
		}
		blockStore, exit := openBlockStore(rootPath, stderr)
		if exit != 0 {
			_ = lock.Release()
			return nil, nil, exit
		}
		return blockStore, lock, 0
	}
	if err := requireAbsentPath("blockstore root", rootPath); err != nil {
		_, _ = fmt.Fprintf(stderr, "blockstore create failed: %v\n", err)
		return nil, nil, 2
	}
	if err := requireAbsentPath("chainstate", chainStatePath); err != nil {
		_, _ = fmt.Fprintf(stderr, "blockstore create failed: %v\n", err)
		return nil, nil, 2
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		_, _ = fmt.Fprintf(stderr, "datadir create failed: %v\n", err)
		return nil, nil, 2
	}
	lock, lockExit := acquireDatadirLock(dataDir, stderr)
	if lockExit != 0 {
		return nil, nil, lockExit
	}
	if err := requireAbsentPath("blockstore root", rootPath); err != nil {
		_ = lock.Release()
		_, _ = fmt.Fprintf(stderr, "blockstore create failed: %v\n", err)
		return nil, nil, 2
	}
	if err := requireAbsentPath("chainstate", chainStatePath); err != nil {
		_ = lock.Release()
		_, _ = fmt.Fprintf(stderr, "blockstore create failed: %v\n", err)
		return nil, nil, 2
	}
	blockStore, err := node.CreateBlockStore(rootPath)
	if err != nil {
		_ = lock.Release()
		_, _ = fmt.Fprintf(stderr, "blockstore create failed: %v\n", err)
		return nil, nil, 2
	}
	return blockStore, lock, 0
}

// missingBlockStoreOpenError preserves the strict-open rejection for an
// initially absent datadir without entering BlockStore open before a mutating
// caller owns the datadir lock. The second, root-level probe closes the only
// relevant race: if a concurrent create has made the root appear, the caller
// continues to acquire the lock and opens the store under it. If it remains
// absent, format the same root Stat error that BlockStore open would report.
func missingBlockStoreOpenError(dataDir, rootPath string) error {
	if _, err := os.Lstat(dataDir); !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if _, err := os.Stat(rootPath); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("blockstore directory %s: %w", rootPath, err)
	}
	return nil
}

func openBlockStore(rootPath string, stderr io.Writer) (*node.BlockStore, int) {
	blockStore, err := node.OpenBlockStore(rootPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "blockstore open failed: %v\n", err)
		return nil, 2
	}
	return blockStore, 0
}

// requireAbsentPath rejects any existing filesystem entry at path. Lstat, not
// Stat, so a dangling symlink counts as present rather than as "not found".
func requireAbsentPath(label, path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists: %s", label, path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat %s %s: %w", label, path, err)
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	defaults := node.DefaultConfig()
	var peers multiStringFlag
	var legacySuiteIDs multiStringFlag
	var watchedSuiteIDs []uint8

	cfg := defaults
	fs := flag.NewFlagSet("rubin-node", flag.ContinueOnError)
	fs.SetOutput(stderr)

	peerCSV := fs.String("peers", "", "bootstrap peers, comma-separated host:port")
	fs.Var(&peers, "peer", "single bootstrap peer host:port (repeatable)")
	fs.StringVar(&cfg.Network, "network", defaults.Network, "network name (devnet/testnet/mainnet)")
	fs.StringVar(&cfg.DataDir, "datadir", defaults.DataDir, "node data directory")
	fs.StringVar(&cfg.BindAddr, "bind", defaults.BindAddr, "bind address host:port")
	fs.StringVar(&cfg.RPCBindAddr, "rpc-bind", defaults.RPCBindAddr, "devnet HTTP RPC bind address host:port (disabled when empty)")
	fs.StringVar(&cfg.LogLevel, "log-level", defaults.LogLevel, "log level: debug|info|warn|error")
	genesisFile := fs.String("genesis-file", "", "path to genesis pack JSON with chain_id_hex and genesis hash")
	fs.IntVar(&cfg.MaxPeers, "max-peers", defaults.MaxPeers, "max connected peers")
	fs.IntVar(&cfg.MempoolMaxTxs, "mempool-max-txs", defaults.MempoolMaxTxs, "maximum canonical mempool transactions")
	fs.IntVar(&cfg.MempoolMaxBytes, "mempool-max-bytes", defaults.MempoolMaxBytes, "maximum canonical mempool serialized transaction bytes")
	fs.StringVar(&cfg.MineAddress, "mine-address", "", "miner pubkey: 64-char hex key_id or 66-char hex suite_id||key_id")
	mineBlocks := fs.Int("mine-blocks", 0, "mine N blocks locally after startup")
	mineExit := fs.Bool("mine-exit", false, "exit immediately after local mining")
	featurebitsDeploymentsPath := fs.String("featurebits-deployments", "", "path to JSON file with featurebit deployments (telemetry-only)")
	pvMode := fs.String("pv-mode", "off", "parallel validation mode: off|shadow|on (truth path is sequential)")
	pvShadowMax := fs.Uint64("pv-shadow-max", 3, "max pv shadow mismatch samples to record/print (bounded)")
	legacyExposureScan := fs.Bool("legacy-exposure-scan", false, "emit legacy suite exposure report and exit")
	fs.Var(&legacySuiteIDs, "legacy-suite-id", "legacy suite_id to watch (decimal or 0xNN); repeatable")
	legacyExposureIncludeOutpoints := fs.Bool("legacy-exposure-include-outpoints", false, "include deterministic outpoint lists in legacy exposure report")
	dryRun := fs.Bool("dry-run", false, "report effective config and on-disk datadir state without writing to it; not a startup preflight — it does not predict whether startup will succeed")
	createStore := fs.Bool("create-store", false, "create a new blockstore (default: strictly open an existing one)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	cfg.Peers = node.NormalizePeers(append([]string{*peerCSV}, peers...)...)
	if err := node.ValidateConfig(cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid config: %v\n", err)
		return 2
	}
	cfg.DataDir = node.NormalizeDataDir(cfg.DataDir)
	if canonicalNetwork, ok := node.CanonicalNetworkName(cfg.Network); ok {
		cfg.Network = canonicalNetwork
	}
	// --mine-address is untrusted operator input. node.ValidateConfig above
	// already rejected everything node.ParseMineAddress rejects
	// (validateConfigMineAddress delegates to that same pure parser), so on
	// this path the call below cannot fail and its error branch is defense in
	// depth for a caller that reorders the two guards. Its purpose here is to
	// produce the covenant_data bytes EXACTLY ONCE, before the
	// legacy-exposure-scan chainstate read, the storage lifecycle
	// (createOrOpenBlockStore below), chainstate load/reconcile/save and
	// service startup: both consuming sites (the --mine-blocks miner and the
	// devnet RPC live miner) reuse this value instead of re-parsing the
	// string, which is what let a rejected value reach the miner after the
	// whole storage lifecycle — or silently disable RPC mining — before
	// RUB-1135. An empty or whitespace-only flag yields a nil address and
	// leaves both miner configs on their built-in default.
	mineAddress, mineAddressErr := node.ParseMineAddress(cfg.MineAddress)
	if mineAddressErr != nil {
		_, _ = fmt.Fprintf(stderr, "invalid mine-address: %v\n", mineAddressErr)
		return 2
	}
	// pv-mode is untrusted operator input: reject an invalid mode BEFORE
	// the legacy-exposure-scan branch (its chainstate read below) and
	// BEFORE the storage lifecycle (createOrOpenBlockStore below), so the
	// process exits on an untouched filesystem with no service started.
	// Everything above this guard is pure parse/normalize over argv.
	// NewSyncEngine re-parses the same value internally (defense in
	// depth for embedded callers), so on the normal startup path this
	// guard only moves that existing rejection earlier. On the
	// --legacy-exposure-scan path it instead ADDS a new rejection:
	// exit 2 where the pre-diff code returned 0 with an invalid mode
	// silently ignored (a contracted operator-visible change).
	if err := node.ValidateParallelValidationMode(*pvMode); err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid pv-mode: %v\n", err)
		return 2
	}
	if *legacyExposureScan {
		var err error
		watchedSuiteIDs, err = normalizeLegacySuiteIDs([]string(legacySuiteIDs))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "legacy exposure scan config failed: %v\n", err)
			return 2
		}
	} else if len(legacySuiteIDs) > 0 || *legacyExposureIncludeOutpoints {
		_, _ = fmt.Fprintln(stderr, "legacy exposure flags require --legacy-exposure-scan")
		return 2
	}
	// --create-store mutates storage; --dry-run and --legacy-exposure-scan are
	// read-only — the scan by returning below before the block store is opened,
	// --dry-run by skipping the chainstate reconcile+save further down (both
	// enforced by tests, not by convention). Reject the combination after the
	// existing config/legacy-suite validation and before genesis loading, the
	// scan's chainstate read, and every filesystem write: exit 2 on an
	// untouched filesystem.
	if *createStore && (*dryRun || *legacyExposureScan) {
		_, _ = fmt.Fprintln(stderr, "--create-store cannot be combined with --dry-run or --legacy-exposure-scan")
		return 2
	}
	// --featurebits-deployments is untrusted operator input: parse and
	// validate it with the same loader the telemetry print consumes BEFORE
	// the legacy-exposure-scan chainstate read, the storage lifecycle
	// (createOrOpenBlockStore below), chainstate load/reconcile/save, and
	// service startup, so an invalid file exits 2 on an untouched
	// filesystem with no service started. The parsed rows are reused by
	// the telemetry print below — the file is read exactly once per run.
	// An empty value skips validation and telemetry alike (the flag's
	// pre-existing contract). On the --legacy-exposure-scan path and on a
	// store with no tip this ADDS a new rejection: exit 2 where the
	// pre-diff code returned 0 with an invalid file silently ignored (the
	// scan returns before the telemetry branch, which is also tipOK-gated)
	// — a contracted operator-visible change.
	var featureBitDeployments []featureBitDeploymentJSON
	if *featurebitsDeploymentsPath != "" {
		ds, err := loadFeatureBitDeployments(*featurebitsDeploymentsPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "invalid featurebits deployments: %v\n", err)
			return 2
		}
		featureBitDeployments = ds
	}
	chainStatePath := node.ChainStatePath(cfg.DataDir)
	if *legacyExposureScan {
		chainState, err := loadLegacyExposureScanChainState(chainStatePath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%v\n", err)
			return 2
		}
		// The snapshot is the node's precommit CHECKPOINT and may lag the
		// canonical index by a transition. The scanner does not replay: replay
		// needs the network identity this mode deliberately does not require a
		// genesis file for, and measuring exposure against a guessed identity is
		// worse than not measuring it. So the report is emitted ONLY when the
		// snapshot IS the canonical tip; otherwise this exits 2 with no JSON and
		// the operator re-runs after the node has checkpointed at the tip.
		if exit := requireCheckpointAtCanonicalTip(cfg.DataDir, chainStatePath, chainState, stderr); exit != 0 {
			return exit
		}
		report := buildLegacyExposureReport(cfg.Network, cfg.DataDir, chainState, watchedSuiteIDs, *legacyExposureIncludeOutpoints)
		if err := printLegacyExposureReport(stdout, report); err != nil {
			_, _ = fmt.Fprintf(stderr, "legacy exposure encode failed: %v\n", err)
			return 1
		}
		return 0
	}
	if cfg.Network != "devnet" && strings.TrimSpace(*genesisFile) == "" {
		_, _ = fmt.Fprintf(stderr, "error: --network %s requires a genesis file (--genesis-file) with chain_id and genesis_hash\n", cfg.Network)
		return 2
	}
	genesisCfg, err := parseGenesisConfigFull(*genesisFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid genesis file: %v\n", err)
		return 2
	}
	// Genesis-identity guards run BEFORE the storage lifecycle
	// (createOrOpenBlockStore below). A wrong devnet chain_id /
	// genesis_hash, or a misconfigured mainnet runtime, must reject on a
	// clean filesystem so operators do not end up with partial datadir /
	// chainstate / blockstore artifacts that the next startup would have
	// to detect and recover. Both validators are pure functions over the
	// already-parsed config; failure paths only print to stderr and
	// return exit code 2.
	if cfg.Network == "devnet" {
		if err := node.ValidateDevnetGenesisIdentity(genesisCfg.ChainID, genesisCfg.GenesisHash); err != nil {
			_, _ = fmt.Fprintf(stderr, "devnet genesis identity guard failed: %v\n", err)
			return 2
		}
	}
	if err := node.ValidateMainnetGenesisGuard(node.SyncConfig{Network: cfg.Network}); err != nil {
		_, _ = fmt.Fprintf(stderr, "mainnet genesis guard failed: %v\n", err)
		return 2
	}
	// Storage lifecycle runs BEFORE the chainstate load: an uninitialized or
	// half-initialized store must reject before anything reads or writes
	// chainstate. Ordinary startup performs no mkdir at all.
	blockStore, datadirLock, storeExit := createOrOpenBlockStore(cfg.DataDir, chainStatePath, *createStore, *dryRun, stderr)
	if storeExit != 0 {
		return storeExit
	}
	if datadirLock != nil {
		defer func() { _ = datadirLock.Release() }()
	}
	if !*dryRun {
		var reclaimErr error
		if *createStore {
			reclaimErr = node.ReclaimAtomicWriteScratchInParent(cfg.DataDir)
		} else {
			reclaimErr = node.ReclaimAtomicWriteScratch(cfg.DataDir)
		}
		if reclaimErr != nil {
			_, _ = fmt.Fprintf(stderr, "%v\n", reclaimErr)
			return 2
		}
	}
	chainState, err := node.LoadChainState(chainStatePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "chainstate load failed: %v\n", err)
		return 2
	}
	chainIDFromGenesis := genesisCfg.ChainID
	genesisHashFromGenesis := genesisCfg.GenesisHash
	var zeroChainID [32]byte
	if chainIDFromGenesis != zeroChainID {
		cfg.ChainID = fmt.Sprintf("%x", chainIDFromGenesis[:])
	}
	// Wire rotation descriptor from config into ChainState.
	rotation, registry, err := cfg.BuildRotationProvider()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rotation config failed: %v\n", err)
		return 2
	}
	chainState.Rotation = rotation
	chainState.Registry = registry
	syncCfg := node.DefaultSyncConfig(nil, chainIDFromGenesis, chainStatePath)
	syncCfg.Network = cfg.Network
	applySuiteContextToSyncConfig(&syncCfg, rotation, registry)
	syncCfg.ParallelValidationMode = *pvMode
	syncCfg.PVShadowMaxSamples = *pvShadowMax
	// Genesis-identity guards (devnet ValidateDevnetGenesisIdentity and
	// mainnet ValidateMainnetGenesisGuard) ran above the storage lifecycle, so
	// any malformed pack or misconfigured mainnet runtime has already
	// rejected on a clean filesystem. NewSyncEngine still re-runs the
	// mainnet guard internally for embedded / test callers that
	// construct an engine directly with a custom SyncConfig.
	// Reconcile + save BEFORE constructing the sync engine. Rust mirror
	// in clients/rust/crates/rubin-node/src/main.rs: the contract is
	// that chainstate is persisted to disk BEFORE any sync / P2P / RPC /
	// miner thread can observe it, so a post-reconcile crash cannot
	// expose a chainstate whose claimed tip disagrees with the canonical
	// index. The reconcile itself writes nothing: a canonical index
	// declaring committed entries whose header/block/undo set is
	// incomplete is refused rather than truncated or repaired, so that
	// datadir exits 2 here and reaches no service start. If chainState.Save
	// fails after a successful reconcile, the canonical index on disk is
	// untouched but the chainstate snapshot may be stale; the next startup
	// detects this via height/tip mismatch and resets and replays, or
	// replays forward from its snapshot height — correct, just wasteful on
	// large chains. If the sync engine constructor itself fails later, the
	// chainstate saved above is durable on disk.
	//
	// NONE of the three steps runs under --dry-run, which reports the datadir
	// and must not change it: Save WOULD rewrite the snapshot (temp file +
	// rename, so a fresh inode) on every single invocation, the reconcile
	// WOULD reset the in-memory chainstate the banners report, and
	// VerifyGenesisAnchor is skipped for the reason in the inner comment below.
	// The banners therefore describe the RAW snapshot as loaded from disk — a
	// snapshot that disagrees with the blockstore is reported, not fixed, and a
	// datadir the mutating path would refuse is shown intact. Ordinary startup
	// is unaffected by this gate: same three calls, same order, same exit codes.
	if !*dryRun {
		// RUB-1134 genesis anchor: a non-empty canonical index whose row 0 is
		// not the configured genesis hash is a foreign datadir. Checked BEFORE
		// the reconcile so no replay or adoption consumes a foreign index; an
		// empty index skips it. --dry-run adopts nothing, so the anchor is
		// enforced only on this mutating path, as in the Rust mirror.
		if err := blockStore.VerifyGenesisAnchor(genesisHashFromGenesis); err != nil {
			_, _ = fmt.Fprintf(stderr, "canonical index genesis anchor failed: %v\n", err)
			return 2
		}
		if _, err := node.ReconcileChainStateWithBlockStore(chainState, blockStore, syncCfg); err != nil {
			_, _ = fmt.Fprintf(stderr, "chainstate reconcile failed: %v\n", err)
			return 2
		}
		if err := chainState.Save(chainStatePath); err != nil {
			_, _ = fmt.Fprintf(stderr, "chainstate save failed: %v\n", err)
			return 2
		}
	}
	syncEngine, err := newSyncEngineFn(
		chainState,
		blockStore,
		syncCfg,
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sync engine init failed: %v\n", err)
		return 2
	}
	mempoolCfg := node.DefaultMempoolConfig()
	mempoolCfg.MaxTransactions = cfg.MempoolMaxTxs
	mempoolCfg.MaxBytes = cfg.MempoolMaxBytes
	mempool, err := newMempoolFn(chainState, blockStore, chainIDFromGenesis, mempoolCfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mempool init failed: %v\n", err)
		return 2
	}
	syncEngine.SetMempool(mempool)
	if syncEngine.DARelayState() == nil {
		_, _ = fmt.Fprintln(stderr, "DA relay state init failed")
		return 2
	}
	syncEngine.SetStderr(stderr)
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig(cfg.Network, cfg.MaxPeers))

	tipHeight, tipHash, tipOK, err := blockStore.Tip()
	tipHeight, tipHash, tipOK, tipExitCode := mustTipFn(tipHeight, tipHash, tipOK, err, stderr)
	if tipExitCode != 0 {
		return tipExitCode
	}
	if tipOK {
		syncEngine.RecordBestKnownHeight(tipHeight)
	}

	if err := printConfig(stdout, cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "config encode failed: %v\n", err)
		return 1
	}
	if tipOK {
		_, _ = fmt.Fprintf(stdout, "chainstate: has_tip=%v height=%d utxos=%d already_generated=%s tip=%x\n", chainState.HasTip, chainState.Height, len(chainState.Utxos), chainState.AlreadyGenerated.String(), chainState.TipHash)
		_, _ = fmt.Fprintf(stdout, "blockstore: tip_height=%d tip_hash=%x\n", tipHeight, tipHash) // #nosec G705 -- plain-text CLI diagnostics to stdout, not HTML/template output.
	} else {
		_, _ = fmt.Fprintf(stdout, "chainstate: has_tip=%v height=%d utxos=%d already_generated=%s\n", chainState.HasTip, chainState.Height, len(chainState.Utxos), chainState.AlreadyGenerated.String())
		_, _ = fmt.Fprintln(stdout, "blockstore: empty")
	}
	if *featurebitsDeploymentsPath != "" && tipOK {
		nextHeight := tipHeight + 1
		if err := printFeatureBitsTelemetryRows(stdout, blockStore, nextHeight, featureBitDeployments); err != nil {
			_, _ = fmt.Fprintf(stderr, "featurebits telemetry failed: %v\n", err)
			return 2
		}
	}
	headerReq := syncEngine.HeaderSyncRequest()
	_, _ = fmt.Fprintf(stdout, "sync: header_request_has_from=%v header_request_limit=%d ibd=%v\n", headerReq.HasFrom, headerReq.Limit, syncEngine.IsInIBD(nowUnixU64()))
	_, _ = fmt.Fprintf(stdout, "p2p: peer_slots=%d connected=%d\n", cfg.MaxPeers, len(peerManager.Snapshot()))
	if *dryRun {
		return 0
	}
	if *mineBlocks > 0 {
		minerCfg := node.DefaultMinerConfig()
		if mineAddress != nil {
			minerCfg.MineAddress = mineAddress
		}
		minerCfg.CurrentMempoolMinFeeRateFn = mempool.CurrentMinFeeRateSnapshot
		miner, err := newMinerFn(chainState, blockStore, syncEngine, minerCfg)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "miner init failed: %v\n", err)
			return 2
		}
		mined, err := miner.MineN(context.Background(), *mineBlocks, nil)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "mining failed: %v\n", err)
			return 2
		}
		for _, b := range mined {
			_, _ = fmt.Fprintf(stdout, "mined: height=%d hash=%x timestamp=%d nonce=%d tx_count=%d\n", b.Height, b.Hash, b.Timestamp, b.Nonce, b.TxCount)
		}
		if *mineExit {
			return 0
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	p2pService, err := newP2PServiceFn(p2p.ServiceConfig{
		BindAddr:          cfg.BindAddr,
		BootstrapPeers:    cfg.Peers,
		UserAgent:         "rubin-node/go",
		GenesisHash:       genesisHashFromGenesis,
		PeerRuntimeConfig: node.DefaultPeerRuntimeConfig(cfg.Network, cfg.MaxPeers),
		PeerManager:       peerManager,
		SyncConfig:        syncCfg,
		SyncEngine:        syncEngine,
		BlockStore:        blockStore,
		TxPool:            p2p.NewCanonicalMempoolTxPool(mempool),
		TxMetadataFunc:    p2p.CanonicalMempoolRelayMetadata,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "p2p init failed: %v\n", err)
		return 2
	}
	// The P2P runtime parent is deliberately context.Background(), not the
	// signal ctx: signal delivery must not cancel the P2P runtime before the
	// deferred RPC drain below has returned. p2p.Service.Close (deferred on
	// the next line, so LIFO unwinds it after the later-registered RPC close)
	// owns the P2P runtime cancellation.
	if err := p2pService.Start(context.Background()); err != nil {
		_, _ = fmt.Fprintf(stderr, "p2p start failed: %v\n", err)
		return 2
	}
	defer p2pService.Close()
	var liveMiner *node.Miner
	if cfg.Network == "devnet" && strings.TrimSpace(cfg.RPCBindAddr) != "" && rpcBindHostIsLoopback(cfg.RPCBindAddr) {
		minerCfg := node.DefaultMinerConfig()
		// Reuses the single parse above. A rejected --mine-address never
		// reaches this site: it exits 2 at config validation, so live mining
		// is no longer silently disabled on operator input the startup check
		// should have refused.
		if mineAddress != nil {
			minerCfg.MineAddress = mineAddress
		}
		minerCfg.CurrentMempoolMinFeeRateFn = mempool.CurrentMinFeeRateSnapshot
		minerCfg.CompleteDASetProvider = p2pService
		liveMiner, err = newMinerFn(chainState, blockStore, syncEngine, minerCfg)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "rpc: live mining disabled: %v\n", err)
			liveMiner = nil
		}
	}
	// newDevnetRPCStateWithLifecycle is the canonical production wiring:
	// it combines newDevnetRPCState with state.SetShutdownCtx so the
	// readiness gate observes the lifecycle ctx instead of the
	// placeholder context.TODO() the bare constructor seeds. The helper
	// runs BEFORE startDevnetRPCServer so any /ready handler that races
	// the boot-time TryMarkReadyOnStartup sees shutdownCtx through the
	// gate's locked IsReady, not via raw state. Tests use the same
	// helper to keep production-wiring and regression-wiring paths
	// identical.
	rpcState := newDevnetRPCStateWithLifecycle(syncEngine, blockStore, mempool, peerManager, p2pService.AnnounceTx, p2pService.AnnounceBlock, stderr, liveMiner, ctx)
	rpcState.SetAcceptedBlockDASetConsumer(p2pService.ConsumeAcceptedBlockDASets)
	// Late-bind the startup-wired chain identity so the read-only
	// /chain_identity handler echoes the values that already flowed
	// through genesis parsing + network canonicalization, rather than
	// synthesizing devnet constants inside the handler. Done in one
	// place after newDevnetRPCStateWithLifecycle so production wiring
	// matches the regression-test wiring path that calls SetIdentity
	// directly.
	rpcState.SetIdentity(cfg.Network, chainIDFromGenesis, genesisHashFromGenesis)
	// Bind the peer-lifecycle-exit closure so /metrics rendering can
	// observe the running *p2p.Service counter without cmd/rubin-node's
	// RPC state taking a structural dependency on the p2p package —
	// same indirection pattern as p2pService.AnnounceTx above.
	rpcState.SetPeerLifecycleExitsFunc(p2pService.PeerLifecycleExits)
	rpcServer, err := startDevnetRPCServer(cfg.RPCBindAddr, rpcState, stdout, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rpc start failed: %v\n", err)
		return 2
	}
	if rpcServer != nil {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = rpcServer.Close(shutdownCtx)
		}()
	}

	// Boot-time readiness transition. The gate's TryMarkReadyOnStartup
	// observes the wired shutdownCtx atomically with the state
	// transition: if SIGINT or SIGTERM was already observed in the
	// window between the gate wiring above and this call site, the
	// gate stamps Shutdown and the transition fails. The "rpc:
	// ready=%v" stdout banner is runtime evidence (the printed value
	// is the post-call IsReady() readback, which itself observes
	// shutdownCtx under the gate's mutex) — not the operator signal
	// itself. The operator signal is the GET /ready 200 response; the
	// banner exists so subprocess regression tests can pin that the
	// transition was attempted at this exact call site.
	maybeFlipReadyOnStartup(rpcServer, stdout)
	_, _ = fmt.Fprintln(stdout, "rubin-node skeleton running")
	<-ctx.Done()
	// At the start of shutdown drain, stamp the gate Shutdown — the
	// durable sticky transition. Subsequent gate decisions
	// (TryMarkReadyOnStartup or IsReady) that observe a canceled
	// shutdownCtx via observeShutdownLocked also stamp Shutdown, so
	// in many interleavings the gate is already Shutdown before this
	// MarkShutdown call runs; the explicit call ensures the stamp is
	// durable independent of whether shutdownCtx is later replaced
	// or cleared.
	//
	// Contract intentionally limited per the accepted residual
	// non-goal documented on readinessGate: every NEW gate decision
	// after ctx is observed canceled returns false; a /ready handler
	// already inside the gate's lock when the signal arrives may
	// complete its 200 response with the previously captured Ready
	// snapshot. Strict request-time arbitration requires a broader
	// Class-C lifecycle/control-plane owner and is out of scope.
	//
	// The "rpc: ready=%v" banner reads the post-stamp IsReady() so
	// its literal value tracks the gate state; deleting or moving
	// MarkShutdown past the print would still leave the banner
	// reading "false" because IsReady's locked observation also
	// stamps Shutdown when shutdownCtx is canceled.
	if rpcServer != nil {
		rpcServer.MarkShutdown()
		_, _ = fmt.Fprintf(stdout, "rpc: ready=%v\n", rpcServer.IsReady())
	}
	_, _ = fmt.Fprintln(stdout, "rubin-node skeleton stopped")
	return 0
}

type featureBitDeploymentJSON struct {
	Name             string  `json:"name"`
	Bit              uint8   `json:"bit"`
	StartHeight      uint64  `json:"start_height"`
	TimeoutHeight    uint64  `json:"timeout_height"`
	ActivationHeight *uint64 `json:"activation_height,omitempty"`
}

type headerStore interface {
	CanonicalHash(height uint64) ([32]byte, bool, error)
	GetHeaderByHash(hash [32]byte) ([]byte, error)
}

// loadFeatureBitDeployments reads, parses, and validates a
// --featurebits-deployments file without touching the blockstore: the
// bounded config read (RUB-1062 rider A; see node.ReadConfigFile for the
// ceiling derivation), the JSON decode, and the per-row consensus
// validation that FeatureBitStateAtHeightFromWindowCounts would otherwise
// report only at telemetry time. It is the validation-only half of the
// telemetry path, hoisted so run() can reject an invalid file before any
// filesystem or service side effect (RUB-876).
func loadFeatureBitDeployments(deploymentsPath string) ([]featureBitDeploymentJSON, error) {
	raw, err := node.ReadConfigFile(filepath.Clean(deploymentsPath))
	if err != nil {
		return nil, err
	}
	var ds []featureBitDeploymentJSON
	if err := json.Unmarshal(raw, &ds); err != nil {
		return nil, err
	}
	for _, dj := range ds {
		d := consensus.FeatureBitDeployment{
			Name:          dj.Name,
			Bit:           dj.Bit,
			StartHeight:   dj.StartHeight,
			TimeoutHeight: dj.TimeoutHeight,
		}
		if err := d.Validate(); err != nil {
			return nil, err
		}
	}
	return ds, nil
}

func printFeatureBitsTelemetryRows(w io.Writer, bs headerStore, height uint64, ds []featureBitDeploymentJSON) error {
	for _, dj := range ds {
		d := consensus.FeatureBitDeployment{
			Name:          dj.Name,
			Bit:           dj.Bit,
			StartHeight:   dj.StartHeight,
			TimeoutHeight: dj.TimeoutHeight,
		}
		boundaryHeight := height - (height % consensus.SIGNAL_WINDOW)
		targetBoundaryIndex := boundaryHeight / consensus.SIGNAL_WINDOW

		counts := make([]uint32, targetBoundaryIndex)
		if targetBoundaryIndex > 0 {
			firstBoundary := ((d.StartHeight + consensus.SIGNAL_WINDOW - 1) / consensus.SIGNAL_WINDOW) * consensus.SIGNAL_WINDOW
			startWindowIndex := firstBoundary / consensus.SIGNAL_WINDOW
			for win := startWindowIndex; win < targetBoundaryIndex; win++ {
				cnt, err := countSignalsInWindow(bs, win, d.Bit)
				if err != nil {
					return err
				}
				counts[win] = cnt
			}
		}

		ev, err := consensus.FeatureBitStateAtHeightFromWindowCounts(d, height, counts)
		if err != nil {
			return err
		}
		consensusActive := ""
		if dj.ActivationHeight != nil {
			active := height >= *dj.ActivationHeight
			consensusActive = fmt.Sprintf(" consensus_active=%t activation_height=%d", active, *dj.ActivationHeight)
		}
		_, _ = fmt.Fprintf( // #nosec G705 -- plain-text featurebits telemetry to CLI output, not HTML/template output.
			w,
			"featurebits: name=%s bit=%d height=%d boundary=%d state=%s prev_window_signal_count=%d%s\n",
			d.Name,
			d.Bit,
			height,
			ev.BoundaryHeight,
			ev.State,
			ev.PrevWindowSignalCnt,
			consensusActive,
		)
	}
	return nil
}

func countSignalsInWindow(bs headerStore, windowIndex uint64, bit uint8) (uint32, error) {
	var count uint32
	start := windowIndex * consensus.SIGNAL_WINDOW
	end := start + consensus.SIGNAL_WINDOW - 1
	for h := start; h <= end; h++ {
		hash, ok, err := bs.CanonicalHash(h)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, fmt.Errorf("missing canonical hash at height %d", h)
		}
		headerBytes, err := bs.GetHeaderByHash(hash)
		if err != nil {
			return 0, err
		}
		header, err := consensus.ParseBlockHeaderBytes(headerBytes)
		if err != nil {
			return 0, err
		}
		if ((header.Version >> bit) & 1) == 1 {
			count++
		}
	}
	return count, nil
}

func printConfig(w io.Writer, cfg node.Config) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}

func nowUnixU64() uint64 {
	now := nowUnix()
	if now <= 0 {
		return 0
	}
	return uint64(now)
}

type genesisPack struct {
	ChainIDHex            string `json:"chain_id_hex"`
	GenesisHashHex        string `json:"genesis_hash_hex"`
	GenesisBlockHashHex   string `json:"genesis_block_hash_hex"`
	GenesisHeaderBytesHex string `json:"genesis_header_bytes_hex"`
}

type parsedGenesisConfig struct {
	ChainID     [32]byte
	GenesisHash [32]byte
}

// maybeFlipReadyOnStartup attempts the boot-time readiness gate
// transition NotReady → Ready via TryMarkReadyOnStartup. The gate
// observes its wired shutdownCtx under its own mutex, so this helper
// does NOT pass ctx as a parameter — the synchronization boundary is
// internal to the gate. If SIGINT/SIGTERM was already observed before
// this helper runs, the gate's locked observe-then-decide path stamps
// Shutdown and the transition fails. The stdout audit banner reads
// the post-call IsReady() (which itself observes shutdownCtx under
// the gate's mutex), so its literal value reflects the gate's actual
// post-transition state. Regression coverage does not treat
// "rpc: ready=false" as a failure here: that banner is expected for
// pre-canceled/Shutdown states. The guarded regression is the inverse
// case — if shutdown is not observed under lock and the helper reports
// an incorrect "rpc: ready=true", the corresponding test assertion
// fails.
//
// Nil-receiver safe: --rpc-bind "" path leaves rpcServer == nil and
// this helper returns without writing the banner.
func maybeFlipReadyOnStartup(rpcServer *runningDevnetRPCServer, stdout io.Writer) {
	if rpcServer == nil {
		return
	}
	// Locked transition inside the gate. Return value is intentionally
	// not gating the banner — the banner exists to prove the helper
	// reached this exact call site and to surface the gate's
	// post-transition state. If the transition lost (gate observed
	// shutdownCtx canceled), the banner reads "false".
	rpcServer.TryMarkReadyOnStartup()
	if stdout != nil {
		_, _ = fmt.Fprintf(stdout, "rpc: ready=%v\n", rpcServer.IsReady())
	}
}

func parseGenesisConfig(path string) ([32]byte, [32]byte, error) {
	cfg, err := parseGenesisConfigFull(path)
	return cfg.ChainID, cfg.GenesisHash, err
}

func parseGenesisConfigFull(path string) (parsedGenesisConfig, error) {
	cfg := parsedGenesisConfig{
		ChainID:     node.DevnetGenesisChainID(),
		GenesisHash: node.DevnetGenesisBlockHash(),
	}
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}
	// Operator config read, bounded pre-allocation (RUB-1062 rider A; see
	// node.ReadConfigFile for the ceiling derivation).
	raw, err := node.ReadConfigFile(filepath.Clean(path))
	if err != nil {
		return cfg, err
	}
	if err := rejectRemovedGenesisCoreExtKeys(raw); err != nil {
		return cfg, err
	}
	var payload genesisPack
	if err := json.Unmarshal(raw, &payload); err != nil {
		return cfg, err
	}
	cfg.ChainID, err = parseHex32Field("chain_id", payload.ChainIDHex)
	if err != nil {
		return cfg, err
	}
	cfg.GenesisHash, err = parseGenesisHash(payload)
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

func rejectRemovedGenesisCoreExtKeys(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, key := range []string{"core_ext_profiles", "core_ext_profile_set_anchor_hex"} {
		if _, ok := fields[key]; ok {
			return fmt.Errorf("unsupported genesis field %q: Go node CORE_EXT profile wiring was removed", key)
		}
	}
	return nil
}

func parseGenesisChainID(path string) ([32]byte, error) {
	chainID, _, err := parseGenesisConfig(path)
	return chainID, err
}

func parseGenesisHash(payload genesisPack) ([32]byte, error) {
	if strings.TrimSpace(payload.GenesisHashHex) != "" {
		return parseHex32Field("genesis_hash", payload.GenesisHashHex)
	}
	if strings.TrimSpace(payload.GenesisBlockHashHex) != "" {
		return parseHex32Field("genesis_block_hash", payload.GenesisBlockHashHex)
	}
	headerHex := strings.TrimSpace(payload.GenesisHeaderBytesHex)
	if headerHex == "" {
		var zero [32]byte
		return zero, fmt.Errorf("genesis hash missing")
	}
	headerHex = trimHexPrefix(headerHex)
	headerBytes, err := hex.DecodeString(headerHex)
	if err != nil {
		var zero [32]byte
		return zero, err
	}
	if len(headerBytes) != consensus.BLOCK_HEADER_BYTES {
		var zero [32]byte
		return zero, fmt.Errorf("genesis_header_bytes must be %d bytes, got %d", consensus.BLOCK_HEADER_BYTES, len(headerBytes))
	}
	return consensus.BlockHash(headerBytes)
}

func parseHex32Field(name, value string) ([32]byte, error) {
	var out [32]byte
	value = strings.TrimSpace(value)
	if value == "" {
		return out, fmt.Errorf("%s_hex missing", name)
	}
	rawValue, err := hex.DecodeString(trimHexPrefix(value))
	if err != nil {
		return out, err
	}
	if len(rawValue) != len(out) {
		return out, fmt.Errorf("%s must be 32 bytes, got %d", name, len(rawValue))
	}
	copy(out[:], rawValue)
	return out, nil
}

func trimHexPrefix(value string) string {
	value = strings.TrimPrefix(value, "0x")
	value = strings.TrimPrefix(value, "0X")
	return value
}

func mustTip(tipHeight uint64, tipHash [32]byte, tipOK bool, err error, stderr io.Writer) (uint64, [32]byte, bool, int) {
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "blockstore tip read failed: %v\n", err)
		var zero [32]byte
		return 0, zero, false, 2
	}
	return tipHeight, tipHash, tipOK, 0
}
