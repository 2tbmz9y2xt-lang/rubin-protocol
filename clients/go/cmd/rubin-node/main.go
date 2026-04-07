package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node/p2p"
)

var nowUnix = func() int64 { return time.Now().Unix() }

var mustTipFn = mustTip

var newMinerFn = node.NewMiner

var newSyncEngineFn = node.NewSyncEngine

var newMempoolFn = node.NewMempoolWithConfig

func applySuiteContextToSyncConfig(cfg *node.SyncConfig, rotation consensus.RotationProvider, registry *consensus.SuiteRegistry) {
	if cfg == nil {
		return
	}
	cfg.RotationProvider = rotation
	cfg.SuiteRegistry = registry
}

const legacyExposureReportVersion = 1

type legacyExposureSuiteReport struct {
	SuiteID           uint8     `json:"suite_id"`
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
	IndexedSuiteIDs       []uint8                     `json:"indexed_suite_ids"`
	WatchedLegacySuiteIDs []uint8                     `json:"watched_legacy_suite_ids"`
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

func legacyExposureHooks(total uint64) (string, string, string) {
	if total == 0 {
		return "ready_for_operator_defined_grace_window", "none", "start_operator_defined_grace_window"
	}
	return "not_ready_legacy_exposure_present", "legacy_exposure_present_notify_operator_and_council", "not_applicable_legacy_exposure_present"
}

func saturatingAddUint64(total, value uint64) uint64 {
	if value > ^uint64(0)-total {
		return ^uint64(0)
	}
	return total + value
}

func buildLegacyExposureReport(network, dataDir string, chainState *node.ChainState, legacySuiteIDs []uint8, includeOutpoints bool) legacyExposureReport {
	reports := make([]legacyExposureSuiteReport, 0, len(legacySuiteIDs))
	var total uint64
	for _, suiteID := range legacySuiteIDs {
		count := chainState.UtxoExposureCountBySuiteID(suiteID)
		report := legacyExposureSuiteReport{
			SuiteID:           suiteID,
			UtxoExposureCount: count,
			OutpointCount:     count,
		}
		if includeOutpoints {
			outpoints := chainState.UtxoOutpointsBySuiteID(suiteID)
			report.OutpointCount = uint64(len(outpoints))
			reportOutpoints := make([]string, 0, len(outpoints))
			for _, op := range outpoints {
				reportOutpoints = append(reportOutpoints, formatLegacyExposureOutpoint(op))
			}
			report.Outpoints = &reportOutpoints
		}
		total = saturatingAddUint64(total, count)
		reports = append(reports, report)
	}
	sunsetReadiness, warningHook, graceHook := legacyExposureHooks(total)
	return legacyExposureReport{
		ReportVersion:         legacyExposureReportVersion,
		MeasurementScope:      "explicit_suite_id_utxos",
		Network:               network,
		DataDir:               dataDir,
		ChainstateHeight:      chainState.Height,
		ChainstateHasTip:      chainState.HasTip,
		IndexedSuiteIDs:       chainState.IndexedSuiteIDs(),
		WatchedLegacySuiteIDs: legacySuiteIDs,
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
	genesisFile := fs.String("genesis-file", "", "path to genesis pack JSON with chain_id_hex, genesis hash, and optional core_ext_profiles")
	fs.IntVar(&cfg.MaxPeers, "max-peers", defaults.MaxPeers, "max connected peers")
	fs.StringVar(&cfg.MineAddress, "mine-address", "", "miner pubkey: 64-char hex key_id or 66-char hex suite_id||key_id")
	mineBlocks := fs.Int("mine-blocks", 0, "mine N blocks locally after startup")
	mineExit := fs.Bool("mine-exit", false, "exit immediately after local mining")
	featurebitsDeploymentsPath := fs.String("featurebits-deployments", "", "path to JSON file with featurebit deployments (telemetry-only)")
	pvMode := fs.String("pv-mode", "off", "parallel validation mode: off|shadow|on (truth path is sequential)")
	pvShadowMax := fs.Uint64("pv-shadow-max", 3, "max pv shadow mismatch samples to record/print (bounded)")
	legacyExposureScan := fs.Bool("legacy-exposure-scan", false, "emit legacy suite exposure report and exit")
	fs.Var(&legacySuiteIDs, "legacy-suite-id", "legacy suite_id to watch (decimal or 0xNN); repeatable")
	legacyExposureIncludeOutpoints := fs.Bool("legacy-exposure-include-outpoints", false, "include deterministic outpoint lists in legacy exposure report")
	dryRun := fs.Bool("dry-run", false, "print effective config and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	cfg.Peers = node.NormalizePeers(append([]string{*peerCSV}, peers...)...)
	if err := node.ValidateConfig(cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid config: %v\n", err)
		return 2
	}
	if canonicalNetwork, ok := node.CanonicalNetworkName(cfg.Network); ok {
		cfg.Network = canonicalNetwork
	}
	if *legacyExposureScan {
		var err error
		watchedSuiteIDs, err = normalizeLegacySuiteIDs([]string(legacySuiteIDs))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "legacy exposure scan config failed: %v\n", err)
			return 2
		}
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		_, _ = fmt.Fprintf(stderr, "datadir create failed: %v\n", err)
		return 2
	}
	chainStatePath := node.ChainStatePath(cfg.DataDir)
	chainState, err := node.LoadChainState(chainStatePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "chainstate load failed: %v\n", err)
		return 2
	}
	if *legacyExposureScan {
		report := buildLegacyExposureReport(cfg.Network, cfg.DataDir, chainState, watchedSuiteIDs, *legacyExposureIncludeOutpoints)
		if err := printLegacyExposureReport(stdout, report); err != nil {
			_, _ = fmt.Fprintf(stderr, "legacy exposure encode failed: %v\n", err)
			return 1
		}
		return 0
	}
	genesisCfg, err := parseGenesisConfigFull(*genesisFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid genesis file: %v\n", err)
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
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(cfg.DataDir))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "blockstore open failed: %v\n", err)
		return 2
	}
	syncCfg := node.DefaultSyncConfig(nil, chainIDFromGenesis, chainStatePath)
	syncCfg.Network = cfg.Network
	syncCfg.CoreExtProfiles = genesisCfg.CoreExtProfiles
	applySuiteContextToSyncConfig(&syncCfg, rotation, registry)
	syncCfg.ParallelValidationMode = *pvMode
	syncCfg.PVShadowMaxSamples = *pvShadowMax
	syncEngine, err := newSyncEngineFn(
		chainState,
		blockStore,
		syncCfg,
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sync engine init failed: %v\n", err)
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
	mempoolCfg := node.DefaultMempoolConfig()
	mempoolCfg.CoreExtProfiles = genesisCfg.CoreExtProfiles
	mempool, err := newMempoolFn(chainState, blockStore, chainIDFromGenesis, mempoolCfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mempool init failed: %v\n", err)
		return 2
	}
	syncEngine.SetMempool(mempool)
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
		_, _ = fmt.Fprintf(stdout, "chainstate: has_tip=%v height=%d utxos=%d already_generated=%d tip=%x\n", chainState.HasTip, chainState.Height, len(chainState.Utxos), chainState.AlreadyGenerated, chainState.TipHash)
		_, _ = fmt.Fprintf(stdout, "blockstore: tip_height=%d tip_hash=%x\n", tipHeight, tipHash) // #nosec G705 -- plain-text CLI diagnostics to stdout, not HTML/template output.
	} else {
		_, _ = fmt.Fprintf(stdout, "chainstate: has_tip=%v height=%d utxos=%d already_generated=%d\n", chainState.HasTip, chainState.Height, len(chainState.Utxos), chainState.AlreadyGenerated)
		_, _ = fmt.Fprintln(stdout, "blockstore: empty")
	}
	if *featurebitsDeploymentsPath != "" && tipOK {
		nextHeight := tipHeight + 1
		if err := printFeatureBitsTelemetry(stdout, blockStore, nextHeight, *featurebitsDeploymentsPath); err != nil {
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
		if cfg.MineAddress != "" {
			addrBytes, addrErr := node.ParseMineAddress(cfg.MineAddress)
			if addrErr != nil {
				_, _ = fmt.Fprintf(stderr, "invalid mine-address: %v\n", addrErr)
				return 2
			}
			minerCfg.MineAddress = addrBytes
		}
		minerCfg.CoreExtProfiles = genesisCfg.CoreExtProfiles
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
	p2pService, err := p2p.NewService(p2p.ServiceConfig{
		BindAddr:          cfg.BindAddr,
		BootstrapPeers:    cfg.Peers,
		UserAgent:         "rubin-node/go",
		GenesisHash:       genesisHashFromGenesis,
		PeerRuntimeConfig: node.DefaultPeerRuntimeConfig(cfg.Network, cfg.MaxPeers),
		PeerManager:       peerManager,
		SyncConfig:        syncCfg,
		SyncEngine:        syncEngine,
		BlockStore:        blockStore,
		TxMetadataFunc:    mempool.RelayMetadata,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "p2p init failed: %v\n", err)
		return 2
	}
	if err := p2pService.Start(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "p2p start failed: %v\n", err)
		return 2
	}
	defer p2pService.Close()
	rpcState := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, p2pService.AnnounceTx, stderr)
	rpcServer, err := startDevnetRPCServer(ctx, cfg.RPCBindAddr, rpcState, stdout, stderr)
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

	_, _ = fmt.Fprintln(stdout, "rubin-node skeleton running")
	<-ctx.Done()
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

func printFeatureBitsTelemetry(w io.Writer, bs headerStore, height uint64, deploymentsPath string) error {
	raw, err := os.ReadFile(filepath.Clean(deploymentsPath))
	if err != nil {
		return err
	}
	var ds []featureBitDeploymentJSON
	if err := json.Unmarshal(raw, &ds); err != nil {
		return err
	}
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
	ChainIDHex                 string                  `json:"chain_id_hex"`
	GenesisHashHex             string                  `json:"genesis_hash_hex"`
	GenesisBlockHashHex        string                  `json:"genesis_block_hash_hex"`
	GenesisHeaderBytesHex      string                  `json:"genesis_header_bytes_hex"`
	CoreExtProfiles            []genesisCoreExtProfile `json:"core_ext_profiles,omitempty"`
	CoreExtProfileSetAnchorHex string                  `json:"core_ext_profile_set_anchor_hex,omitempty"`
}

type genesisCoreExtProfile struct {
	ExtID                uint16  `json:"ext_id"`
	ActivationHeight     uint64  `json:"activation_height"`
	TxContextEnabled     bool    `json:"tx_context_enabled,omitempty"`
	AllowedSuiteIDs      []uint8 `json:"allowed_suite_ids,omitempty"`
	Binding              string  `json:"binding,omitempty"`
	BindingDescriptorHex string  `json:"binding_descriptor_hex,omitempty"`
	ExtPayloadSchemaHex  string  `json:"ext_payload_schema_hex,omitempty"`
}

type parsedGenesisConfig struct {
	ChainID         [32]byte
	GenesisHash     [32]byte
	CoreExtProfiles consensus.CoreExtProfileProvider
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
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
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
	cfg.CoreExtProfiles, err = buildGenesisCoreExtProfiles(payload.CoreExtProfiles, cfg.ChainID, payload.CoreExtProfileSetAnchorHex)
	if err != nil {
		return cfg, err
	}
	return cfg, nil
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

const maxCoreExtHexFieldBytes = 4096

func decodeOptionalHexBytesField(name, value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	trimmed := trimHexPrefix(value)
	if (name == "binding_descriptor_hex" || name == "ext_payload_schema_hex") && len(trimmed) > maxCoreExtHexFieldBytes*2 {
		return nil, fmt.Errorf("bad %s", name)
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("bad %s", name)
	}
	return raw, nil
}

func genesisCoreExtBindingIsSupported(binding string) bool {
	switch strings.TrimSpace(binding) {
	case "", "native_verify_sig", consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1:
		return true
	default:
		return false
	}
}

func buildGenesisCoreExtProfiles(items []genesisCoreExtProfile, chainID [32]byte, expectedSetAnchorHex string) (consensus.CoreExtProfileProvider, error) {
	deployments := make([]consensus.CoreExtDeploymentProfile, 0, len(items))
	for _, item := range items {
		binding := strings.TrimSpace(item.Binding)
		if item.TxContextEnabled {
			return nil, fmt.Errorf(
				"tx_context_enabled core_ext profile for ext_id=%d requires runtime txcontext verifier wiring",
				item.ExtID,
			)
		}
		if !genesisCoreExtBindingIsSupported(binding) {
			return nil, fmt.Errorf("unsupported core_ext binding: %s", item.Binding)
		}
		bindingDescriptor, err := decodeOptionalHexBytesField("binding_descriptor_hex", item.BindingDescriptorHex)
		if err != nil {
			return nil, err
		}
		extPayloadSchema, err := decodeOptionalHexBytesField("ext_payload_schema_hex", item.ExtPayloadSchemaHex)
		if err != nil {
			return nil, err
		}
		verifySigExtFn, err := parseCoreExtBinding(binding, bindingDescriptor, extPayloadSchema)
		if err != nil {
			return nil, err
		}
		allowed := make(map[uint8]struct{}, len(item.AllowedSuiteIDs))
		for _, suiteID := range item.AllowedSuiteIDs {
			allowed[suiteID] = struct{}{}
		}
		deployments = append(deployments, consensus.CoreExtDeploymentProfile{
			ExtID:             item.ExtID,
			ActivationHeight:  item.ActivationHeight,
			TxContextEnabled:  item.TxContextEnabled,
			AllowedSuites:     allowed,
			VerifySigExtFn:    verifySigExtFn,
			BindingDescriptor: bindingDescriptor,
			ExtPayloadSchema:  extPayloadSchema,
		})
	}
	if strings.TrimSpace(expectedSetAnchorHex) != "" {
		expectedAnchor, err := parseHex32Field("core_ext_profile_set_anchor", expectedSetAnchorHex)
		if err != nil {
			return nil, err
		}
		actualAnchor, err := consensus.CoreExtProfileSetAnchorV1(chainID, deployments)
		if err != nil {
			return nil, err
		}
		if actualAnchor != expectedAnchor {
			return nil, fmt.Errorf("core_ext profile set anchor mismatch")
		}
	}
	if len(items) == 0 {
		return consensus.NewStaticCoreExtProfileProvider(nil)
	}
	return consensus.NewStaticCoreExtProfileProvider(deployments)
}

func parseCoreExtBinding(binding string, bindingDescriptor []byte, extPayloadSchema []byte) (consensus.CoreExtVerifySigExtFunc, error) {
	binding = strings.TrimSpace(binding)
	if binding == consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1 && len(extPayloadSchema) == 0 {
		return nil, fmt.Errorf("core_ext binding %s requires ext_payload_schema_hex", consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1)
	}
	return consensus.ParseCoreExtVerifySigExtBinding(binding, bindingDescriptor)
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
