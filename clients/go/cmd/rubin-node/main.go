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

var newMempoolFn = node.NewMempool

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

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	defaults := node.DefaultConfig()
	var peers multiStringFlag

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
	genesisFile := fs.String("genesis-file", "", "path to genesis pack JSON with chain_id_hex")
	fs.IntVar(&cfg.MaxPeers, "max-peers", defaults.MaxPeers, "max connected peers")
	fs.StringVar(&cfg.MineAddress, "mine-address", "", "miner pubkey: 64-char hex key_id or 66-char hex suite_id||key_id")
	mineBlocks := fs.Int("mine-blocks", 0, "mine N blocks locally after startup")
	mineExit := fs.Bool("mine-exit", false, "exit immediately after local mining")
	featurebitsDeploymentsPath := fs.String("featurebits-deployments", "", "path to JSON file with featurebit deployments (telemetry-only)")
	dryRun := fs.Bool("dry-run", false, "print effective config and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	cfg.Peers = node.NormalizePeers(append([]string{*peerCSV}, peers...)...)
	chainIDFromGenesis, err := parseGenesisChainID(*genesisFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid genesis file: %v\n", err)
		return 2
	}
	var zeroChainID [32]byte
	if chainIDFromGenesis != zeroChainID {
		cfg.ChainID = fmt.Sprintf("%x", chainIDFromGenesis[:])
	}
	if err := node.ValidateConfig(cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid config: %v\n", err)
		return 2
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
	if err := chainState.Save(chainStatePath); err != nil {
		_, _ = fmt.Fprintf(stderr, "chainstate save failed: %v\n", err)
		return 2
	}

	blockStore, err := node.OpenBlockStore(node.BlockStorePath(cfg.DataDir))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "blockstore open failed: %v\n", err)
		return 2
	}
	syncCfg := node.DefaultSyncConfig(nil, chainIDFromGenesis, chainStatePath)
	syncCfg.Network = cfg.Network
	syncEngine, err := newSyncEngineFn(
		chainState,
		blockStore,
		syncCfg,
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sync engine init failed: %v\n", err)
		return 2
	}
	mempool, err := newMempoolFn(chainState, blockStore, chainIDFromGenesis)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mempool init failed: %v\n", err)
		return 2
	}
	syncEngine.SetMempool(mempool)
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
		_, _ = fmt.Fprintf(stdout, "blockstore: tip_height=%d tip_hash=%x\n", tipHeight, tipHash)
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
		GenesisHash:       node.DevnetGenesisBlockHash(),
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
	rpcState := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, p2pService.AnnounceTx)
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
		_, _ = fmt.Fprintf(
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
	ChainIDHex string `json:"chain_id_hex"`
}

func parseGenesisChainID(path string) ([32]byte, error) {
	var out [32]byte
	if strings.TrimSpace(path) == "" {
		return node.DevnetGenesisChainID(), nil
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return out, err
	}
	var payload genesisPack
	if err := json.Unmarshal(raw, &payload); err != nil {
		return out, err
	}
	chainIDHex := strings.TrimSpace(payload.ChainIDHex)
	if chainIDHex == "" {
		return out, fmt.Errorf("chain_id_hex missing")
	}
	chainIDHex = strings.TrimPrefix(chainIDHex, "0x")
	chainIDHex = strings.TrimPrefix(chainIDHex, "0X")
	rawChainID, err := hex.DecodeString(chainIDHex)
	if err != nil {
		return out, err
	}
	if len(rawChainID) != len(out) {
		return out, fmt.Errorf("chain_id must be 32 bytes, got %d", len(rawChainID))
	}
	copy(out[:], rawChainID)
	return out, nil
}

func mustTip(tipHeight uint64, tipHash [32]byte, tipOK bool, err error, stderr io.Writer) (uint64, [32]byte, bool, int) {
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "blockstore tip read failed: %v\n", err)
		var zero [32]byte
		return 0, zero, false, 2
	}
	return tipHeight, tipHash, tipOK, 0
}
