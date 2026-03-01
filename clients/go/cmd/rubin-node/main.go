package main

import (
	"context"
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
)

var nowUnix = func() int64 { return time.Now().Unix() }

var mustTipFn = mustTip

var newMinerFn = node.NewMiner

var newSyncEngineFn = node.NewSyncEngine

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
	fs.StringVar(&cfg.LogLevel, "log-level", defaults.LogLevel, "log level: debug|info|warn|error")
	fs.IntVar(&cfg.MaxPeers, "max-peers", defaults.MaxPeers, "max connected peers")
	mineBlocks := fs.Int("mine-blocks", 0, "mine N blocks locally after startup")
	mineExit := fs.Bool("mine-exit", false, "exit immediately after local mining")
	featurebitsDeploymentsPath := fs.String("featurebits-deployments", "", "path to JSON file with featurebit deployments (telemetry-only)")
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
	syncEngine, err := newSyncEngineFn(
		chainState,
		blockStore,
		func() node.SyncConfig {
			syncCfg := node.DefaultSyncConfig(nil, [32]byte{}, chainStatePath)
			syncCfg.Network = cfg.Network
			return syncCfg
		}(),
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sync engine init failed: %v\n", err)
		return 2
	}
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig(cfg.Network, cfg.MaxPeers))

	tipHeight, tipHash, tipOK, err := blockStore.Tip()
	tipHeight, tipHash, tipOK, tipExitCode := mustTipFn(tipHeight, tipHash, tipOK, err, stderr)
	if tipExitCode != 0 {
		return tipExitCode
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
		miner, err := newMinerFn(chainState, blockStore, syncEngine, node.DefaultMinerConfig())
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

	_, _ = fmt.Fprintln(stdout, "rubin-node skeleton running")
	<-ctx.Done()
	_, _ = fmt.Fprintln(stdout, "rubin-node skeleton stopped")
	return 0
}

type featureBitDeploymentJSON struct {
	Name          string `json:"name"`
	Bit           uint8  `json:"bit"`
	StartHeight   uint64 `json:"start_height"`
	TimeoutHeight uint64 `json:"timeout_height"`
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
		_, _ = fmt.Fprintf(
			w,
			"featurebits: name=%s bit=%d height=%d boundary=%d state=%s prev_window_signal_count=%d\n",
			d.Name,
			d.Bit,
			height,
			ev.BoundaryHeight,
			ev.State,
			ev.PrevWindowSignalCnt,
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

func mustTip(tipHeight uint64, tipHash [32]byte, tipOK bool, err error, stderr io.Writer) (uint64, [32]byte, bool, int) {
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "blockstore tip read failed: %v\n", err)
		var zero [32]byte
		return 0, zero, false, 2
	}
	return tipHeight, tipHash, tipOK, 0
}
