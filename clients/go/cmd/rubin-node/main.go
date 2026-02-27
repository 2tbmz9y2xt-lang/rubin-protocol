package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

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
	defaults := node.DefaultConfig()
	var peers multiStringFlag

	cfg := defaults
	peerCSV := flag.String("peers", "", "bootstrap peers, comma-separated host:port")
	flag.Var(&peers, "peer", "single bootstrap peer host:port (repeatable)")
	flag.StringVar(&cfg.Network, "network", defaults.Network, "network name (devnet/testnet/mainnet)")
	flag.StringVar(&cfg.DataDir, "datadir", defaults.DataDir, "node data directory")
	flag.StringVar(&cfg.BindAddr, "bind", defaults.BindAddr, "bind address host:port")
	flag.StringVar(&cfg.LogLevel, "log-level", defaults.LogLevel, "log level: debug|info|warn|error")
	flag.IntVar(&cfg.MaxPeers, "max-peers", defaults.MaxPeers, "max connected peers")
	mineBlocks := flag.Int("mine-blocks", 0, "mine N blocks locally after startup")
	mineExit := flag.Bool("mine-exit", false, "exit immediately after local mining")
	dryRun := flag.Bool("dry-run", false, "print effective config and exit")
	flag.Parse()

	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	cfg.Peers = node.NormalizePeers(append([]string{*peerCSV}, peers...)...)
	if err := node.ValidateConfig(cfg); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		os.Exit(2)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "datadir create failed: %v\n", err)
		os.Exit(2)
	}
	chainStatePath := node.ChainStatePath(cfg.DataDir)
	chainState, err := node.LoadChainState(chainStatePath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "chainstate load failed: %v\n", err)
		os.Exit(2)
	}
	if err := chainState.Save(chainStatePath); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "chainstate save failed: %v\n", err)
		os.Exit(2)
	}

	blockStore, err := node.OpenBlockStore(node.BlockStorePath(cfg.DataDir))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "blockstore open failed: %v\n", err)
		os.Exit(2)
	}
	syncEngine, err := node.NewSyncEngine(
		chainState,
		blockStore,
		node.DefaultSyncConfig(nil, [32]byte{}, chainStatePath),
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sync engine init failed: %v\n", err)
		os.Exit(2)
	}
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig(cfg.Network, cfg.MaxPeers))

	tipHeight, tipHash, tipOK, err := blockStore.Tip()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "blockstore tip read failed: %v\n", err)
		os.Exit(2)
	}

	if err := printConfig(cfg); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "config encode failed: %v\n", err)
		os.Exit(1)
	}
	if tipOK {
		_, _ = fmt.Fprintf(os.Stdout, "chainstate: has_tip=%v height=%d utxos=%d already_generated=%d tip=%x\n", chainState.HasTip, chainState.Height, len(chainState.Utxos), chainState.AlreadyGenerated, chainState.TipHash)
		_, _ = fmt.Fprintf(os.Stdout, "blockstore: tip_height=%d tip_hash=%x\n", tipHeight, tipHash)
	} else {
		_, _ = fmt.Fprintf(os.Stdout, "chainstate: has_tip=%v height=%d utxos=%d already_generated=%d\n", chainState.HasTip, chainState.Height, len(chainState.Utxos), chainState.AlreadyGenerated)
		_, _ = fmt.Fprintln(os.Stdout, "blockstore: empty")
	}
	headerReq := syncEngine.HeaderSyncRequest()
	_, _ = fmt.Fprintf(os.Stdout, "sync: header_request_has_from=%v header_request_limit=%d ibd=%v\n", headerReq.HasFrom, headerReq.Limit, syncEngine.IsInIBD(nowUnixU64()))
	_, _ = fmt.Fprintf(os.Stdout, "p2p: peer_slots=%d connected=%d\n", cfg.MaxPeers, len(peerManager.Snapshot()))
	if *dryRun {
		return
	}
	if *mineBlocks > 0 {
		miner, err := node.NewMiner(chainState, blockStore, syncEngine, node.DefaultMinerConfig())
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "miner init failed: %v\n", err)
			os.Exit(2)
		}
		mined, err := miner.MineN(context.Background(), *mineBlocks, nil)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "mining failed: %v\n", err)
			os.Exit(2)
		}
		for _, b := range mined {
			_, _ = fmt.Fprintf(os.Stdout, "mined: height=%d hash=%x timestamp=%d nonce=%d tx_count=%d\n", b.Height, b.Hash, b.Timestamp, b.Nonce, b.TxCount)
		}
		if *mineExit {
			return
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	_, _ = fmt.Fprintln(os.Stdout, "rubin-node skeleton running")
	<-ctx.Done()
	_, _ = fmt.Fprintln(os.Stdout, "rubin-node skeleton stopped")
}

func printConfig(cfg node.Config) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}

func nowUnixU64() uint64 {
	now := time.Now().Unix()
	if now <= 0 {
		return 0
	}
	return uint64(now)
}
