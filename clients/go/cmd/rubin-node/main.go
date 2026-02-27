package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
		node.DefaultSyncConfig(nil, [32]byte{}, chainStatePath),
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
