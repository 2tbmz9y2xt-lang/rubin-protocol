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
	dryRun := flag.Bool("dry-run", false, "print effective config and exit")
	flag.Parse()

	cfg.Peers = node.NormalizePeers(append([]string{*peerCSV}, peers...)...)
	if err := node.ValidateConfig(cfg); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		os.Exit(2)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "datadir create failed: %v\n", err)
		os.Exit(2)
	}
	if err := printConfig(cfg); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "config encode failed: %v\n", err)
		os.Exit(1)
	}
	if *dryRun {
		return
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
