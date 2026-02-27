package node

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Network  string   `json:"network"`
	DataDir  string   `json:"data_dir"`
	BindAddr string   `json:"bind_addr"`
	LogLevel string   `json:"log_level"`
	Peers    []string `json:"peers"`
	MaxPeers int      `json:"max_peers"`
}

var allowedLogLevels = map[string]struct{}{
	"debug": {},
	"info":  {},
	"warn":  {},
	"error": {},
}

func DefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".rubin"
	}
	return filepath.Join(home, ".rubin")
}

func DefaultConfig() Config {
	return Config{
		Network:  "devnet",
		DataDir:  DefaultDataDir(),
		BindAddr: "0.0.0.0:19111",
		Peers:    nil,
		LogLevel: "info",
		MaxPeers: 64,
	}
}

func NormalizePeers(raw ...string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, token := range raw {
		for _, p := range strings.Split(token, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func ValidateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Network) == "" {
		return errors.New("network is required")
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		return errors.New("data_dir is required")
	}
	if err := validateAddr(cfg.BindAddr); err != nil {
		return fmt.Errorf("invalid bind_addr: %w", err)
	}
	for _, peer := range cfg.Peers {
		if err := validatePeerAddr(peer); err != nil {
			return fmt.Errorf("invalid peer %q: %w", peer, err)
		}
	}
	logLevel := strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	if _, ok := allowedLogLevels[logLevel]; !ok {
		return fmt.Errorf("invalid log_level %q", cfg.LogLevel)
	}
	if cfg.MaxPeers <= 0 {
		return errors.New("max_peers must be > 0")
	}
	if cfg.MaxPeers > 4096 {
		return errors.New("max_peers must be <= 4096")
	}
	return nil
}

func validateAddr(addr string) error {
	if strings.TrimSpace(addr) == "" {
		return errors.New("empty address")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if strings.TrimSpace(port) == "" {
		return errors.New("missing port")
	}
	if strings.Contains(host, " ") {
		return errors.New("invalid host")
	}
	return nil
}

func validatePeerAddr(addr string) error {
	if err := validateAddr(addr); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(addr)
	if strings.TrimSpace(host) == "" {
		return errors.New("missing host")
	}
	return nil
}
