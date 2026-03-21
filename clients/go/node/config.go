package node

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type Config struct {
	Network            string              `json:"network"`
	DataDir            string              `json:"data_dir"`
	BindAddr           string              `json:"bind_addr"`
	RPCBindAddr        string              `json:"rpc_bind_addr,omitempty"`
	LogLevel           string              `json:"log_level"`
	Peers              []string            `json:"peers"`
	MaxPeers           int                 `json:"max_peers"`
	ChainID            string              `json:"chain_id_hex,omitempty"`
	MineAddress        string              `json:"mine_address"`
	RotationDescriptor *RotationConfigJSON `json:"rotation_descriptor,omitempty"`
}

// RotationConfigJSON is the JSON-serializable rotation descriptor for node config.
// When present, the node constructs a DescriptorRotationProvider from it.
// When absent (nil), DefaultRotationProvider is used (ML-DSA-87 at all heights).
type RotationConfigJSON struct {
	Name         string `json:"name"`
	OldSuiteID   uint8  `json:"old_suite_id"`
	NewSuiteID   uint8  `json:"new_suite_id"`
	CreateHeight uint64 `json:"create_height"`
	SpendHeight  uint64 `json:"spend_height"`
	SunsetHeight uint64 `json:"sunset_height,omitempty"`
}

// BuildRotationProvider constructs a RotationProvider from the config.
// Returns nil (=> default) if no rotation descriptor is configured.
func (cfg Config) BuildRotationProvider() (consensus.RotationProvider, *consensus.SuiteRegistry, error) {
	if cfg.RotationDescriptor == nil {
		return nil, nil, nil
	}
	rd := cfg.RotationDescriptor
	registry := consensus.DefaultSuiteRegistry()
	desc := consensus.CryptoRotationDescriptor{
		Name:         rd.Name,
		OldSuiteID:   rd.OldSuiteID,
		NewSuiteID:   rd.NewSuiteID,
		CreateHeight: rd.CreateHeight,
		SpendHeight:  rd.SpendHeight,
		SunsetHeight: rd.SunsetHeight,
	}
	if err := desc.Validate(registry); err != nil {
		return nil, nil, fmt.Errorf("rotation_descriptor: %w", err)
	}
	return consensus.DescriptorRotationProvider{Descriptor: desc}, registry, nil
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
		Network:     "devnet",
		DataDir:     DefaultDataDir(),
		BindAddr:    "0.0.0.0:19111",
		RPCBindAddr: "",
		Peers:       nil,
		LogLevel:    "info",
		MaxPeers:    64,
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
	if strings.TrimSpace(cfg.RPCBindAddr) != "" {
		if err := validateAddr(cfg.RPCBindAddr); err != nil {
			return fmt.Errorf("invalid rpc_bind_addr: %w", err)
		}
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
	if cfg.MineAddress != "" {
		raw, err := hex.DecodeString(cfg.MineAddress)
		if err != nil {
			return fmt.Errorf("invalid mine_address hex: %w", err)
		}
		if len(raw) != 32 && len(raw) != 33 {
			return fmt.Errorf("mine_address must be 32 (key_id) or 33 (suite_id||key_id) bytes, got %d", len(raw))
		}
	}
	if cfg.RotationDescriptor != nil {
		if _, _, err := cfg.BuildRotationProvider(); err != nil {
			return err
		}
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
