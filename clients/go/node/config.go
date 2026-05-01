package node

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
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
	MempoolMaxTxs      int                 `json:"mempool_max_txs"`
	MempoolMaxBytes    int                 `json:"mempool_max_bytes"`
	ChainID            string              `json:"chain_id_hex,omitempty"`
	MineAddress        string              `json:"mine_address"`
	RotationDescriptor *RotationConfigJSON `json:"rotation_descriptor,omitempty"`
	SuiteRegistry      []SuiteParamsJSON   `json:"suite_registry,omitempty"`
}

// RotationConfigJSON is the JSON-serializable rotation descriptor for node config.
// When present on non-production networks, the node constructs a
// DescriptorRotationProvider from it. Production networks derive activation
// only from the compiled schedule artifact.
type RotationConfigJSON struct {
	Name         string `json:"name"`
	OldSuiteID   uint8  `json:"old_suite_id"`
	NewSuiteID   uint8  `json:"new_suite_id"`
	CreateHeight uint64 `json:"create_height"`
	SpendHeight  uint64 `json:"spend_height"`
	SunsetHeight uint64 `json:"sunset_height,omitempty"`
}

// SuiteParamsJSON is the JSON-serializable registry entry used for controlled
// native-suite bootstrap without editing the built-in default registry.
type SuiteParamsJSON struct {
	SuiteID    uint8   `json:"suite_id"`
	PubkeyLen  uint32  `json:"pubkey_len"`
	SigLen     uint32  `json:"sig_len"`
	VerifyCost uint64  `json:"verify_cost"`
	AlgName    *string `json:"-"`
}

type suiteParamsJSONWire struct {
	SuiteID    uint8   `json:"suite_id"`
	PubkeyLen  uint32  `json:"pubkey_len"`
	SigLen     uint32  `json:"sig_len"`
	VerifyCost uint64  `json:"verify_cost"`
	AlgName    *string `json:"alg_name,omitempty"`
	OpenSSLAlg *string `json:"openssl_alg,omitempty"`
}

func (item *SuiteParamsJSON) UnmarshalJSON(data []byte) error {
	var wire suiteParamsJSONWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	item.SuiteID = wire.SuiteID
	item.PubkeyLen = wire.PubkeyLen
	item.SigLen = wire.SigLen
	item.VerifyCost = wire.VerifyCost
	item.AlgName = wire.AlgName
	if item.AlgName == nil {
		item.AlgName = wire.OpenSSLAlg
	}
	return nil
}

func (item SuiteParamsJSON) MarshalJSON() ([]byte, error) {
	return json.Marshal(suiteParamsJSONWire{
		SuiteID:    item.SuiteID,
		PubkeyLen:  item.PubkeyLen,
		SigLen:     item.SigLen,
		VerifyCost: item.VerifyCost,
		AlgName:    item.AlgName,
	})
}

const maxSuiteRegistryParamLen = consensus.MAX_WITNESS_BYTES_PER_TX
const maxExplicitSuiteRegistryEntries = 16
const productionLocalRotationDescriptorErr = "rotation_descriptor: production networks forbid local rotation_descriptor"
const supportedNetworkNamesCSV = "devnet, testnet, mainnet"

// CanonicalNetworkName returns the canonical network token for normalized
// devnet/testnet/mainnet inputs. Callers that care about distinguishing an
// explicitly blank raw config value must reject that before canonicalization.
func CanonicalNetworkName(network string) (string, bool) {
	normalized := normalizedNetworkName(network)
	switch normalized {
	case "devnet", "testnet", "mainnet":
		return normalized, true
	default:
		return normalized, false
	}
}

func canonicalConfigNetworkName(network string) (string, error) {
	canonical, ok := CanonicalNetworkName(network)
	if !ok {
		return "", fmt.Errorf(
			"unknown network '%s' (expected: %s)",
			normalizedNetworkName(network),
			supportedNetworkNamesCSV,
		)
	}
	return canonical, nil
}

func validateSuiteRegistryParamLen(value uint32) (int, error) {
	if value == 0 || value > uint32(maxSuiteRegistryParamLen) {
		return 0, errors.New("bad suite_registry")
	}
	return int(value), nil
}

func normalizeSuiteRegistryAlgName(value *string) (string, error) {
	if value == nil {
		return "", errors.New("bad suite_registry")
	}
	switch trimmed := strings.TrimSpace(*value); {
	case strings.EqualFold(trimmed, "ML-DSA-87"):
		return "ML-DSA-87", nil
	default:
		return "", errors.New("bad suite_registry")
	}
}

func defaultSuiteRegistryParams() consensus.SuiteParams {
	return consensus.SuiteParams{
		SuiteID:    consensus.SUITE_ID_ML_DSA_87,
		PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
		SigLen:     consensus.ML_DSA_87_SIG_BYTES,
		VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
		AlgName:    "ML-DSA-87",
	}
}

func validateSuiteRegistryItem(item SuiteParamsJSON) (consensus.SuiteParams, error) {
	if item.SuiteID == consensus.SUITE_ID_SENTINEL || item.VerifyCost == 0 {
		return consensus.SuiteParams{}, errors.New("bad suite_registry")
	}
	pubkeyLen, err := validateSuiteRegistryParamLen(item.PubkeyLen)
	if err != nil {
		return consensus.SuiteParams{}, err
	}
	sigLen, err := validateSuiteRegistryParamLen(item.SigLen)
	if err != nil {
		return consensus.SuiteParams{}, err
	}
	alg, err := normalizeSuiteRegistryAlgName(item.AlgName)
	if err != nil {
		return consensus.SuiteParams{}, err
	}
	params := consensus.SuiteParams{
		SuiteID:    item.SuiteID,
		PubkeyLen:  pubkeyLen,
		SigLen:     sigLen,
		VerifyCost: item.VerifyCost,
		AlgName:    alg,
	}
	// Live node config is canonical-only. Synthetic suite_registry shapes are
	// reserved for the CLI harness/conformance surface and must never be
	// accepted here on mainnet/testnet or devnet bootstrap.
	want := defaultSuiteRegistryParams()
	if params.PubkeyLen != want.PubkeyLen ||
		params.SigLen != want.SigLen ||
		params.VerifyCost != want.VerifyCost {
		return consensus.SuiteParams{}, errors.New("bad suite_registry")
	}
	return params, nil
}

func (cfg Config) buildSuiteRegistry() (*consensus.SuiteRegistry, error) {
	if len(cfg.SuiteRegistry) == 0 {
		return nil, nil
	}
	if len(cfg.SuiteRegistry) > maxExplicitSuiteRegistryEntries {
		return nil, errors.New("bad suite_registry")
	}
	seen := make(map[uint8]struct{}, len(cfg.SuiteRegistry))
	paramsByID := map[uint8]consensus.SuiteParams{
		consensus.SUITE_ID_ML_DSA_87: defaultSuiteRegistryParams(),
	}
	for _, item := range cfg.SuiteRegistry {
		if _, ok := seen[item.SuiteID]; ok {
			return nil, errors.New("bad suite_registry")
		}
		params, err := validateSuiteRegistryItem(item)
		if err != nil {
			return nil, err
		}
		seen[item.SuiteID] = struct{}{}
		paramsByID[item.SuiteID] = params
	}
	ids := make([]uint8, 0, len(paramsByID))
	for id := range paramsByID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	params := make([]consensus.SuiteParams, 0, len(ids))
	for _, id := range ids {
		params = append(params, paramsByID[id])
	}
	return consensus.NewSuiteRegistryFromParams(params), nil
}

// BuildRotationProvider constructs node startup rotation state.
// On mainnet/testnet, activation authority comes only from the compiled
// production schedule artifact; local suite_registry is ignored there and
// never becomes a live activation or live binding source.
func (cfg Config) BuildRotationProvider() (consensus.RotationProvider, *consensus.SuiteRegistry, error) {
	return cfg.buildRotationProviderWithProductionLookup(productionRotationDescriptorForNetwork)
}

func resolveProductionRotationState(
	network string,
	localDescriptor *RotationConfigJSON,
	productionLookup func(string) (*consensus.CryptoRotationDescriptor, *consensus.SuiteRegistry, error),
) (*consensus.CryptoRotationDescriptor, *consensus.SuiteRegistry, bool, error) {
	canonicalNetwork, ok := CanonicalNetworkName(network)
	if !ok || (canonicalNetwork != "mainnet" && canonicalNetwork != "testnet") {
		return nil, nil, false, nil
	}
	if localDescriptor != nil {
		return nil, nil, true, errors.New(productionLocalRotationDescriptorErr)
	}
	desc, registry, err := productionLookup(canonicalNetwork)
	if err != nil {
		return nil, nil, true, err
	}
	if desc == nil {
		if registry == nil {
			registry = consensus.DefaultSuiteRegistry()
		}
		if !registry.IsCanonicalDefaultLiveManifest() {
			return nil, nil, true, errors.New("production_rotation_schedule: invalid empty-slot registry")
		}
		return nil, registry, true, nil
	}
	if registry == nil {
		return nil, nil, true, errors.New("production_rotation_schedule: missing registry")
	}
	return desc, registry, true, nil
}

func (cfg Config) buildRotationProviderWithProductionLookup(
	productionLookup func(string) (*consensus.CryptoRotationDescriptor, *consensus.SuiteRegistry, error),
) (consensus.RotationProvider, *consensus.SuiteRegistry, error) {
	if strings.TrimSpace(cfg.Network) == "" {
		return nil, nil, errors.New("network is required")
	}
	network, err := canonicalConfigNetworkName(cfg.Network)
	if err != nil {
		return nil, nil, err
	}
	productionDesc, productionRegistry, productionHandled, err := resolveProductionRotationState(
		network,
		cfg.RotationDescriptor,
		productionLookup,
	)
	if err != nil {
		return nil, nil, err
	}
	if productionHandled {
		if productionDesc == nil {
			// Production empty slots use an explicit default pre-rotation runtime
			// and must ignore any local suite_registry override entirely.
			return consensus.DefaultRotationProvider{}, productionRegistry, nil
		}
		return consensus.DescriptorRotationProvider{Descriptor: *productionDesc}, productionRegistry, nil
	}
	explicitRegistry, err := cfg.buildSuiteRegistry()
	if err != nil {
		return nil, nil, fmt.Errorf("suite_registry: %w", err)
	}
	if cfg.RotationDescriptor == nil {
		if explicitRegistry == nil {
			return nil, nil, nil
		}
		return consensus.DefaultRotationProvider{}, explicitRegistry, nil
	}
	rd := cfg.RotationDescriptor
	registry := explicitRegistry
	if registry == nil {
		registry = consensus.DefaultSuiteRegistry()
	}
	desc := consensus.CryptoRotationDescriptor{
		Name:         rd.Name,
		OldSuiteID:   rd.OldSuiteID,
		NewSuiteID:   rd.NewSuiteID,
		CreateHeight: rd.CreateHeight,
		SpendHeight:  rd.SpendHeight,
		SunsetHeight: rd.SunsetHeight,
	}
	if err := consensus.ValidateRotationDescriptorForNetwork(network, desc, registry); err != nil {
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

// NormalizeDataDir applies lexical path cleanup only. Callers must reject blank
// datadir values before calling it when "." would be an invalid operator input.
func NormalizeDataDir(path string) string {
	return filepath.Clean(path)
}

func DefaultConfig() Config {
	mempoolDefaults := DefaultMempoolConfig()
	return Config{
		Network:         "devnet",
		DataDir:         DefaultDataDir(),
		BindAddr:        "0.0.0.0:19111",
		RPCBindAddr:     "",
		Peers:           nil,
		LogLevel:        "info",
		MaxPeers:        64,
		MempoolMaxTxs:   mempoolDefaults.MaxTransactions,
		MempoolMaxBytes: mempoolDefaults.MaxBytes,
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
	network, err := canonicalConfigNetworkName(cfg.Network)
	if err != nil {
		return err
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
	if cfg.MempoolMaxTxs <= 0 {
		return errors.New("mempool_max_txs must be > 0")
	}
	if cfg.MempoolMaxBytes <= 0 {
		return errors.New("mempool_max_bytes must be > 0")
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
	if _, _, productionHandled, err := resolveProductionRotationState(
		network,
		cfg.RotationDescriptor,
		productionRotationDescriptorForNetwork,
	); err != nil {
		return err
	} else if productionHandled {
		return nil
	}
	if _, err := cfg.buildSuiteRegistry(); err != nil {
		return fmt.Errorf("suite_registry: %w", err)
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
