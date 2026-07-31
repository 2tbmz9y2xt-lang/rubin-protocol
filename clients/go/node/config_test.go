package node

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type operatorPathFixture struct {
	ContractVersion uint64 `json:"contract_version"`
	FixtureKind     string `json:"fixture_kind"`
	Description     string `json:"description"`
	Cases           []struct {
		ID           *string `json:"id"`
		Input        *string `json:"input"`
		ExpectedUnix *string `json:"expected_unix"`
	} `json:"cases"`
}

func TestNormalizePeers(t *testing.T) {
	got := NormalizePeers("127.0.0.1:19111, 127.0.0.1:19112", "127.0.0.1:19111", " ", "10.0.0.1:19111")
	want := []string{"127.0.0.1:19111", "127.0.0.1:19112", "10.0.0.1:19111"}
	if !slices.Equal(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestValidateConfigOK(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Peers = []string{"127.0.0.1:19111"}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidateConfigRejectsBadBind(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BindAddr = "127.0.0.1"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateConfigAcceptsRPCBindAddr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RPCBindAddr = "127.0.0.1:19112"
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("expected valid rpc_bind_addr, got %v", err)
	}
}

func TestValidateConfigRejectsBadRPCBindAddr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RPCBindAddr = "127.0.0.1"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateConfigRejectsBadPeer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Peers = []string{"bad-peer"}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateConfigRejectsPeerMissingHost(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Peers = []string{":19111"}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateConfigRejectsEmptyNetwork(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Network = " "
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateConfigRejectsEmptyDataDir(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataDir = ""
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateConfigRejectsWhitespaceDataDir(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataDir = " \t "
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestNormalizeDataDir(t *testing.T) {
	abs := t.TempDir()
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "parent", input: filepath.Join("a", "..", "b"), want: "b"},
		{name: "dot-prefix", input: "." + string(filepath.Separator) + "a", want: "a"},
		{name: "dot-middle", input: filepath.Join("a", ".", "b"), want: filepath.Join("a", "b")},
		{name: "clean-absolute", input: abs, want: abs},
		{name: "clean-relative", input: filepath.Join("clean", "path"), want: filepath.Join("clean", "path")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeDataDir(tc.input); got != tc.want {
				t.Fatalf("NormalizeDataDir(%q)=%q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestOperatorPathNormalizationFixture(t *testing.T) {
	if filepath.Separator != '/' {
		t.Skip("fixture assertions are scoped to Unix")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "fixtures", "protocol", "operator_path_normalization_v1.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture operatorPathFixture
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("fixture has trailing JSON: %v", err)
	}
	if fixture.ContractVersion != 1 || fixture.FixtureKind != "operator_path_normalization_v1" {
		t.Fatalf("unexpected fixture identity: version=%d kind=%q", fixture.ContractVersion, fixture.FixtureKind)
	}
	if strings.TrimSpace(fixture.Description) == "" {
		t.Fatal("fixture description must be non-empty")
	}
	required := map[string]string{"empty": "", "dot": ".", "parent": "..", "dot-prefix": "./name", "bare-name": "name", "repeated-separator": "a//b", "trailing-separator": "a/b/", "trailing-dot": "a/b/.", "trailing-parent": "a/b/..", "mid-dot": "a/./b", "mid-parent": "a/x/../b", "absolute-root": "/", "rooted-parent": "/../name", "symlink-lexical": "sub/link/../genesis.json"}
	for _, tc := range fixture.Cases {
		if tc.ID == nil || tc.Input == nil || tc.ExpectedUnix == nil {
			t.Fatalf("fixture case has a missing field: %+v", tc)
		}
		wantInput, ok := required[*tc.ID]
		if !ok {
			t.Fatalf("unknown or duplicate fixture id %q", *tc.ID)
		}
		delete(required, *tc.ID)
		if *tc.Input != wantInput {
			t.Fatalf("%s: input=%q, want %q", *tc.ID, *tc.Input, wantInput)
		}
		if got := NormalizeDataDir(*tc.Input); got != *tc.ExpectedUnix {
			t.Errorf("%s: NormalizeDataDir(%q)=%q, want %q", *tc.ID, *tc.Input, got, *tc.ExpectedUnix)
		}
	}
	for id := range required {
		t.Errorf("missing fixture id %q", id)
	}
}

func TestCanonicalNetworkName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{name: "mainnet-trimmed", input: " MAINNET ", want: "mainnet", wantOK: true},
		{name: "empty-defaults-devnet", input: " \t ", want: "devnet", wantOK: true},
		{name: "unknown-stays-unknown", input: "private-net", want: "private-net", wantOK: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CanonicalNetworkName(tc.input)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("CanonicalNetworkName(%q)=(%q,%v), want (%q,%v)", tc.input, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestValidateConfigRejectsInvalidLogLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LogLevel = "verbose"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateConfigRejectsMaxPeersZero(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeers = 0
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateConfigRejectsMaxPeersTooHigh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeers = 4097
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}

func TestDefaultConfigIncludesMempoolLimits(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MempoolMaxTxs != DefaultMempoolMaxTransactions {
		t.Fatalf("mempool_max_txs=%d, want %d", cfg.MempoolMaxTxs, DefaultMempoolMaxTransactions)
	}
	if cfg.MempoolMaxBytes != DefaultMempoolMaxBytes {
		t.Fatalf("mempool_max_bytes=%d, want %d", cfg.MempoolMaxBytes, DefaultMempoolMaxBytes)
	}
}

func TestValidateConfigRejectsInvalidMempoolLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Config)
		want string
	}{
		{name: "zero txs", edit: func(cfg *Config) { cfg.MempoolMaxTxs = 0 }, want: "mempool_max_txs"},
		{name: "negative txs", edit: func(cfg *Config) { cfg.MempoolMaxTxs = -1 }, want: "mempool_max_txs"},
		{name: "zero bytes", edit: func(cfg *Config) { cfg.MempoolMaxBytes = 0 }, want: "mempool_max_bytes"},
		{name: "negative bytes", edit: func(cfg *Config) { cfg.MempoolMaxBytes = -1 }, want: "mempool_max_bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.edit(&cfg)
			if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %s rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestParseMineAddressAcceptsKeyIDAndCanonicalEncoding(t *testing.T) {
	raw := strings.Repeat("11", mineAddressKeyIDBytes)
	got, err := ParseMineAddress(raw)
	if err != nil {
		t.Fatalf("ParseMineAddress: %v", err)
	}

	want := make([]byte, 0, consensus.MAX_P2PK_COVENANT_DATA)
	want = append(want, consensus.SUITE_ID_ML_DSA_87)
	want = append(want, bytes.Repeat([]byte{0x11}, mineAddressKeyIDBytes)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("mine address mismatch: got=%x want=%x", got, want)
	}
}

func TestValidateConfigRejectsInvalidMineAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MineAddress = "abcd"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error")
	}
}
