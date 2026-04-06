package node

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

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
