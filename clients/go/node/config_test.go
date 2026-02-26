package node

import (
	"slices"
	"testing"
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
