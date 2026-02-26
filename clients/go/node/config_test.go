package node

import "testing"

func TestNormalizePeers(t *testing.T) {
	got := NormalizePeers("127.0.0.1:19111, 127.0.0.1:19112", "127.0.0.1:19111", " ", "10.0.0.1:19111")
	want := []string{"127.0.0.1:19111", "127.0.0.1:19112", "10.0.0.1:19111"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("at %d got=%q want=%q", i, got[i], want[i])
		}
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
