package node

import (
	"reflect"
	"testing"
)

func TestDefaultPeerRuntimeConfig_ClampMaxPeers(t *testing.T) {
	cfg := DefaultPeerRuntimeConfig("devnet", 0)
	if cfg.MaxPeers != 64 {
		t.Fatalf("max_peers=%d, want 64", cfg.MaxPeers)
	}
	if cfg.ReadDeadline != defaultReadDeadline || cfg.WriteDeadline != defaultWriteDeadline {
		t.Fatalf("unexpected deadlines: %#v", cfg)
	}
	if cfg.HandshakeTimeout != defaultHandshakeTimeout {
		t.Fatalf("handshake_timeout=%s, want %s", cfg.HandshakeTimeout, defaultHandshakeTimeout)
	}
	if cfg.BanThreshold != defaultBanThreshold {
		t.Fatalf("ban_threshold=%d, want %d", cfg.BanThreshold, defaultBanThreshold)
	}
	if cfg.MaxMessageSize != defaultMaxMessageSize {
		t.Fatalf("max_message_size=%d, want %d", cfg.MaxMessageSize, defaultMaxMessageSize)
	}
}

func TestDefaultPeerRuntimeConfig_NormalizesNetwork(t *testing.T) {
	cfg := DefaultPeerRuntimeConfig(" MAINNET ", 8)
	if cfg.Network != "mainnet" {
		t.Fatalf("network=%q, want mainnet", cfg.Network)
	}
}

func TestNewPeerManager_DefaultsApplied(t *testing.T) {
	pm := NewPeerManager(PeerRuntimeConfig{Network: "devnet"})
	if pm.cfg.MaxPeers != 64 {
		t.Fatalf("max_peers=%d, want 64", pm.cfg.MaxPeers)
	}
	if pm.cfg.HandshakeTimeout != defaultHandshakeTimeout {
		t.Fatalf("handshake_timeout=%s, want %s", pm.cfg.HandshakeTimeout, defaultHandshakeTimeout)
	}
}

func TestPeerManagerMaxPeers(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 1))
	if err := pm.AddPeer(&PeerState{Addr: "a"}); err != nil {
		t.Fatalf("add first peer: %v", err)
	}
	if err := pm.AddPeer(&PeerState{Addr: "b"}); err == nil {
		t.Fatalf("expected max peers error")
	}
}

func TestPeerManager_AddPeerNilCases(t *testing.T) {
	var pm *PeerManager
	if err := pm.AddPeer(&PeerState{Addr: "x"}); err == nil {
		t.Fatalf("expected error for nil pm")
	}

	pm = NewPeerManager(DefaultPeerRuntimeConfig("devnet", 1))
	if err := pm.AddPeer(nil); err == nil {
		t.Fatalf("expected error for nil peer")
	}
}

func TestPeerManager_SnapshotClones(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 8))
	st := &PeerState{Addr: "a", BanScore: 7, LastError: "x"}
	if err := pm.AddPeer(st); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	st.BanScore = 999
	snap := pm.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot len=%d, want 1", len(snap))
	}
	if snap[0].BanScore != 7 {
		t.Fatalf("snapshot ban_score=%d, want 7", snap[0].BanScore)
	}
}

func TestPeerManager_RemovePeer(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 8))
	if err := pm.AddPeer(&PeerState{Addr: "a"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	pm.RemovePeer("a")
	if got := pm.Snapshot(); len(got) != 0 {
		t.Fatalf("snapshot len=%d, want 0", len(got))
	}

	var nilPM *PeerManager
	nilPM.RemovePeer("a")
}

func TestPeerManager_UpsertPeer(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 1))
	if err := pm.UpsertPeer(&PeerState{Addr: "a", BanScore: 1}); err != nil {
		t.Fatalf("UpsertPeer(first): %v", err)
	}
	if err := pm.UpsertPeer(&PeerState{Addr: "a", BanScore: 9}); err != nil {
		t.Fatalf("UpsertPeer(update): %v", err)
	}
	snap := pm.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot len=%d, want 1", len(snap))
	}
	if snap[0].BanScore != 9 {
		t.Fatalf("ban_score=%d, want 9", snap[0].BanScore)
	}
}

func requirePeerTable(t *testing.T, pm *PeerManager, want []PeerState) {
	t.Helper()
	if got := pm.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot=%#v, want %#v", got, want)
	}
}

func TestPeerManagerClaimFreeSucceeds(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 8))
	if err := pm.Claim(); err != nil {
		t.Fatalf("Claim on free manager: %v", err)
	}
}

func TestPeerManagerClaimHeldRefusedTableUnchanged(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 1))
	if err := pm.AddPeer(&PeerState{Addr: "a", BanScore: 3}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := pm.Claim(); err != nil {
		t.Fatalf("first Claim: %v", err)
	}
	err := pm.Claim()
	if err == nil || err.Error() != "peer manager is already claimed" {
		t.Fatalf("second Claim err=%v, want peer manager is already claimed", err)
	}
	requirePeerTable(t, pm, []PeerState{{Addr: "a", BanScore: 3}})
	if err := pm.AddPeer(&PeerState{Addr: "b"}); err == nil || err.Error() != "max peers reached" {
		t.Fatalf("AddPeer over limit err=%v, want max peers reached", err)
	}
}

func TestPeerManagerReleaseThenClaimSucceeds(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 8))
	if err := pm.AddPeer(&PeerState{Addr: "a"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := pm.Claim(); err != nil {
		t.Fatalf("first Claim: %v", err)
	}
	pm.Release()
	requirePeerTable(t, pm, []PeerState{{Addr: "a"}})
	if err := pm.Claim(); err != nil {
		t.Fatalf("Claim after Release: %v", err)
	}
}

func TestPeerManagerReleaseOnFreeChangesNothing(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 8))
	if err := pm.AddPeer(&PeerState{Addr: "a"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	pm.Release()
	requirePeerTable(t, pm, []PeerState{{Addr: "a"}})
	if err := pm.Claim(); err != nil {
		t.Fatalf("Claim after Release on free manager: %v", err)
	}
	if err := pm.Claim(); err == nil || err.Error() != "peer manager is already claimed" {
		t.Fatalf("second Claim err=%v, want peer manager is already claimed", err)
	}
}

func TestPeerManagerClaimNilReceiver(t *testing.T) {
	var pm *PeerManager
	if err := pm.Claim(); err == nil || err.Error() != "nil peer manager" {
		t.Fatalf("Claim on nil err=%v, want nil peer manager", err)
	}
	pm.Release()
}
