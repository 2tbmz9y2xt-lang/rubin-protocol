package p2p

import (
	"net"
	"testing"
)

func TestCoverageResidual_ServiceSyncBroadcastBranches(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	if err := h.service.broadcastInventory(nil, []InventoryVector{{Type: MSG_BLOCK, Hash: [32]byte{0x01}}}); err != nil {
		t.Fatalf("broadcastInventory without peers: %v", err)
	}

	local1, remote1 := net.Pipe()
	defer remote1.Close()
	defer local1.Close()
	peer1 := &peer{conn: local1, service: h.service}
	peer1.state.Addr = "peer-1"

	local2, remote2 := net.Pipe()
	local2.Close()
	defer remote2.Close()
	peer2 := &peer{conn: local2, service: h.service}
	peer2.state.Addr = "peer-2"

	h.service.peersMu.Lock()
	h.service.peers[peer1.addr()] = peer1
	h.service.peers[peer2.addr()] = peer2
	h.service.peersMu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := readFrame(remote1, h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		done <- err
	}()
	if err := h.service.broadcastInventory(peer2, []InventoryVector{{Type: MSG_BLOCK, Hash: [32]byte{0x02}}}); err != nil {
		t.Fatalf("broadcastInventory with skip: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("expected first peer to receive inventory: %v", err)
	}

	done2 := make(chan error, 1)
	go func() {
		_, err := readFrame(remote1, h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		done2 <- err
	}()
	if err := h.service.broadcastInventory(nil, []InventoryVector{{Type: MSG_BLOCK, Hash: [32]byte{0x03}}}); err != nil {
		t.Fatalf("broadcastInventory with closed peer: %v", err)
	}
	if err := <-done2; err != nil {
		t.Fatalf("expected first peer to receive second inventory: %v", err)
	}
	if peer2.snapshotState().LastError == "" {
		t.Fatalf("expected send failure to record peer2 error")
	}
}
