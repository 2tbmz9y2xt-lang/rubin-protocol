package p2p

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
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

func TestSelectTxRelayPeersDeterministic(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	peers := []*peer{
		{service: h.service, state: nodePeerState("peer-3")},
		{service: h.service, state: nodePeerState("peer-1")},
		{service: h.service, state: nodePeerState("peer-4")},
		{service: h.service, state: nodePeerState("peer-2")},
	}
	var txid [32]byte
	txid[0] = 0x44
	first := selectTxRelayPeers(txid, "sender-a", peers, 2)
	second := selectTxRelayPeers(txid, "sender-a", peers, 2)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("got %d and %d peers, want 2", len(first), len(second))
	}
	if first[0].addr() != second[0].addr() || first[1].addr() != second[1].addr() {
		t.Fatalf("selection should be deterministic: %q,%q vs %q,%q", first[0].addr(), first[1].addr(), second[0].addr(), second[1].addr())
	}
	var otherTxid [32]byte
	otherTxid[0] = 0x55
	other := selectTxRelayPeers(otherTxid, "sender-a", peers, 2)
	if first[0].addr() == other[0].addr() && first[1].addr() == other[1].addr() {
		t.Fatalf("different txids should not always pick the same relay peers")
	}
	otherSender := selectTxRelayPeers(txid, "sender-b", peers, 2)
	if first[0].addr() == otherSender[0].addr() && first[1].addr() == otherSender[1].addr() {
		t.Fatalf("different sender salts should not always pick the same relay peers")
	}
}

func TestSelectTxRelayPeersLimitFallbacks(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	peers := []*peer{
		{service: h.service, state: nodePeerState("peer-1")},
		{service: h.service, state: nodePeerState("peer-2")},
	}
	var txid [32]byte
	txid[0] = 0x77
	if got := selectTxRelayPeers(txid, "sender-a", peers, 0); len(got) != len(peers) {
		t.Fatalf("limit=0 should return all peers, got %d want %d", len(got), len(peers))
	}
	if got := selectTxRelayPeers(txid, "sender-a", peers, 8); len(got) != len(peers) {
		t.Fatalf("oversized limit should return all peers, got %d want %d", len(got), len(peers))
	}
}

func TestInventoryRelayKeyMultipleItems(t *testing.T) {
	items := []InventoryVector{
		{Type: MSG_TX, Hash: [32]byte{0x01}},
		{Type: MSG_TX, Hash: [32]byte{0x02}},
	}
	first := inventoryRelayKey(items)
	second := inventoryRelayKey(items)
	if first != second {
		t.Fatal("inventoryRelayKey should be deterministic for the same input")
	}
	if first == items[0].Hash {
		t.Fatal("multi-item relay key should not collapse to the first txid")
	}
}

func TestRelayTxMetadataFallbackAndProvider(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	meta, err := h.service.relayTxMetadata([]byte{0xAA, 0xBB, 0xCC})
	if err != nil {
		t.Fatalf("fallback relayTxMetadata: %v", err)
	}
	if meta.Fee != 0 || meta.Size != 3 {
		t.Fatalf("fallback meta=%+v, want fee=0 size=3", meta)
	}
	h.service.cfg.TxMetadataFunc = func([]byte) (node.RelayTxMetadata, error) {
		return node.RelayTxMetadata{Fee: 9, Size: 7}, nil
	}
	meta, err = h.service.relayTxMetadata([]byte{0x00})
	if err != nil {
		t.Fatalf("provider relayTxMetadata: %v", err)
	}
	if meta.Fee != 9 || meta.Size != 7 {
		t.Fatalf("provider meta=%+v, want fee=9 size=7", meta)
	}
}

func TestBroadcastInventoryTxUsesFanoutLimit(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.TxRelayFanout = 2

	peers := make([]*peer, 0, 4)
	recorders := make([]*recordingConn, 0, 4)
	for i := 1; i <= 4; i++ {
		conn := &recordingConn{}
		current := &peer{conn: conn, service: h.service, state: nodePeerState("peer-" + string(rune('0'+i)))}
		peers = append(peers, current)
		recorders = append(recorders, conn)
		h.service.peers[current.addr()] = current
	}

	var txid [32]byte
	txid[0] = 0x99
	selected := selectTxRelayPeers(txid, h.service.txRelaySalt(nil), peers, h.service.cfg.TxRelayFanout)
	selectedSet := make(map[string]struct{}, len(selected))
	for _, current := range selected {
		selectedSet[current.addr()] = struct{}{}
	}

	if err := h.service.broadcastInventory(nil, []InventoryVector{{Type: MSG_TX, Hash: txid}}); err != nil {
		t.Fatalf("broadcastInventory tx: %v", err)
	}
	for idx, conn := range recorders {
		peerAddr := peers[idx].addr()
		got := conn.framesWritten() == 1
		_, shouldReceive := selectedSet[peerAddr]
		if got != shouldReceive {
			t.Fatalf("peer %s receive=%v, want %v", peerAddr, got, shouldReceive)
		}
	}
}

func TestBroadcastInventoryMixedKeepsBlocksGlobal(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.TxRelayFanout = 1

	local1, remote1 := net.Pipe()
	defer local1.Close()
	defer remote1.Close()
	peer1 := &peer{conn: local1, service: h.service, state: nodePeerState("peer-a")}

	local2, remote2 := net.Pipe()
	defer local2.Close()
	defer remote2.Close()
	peer2 := &peer{conn: local2, service: h.service, state: nodePeerState("peer-b")}

	h.service.peers[peer1.addr()] = peer1
	h.service.peers[peer2.addr()] = peer2

	done1 := make(chan int, 1)
	done2 := make(chan int, 1)
	go countFrames(remote1, h.service.cfg.PeerRuntimeConfig.MaxMessageSize, 2, done1)
	go countFrames(remote2, h.service.cfg.PeerRuntimeConfig.MaxMessageSize, 2, done2)

	items := []InventoryVector{
		{Type: MSG_BLOCK, Hash: [32]byte{0x01}},
		{Type: MSG_TX, Hash: [32]byte{0x02}},
	}
	if err := h.service.broadcastInventory(nil, items); err != nil {
		t.Fatalf("broadcastInventory mixed: %v", err)
	}

	got1 := <-done1
	got2 := <-done2
	if got1+got2 != 3 {
		t.Fatalf("expected 3 total frames (2 block + 1 tx), got %d", got1+got2)
	}
	if got1 == 0 || got2 == 0 {
		t.Fatalf("both peers should receive the block inventory")
	}
}

func countFrames(conn net.Conn, maxSize uint32, limit int, done chan<- int) {
	received := 0
	for received < limit {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := readFrame(conn, maxSize); err != nil {
			break
		}
		received++
	}
	done <- received
}

func nodePeerState(addr string) node.PeerState {
	return node.PeerState{Addr: addr, HandshakeComplete: true}
}

type recordingConn struct {
	bytes.Buffer
}

func (c *recordingConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Close() error                       { return nil }
func (c *recordingConn) LocalAddr() net.Addr                { return stubAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr               { return stubAddr("remote") }
func (c *recordingConn) SetDeadline(_ time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *recordingConn) framesWritten() int {
	payload := c.Bytes()
	frames := 0
	for len(payload) >= 4 {
		size := int(uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3]))
		if len(payload) < 4+size {
			break
		}
		frames++
		payload = payload[4+size:]
	}
	return frames
}

type stubAddr string

func (a stubAddr) Network() string { return "test" }
func (a stubAddr) String() string  { return string(a) }
