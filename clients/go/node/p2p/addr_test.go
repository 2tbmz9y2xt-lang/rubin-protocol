package p2p

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestAddrPayloadRoundTrip(t *testing.T) {
	addrs := []string{"127.0.0.1:18444", "[::1]:18445"}
	encoded, err := encodeAddrPayload(addrs)
	if err != nil {
		t.Fatalf("encodeAddrPayload: %v", err)
	}
	decoded, err := decodeAddrPayload(encoded)
	if err != nil {
		t.Fatalf("decodeAddrPayload: %v", err)
	}
	if !slices.Equal(decoded, []string{"127.0.0.1:18444", "[::1]:18445"}) {
		t.Fatalf("decoded=%v", decoded)
	}
}

func TestAddrPayloadErrorsAndHandshakeCaps(t *testing.T) {
	if _, err := encodeAddrPayload([]string{"bad"}); err == nil {
		t.Fatalf("encodeAddrPayload(bad) unexpectedly succeeded")
	}
	if _, err := encodeAddrPayload([]string{"localhost:18444"}); err == nil {
		t.Fatalf("encodeAddrPayload(localhost) unexpectedly succeeded")
	}
	if _, err := encodeAddrPayload([]string{"127.0.0.1:0"}); err == nil {
		t.Fatalf("encodeAddrPayload(port=0) unexpectedly succeeded")
	}
	if _, err := decodeAddrPayload([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("decodeAddrPayload(short) unexpectedly succeeded")
	}
	if decoded, err := decodeAddrPayload(nil); err != nil || decoded != nil {
		t.Fatalf("decodeAddrPayload(nil)=%v err=%v, want nil nil", decoded, err)
	}
	invalidEntry, err := encodeAddrPayload([]string{"127.0.0.1:18444"})
	if err != nil {
		t.Fatalf("encodeAddrPayload(valid): %v", err)
	}
	invalidEntry[len(invalidEntry)-2] = 0
	invalidEntry[len(invalidEntry)-1] = 0
	if _, err := decodeAddrPayload(invalidEntry); err == nil {
		t.Fatalf("decodeAddrPayload(invalid entry) unexpectedly succeeded")
	}
	if _, err := decodeAddrPayload([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}); err == nil {
		t.Fatalf("decodeAddrPayload(overflow count) unexpectedly succeeded")
	}
	tooMany := consensus.AppendCompactSize(nil, maxAddrPayloadEntries+1)
	if _, err := decodeAddrPayload(tooMany); err == nil {
		t.Fatalf("decodeAddrPayload(too many entries) unexpectedly succeeded")
	}
	if got := preHandshakePayloadCap(messageGetAddr); got != 0 {
		t.Fatalf("preHandshakePayloadCap(getaddr)=%d, want 0", got)
	}
	if got := preHandshakePayloadCap(messageAddr); got != 0 {
		t.Fatalf("preHandshakePayloadCap(addr)=%d, want 0", got)
	}
}

func TestAddrExchange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	sink.service.addrMgr.AddAddrs([]string{"127.0.0.1:18501"})
	if err := sink.service.Start(ctx); err != nil {
		t.Fatalf("sink.Start: %v", err)
	}
	defer sink.service.Close()

	source := newTestHarness(t, 1, "127.0.0.1:0", []string{sink.service.Addr()})
	source.service.cfg.PeerRuntimeConfig.MaxPeers = 1
	if err := source.service.Start(ctx); err != nil {
		t.Fatalf("source.Start: %v", err)
	}
	defer source.service.Close()

	waitFor(t, 5*time.Second, func() bool {
		return slices.Contains(source.service.addrMgr.GetAddrs(8), "127.0.0.1:18501")
	})
}

func TestAddrPropagation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeC := newTestHarness(t, 1, "127.0.0.1:0", nil)
	if err := nodeC.service.Start(ctx); err != nil {
		t.Fatalf("nodeC.Start: %v", err)
	}
	defer nodeC.service.Close()

	nodeB := newTestHarness(t, 1, "127.0.0.1:0", nil)
	nodeB.service.addrMgr.AddAddrs([]string{nodeC.service.Addr()})
	if err := nodeB.service.Start(ctx); err != nil {
		t.Fatalf("nodeB.Start: %v", err)
	}
	defer nodeB.service.Close()

	nodeA := newTestHarness(t, 1, "127.0.0.1:0", []string{nodeB.service.Addr()})
	if err := nodeA.service.Start(ctx); err != nil {
		t.Fatalf("nodeA.Start: %v", err)
	}
	defer nodeA.service.Close()

	waitFor(t, 5*time.Second, func() bool {
		return nodeA.peerManager.Count() == 2 && nodeC.peerManager.Count() >= 1
	})
}

func TestAddrManagerEvictionAndLen(t *testing.T) {
	currentTime := time.Unix(1_777_000_300, 0)
	manager := newAddrManager(func() time.Time {
		currentTime = currentTime.Add(time.Second)
		return currentTime
	})
	for port := 20000; port <= 21000; port++ {
		manager.AddAddrs([]string{fmt.Sprintf("127.0.0.1:%d", port)})
	}
	if got := manager.Len(); got != maxKnownAddrs {
		t.Fatalf("Len()=%d, want %d", got, maxKnownAddrs)
	}
	addrs := manager.GetAddrs(maxKnownAddrs)
	if slices.Contains(addrs, "127.0.0.1:20000") {
		t.Fatalf("oldest address was not evicted")
	}
	if !slices.Contains(addrs, "127.0.0.1:21000") {
		t.Fatalf("newest address missing after eviction")
	}
	manager.MarkAttempted("127.0.0.1:21000")
}

func TestAddrManagerNilAndHelperBranches(t *testing.T) {
	var nilManager *addrManager
	nilManager.AddAddrs([]string{"127.0.0.1:20001"})
	nilManager.MarkAttempted("127.0.0.1:20001")
	if got := nilManager.GetAddrs(1); got != nil {
		t.Fatalf("GetAddrs(nil)=%v, want nil", got)
	}
	if got := nilManager.Len(); got != 0 {
		t.Fatalf("Len(nil)=%d, want 0", got)
	}

	manager := newAddrManager(nil)
	manager.AddAddrs([]string{"127.0.0.1:20002", "127.0.0.1:20003"})
	if got := manager.GetAddrs(-1); len(got) != 2 {
		t.Fatalf("GetAddrs(-1) len=%d, want 2", len(got))
	}
	if got := normalizeNetAddr("127.0.0.1:99999"); got != "" {
		t.Fatalf("normalizeNetAddr(invalid port)=%q, want empty", got)
	}
	if got := normalizeNetAddr("localhost:18444"); got != "" {
		t.Fatalf("normalizeNetAddr(non-ip host)=%q, want empty", got)
	}
	if got := normalizeDialTarget("Seed.Example.com:18444"); got != "seed.example.com:18444" {
		t.Fatalf("normalizeDialTarget(hostname)=%q, want seed.example.com:18444", got)
	}
}

func TestDiscoverableAddrsFiltersSelfConnectedAndBanned(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:19011", nil)
	self := normalizeNetAddr(h.service.Addr())
	connected := "127.0.0.1:19012"
	banned := "127.0.0.1:19013"
	candidate := "127.0.0.1:19014"

	h.service.addrMgr.AddAddrs([]string{self, connected, banned, candidate})
	h.service.peers[connected] = &peer{service: h.service, state: node.PeerState{Addr: connected}}
	if err := h.peerManager.AddPeer(&node.PeerState{
		Addr:     banned,
		BanScore: h.service.cfg.PeerRuntimeConfig.BanThreshold,
	}); err != nil {
		t.Fatalf("AddPeer(banned): %v", err)
	}

	if got := h.service.discoverableAddrs(8); !slices.Equal(got, []string{candidate}) {
		t.Fatalf("discoverableAddrs=%v, want [%s]", got, candidate)
	}
}

func TestRequestPeerAddrsNilAndConnectDiscoveredSkipsConnected(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:19021", nil)
	if err := h.service.requestPeerAddrs(nil); err != nil {
		t.Fatalf("requestPeerAddrs(nil): %v", err)
	}
	addr := "127.0.0.1:19022"
	h.service.peers[addr] = &peer{service: h.service, state: node.PeerState{Addr: addr}}
	h.service.connectDiscoveredAddrs([]string{addr})
	if got := h.service.connectedPeerCount(); got != 1 {
		t.Fatalf("connectedPeerCount()=%d, want 1", got)
	}
}

func TestConnectDiscoveredAddrsUsesBudgetAndPendingDedupe(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:19025", nil)
	h.service.cfg.PeerRuntimeConfig.MaxPeers = maxDiscoveredDialFanout
	for i := 0; i < maxDiscoveredDialFanout-1; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", 19100+i)
		if !h.service.beginDial(addr) {
			t.Fatalf("beginDial(%s) unexpectedly failed", addr)
		}
	}
	addrA := "127.0.0.1:19201"
	addrB := "127.0.0.1:19202"
	addrC := "127.0.0.1:19203"
	h.service.connectDiscoveredAddrs([]string{addrA, addrA, addrB, addrC})
	if !h.service.isDialing(addrA) {
		t.Fatalf("expected addrA to be scheduled")
	}
	if h.service.isDialing(addrB) || h.service.isDialing(addrC) {
		t.Fatalf("expected per-message dial budget to cap discovered dials")
	}
}

func TestAddrHandlerAndDiscoveryEdgeBranches(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:19031", nil)
	p := newPeerRuntimeTestPeer(t)
	p.service = h.service

	if err := p.handleGetAddr([]byte{0x01}); err != nil {
		t.Fatalf("handleGetAddr(non-empty payload): %v", err)
	}
	if err := p.handleAddr([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("handleAddr(invalid payload) unexpectedly succeeded")
	}

	var nilService *Service
	if got := nilService.discoverableAddrs(3); got != nil {
		t.Fatalf("discoverableAddrs(nil)=%v, want nil", got)
	}
	nilService.connectDiscoveredAddrs([]string{"127.0.0.1:19032"})

	h.service.addrMgr.AddAddrs([]string{"127.0.0.1:19032", "127.0.0.1:19033"})
	got := h.service.discoverableAddrs(1)
	if len(got) != 1 {
		t.Fatalf("discoverableAddrs(max=1)=%v, want single entry", got)
	}

	normalized := normalizePeerAddrs([]string{" 127.0.0.1:19032 ", "127.0.0.1:19032", "", "127.0.0.1:19033"})
	if !slices.Equal(normalized, []string{"127.0.0.1:19032", "127.0.0.1:19033"}) {
		t.Fatalf("normalizePeerAddrs=%v", normalized)
	}
}

func TestRegisterPeerDoesNotPersistRemoteSocketEndpoint(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:19041", nil)
	pr := &peer{
		service: h.service,
		state:   node.PeerState{Addr: "127.0.0.1:39000"},
	}
	if err := h.service.registerPeer(pr); err != nil {
		t.Fatalf("registerPeer: %v", err)
	}
	if got := h.service.addrMgr.GetAddrs(8); len(got) != 0 {
		t.Fatalf("addr manager learned transient peer addr: %v", got)
	}
}

func TestNewServiceSeedsAddrManagerFromBootstrapPeers(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:19051", []string{
		"127.0.0.1:19052",
		"seed.example.com:18444",
		"127.0.0.1:19052",
	})
	if got := h.service.addrMgr.GetAddrs(8); !slices.Equal(got, []string{"127.0.0.1:19052"}) {
		t.Fatalf("seeded bootstrap addrs=%v, want [127.0.0.1:19052]", got)
	}
}
