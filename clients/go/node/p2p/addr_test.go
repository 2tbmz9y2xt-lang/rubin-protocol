package p2p

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

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
	if _, err := decodeAddrPayload([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("decodeAddrPayload(short) unexpectedly succeeded")
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
