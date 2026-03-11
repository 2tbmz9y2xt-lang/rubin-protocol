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
	for index := 0; index <= maxKnownAddrs; index++ {
		thirdOctet := index / maxAddrsPerSubnet
		fourthOctet := (index % maxAddrsPerSubnet) + 1
		manager.AddAddrs([]string{fmt.Sprintf("10.0.%d.%d:18444", thirdOctet, fourthOctet)})
	}
	if got := manager.Len(); got != maxKnownAddrs {
		t.Fatalf("Len()=%d, want %d", got, maxKnownAddrs)
	}
	addrs := manager.GetAddrs(maxKnownAddrs)
	if slices.Contains(addrs, "10.0.0.1:18444") {
		t.Fatalf("oldest address was not evicted")
	}
	if !slices.Contains(addrs, "10.0.100.1:18444") {
		t.Fatalf("newest address missing after eviction")
	}
	manager.MarkAttempted("10.0.100.1:18444")
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

func TestAddrManagerSubnetDiversityLimit(t *testing.T) {
	manager := newAddrManager(nil)
	for host := 1; host <= maxAddrsPerSubnet+2; host++ {
		manager.AddAddrs([]string{fmt.Sprintf("10.1.2.%d:18444", host)})
	}
	manager.AddAddrs([]string{"10.1.3.1:18444"})

	addrs := manager.GetAddrs(-1)
	subnetCount := 0
	for _, addr := range addrs {
		if subnetKey(addr) == "10.1.2.0/24" {
			subnetCount++
		}
	}
	if subnetCount != maxAddrsPerSubnet {
		t.Fatalf("10.1.2.0/24 count=%d, want %d", subnetCount, maxAddrsPerSubnet)
	}
	if !slices.Contains(addrs, "10.1.3.1:18444") {
		t.Fatalf("expected other subnet address to be retained, got %v", addrs)
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

func TestConnectDiscoveredSkipsConnected(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:19021", nil)
	addr := "127.0.0.1:19022"
	h.service.peers[addr] = &peer{service: h.service, state: node.PeerState{Addr: addr}}
	h.service.connectDiscoveredAddrs([]string{addr})
	if got := h.service.connectedPeerCount(); got != 1 {
		t.Fatalf("connectedPeerCount()=%d, want 1", got)
	}
}

func TestShouldDialDiscoveredAddrFiltersByNetwork(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		network string
		want    bool
	}{
		{name: "mainnet rejects loopback", addr: "127.0.0.1:18444", network: "mainnet", want: false},
		{name: "testnet rejects rfc1918", addr: "10.1.2.3:18444", network: "testnet", want: false},
		{name: "mainnet rejects link local", addr: "169.254.1.2:18444", network: "mainnet", want: false},
		{name: "mainnet rejects unspecified", addr: "0.0.0.0:18444", network: "mainnet", want: false},
		{name: "mainnet rejects multicast", addr: "224.0.0.1:18444", network: "mainnet", want: false},
		{name: "mainnet rejects shared space", addr: "100.64.1.2:18444", network: "mainnet", want: false},
		{name: "mainnet rejects benchmark net", addr: "198.18.1.2:18444", network: "mainnet", want: false},
		{name: "mainnet rejects doc net 192-0-2", addr: "192.0.2.1:18444", network: "mainnet", want: false},
		{name: "mainnet rejects doc net 198-51-100", addr: "198.51.100.1:18444", network: "mainnet", want: false},
		{name: "mainnet rejects doc net 203-0-113", addr: "203.0.113.1:18444", network: "mainnet", want: false},
		{name: "testnet rejects ipv6 loopback", addr: "[::1]:18444", network: "testnet", want: false},
		{name: "testnet rejects ipv6 multicast", addr: "[ff02::1]:18444", network: "testnet", want: false},
		{name: "testnet rejects ipv6 documentation range", addr: "[2001:db8::1]:18444", network: "testnet", want: false},
		{name: "mainnet rejects hostname", addr: "seed.example.com:18444", network: "mainnet", want: false},
		{name: "mainnet allows public ipv4", addr: "8.8.8.8:18444", network: "mainnet", want: true},
		{name: "testnet allows public ipv6", addr: "[2001:4860:4860::8888]:18444", network: "testnet", want: true},
		{name: "devnet allows loopback", addr: "127.0.0.1:18444", network: "devnet", want: true},
		{name: "empty network stays filtered", addr: "127.0.0.1:18444", network: "", want: false},
		{name: "malformed addr rejected", addr: "bad", network: "mainnet", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldDialDiscoveredAddr(tc.addr, tc.network); got != tc.want {
				t.Fatalf("shouldDialDiscoveredAddr(%q, %q)=%v, want %v", tc.addr, tc.network, got, tc.want)
			}
		})
	}
}

func TestConnectDiscoveredAddrsRespectsMaxPeersWithInFlightDials(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:19024", nil)
	h.service.cfg.PeerRuntimeConfig.MaxPeers = 1
	h.service.inFlightDial["127.0.0.1:19025"] = struct{}{}

	h.service.connectDiscoveredAddrs([]string{"127.0.0.1:19026", "127.0.0.1:19027"})

	if got := h.service.inFlightDialCount(); got != 1 {
		t.Fatalf("inFlightDialCount()=%d, want 1", got)
	}
}

func TestTrackDialEdgeCases(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:19030", nil)

	// nil receiver returns false.
	var nilSvc *Service
	if nilSvc.trackDialPeer("x") {
		t.Fatal("nil trackDialPeer must return false")
	}
	if nilSvc.tryTrackDiscoveredDial("x", 10) {
		t.Fatal("nil tryTrackDiscoveredDial must return false")
	}

	// Empty/whitespace addr returns false.
	if h.service.trackDialPeer("") {
		t.Fatal("empty addr must return false")
	}
	if h.service.trackDialPeer("   ") {
		t.Fatal("whitespace addr must return false")
	}
	if h.service.tryTrackDiscoveredDial("", 10) {
		t.Fatal("empty addr must return false")
	}

	// Successful track.
	if !h.service.trackDialPeer("127.0.0.1:9999") {
		t.Fatal("first trackDialPeer must succeed")
	}
	// Duplicate returns false.
	if h.service.trackDialPeer("127.0.0.1:9999") {
		t.Fatal("duplicate trackDialPeer must return false")
	}

	// tryTrackDiscoveredDial with existing addr returns false.
	if h.service.tryTrackDiscoveredDial("127.0.0.1:9999", 10) {
		t.Fatal("existing addr must return false")
	}

	// At-limit returns false.
	h.service.cfg.PeerRuntimeConfig.MaxPeers = 1
	if h.service.tryTrackDiscoveredDial("127.0.0.1:8888", 1) {
		t.Fatal("at-limit must return false")
	}
}

func TestFinishDialPeerEdgeCases(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:19035", nil)

	// nil receiver does not panic.
	var nilSvc *Service
	nilSvc.finishDialPeer("x")

	// Empty addr is no-op.
	h.service.finishDialPeer("")
	h.service.finishDialPeer("   ")

	// Normal finish removes entry.
	h.service.inFlightDial["127.0.0.1:7777"] = struct{}{}
	h.service.finishDialPeer("127.0.0.1:7777")
	if h.service.inFlightDialCount() != 0 {
		t.Fatal("finishDialPeer must remove entry")
	}
}

func TestInFlightDialCountNilReceiver(t *testing.T) {
	var nilSvc *Service
	if nilSvc.inFlightDialCount() != 0 {
		t.Fatal("nil inFlightDialCount must return 0")
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

func TestSubnetKeyEdgeCases(t *testing.T) {
	if got := subnetKey("not-a-hostport"); got != "" {
		t.Fatalf("subnetKey(invalid)=%q, want empty", got)
	}
	if got := subnetKey("hostname.example.com:1234"); got != "" {
		t.Fatalf("subnetKey(hostname)=%q, want empty", got)
	}
	if got := subnetKey("[::1]:1234"); got != "" {
		t.Fatalf("subnetKey(ipv6)=%q, want empty", got)
	}
	if got := subnetKey("10.0.1.5:18444"); got != "10.0.1.0/24" {
		t.Fatalf("subnetKey(valid)=%q, want 10.0.1.0/24", got)
	}
}
