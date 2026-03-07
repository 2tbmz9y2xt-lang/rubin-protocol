package p2p

import (
	"context"
	"slices"
	"testing"
	"time"
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
