package p2p

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type testHarness struct {
	peerManager *node.PeerManager
	chainState  *node.ChainState
	blockStore  *node.BlockStore
	syncCfg     node.SyncConfig
	syncEngine  *node.SyncEngine
	service     *Service
	timestamp   uint64
}

func TestHandshakeValid(t *testing.T) {
	localConn, remoteConn := net.Pipe()
	defer localConn.Close()
	defer remoteConn.Close()

	cfg := node.DefaultPeerRuntimeConfig("devnet", 8)
	cfg.HandshakeTimeout = time.Second
	localVersion := testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "local", 7)
	remoteVersion := testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 11)

	errCh := make(chan error, 1)
	go func() {
		errCh <- completeRemoteHandshake(remoteConn, cfg, remoteVersion)
	}()

	state, err := performHandshake(
		context.Background(),
		localConn,
		cfg,
		localVersion,
		localVersion.ChainID,
		localVersion.GenesisHash,
	)
	if err != nil {
		t.Fatalf("performHandshake: %v", err)
	}
	if !state.HandshakeComplete {
		t.Fatalf("expected complete handshake: %+v", state)
	}
	if state.RemoteVersion.BestHeight != remoteVersion.BestHeight {
		t.Fatalf("best_height=%d, want %d", state.RemoteVersion.BestHeight, remoteVersion.BestHeight)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("remote handshake failed: %v", err)
	}
}

func TestHandshakeChainIDMismatch(t *testing.T) {
	localConn, remoteConn := net.Pipe()
	defer localConn.Close()
	defer remoteConn.Close()

	cfg := node.DefaultPeerRuntimeConfig("devnet", 8)
	cfg.HandshakeTimeout = time.Second
	localVersion := testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "local", 0)
	var wrongChainID [32]byte
	wrongChainID[0] = 0x42
	remoteVersion := testVersionPayload(wrongChainID, node.DevnetGenesisBlockHash(), "remote", 0)

	go func() {
		_ = sendRemoteVersionOnly(remoteConn, cfg, remoteVersion)
	}()

	state, err := performHandshake(
		context.Background(),
		localConn,
		cfg,
		localVersion,
		localVersion.ChainID,
		localVersion.GenesisHash,
	)
	if err == nil {
		t.Fatalf("expected handshake failure")
	}
	if state.BanScore != cfg.BanThreshold {
		t.Fatalf("ban_score=%d, want %d", state.BanScore, cfg.BanThreshold)
	}
	if state.LastError != "chain_id mismatch" {
		t.Fatalf("last_error=%q, want chain_id mismatch", state.LastError)
	}
}

func TestHandshakeProtocolVersionMismatch(t *testing.T) {
	localConn, remoteConn := net.Pipe()
	defer localConn.Close()
	defer remoteConn.Close()

	cfg := node.DefaultPeerRuntimeConfig("devnet", 8)
	cfg.HandshakeTimeout = time.Second
	localVersion := testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "local", 0)
	remoteVersion := testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 0)
	remoteVersion.ProtocolVersion += 2

	go func() {
		_ = sendRemoteVersionOnly(remoteConn, cfg, remoteVersion)
	}()

	state, err := performHandshake(
		context.Background(),
		localConn,
		cfg,
		localVersion,
		localVersion.ChainID,
		localVersion.GenesisHash,
	)
	if err == nil {
		t.Fatalf("expected handshake failure")
	}
	want := fmt.Sprintf("protocol_version mismatch: local=%d remote=%d", localVersion.ProtocolVersion, remoteVersion.ProtocolVersion)
	if state.LastError != want {
		t.Fatalf("last_error=%q, want %q", state.LastError, want)
	}
	if state.BanScore != 0 {
		t.Fatalf("ban_score=%d, want 0", state.BanScore)
	}
}

func TestHandshakeGenesisHashMismatch(t *testing.T) {
	localConn, remoteConn := net.Pipe()
	defer localConn.Close()
	defer remoteConn.Close()

	cfg := node.DefaultPeerRuntimeConfig("devnet", 8)
	cfg.HandshakeTimeout = time.Second
	localVersion := testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "local", 0)
	var wrongGenesis [32]byte
	wrongGenesis[0] = 0x24
	remoteVersion := testVersionPayload(node.DevnetGenesisChainID(), wrongGenesis, "remote", 0)

	go func() {
		_ = sendRemoteVersionOnly(remoteConn, cfg, remoteVersion)
	}()

	state, err := performHandshake(
		context.Background(),
		localConn,
		cfg,
		localVersion,
		localVersion.ChainID,
		localVersion.GenesisHash,
	)
	if err == nil {
		t.Fatalf("expected handshake failure")
	}
	if state.LastError != "genesis_hash mismatch" {
		t.Fatalf("last_error=%q, want genesis_hash mismatch", state.LastError)
	}
	if state.BanScore != cfg.BanThreshold {
		t.Fatalf("ban_score=%d, want %d", state.BanScore, cfg.BanThreshold)
	}
}

func TestBlockRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := newTestHarness(t, 1, "127.0.0.1:0", nil)
	if err := source.service.Start(ctx); err != nil {
		t.Fatalf("source.Start: %v", err)
	}
	defer source.service.Close()

	sink := newTestHarness(t, 1, "127.0.0.1:0", []string{source.service.Addr()})
	if err := sink.service.Start(ctx); err != nil {
		t.Fatalf("sink.Start: %v", err)
	}
	defer sink.service.Close()

	waitFor(t, 5*time.Second, func() bool {
		return source.peerManager.Count() == 1 && sink.peerManager.Count() == 1
	})

	blockBytes := source.mineNextBlockBytes(t)
	if err := source.service.AnnounceBlock(blockBytes); err != nil {
		t.Fatalf("AnnounceBlock: %v", err)
	}

	waitFor(t, 5*time.Second, func() bool {
		height, _, ok, err := sink.blockStore.Tip()
		return err == nil && ok && height == 1
	})

	sourceHeight, sourceHash, sourceOK, err := source.blockStore.Tip()
	if err != nil {
		t.Fatalf("source tip: %v", err)
	}
	sinkHeight, sinkHash, sinkOK, err := sink.blockStore.Tip()
	if err != nil {
		t.Fatalf("sink tip: %v", err)
	}
	if !sourceOK || !sinkOK {
		t.Fatalf("expected both peers to have tips")
	}
	if sourceHeight != 1 || sinkHeight != 1 {
		t.Fatalf("source_height=%d sink_height=%d, want 1/1", sourceHeight, sinkHeight)
	}
	if sourceHash != sinkHash {
		t.Fatalf("tip hash mismatch: source=%x sink=%x", sourceHash, sinkHash)
	}
}

func TestIBDSync(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	if err := source.service.Start(ctx); err != nil {
		t.Fatalf("source.Start: %v", err)
	}
	defer source.service.Close()

	sink := newTestHarness(t, 0, "127.0.0.1:0", []string{source.service.Addr()})
	if err := sink.service.Start(ctx); err != nil {
		t.Fatalf("sink.Start: %v", err)
	}
	defer sink.service.Close()

	waitFor(t, 5*time.Second, func() bool {
		height, _, ok, err := sink.blockStore.Tip()
		return err == nil && ok && height == 1
	})

	sourceHeight, sourceHash, sourceOK, err := source.blockStore.Tip()
	if err != nil {
		t.Fatalf("source tip: %v", err)
	}
	sinkHeight, sinkHash, sinkOK, err := sink.blockStore.Tip()
	if err != nil {
		t.Fatalf("sink tip: %v", err)
	}
	if !sourceOK || !sinkOK {
		t.Fatalf("expected both peers to have tips")
	}
	if sourceHeight != 1 || sinkHeight != 1 {
		t.Fatalf("source_height=%d sink_height=%d, want 1/1", sourceHeight, sinkHeight)
	}
	if sourceHash != sinkHash {
		t.Fatalf("tip hash mismatch: source=%x sink=%x", sourceHash, sinkHash)
	}
}

func TestOrphanResolution(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 0, "127.0.0.1:0", nil)

	genesisBytes := node.DevnetGenesisBlockBytes()
	_, block1Bytes := testHarnessBlockAtHeight(t, source, 1)
	height2Hash, block2Bytes := testHarnessBlockAtHeight(t, source, 2)
	peer := testPeerForService(sink.service, "remote", 2)

	assertRelayedBlockIsOrphan(t, peer, block2Bytes, "block2")
	assertRelayedBlockIsOrphan(t, peer, block1Bytes, "block1")
	assertOrphanPoolLen(t, sink.service, 2)
	assertBlockInventoryKnown(t, peer, height2Hash, "orphan height2")

	summary, err := peer.processRelayedBlock(genesisBytes)
	if err != nil {
		t.Fatalf("processRelayedBlock(genesis): %v", err)
	}
	if summary == nil || summary.BlockHeight != 0 {
		t.Fatalf("genesis summary=%v, want height 0", summary)
	}
	assertOrphanPoolLen(t, sink.service, 0)
	assertHarnessTip(t, sink, 2, height2Hash)
}

func TestAcceptedBlockKeepsResolvingOrphansWhenDATTLExpiryFails(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 0, "127.0.0.1:0", nil)
	sink.service.daRelay = newDARelayStateForTest(t, defaultDARelayCaps())
	overflowID := daRelayTestID(102)
	overflowRecord := daRelayOverflowOrphanAccountingRecord(overflowID)
	overflowRecord.ttlBlocksRemaining = 2
	sink.service.daRelay.sets[overflowID] = overflowRecord
	sink.service.daRelay.orphanBytesByDAID[overflowID] = overflowRecord.wireBytes

	genesisBytes := node.DevnetGenesisBlockBytes()
	_, block1Bytes := testHarnessBlockAtHeight(t, source, 1)
	height2Hash, block2Bytes := testHarnessBlockAtHeight(t, source, 2)
	peer := testPeerForService(sink.service, "remote", 2)

	assertRelayedBlockIsOrphan(t, peer, block2Bytes, "block2")
	assertRelayedBlockIsOrphan(t, peer, block1Bytes, "block1")
	summary, err := peer.processRelayedBlock(genesisBytes)
	if err != nil {
		t.Fatalf("processRelayedBlock(genesis): %v", err)
	}
	if summary == nil || summary.BlockHeight != 0 {
		t.Fatalf("genesis summary=%v, want height 0", summary)
	}
	if peer.snapshotState().LastError == "" {
		t.Fatalf("expected DA TTL cleanup error to be recorded")
	}
	assertOrphanPoolLen(t, sink.service, 0)
	assertHarnessTip(t, sink, 2, height2Hash)
}

func TestProcessRelayedBlockAdvancesDARelayTTL(t *testing.T) {
	sink := newTestHarness(t, 0, "127.0.0.1:0", nil)
	caps := defaultDARelayCaps()
	caps.orphanTTLBlocks = 1
	sink.service.daRelay = newDARelayStateForTest(t, caps)

	daID := daRelayTestID(100)
	mustAddDAChunk(t, sink.service.daRelay, "peer-a", daRelayTestChunk(daID, 0, 7))
	if got := sink.service.daRelay.orphanBytes; got == 0 {
		t.Fatalf("orphanBytes=%d, want staged orphan bytes before block accept", got)
	}

	peer := testPeerForService(sink.service, "remote", 1)
	summary, err := peer.processRelayedBlock(node.DevnetGenesisBlockBytes())
	if err != nil {
		t.Fatalf("processRelayedBlock(genesis): %v", err)
	}
	if summary == nil || summary.BlockHeight != 0 {
		t.Fatalf("summary=%v, want height 0", summary)
	}
	if _, ok := sink.service.daRelay.sets[daID]; ok {
		t.Fatalf("DA set %x still present after accepted block TTL expiry", daID)
	}
	if got := sink.service.daRelay.orphanBytes; got != 0 {
		t.Fatalf("orphanBytes=%d, want 0 after accepted block TTL expiry", got)
	}
	if got := sink.service.daRelay.orphanBytesForPeer("peer-a"); got != 0 {
		t.Fatalf("orphanBytesForPeer(peer-a)=%d, want 0", got)
	}
	if got := sink.service.daRelay.orphanBytesForDAID(daID); got != 0 {
		t.Fatalf("orphanBytesForDAID=%d, want 0", got)
	}
}

func TestAnnounceBlockAdvancesDARelayTTL(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	caps := defaultDARelayCaps()
	caps.orphanTTLBlocks = 1
	h.service.daRelay = newDARelayStateForTest(t, caps)

	daID := daRelayTestID(101)
	mustAddDAChunk(t, h.service.daRelay, "peer-a", daRelayTestChunk(daID, 0, 7))
	blockBytes := h.mineNextBlockBytes(t)
	if err := h.service.AnnounceBlock(blockBytes); err != nil {
		t.Fatalf("AnnounceBlock: %v", err)
	}
	if _, ok := h.service.daRelay.sets[daID]; ok {
		t.Fatalf("DA set %x still present after local block announce TTL expiry", daID)
	}
	if got := h.service.daRelay.orphanBytes; got != 0 {
		t.Fatalf("orphanBytes=%d, want 0 after local block announce TTL expiry", got)
	}
	if got := h.service.daRelay.orphanBytesForPeer("peer-a"); got != 0 {
		t.Fatalf("orphanBytesForPeer(peer-a)=%d, want 0", got)
	}
	if got := h.service.daRelay.orphanBytesForDAID(daID); got != 0 {
		t.Fatalf("orphanBytesForDAID=%d, want 0", got)
	}
}

func TestUnregisterPeerReleasesDAChunkPeerAccountingAndDropsOwnedChunk(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	caps := defaultDARelayCaps()
	caps.orphanPoolPerPeerBytes = 10
	h.service.daRelay = newDARelayStateForTest(t, caps)
	daID := daRelayTestID(106)
	completeID := daRelayTestID(111)
	payload := []byte("complete-payload")
	mustAddDAChunk(t, h.service.daRelay, "127.0.0.1:19111", daRelayTestChunk(daID, 0, 7))
	mustAddDACommit(t, h.service.daRelay, "127.0.0.1:19111", daRelayTestCommitForPayloads(completeID, 3, payload))
	complete := mustAddDAChunk(t, h.service.daRelay, "127.0.0.1:19111", daRelayTestChunkPayload(completeID, 0, uint64(len(payload)), payload))
	if complete.state != daRelayStateCompleteSet || h.service.daRelay.pinnedPayloadBytes == 0 {
		t.Fatalf("setup complete state=%v pinned=%d", complete.state, h.service.daRelay.pinnedPayloadBytes)
	}
	wantPinned := h.service.daRelay.pinnedPayloadBytes
	peer := &peer{service: h.service, state: node.PeerState{Addr: "127.0.0.1:19111"}}
	if err := h.service.registerPeer(peer); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	h.service.unregisterPeer(peer)
	if got := h.service.daRelay.orphanBytesForPeer("127.0.0.1:19111"); got != 0 {
		t.Fatalf("peer orphan bytes after unregister = %d, want 0", got)
	}
	if got := h.service.daRelay.orphanBytes; got != 0 {
		t.Fatalf("global orphan bytes after unregister = %d, want 0", got)
	}
	if got := h.service.daRelay.orphanBytesForDAID(daID); got != 0 {
		t.Fatalf("da_id orphan bytes after unregister = %d, want 0", got)
	}
	if _, ok := h.service.daRelay.sets[daID]; ok {
		t.Fatalf("DA record %x retained after owner disconnect", daID)
	}
	if got := h.service.daRelay.sets[completeID]; got.state != daRelayStateCompleteSet || h.service.daRelay.pinnedPayloadBytes != wantPinned {
		t.Fatalf("complete set after unregister state=%v pinned=%d want %d", got.state, h.service.daRelay.pinnedPayloadBytes, wantPinned)
	}
}

func TestUnregisterPeerReleasesDACommitPeerAccountingAndPreservesOtherChunks(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	caps := defaultDARelayCaps()
	caps.orphanPoolPerPeerBytes = 10
	h.service.daRelay = newDARelayStateForTest(t, caps)
	daID := daRelayTestID(109)
	otherChunk := mustAddDAChunk(t, h.service.daRelay, "127.0.0.2:19112", daRelayTestChunk(daID, 0, 3))
	mustAddDACommit(t, h.service.daRelay, "127.0.0.1:19111", daRelayTestCommit(daID, 2, 7))
	peer := &peer{service: h.service, state: node.PeerState{Addr: "127.0.0.1:19111"}}
	if err := h.service.registerPeer(peer); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	h.service.unregisterPeer(peer)
	if got := h.service.daRelay.orphanBytesForPeer("127.0.0.1:19111"); got != 0 {
		t.Fatalf("peer orphan bytes after unregister = %d, want 0", got)
	}
	if got := h.service.daRelay.orphanBytesForPeer("127.0.0.2:19112"); got != otherChunk.wireBytes {
		t.Fatalf("other peer orphan bytes after unregister = %d, want %d", got, otherChunk.wireBytes)
	}
	if got := h.service.daRelay.orphanBytes; got != otherChunk.wireBytes {
		t.Fatalf("global orphan bytes after unregister = %d, want %d", got, otherChunk.wireBytes)
	}
	if got := h.service.daRelay.orphanBytesForDAID(daID); got != otherChunk.wireBytes {
		t.Fatalf("da_id orphan bytes after unregister = %d, want %d", got, otherChunk.wireBytes)
	}
	if got := h.service.daRelay.orphanCommitOverheadBytes; got != 0 {
		t.Fatalf("commit overhead after unregister = %d, want 0", got)
	}
	gotRecord := h.service.daRelay.sets[daID]
	if gotRecord.state != daRelayStateOrphanChunks || gotRecord.commit.chunkCount != 0 || len(gotRecord.chunks) != 1 {
		t.Fatalf("record after unregister state=%v commit_count=%d chunks=%d", gotRecord.state, gotRecord.commit.chunkCount, len(gotRecord.chunks))
	}
	if _, ok := gotRecord.chunks[0]; !ok {
		t.Fatalf("other peer chunk missing after unregister")
	}
}

func TestUnregisterPeerKeepsDAAccountingForActiveQuotaKey(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	h.service.daRelay = newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(107)
	record := mustAddDAChunk(t, h.service.daRelay, "127.0.0.1:19112", daRelayTestChunk(daID, 0, 9))
	oldPeer := &peer{service: h.service, state: node.PeerState{Addr: "127.0.0.1:19111"}}
	newPeer := &peer{service: h.service, state: node.PeerState{Addr: "127.0.0.1:19112"}}
	if err := h.service.registerPeer(oldPeer); err != nil {
		t.Fatalf("register old peer: %v", err)
	}
	unlockQuota := h.service.lockPeerQuotaKey(peerQuotaKey(newPeer.addr()))
	registered := make(chan error, 1)
	go func() { registered <- h.service.registerPeer(newPeer) }()
	waitForPeerQuotaLockRefs(t, h.service, peerQuotaKey(newPeer.addr()), 2)
	select {
	case err := <-registered:
		unlockQuota()
		t.Fatalf("register new peer completed while quota locked: %v", err)
	default:
	}
	if got := h.service.cfg.PeerManager.Count(); got != 1 {
		unlockQuota()
		t.Fatalf("peer manager count while quota locked = %d, want 1", got)
	}
	unlockQuota()
	if err := <-registered; err != nil {
		t.Fatalf("register new peer: %v", err)
	}

	h.service.unregisterPeer(oldPeer)
	if got := h.service.daRelay.orphanBytesForPeer("127.0.0.1:19112"); got != record.wireBytes {
		t.Fatalf("active quota key orphan bytes = %d, want %d", got, record.wireBytes)
	}
	if got := h.service.peers["127.0.0.1:19112"]; got != newPeer {
		t.Fatalf("active peer was not retained")
	}
}

func TestUnregisterPeerHoldsQuotaLockThroughPeerManagerRemoval(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	runtimeCfg := node.DefaultPeerRuntimeConfig("devnet", 1)
	h.peerManager = node.NewPeerManager(runtimeCfg)
	h.service.cfg.PeerManager = h.peerManager
	h.service.cfg.PeerRuntimeConfig = runtimeCfg
	h.service.daRelay = newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(112)
	oldPeer := &peer{service: h.service, state: node.PeerState{Addr: "127.0.0.1:19111"}}
	newPeer := &peer{service: h.service, state: node.PeerState{Addr: "127.0.0.1:19112"}}
	if err := h.service.registerPeer(oldPeer); err != nil {
		t.Fatalf("register old peer: %v", err)
	}
	mustAddDAChunk(t, h.service.daRelay, oldPeer.addr(), daRelayTestChunk(daID, 0, 9))

	h.service.daRelay.mu.Lock()
	unregistered := make(chan struct{})
	go func() {
		h.service.unregisterPeer(oldPeer)
		close(unregistered)
	}()
	waitFor(t, time.Second, func() bool {
		return h.service.cfg.PeerManager.Count() == 0
	})

	registered := make(chan error, 1)
	go func() { registered <- h.service.registerPeer(newPeer) }()
	waitForPeerQuotaLockRefs(t, h.service, peerQuotaKey(newPeer.addr()), 2)
	select {
	case err := <-registered:
		h.service.daRelay.mu.Unlock()
		t.Fatalf("register new peer completed while unregister held DA relay lock: %v", err)
	default:
	}
	h.service.daRelay.mu.Unlock()
	<-unregistered
	if err := <-registered; err != nil {
		t.Fatalf("register new peer: %v", err)
	}
	if got := h.service.cfg.PeerManager.Count(); got != 1 {
		t.Fatalf("peer manager count after replacement register = %d, want 1", got)
	}
}

func TestLockPeerQuotaKeyInitializesNilMap(t *testing.T) {
	s := &Service{}
	unlock := s.lockPeerQuotaKey("127.0.0.1")
	unlock()
	if s.peerQuotaLocks == nil {
		t.Fatalf("peer quota locks map was not initialized")
	}
	if got := len(s.peerQuotaLocks); got != 0 {
		t.Fatalf("peer quota locks after unlock = %d, want 0", got)
	}
}

func TestReleaseDAQuotaIfInactiveHandlesNilRelay(t *testing.T) {
	s := &Service{}
	if err := s.releaseDAQuotaIfInactive("127.0.0.1"); err != nil {
		t.Fatalf("release DA quota with nil relay: %v", err)
	}
	if s.peerQuotaLocks == nil {
		t.Fatalf("peer quota locks map was not initialized")
	}
	if got := len(s.peerQuotaLocks); got != 0 {
		t.Fatalf("peer quota locks after release = %d, want 0", got)
	}
}

func TestHandleBlockRequestsMoreBlocksAfterAccept(t *testing.T) {
	sink := newTestHarness(t, 0, "127.0.0.1:0", nil)
	peer := &peer{
		service: sink.service,
		state: node.PeerState{
			RemoteVersion: testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 2),
		},
	}

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	peer.conn = local

	done := make(chan message, 1)
	go func() {
		frame, err := readFrame(remote, networkMagic(peer.service.cfg.PeerRuntimeConfig.Network), peer.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		if err != nil {
			t.Errorf("readFrame(remote): %v", err)
			return
		}
		done <- frame
	}()

	if err := peer.handleBlock(node.DevnetGenesisBlockBytes()); err != nil {
		t.Fatalf("handleBlock(genesis): %v", err)
	}

	frame := <-done
	if frame.Command != messageGetBlk {
		t.Fatalf("frame.Command=%q, want %q", frame.Command, messageGetBlk)
	}
}

func TestProcessRelayedBlockExistingBlockIsNoop(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	peer := &peer{
		service: h.service,
		state: node.PeerState{
			RemoteVersion: testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 0),
		},
	}

	summary, err := peer.processRelayedBlock(node.DevnetGenesisBlockBytes())
	if err != nil {
		t.Fatalf("processRelayedBlock(existing genesis): %v", err)
	}
	if summary != nil {
		t.Fatalf("summary=%v, want nil for existing block", summary)
	}
}

func TestResolveOrphansDropsInvalidChildBytes(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	var parentHash [32]byte
	parentHash[31] = 0x11
	var childHash [32]byte
	childHash[31] = 0x22
	if added, _ := h.service.orphans.Add(childHash, parentHash, []byte{0x00}, ""); !added {
		t.Fatalf("expected orphan add")
	}

	h.service.resolveOrphans(nil, parentHash)

	if got := h.service.orphans.Len(); got != 0 {
		t.Fatalf("orphans.Len()=%d, want 0 after invalid child drop", got)
	}
}

func TestResolveOrphansRequeuesStillMissingChild(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 0, "127.0.0.1:0", nil)

	height1Hash, ok, err := source.blockStore.CanonicalHash(1)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(1): ok=%v err=%v", ok, err)
	}
	height2Hash, ok, err := source.blockStore.CanonicalHash(2)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(2): ok=%v err=%v", ok, err)
	}
	block2Bytes, err := source.blockStore.GetBlockByHash(height2Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash(height2): %v", err)
	}

	var wrongParent [32]byte
	wrongParent[31] = 0x44
	if added, _ := sink.service.orphans.Add(height2Hash, wrongParent, block2Bytes, ""); !added {
		t.Fatalf("expected orphan add")
	}

	sink.service.resolveOrphans(nil, wrongParent)

	if got := sink.service.orphans.Len(); got != 1 {
		t.Fatalf("orphans.Len()=%d, want 1 after requeue", got)
	}
	if !sink.service.blockSeen.Has(height2Hash) {
		t.Fatalf("expected child hash to stay marked in blockSeen")
	}
	children := sink.service.orphans.TakeChildren(height1Hash)
	if len(children) != 1 || children[0].blockHash != height2Hash {
		t.Fatalf("children=%v, want requeued child under actual parent", children)
	}
}

func TestProcessRelayedBlockDoesNotMarkSeenWhenOrphanIsRejected(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 0, "127.0.0.1:0", nil)

	height2Hash, ok, err := source.blockStore.CanonicalHash(2)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(2): ok=%v err=%v", ok, err)
	}
	block2Bytes, err := source.blockStore.GetBlockByHash(height2Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash(height2): %v", err)
	}
	sink.service.orphans.byteLimit = 1

	peer := &peer{
		service: sink.service,
		state: node.PeerState{
			RemoteVersion: testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 2),
		},
	}

	summary, err := peer.processRelayedBlock(block2Bytes)
	if err != nil {
		t.Fatalf("processRelayedBlock(rejected orphan): %v", err)
	}
	if summary != nil {
		t.Fatalf("summary=%v, want nil when orphan is not retained", summary)
	}
	if sink.service.orphans.Len() != 0 {
		t.Fatalf("orphans.Len()=%d, want 0", sink.service.orphans.Len())
	}
	// Rejected orphans must NOT be added to blockSeen: blockSeen is
	// consulted by needsInventory(), so poisoning it would suppress
	// valid block announcements from other peers.
	if sink.service.blockSeen.Has(height2Hash) {
		t.Fatalf("blockSeen must not be set for rejected orphans")
	}
}

func TestProcessRelayedBlockRejectsInvalidOrphanPoWBeforeRetention(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 0, "127.0.0.1:0", nil)

	height2Hash, ok, err := source.blockStore.CanonicalHash(2)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(2): ok=%v err=%v", ok, err)
	}
	block2Bytes, err := source.blockStore.GetBlockByHash(height2Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash(height2): %v", err)
	}
	invalid := append([]byte(nil), block2Bytes...)
	for i := 76; i < 108; i++ {
		invalid[i] = 0
	}

	peer := &peer{
		service: sink.service,
		state: node.PeerState{
			Addr:          "127.0.0.1:39001",
			RemoteVersion: testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 2),
		},
	}

	summary, err := peer.processRelayedBlock(invalid)
	if err == nil {
		t.Fatalf("processRelayedBlock(invalid orphan pow) unexpectedly succeeded")
	}
	if summary != nil {
		t.Fatalf("summary=%v, want nil", summary)
	}
	if sink.service.orphans.Len() != 0 {
		t.Fatalf("orphans.Len()=%d, want 0", sink.service.orphans.Len())
	}
	if state := peer.snapshotState(); state.BanScore < 100 {
		t.Fatalf("ban_score=%d, want >= 100", state.BanScore)
	}
}

func TestAcceptedRelayedBlockBroadcastsResolvedOrphans(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)

	height1Hash, block1Bytes := testHarnessBlockAtHeight(t, source, 1)
	height2Hash, block2Bytes := testHarnessBlockAtHeight(t, source, 2)

	if added, _ := sink.service.orphans.Add(height2Hash, height1Hash, block2Bytes, ""); !added {
		t.Fatalf("expected orphan add")
	}
	sink.service.blockSeen.Add(height2Hash)

	readFrames := registerRelayFrameSink(t, sink.service, "relay-peer", 2)

	originPeer := testPeerForService(sink.service, "origin", 2)

	summary, err := originPeer.processRelayedBlock(block1Bytes)
	if err != nil {
		t.Fatalf("processRelayedBlock(block1): %v", err)
	}
	if summary == nil || summary.BlockHeight != 1 {
		t.Fatalf("summary=%v, want block height 1", summary)
	}

	assertInventoryFrameHashes(t, readFrames(), []InventoryVector{
		{Type: MSG_BLOCK, Hash: height1Hash},
		{Type: MSG_BLOCK, Hash: height2Hash},
	})
}

func TestProcessRelayedBlockRejectsSideBranchTimestampBeforeAcceptedInventory(t *testing.T) {
	sink := newTestHarness(t, 3, "127.0.0.1:0", nil)
	_, block1Bytes := testHarnessBlockAtHeight(t, sink, 1)
	genesisParsed, err := consensus.ParseBlockBytes(node.DevnetGenesisBlockBytes())
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	sideBlock := blockWithHeaderTimestamp(t, block1Bytes, genesisParsed.Header.Timestamp)
	_, sideHash, err := parseRelayedBlock(sideBlock)
	if err != nil {
		t.Fatalf("parseRelayedBlock(side): %v", err)
	}

	readFrames, closeProbe := registerRelayFrameProbe(t, sink.service, "relay-peer")
	defer closeProbe()

	peer := testPeerForService(sink.service, "remote", 3)
	before := sink.syncEngine.BlockApplyCounts()
	summary, err := peer.processRelayedBlock(sideBlock)
	if err == nil {
		t.Fatalf("expected timestamp-invalid side block rejection")
	}
	if summary != nil {
		t.Fatalf("summary=%v, want nil", summary)
	}
	requireP2PConsensusTxErrCode(t, err, consensus.BLOCK_ERR_TIMESTAMP_OLD)
	if after := sink.syncEngine.BlockApplyCounts(); after != before {
		t.Fatalf("timestamp-invalid side block changed BlockApplyCounts from %+v to %+v", before, after)
	}
	if sink.service.blockSeen.Has(sideHash) {
		t.Fatalf("timestamp-invalid side block must not be marked seen")
	}
	assertNoRelayFrame(t, readFrames, "timestamp-invalid side block")
	if _, err := sink.blockStore.GetBlockByHash(sideHash); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("GetBlockByHash(timestamp-invalid side) err=%v, want not-exist", err)
	}
}

func TestHandshakeSlotNilServiceAndChannel(t *testing.T) {
	var nilSvc *Service
	if !nilSvc.tryAcquireHandshakeSlot() {
		t.Fatal("nil service should return true")
	}
	nilSvc.releaseHandshakeSlot()

	svc := &Service{}
	if !svc.tryAcquireHandshakeSlot() {
		t.Fatal("nil channel should return true")
	}
	svc.releaseHandshakeSlot()
}

func TestHandshakeSlotHelpersBoundCapacity(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	limit := h.service.cfg.PeerRuntimeConfig.MaxPeers
	for i := 0; i < limit; i++ {
		if !h.service.tryAcquireHandshakeSlot() {
			t.Fatalf("tryAcquireHandshakeSlot() failed at slot %d/%d", i+1, limit)
		}
	}
	if h.service.tryAcquireHandshakeSlot() {
		t.Fatalf("tryAcquireHandshakeSlot() succeeded past max peers")
	}
	for i := 0; i < limit; i++ {
		h.service.releaseHandshakeSlot()
	}
	if !h.service.tryAcquireHandshakeSlot() {
		t.Fatalf("expected released slot to be reusable")
	}
	h.service.releaseHandshakeSlot()
}

func TestRetainOrResolveOrphanImmediatelyResolvesWhenParentAlreadyExists(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)

	height1Hash, ok, err := source.blockStore.CanonicalHash(1)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(1): ok=%v err=%v", ok, err)
	}
	block1Bytes, err := source.blockStore.GetBlockByHash(height1Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash(height1): %v", err)
	}

	sink.service.retainOrResolveOrphan(nil, height1Hash, node.DevnetGenesisBlockHash(), block1Bytes)

	if got := sink.service.orphans.Len(); got != 0 {
		t.Fatalf("orphans.Len()=%d, want 0 after immediate resolve", got)
	}
	if !sink.service.blockSeen.Has(height1Hash) {
		t.Fatalf("expected block hash to remain marked as seen")
	}
	height, tipHash, ok, err := sink.blockStore.Tip()
	if err != nil {
		t.Fatalf("sink tip: %v", err)
	}
	if !ok || height != 1 || tipHash != height1Hash {
		t.Fatalf("tip=(%d,%x,%v), want (1,%x,true)", height, tipHash, ok, height1Hash)
	}
}

// testHarnessDefaultTxMetadata is the TxMetadataFunc wired by newTestHarness
// and newPeerRuntimeTestPeer so tests that do not exercise fee/size specifics
// still satisfy the NewService non-nil-provider contract. Tests that need a
// specific provider override the field after construction.
func testHarnessDefaultTxMetadata(b []byte) (node.RelayTxMetadata, error) {
	return node.RelayTxMetadata{Fee: 0, Size: len(b)}, nil
}

func newTestHarness(t *testing.T, blockCount int, bindAddr string, bootstrapPeers []string) *testHarness {
	t.Helper()

	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	chainState := node.NewChainState()
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	syncCfg := node.DefaultSyncConfig(&target, node.DevnetGenesisChainID(), chainStatePath)
	syncEngine, err := node.NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}

	h := &testHarness{
		peerManager: node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8)),
		chainState:  chainState,
		blockStore:  blockStore,
		syncCfg:     syncCfg,
		syncEngine:  syncEngine,
		timestamp:   1_777_000_000,
	}

	if blockCount > 0 {
		if _, err := h.syncEngine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
			t.Fatalf("ApplyBlock(genesis): %v", err)
		}
	}
	for i := 1; i < blockCount; i++ {
		_ = h.mineNextBlockBytes(t)
	}

	runtimeCfg := node.DefaultPeerRuntimeConfig("devnet", 8)
	runtimeCfg.ReadDeadline = time.Second
	runtimeCfg.WriteDeadline = time.Second
	runtimeCfg.HandshakeTimeout = time.Second

	service, err := NewService(ServiceConfig{
		BindAddr:          bindAddr,
		BootstrapPeers:    bootstrapPeers,
		UserAgent:         "rubin-go/test",
		GenesisHash:       node.DevnetGenesisBlockHash(),
		PeerRuntimeConfig: runtimeCfg,
		PeerManager:       h.peerManager,
		SyncConfig:        syncCfg,
		SyncEngine:        syncEngine,
		BlockStore:        blockStore,
		TxMetadataFunc:    testHarnessDefaultTxMetadata,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	h.service = service
	return h
}

func (h *testHarness) mineNextBlockBytes(t *testing.T) []byte {
	t.Helper()

	minerCfg := node.DefaultMinerConfig()
	minerCfg.TimestampSource = func() uint64 {
		h.timestamp++
		return h.timestamp
	}
	miner, err := node.NewMiner(h.chainState, h.blockStore, h.syncEngine, minerCfg)
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	mined, err := miner.MineOne(context.Background(), nil)
	if err != nil {
		t.Fatalf("MineOne: %v", err)
	}
	blockBytes, err := h.blockStore.GetBlockByHash(mined.Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash: %v", err)
	}
	return blockBytes
}

func testHarnessBlockAtHeight(t *testing.T, h *testHarness, height uint64) ([32]byte, []byte) {
	t.Helper()

	hash, ok, err := h.blockStore.CanonicalHash(height)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(%d): ok=%v err=%v", height, ok, err)
	}
	blockBytes, err := h.blockStore.GetBlockByHash(hash)
	if err != nil {
		t.Fatalf("GetBlockByHash(height %d): %v", height, err)
	}
	return hash, blockBytes
}

func blockWithHeaderTimestamp(t *testing.T, block []byte, timestamp uint64) []byte {
	t.Helper()
	const timestampOffset = 4 + 32 + 32
	if len(block) < consensus.BLOCK_HEADER_BYTES {
		t.Fatalf("block length=%d, want at least header length %d", len(block), consensus.BLOCK_HEADER_BYTES)
	}
	out := append([]byte(nil), block...)
	binary.LittleEndian.PutUint64(out[timestampOffset:timestampOffset+8], timestamp)
	return out
}

func requireP2PConsensusTxErrCode(t *testing.T, err error, want consensus.ErrorCode) {
	t.Helper()
	var txErr *consensus.TxError
	if !errors.As(err, &txErr) {
		t.Fatalf("err=%T %v, want consensus.TxError code %s", err, err, want)
	}
	if txErr.Code != want {
		t.Fatalf("err code=%s, want %s", txErr.Code, want)
	}
}

func registerRelayFrameProbe(t *testing.T, svc *Service, addr string) (<-chan message, func()) {
	t.Helper()

	remotePeer := newPeerRuntimeTestPeer(t)
	remotePeer.service = svc
	remotePeer.state.Addr = addr
	local, remote := net.Pipe()
	remotePeer.conn = local
	closeBoth := func() {
		_ = local.Close()
		_ = remote.Close()
	}
	t.Cleanup(closeBoth)

	svc.peersMu.Lock()
	svc.peers[remotePeer.addr()] = remotePeer
	svc.peersMu.Unlock()

	frames := make(chan message, 1)
	go func() {
		frame, err := readFrame(remote, networkMagic(svc.cfg.PeerRuntimeConfig.Network), svc.cfg.PeerRuntimeConfig.MaxMessageSize)
		if err == nil {
			frames <- frame
		}
	}()
	return frames, closeBoth
}

func assertNoRelayFrame(t *testing.T, frames <-chan message, label string) {
	t.Helper()
	select {
	case frame := <-frames:
		t.Fatalf("unexpected relay frame for %s: command=%q", label, frame.Command)
	case <-time.After(100 * time.Millisecond):
		return
	}
}

func testPeerForService(svc *Service, userAgent string, bestHeight uint64) *peer {
	return &peer{
		service: svc,
		state: node.PeerState{
			RemoteVersion: testVersionPayload(
				node.DevnetGenesisChainID(),
				node.DevnetGenesisBlockHash(),
				userAgent,
				bestHeight,
			),
		},
	}
}

func assertRelayedBlockIsOrphan(t *testing.T, p *peer, blockBytes []byte, label string) {
	t.Helper()
	summary, err := p.processRelayedBlock(blockBytes)
	if err != nil {
		t.Fatalf("processRelayedBlock(%s): %v", label, err)
	}
	if summary != nil {
		t.Fatalf("expected nil summary for orphan %s", label)
	}
}

func assertOrphanPoolLen(t *testing.T, svc *Service, want int) {
	t.Helper()
	if got := svc.orphans.Len(); got != want {
		t.Fatalf("orphans.Len()=%d, want %d", got, want)
	}
}

func assertBlockInventoryKnown(t *testing.T, p *peer, hash [32]byte, label string) {
	t.Helper()
	missing, err := p.needsInventory(InventoryVector{Type: MSG_BLOCK, Hash: hash})
	if err != nil || missing {
		t.Fatalf("needsInventory(%s)=%v err=%v, want false,nil", label, missing, err)
	}
}

func assertHarnessTip(t *testing.T, h *testHarness, wantHeight uint64, wantHash [32]byte) {
	t.Helper()
	height, tipHash, ok, err := h.blockStore.Tip()
	if err != nil {
		t.Fatalf("tip: %v", err)
	}
	if !ok || height != wantHeight {
		t.Fatalf("height=%d ok=%v, want %d/true", height, ok, wantHeight)
	}
	if tipHash != wantHash {
		t.Fatalf("tip hash=%x, want %x", tipHash, wantHash)
	}
}

func registerRelayFrameSink(t *testing.T, svc *Service, addr string, frameCount int) func() []message {
	t.Helper()

	remotePeer := newPeerRuntimeTestPeer(t)
	remotePeer.service = svc
	remotePeer.state.Addr = addr
	local, remote := net.Pipe()
	remotePeer.conn = local
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})

	svc.peersMu.Lock()
	svc.peers[remotePeer.addr()] = remotePeer
	svc.peersMu.Unlock()

	frames := make(chan message, frameCount)
	errs := make(chan error, 1)
	go func() {
		for i := 0; i < frameCount; i++ {
			frame, readErr := readFrame(remote, networkMagic(svc.cfg.PeerRuntimeConfig.Network), svc.cfg.PeerRuntimeConfig.MaxMessageSize)
			if readErr != nil {
				errs <- readErr
				return
			}
			frames <- frame
		}
	}()

	return func() []message {
		t.Helper()
		out := make([]message, 0, frameCount)
		timeout := time.After(5 * time.Second)
		for len(out) < frameCount {
			select {
			case frame := <-frames:
				out = append(out, frame)
			case err := <-errs:
				t.Fatalf("readFrame(remote): %v", err)
			case <-timeout:
				t.Fatalf("timed out reading %d relay frames; got %d", frameCount, len(out))
			}
		}
		return out
	}
}

func assertInventoryFrameHashes(t *testing.T, frames []message, want []InventoryVector) {
	t.Helper()
	if len(frames) != len(want) {
		t.Fatalf("frames=%d, want %d", len(frames), len(want))
	}
	for i, frame := range frames {
		if frame.Command != messageInv {
			t.Fatalf("frame %d command=%q, want %q", i, frame.Command, messageInv)
		}
		items, err := decodeInventoryVectors(frame.Payload)
		if err != nil {
			t.Fatalf("decodeInventoryVectors(frame %d): %v", i, err)
		}
		if len(items) != 1 {
			t.Fatalf("frame %d inventory length=%d, want 1", i, len(items))
		}
		if items[0] != want[i] {
			t.Fatalf("frame %d inventory=%+v, want %+v", i, items[0], want[i])
		}
	}
}

func testVersionPayload(chainID, genesisHash [32]byte, userAgent string, bestHeight uint64) node.VersionPayloadV1 {
	return node.VersionPayloadV1{
		ProtocolVersion:   ProtocolVersion,
		TxRelay:           true,
		PrunedBelowHeight: 0,
		DaMempoolSize:     0,
		ChainID:           chainID,
		GenesisHash:       genesisHash,
		BestHeight:        bestHeight,
		UserAgent:         userAgent,
	}
}

func sendRemoteVersionOnly(conn net.Conn, cfg node.PeerRuntimeConfig, remoteVersion node.VersionPayloadV1) error {
	frame, err := readFrame(conn, networkMagic(cfg.Network), cfg.MaxMessageSize)
	if err != nil {
		return err
	}
	if frame.Command != messageVersion {
		return fmt.Errorf("unexpected message kind: %s", frame.Command)
	}
	payload, err := encodeVersionPayload(remoteVersion)
	if err != nil {
		return err
	}
	return writeFrame(conn, networkMagic(cfg.Network), message{Command: messageVersion, Payload: payload}, cfg.MaxMessageSize)
}

func completeRemoteHandshake(conn net.Conn, cfg node.PeerRuntimeConfig, remoteVersion node.VersionPayloadV1) error {
	if err := sendRemoteVersionOnly(conn, cfg, remoteVersion); err != nil {
		return err
	}
	frame, err := readFrame(conn, networkMagic(cfg.Network), cfg.MaxMessageSize)
	if err != nil {
		return err
	}
	if frame.Command != messageVerAck {
		return fmt.Errorf("unexpected message kind: %s", frame.Command)
	}
	return writeFrame(conn, networkMagic(cfg.Network), message{Command: messageVerAck}, cfg.MaxMessageSize)
}

func waitFor(t *testing.T, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func waitForPeerQuotaLockRefs(t *testing.T, s *Service, quotaKey string, want int) {
	t.Helper()
	waitFor(t, time.Second, func() bool {
		s.peerQuotaLocksMu.Lock()
		defer s.peerQuotaLocksMu.Unlock()
		quotaLock := s.peerQuotaLocks[quotaKey]
		return quotaLock != nil && quotaLock.refs == want
	})
}

func TestRetainOrResolveOrphanClearsSeenForEvictedOrphan(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 0, "127.0.0.1:0", nil)

	height1Hash, ok, err := source.blockStore.CanonicalHash(1)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(1): ok=%v err=%v", ok, err)
	}
	height2Hash, ok, err := source.blockStore.CanonicalHash(2)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(2): ok=%v err=%v", ok, err)
	}
	block1Bytes, err := source.blockStore.GetBlockByHash(height1Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash(height1): %v", err)
	}
	block2Bytes, err := source.blockStore.GetBlockByHash(height2Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash(height2): %v", err)
	}

	sink.service.orphans.limit = 1

	peer := &peer{service: sink.service}
	if _, err := peer.processRelayedBlock(block1Bytes); err != nil {
		t.Fatalf("processRelayedBlock(block1): %v", err)
	}
	if !sink.service.blockSeen.Has(height1Hash) {
		t.Fatalf("expected first orphan in blockSeen")
	}
	if _, err := peer.processRelayedBlock(block2Bytes); err != nil {
		t.Fatalf("processRelayedBlock(block2): %v", err)
	}
	if sink.service.orphans.Len() != 1 {
		t.Fatalf("orphans.Len()=%d, want 1", sink.service.orphans.Len())
	}
	if sink.service.blockSeen.Has(height1Hash) {
		t.Fatalf("expected evicted orphan hash to be removed from blockSeen")
	}
	if !sink.service.blockSeen.Has(height2Hash) {
		t.Fatalf("expected latest orphan hash to remain in blockSeen")
	}
}

// TestFaultAttributionSplitConsensusVsIO verifies that consensus-invalid blocks
// still result in a hard ban (100 points) after ApplyBlockWithReorg fault
// attribution is split between peer-invalid and local/runtime failures.
func TestFaultAttributionSplitConsensusVsIO(t *testing.T) {
	// Source has genesis+block1. Sink has genesis only.
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)

	height1Hash, ok, err := source.blockStore.CanonicalHash(1)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(1): ok=%v err=%v", ok, err)
	}
	block1Bytes, err := source.blockStore.GetBlockByHash(height1Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash(height1): %v", err)
	}

	// Corrupt the merkle root (bytes 36..68 in the header) so consensus
	// validation fails.  Parent (genesis) exists in sink, so
	// ApplyBlockWithReorg is reached and should return a TxError.
	corrupted := append([]byte(nil), block1Bytes...)
	for i := 36; i < 68; i++ {
		corrupted[i] = 0xFF
	}

	peer := &peer{
		service: sink.service,
		state: node.PeerState{
			Addr:          "127.0.0.1:41001",
			RemoteVersion: testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 2),
		},
	}

	_, applyErr := peer.processRelayedBlock(corrupted)
	if applyErr == nil {
		t.Fatalf("expected error for corrupted block")
	}
	// The error should be a consensus TxError (hard ban path).
	var txErr *consensus.TxError
	if !errors.As(applyErr, &txErr) {
		t.Fatalf("expected TxError, got %T: %v", applyErr, applyErr)
	}
	if state := peer.snapshotState(); state.BanScore < 100 {
		t.Fatalf("ban_score=%d, want >= 100 for consensus error", state.BanScore)
	}
}

func TestFaultAttributionSplitLocalApplyErrorDoesNotHardBan(t *testing.T) {
	// Source has genesis+block1. Sink has genesis only, but we replace the
	// sync engine with an uninitialized zero-value to force a local/runtime
	// ApplyBlockWithReorg failure after parent discovery succeeds.
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)

	height1Hash, ok, err := source.blockStore.CanonicalHash(1)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(1): ok=%v err=%v", ok, err)
	}
	block1Bytes, err := source.blockStore.GetBlockByHash(height1Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash(height1): %v", err)
	}

	sink.service.cfg.SyncEngine = &node.SyncEngine{}

	peer := &peer{
		service: sink.service,
		state: node.PeerState{
			Addr:          "127.0.0.1:41002",
			RemoteVersion: testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 2),
		},
	}

	_, applyErr := peer.processRelayedBlock(block1Bytes)
	if applyErr == nil {
		t.Fatalf("expected local/runtime error")
	}
	if state := peer.snapshotState(); state.BanScore != 0 {
		t.Fatalf("ban_score=%d, want 0 for local/runtime error", state.BanScore)
	}
	if state := peer.snapshotState(); state.LastError == "" {
		t.Fatalf("expected local/runtime error to be recorded in LastError")
	}
}

func TestIsConsensusApplyBlockError(t *testing.T) {
	if isConsensusApplyBlockError(nil) {
		t.Fatalf("nil error must not be treated as consensus error")
	}
	if isConsensusApplyBlockError(errors.New("local runtime failure")) {
		t.Fatalf("plain runtime error must not be treated as consensus error")
	}
	if !isConsensusApplyBlockError(&consensus.TxError{Code: consensus.TX_ERR_PARSE, Msg: "bad block"}) {
		t.Fatalf("consensus TxError must be treated as consensus error")
	}
}
