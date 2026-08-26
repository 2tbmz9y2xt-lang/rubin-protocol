package p2p

import (
	"context"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type testHarness struct {
	dataDir     string
	peerManager *node.PeerManager
	chainState  *node.ChainState
	blockStore  *node.BlockStore
	syncCfg     node.SyncConfig
	syncEngine  *node.SyncEngine
	mempool     *node.Mempool
	service     *Service
	timestamp   uint64
}

func unclaimedServiceConfig(t *testing.T) ServiceConfig {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	engine, err := node.NewSyncEngine(h.chainState, h.blockStore, h.syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := node.NewMempool(h.chainState, h.blockStore, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)
	cfg := h.service.cfg
	cfg.SyncEngine = engine
	return cfg
}

func TestNewServiceCloseDoesNotReleaseEngineClaim(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	want := h.syncEngine.DARelayState()
	if want == nil || h.service.daRelay != want {
		t.Fatalf("first service relay=%p engine relay=%p", h.service.daRelay, want)
	}
	if err := h.service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := NewService(h.service.cfg); err == nil || err.Error() != "sync engine DA relay state is already claimed" {
		t.Fatalf("NewService after Close: %v", err)
	}
}

func TestNewServiceRejectsUninitializedEngineAfterConfigValidation(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	uninitialized, err := node.NewSyncEngine(h.chainState, h.blockStore, h.syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	cfg := h.service.cfg
	cfg.SyncEngine = uninitialized
	if _, err := NewService(cfg); err == nil || err.Error() != "sync engine DA relay state is not initialized" {
		t.Fatalf("uninitialized engine error=%v", err)
	}
	cfg.TxMetadataFunc = nil
	if _, err := NewService(cfg); err == nil || !strings.Contains(err.Error(), "tx metadata") {
		t.Fatalf("pre-existing config error lost priority: %v", err)
	}
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

// TestProcessRelayedBlockDropsRetainedDAOrphanNotValidAgainstC1 pins where
// retained-DA cleanup now happens for a relayed block: INSIDE the canonical
// transition, not in a post-return loop.
//
// The staged orphan chunk carries its exact retained transaction bytes, exactly
// as the ingest path would, so the transition can parse it — and that
// transaction funds nothing, so it is not final_chain_valid against C1 and the
// whole record leaves the published image. The proof is that the SAME chunk
// stages again afterwards: while the record was retained, a restage is refused
// as a duplicate.
func TestProcessRelayedBlockDropsRetainedDAOrphanNotValidAgainstC1(t *testing.T) {
	sink := newTestHarness(t, 0, "127.0.0.1:0", nil)
	sink.service.cfg.Now = func() time.Time { return time.Unix(0, 0) }
	chunk := stageRetainedDAOrphanChunk(t, sink.service, daRelayTestID(100), "127.0.0.1:19111")
	if err := sink.service.daRelay.StageChunk(peerQuotaKey("127.0.0.1:19111"), chunk); err == nil {
		t.Fatal("the retained orphan did not refuse its own restage before any block was applied")
	}
	peer := testPeerForService(sink.service, "remote", 2)
	// Exactly ONE block, against an orphan TTL of 3: TTL expiry cannot be the
	// reason the record left, so the restage below can only be explained by the
	// canonical transition's own D validation.
	if _, err := peer.processRelayedBlock(node.DevnetGenesisBlockBytes()); err != nil {
		t.Fatalf("process relayed block: %v", err)
	}
	if err := sink.service.daRelay.StageChunk(peerQuotaKey("127.0.0.1:19111"), chunk); err != nil {
		t.Fatalf("the canonical transition kept a retained orphan it could not validate against C1: %v", err)
	}
}

// stageRetainedDAOrphanChunk retains one orphan chunk WITH the exact canonical
// transaction bytes its Section 5.2 admission used, which is what production
// ingest always supplies and what the canonical transition parses to derive the
// record's exact identity.
func stageRetainedDAOrphanChunk(t *testing.T, svc *Service, daID [32]byte, peerAddr string) node.DARelayChunk {
	t.Helper()
	payload := []byte{daID[0]}
	txBytes := daChunkRelayTxBytes(t, daID, 0, uint64(daID[0]), payload)
	chunk := node.DARelayChunk{
		DAID:      daID,
		ChunkHash: sha3.Sum256(payload),
		Payload:   payload,
		WireBytes: uint64(len(txBytes)),
		TxBytes:   txBytes,
	}
	if err := svc.daRelay.StageChunk(peerQuotaKey(peerAddr), chunk); err != nil {
		t.Fatalf("StageChunk: %v", err)
	}
	return chunk
}

// TestAnnounceBlockAdvancesDARelayTTL keeps the TTL mechanism observable on its
// own: AnnounceBlock applies nothing, so no canonical transition runs on this
// harness and the fenced TTL advance is the ONLY thing that can release the
// retained orphan. The blocks come from a second harness for exactly that
// reason — mining them here would run a transition and settle the question
// another way.
func TestAnnounceBlockAdvancesDARelayTTL(t *testing.T) {
	source := newTestHarness(t, 4, "127.0.0.1:0", nil)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	chunk := stageOrphanQuotaBoundary(t, h.service, 101)
	for height := uint64(1); height <= 2; height++ {
		if err := h.service.AnnounceBlock(blockAtHeight(t, source, height)); err != nil {
			t.Fatalf("AnnounceBlock(%d): %v", height, err)
		}
	}
	if err := h.service.daRelay.StageChunk(peerQuotaKey("127.0.0.1:19111"), chunk); err == nil {
		t.Fatal("the orphan expired before its TTL ran out")
	}
	if err := h.service.AnnounceBlock(blockAtHeight(t, source, 3)); err != nil {
		t.Fatalf("AnnounceBlock(3): %v", err)
	}
	if err := h.service.daRelay.StageChunk(peerQuotaKey("127.0.0.1:19111"), chunk); err != nil {
		t.Fatalf("expired local orphan was retained: %v", err)
	}
}

// stageCompleteDASetForService retains one single-chunk COMPLETE_SET through the
// exported writer wrappers, with MINIMAL metadata and DELIBERATELY non-canonical
// member bytes: TxBytes is the literal "commit"/"chunk", not the canonical
// serialization of any transaction. The record is therefore NOT what an ingest
// path would have staged, and that is what makes it serve both of its callers —
// the retention rows here and in service_work_lifecycle_test.go, which only need
// a record to be present, and latchedDAHarness, whose engine latches GENUINELY
// because the next canonical transition's D preparation cannot parse these bytes.
//
// Relocated here from the deleted da_relay_consume_test.go, unchanged.
func stageCompleteDASetForService(t *testing.T, svc *Service, daID [32]byte, payload []byte) {
	t.Helper()
	commitment := sha3.Sum256(payload)
	if err := svc.daRelay.StageCommit("peer-a", node.DARelayCommit{
		DAID:              daID,
		PayloadCommitment: commitment,
		ChunkCount:        1,
		WireBytes:         1,
		TxBytes:           []byte("commit"),
	}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
	if err := svc.daRelay.StageChunk("peer-b", node.DARelayChunk{
		DAID:       daID,
		ChunkHash:  sha3.Sum256(payload),
		ChunkIndex: 0,
		Payload:    payload,
		WireBytes:  uint64(len(payload)),
		TxBytes:    []byte("chunk"),
	}); err != nil {
		t.Fatalf("StageChunk: %v", err)
	}
}

func TestUnregisterPeerReleasesDAChunkPeerAccountingAndDropsOwnedChunk(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	owner := "127.0.0.1:19111"
	completeID := daRelayTestID(128)
	stageCompleteDASetForService(t, h.service, completeID, []byte("complete"))
	chunk := stageOrphanQuotaBoundary(t, h.service, 106)
	peer := &peer{service: h.service, state: node.PeerState{Addr: owner}}
	if err := h.service.registerPeer(peer); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	h.service.unregisterPeer(peer)
	if err := h.service.daRelay.StageChunk(peerQuotaKey(owner), chunk); err != nil {
		t.Fatalf("owned orphan was retained: %v", err)
	}
	if candidates := h.service.CompleteDASetCandidates(^uint64(0)); len(candidates) != 1 || candidates[0].DAID != completeID {
		t.Fatalf("complete candidates=%+v", candidates)
	}
}

func TestUnregisterPeerReleasesDACommitPeerAccountingAndPreservesOtherChunks(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	owner, other := "127.0.0.1:19111", "127.0.0.2:19112"
	daID := daRelayTestID(109)
	const quotaUnit = uint64(4 << 20)
	for i := byte(0); i < 13; i++ {
		stageOrphanDAChunk(t, h.service, daRelayTestID(120+i), fmt.Sprintf("127.0.2.%d:19111", i+1), quotaUnit)
	}
	chunk := stageOrphanDAChunk(t, h.service, daID, other, quotaUnit)
	if err := h.service.daRelay.StageCommit(peerQuotaKey(owner), node.DARelayCommit{DAID: daID, ChunkCount: 2, WireBytes: quotaUnit}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
	peer := &peer{service: h.service, state: node.PeerState{Addr: owner}}
	if err := h.service.registerPeer(peer); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	h.service.unregisterPeer(peer)
	if err := h.service.daRelay.StageChunk(peerQuotaKey(other), chunk); err == nil {
		t.Fatal("other peer chunk was released")
	}
	if err := h.service.daRelay.StageCommit(peerQuotaKey(owner), node.DARelayCommit{DAID: daID, ChunkCount: 2, WireBytes: quotaUnit}); err != nil {
		t.Fatalf("owned commit was retained: %v", err)
	}
	if err := h.service.daRelay.StageCommit(peerQuotaKey("127.0.0.3:19113"), node.DARelayCommit{DAID: daRelayTestID(110), ChunkCount: 2, WireBytes: quotaUnit}); err != nil {
		t.Fatalf("commit quota was not reused: %v", err)
	}
}

func TestUnregisterPeerKeepsDAAccountingForActiveQuotaKey(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	oldAddr, activeAddr := "127.0.0.1:19111", "127.0.0.1:19112"
	chunk := stageOrphanDAChunk(t, h.service, daRelayTestID(107), activeAddr)
	oldPeer := &peer{service: h.service, state: node.PeerState{Addr: oldAddr}}
	activePeer := &peer{service: h.service, state: node.PeerState{Addr: activeAddr}}
	for _, peer := range []*peer{oldPeer, activePeer} {
		if err := h.service.registerPeer(peer); err != nil {
			t.Fatalf("register peer: %v", err)
		}
	}
	h.service.unregisterPeer(oldPeer)
	if err := h.service.daRelay.StageChunk(peerQuotaKey(activeAddr), chunk); err == nil {
		t.Fatal("active quota key released retained chunk")
	}
}

func TestUnregisterPeerHoldsQuotaLockThroughPeerManagerRemoval(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	runtimeCfg := node.DefaultPeerRuntimeConfig("devnet", 1)
	h.peerManager = node.NewPeerManager(runtimeCfg)
	h.service.cfg.PeerManager, h.service.cfg.PeerRuntimeConfig = h.peerManager, runtimeCfg
	oldPeer := &peer{service: h.service, state: node.PeerState{Addr: "127.0.0.1:19111"}}
	newPeer := &peer{service: h.service, state: node.PeerState{Addr: "127.0.0.1:19112"}}
	if err := h.service.registerPeer(oldPeer); err != nil {
		t.Fatalf("register old peer: %v", err)
	}
	chunk := stageOrphanDAChunk(t, h.service, daRelayTestID(112), oldPeer.addr(), 4<<20)
	key := peerQuotaKey(oldPeer.addr())
	unlock := h.service.lockPeerQuotaKey(key)
	unregistered := make(chan struct{})
	go func() { h.service.unregisterPeer(oldPeer); close(unregistered) }()
	waitForPeerQuotaLockRefs(t, h.service, key, 2)
	registered := make(chan error, 1)
	go func() { registered <- h.service.registerPeer(newPeer) }()
	waitForPeerQuotaLockRefs(t, h.service, key, 3)
	select {
	case err := <-unregistered:
		unlock()
		t.Fatalf("unregister completed while peers barrier held: %v", err)
	case err := <-registered:
		unlock()
		t.Fatalf("replacement completed while quota locked: %v", err)
	default:
	}
	if got := h.service.cfg.PeerManager.Count(); got != 1 {
		unlock()
		t.Fatalf("peer manager count while quota locked = %d, want 1", got)
	}
	unlock()
	<-unregistered
	if err := <-registered; err != nil {
		if err.Error() != "max peers reached" || h.service.registerPeer(newPeer) != nil {
			t.Fatalf("replacement register: %v", err)
		}
	}
	if err := h.service.daRelay.StageChunk(key, chunk); err != nil {
		t.Fatalf("cleanup raced replacement: %v", err)
	}
}

func blockAtHeight(t *testing.T, h *testHarness, height uint64) []byte {
	_, block := testHarnessBlockAtHeight(t, h, height)
	return block
}

func stageOrphanDAChunk(t *testing.T, svc *Service, daID [32]byte, peerAddr string, wireBytes ...uint64) node.DARelayChunk {
	payload := []byte{daID[0]}
	wireBytesValue := uint64(len(payload))
	if len(wireBytes) != 0 {
		wireBytesValue = wireBytes[0]
	}
	chunk := node.DARelayChunk{DAID: daID, ChunkHash: sha3.Sum256(payload), Payload: payload, WireBytes: wireBytesValue}
	if err := svc.daRelay.StageChunk(peerQuotaKey(peerAddr), chunk); err != nil {
		t.Fatalf("StageChunk: %v", err)
	}
	return chunk
}

func stageOrphanQuotaBoundary(t *testing.T, svc *Service, seed byte) (first node.DARelayChunk) {
	for i := byte(0); i < 8; i++ {
		id := daRelayTestID(seed + i)
		chunk := stageOrphanDAChunk(t, svc, id, fmt.Sprintf("127.0.0.%d:19111", i+1), 4<<20)
		if i == 0 {
			first = chunk
		}
		payload := []byte{seed + i, 1}
		next := node.DARelayChunk{DAID: id, ChunkHash: sha3.Sum256(payload), ChunkIndex: 1, Payload: payload, WireBytes: 4 << 20}
		if err := svc.daRelay.StageChunk(peerQuotaKey(fmt.Sprintf("127.0.1.%d:19111", i+1)), next); err != nil {
			t.Fatalf("StageChunk: %v", err)
		}
	}
	return first
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
	sink.service.cfg.Now = func() time.Time { return time.Unix(0, 0) }

	height1Hash, block1Bytes := testHarnessBlockAtHeight(t, source, 1)
	height2Hash, block2Bytes := testHarnessBlockAtHeight(t, source, 2)

	if added, _ := sink.service.orphans.Add(height2Hash, height1Hash, block2Bytes, ""); !added {
		t.Fatalf("expected orphan add")
	}
	sink.service.blockSeen.Add(height2Hash)

	readFrames := registerRelayFrameSink(t, sink.service, "relay-peer", 2)
	sink.service.peersMu.RLock()
	relayPeer := sink.service.peers["relay-peer"]
	sink.service.peersMu.RUnlock()
	relayPeer.stateMu.Lock()
	relayPeer.state.HandshakeComplete = true
	relayPeer.stateMu.Unlock()

	originPeer := testPeerForService(sink.service, "origin", 2)
	originConn := &scriptedConn{}
	originPeer.conn = originConn
	originPeer.state.Addr = "origin"
	originPeer.state.HandshakeComplete = true
	sink.service.peersMu.Lock()
	sink.service.peers[originPeer.addr()] = originPeer
	sink.service.peersMu.Unlock()

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
	if originConn.Len() != 57 {
		t.Fatalf("source relay bytes=%d, want one child frame", originConn.Len())
	}
	items, err := decodeInventoryVectors(originConn.Bytes()[wireHeaderSize:])
	if err != nil || len(items) != 1 || items[0] != (InventoryVector{Type: MSG_BLOCK, Hash: height2Hash}) {
		t.Fatalf("source inventory=%+v err=%v, want child only", items, err)
	}
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
	return node.RelayTxMetadata{Fee: consensus.Uint128FromU64(0), Size: len(b)}, nil
}

func newTestHarness(t *testing.T, blockCount int, bindAddr string, bootstrapPeers []string) *testHarness {
	t.Helper()

	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	chainState := node.NewChainState()
	blockStore, err := node.CreateBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	syncCfg := node.DefaultSyncConfig(&target, node.DevnetGenesisChainID(), chainStatePath)
	syncEngine, err := node.NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}

	h := &testHarness{
		dataDir:     dir,
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
	mempool, err := node.NewMempool(chainState, blockStore, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	syncEngine.SetMempool(mempool)
	if syncEngine.DARelayState() == nil {
		t.Fatal("SetMempool did not initialize DA relay state")
	}
	h.mempool = mempool

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

func TestRelayedCandidateWithCorruptStoredAncestorIsPeerNeutral(t *testing.T) {
	// An honest relay with a corrupt local parent must stay peer-neutral.
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	b1Hash, _ := testHarnessBlockAtHeight(t, source, 1)
	_, b2Bytes := testHarnessBlockAtHeight(t, source, 2)
	b2Parsed, b2Hash, err := parseRelayedBlock(b2Bytes)
	if err != nil || b2Parsed == nil {
		t.Fatalf("parseRelayedBlock(B2): parsed=%v err=%v", b2Parsed, err)
	}

	storePath := filepath.Join(node.BlockStorePath(sink.dataDir), "blocks", hex.EncodeToString(b1Hash[:])+".bin")
	if err := os.WriteFile(storePath, []byte("corrupt stored parent"), 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt parent): %v", err)
	}
	peer := testPeerForService(sink.service, "remote", 2)
	beforeHeight, beforeTip, beforeOK, err := sink.blockStore.Tip()
	if err != nil || !beforeOK {
		t.Fatalf("sink tip before: height=%d hash=%x ok=%v err=%v", beforeHeight, beforeTip, beforeOK, err)
	}

	summary, err := peer.processRelayedBlock(b2Bytes)
	if err == nil || summary != nil {
		t.Fatalf("processRelayedBlock(corrupt stored parent): summary=%v err=%v", summary, err)
	}
	var txErr *consensus.TxError
	if errors.As(err, &txErr) {
		t.Fatalf("local stored corruption leaked consensus error: %v", err)
	}
	if state := peer.snapshotState(); state.BanScore != 0 || state.LastError == "" {
		t.Fatalf("peer state=%+v, want peer-neutral local diagnostic", state)
	}
	if sink.service.blockSeen.Has(b2Hash) {
		t.Fatal("locally failed relayed candidate must not be marked seen")
	}
	afterHeight, afterTip, afterOK, err := sink.blockStore.Tip()
	if err != nil || afterOK != beforeOK || afterHeight != beforeHeight || afterTip != beforeTip {
		t.Fatalf("sink tip after: height=%d hash=%x ok=%v err=%v", afterHeight, afterTip, afterOK, err)
	}
}

func TestRelayedHeavierCandidateWithCorruptStoredChainWorkHeaderIsPeerNeutral(t *testing.T) {
	// The source's B2 is an honest two-block branch above the genesis common
	// ancestor. Sink stores the valid B1 body/header as a side ancestor so the
	// P2P relay reaches fork-choice, where the corrupted canonical genesis
	// HEADER (not its full block body) is consumed by ChainWork.
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	b1Hash, b1Bytes := testHarnessBlockAtHeight(t, source, 1)
	_, b2Bytes := testHarnessBlockAtHeight(t, source, 2)
	_, b2Hash, err := parseRelayedBlock(b2Bytes)
	if err != nil {
		t.Fatalf("parseRelayedBlock(B2): %v", err)
	}
	candidateWork, err := source.blockStore.ChainWork(b2Hash)
	if err != nil {
		t.Fatalf("source ChainWork(B2): %v", err)
	}
	genesisWork, err := source.blockStore.ChainWork(node.DevnetGenesisBlockHash())
	if err != nil || candidateWork.Cmp(genesisWork) <= 0 {
		t.Fatalf("honest candidate work=%v genesis work=%v err=%v, want heavier branch", candidateWork, genesisWork, err)
	}
	b1Header, err := source.blockStore.GetHeaderByHash(b1Hash)
	if err != nil {
		t.Fatalf("GetHeaderByHash(B1): %v", err)
	}
	if err := sink.blockStore.StoreBlock(b1Hash, b1Header, b1Bytes); err != nil {
		t.Fatalf("StoreBlock(side B1): %v", err)
	}

	genesisHash := node.DevnetGenesisBlockHash()
	storedGenesis, err := sink.blockStore.GetBlockByHash(genesisHash)
	if err != nil {
		t.Fatalf("GetBlockByHash(genesis): %v", err)
	}
	parsedGenesis, err := consensus.ParseBlockBytes(storedGenesis)
	if err != nil {
		t.Fatalf("ParseBlockBytes(stored genesis): %v", err)
	}
	if bodyHash, err := consensus.BlockHash(parsedGenesis.HeaderBytes); err != nil || bodyHash != genesisHash {
		t.Fatalf("stored genesis body identity=(%x,%v), want %x,nil", bodyHash, err, genesisHash)
	}
	headerPath := filepath.Join(node.BlockStorePath(sink.dataDir), "headers", hex.EncodeToString(genesisHash[:])+".bin")
	if err := os.WriteFile(headerPath, b1Header, 0o600); err != nil {
		t.Fatalf("WriteFile(substituted canonical header): %v", err)
	}

	peer := testPeerForService(sink.service, "remote", 2)
	beforeHeight, beforeTip, beforeOK, err := sink.blockStore.Tip()
	if err != nil || !beforeOK {
		t.Fatalf("sink tip before: height=%d hash=%x ok=%v err=%v", beforeHeight, beforeTip, beforeOK, err)
	}
	summary, err := peer.processRelayedBlock(b2Bytes)
	if err == nil || summary != nil || !strings.Contains(err.Error(), "stored header") {
		t.Fatalf("processRelayedBlock(corrupt ChainWork header): summary=%v err=%v", summary, err)
	}
	var txErr *consensus.TxError
	if errors.As(err, &txErr) {
		t.Fatalf("local ChainWork header corruption leaked consensus.TxError: %v", err)
	}
	if state := peer.snapshotState(); state.BanScore != 0 || state.LastError == "" {
		t.Fatalf("peer state=%+v, want peer-neutral local diagnostic", state)
	}
	if sink.service.blockSeen.Has(b2Hash) {
		t.Fatal("locally failed relayed candidate must not be marked seen")
	}
	afterHeight, afterTip, afterOK, err := sink.blockStore.Tip()
	if err != nil || afterOK != beforeOK || afterHeight != beforeHeight || afterTip != beforeTip {
		t.Fatalf("sink tip after: height=%d hash=%x ok=%v err=%v", afterHeight, afterTip, afterOK, err)
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

// B1 parity matrix rows 14-16: the Go behavioral reference for block presence.
// Absence is only reported when a healthy lookup proves it; a local store fault
// is an error, never absence. Rust mirror: `has_block_local_store_rows`.
func TestServiceHasBlockLocalStoreRows(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	tip, _, ok, err := h.blockStore.Tip()
	if err != nil || !ok {
		t.Fatalf("tip = %d ok=%v err=%v", tip, ok, err)
	}
	_, tipHash, _, err := h.blockStore.Tip()
	if err != nil {
		t.Fatalf("tip hash: %v", err)
	}

	// Row 14: readable header -> present.
	if have, err := h.service.hasBlock(tipHash); err != nil || !have {
		t.Fatalf("readable header: have=%v err=%v, want true/nil", have, err)
	}
	// Row 15: healthy missing header -> absent, NOT an error.
	if have, err := h.service.hasBlock([32]byte{0xab}); err != nil || have {
		t.Fatalf("missing header: have=%v err=%v, want false/nil", have, err)
	}
	// Row 16: the header path exists but cannot be read -> error, not absence.
	var unreadable [32]byte
	unreadable[0] = 0x5a
	leaf := filepath.Join(node.BlockStorePath(h.dataDir), "headers", hex.EncodeToString(unreadable[:])+".bin")
	if err := os.Mkdir(leaf, 0o700); err != nil {
		t.Fatalf("header leaf as directory: %v", err)
	}
	have, err := h.service.hasBlock(unreadable)
	if err == nil {
		t.Fatalf("a failed header read must not read as absence (have=%v)", have)
	}
	if os.IsNotExist(err) {
		t.Fatalf("read failure must not be classified as NotFound: %v", err)
	}
}
