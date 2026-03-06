package p2p

import (
	"context"
	"fmt"
	"net"
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
		frame, err := readFrame(remoteConn, cfg.MaxMessageSize)
		if err != nil {
			errCh <- err
			return
		}
		if frame.Kind != messageVersion {
			errCh <- fmt.Errorf("unexpected message kind: %d", frame.Kind)
			return
		}
		payload, err := encodeVersionPayload(remoteVersion)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- writeFrame(remoteConn, message{Kind: messageVersion, Payload: payload}, cfg.MaxMessageSize)
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
	if state.RemoteVersion.UserAgent != remoteVersion.UserAgent {
		t.Fatalf("user_agent=%q, want %q", state.RemoteVersion.UserAgent, remoteVersion.UserAgent)
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
		frame, err := readFrame(remoteConn, cfg.MaxMessageSize)
		if err != nil {
			return
		}
		if frame.Kind != messageVersion {
			return
		}
		payload, err := encodeVersionPayload(remoteVersion)
		if err != nil {
			return
		}
		_ = writeFrame(remoteConn, message{Kind: messageVersion, Payload: payload}, cfg.MaxMessageSize)
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

func testVersionPayload(chainID, genesisHash [32]byte, userAgent string, bestHeight uint64) node.VersionPayloadV1 {
	return node.VersionPayloadV1{
		Magic:           ProtocolMagic,
		ProtocolVersion: ProtocolVersion,
		ChainID:         chainID,
		GenesisHash:     genesisHash,
		UserAgent:       userAgent,
		BestHeight:      bestHeight,
	}
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
