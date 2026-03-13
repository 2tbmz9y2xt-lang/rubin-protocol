package p2p

import (
	"context"
	"errors"
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

	peer := &peer{
		service: sink.service,
		state: node.PeerState{
			RemoteVersion: testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 2),
		},
	}

	if summary, err := peer.processRelayedBlock(block2Bytes); err != nil {
		t.Fatalf("processRelayedBlock(block2): %v", err)
	} else if summary != nil {
		t.Fatalf("expected nil summary for orphan block2")
	}
	if summary, err := peer.processRelayedBlock(block1Bytes); err != nil {
		t.Fatalf("processRelayedBlock(block1): %v", err)
	} else if summary != nil {
		t.Fatalf("expected nil summary for orphan block1")
	}
	if got := sink.service.orphans.Len(); got != 2 {
		t.Fatalf("orphans.Len()=%d, want 2", got)
	}
	if missing, err := peer.needsInventory(InventoryVector{Type: MSG_BLOCK, Hash: height2Hash}); err != nil || missing {
		t.Fatalf("needsInventory(orphan height2)=%v err=%v, want false,nil", missing, err)
	}

	summary, err := peer.processRelayedBlock(genesisBytes)
	if err != nil {
		t.Fatalf("processRelayedBlock(genesis): %v", err)
	}
	if summary == nil || summary.BlockHeight != 0 {
		t.Fatalf("genesis summary=%v, want height 0", summary)
	}
	if got := sink.service.orphans.Len(); got != 0 {
		t.Fatalf("orphans.Len()=%d, want 0 after resolve", got)
	}
	height, tipHash, ok, err := sink.blockStore.Tip()
	if err != nil {
		t.Fatalf("sink tip: %v", err)
	}
	if !ok || height != 2 {
		t.Fatalf("sink height=%d ok=%v, want 2/true", height, ok)
	}
	if tipHash != height2Hash {
		t.Fatalf("sink tip hash=%x, want %x", tipHash, height2Hash)
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

	if added, _ := sink.service.orphans.Add(height2Hash, height1Hash, block2Bytes, ""); !added {
		t.Fatalf("expected orphan add")
	}
	sink.service.blockSeen.Add(height2Hash)

	remotePeer := newPeerRuntimeTestPeer(t)
	remotePeer.service = sink.service
	remotePeer.state.Addr = "relay-peer"
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	remotePeer.conn = local
	sink.service.peersMu.Lock()
	sink.service.peers[remotePeer.addr()] = remotePeer
	sink.service.peersMu.Unlock()

	frames := make(chan message, 2)
	go func() {
		for i := 0; i < 2; i++ {
			frame, readErr := readFrame(remote, networkMagic(sink.service.cfg.PeerRuntimeConfig.Network), sink.service.cfg.PeerRuntimeConfig.MaxMessageSize)
			if readErr != nil {
				t.Errorf("readFrame(remote): %v", readErr)
				return
			}
			frames <- frame
		}
	}()

	originPeer := &peer{
		service: sink.service,
		state: node.PeerState{
			RemoteVersion: testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "origin", 2),
		},
	}

	summary, err := originPeer.processRelayedBlock(block1Bytes)
	if err != nil {
		t.Fatalf("processRelayedBlock(block1): %v", err)
	}
	if summary == nil || summary.BlockHeight != 1 {
		t.Fatalf("summary=%v, want block height 1", summary)
	}

	first := <-frames
	second := <-frames
	if first.Command != messageInv || second.Command != messageInv {
		t.Fatalf("unexpected commands: %q, %q", first.Command, second.Command)
	}
	firstItems, err := decodeInventoryVectors(first.Payload)
	if err != nil {
		t.Fatalf("decodeInventoryVectors(first): %v", err)
	}
	secondItems, err := decodeInventoryVectors(second.Payload)
	if err != nil {
		t.Fatalf("decodeInventoryVectors(second): %v", err)
	}
	if len(firstItems) != 1 || len(secondItems) != 1 {
		t.Fatalf("inventory lengths=%d/%d, want 1/1", len(firstItems), len(secondItems))
	}
	if firstItems[0].Hash != height1Hash {
		t.Fatalf("first relayed hash=%x, want %x", firstItems[0].Hash, height1Hash)
	}
	if secondItems[0].Hash != height2Hash {
		t.Fatalf("second relayed hash=%x, want %x", secondItems[0].Hash, height2Hash)
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
