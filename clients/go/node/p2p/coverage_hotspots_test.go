package p2p

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestCoverage_NewServiceAndListenerGuards(t *testing.T) {
	if _, err := NewService(ServiceConfig{}); err == nil {
		t.Fatalf("expected bind address rejection")
	}
	if _, err := NewService(ServiceConfig{BindAddr: "127.0.0.1:0"}); err == nil {
		t.Fatalf("expected nil peer manager rejection")
	}
	if _, err := NewService(ServiceConfig{BindAddr: "127.0.0.1:0", PeerManager: node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))}); err == nil {
		t.Fatalf("expected nil sync engine rejection")
	}
	var nilService *Service
	if err := nilService.Start(context.Background()); err == nil {
		t.Fatalf("expected nil service start rejection")
	}
	if err := nilService.Close(); err != nil {
		t.Fatalf("nil close: %v", err)
	}
	if addr := nilService.Addr(); addr != "" {
		t.Fatalf("nil addr=%q", addr)
	}

	h := newTestHarness(t, 0, "127.0.0.1:0", []string{"", "  "})
	if err := h.service.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()
	if err := h.service.Start(context.Background()); err == nil {
		t.Fatalf("expected already-started rejection")
	}
	if !strings.Contains(h.service.Addr(), ":") {
		t.Fatalf("unexpected addr=%q", h.service.Addr())
	}
}

func TestCoverage_NewServiceDefaultsAndAnnounceBlock(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	svc, err := NewService(ServiceConfig{
		BindAddr:    "127.0.0.1:0",
		PeerManager: h.peerManager,
		SyncConfig:  h.syncCfg,
		SyncEngine:  h.syncEngine,
		BlockStore:  h.blockStore,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc.cfg.TxPool == nil || svc.cfg.UserAgent == "" || svc.cfg.GenesisHash == ([32]byte{}) || svc.cfg.LocatorLimit == 0 || svc.cfg.GetBlocksBatchSize == 0 {
		t.Fatalf("expected defaults to be populated: %#v", svc.cfg)
	}
	if err := (*Service)(nil).AnnounceBlock(nil); err == nil {
		t.Fatalf("expected nil service announce block rejection")
	}
	if err := svc.AnnounceBlock([]byte{0x00}); err == nil {
		t.Fatalf("expected invalid block parse")
	}
	blockBytes := h.mineNextBlockBytes(t)
	if err := svc.AnnounceBlock(blockBytes); err != nil {
		t.Fatalf("AnnounceBlock(valid): %v", err)
	}
	if err := svc.AnnounceBlock(blockBytes); err != nil {
		t.Fatalf("AnnounceBlock(duplicate): %v", err)
	}
}

func TestCoverage_HandshakeHelpers(t *testing.T) {
	localConn, remoteConn := net.Pipe()
	defer localConn.Close()
	defer remoteConn.Close()

	cfg := node.DefaultPeerRuntimeConfig("devnet", 8)
	cfg.HandshakeTimeout = time.Second
	localVersion := testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "local", 0)

	go func() {
		_, _ = readFrame(remoteConn, networkMagic(cfg.Network), cfg.MaxMessageSize)
		_ = writeFrame(remoteConn, networkMagic(cfg.Network), message{Command: messageInv}, cfg.MaxMessageSize)
	}()
	state, err := performHandshake(context.Background(), localConn, cfg, localVersion, localVersion.ChainID, localVersion.GenesisHash)
	if err == nil || state.LastError != "unexpected pre-handshake command" {
		t.Fatalf("expected unexpected pre-handshake command, got state=%+v err=%v", state, err)
	}

	if got := handshakeDeadline(nil, time.Second); got.Before(time.Now()) {
		t.Fatalf("deadline unexpectedly in the past")
	}
	if normalizeDuration(0, time.Second) != time.Second || normalizeDuration(time.Millisecond, time.Second) != time.Millisecond {
		t.Fatalf("normalizeDuration mismatch")
	}

	state2 := node.PeerState{}
	if err := validateRemoteVersion(testVersionPayload([32]byte{}, node.DevnetGenesisBlockHash(), "ua", 0), ProtocolVersion, node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), 10, &state2); err == nil {
		t.Fatalf("expected magic mismatch")
	}
}

func TestCoverage_AnnounceTxAndHandleTxBranches(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	if err := (*Service)(nil).AnnounceTx(nil); err == nil {
		t.Fatalf("expected nil service reject")
	}
	if err := h.service.AnnounceTx([]byte{0x00}); err == nil {
		t.Fatalf("expected parse reject")
	}

	fromKey := mustP2PMLDSA87Keypair(t)
	toKey := mustP2PMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	utxos, outpoints := testP2PUtxoSet(fromAddress, []uint64{100})
	txBytes := mustBuildSignedP2PTx(t, utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)

	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.PeerRuntimeConfig.BanThreshold = 100
	if err := p.handleTx(append(txBytes, 0x00)); err != nil {
		t.Fatalf("expected below-threshold invalid tx to be ignored, got %v", err)
	}
	if err := p.handleTx(txBytes); err != nil {
		t.Fatalf("handleTx(valid): %v", err)
	}
	if err := p.handleTx(txBytes); err != nil {
		t.Fatalf("handleTx(duplicate): %v", err)
	}

	p2 := newPeerRuntimeTestPeer(t)
	p2.service.cfg.PeerRuntimeConfig.BanThreshold = 5
	if err := p2.handleTx([]byte{0x00}); err == nil {
		t.Fatalf("expected threshold-reaching invalid tx error")
	}
}

func TestCoverage_InventoryAndBlockBranches(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	if err := p.handleGetData([]byte{0x00}); err == nil {
		t.Fatalf("expected decode reject")
	}
	if ok, err := p.needsInventory(InventoryVector{Type: 77}); err != nil || ok {
		t.Fatalf("default inventory path mismatch: ok=%v err=%v", ok, err)
	}
	if err := p.respondToInventory(InventoryVector{Type: MSG_BLOCK, Hash: [32]byte{0xaa}}); err != nil {
		t.Fatalf("missing block should be ignored, got %v", err)
	}
	if err := p.respondToInventory(InventoryVector{Type: MSG_TX, Hash: [32]byte{0xbb}}); err != nil {
		t.Fatalf("missing tx should be ignored, got %v", err)
	}
	if err := p.respondToInventory(InventoryVector{Type: 77}); err != nil {
		t.Fatalf("unknown inventory type should be ignored, got %v", err)
	}
	if _, _, err := parseRelayedBlock([]byte{0x00}); err == nil {
		t.Fatalf("expected invalid block parse")
	}
	if _, err := p.blockInventoryAfterLocators(GetBlocksPayload{}); err != nil {
		t.Fatalf("blockInventoryAfterLocators: %v", err)
	}
	if err := p.handleGetBlocks([]byte{0x00}); err == nil {
		t.Fatalf("expected invalid getblocks payload")
	}
	if err := p.handleBlock([]byte{0x00}); err == nil {
		t.Fatalf("expected invalid relayed block rejection")
	}
	if got := p.snapshotState().BanScore; got != 10 {
		t.Fatalf("ban_score=%d, want 10 for malformed block parse", got)
	}

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p.service = h.service
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	p.conn = local
	done := make(chan error, 1)
	go func() {
		_, err := readFrame(remote, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		done <- err
	}()
	if err := p.handleGetBlocks(mustEncodeGetBlocksPayload(t, GetBlocksPayload{})); err != nil {
		t.Fatalf("handleGetBlocks(empty inventory): %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("handleGetBlocks read: %v", err)
	}
	blockBytes := h.mineNextBlockBytes(t)
	if err := p.handleBlock(blockBytes); err != nil {
		t.Fatalf("handleBlock(existing block): %v", err)
	}
}

func TestCoverage_ServiceSyncPaths(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	p := newPeerRuntimeTestPeer(t)
	p.service = h.service
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	p.conn = local
	done := make(chan error, 1)
	go func() {
		_, err := readFrame(remote, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		done <- err
	}()

	if err := h.service.requestBlocksIfBehind(p); err != nil {
		t.Fatalf("requestBlocksIfBehind without tip: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("requestBlocksIfBehind read: %v", err)
	}

	h2 := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p2 := newPeerRuntimeTestPeer(t)
	p2.service = h2.service
	p2.state.RemoteVersion.BestHeight = 0
	if err := h2.service.requestBlocksIfBehind(p2); err != nil {
		t.Fatalf("requestBlocksIfBehind up-to-date: %v", err)
	}

	if _, err := h2.service.getBlocksRequestPayload(); err != nil {
		t.Fatalf("getBlocksRequestPayload: %v", err)
	}
	if have, err := h2.service.hasBlock([32]byte{0xff}); err != nil || have {
		t.Fatalf("hasBlock missing mismatch: have=%v err=%v", have, err)
	}
}

func TestCoverage_HandleConnLifecyclePaths(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = readFrame(remote, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		_ = writeFrame(remote, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), message{Command: messageVersion, Payload: []byte{0x00}}, h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	}()
	h.service.ctx = context.Background()
	h.service.handleConn(local)
	<-done
}

func TestCoverage_HandleConnSuccessPath(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.service.ctx = ctx

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	remoteDone := make(chan error, 1)
	go func() {
		frame, err := readFrame(remote, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		if err != nil {
			remoteDone <- err
			return
		}
		if frame.Command != messageVersion {
			remoteDone <- err
			return
		}
		payload, err := encodeVersionPayload(testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 0))
		if err != nil {
			remoteDone <- err
			return
		}
		if err := writeFrame(remote, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), message{Command: messageVersion, Payload: payload}, h.service.cfg.PeerRuntimeConfig.MaxMessageSize); err != nil {
			remoteDone <- err
			return
		}
		time.Sleep(20 * time.Millisecond)
		cancel()
		remoteDone <- nil
	}()

	h.service.handleConn(local)
	if err := <-remoteDone; err != nil {
		t.Fatalf("remote handshake: %v", err)
	}
}

func TestCoverage_HandleConnRunErrorPath(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.service.ctx = ctx

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	remoteDone := make(chan error, 1)
	go func() {
		frame, err := readFrame(remote, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		if err != nil {
			remoteDone <- err
			return
		}
		if frame.Command != messageVersion {
			remoteDone <- nil
			return
		}
		payload, err := encodeVersionPayload(testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 0))
		if err != nil {
			remoteDone <- err
			return
		}
		if err := writeFrame(remote, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), message{Command: messageVersion, Payload: payload}, h.service.cfg.PeerRuntimeConfig.MaxMessageSize); err != nil {
			remoteDone <- err
			return
		}
		err = writeFrame(remote, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), message{Command: messageVersion, Payload: payload}, h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		if err != nil && strings.Contains(err.Error(), "closed pipe") {
			err = nil
		}
		remoteDone <- err
	}()

	h.service.handleConn(local)
	if err := <-remoteDone; err != nil {
		t.Fatalf("remote sequence: %v", err)
	}
}

func TestCoverage_HandleConnRequestBlocksErrorPath(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.ctx = context.Background()

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	remoteDone := make(chan error, 1)
	go func() {
		frame, err := readFrame(remote, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		if err != nil {
			remoteDone <- err
			return
		}
		if frame.Command != messageVersion {
			remoteDone <- nil
			return
		}
		payload, err := encodeVersionPayload(testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 2))
		if err != nil {
			remoteDone <- err
			return
		}
		if err := writeFrame(remote, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), message{Command: messageVersion, Payload: payload}, h.service.cfg.PeerRuntimeConfig.MaxMessageSize); err != nil {
			remoteDone <- err
			return
		}
		_ = remote.Close()
		remoteDone <- nil
	}()

	if err := h.service.handleConn(local); err == nil {
		t.Fatalf("expected requestBlocksIfBehind error")
	}
	if err := <-remoteDone; err != nil {
		t.Fatalf("remote handshake: %v", err)
	}
}

func TestCoverage_RegisterPeerAndLocalVersion(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	pr := &peer{
		service: h.service,
		state: node.PeerState{
			Addr: "peer-register",
		},
	}
	if err := h.service.registerPeer(pr); err != nil {
		t.Fatalf("registerPeer: %v", err)
	}
	if _, ok := h.service.peers["peer-register"]; !ok {
		t.Fatalf("peer not registered")
	}
	h.service.unregisterPeer("peer-register")
	if _, ok := h.service.peers["peer-register"]; ok {
		t.Fatalf("peer still registered")
	}

	version, err := h.service.localVersion()
	if err != nil {
		t.Fatalf("localVersion: %v", err)
	}
	if version.BestHeight != 0 {
		t.Fatalf("best_height=%d, want 0", version.BestHeight)
	}
}

func TestCoverage_UnregisterPeerSchedulesReconnectForOutbound(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", []string{"peer-outbound"})
	h.service.scheduleReconnect("peer-outbound")
	h.service.peers["peer-outbound"] = &peer{service: h.service, state: node.PeerState{Addr: "peer-outbound"}}
	h.service.unregisterPeer("peer-outbound")
	if !h.service.isOutboundAddr("peer-outbound") {
		t.Fatalf("expected outbound peer tracking")
	}
	if got := h.service.reconnectSnapshot("peer-outbound").nextRetry; got.IsZero() {
		t.Fatalf("expected reconnect schedule after unregister")
	}
	if h.service.isOutboundAddr("  ") {
		t.Fatalf("blank outbound addr must be false")
	}
}

func mustEncodeGetBlocksPayload(t *testing.T, payload GetBlocksPayload) []byte {
	t.Helper()
	raw, err := encodeGetBlocksPayload(payload)
	if err != nil {
		t.Fatalf("encodeGetBlocksPayload: %v", err)
	}
	return raw
}

func mustP2PMLDSA87Keypair(t *testing.T) *consensus.MLDSA87Keypair {
	t.Helper()
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		t.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	t.Cleanup(func() { kp.Close() })
	return kp
}

func testP2PUtxoSet(fromAddress []byte, values []uint64) (map[consensus.Outpoint]consensus.UtxoEntry, []consensus.Outpoint) {
	utxos := make(map[consensus.Outpoint]consensus.UtxoEntry, len(values))
	outpoints := make([]consensus.Outpoint, 0, len(values))
	for i, value := range values {
		var txid [32]byte
		txid[0] = byte(i + 1)
		txid[31] = byte(i + 9)
		op := consensus.Outpoint{Txid: txid, Vout: uint32(i)}
		utxos[op] = consensus.UtxoEntry{
			Value:             value,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      append([]byte(nil), fromAddress...),
			CreationHeight:    1,
			CreatedByCoinbase: true,
		}
		outpoints = append(outpoints, op)
	}
	return utxos, outpoints
}

func mustBuildSignedP2PTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	inputs []consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
	toAddress []byte,
) []byte {
	t.Helper()
	txInputs := make([]consensus.TxInput, 0, len(inputs))
	var totalIn uint64
	for _, op := range inputs {
		entry, ok := utxos[op]
		if !ok {
			t.Fatalf("missing utxo for %x:%d", op.Txid, op.Vout)
		}
		totalIn += entry.Value
		txInputs = append(txInputs, consensus.TxInput{
			PrevTxid: op.Txid,
			PrevVout: op.Vout,
			Sequence: 0,
		})
	}
	change := totalIn - amount - fee
	outputs := []consensus.TxOutput{{
		Value:        amount,
		CovenantType: consensus.COV_TYPE_P2PK,
		CovenantData: append([]byte(nil), toAddress...),
	}}
	if change > 0 {
		outputs = append(outputs, consensus.TxOutput{
			Value:        change,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), changeAddress...),
		})
	}
	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  nonce,
		Inputs:   txInputs,
		Outputs:  outputs,
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, node.DevnetGenesisChainID(), signer); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return txBytes
}
