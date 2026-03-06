package p2p

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestShouldIgnoreAndNormalizeReadError(t *testing.T) {
	if !shouldIgnoreReadError(os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded to be ignored")
	}
	if !shouldIgnoreReadError(timeoutErr{}) {
		t.Fatalf("expected timeout net.Error to be ignored")
	}
	if shouldIgnoreReadError(io.EOF) {
		t.Fatalf("expected EOF to not be ignored")
	}

	if err := normalizeReadError(io.EOF); err != nil {
		t.Fatalf("EOF should normalize to nil, got %v", err)
	}
	if err := normalizeReadError(net.ErrClosed); err != nil {
		t.Fatalf("net.ErrClosed should normalize to nil, got %v", err)
	}
	boom := errors.New("boom")
	if err := normalizeReadError(boom); !errors.Is(err, boom) {
		t.Fatalf("normalizeReadError changed error: %v", err)
	}
}

func TestHandleMessageRejectsInvalidKinds(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	if err := p.handleMessage(message{Kind: messageVersion}); err == nil || !strings.Contains(err.Error(), "invalid version message") {
		t.Fatalf("expected version rejection, got %v", err)
	}
	if err := p.handleMessage(message{Kind: 0xff}); err == nil || !strings.Contains(err.Error(), "unknown message type") {
		t.Fatalf("expected unknown-kind rejection, got %v", err)
	}
}

func TestMissingInventoryAndNeedsInventory(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	var seenBlock [32]byte
	seenBlock[0] = 0x01
	p.service.blockSeen.Add(seenBlock)

	var unknownBlock [32]byte
	unknownBlock[0] = 0x02
	var unseenTx [32]byte
	unseenTx[0] = 0x03
	var pooledTx [32]byte
	pooledTx[0] = 0x04
	p.service.cfg.TxPool.Put(pooledTx, []byte{0x01})

	items := []InventoryVector{
		{Type: MSG_BLOCK, Hash: seenBlock},
		{Type: MSG_BLOCK, Hash: unknownBlock},
		{Type: MSG_TX, Hash: unseenTx},
		{Type: MSG_TX, Hash: pooledTx},
		{Type: 99, Hash: [32]byte{0x05}},
	}
	requests, err := p.missingInventory(items)
	if err != nil {
		t.Fatalf("missingInventory: %v", err)
	}
	if len(requests) != 2 {
		t.Fatalf("requests=%v, want 2 items", requests)
	}
	if requests[0].Hash != unknownBlock || requests[1].Hash != unseenTx {
		t.Fatalf("unexpected requests order/content: %v", requests)
	}
}

func TestCanonicalTxIDAcceptsCanonicalAndRejectsTrailingBytes(t *testing.T) {
	txBytes := mustMarshalPeerRuntimeTx(t, &consensus.Tx{
		Version:   1,
		TxKind:    0x00,
		TxNonce:   7,
		Inputs:    nil,
		Outputs:   nil,
		Locktime:  0,
		Witness:   nil,
		DaPayload: nil,
	})

	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}
	_, parsedTxID, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if consumed != len(txBytes) {
		t.Fatalf("consumed=%d len=%d", consumed, len(txBytes))
	}
	if txid != parsedTxID {
		t.Fatalf("txid mismatch")
	}

	_, err = canonicalTxID(append(append([]byte(nil), txBytes...), 0x00))
	if err == nil || !strings.Contains(err.Error(), "non-canonical tx bytes") {
		t.Fatalf("expected non-canonical error, got %v", err)
	}
}

func TestSetLastErrorAndBumpBanPersistState(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.setLastError("read failed")
	snap := p.snapshotState()
	if snap.LastError != "read failed" {
		t.Fatalf("last_error=%q, want read failed", snap.LastError)
	}

	if p.bumpBan(50, "warn") {
		t.Fatalf("unexpected ban threshold reached")
	}
	if !p.bumpBan(60, "fatal") {
		t.Fatalf("expected ban threshold reached")
	}
	snap = p.snapshotState()
	if snap.BanScore != 110 {
		t.Fatalf("ban_score=%d, want 110", snap.BanScore)
	}
	if snap.LastError != "fatal" {
		t.Fatalf("last_error=%q, want fatal", snap.LastError)
	}
	pmState := p.service.cfg.PeerManager.Snapshot()
	if len(pmState) != 1 || pmState[0].BanScore != 110 {
		t.Fatalf("peer manager snapshot=%v, want single updated peer", pmState)
	}
}

func TestSendAndRunContextCancellation(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	p.conn = local
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = 0
	p.service.cfg.PeerRuntimeConfig.WriteDeadline = 0

	errCh := make(chan error, 1)
	go func() {
		msg, err := readFrame(remote, p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		if err != nil {
			errCh <- err
			return
		}
		if msg.Kind != messageTx || !bytes.Equal(msg.Payload, []byte{0xaa, 0xbb}) {
			errCh <- errors.New("unexpected frame")
			return
		}
		errCh <- nil
	}()

	if err := p.send(messageTx, []byte{0xaa, 0xbb}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("remote read: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.run(ctx); err != nil {
		t.Fatalf("run(ctx canceled): %v", err)
	}
}

func newPeerRuntimeTestPeer(t *testing.T) *peer {
	t.Helper()
	dir := t.TempDir()
	chainState := node.NewChainState()
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncEngine, err := node.NewSyncEngine(
		chainState,
		blockStore,
		node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), node.ChainStatePath(dir)),
	)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	cfg := ServiceConfig{
		BindAddr:          "127.0.0.1:0",
		GenesisHash:       node.DevnetGenesisBlockHash(),
		PeerManager:       node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8)),
		SyncConfig:        node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), node.ChainStatePath(dir)),
		SyncEngine:        syncEngine,
		BlockStore:        blockStore,
		TxPool:            NewMemoryTxPool(),
		PeerRuntimeConfig: node.DefaultPeerRuntimeConfig("devnet", 8),
		Now:               time.Now,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	pr := &peer{
		service: svc,
		state: node.PeerState{
			Addr: "peer-test",
			RemoteVersion: node.VersionPayloadV1{
				BestHeight: 0,
			},
		},
	}
	if err := svc.cfg.PeerManager.AddPeer(&pr.state); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	return pr
}

func mustMarshalPeerRuntimeTx(t *testing.T, tx *consensus.Tx) []byte {
	t.Helper()
	b, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return b
}
