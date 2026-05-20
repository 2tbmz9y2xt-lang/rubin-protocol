package p2p

import (
	"context"
	"encoding/binary"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestCompactBlockTxnFlowRequestsAndAcceptsMatchingResponse(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadFromBlock(t, blockBytes, 11, 12)

	p, conn := compactTestPeerWithConn(sink)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(cmpctblock): %v", err)
	}

	frame := readCompactTestFrame(t, p, conn)
	if frame.Command != messageGetBlockTxn {
		t.Fatalf("command=%q, want getblocktxn", frame.Command)
	}
	req, err := decodeGetBlockTxnPayload(frame.Payload)
	if err != nil {
		t.Fatalf("decodeGetBlockTxnPayload: %v", err)
	}
	if req.BlockHash != blockHash || !reflect.DeepEqual(req.Indexes, []uint64{0}) {
		t.Fatalf("getblocktxn=%+v, want block %x index [0]", req, blockHash)
	}
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); !ok || outstanding.BlockHash != blockHash {
		t.Fatalf("outstanding=%+v ok=%v, want block %x", outstanding, ok, blockHash)
	}

	_, txs, err := compactBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactBlockTransactions: %v", err)
	}
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: mustEncodeBlockTxnForHash(t, blockHash, txs[:1])}); err != nil {
		t.Fatalf("handleMessage(blocktxn): %v", err)
	}
	assertHarnessTip(t, sink, 1, blockHash)
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("outstanding survived matching blocktxn: %+v", outstanding)
	}
}

func TestCmpctBlockRefreshesOutstandingExpiryAfterSend(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadFromBlock(t, blockBytes, 11, 12)
	start := time.Unix(1_777_000_010, 0)
	now := start
	sink.service.cfg.Now = func() time.Time { return now }
	sink.service.cfg.PeerRuntimeConfig.ReadDeadline = time.Second

	conn := &compactAdvancingConn{onWrite: func() {
		now = start.Add(500 * time.Millisecond)
	}}
	p := testPeerForService(sink.service, "rubin-go/test-peer", 1)
	p.conn = conn
	enableCompactRelayForTest(p)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(cmpctblock): %v", err)
	}
	frame, err := readFrame(&conn.Buffer, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if frame.Command != messageGetBlockTxn {
		t.Fatalf("command=%q, want getblocktxn", frame.Command)
	}
	outstanding, ok := p.compactOutstandingRequestSnapshot()
	if !ok || outstanding.BlockHash != blockHash {
		t.Fatalf("outstanding=%+v ok=%v, want block %x", outstanding, ok, blockHash)
	}
	wantExpiry := start.Add(1500 * time.Millisecond)
	if !outstanding.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("outstanding expiry=%s, want refreshed expiry %s", outstanding.ExpiresAt, wantExpiry)
	}
}

type compactAdvancingConn struct {
	scriptedConn
	onWrite func()
}

func (c *compactAdvancingConn) Write(p []byte) (int, error) {
	if c.onWrite != nil {
		c.onWrite()
	}
	return c.scriptedConn.Write(p)
}

func TestCompactRelayObjectCommandsRequireNegotiation(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{}
	capFn := p.postHandshakePayloadCap()
	assertCompactCommandCap(t, capFn, messageSendCmpct, sendCmpctPayloadBytes)
	for _, command := range []string{messageCmpctBlock, messageGetBlockTxn, messageBlockTxn} {
		assertCompactCommandCap(t, capFn, command, 0)
		err := p.handleMessage(message{Command: command, Payload: nil})
		if err == nil || !strings.Contains(err.Error(), "compact relay not negotiated") {
			t.Fatalf("handleMessage(%s) err=%v, want negotiation rejection", command, err)
		}
	}
	assertNoCompactOutstanding(t, p, "non-negotiated compact command")
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 2, Version: compactRelayVersion})
	assertCompactCommandCap(t, capFn, messageCmpctBlock, 0)
	enableCompactRelayForTest(p)
	for _, command := range []string{messageCmpctBlock, messageGetBlockTxn} {
		assertCompactCommandCapEnabled(t, capFn, command)
	}
	assertCompactCommandCap(t, capFn, messageBlockTxn, 0)
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: [32]byte{0x01}, MissingIndexes: []uint64{0}})
	assertBoundedBlockTxnCap(t, p)
}

func TestCmpctBlockKnownBlockStillValidatesFullPayloadShape(t *testing.T) {
	h := newTestHarness(t, 2, "127.0.0.1:0", nil)
	_, blockBytes := testHarnessBlockAtHeight(t, h, 1)
	block := compactTestPayloadFromBlock(t, blockBytes, 13, 14)
	payload := append(mustEncodeCmpctBlockPayload(t, block), 0xff)

	p, conn := compactTestPeerWithConn(h)
	err := p.handleMessage(message{Command: messageCmpctBlock, Payload: payload})
	if err == nil || !strings.Contains(err.Error(), "cmpctblock payload has trailing bytes") {
		t.Fatalf("known-block malformed cmpctblock err=%v, want full payload validation", err)
	}
	if conn.Buffer.Len() != 0 {
		t.Fatalf("known-block malformed cmpctblock wrote %d bytes, want none", conn.Buffer.Len())
	}
}

func TestCmpctBlockOversizedEntriesFallbackBeforeFullDecode(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadFromBlock(t, blockBytes, 15, 16)
	block.ShortIDs = make([]compactShortID, maxCompactRelayEntries+1)

	p, conn := compactTestPeerWithConn(sink)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(oversized cmpctblock): %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, blockHash)
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("oversized cmpctblock left outstanding: %+v", outstanding)
	}
}

func TestCmpctBlockUsesLocalTxPoolBeforeRequest(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadFromBlock(t, blockBytes, 21, 22)
	_, txs, err := compactBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactBlockTransactions: %v", err)
	}
	_, txid, _, consumed, err := consensus.ParseTx(txs[0])
	if err != nil || consumed != len(txs[0]) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	if !sink.service.cfg.TxPool.Put(txid, txs[0], uint64(len(txs[0])), len(txs[0])) {
		t.Fatalf("Put local compact tx failed")
	}

	p, conn := compactTestPeerWithConn(sink)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(cmpctblock): %v", err)
	}
	assertHarnessTip(t, sink, 1, blockHash)
	if conn.Buffer.Len() != 0 {
		t.Fatalf("local reconstruction wrote %d response bytes, want none", conn.Buffer.Len())
	}
}

func TestBlockTxnFlowPreservesLocalMatchesAcrossResponse(t *testing.T) {
	_, sink, blockHash, blockBytes, localTx := compactTestMinedBlockWithSpend(t)
	block := compactTestPayloadFromBlock(t, blockBytes, 23, 24)
	_, txs, err := compactBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactBlockTransactions: %v", err)
	}
	if !reflect.DeepEqual(txs[1], localTx) {
		t.Fatalf("test setup tx[1] does not match local tx")
	}
	_, txid, _, consumed, err := consensus.ParseTx(localTx)
	if err != nil || consumed != len(localTx) {
		t.Fatalf("ParseTx(local): consumed=%d err=%v", consumed, err)
	}
	if !sink.service.cfg.TxPool.Put(txid, localTx, uint64(len(localTx)), len(localTx)) {
		t.Fatalf("Put local compact tx failed")
	}

	p, conn := compactTestPeerWithConn(sink)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(cmpctblock): %v", err)
	}
	req := mustReadCompactGetBlockTxn(t, p, conn)
	if !reflect.DeepEqual(req.Indexes, []uint64{0}) {
		t.Fatalf("getblocktxn indexes=%v, want only missing coinbase index 0", req.Indexes)
	}
	outstanding, ok := p.compactOutstandingRequestSnapshot()
	if !ok || outstanding.Transactions[0] != nil || !reflect.DeepEqual(outstanding.Transactions[1], localTx) {
		t.Fatalf("outstanding partial txs=%+v ok=%v, want nil/local tx", outstanding.Transactions, ok)
	}
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: mustEncodeBlockTxnForHash(t, blockHash, txs[:1])}); err != nil {
		t.Fatalf("handleMessage(blocktxn): %v", err)
	}
	assertHarnessTip(t, sink, 1, blockHash)
}

func TestCompactReconstructedMissingParentRequestsFullBlockFallback(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 2)
	block := compactTestPayloadFromBlock(t, blockBytes, 23, 24)
	_, txs, err := compactBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactBlockTransactions: %v", err)
	}

	p, conn := compactTestPeerWithConn(sink)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(cmpctblock): %v", err)
	}
	_ = mustReadCompactGetBlockTxn(t, p, conn)
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: mustEncodeBlockTxnForHash(t, blockHash, txs)}); err != nil {
		t.Fatalf("handleMessage(blocktxn): %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, blockHash)
	assertOrphanPoolLen(t, sink.service, 0)
	if sink.service.blockSeen.Has(blockHash) {
		t.Fatalf("compact reconstructed missing-parent block must not mark blockSeen before full-block validation")
	}
	if got := p.snapshotState().BanScore; got != 0 {
		t.Fatalf("missing-parent compact reconstruction ban score=%d, want 0", got)
	}
}

func TestCompactRelayedBlockPropagatesLocalServiceErrors(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadFromBlock(t, blockBytes, 41, 42)
	_, txs, err := compactBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactBlockTransactions: %v", err)
	}

	for _, tc := range []struct {
		name  string
		setup func(*Service)
		want  string
	}{
		{
			name: "hasBlock error",
			setup: func(s *Service) {
				s.cfg.BlockStore = nil
			},
			want: "nil blockstore",
		},
		{
			name: "sync engine error",
			setup: func(s *Service) {
				s.cfg.SyncEngine = nil
			},
			want: "sync engine is not initialized",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
			p, conn := compactTestPeerWithConn(sink)
			tc.setup(p.service)
			err := p.processCompactTransactions(blockHash, block.Header, txs)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("processCompactTransactions err=%v, want %q", err, tc.want)
			}
			if conn.Buffer.Len() != 0 {
				t.Fatalf("local %s wrote %d fallback bytes, want none", tc.name, conn.Buffer.Len())
			}
		})
	}
}

func TestCompactRelayedBlockRecordsHeaderContextConsensusErrors(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadFromBlock(t, blockBytes, 43, 44)
	_, txs, err := compactBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactBlockTransactions: %v", err)
	}
	wrongTarget := consensus.POW_LIMIT
	wrongTarget[0] = 0x7f
	syncEngine, err := node.NewSyncEngine(
		sink.chainState,
		sink.blockStore,
		node.DefaultSyncConfig(&wrongTarget, node.DevnetGenesisChainID(), node.ChainStatePath(t.TempDir())),
	)
	if err != nil {
		t.Fatalf("NewSyncEngine(wrong target): %v", err)
	}
	sink.service.cfg.SyncEngine = syncEngine

	p, conn := compactTestPeerWithConn(sink)
	err = p.processCompactTransactions(blockHash, block.Header, txs)
	if err == nil || !strings.Contains(err.Error(), string(consensus.BLOCK_ERR_TARGET_INVALID)) {
		t.Fatalf("processCompactTransactions err=%v, want target invalid", err)
	}
	if conn.Buffer.Len() != 0 {
		t.Fatalf("target-invalid compact block wrote %d fallback bytes, want none", conn.Buffer.Len())
	}
	if state := p.snapshotState(); state.BanScore < 100 {
		t.Fatalf("ban_score=%d, want >= 100 for header-context consensus error", state.BanScore)
	}
}

func TestCmpctBlockWithPendingRequestFallsBackNewBlockWithoutOverwrite(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	firstHash, firstBytes := testHarnessBlockAtHeight(t, source, 1)
	secondHash, secondBytes := testHarnessBlockAtHeight(t, source, 2)
	first := compactTestPayloadFromBlock(t, firstBytes, 25, 26)
	second := compactTestPayloadFromBlock(t, secondBytes, 27, 28)

	p, conn := compactTestPeerWithConn(sink)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, first)}); err != nil {
		t.Fatalf("handleMessage(first cmpctblock): %v", err)
	}
	_ = mustReadCompactGetBlockTxn(t, p, conn)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, second)}); err != nil {
		t.Fatalf("handleMessage(second cmpctblock): %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, secondHash)
	outstanding, ok := p.compactOutstandingRequestSnapshot()
	if !ok || outstanding.BlockHash != firstHash {
		t.Fatalf("outstanding after second cmpctblock=%+v ok=%v, want first block %x", outstanding, ok, firstHash)
	}
}

func TestCmpctBlockRejectsInvalidHeaderBeforeRequest(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	_, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadFromBlock(t, blockBytes, 25, 26)
	const targetOffset = 4 + 32 + 32 + 8
	for i := range block.Header[targetOffset : targetOffset+32] {
		block.Header[targetOffset+i] = 0
	}

	payload := append(mustEncodeCmpctBlockPayload(t, block), 0xff)
	p, conn := compactTestPeerWithConn(sink)
	err := p.handleMessage(message{Command: messageCmpctBlock, Payload: payload})
	if err == nil || !strings.Contains(err.Error(), "target out of range") {
		t.Fatalf("handleMessage(cmpctblock invalid header) err=%v, want target rejection", err)
	}
	if conn.Buffer.Len() != 0 {
		t.Fatalf("invalid compact header wrote %d bytes, want no request", conn.Buffer.Len())
	}
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("invalid compact header left outstanding: %+v", outstanding)
	}
	if p.snapshotState().BanScore == 0 {
		t.Fatalf("invalid compact header did not bump ban score")
	}
}

func TestCmpctBlockRejectsWrongTargetBeforeMissingRequest(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	_, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadWithWrongHeaderTarget(t, compactTestPayloadFromBlock(t, blockBytes, 57, 58))

	p, conn := compactTestPeerWithConn(sink)
	err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)})
	if err == nil || !strings.Contains(err.Error(), string(consensus.BLOCK_ERR_TARGET_INVALID)) {
		t.Fatalf("handleMessage(cmpctblock wrong target) err=%v, want target rejection", err)
	}
	if conn.Buffer.Len() != 0 {
		t.Fatalf("wrong-target compact header wrote %d bytes, want no getblocktxn request", conn.Buffer.Len())
	}
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("wrong-target compact header left outstanding: %+v", outstanding)
	}
	if state := p.snapshotState(); state.BanScore < 100 {
		t.Fatalf("ban_score=%d, want >= 100 for wrong compact target", state.BanScore)
	}
}

func TestCmpctBlockRejectsWrongTargetBeforeOversizedFallback(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	_, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadWithWrongHeaderTarget(t, compactTestPayloadFromBlock(t, blockBytes, 59, 60))
	block.ShortIDs = make([]compactShortID, maxCompactRelayEntries+1)

	p, conn := compactTestPeerWithConn(sink)
	err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)})
	if err == nil || !strings.Contains(err.Error(), string(consensus.BLOCK_ERR_TARGET_INVALID)) {
		t.Fatalf("handleMessage(oversized cmpctblock wrong target) err=%v, want target rejection", err)
	}
	if conn.Buffer.Len() != 0 {
		t.Fatalf("wrong-target oversized compact block wrote %d bytes, want no fallback request", conn.Buffer.Len())
	}
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("wrong-target oversized compact block left outstanding: %+v", outstanding)
	}
	if state := p.snapshotState(); state.BanScore < 100 {
		t.Fatalf("ban_score=%d, want >= 100 for wrong compact target", state.BanScore)
	}
}

func TestBlockTxnIgnoresUnsolicitedWithoutOutstanding(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	_, txs, err := compactBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactBlockTransactions: %v", err)
	}

	p, conn := compactTestPeerWithConn(sink)
	if got := p.postHandshakePayloadCap()(messageBlockTxn); got != 0 {
		t.Fatalf("unsolicited blocktxn cap=%d, want 0", got)
	}
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: mustEncodeBlockTxnForHash(t, blockHash, txs[:1])}); err != nil {
		t.Fatalf("unsolicited blocktxn: %v", err)
	}
	if conn.Buffer.Len() != 0 {
		t.Fatalf("unsolicited blocktxn wrote %d bytes, want none", conn.Buffer.Len())
	}
	assertHarnessTip(t, sink, 0, nodeGenesisHash(t, sink))
}

func TestBlockTxnRejectsWrongHashAndCount(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadFromBlock(t, blockBytes, 31, 32)

	p, conn := compactTestPeerWithConn(sink)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(cmpctblock): %v", err)
	}
	_ = mustReadCompactGetBlockTxn(t, p, conn)
	wrongHash := blockHash
	wrongHash[0] ^= 0xff
	malformedWrongHash := append([]byte(nil), wrongHash[:]...)
	malformedWrongHash = append(malformedWrongHash, 0xff)
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: malformedWrongHash}); err != nil {
		t.Fatalf("wrong-hash blocktxn fallback: %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, blockHash)
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("wrong-hash blocktxn did not clear outstanding: %+v", outstanding)
	}
	assertHarnessTip(t, sink, 0, nodeGenesisHash(t, sink))

	p, conn = compactTestPeerWithConn(sink)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(cmpctblock): %v", err)
	}
	_ = mustReadCompactGetBlockTxn(t, p, conn)
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: mustEncodeBlockTxnForHash(t, blockHash, nil)}); err != nil {
		t.Fatalf("count-mismatch blocktxn fallback: %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, blockHash)
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("count-mismatch blocktxn did not clear outstanding: %+v", outstanding)
	}
	assertHarnessTip(t, sink, 0, nodeGenesisHash(t, sink))
}

func TestBlockTxnLateAfterExpiredOutstandingIsIgnored(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	enableCompactRelayForTest(p)
	conn := &scriptedConn{}
	p.conn = conn
	now := time.Unix(1_777_000_100, 0)
	p.service.cfg.Now = func() time.Time { return now }
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = time.Second
	hash := [32]byte{0xd1}
	tx := minimalBlockTxnTestTxBytes(104)
	shortID := mustCompactTransactionShortID(t, tx, 45, 46)
	p.setCompactOutstandingRequest(compactOutstandingRequest{
		BlockHash:       hash,
		MissingIndexes:  []uint64{0},
		MissingShortIDs: []compactShortID{shortID},
		Transactions:    make([][]byte, 1),
		Nonce1:          45,
		Nonce2:          46,
	})
	activeCap := assertBoundedBlockTxnCap(t, p)

	now = now.Add(time.Second)
	if err := p.expireCompactOutstandingRequest(); err != nil {
		t.Fatalf("expire compact outstanding: %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, hash)
	assertNoCompactOutstanding(t, p, "expired compact request")
	assertCompactCommandCap(t, p.postHandshakePayloadCap(), messageBlockTxn, activeCap)
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: mustEncodeBlockTxnForHash(t, hash, [][]byte{tx})}); err != nil {
		t.Fatalf("late blocktxn after fallback: %v", err)
	}
	assertCompactCommandCap(t, p.postHandshakePayloadCap(), messageBlockTxn, 0)
}

func TestBlockTxnRejectsResponseOrderMismatch(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	enableCompactRelayForTest(p)
	conn := &scriptedConn{}
	p.conn = conn
	txA := minimalBlockTxnTestTxBytes(101)
	txB := minimalBlockTxnTestTxBytes(102)
	nonce1, nonce2 := uint64(41), uint64(42)
	hash := [32]byte{0xab}
	shortA, err := compactTransactionShortID(txA, nonce1, nonce2)
	if err != nil {
		t.Fatalf("short A: %v", err)
	}
	shortB, err := compactTransactionShortID(txB, nonce1, nonce2)
	if err != nil {
		t.Fatalf("short B: %v", err)
	}
	p.setCompactOutstandingRequest(compactOutstandingRequest{
		BlockHash:       hash,
		MissingIndexes:  []uint64{0, 1},
		MissingShortIDs: []compactShortID{shortA, shortB},
		Transactions:    make([][]byte, 2),
		Nonce1:          nonce1,
		Nonce2:          nonce2,
	})

	err = p.handleMessage(message{Command: messageBlockTxn, Payload: mustEncodeBlockTxnForHash(t, hash, [][]byte{txB, txA})})
	if err != nil {
		t.Fatalf("order-mismatch blocktxn fallback: %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, hash)
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("order-mismatch blocktxn did not clear outstanding: %+v", outstanding)
	}
}

func TestBlockTxnMalformedAndProcessFailureFallback(t *testing.T) {
	hash := [32]byte{0xbe}
	p := newPeerRuntimeTestPeer(t)
	enableCompactRelayForTest(p)
	conn := &scriptedConn{}
	p.conn = conn
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: hash})
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: []byte{0x01}}); err != nil {
		t.Fatalf("malformed blocktxn fallback: %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, hash)
	if got := p.snapshotState().BanScore; got != 0 {
		t.Fatalf("malformed compact response ban score=%d, want fallback without ban", got)
	}

	p = newPeerRuntimeTestPeer(t)
	enableCompactRelayForTest(p)
	conn = &scriptedConn{}
	p.conn = conn
	tx := minimalBlockTxnTestTxBytes(103)
	nonce1, nonce2 := uint64(43), uint64(44)
	shortID, err := compactTransactionShortID(tx, nonce1, nonce2)
	if err != nil {
		t.Fatalf("compactTransactionShortID: %v", err)
	}
	p.setCompactOutstandingRequest(compactOutstandingRequest{
		BlockHash:       hash,
		MissingIndexes:  []uint64{0},
		MissingShortIDs: []compactShortID{shortID},
		Transactions:    make([][]byte, 1),
		Nonce1:          nonce1,
		Nonce2:          nonce2,
	})
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: mustEncodeBlockTxnForHash(t, hash, [][]byte{tx})}); err != nil {
		t.Fatalf("process-failure blocktxn fallback: %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, hash)
	if got := p.snapshotState().BanScore; got != 0 {
		t.Fatalf("compact reconstruction failure ban score=%d, want fallback without ban", got)
	}
}

func TestCompactOutstandingRequestClearsOnReadTimeout(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	conn := &scriptedConn{reads: []scriptedRead{{err: timeoutErr{}}, {err: io.EOF}}}
	p.conn = conn
	hash := [32]byte{0xcd}
	p.setCompactOutstandingRequest(compactOutstandingRequest{
		BlockHash:       hash,
		MissingIndexes:  []uint64{0},
		MissingShortIDs: []compactShortID{{0x01}},
		Transactions:    make([][]byte, 1),
	})

	if err := p.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("read timeout did not clear outstanding request: %+v", outstanding)
	}
	assertCompactFullBlockRequest(t, p, conn, hash)
}

func TestCompactOutstandingRequestExpiresBeforeUnrelatedFrame(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	conn := &scriptedConn{}
	p.conn = conn
	now := time.Unix(1_777_000_000, 0)
	p.service.cfg.Now = func() time.Time { return now }
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = time.Second
	hash := [32]byte{0xce}
	p.setCompactOutstandingRequest(compactOutstandingRequest{
		BlockHash:       hash,
		MissingIndexes:  []uint64{0},
		MissingShortIDs: []compactShortID{{0x02}},
		Transactions:    make([][]byte, 1),
	})

	now = now.Add(time.Second)
	if err := p.handleMessage(message{Command: messagePing}); err != nil {
		t.Fatalf("handleMessage(ping after compact expiry): %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, hash)
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("expired compact request still outstanding: %+v", outstanding)
	}
}

func TestGetBlockTxnRespondsWithRequestedTransactions(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	_, txs, err := compactBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactBlockTransactions: %v", err)
	}

	p, conn := compactTestPeerWithConn(source)
	if err := p.handleMessage(message{Command: messageGetBlockTxn, Payload: mustEncodeGetBlockTxnForHash(t, blockHash, []uint64{0})}); err != nil {
		t.Fatalf("handleMessage(getblocktxn): %v", err)
	}
	frame := readCompactTestFrame(t, p, conn)
	if frame.Command != messageBlockTxn {
		t.Fatalf("command=%q, want blocktxn", frame.Command)
	}
	response, err := decodeBlockTxnPayload(frame.Payload)
	if err != nil {
		t.Fatalf("decodeBlockTxnPayload: %v", err)
	}
	if response.BlockHash != blockHash || !reflect.DeepEqual(response.Transactions, txs[:1]) {
		t.Fatalf("blocktxn=%+v, want block %x tx0", response, blockHash)
	}
}

func TestGetBlockTxnRejectsDuplicateIndexesBeforeResponse(t *testing.T) {
	source := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash := [32]byte{0xee}
	p, conn := compactTestPeerWithConn(source)

	err := p.handleMessage(message{Command: messageGetBlockTxn, Payload: mustEncodeGetBlockTxnForHash(t, blockHash, []uint64{0, 0})})
	if err == nil || !strings.Contains(err.Error(), "duplicate compact relay index") {
		t.Fatalf("handleMessage(getblocktxn duplicate) err=%v, want duplicate rejection", err)
	}
	if conn.Buffer.Len() != 0 {
		t.Fatalf("duplicate getblocktxn wrote %d bytes, want no response", conn.Buffer.Len())
	}
}

func TestGetBlockTxnRejectsOutOfRangeIndexBeforeResponse(t *testing.T) {
	source := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, _ := testHarnessBlockAtHeight(t, source, 0)
	p, conn := compactTestPeerWithConn(source)

	err := p.handleMessage(message{Command: messageGetBlockTxn, Payload: mustEncodeGetBlockTxnForHash(t, blockHash, []uint64{maxCompactRelayEntries})})
	if err == nil || !strings.Contains(err.Error(), "compact relay index out of range") {
		t.Fatalf("handleMessage(getblocktxn high index) err=%v, want out-of-range rejection", err)
	}
	if conn.Buffer.Len() != 0 {
		t.Fatalf("high-index getblocktxn wrote %d bytes, want no response", conn.Buffer.Len())
	}
}

func TestCmpctBlockMissingAboveRequestCapRequestsFullBlockFallback(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestPayloadFromBlock(t, blockBytes, 51, 52)
	block.ShortIDs = make([]compactShortID, maxCompactRelayEntries+1)

	p, conn := compactTestPeerWithConn(sink)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(cmpctblock many missing): %v", err)
	}
	assertCompactFullBlockRequest(t, p, conn, blockHash)
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("many-missing cmpctblock left outstanding: %+v", outstanding)
	}
	assertHarnessTip(t, sink, 0, nodeGenesisHash(t, sink))
}

func compactTestMinedBlockWithSpend(t *testing.T) (*testHarness, *testHarness, [32]byte, []byte, []byte) {
	t.Helper()
	source := newTestHarness(t, 1, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	txBytes, _, utxos := signedCanonicalP2PTxWithoutSeeding(t, 326)
	seedHarnessUtxos(source, utxos)
	seedHarnessUtxos(sink, utxos)
	mempool := wireCanonicalMempoolForP2PTest(t, source)
	if err := mempool.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx(local spend): %v", err)
	}
	blockBytes := source.mineNextBlockBytes(t)
	blockHash, err := consensus.BlockHash(blockBytes[:consensus.BLOCK_HEADER_BYTES])
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}
	_, txs, err := compactBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactBlockTransactions: %v", err)
	}
	if len(txs) != 2 {
		t.Fatalf("mined tx count=%d, want coinbase + spend", len(txs))
	}
	return source, sink, blockHash, blockBytes, txBytes
}

func compactTestPayloadFromBlock(t *testing.T, blockBytes []byte, nonce1, nonce2 uint64) cmpctBlockPayload {
	t.Helper()
	header, txs, err := compactBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactBlockTransactions: %v", err)
	}
	shortIDs := make([]compactShortID, 0, len(txs))
	for _, tx := range txs {
		shortID, err := compactTransactionShortID(tx, nonce1, nonce2)
		if err != nil {
			t.Fatalf("compactTransactionShortID: %v", err)
		}
		shortIDs = append(shortIDs, shortID)
	}
	return cmpctBlockPayload{Header: header, Nonce1: nonce1, Nonce2: nonce2, ShortIDs: shortIDs}
}

func compactTestPayloadWithWrongHeaderTarget(t *testing.T, block cmpctBlockPayload) cmpctBlockPayload {
	t.Helper()
	const targetOffset = 4 + 32 + 32 + 8
	const nonceOffset = targetOffset + 32
	target := consensus.POW_LIMIT
	target[0] = 0xfe
	copy(block.Header[targetOffset:nonceOffset], target[:])
	for nonce := uint64(0); nonce < 1_000_000; nonce++ {
		binary.LittleEndian.PutUint64(block.Header[nonceOffset:], nonce)
		if err := consensus.PowCheck(block.Header[:], target); err == nil {
			return block
		}
	}
	t.Fatal("failed to mine wrong-target compact test header")
	return cmpctBlockPayload{}
}

func compactTestPeerWithConn(h *testHarness) (*peer, *scriptedConn) {
	conn := &scriptedConn{}
	p := testPeerForService(h.service, "rubin-go/test-peer", 1)
	p.conn = conn
	enableCompactRelayForTest(p)
	return p, conn
}

func enableCompactRelayForTest(p *peer) {
	p.service.cfg.CompactRelayObjectsEnabled = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 2, Version: compactRelayVersion})
}

func assertCompactCommandCap(t *testing.T, capFn payloadLimitFn, command string, want uint32) {
	t.Helper()
	if got := capFn(command); got != want {
		t.Fatalf("%s cap=%d, want %d", command, got, want)
	}
}

func assertCompactCommandCapEnabled(t *testing.T, capFn payloadLimitFn, command string) {
	t.Helper()
	if got := capFn(command); got == 0 {
		t.Fatalf("%s cap=0, want enabled compact cap", command)
	}
}

func assertBoundedBlockTxnCap(t *testing.T, p *peer) uint32 {
	t.Helper()
	got := p.postHandshakePayloadCap()(messageBlockTxn)
	if got == 0 || got >= compactRelayPayloadCap(messageBlockTxn) {
		t.Fatalf("blocktxn cap=%d, want bounded non-zero cap", got)
	}
	return got
}

func assertNoCompactOutstanding(t *testing.T, p *peer, context string) {
	t.Helper()
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("%s left outstanding: %+v", context, outstanding)
	}
}

func mustCompactTransactionShortID(t *testing.T, tx []byte, nonce1, nonce2 uint64) compactShortID {
	t.Helper()
	shortID, err := compactTransactionShortID(tx, nonce1, nonce2)
	if err != nil {
		t.Fatalf("compactTransactionShortID: %v", err)
	}
	return shortID
}

func readCompactTestFrame(t *testing.T, p *peer, conn *scriptedConn) message {
	t.Helper()
	frame, err := readFrame(&conn.Buffer, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	return frame
}

func mustReadCompactGetBlockTxn(t *testing.T, p *peer, conn *scriptedConn) getBlockTxnPayload {
	t.Helper()
	frame := readCompactTestFrame(t, p, conn)
	if frame.Command != messageGetBlockTxn {
		t.Fatalf("command=%q, want getblocktxn", frame.Command)
	}
	req, err := decodeGetBlockTxnPayload(frame.Payload)
	if err != nil {
		t.Fatalf("decodeGetBlockTxnPayload: %v", err)
	}
	return req
}

func assertCompactFullBlockRequest(t *testing.T, p *peer, conn *scriptedConn, blockHash [32]byte) {
	t.Helper()
	frame := readCompactTestFrame(t, p, conn)
	if frame.Command != messageGetData {
		t.Fatalf("command=%q, want getdata full-block fallback", frame.Command)
	}
	items, err := decodeInventoryVectors(frame.Payload)
	if err != nil {
		t.Fatalf("decodeInventoryVectors: %v", err)
	}
	want := []InventoryVector{{Type: MSG_BLOCK, Hash: blockHash}}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("fallback inventory=%+v, want %+v", items, want)
	}
}

func mustEncodeCmpctBlockPayload(t *testing.T, block cmpctBlockPayload) []byte {
	t.Helper()
	raw, err := encodeCmpctBlockPayload(block)
	if err != nil {
		t.Fatalf("encodeCmpctBlockPayload: %v", err)
	}
	return raw
}

func mustEncodeBlockTxnForHash(t *testing.T, blockHash [32]byte, txs [][]byte) []byte {
	t.Helper()
	raw, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: txs})
	if err != nil {
		t.Fatalf("encodeBlockTxnPayload: %v", err)
	}
	return raw
}

func mustEncodeGetBlockTxnForHash(t *testing.T, blockHash [32]byte, indexes []uint64) []byte {
	t.Helper()
	raw, err := encodeGetBlockTxnPayload(getBlockTxnPayload{BlockHash: blockHash, Indexes: indexes})
	if err != nil {
		t.Fatalf("encodeGetBlockTxnPayload: %v", err)
	}
	return raw
}

func nodeGenesisHash(t *testing.T, h *testHarness) [32]byte {
	t.Helper()
	_, hash, ok, err := h.blockStore.Tip()
	if err != nil || !ok {
		t.Fatalf("tip: ok=%v err=%v", ok, err)
	}
	return hash
}
