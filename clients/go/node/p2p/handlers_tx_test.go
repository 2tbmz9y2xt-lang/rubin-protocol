package p2p

import (
	"bytes"
	"context"
	"crypto/sha3"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// minimalValidTxBytes builds the smallest transaction that consensus.ParseTx
// accepts. It has 0 inputs, 0 outputs, no witness, and no DA payload.
// This is enough to exercise all code paths in handleTx (parse → pool → seen → relay)
// without needing a full blockchain (coinbase maturity, UTXO spending, ML-DSA signing).
func minimalValidTxBytes(t *testing.T) []byte {
	t.Helper()
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx minimal: %v", err)
	}
	return raw
}

// distinctTxBytes returns a valid tx with a unique nonce so that each call
// produces a different txid.
func distinctTxBytes(t *testing.T, nonce uint64) []byte {
	t.Helper()
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: nonce,
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx nonce=%d: %v", nonce, err)
	}
	return raw
}

func daCommitRelayTxBytes(t *testing.T, daID [32]byte, nonce uint64, payloads ...[]byte) []byte {
	t.Helper()
	if len(payloads) == 0 {
		t.Fatal("DA commit test tx requires at least one payload")
	}
	commitment := daRelayPayloadCommitment(payloads...)
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x01,
		TxNonce: nonce,
		Outputs: []consensus.TxOutput{{
			Value:        0,
			CovenantType: consensus.COV_TYPE_DA_COMMIT,
			CovenantData: append([]byte(nil), commitment[:]...),
		}},
		DaCommitCore: &consensus.DaCommitCore{
			DaID:       daID,
			ChunkCount: uint16(len(payloads)),
		},
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx DA commit: %v", err)
	}
	return raw
}

func daChunkRelayTxBytes(t *testing.T, daID [32]byte, index uint16, nonce uint64, payload []byte) []byte {
	t.Helper()
	chunkHash := sha3.Sum256(payload)
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x02,
		TxNonce: nonce,
		DaChunkCore: &consensus.DaChunkCore{
			DaID:       daID,
			ChunkIndex: index,
			ChunkHash:  chunkHash,
		},
		DaPayload: cloneBytes(payload),
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx DA chunk: %v", err)
	}
	return raw
}

func sameTxIDWithSentinelWitness(t *testing.T, raw []byte) []byte {
	t.Helper()
	tx, txid, err := parseCanonicalTx(raw)
	if err != nil {
		t.Fatalf("parse canonical tx: %v", err)
	}
	tx.Witness = []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL}}
	alt, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx alternate witness: %v", err)
	}
	altTxid, err := canonicalTxID(alt)
	if err != nil {
		t.Fatalf("alternate witness txid: %v", err)
	}
	if altTxid != txid || bytes.Equal(alt, raw) {
		t.Fatalf("alternate witness txid=%x want %x different_bytes=%v", altTxid, txid, !bytes.Equal(alt, raw))
	}
	return alt
}

func sameTxIDWithDAPayload(t *testing.T, raw []byte, payload []byte) []byte {
	t.Helper()
	tx, txid, err := parseCanonicalTx(raw)
	if err != nil {
		t.Fatalf("parse canonical tx: %v", err)
	}
	tx.DaPayload = cloneBytes(payload)
	alt, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx alternate DA payload: %v", err)
	}
	altTxid, err := canonicalTxID(alt)
	if err != nil {
		t.Fatalf("alternate DA payload txid: %v", err)
	}
	if altTxid != txid || bytes.Equal(alt, raw) {
		t.Fatalf("alternate DA payload txid=%x want %x different_bytes=%v", altTxid, txid, !bytes.Equal(alt, raw))
	}
	return alt
}

func daRelayRecordSnapshot(t *testing.T, state *daRelayState, daID [32]byte) (daRelaySetRecord, bool) {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	record, ok := state.sets[daID]
	return record.clone(), ok
}

func daRelayStoredRecordSnapshot(t *testing.T, state *daRelayState, daID [32]byte) (daRelaySetRecord, bool) {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	record, ok := state.sets[daID]
	return record.cloneForStateMutation(), ok
}

func daRelayTestPeer(h *testHarness, addr string) *peer {
	return &peer{
		service: h.service,
		state:   node.PeerState{Addr: addr, HandshakeComplete: true},
	}
}

func putRelayTx(pool *MemoryTxPool, txid [32]byte, raw []byte) bool {
	return pool.Put(txid, raw, uint64(len(raw)), len(raw))
}

type rejectingTxPool struct{}

func (rejectingTxPool) Get([32]byte) ([]byte, bool) { return nil, false }

func (rejectingTxPool) Has([32]byte) bool { return false }

func (rejectingTxPool) Put([32]byte, []byte, uint64, int) bool { return false }

type inconsistentTxPool struct {
	raw []byte
	ok  bool
}

func (p inconsistentTxPool) Get([32]byte) ([]byte, bool) {
	return cloneBytes(p.raw), p.ok
}

func (p inconsistentTxPool) Has([32]byte) bool { return true }

func (p inconsistentTxPool) Put([32]byte, []byte, uint64, int) bool { return false }

func wireCanonicalMempoolForP2PTest(t *testing.T, h *testHarness) *node.Mempool {
	t.Helper()
	if h == nil || h.service == nil {
		t.Fatal("nil p2p test harness")
	}
	mempool, err := node.NewMempool(h.chainState, h.blockStore, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	h.syncEngine.SetMempool(mempool)
	h.service.cfg.TxPool = NewCanonicalMempoolTxPool(mempool)
	h.service.cfg.TxMetadataFunc = CanonicalMempoolRelayMetadata
	return mempool
}

func signedCanonicalP2PTxForHarness(t *testing.T, h *testHarness, nonce uint64) ([]byte, [32]byte, map[consensus.Outpoint]consensus.UtxoEntry) {
	t.Helper()
	txBytes, txid, utxos := signedCanonicalP2PTxWithoutSeeding(t, nonce)
	seedHarnessUtxos(h, utxos)
	return txBytes, txid, utxos
}

func signedCanonicalP2PTxWithoutSeeding(t *testing.T, nonce uint64) ([]byte, [32]byte, map[consensus.Outpoint]consensus.UtxoEntry) {
	t.Helper()
	fromKey := mustP2PMLDSA87Keypair(t)
	toKey := mustP2PMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	utxos, outpoints := testP2PUtxoSet(fromAddress, []uint64{1_000_000})
	for op, entry := range utxos {
		entry.CreatedByCoinbase = false
		entry.CreationHeight = 0
		utxos[op] = entry
	}
	txBytes := mustBuildSignedP2PTx(t, utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, nonce, fromKey, fromAddress, toAddress)
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}
	return txBytes, txid, utxos
}

func seedHarnessUtxos(h *testHarness, utxos map[consensus.Outpoint]consensus.UtxoEntry) {
	for op, entry := range utxos {
		h.chainState.Utxos[op] = entry
	}
}

func parsedBlockHasTxID(block *consensus.ParsedBlock, txid [32]byte) bool {
	if block == nil {
		return false
	}
	for _, got := range block.Txids {
		if got == txid {
			return true
		}
	}
	return false
}

func TestHandleTxMalformed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	pool := h.service.cfg.TxPool
	p := &peer{
		service: h.service,
		state: node.PeerState{
			HandshakeComplete: true,
		},
	}

	// Malformed tx (garbage bytes) should bump ban score
	err := p.handleTx([]byte{0xFF, 0xFE})
	if err != nil {
		t.Fatalf("handleTx malformed should not return error for sub-threshold ban: %v", err)
	}
	if p.state.BanScore == 0 {
		t.Fatal("ban score should be > 0 after malformed tx")
	}

	// Pool should NOT contain the malformed tx
	if pool.Has([32]byte{}) {
		t.Fatal("malformed tx should not be in pool")
	}
}

func TestHandleTxValid(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	pool := h.service.cfg.TxPool.(*MemoryTxPool)
	p := &peer{
		service: h.service,
		state: node.PeerState{
			HandshakeComplete: true,
		},
	}

	txBytes := minimalValidTxBytes(t)
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}

	err = p.handleTx(txBytes)
	if err != nil {
		t.Fatalf("handleTx valid: %v", err)
	}

	// Tx should be in pool
	if !pool.Has(txid) {
		t.Fatal("valid tx should be in pool after handleTx")
	}

	// Tx should be in txSeen
	if !h.service.txSeen.Has(txid) {
		t.Fatal("valid tx should be in txSeen after handleTx")
	}

	// Second call: duplicate should be silently ignored (pool.Put returns false)
	poolLenBefore := pool.Len()
	err = p.handleTx(txBytes)
	if err != nil {
		t.Fatalf("handleTx duplicate: %v", err)
	}
	if pool.Len() != poolLenBefore {
		t.Fatal("duplicate handleTx should not add to pool")
	}
}

func TestHandleTxStagesDATxsIntoRelayState(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := daRelayTestPeer(h, "127.0.0.1:19111")
	daID := daRelayTestID(120)
	payload := []byte("relay-da-payload")
	commitTx := daCommitRelayTxBytes(t, daID, 9101, payload)
	chunkTx := daChunkRelayTxBytes(t, daID, 0, 9102, payload)

	if err := p.handleTx(commitTx); err != nil {
		t.Fatalf("handleTx DA commit: %v", err)
	}
	record, ok := daRelayRecordSnapshot(t, h.service.daRelay, daID)
	if !ok {
		t.Fatal("DA commit tx did not create a relay state record")
	}
	if record.state != daRelayStateStagedCommit || record.commit.chunkCount != 1 {
		t.Fatalf("DA commit relay state=%v chunk_count=%d, want staged/1", record.state, record.commit.chunkCount)
	}
	if record.commit.payloadCommitment != daRelayPayloadCommitment(payload) {
		t.Fatal("DA commit relay state stored wrong payload commitment")
	}

	if err := p.handleTx(chunkTx); err != nil {
		t.Fatalf("handleTx DA chunk: %v", err)
	}
	record, ok = daRelayRecordSnapshot(t, h.service.daRelay, daID)
	if !ok {
		t.Fatal("DA chunk tx removed relay state record")
	}
	if record.state != daRelayStateCompleteSet {
		t.Fatalf("DA relay state=%v, want complete set", record.state)
	}
	if record.payloadBytes != uint64(len(payload)) || h.service.daRelay.pinnedPayloadBytes == 0 {
		t.Fatalf("DA complete accounting payload=%d pinned=%d", record.payloadBytes, h.service.daRelay.pinnedPayloadBytes)
	}
}

func TestStageRelayDATxIgnoresIncompleteMetadata(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	daID := daRelayTestID(123)
	peerAddr := "127.0.0.1:19114"

	var nilService *Service
	if err := nilService.stageRelayDATx(peerAddr, nil, &consensus.Tx{}); err != nil {
		t.Fatalf("nil service stageRelayDATx: %v", err)
	}
	if err := h.service.stageRelayDATx(peerAddr, nil, nil); err != nil {
		t.Fatalf("nil tx stageRelayDATx: %v", err)
	}
	if err := h.service.stageRelayDATx(peerAddr, []byte{0x01}, &consensus.Tx{TxKind: 0x01}); err != nil {
		t.Fatalf("DA commit without core: %v", err)
	}
	if err := h.service.stageRelayDATx(peerAddr, []byte{0x02}, &consensus.Tx{TxKind: 0x02}); err != nil {
		t.Fatalf("DA chunk without core: %v", err)
	}

	wrongCovenant := &consensus.Tx{
		TxKind: 0x01,
		Outputs: []consensus.TxOutput{{
			CovenantType: consensus.COV_TYPE_P2PK,
		}},
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: 1},
	}
	if err := h.service.stageRelayDATx(peerAddr, []byte{0x03}, wrongCovenant); err != nil {
		t.Fatalf("DA commit without DA covenant output: %v", err)
	}

	badCommitment := &consensus.Tx{
		TxKind: 0x01,
		Outputs: []consensus.TxOutput{{
			CovenantType: consensus.COV_TYPE_DA_COMMIT,
			CovenantData: []byte{0x01},
		}},
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: 1},
	}
	if err := h.service.stageRelayDATx(peerAddr, []byte{0x04}, badCommitment); err != nil {
		t.Fatalf("DA commit with short commitment: %v", err)
	}
	if _, ok := daRelayRecordSnapshot(t, h.service.daRelay, daID); ok {
		t.Fatal("incomplete DA metadata mutated relay state")
	}
}

func TestHandleTxNonCanonical(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	p := &peer{
		service: h.service,
		state: node.PeerState{
			HandshakeComplete: true,
		},
	}

	// Valid tx bytes + trailing garbage → non-canonical (consumed != len)
	txBytes := minimalValidTxBytes(t)
	nonCanonical := append(txBytes, 0x00, 0x00)

	err := p.handleTx(nonCanonical)
	if err != nil {
		t.Fatalf("handleTx non-canonical should not error (sub-threshold): %v", err)
	}
	if p.state.BanScore == 0 {
		t.Fatal("ban score should be > 0 after non-canonical tx")
	}
}

func TestHandleTxDAAdmissionRejectsDoNotMutateRelayState(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := daRelayTestPeer(h, "127.0.0.1:19112")
	daID := daRelayTestID(121)
	payload := []byte("relay-da-bad-payload")
	nonCanonical := append(daCommitRelayTxBytes(t, daID, 9201, payload), 0x00)
	if err := p.handleTx(nonCanonical); err != nil {
		t.Fatalf("handleTx non-canonical DA commit: %v", err)
	}
	if _, ok := daRelayRecordSnapshot(t, h.service.daRelay, daID); ok {
		t.Fatal("non-canonical DA commit mutated relay state")
	}

	badChunk := daChunkRelayTxBytes(t, daID, 0, 9202, payload)
	badChunk[len(badChunk)-1] ^= 0xff
	if err := p.handleTx(badChunk); err != nil {
		t.Fatalf("handleTx DA chunk hash mismatch: %v", err)
	}
	if _, ok := daRelayRecordSnapshot(t, h.service.daRelay, daID); ok {
		t.Fatal("DA chunk hash mismatch mutated relay state")
	}
	if p.snapshotState().BanScore != 10 {
		t.Fatalf("ban score=%d, want only the non-canonical parse penalty", p.snapshotState().BanScore)
	}
}

func TestAnnounceTx(t *testing.T) {
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

	txBytes := minimalValidTxBytes(t)
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}

	// Announce on source
	if err := source.service.AnnounceTx(txBytes); err != nil {
		t.Fatalf("AnnounceTx: %v", err)
	}

	// Source pool should have it
	if !source.service.cfg.TxPool.Has(txid) {
		t.Fatal("source pool should have tx after AnnounceTx")
	}

	// Source txSeen should have it
	if !source.service.txSeen.Has(txid) {
		t.Fatal("source txSeen should have tx after AnnounceTx")
	}

	// Sink should receive via relay (inv → getData → handleTx)
	waitFor(t, 5*time.Second, func() bool {
		return sink.service.cfg.TxPool.Has(txid)
	})
}

func TestAnnounceTxStagesDAOnceAcrossLocalAndInbound(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := daRelayTestPeer(h, "127.0.0.1:19113")
	daID := daRelayTestID(122)
	payload := []byte("relay-da-local-payload")
	commitTx := daCommitRelayTxBytes(t, daID, 9301, payload)
	chunkTx := daChunkRelayTxBytes(t, daID, 0, 9302, payload)

	if err := h.service.AnnounceTx(commitTx); err != nil {
		t.Fatalf("AnnounceTx DA commit: %v", err)
	}
	if err := p.handleTx(commitTx); err != nil {
		t.Fatalf("handleTx duplicate DA commit: %v", err)
	}
	record, ok := daRelayRecordSnapshot(t, h.service.daRelay, daID)
	if !ok {
		t.Fatal("local DA commit did not create relay state")
	}
	if record.state != daRelayStateStagedCommit || record.receivedTime != 1 {
		t.Fatalf("after duplicate DA commit state=%v received_time=%d, want staged/1", record.state, record.receivedTime)
	}

	if err := h.service.AnnounceTx(chunkTx); err != nil {
		t.Fatalf("AnnounceTx DA chunk: %v", err)
	}
	if err := p.handleTx(chunkTx); err != nil {
		t.Fatalf("handleTx duplicate DA chunk: %v", err)
	}
	record, ok = daRelayRecordSnapshot(t, h.service.daRelay, daID)
	if !ok {
		t.Fatal("local DA chunk removed relay state")
	}
	if record.state != daRelayStateCompleteSet || record.receivedTime != 1 || h.service.daRelay.nextReceivedTime != 1 {
		t.Fatalf("duplicate local/inbound DA relay state=%v received=%d next=%d, want complete/1/1", record.state, record.receivedTime, h.service.daRelay.nextReceivedTime)
	}
}

func TestAnnounceTxRelaysIntoCanonicalMempoolAndMiner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := newTestHarness(t, 1, "127.0.0.1:0", nil)
	sourceMempool := wireCanonicalMempoolForP2PTest(t, source)
	txBytes, txid, utxos := signedCanonicalP2PTxForHarness(t, source, 9001)
	if err := sourceMempool.AddTx(txBytes); err != nil {
		t.Fatalf("source canonical AddTx: %v", err)
	}
	if err := source.service.Start(ctx); err != nil {
		t.Fatalf("source.Start: %v", err)
	}
	defer source.service.Close()

	sink := newTestHarness(t, 1, "127.0.0.1:0", []string{source.service.Addr()})
	sinkMempool := wireCanonicalMempoolForP2PTest(t, sink)
	seedHarnessUtxos(sink, utxos)
	if err := sink.service.Start(ctx); err != nil {
		t.Fatalf("sink.Start: %v", err)
	}
	defer sink.service.Close()

	waitFor(t, 5*time.Second, func() bool {
		return source.peerManager.Count() == 1 && sink.peerManager.Count() == 1
	})

	if err := source.service.AnnounceTx(txBytes); err != nil {
		t.Fatalf("AnnounceTx: %v", err)
	}
	if !sourceMempool.Contains(txid) {
		t.Fatal("source canonical mempool should contain announced tx")
	}
	waitFor(t, 5*time.Second, func() bool {
		return sinkMempool.Contains(txid)
	})

	minerCfg := node.DefaultMinerConfig()
	minerCfg.TimestampSource = func() uint64 {
		sink.timestamp++
		return sink.timestamp
	}
	miner, err := node.NewMiner(sink.chainState, sink.blockStore, sink.syncEngine, minerCfg)
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	mined, err := miner.MineOne(context.Background(), nil)
	if err != nil {
		t.Fatalf("MineOne: %v", err)
	}
	if mined.TxCount != 2 {
		t.Fatalf("mined tx_count=%d, want 2", mined.TxCount)
	}
	blockBytes, err := sink.blockStore.GetBlockByHash(mined.Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash: %v", err)
	}
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	if !parsedBlockHasTxID(parsed, txid) {
		t.Fatalf("mined block missing relayed tx %x", txid)
	}
}

func TestAnnounceTxNonCanonical(t *testing.T) {
	txBytes := minimalValidTxBytes(t)
	nonCanonical := append(txBytes, 0x00)

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	err := h.service.AnnounceTx(nonCanonical)
	if err == nil {
		t.Fatal("AnnounceTx with non-canonical bytes should error")
	}
}

func TestAnnounceTxNilService(t *testing.T) {
	var s *Service
	err := s.AnnounceTx([]byte{0x01})
	if err == nil {
		t.Fatal("AnnounceTx on nil service should error")
	}
}

func TestHandleTxPoolFullMarksSeen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	pool := h.service.cfg.TxPool.(*MemoryTxPool)

	// Fill pool to capacity.
	for i := 0; i < pool.maxSize; i++ {
		raw := distinctTxBytes(t, uint64(i))
		txid, err := canonicalTxID(raw)
		if err != nil {
			t.Fatalf("canonicalTxID(%d): %v", i, err)
		}
		if !putRelayTx(pool, txid, raw) {
			t.Fatalf("Put(%d) should succeed", i)
		}
	}

	p := &peer{
		service: h.service,
		state:   node.PeerState{HandshakeComplete: true},
	}

	// Submit a valid tx that will be rejected by the full pool.
	overflowTx := distinctTxBytes(t, 999_999)
	overflowID, err := canonicalTxID(overflowTx)
	if err != nil {
		t.Fatalf("canonicalTxID overflow: %v", err)
	}

	err = p.handleTx(overflowTx)
	if err != nil {
		t.Fatalf("handleTx pool-full: %v", err)
	}

	// Tx should NOT be in pool (rejected at capacity).
	if pool.Has(overflowID) {
		t.Fatal("overflow tx should not be in pool")
	}

	// Tx MUST be in txSeen — prevents repeated getdata churn.
	if !h.service.txSeen.Has(overflowID) {
		t.Fatal("overflow tx should be in txSeen even when pool is full")
	}
}

func TestHandleTxMetadataErrorIsPeerNeutralAndMarksSeen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.TxMetadataFunc = func([]byte) (node.RelayTxMetadata, error) {
		return node.RelayTxMetadata{}, errors.New("metadata unavailable")
	}
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	p := &peer{
		service: h.service,
		state:   node.PeerState{HandshakeComplete: true},
	}
	txBytes := distinctTxBytes(t, 777)
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}
	if err := p.handleTx(txBytes); err != nil {
		t.Fatalf("handleTx metadata error should be swallowed, got %v", err)
	}
	if p.state.BanScore != 0 {
		t.Fatalf("ban score=%d, want 0 for peer-neutral metadata error", p.state.BanScore)
	}
	if p.state.LastError != "" {
		t.Fatalf("last error=%q, want empty for peer-neutral metadata error", p.state.LastError)
	}
	if h.service.cfg.TxPool.Has(txid) {
		t.Fatal("metadata failure should not admit tx into relay pool")
	}
	if !h.service.txSeen.Has(txid) {
		t.Fatal("metadata failure should still mark tx as seen to suppress churn")
	}
}

func TestHandleTxCanonicalMempoolRejectsMalformedAndAdmissionWithoutMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	canonicalMempool := wireCanonicalMempoolForP2PTest(t, h)
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	p := &peer{
		service: h.service,
		state:   node.PeerState{HandshakeComplete: true},
	}

	if err := p.handleTx([]byte{0xFF, 0xFE}); err != nil {
		t.Fatalf("malformed handleTx should not return before ban threshold: %v", err)
	}
	if got := canonicalMempool.Len(); got != 0 {
		t.Fatalf("canonical mempool len after malformed=%d, want 0", got)
	}

	txBytes, txid, _ := signedCanonicalP2PTxWithoutSeeding(t, 9002)
	if err := p.handleTx(txBytes); err != nil {
		t.Fatalf("admission reject handleTx should be peer-neutral, got %v", err)
	}
	if got := canonicalMempool.Len(); got != 0 {
		t.Fatalf("canonical mempool len after missing-utxo admission reject=%d, want 0", got)
	}
	if !h.service.txSeen.Has(txid) {
		t.Fatal("admission-rejected tx should be marked seen to suppress getdata churn")
	}
	if canonicalMempool.Contains(txid) {
		t.Fatal("admission-rejected tx must not enter canonical mempool")
	}
}

func TestHandleTxCanonicalMempoolDuplicateIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	canonicalMempool := wireCanonicalMempoolForP2PTest(t, h)
	txBytes, txid, _ := signedCanonicalP2PTxForHarness(t, h, 9003)
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	p := &peer{
		service: h.service,
		state:   node.PeerState{HandshakeComplete: true},
	}

	wrongTxid := txid
	wrongTxid[0] ^= 0x80
	if h.service.cfg.TxPool.Put(wrongTxid, txBytes, 0, 0) {
		t.Fatal("canonical adapter should reject txid/raw mismatch")
	}
	if got := canonicalMempool.Len(); got != 0 {
		t.Fatalf("canonical mempool len after txid/raw mismatch=%d, want 0", got)
	}

	if err := p.handleTx(txBytes); err != nil {
		t.Fatalf("handleTx first: %v", err)
	}
	if got := canonicalMempool.Len(); got != 1 {
		t.Fatalf("canonical mempool len after first handleTx=%d, want 1", got)
	}
	if !canonicalMempool.Contains(txid) {
		t.Fatal("canonical mempool should contain first relayed tx")
	}
	if err := p.handleTx(txBytes); err != nil {
		t.Fatalf("handleTx duplicate: %v", err)
	}
	if got := canonicalMempool.Len(); got != 1 {
		t.Fatalf("canonical mempool len after duplicate handleTx=%d, want 1", got)
	}
}

func TestHandleTxCanonicalMempoolSkipsValidatingMetadataProvider(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	canonicalMempool := wireCanonicalMempoolForP2PTest(t, h)
	txBytes, txid, _ := signedCanonicalP2PTxForHarness(t, h, 9004)
	var metadataCalls atomic.Int32
	h.service.cfg.TxMetadataFunc = func([]byte) (node.RelayTxMetadata, error) {
		metadataCalls.Add(1)
		return node.RelayTxMetadata{}, errors.New("unexpected validating metadata call")
	}
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	p := &peer{
		service: h.service,
		state:   node.PeerState{HandshakeComplete: true},
	}
	if err := p.handleTx(txBytes); err != nil {
		t.Fatalf("handleTx canonical mempool: %v", err)
	}
	if got := metadataCalls.Load(); got != 0 {
		t.Fatalf("validating metadata calls=%d, want 0 for canonical mempool", got)
	}
	if !canonicalMempool.Contains(txid) {
		t.Fatal("canonical mempool should contain relayed tx admitted through Put/AddTx")
	}
}

func TestHandleTxDuplicateSkipsMetadataValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	var metadataCalls atomic.Int32
	h.service.cfg.TxMetadataFunc = func([]byte) (node.RelayTxMetadata, error) {
		metadataCalls.Add(1)
		return node.RelayTxMetadata{Fee: 1, Size: 1}, nil
	}
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	p := &peer{
		service: h.service,
		state:   node.PeerState{HandshakeComplete: true},
	}
	txBytes := distinctTxBytes(t, 779)
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}
	if err := p.handleTx(txBytes); err != nil {
		t.Fatalf("handleTx first: %v", err)
	}
	if got := metadataCalls.Load(); got != 1 {
		t.Fatalf("metadataCalls after first handleTx=%d, want 1", got)
	}
	if err := p.handleTx(txBytes); err != nil {
		t.Fatalf("handleTx duplicate: %v", err)
	}
	if got := metadataCalls.Load(); got != 1 {
		t.Fatalf("metadataCalls after duplicate=%d, want 1", got)
	}
	if !h.service.cfg.TxPool.Has(txid) {
		t.Fatal("duplicate shortcut must preserve prior pool admission")
	}
}

func TestAnnounceTxMetadataError(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.TxMetadataFunc = func([]byte) (node.RelayTxMetadata, error) {
		return node.RelayTxMetadata{}, errors.New("metadata unavailable")
	}
	txBytes := distinctTxBytes(t, 778)
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}
	if err := h.service.AnnounceTx(txBytes); err == nil {
		t.Fatal("AnnounceTx should surface metadata errors for local submissions")
	}
	if h.service.cfg.TxPool.Has(txid) {
		t.Fatal("metadata failure should not admit announced tx into relay pool")
	}
	if h.service.txSeen.Has(txid) {
		t.Fatal("failed AnnounceTx should not mark tx as seen")
	}
}

func TestAnnounceTxAdmissionRejectDoesNotMarkSeen(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.cfg.TxPool = rejectingTxPool{}
	txBytes := minimalValidTxBytes(t)
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}
	if err := h.service.AnnounceTx(txBytes); err == nil {
		t.Fatal("AnnounceTx should reject when tx was not admitted to relay pool")
	}
	if h.service.txSeen.Has(txid) {
		t.Fatal("admission-rejected AnnounceTx must not mark tx as seen")
	}
}

func TestEnsureRelayTxAdmittedInvariantErrorsNameTxID(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	txBytes := distinctTxBytes(t, 8841)
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}
	otherTxBytes := distinctTxBytes(t, 8842)
	otherTxid, err := canonicalTxID(otherTxBytes)
	if err != nil {
		t.Fatalf("other canonicalTxID: %v", err)
	}

	h.service.cfg.TxPool = inconsistentTxPool{raw: otherTxBytes, ok: true}
	_, _, err = h.service.ensureRelayTxAdmitted(txid, txBytes)
	if err == nil {
		t.Fatal("ensureRelayTxAdmitted should reject mismatched admitted txid")
	}
	for _, want := range []string{
		"admitted txid mismatch",
		fmt.Sprintf("expected=%x", txid),
		fmt.Sprintf("got=%x", otherTxid),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestAnnounceTxAlreadyAdmittedSkipsMetadataValidation(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	canonicalMempool := wireCanonicalMempoolForP2PTest(t, h)
	txBytes, txid, _ := signedCanonicalP2PTxForHarness(t, h, 9005)
	if err := canonicalMempool.AddTx(txBytes); err != nil {
		t.Fatalf("canonical AddTx: %v", err)
	}
	var metadataCalls atomic.Int32
	h.service.cfg.TxMetadataFunc = func([]byte) (node.RelayTxMetadata, error) {
		metadataCalls.Add(1)
		return node.RelayTxMetadata{}, errors.New("unexpected validating metadata call")
	}
	if err := h.service.AnnounceTx(txBytes); err != nil {
		t.Fatalf("AnnounceTx already-admitted canonical tx: %v", err)
	}
	if got := metadataCalls.Load(); got != 0 {
		t.Fatalf("validating metadata calls=%d, want 0 for already-admitted tx", got)
	}
	if !h.service.txSeen.Has(txid) {
		t.Fatal("announced tx should be marked seen after already-admitted broadcast")
	}
}

func TestDAStagingUsesOnlyAdmittedTxBytes(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*testHarness) (*MemoryTxPool, func([]byte) error)
	}{
		{
			name: "AnnounceTx",
			setup: func(h *testHarness) (*MemoryTxPool, func([]byte) error) {
				return h.service.cfg.TxPool.(*MemoryTxPool), h.service.AnnounceTx
			},
		},
		{
			name: "handleTx",
			setup: func(h *testHarness) (*MemoryTxPool, func([]byte) error) {
				pool := NewMemoryTxPoolWithLimit(2)
				h.service.cfg.TxPool = pool
				return pool, daRelayTestPeer(h, "127.0.0.1:19114").handleTx
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t, 1, "127.0.0.1:0", nil)
			pool, stage := tc.setup(h)
			daID := daRelayTestID(byte(126 + i))
			payload := []byte("admitted-da-payload")
			admittedCommit := daCommitRelayTxBytes(t, daID, uint64(9401+i*10), payload)
			admittedChunk := daChunkRelayTxBytes(t, daID, 0, uint64(9402+i*10), payload)
			commitID, err := canonicalTxID(admittedCommit)
			if err != nil {
				t.Fatalf("commit txid: %v", err)
			}
			chunkID, err := canonicalTxID(admittedChunk)
			if err != nil {
				t.Fatalf("chunk txid: %v", err)
			}
			if !putRelayTx(pool, commitID, admittedCommit) {
				t.Fatal("preload admitted commit")
			}
			if !putRelayTx(pool, chunkID, admittedChunk) {
				t.Fatal("preload admitted chunk")
			}

			alternateCommit := sameTxIDWithSentinelWitness(t, admittedCommit)
			alternateChunk := sameTxIDWithDAPayload(t, admittedChunk, []byte("unadmitted-da-payload"))
			if err := stage(alternateCommit); err != nil {
				t.Fatalf("stage alternate commit: %v", err)
			}
			if err := stage(alternateChunk); err != nil {
				t.Fatalf("stage alternate chunk: %v", err)
			}

			record, ok := daRelayStoredRecordSnapshot(t, h.service.daRelay, daID)
			if !ok || record.state != daRelayStateCompleteSet {
				t.Fatalf("DA relay record ok=%v state=%v, want complete set", ok, record.state)
			}
			if !bytes.Equal(record.commit.txBytes, admittedCommit) || bytes.Equal(record.commit.txBytes, alternateCommit) {
				t.Fatalf("commit relay state did not retain admitted bytes")
			}
			chunk := record.chunks[0]
			if !bytes.Equal(chunk.txBytes, admittedChunk) || bytes.Equal(chunk.txBytes, alternateChunk) {
				t.Fatalf("chunk relay state did not retain admitted bytes")
			}
			if len(chunk.payload) != 0 {
				t.Fatalf("complete relay record retained duplicate chunk payload copy")
			}
		})
	}
}

// --- MemoryTxPool unit tests ---

func TestMemoryTxPoolSizeLimit(t *testing.T) {
	pool := NewMemoryTxPoolWithLimit(3)

	for i := 0; i < 3; i++ {
		var txid [32]byte
		txid[0] = byte(i)
		if !pool.Put(txid, []byte{byte(i)}, uint64(i+1), 1) {
			t.Fatalf("Put(%d) should succeed", i)
		}
	}

	// Pool is full — next Put should fail
	var overflow [32]byte
	overflow[0] = 0xFF
	if pool.Put(overflow, []byte{0xFF}, 0, 1) {
		t.Fatal("Put should fail when pool is full")
	}

	if pool.Len() != 3 {
		t.Fatalf("pool.Len()=%d, want 3", pool.Len())
	}

	// Remove one and try again
	var removeID [32]byte
	removeID[0] = 0x00
	pool.Remove(removeID)

	if pool.Len() != 2 {
		t.Fatalf("pool.Len()=%d after remove, want 2", pool.Len())
	}

	if !pool.Put(overflow, []byte{0xFF}, 1, 1) {
		t.Fatal("Put should succeed after Remove freed space")
	}
}

func TestMemoryTxPoolDuplicate(t *testing.T) {
	pool := NewMemoryTxPool()

	var txid [32]byte
	txid[0] = 0x42
	if !pool.Put(txid, []byte{0x01, 0x02}, 2, 2) {
		t.Fatal("first Put should succeed")
	}
	if pool.Put(txid, []byte{0x03, 0x04}, 2, 2) {
		t.Fatal("duplicate Put should return false")
	}

	// Verify original data is preserved (not overwritten)
	raw, ok := pool.Get(txid)
	if !ok {
		t.Fatal("Get after Put should succeed")
	}
	if len(raw) != 2 || raw[0] != 0x01 || raw[1] != 0x02 {
		t.Fatalf("Get returned %x, want 0102", raw)
	}
}

func TestMemoryTxPoolNilSafe(t *testing.T) {
	var pool *MemoryTxPool
	if pool.Has([32]byte{}) {
		t.Fatal("nil pool Has should return false")
	}
	if pool.Put([32]byte{}, nil, 0, 0) {
		t.Fatal("nil pool Put should return false")
	}
	_, ok := pool.Get([32]byte{})
	if ok {
		t.Fatal("nil pool Get should return false")
	}
	if pool.Len() != 0 {
		t.Fatal("nil pool Len should return 0")
	}
	pool.Remove([32]byte{}) // should not panic
}

func TestMemoryTxPoolGetCopy(t *testing.T) {
	pool := NewMemoryTxPool()
	var txid [32]byte
	txid[0] = 0x01
	original := []byte{0xAA, 0xBB}
	pool.Put(txid, original, uint64(len(original)), len(original))

	// Mutate original — pool should be unaffected
	original[0] = 0x00
	raw, ok := pool.Get(txid)
	if !ok {
		t.Fatal("Get should succeed")
	}
	if raw[0] != 0xAA {
		t.Fatal("pool should store a copy, not a reference to the original slice")
	}

	// Mutate returned value — pool should be unaffected
	raw[0] = 0xFF
	raw2, _ := pool.Get(txid)
	if raw2[0] != 0xAA {
		t.Fatal("Get should return a copy each time")
	}
}

func TestCanonicalTxID(t *testing.T) {
	txBytes := minimalValidTxBytes(t)
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}
	if txid == ([32]byte{}) {
		t.Fatal("txid should not be zero")
	}

	// Trailing bytes → error
	_, err = canonicalTxID(append(txBytes, 0x00))
	if err == nil {
		t.Fatal("canonicalTxID with trailing bytes should error")
	}

	// Garbage → error
	_, err = canonicalTxID([]byte{0xFF})
	if err == nil {
		t.Fatal("canonicalTxID with garbage should error")
	}
}

func TestMemoryTxPoolWithLimitZeroDefault(t *testing.T) {
	// maxSize <= 0 should fall back to defaultMaxTxPoolSize.
	pool := NewMemoryTxPoolWithLimit(0)
	if pool.maxSize != defaultMaxTxPoolSize {
		t.Fatalf("pool(0).maxSize=%d, want %d", pool.maxSize, defaultMaxTxPoolSize)
	}

	pool2 := NewMemoryTxPoolWithLimit(-5)
	if pool2.maxSize != defaultMaxTxPoolSize {
		t.Fatalf("pool(-5).maxSize=%d, want %d", pool2.maxSize, defaultMaxTxPoolSize)
	}

	// Verify the fallback pool is functional.
	var txid [32]byte
	txid[0] = 0x42
	if !pool.Put(txid, []byte{0x01}, 1, 1) {
		t.Fatal("Put should succeed on fallback-default pool")
	}
	if !pool.Has(txid) {
		t.Fatal("Has should return true after Put")
	}
}

func TestBlockBytesIOError(t *testing.T) {
	// Create a valid BlockStore, then corrupt its blocks directory to force
	// a non-ErrNotExist error from GetBlockByHash. This exercises the error
	// propagation path in blockBytes (line: return nil, false, err).
	dir := t.TempDir()
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}

	// Replace the blocks directory with a regular file.
	// os.DirFS will then fail with ENOTDIR (not ErrNotExist).
	blocksDir := filepath.Join(node.BlockStorePath(dir), "blocks")
	if err := os.RemoveAll(blocksDir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.WriteFile(blocksDir, []byte("not-a-dir"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Minimal service — blockBytes only needs chainMu + cfg.BlockStore.
	svc := &Service{
		cfg: ServiceConfig{
			BlockStore: blockStore,
		},
	}
	p := &peer{service: svc}

	_, _, err = p.blockBytes([32]byte{0x01})
	if err == nil {
		t.Fatal("blockBytes should return error when blocks dir is corrupted")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatal("expected non-ErrNotExist error, got ErrNotExist")
	}
}

// TestHandleTxOversizeBumpsBan covers the C.1 parity gap: Go handleTx must
// explicitly reject payloads larger than consensus.MAX_RELAY_MSG_BYTES with a
// ban-score bump, mirroring Rust's tx_relay::handle_received_tx oversize guard
// (see clients/rust/crates/rubin-node/src/tx_relay.rs RelayTxOutcome::Oversized).
//
// Allocates ~96MB. Skipped under -short. Coverage of the new oversize ban
// branch requires the real length check to fire, which needs the full
// allocation; an env-var opt-in skip would drop Codacy diff-coverage below
// the 85% gate, so the alloc is accepted on default CI.
func TestHandleTxOversizeBumpsBan(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates MAX_RELAY_MSG_BYTES+1 bytes; skipped in short mode")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	p := &peer{
		service: h.service,
		state: node.PeerState{
			HandshakeComplete: true,
		},
	}

	// Payload exactly one byte over MAX_RELAY_MSG_BYTES.
	oversize := make([]byte, consensus.MAX_RELAY_MSG_BYTES+1)
	err := p.handleTx(oversize)
	if err != nil {
		t.Fatalf("handleTx oversize (sub-threshold ban): %v", err)
	}
	if p.state.BanScore != 10 {
		t.Fatalf("ban score bump=%d, want 10 (parity with malformed-parse path)", p.state.BanScore)
	}
}
