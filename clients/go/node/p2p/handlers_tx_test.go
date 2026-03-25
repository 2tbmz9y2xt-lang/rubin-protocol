package p2p

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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

func putRelayTx(pool *MemoryTxPool, txid [32]byte, raw []byte) bool {
	return pool.Put(txid, raw, uint64(len(raw)), len(raw))
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

func TestHandleTxMetadataErrorStillMarksSeen(t *testing.T) {
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
	if h.service.cfg.TxPool.Has(txid) {
		t.Fatal("metadata failure should not admit tx into relay pool")
	}
	if !h.service.txSeen.Has(txid) {
		t.Fatal("metadata failure should still mark tx as seen to suppress churn")
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

func TestAnnounceTxPoolFullSkipsBroadcast(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	// Replace pool with capacity=1 so second insert fails.
	h.service.cfg.TxPool = NewMemoryTxPoolWithLimit(1)
	// Pre-fill the pool with a high-fee tx so that the low-fee announce is rejected.
	occupant := distinctTxBytes(t, 900)
	occupantID, _ := canonicalTxID(occupant)
	h.service.cfg.TxPool.Put(occupantID, occupant, 9999, len(occupant))

	// Announce a tx with default fee=0 (relayTxMetadata fallback) — pool should reject.
	txBytes := distinctTxBytes(t, 901)
	txid, _ := canonicalTxID(txBytes)
	if err := h.service.AnnounceTx(txBytes); err != nil {
		t.Fatalf("AnnounceTx should return nil even on pool-full: %v", err)
	}
	if h.service.cfg.TxPool.Has(txid) {
		t.Fatal("pool-rejected tx should not be stored")
	}
	if h.service.txSeen.Has(txid) {
		t.Fatal("pool-rejected tx should not be marked seen")
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
	if err := os.WriteFile(blocksDir, []byte("not-a-dir"), 0644); err != nil {
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
