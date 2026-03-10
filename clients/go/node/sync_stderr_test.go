package node

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestSetStderrNil(t *testing.T) {
	engine := &SyncEngine{stderr: io.Discard}
	engine.SetStderr(nil)
	if engine.stderr != io.Discard {
		t.Fatal("SetStderr(nil) should fallback to io.Discard")
	}
}

func TestSetStderrOnNilEngine(t *testing.T) {
	var engine *SyncEngine
	engine.SetStderr(io.Discard) // must not panic
}

func TestSetStderrSetsWriter(t *testing.T) {
	var buf bytes.Buffer
	engine := &SyncEngine{stderr: io.Discard}
	engine.SetStderr(&buf)
	if engine.stderr != &buf {
		t.Fatal("SetStderr should set the provided writer")
	}
}

// TestRequeueDisconnectedNoErrorOnCoinbaseOnly verifies that
// requeueDisconnectedTransactions does not log errors for coinbase-only
// blocks (which have no user txs to requeue).
func TestRequeueDisconnectedNoErrorOnCoinbaseOnly(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncCfg := DefaultSyncConfig(nil, [32]byte{}, chainStatePath)
	engine, err := NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := NewMempool(chainState, blockStore, [32]byte{})
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

	var stderrBuf bytes.Buffer
	engine.SetStderr(&stderrBuf)

	cfg := DefaultMinerConfig()
	miner, err := NewMiner(chainState, blockStore, engine, cfg)
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	mined, err := miner.MineN(context.Background(), 1, nil)
	if err != nil {
		t.Fatalf("MineN: %v", err)
	}
	if len(mined) == 0 {
		t.Fatal("expected at least one mined block")
	}

	// Get the raw block bytes from blockstore to feed into requeue.
	rawBlock, err := blockStore.GetBlockByHash(mined[0].Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash: %v", err)
	}

	stderrBuf.Reset()
	engine.requeueDisconnectedTransactions([][]byte{rawBlock})
	if stderrBuf.Len() != 0 {
		t.Fatalf("expected no errors for coinbase-only block, got: %s", stderrBuf.String())
	}
}

// TestRequeueDisconnectedSkipsUnparseableBlocks verifies that unparseable
// blocks are silently skipped (pre-existing behavior; parse error → continue).
func TestRequeueDisconnectedSkipsUnparseableBlocks(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncCfg := DefaultSyncConfig(nil, [32]byte{}, chainStatePath)
	engine, err := NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := NewMempool(chainState, blockStore, [32]byte{})
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

	var stderrBuf bytes.Buffer
	engine.SetStderr(&stderrBuf)

	engine.requeueDisconnectedTransactions([][]byte{{0xff, 0xfe}})
	if stderrBuf.Len() != 0 {
		t.Fatalf("expected no stderr for unparseable block, got: %s", stderrBuf.String())
	}
}

// TestApplyBlockMempoolEvictStderrPlumbing verifies that the stderr field
// is correctly wired through the block-apply path and does not produce
// spurious errors for valid blocks.
func TestApplyBlockMempoolEvictStderrPlumbing(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncCfg := DefaultSyncConfig(nil, [32]byte{}, chainStatePath)
	engine, err := NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := NewMempool(chainState, blockStore, [32]byte{})
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

	var stderrBuf bytes.Buffer
	engine.SetStderr(&stderrBuf)

	cfg := DefaultMinerConfig()
	miner, err := NewMiner(chainState, blockStore, engine, cfg)
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}

	// Mine a block — this calls ApplyBlock internally. Because the block is
	// valid, EvictConfirmed/RemoveConflicting should succeed and stderr
	// should remain empty.
	_, err = miner.MineN(context.Background(), 1, nil)
	if err != nil {
		t.Fatalf("MineN: %v", err)
	}
	output := stderrBuf.String()
	if strings.Contains(output, "mempool:") {
		t.Fatalf("expected no mempool errors for valid block, got: %s", output)
	}
}
