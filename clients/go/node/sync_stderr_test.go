package node

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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

// TestRequeueDisconnectedLogsAddTxError verifies that requeueDisconnectedTransactions
// writes an error to stderr when AddTx fails (e.g. inputs already spent).
func TestRequeueDisconnectedLogsAddTxError(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncCfg := DefaultSyncConfig(nil, devnetGenesisChainID, chainStatePath)
	engine, err := NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := NewMempool(chainState, blockStore, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

	var stderrBuf bytes.Buffer
	engine.SetStderr(&stderrBuf)

	// Mine 102 blocks so at least one coinbase UTXO is mature.
	// Genesis (height 0) has subsidy=0; height 1 has subsidy>0 and
	// CreationHeight=1. At height 101: 101-1=100 >= COINBASE_MATURITY.
	minerCfg := DefaultMinerConfig()
	minerCfg.MineAddress = fromAddress
	miner, err := NewMiner(chainState, blockStore, engine, minerCfg)
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	if _, err := miner.MineN(context.Background(), 102, nil); err != nil {
		t.Fatalf("MineN(102): %v", err)
	}

	// Find a mature coinbase UTXO belonging to fromAddress.
	// Maturity check: nextHeight >= CreationHeight + COINBASE_MATURITY,
	// where nextHeight = chainState.Height + 1.
	nextHeight := chainState.Height + 1
	var spendOP consensus.Outpoint
	var spendEntry consensus.UtxoEntry
	found := false
	for op, entry := range chainState.Utxos {
		if entry.CreatedByCoinbase && entry.Value > 0 &&
			bytes.Equal(entry.CovenantData, fromAddress) &&
			nextHeight >= entry.CreationHeight+consensus.COINBASE_MATURITY {
			spendOP = op
			spendEntry = entry
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no mature coinbase UTXO found")
	}

	// Build a signed transfer tx spending the mature coinbase.
	txBytes := mustBuildSignedTransferTx(
		t,
		map[consensus.Outpoint]consensus.UtxoEntry{spendOP: spendEntry},
		[]consensus.Outpoint{spendOP},
		spendEntry.Value-1, // amount
		1,                  // fee
		1,                  // nonce (must be >= 1 for non-coinbase)
		fromKey,
		fromAddress,
		toAddress,
	)

	// Mine a block containing the tx.
	mined, err := miner.MineN(context.Background(), 1, [][]byte{txBytes})
	if err != nil {
		t.Fatalf("MineN(1,tx): %v", err)
	}
	if mined[0].TxCount < 2 {
		t.Fatalf("expected at least 2 txs (coinbase+transfer), got %d", mined[0].TxCount)
	}

	// Get the raw block bytes from the blockstore.
	rawBlock, err := blockStore.GetBlockByHash(mined[0].Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash: %v", err)
	}

	// Requeue the disconnected block: the tx's inputs are already spent,
	// so AddTx fails and the error is logged to stderr.
	stderrBuf.Reset()
	engine.requeueDisconnectedTransactions([][]byte{rawBlock})

	output := stderrBuf.String()
	if !strings.Contains(output, "mempool: requeue-tx:") {
		t.Fatalf("expected 'mempool: requeue-tx:' in stderr, got: %q", output)
	}
}
