package node_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node/p2p"
)

type devnetNode struct {
	name           string
	dir            string
	chainStatePath string
	chainState     *node.ChainState
	blockStore     *node.BlockStore
	syncEngine     *node.SyncEngine
	syncCfg        node.SyncConfig
	peerManager    *node.PeerManager
	mempool        *node.Mempool
	service        *p2p.Service
	bindAddr       string
	bootstrapPeers []string
	mineAddress    []byte
	timestamp      uint64
}

func TestDevnetThreeNodeSyncAndDeterminism(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeA := newDevnetNode(t, "node-a", "127.0.0.1:0", nil, 0x11, true)
	if err := nodeA.start(ctx); err != nil {
		t.Fatalf("start node A: %v", err)
	}
	defer nodeA.close()

	nodeB := newDevnetNode(t, "node-b", "127.0.0.1:0", []string{nodeA.service.Addr()}, 0x22, false)
	if err := nodeB.start(ctx); err != nil {
		t.Fatalf("start node B: %v", err)
	}
	defer nodeB.close()

	nodeC := newDevnetNode(t, "node-c", "127.0.0.1:0", []string{nodeA.service.Addr()}, 0x33, false)
	if err := nodeC.start(ctx); err != nil {
		t.Fatalf("start node C: %v", err)
	}
	defer nodeC.close()

	waitFor(t, 5*time.Second, "peer connectivity", func() bool {
		return nodeA.peerManager.Count() == 2 && nodeB.peerManager.Count() == 1 && nodeC.peerManager.Count() == 1
	})
	waitForHeight(t, nodeB, 0)
	waitForHeight(t, nodeC, 0)

	for wantHeight := uint64(1); wantHeight <= 10; wantHeight++ {
		mined := nodeA.mineOne(t, true)
		if mined.Height != wantHeight {
			t.Fatalf("node A mined height=%d, want %d", mined.Height, wantHeight)
		}
		waitForHeight(t, nodeB, wantHeight)
		waitForHeight(t, nodeC, wantHeight)
	}

	assertSameTip(t, nodeA, nodeB, nodeC)
	assertSameUTXOSet(t, nodeA, nodeB, nodeC)
	assertSameChainStateFile(t, nodeA, nodeB, nodeC)

	wantSubsidy := cumulativeSubsidy(10)
	for _, current := range []*devnetNode{nodeA, nodeB, nodeC} {
		state := loadChainState(t, current)
		if state.AlreadyGenerated != wantSubsidy {
			t.Fatalf("%s already_generated=%d, want %d", current.name, state.AlreadyGenerated, wantSubsidy)
		}
		if state.Height != 10 {
			t.Fatalf("%s height=%d, want 10", current.name, state.Height)
		}
	}
}

func TestDevnetLongestChainWinsReplayGate(t *testing.T) {
	shortFork := newDevnetNode(t, "short-fork", "", nil, 0x44, true)
	longFork := newDevnetNode(t, "long-fork", "", nil, 0x55, true)
	observer := newDevnetNode(t, "observer", "", nil, 0x66, false)

	shortFork.mineN(t, 4, false)
	longFork.mineN(t, 6, false)

	shortDigest := chainStateDigest(t, shortFork)
	longDigest := chainStateDigest(t, longFork)
	if shortDigest == longDigest {
		t.Fatalf("expected competing forks to diverge before replay")
	}

	observer.reorgToCanonical(t, shortFork)
	assertSameTip(t, shortFork, observer)
	assertSameUTXOSet(t, shortFork, observer)

	observer.reorgToCanonical(t, longFork)
	shortFork.reorgToCanonical(t, longFork)

	assertSameTip(t, shortFork, longFork, observer)
	assertSameUTXOSet(t, shortFork, longFork, observer)
	assertSameChainStateFile(t, shortFork, longFork, observer)

	wantSubsidy := cumulativeSubsidy(6)
	for _, current := range []*devnetNode{shortFork, longFork, observer} {
		state := loadChainState(t, current)
		if state.Height != 6 {
			t.Fatalf("%s height=%d, want 6", current.name, state.Height)
		}
		if state.AlreadyGenerated != wantSubsidy {
			t.Fatalf("%s already_generated=%d, want %d", current.name, state.AlreadyGenerated, wantSubsidy)
		}
	}
}

func TestDevnetSoakWithTxGenAndRestart(t *testing.T) {
	const (
		targetHeight    = 1000
		checkpointEvery = 100
		txInterval      = 10
		txAmount        = 10
		txFee           = 1
		restartAt       = 700
		killAt          = 500
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	memBefore := readMemStats()

	txKeypair := mustTxGenKeypair(t)
	txSourceAddress := consensus.P2PKCovenantDataForPubkey(txKeypair.PubkeyBytes())
	txTargetAddress := txSourceAddress

	nodeA := newDevnetNodeWithMineAddress(
		t,
		"node-a",
		"127.0.0.1:0",
		nil,
		txSourceAddress,
		true,
	)
	if err := nodeA.start(ctx); err != nil {
		t.Fatalf("start node A: %v", err)
	}
	defer nodeA.close()

	nodeB := newDevnetNodeWithMineAddress(
		t,
		"node-b",
		"127.0.0.1:0",
		[]string{nodeA.service.Addr()},
		mustMineAddress(t, 0x22),
		false,
	)
	if err := nodeB.start(ctx); err != nil {
		t.Fatalf("start node B: %v", err)
	}
	defer nodeB.close()

	nodeC := newDevnetNodeWithMineAddress(
		t,
		"node-c",
		"127.0.0.1:0",
		[]string{nodeA.service.Addr()},
		mustMineAddress(t, 0x33),
		false,
	)
	if err := nodeC.start(ctx); err != nil {
		t.Fatalf("start node C: %v", err)
	}
	defer nodeC.close()

	waitFor(t, 5*time.Second, "peer connectivity", func() bool {
		return nodeA.peerManager.Count() == 2 && nodeB.peerManager.Count() == 1 && nodeC.peerManager.Count() == 1
	})
	waitForHeight(t, nodeB, 0)
	waitForHeight(t, nodeC, 0)

	txGen := &txGenerator{
		node:    nodeA,
		signer:  txKeypair,
		chainID: node.DevnetGenesisChainID(),
		from:    txSourceAddress,
		to:      txTargetAddress,
		amount:  txAmount,
		fee:     txFee,
	}
	submittedTxs := make([][32]byte, 0, targetHeight/txInterval)

	cNodeDown := false
	for wantHeight := uint64(1); wantHeight <= targetHeight; wantHeight++ {
		mined := nodeA.mineOne(t, true)
		if mined.Height != wantHeight {
			t.Fatalf("node A mined height=%d, want %d", mined.Height, wantHeight)
		}
		if wantHeight%txInterval == 0 && wantHeight >= consensus.COINBASE_MATURITY && wantHeight < targetHeight {
			txBytes, err := txGen.buildNext(txFee)
			if err != nil {
				t.Fatalf("txgen build next tx at height %d: %v", wantHeight, err)
			}
			if err := nodeA.submitTx(txBytes); err != nil {
				t.Fatalf("txgen announce tx at height %d: %v", wantHeight, err)
			}
			submittedTxs = append(submittedTxs, mustTxIDFromRaw(t, txBytes))
		}

		if cNodeDown {
			waitForHeight(t, nodeA, wantHeight)
			waitForHeight(t, nodeB, wantHeight)
		} else {
			waitForHeight(t, nodeA, wantHeight)
			waitForHeight(t, nodeB, wantHeight)
			waitForHeight(t, nodeC, wantHeight)
		}

		if wantHeight == killAt {
			nodeC.stop()
			cNodeDown = true
		}

		if cNodeDown && wantHeight == restartAt {
			if err := nodeC.restartWithPeers(ctx, []string{nodeA.service.Addr()}); err != nil {
				t.Fatalf("restart node C at height %d: %v", wantHeight, err)
			}
			waitForHeightWithTimeout(t, nodeC, wantHeight, 30*time.Second)
			waitForPeerCountWithTimeout(t, nodeC, 1, 10*time.Second)
			cNodeDown = false
		}

		if wantHeight == killAt || wantHeight == restartAt || wantHeight%checkpointEvery == 0 {
			logMonitoringCheckpoint(t, wantHeight, nodeA, nodeB, nodeC)
		}
	}

	assertSubmittedTxsConfirmed(t, submittedTxs, nodeA, nodeB, nodeC)
	assertSameTip(t, nodeA, nodeB, nodeC)
	assertSameChainStateFile(t, nodeA, nodeB, nodeC)
	assertSoakConsensusMetrics(t, nodeA, nodeB, nodeC)

	memAfter := readMemStats()
	if memAfter.HeapAlloc > memBefore.HeapAlloc+512*1024*1024 {
		t.Fatalf(
			"memstats heap alloc delta too high: before=%d after=%d",
			memBefore.HeapAlloc,
			memAfter.HeapAlloc,
		)
	}
	t.Logf(
		"checkpoint memstats: before.heap_alloc=%d after.heap_alloc=%d before.peak_bytes=%d after.peak_bytes=%d",
		memBefore.HeapAlloc,
		memAfter.HeapAlloc,
		memBefore.HeapSys,
		memAfter.HeapSys,
	)
}

func newDevnetNode(t *testing.T, name string, bindAddr string, bootstrapPeers []string, mineSeed byte, applyGenesis bool) *devnetNode {
	t.Helper()
	mineAddress := mustMineAddress(t, mineSeed)
	return newDevnetNodeWithMineAddress(t, name, bindAddr, bootstrapPeers, mineAddress, applyGenesis)
}

func newDevnetNodeWithMineAddress(
	t *testing.T,
	name string,
	bindAddr string,
	bootstrapPeers []string,
	mineAddress []byte,
	applyGenesis bool,
) *devnetNode {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", name, err)
	}
	chainStatePath := node.ChainStatePath(dir)
	chainState := node.NewChainState()
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore %s: %v", name, err)
	}
	target := consensus.POW_LIMIT
	syncCfg := node.DefaultSyncConfig(&target, node.DevnetGenesisChainID(), chainStatePath)
	syncEngine, err := node.NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("new sync engine %s: %v", name, err)
	}
	mempool, err := node.NewMempool(chainState, blockStore, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("new mempool %s: %v", name, err)
	}
	syncEngine.SetMempool(mempool)

	current := &devnetNode{
		name:           name,
		dir:            dir,
		chainStatePath: chainStatePath,
		chainState:     chainState,
		blockStore:     blockStore,
		syncEngine:     syncEngine,
		syncCfg:        syncCfg,
		mempool:        mempool,
		peerManager:    node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8)),
		bindAddr:       bindAddr,
		bootstrapPeers: append([]string(nil), bootstrapPeers...),
		mineAddress:    mineAddress,
		timestamp:      1_777_000_000 + uint64(mineAddress[0])*100,
	}

	if bindAddr != "" {
		service, err := newDevnetService(current, bindAddr, bootstrapPeers)
		if err != nil {
			t.Fatalf("new service %s: %v", name, err)
		}
		current.service = service
	}

	if applyGenesis {
		if _, err := current.syncEngine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
			t.Fatalf("apply genesis %s: %v", name, err)
		}
	}
	return current
}

func newDevnetService(current *devnetNode, bindAddr string, bootstrapPeers []string) (*p2p.Service, error) {
	if current == nil {
		return nil, fmt.Errorf("nil node")
	}
	svc, err := p2p.NewService(p2p.ServiceConfig{
		BindAddr:          bindAddr,
		BootstrapPeers:    bootstrapPeers,
		UserAgent:         "rubin-go/devnet-test",
		GenesisHash:       node.DevnetGenesisBlockHash(),
		PeerRuntimeConfig: defaultPeerRuntimeConfig(),
		PeerManager:       current.peerManager,
		SyncConfig:        current.syncCfg,
		SyncEngine:        current.syncEngine,
		BlockStore:        current.blockStore,
	})
	if err != nil {
		return nil, err
	}
	return svc, nil
}

func defaultPeerRuntimeConfig() node.PeerRuntimeConfig {
	runtimeCfg := node.DefaultPeerRuntimeConfig("devnet", 8)
	runtimeCfg.ReadDeadline = time.Second
	runtimeCfg.WriteDeadline = time.Second
	runtimeCfg.HandshakeTimeout = time.Second
	return runtimeCfg
}

func (n *devnetNode) start(ctx context.Context) error {
	if n == nil || n.service == nil {
		return nil
	}
	return n.service.Start(ctx)
}

func (n *devnetNode) stop() {
	if n == nil || n.service == nil {
		return
	}
	_ = n.service.Close()
	n.service = nil
}

func (n *devnetNode) restartWithPeers(ctx context.Context, peers []string) error {
	if n == nil {
		return fmt.Errorf("nil node")
	}
	if n.bindAddr == "" {
		return fmt.Errorf("node has no bind address")
	}
	restartPeers := append([]string(nil), peers...)
	if len(restartPeers) == 0 {
		restartPeers = append([]string(nil), n.bootstrapPeers...)
	}
	n.stop()
	n.peerManager = node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))
	service, err := newDevnetService(n, n.bindAddr, restartPeers)
	if err != nil {
		return err
	}
	n.service = service
	n.bootstrapPeers = append([]string(nil), restartPeers...)
	if err := n.service.Start(ctx); err != nil {
		n.service = nil
		return err
	}
	return nil
}

func (n *devnetNode) submitTx(raw []byte) error {
	if n == nil {
		return fmt.Errorf("nil node")
	}
	if n.mempool == nil {
		return fmt.Errorf("mempool not initialized")
	}
	if err := n.mempool.AddTx(raw); err != nil {
		return err
	}
	if n.service == nil {
		return fmt.Errorf("service not started")
	}
	if err := n.service.AnnounceTx(raw); err != nil {
		return err
	}
	return nil
}

type txGenerator struct {
	node         *devnetNode
	signer       *consensus.MLDSA87Keypair
	chainID      [32]byte
	from         []byte
	to           []byte
	amount       uint64
	fee          uint64
	nonceCounter uint64
}

func (g *txGenerator) buildNext(txFee uint64) ([]byte, error) {
	if g == nil || g.node == nil || g.node.chainState == nil {
		return nil, fmt.Errorf("invalid tx generator")
	}
	required, err := addAmountAndFee(g.amount, txFee)
	if err != nil {
		return nil, err
	}
	nextHeight := uint64(0)
	if g.node.chainState.HasTip {
		nextHeight = g.node.chainState.Height + 1
	}
	selected, totalIn, err := selectSpendableCoinbases(g.node.chainState, g.from, nextHeight, required)
	if err != nil {
		return nil, err
	}
	inputs := make([]consensus.TxInput, 0, len(selected))
	for _, entry := range selected {
		inputs = append(inputs, consensus.TxInput{
			PrevTxid: entry.outpoint.Txid,
			PrevVout: entry.outpoint.Vout,
			Sequence: 0,
		})
	}
	outputs := []consensus.TxOutput{{
		Value:        g.amount,
		CovenantType: consensus.COV_TYPE_P2PK,
		CovenantData: append([]byte(nil), g.to...),
	}}
	if change := totalIn - required; change > 0 {
		outputs = append(outputs, consensus.TxOutput{
			Value:        change,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), g.from...),
		})
	}
	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  deterministicTxNonce(&g.nonceCounter),
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, g.node.chainState.Utxos, g.chainID, g.signer); err != nil {
		return nil, err
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		return nil, err
	}
	if _, _, _, consumed, err := consensus.ParseTx(raw); err != nil {
		return nil, err
	} else if consumed != len(raw) {
		return nil, fmt.Errorf("non-canonical tx bytes")
	}
	return raw, nil
}

func mustTxIDFromRaw(t *testing.T, raw []byte) [32]byte {
	t.Helper()
	_, txid, _, consumed, err := consensus.ParseTx(raw)
	if err != nil {
		t.Fatalf("parse submitted tx: %v", err)
	}
	if consumed != len(raw) {
		t.Fatalf("submitted tx consumed=%d, want %d", consumed, len(raw))
	}
	return txid
}

func assertSubmittedTxsConfirmed(t *testing.T, txids [][32]byte, nodes ...*devnetNode) {
	t.Helper()
	if len(txids) == 0 {
		t.Fatalf("expected submitted txs during soak test")
	}
	for _, current := range nodes {
		for _, txid := range txids {
			if !chainStateHasTxOutputs(current.chainState, txid) {
				t.Fatalf("%s missing confirmed tx %x", current.name, txid)
			}
		}
	}
}

func chainStateHasTxOutputs(state *node.ChainState, txid [32]byte) bool {
	if state == nil {
		return false
	}
	for op := range state.Utxos {
		if op.Txid == txid {
			return true
		}
	}
	return false
}

type spendableCoinbase struct {
	outpoint consensus.Outpoint
	entry    consensus.UtxoEntry
}

func selectSpendableCoinbases(state *node.ChainState, fromAddress []byte, nextHeight uint64, required uint64) ([]spendableCoinbase, uint64, error) {
	if state == nil {
		return nil, 0, fmt.Errorf("nil chainstate")
	}
	candidates := make([]spendableCoinbase, 0, len(state.Utxos))
	for op, entry := range state.Utxos {
		if !entry.CreatedByCoinbase {
			continue
		}
		if entry.CovenantType != consensus.COV_TYPE_P2PK {
			continue
		}
		if !bytes.Equal(entry.CovenantData, fromAddress) {
			continue
		}
		if entry.CreationHeight > math.MaxUint64-consensus.COINBASE_MATURITY {
			return nil, 0, fmt.Errorf("coinbase maturity overflow")
		}
		if nextHeight < entry.CreationHeight+consensus.COINBASE_MATURITY {
			continue
		}
		candidates = append(candidates, spendableCoinbase{outpoint: op, entry: entry})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].entry.CreationHeight != candidates[j].entry.CreationHeight {
			return candidates[i].entry.CreationHeight < candidates[j].entry.CreationHeight
		}
		if cmp := bytes.Compare(candidates[i].outpoint.Txid[:], candidates[j].outpoint.Txid[:]); cmp != 0 {
			return cmp < 0
		}
		return candidates[i].outpoint.Vout < candidates[j].outpoint.Vout
	})

	selected := make([]spendableCoinbase, 0, len(candidates))
	var total uint64
	for _, candidate := range candidates {
		if total > math.MaxUint64-candidate.entry.Value {
			return nil, 0, fmt.Errorf("selected input total overflow")
		}
		selected = append(selected, candidate)
		total += candidate.entry.Value
		if total >= required {
			return selected, total, nil
		}
	}
	return nil, 0, fmt.Errorf("insufficient mature coinbase balance")
}

func deterministicTxNonce(counter *uint64) uint64 {
	if counter == nil {
		return 1
	}
	*counter++
	if *counter == 0 {
		*counter = 1
	}
	return *counter
}

func addAmountAndFee(amount uint64, fee uint64) (uint64, error) {
	if amount > math.MaxUint64-fee {
		return 0, fmt.Errorf("u64 overflow")
	}
	return amount + fee, nil
}

func logMonitoringCheckpoint(t *testing.T, atHeight uint64, nodes ...*devnetNode) {
	t.Helper()
	for _, current := range nodes {
		state, err := node.LoadChainState(current.chainStatePath)
		if err != nil {
			t.Fatalf("load chainstate %s: %v", current.name, err)
		}
		peerCount := 0
		if current.peerManager != nil {
			peerCount = current.peerManager.Count()
		}
		stateHeight := uint64(0)
		if state.HasTip {
			stateHeight = state.Height
		}
		t.Logf(
			"[checkpoint h=%d] node=%s height=%d tip=%x already_generated=%d utxo_count=%d peers=%d",
			atHeight,
			current.name,
			stateHeight,
			state.TipHash,
			state.AlreadyGenerated,
			len(state.Utxos),
			peerCount,
		)
	}
}

func (n *devnetNode) close() {
	if n == nil {
		return
	}
	n.stop()
}

func (n *devnetNode) mineN(t *testing.T, blocks int, announce bool) {
	t.Helper()
	for i := 0; i < blocks; i++ {
		_ = n.mineOne(t, announce)
	}
}

func (n *devnetNode) mineOne(t *testing.T, announce bool) *node.MinedBlock {
	t.Helper()

	minerCfg := node.DefaultMinerConfig()
	minerCfg.MineAddress = append([]byte(nil), n.mineAddress...)
	minerCfg.TimestampSource = func() uint64 {
		n.timestamp++
		return n.timestamp
	}
	miner, err := node.NewMiner(n.chainState, n.blockStore, n.syncEngine, minerCfg)
	if err != nil {
		t.Fatalf("%s new miner: %v", n.name, err)
	}
	mined, err := miner.MineOne(context.Background(), nil)
	if err != nil {
		t.Fatalf("%s mine one: %v", n.name, err)
	}
	if announce && n.service != nil {
		blockBytes, err := n.blockStore.GetBlockByHash(mined.Hash)
		if err != nil {
			t.Fatalf("%s get mined block: %v", n.name, err)
		}
		if err := n.service.AnnounceBlock(blockBytes); err != nil {
			t.Fatalf("%s announce block: %v", n.name, err)
		}
	}
	return mined
}

func (n *devnetNode) reorgToCanonical(t *testing.T, src *devnetNode) {
	t.Helper()
	if src == nil {
		t.Fatalf("%s reorg source is nil", n.name)
	}
	commonHeight, hasCommonAncestor := commonAncestorHeight(t, n, src)
	n.disconnectToHeight(t, commonHeight, hasCommonAncestor)

	startHeight := uint64(0)
	if hasCommonAncestor {
		startHeight = commonHeight + 1
	}
	srcTipHeight, _, ok, err := src.blockStore.Tip()
	if err != nil {
		t.Fatalf("%s source tip: %v", src.name, err)
	}
	if !ok || startHeight > srcTipHeight {
		return
	}
	for height := startHeight; height <= srcTipHeight; height++ {
		hash, ok, err := src.blockStore.CanonicalHash(height)
		if err != nil {
			t.Fatalf("%s canonical hash %d: %v", src.name, height, err)
		}
		if !ok {
			t.Fatalf("%s missing canonical hash at height %d", src.name, height)
		}
		blockBytes, err := src.blockStore.GetBlockByHash(hash)
		if err != nil {
			t.Fatalf("%s get block %d: %v", src.name, height, err)
		}
		if _, err := n.syncEngine.ApplyBlock(blockBytes, nil); err != nil {
			t.Fatalf("%s replay height %d into %s: %v", src.name, height, n.name, err)
		}
	}
}

func (n *devnetNode) disconnectToHeight(t *testing.T, targetHeight uint64, hasTarget bool) {
	t.Helper()
	targetCount := uint64(0)
	if hasTarget {
		targetCount = targetHeight + 1
	}
	tipHeight, _, ok := tip(t, n)
	currentCount := uint64(0)
	if ok {
		currentCount = tipHeight + 1
	}
	for currentCount > targetCount {
		if _, err := n.syncEngine.DisconnectTip(); err != nil {
			t.Fatalf("%s disconnect tip: %v", n.name, err)
		}
		currentCount--
	}
}

func waitForHeight(t *testing.T, current *devnetNode, want uint64) {
	t.Helper()
	waitFor(t, 5*time.Second, fmt.Sprintf("%s height=%d", current.name, want), func() bool {
		state, err := node.LoadChainState(current.chainStatePath)
		return err == nil && state.HasTip && state.Height == want
	})
}

func waitForHeightWithTimeout(t *testing.T, current *devnetNode, want uint64, timeout time.Duration) {
	t.Helper()
	waitFor(t, timeout, fmt.Sprintf("%s height=%d", current.name, want), func() bool {
		state, err := node.LoadChainState(current.chainStatePath)
		return err == nil && state.HasTip && state.Height == want
	})
}

func waitForPeerCountWithTimeout(t *testing.T, current *devnetNode, want int, timeout time.Duration) {
	t.Helper()
	waitFor(t, timeout, fmt.Sprintf("%s peer_count=%d", current.name, want), func() bool {
		return current != nil && current.peerManager != nil && current.peerManager.Count() == want
	})
}

func assertSoakConsensusMetrics(t *testing.T, nodes ...*devnetNode) {
	t.Helper()
	if len(nodes) < 2 {
		return
	}
	want := nodes[0]
	wantState := loadChainStateMust(t, want)
	for _, current := range nodes[1:] {
		got := loadChainStateMust(t, current)
		if got.Height != wantState.Height {
			t.Fatalf("height mismatch %s=%d %s=%d", current.name, got.Height, want.name, wantState.Height)
		}
		if !bytes.Equal(got.TipHash[:], wantState.TipHash[:]) {
			t.Fatalf("tip mismatch %s=%x want=%x", current.name, got.TipHash, wantState.TipHash)
		}
		if got.AlreadyGenerated != wantState.AlreadyGenerated {
			t.Fatalf("already_generated mismatch %s=%d want=%d", current.name, got.AlreadyGenerated, wantState.AlreadyGenerated)
		}
		if len(got.Utxos) != len(wantState.Utxos) {
			t.Fatalf("utxo count mismatch %s=%d want=%d", current.name, len(got.Utxos), len(wantState.Utxos))
		}
	}
}

func loadChainStateMust(t *testing.T, current *devnetNode) *node.ChainState {
	t.Helper()
	state, err := node.LoadChainState(current.chainStatePath)
	if err != nil {
		t.Fatalf("load chainstate %s: %v", current.name, err)
	}
	return state
}

func mustTxGenKeypair(t *testing.T) *consensus.MLDSA87Keypair {
	t.Helper()
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unsupported") {
			t.Skipf("ML-DSA backend unavailable: %v", err)
		}
		t.Fatalf("new ML-DSA keypair: %v", err)
	}
	t.Cleanup(func() { kp.Close() })
	return kp
}

func readMemStats() runtime.MemStats {
	runtime.GC()
	var out runtime.MemStats
	runtime.ReadMemStats(&out)
	return out
}

func waitFor(t *testing.T, timeout time.Duration, label string, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %s", timeout, label)
}

func assertSameTip(t *testing.T, nodes ...*devnetNode) {
	t.Helper()
	if len(nodes) < 2 {
		return
	}
	wantHeight, wantHash, wantOK := tip(t, nodes[0])
	for _, current := range nodes[1:] {
		height, hash, ok := tip(t, current)
		if height != wantHeight || hash != wantHash || ok != wantOK {
			t.Fatalf(
				"tip mismatch %s vs %s: got ok=%v height=%d hash=%x want ok=%v height=%d hash=%x",
				current.name,
				nodes[0].name,
				ok,
				height,
				hash,
				wantOK,
				wantHeight,
				wantHash,
			)
		}
	}
}

func assertSameUTXOSet(t *testing.T, nodes ...*devnetNode) {
	t.Helper()
	if len(nodes) < 2 {
		return
	}
	wantDigest := utxoDigest(t, nodes[0])
	for _, current := range nodes[1:] {
		if got := utxoDigest(t, current); got != wantDigest {
			t.Fatalf("utxo digest mismatch %s vs %s: got %s want %s", current.name, nodes[0].name, got, wantDigest)
		}
	}
}

func assertSameChainStateFile(t *testing.T, nodes ...*devnetNode) {
	t.Helper()
	if len(nodes) < 2 {
		return
	}
	wantBytes := readChainStateFile(t, nodes[0])
	wantDigest := chainStateDigest(t, nodes[0])
	for _, current := range nodes[1:] {
		gotBytes := readChainStateFile(t, current)
		if !bytes.Equal(gotBytes, wantBytes) {
			t.Fatalf(
				"chainstate bytes mismatch %s vs %s: got=%s want=%s",
				current.name,
				nodes[0].name,
				chainStateDigest(t, current),
				wantDigest,
			)
		}
	}
}

func commonAncestorHeight(t *testing.T, left *devnetNode, right *devnetNode) (uint64, bool) {
	t.Helper()
	leftTip, _, leftOK := tip(t, left)
	rightTip, _, rightOK := tip(t, right)
	if !leftOK || !rightOK {
		return 0, false
	}
	limit := leftTip
	if rightTip < limit {
		limit = rightTip
	}
	for {
		leftHash, ok, err := left.blockStore.CanonicalHash(limit)
		if err != nil {
			t.Fatalf("%s canonical hash %d: %v", left.name, limit, err)
		}
		if !ok {
			t.Fatalf("%s missing canonical hash at height %d", left.name, limit)
		}
		rightHash, ok, err := right.blockStore.CanonicalHash(limit)
		if err != nil {
			t.Fatalf("%s canonical hash %d: %v", right.name, limit, err)
		}
		if !ok {
			t.Fatalf("%s missing canonical hash at height %d", right.name, limit)
		}
		if leftHash == rightHash {
			return limit, true
		}
		if limit == 0 {
			return 0, false
		}
		limit--
	}
}

func tip(t *testing.T, current *devnetNode) (uint64, [32]byte, bool) {
	t.Helper()
	height, hash, ok, err := current.blockStore.Tip()
	if err != nil {
		t.Fatalf("%s tip: %v", current.name, err)
	}
	return height, hash, ok
}

func loadChainState(t *testing.T, current *devnetNode) *node.ChainState {
	t.Helper()
	state, err := node.LoadChainState(current.chainStatePath)
	if err != nil {
		t.Fatalf("%s load chainstate: %v", current.name, err)
	}
	return state
}

func readChainStateFile(t *testing.T, current *devnetNode) []byte {
	t.Helper()
	raw, err := os.ReadFile(current.chainStatePath)
	if err != nil {
		t.Fatalf("%s read chainstate file: %v", current.name, err)
	}
	return raw
}

func chainStateDigest(t *testing.T, current *devnetNode) string {
	t.Helper()
	sum := sha256.Sum256(readChainStateFile(t, current))
	return hex.EncodeToString(sum[:])
}

func utxoDigest(t *testing.T, current *devnetNode) string {
	t.Helper()
	state := loadChainState(t, current)
	rows := make([]string, 0, len(state.Utxos))
	for op, entry := range state.Utxos {
		rows = append(rows, fmt.Sprintf(
			"%x:%d:%d:%d:%x:%d:%t",
			op.Txid,
			op.Vout,
			entry.Value,
			entry.CovenantType,
			entry.CovenantData,
			entry.CreationHeight,
			entry.CreatedByCoinbase,
		))
	}
	sort.Strings(rows)
	sum := sha256.Sum256([]byte(strings.Join(rows, "\n")))
	return hex.EncodeToString(sum[:])
}

func cumulativeSubsidy(height uint64) uint64 {
	var total uint64
	var alreadyGenerated uint64
	for currentHeight := uint64(1); currentHeight <= height; currentHeight++ {
		subsidy := consensus.BlockSubsidy(currentHeight, alreadyGenerated)
		total += subsidy
		alreadyGenerated += subsidy
	}
	return total
}

func mustMineAddress(t *testing.T, seed byte) []byte {
	t.Helper()
	raw, err := node.ParseMineAddress(strings.Repeat(fmt.Sprintf("%02x", seed), 32))
	if err != nil {
		t.Fatalf("parse mine address seed=0x%02x: %v", seed, err)
	}
	return raw
}
