package node_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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
	peerManager    *node.PeerManager
	service        *p2p.Service
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

func newDevnetNode(t *testing.T, name string, bindAddr string, bootstrapPeers []string, mineSeed byte, applyGenesis bool) *devnetNode {
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

	current := &devnetNode{
		name:           name,
		dir:            dir,
		chainStatePath: chainStatePath,
		chainState:     chainState,
		blockStore:     blockStore,
		syncEngine:     syncEngine,
		peerManager:    node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8)),
		mineAddress:    mustMineAddress(t, mineSeed),
		timestamp:      1_777_000_000 + uint64(mineSeed)*100,
	}

	if bindAddr != "" {
		runtimeCfg := node.DefaultPeerRuntimeConfig("devnet", 8)
		runtimeCfg.ReadDeadline = time.Second
		runtimeCfg.WriteDeadline = time.Second
		runtimeCfg.HandshakeTimeout = time.Second

		service, err := p2p.NewService(p2p.ServiceConfig{
			BindAddr:          bindAddr,
			BootstrapPeers:    bootstrapPeers,
			UserAgent:         "rubin-go/devnet-test",
			GenesisHash:       node.DevnetGenesisBlockHash(),
			PeerRuntimeConfig: runtimeCfg,
			PeerManager:       current.peerManager,
			SyncConfig:        syncCfg,
			SyncEngine:        syncEngine,
			BlockStore:        blockStore,
		})
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

func (n *devnetNode) start(ctx context.Context) error {
	if n == nil || n.service == nil {
		return nil
	}
	return n.service.Start(ctx)
}

func (n *devnetNode) close() {
	if n == nil || n.service == nil {
		return
	}
	_ = n.service.Close()
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
