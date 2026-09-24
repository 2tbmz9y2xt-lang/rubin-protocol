package node_test

import (
	"bytes"
	"context"
	"crypto/sha3"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestDevnetThreeNodeCanonicalDAAndRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signer, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		t.Fatalf("new ML-DSA keypair: %v", err)
	}
	t.Cleanup(func() { signer.Close() })
	address := consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())
	a := newDevnetNodeWithMineAddress(t, "da-a", "127.0.0.1:0", nil, address, true)
	if err := a.start(ctx); err != nil {
		t.Fatal(err)
	}
	defer a.close()
	b := newDevnetNode(t, "da-b", "127.0.0.1:0", []string{a.service.Addr()}, 0x22, false)
	if err := b.start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.close()
	c := newDevnetNode(t, "da-c", "127.0.0.1:0", []string{a.service.Addr()}, 0x33, false)
	if err := c.start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.close()
	waitFor(t, 5*time.Second, "DA block peers", func() bool {
		return a.peerManager.Count() == 2 && b.peerManager.Count() == 1 && c.peerManager.Count() == 1
	})
	var firstBlocks [2][32]byte
	for height := uint64(1); height <= consensus.COINBASE_MATURITY+1; height++ {
		mined := a.mineOne(t, true)
		if height <= 2 {
			firstBlocks[height-1] = mined.Hash
		}
		waitForHeight(t, b, height)
		waitForHeight(t, c, height)
	}
	spendable := make([]consensus.Outpoint, 0, 2)
	for height := uint64(1); height <= 2; height++ {
		block, err := a.blockStore.GetBlockByHash(firstBlocks[height-1])
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := consensus.ParseBlockBytes(block)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := consensus.MarshalTx(parsed.Txs[0])
		if err != nil {
			t.Fatal(err)
		}
		spendable = append(spendable, consensus.Outpoint{Txid: mustTxIDFromRaw(t, raw), Vout: 0})
	}
	payload := []byte("three-node DA block")
	hash := sha3.Sum256(payload)
	daID := [32]byte{0xda, 0x42}
	commit := &consensus.Tx{
		Version: 1, TxKind: 0x01, TxNonce: 1,
		Inputs:       []consensus.TxInput{{PrevTxid: spendable[0].Txid, PrevVout: 0}},
		Outputs:      []consensus.TxOutput{{CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: hash[:]}},
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: 1, BatchNumber: 1},
	}
	chunk := &consensus.Tx{
		Version: 1, TxKind: 0x02, TxNonce: 2,
		Inputs:      []consensus.TxInput{{PrevTxid: spendable[1].Txid, PrevVout: 0}},
		DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: 0, ChunkHash: hash},
		DaPayload:   append([]byte(nil), payload...),
	}
	var raw [2][]byte
	for i, tx := range []*consensus.Tx{commit, chunk} {
		if err := consensus.SignTransaction(tx, a.chainState.Utxos, node.DevnetGenesisChainID(), signer); err != nil {
			t.Fatal(err)
		}
		var err error
		raw[i], err = consensus.MarshalTx(tx)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.service.AnnounceTx(raw[i]); err != nil {
			t.Fatalf("announce DA member %d: %v", i, err)
		}
	}
	sets := a.service.CompleteDASetCandidates(consensus.MAX_DA_BYTES_PER_BLOCK)
	if len(sets) != 1 || !bytes.Equal(sets[0].CommitTx, raw[0]) || len(sets[0].Chunks) != 1 || !bytes.Equal(sets[0].Chunks[0].Tx, raw[1]) {
		t.Fatalf("complete DA sets: %+v", sets)
	}
	cfg := node.DefaultMinerConfig()
	cfg.MineAddress = append([]byte(nil), address...)
	cfg.CompleteDASetProvider = a.service
	cfg.TimestampSource = func() uint64 { a.timestamp++; return a.timestamp }
	miner, err := node.NewMiner(a.chainState, a.blockStore, a.syncEngine, cfg)
	if err != nil {
		t.Fatal(err)
	}
	mined, err := miner.MineOne(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	block, err := a.blockStore.GetBlockByHash(mined.Hash)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := consensus.ParseBlockBytes(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Txs) != 3 {
		t.Fatalf("DA block txs=%d, want coinbase/commit/chunk", len(parsed.Txs))
	}
	for _, member := range raw {
		assertBlockContainsTxID(t, a, mined.Hash, mustTxIDFromRaw(t, member))
	}
	if err := a.service.AnnounceBlock(block); err != nil {
		t.Fatal(err)
	}
	waitForHeight(t, b, mined.Height)
	waitForHeight(t, c, mined.Height)
	for _, member := range raw {
		txid := mustTxIDFromRaw(t, member)
		assertBlockContainsTxID(t, b, mined.Hash, txid)
		assertBlockContainsTxID(t, c, mined.Hash, txid)
	}
	assertSameTip(t, a, b, c)
	c.stop()
	before := snapshotNodeImage(t, c)
	oldStore := c.blockStore
	reopened, err := node.OpenBlockStore(node.BlockStorePath(c.dir))
	if err != nil {
		t.Fatalf("reopen node C blockstore: %v", err)
	}
	if reopened == oldStore {
		t.Fatal("node C reused the old BlockStore")
	}
	c.blockStore = reopened
	recovered, err := c.restartWithPeers(t, ctx, []string{a.service.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	if c.blockStore != reopened {
		t.Fatal("node C restart did not use reopened BlockStore")
	}
	for _, member := range raw {
		assertBlockContainsTxID(t, c, mined.Hash, mustTxIDFromRaw(t, member))
	}
	if recovered != before {
		t.Fatalf("DA restart image=%+v want %+v", recovered, before)
	}
	waitForPeerCountWithTimeout(t, c, 1, 5*time.Second)
	assertSameTip(t, a, b, c)
	assertSameRecoveredChainState(t, a, b, c)
	t.Logf("DA commit/chunk in canonical block h=%d on three nodes; node C restart recovered same image", mined.Height)
}
