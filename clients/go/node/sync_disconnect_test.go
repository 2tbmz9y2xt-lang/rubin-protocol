package node

import (
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestDisconnectTipRejectsCorruptStoredCommitmentsBeforeMutation(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	subsidy := consensus.BlockSubsidy(1, 0)
	block := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
	summary, err := engine.ApplyBlock(block, nil)
	if err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}
	beforeState, err := stateToDisk(engine.chainState)
	if err != nil {
		t.Fatalf("stateToDisk(before): %v", err)
	}
	beforeIndex, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot(before): %v", err)
	}
	writeRawStoreBlockFile(t, store, summary.BlockHash, corruptStoredMerkleBody(t, block))

	_, err = engine.DisconnectTip()
	assertBranchStoreCorruption(t, err)
	if got, err := stateToDisk(engine.chainState); err != nil || !reflect.DeepEqual(got, beforeState) {
		t.Fatalf("chainstate after corrupt disconnect: state=%+v err=%v", got, err)
	}
	if got, err := store.CanonicalIndexSnapshot(); err != nil || !reflect.DeepEqual(got, beforeIndex) {
		t.Fatalf("canonical index after corrupt disconnect: index=%v err=%v", got, err)
	}
}

func TestReorgPreviewRejectsCorruptCanonicalStoredCommitmentsBeforeMutation(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	subsidy1 := consensus.BlockSubsidy(1, 0)
	canonical := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	canonicalSummary, err := engine.ApplyBlock(canonical, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(canonical): %v", err)
	}

	sideB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	b1Parsed, b1Hash := mustParseReorgBlockForTest(t, sideB1)
	if err := store.StoreBlock(b1Hash, b1Parsed.HeaderBytes, sideB1); err != nil {
		t.Fatalf("StoreBlock(B1): %v", err)
	}
	sideB2 := buildSingleTxBlock(t, b1Hash, target, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, consensus.BlockSubsidy(2, subsidy1)))

	mempool, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)
	beforeState, err := stateToDisk(engine.chainState)
	if err != nil {
		t.Fatalf("stateToDisk(before): %v", err)
	}
	beforeIndex, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot(before): %v", err)
	}
	beforeCounts := engine.BlockApplyCounts()
	beforeMempoolLen := mempool.Len()
	writeRawStoreBlockFile(t, store, canonicalSummary.BlockHash, corruptStoredMerkleBody(t, canonical))

	_, err = engine.ApplyBlockWithReorg(sideB2, nil)
	assertBranchStoreCorruption(t, err)
	if got, err := stateToDisk(engine.chainState); err != nil || !reflect.DeepEqual(got, beforeState) {
		t.Fatalf("chainstate after corrupt preview: state=%+v err=%v", got, err)
	}
	if got, err := store.CanonicalIndexSnapshot(); err != nil || !reflect.DeepEqual(got, beforeIndex) {
		t.Fatalf("canonical index after corrupt preview: index=%v err=%v", got, err)
	}
	if got := engine.BlockApplyCounts(); got != beforeCounts {
		t.Fatalf("BlockApplyCounts=%+v, want %+v", got, beforeCounts)
	}
	if got := mempool.Len(); got != beforeMempoolLen {
		t.Fatalf("mempool len=%d, want %d", got, beforeMempoolLen)
	}
}

func TestDisconnectPreparedTipUsesRetainedVerifiedBlock(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	subsidy := consensus.BlockSubsidy(1, 0)
	block := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
	summary, err := engine.ApplyBlock(block, nil)
	if err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}
	ctx, err := engine.prepareDisconnectTip()
	if err != nil {
		t.Fatalf("prepareDisconnectTip: %v", err)
	}
	if ctx.storedBlock.lookupHash != summary.BlockHash || !reflect.DeepEqual(ctx.storedBlock.blockBytes, block) {
		t.Fatal("prepared disconnect did not retain the verified canonical block")
	}
	writeRawStoreBlockFile(t, store, summary.BlockHash, []byte("not a block"))

	disconnected, err := engine.disconnectPreparedTip(ctx)
	if err != nil {
		t.Fatalf("disconnectPreparedTip reread or reparsed the block: %v", err)
	}
	if disconnected.BlockHash != summary.BlockHash || engine.chainState.Height != 0 || engine.chainState.TipHash != devnetGenesisBlockHash {
		t.Fatalf("disconnect summary=%+v state=(%d,%x)", disconnected, engine.chainState.Height, engine.chainState.TipHash)
	}
	if _, ok, err := store.CanonicalHash(1); err != nil || ok {
		t.Fatalf("canonical height 1 after disconnect: ok=%v err=%v", ok, err)
	}
}

func TestPreparedCanonicalDisconnectRetainsPreviewedBlocks(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	var hashes [][32]byte
	blocks := make([][]byte, 0, 2)
	prevHash := devnetGenesisBlockHash
	alreadyGenerated := uint64(0)
	for height := uint64(1); height <= 2; height++ {
		subsidy := consensus.BlockSubsidy(height, alreadyGenerated)
		block := buildSingleTxBlock(t, prevHash, target, reorgTestTimestamp(height), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy))
		summary, err := engine.ApplyBlock(block, nil)
		if err != nil {
			t.Fatalf("ApplyBlock(A%d): %v", height, err)
		}
		hashes = append(hashes, summary.BlockHash)
		blocks = append(blocks, block)
		prevHash = summary.BlockHash
		alreadyGenerated += subsidy
	}

	undoDir := store.undoDir
	store.undoDir = t.TempDir()
	writeRawStoreBlockFile(t, store, hashes[0], corruptStoredMerkleBody(t, blocks[0]))
	_, _, err := engine.previewDisconnectCanonicalToAncestor(cloneChainState(engine.chainState), 0)
	assertBranchStoreCorruption(t, err)
	store.undoDir = undoDir
	writeRawStoreBlockFile(t, store, hashes[0], blocks[0])

	prepared, depth, err := engine.previewDisconnectCanonicalToAncestor(cloneChainState(engine.chainState), 0)
	if err != nil || depth != 2 || len(prepared) != 2 {
		t.Fatalf("previewDisconnectCanonicalToAncestor=(%d blocks,%d,%v), want two blocks", len(prepared), depth, err)
	}
	for index, storedBlock := range prepared {
		wantHash := hashes[len(hashes)-1-index]
		if storedBlock.lookupHash != wantHash || storedBlock.parsed == nil {
			t.Fatalf("prepared[%d]=(%x,%v), want retained %x", index, storedBlock.lookupHash, storedBlock.parsed, wantHash)
		}
		writeRawStoreBlockFile(t, store, storedBlock.lookupHash, []byte("replaced after preview"))
	}

	if err := engine.disconnectCanonicalToAncestor(0, prepared); err != nil {
		t.Fatalf("disconnectCanonicalToAncestor reread a prepared block: %v", err)
	}
	if engine.chainState.Height != 0 || engine.chainState.TipHash != devnetGenesisBlockHash {
		t.Fatalf("chainstate after retained disconnect=(%d,%x), want genesis", engine.chainState.Height, engine.chainState.TipHash)
	}
	if _, ok, err := store.CanonicalHash(1); err != nil || ok {
		t.Fatalf("canonical height 1 after retained disconnect: ok=%v err=%v", ok, err)
	}
}

func TestPreparedDisconnectValidationErrors(t *testing.T) {
	engine, _, target := newReorgTestEngine(t)
	block := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
	if _, err := engine.ApplyBlock(block, nil); err != nil {
		t.Fatal(err)
	}
	prepared, _, err := engine.previewDisconnectCanonicalToAncestor(cloneChainState(engine.chainState), 0)
	if err != nil {
		t.Fatal(err)
	}
	stored := prepared[0]
	badTxids, parsed := stored, *stored.parsed
	parsed.Txids, badTxids.parsed = nil, &parsed
	wrongHash := stored
	wrongHash.lookupHash[0] ^= 1
	empty, uninitialized := &SyncEngine{chainState: NewChainState(), blockStore: &BlockStore{}}, &SyncEngine{}
	nilPacket := []verifiedStoredBlock{{lookupHash: stored.lookupHash}}
	context := func(block verifiedStoredBlock) error {
		_, err := engine.prepareDisconnectTipContext(1, stored.lookupHash, block, nil)
		return err
	}
	cases := []struct {
		name, want string
		run        func() error
	}{
		{"prepare uninitialized", "sync engine is not initialized", func() error { _, err := uninitialized.prepareDisconnectTipFromVerified(stored); return err }},
		{"prepare empty store", "blockstore has no canonical tip", func() error { _, err := empty.prepareDisconnectTipFromVerified(stored); return err }},
		{"ancestor above tip", "common ancestor is above canonical tip", func() error { return engine.disconnectCanonicalToAncestor(2, prepared) }},
		{"validate uninitialized", "sync engine is not initialized", func() error { return uninitialized.validatePreparedDisconnectBlocks(0, nil) }},
		{"validate empty store", "blockstore has no canonical tip", func() error { return empty.validatePreparedDisconnectBlocks(0, nil) }},
		{"wrong count", "prepared disconnect block count mismatch", func() error { return engine.validatePreparedDisconnectBlocks(0, nil) }},
		{"nil parsed", "invalid prepared disconnect block", func() error { return engine.validatePreparedDisconnectBlocks(0, nilPacket) }},
		{"txid length", "invalid prepared disconnect block", func() error { return engine.validatePreparedDisconnectBlocks(0, []verifiedStoredBlock{badTxids}) }},
		{"missing canonical", "prepared disconnect block is not canonical", func() error { return engine.validatePreparedDisconnectBlock(stored, 2) }},
		{"lookup mismatch", "prepared disconnect block is not canonical", func() error { return engine.validatePreparedDisconnectBlock(wrongHash, 1) }},
		{"context lookup mismatch", "disconnect block is not current canonical tip", func() error { return context(wrongHash) }},
		{"context nil parsed", "nil verified stored block", func() error { return context(nilPacket[0]) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want %q", err, tc.want)
			}
		})
	}
}
