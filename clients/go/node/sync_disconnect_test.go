package node

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
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

	tr := mustBeginCanonicalTransition(t, engine)
	disconnected, err := engine.disconnectPreparedTip(ctx, tr.rollback)
	if err != nil {
		tr.abort()
		t.Fatalf("disconnectPreparedTip reread or reparsed the block: %v", err)
	}
	if err := tr.finish(); err != nil {
		t.Fatalf("canonical transition finish: %v", err)
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

	tr := mustBeginCanonicalTransition(t, engine)
	if err := engine.disconnectCanonicalToAncestor(0, prepared, tr.rollback); err != nil {
		tr.abort()
		t.Fatalf("disconnectCanonicalToAncestor reread a prepared block: %v", err)
	}
	if err := tr.finish(); err != nil {
		t.Fatalf("canonical transition finish: %v", err)
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
		{"ancestor above tip", "common ancestor is above canonical tip", func() error { return engine.disconnectCanonicalToAncestor(2, prepared, syncRollbackState{}) }},
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

// TestDisconnectTipPendingOutpointAdvancesOneGenerationWithoutRequeue proves the
// standalone-disconnect row: each disconnect runs as ONE canonical transition
// that advances exactly one generation and commits the parent as the owner's
// stable tip, it leaves resident records and their exact tokens untouched, and
// it invents no requeue policy — a transaction carried by the disconnected
// block does not reappear in the standard mempool.
func TestDisconnectTipPendingOutpointAdvancesOneGenerationWithoutRequeue(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	forkHash, forkHeight, forkGenerated := f.tipHash, f.tipHeight, f.alreadyGenerated
	spend := f.spend(t, 700, 1)
	spendID := txID(t, spend)

	subsidy101 := consensus.BlockSubsidy(forkHeight+1, forkGenerated)
	plain := buildSingleTxBlock(t, forkHash, f.target, 202, reorgTestCoinbaseForAddress(t, forkHeight+1, subsidy101, f.sourceAddress))
	if _, err := f.engine.ApplyBlock(plain, nil); err != nil {
		t.Fatalf("ApplyBlock(plain 101): %v", err)
	}
	if err := f.mempool.AddTx(spend); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	f.mempool.mu.Lock()
	residentToken := f.mempool.txs[spendID].token
	f.mempool.mu.Unlock()
	beforeDisconnect := mustAdmissionContext(t, f.owner, "before the standalone disconnect")

	if _, err := f.engine.DisconnectTip(); err != nil {
		t.Fatalf("DisconnectTip(plain 101): %v", err)
	}

	afterDisconnect := mustAdmissionContext(t, f.owner, "after the standalone disconnect")
	if afterDisconnect.Generation != beforeDisconnect.Generation+1 {
		t.Fatalf("generation after disconnect=%d, want exactly one advance from %d", afterDisconnect.Generation, beforeDisconnect.Generation)
	}
	if afterDisconnect.StableTip.Hash != forkHash || afterDisconnect.StableTip.Height != forkHeight {
		t.Fatalf("stable tip after disconnect=%+v, want the parent (%d,%x)", afterDisconnect.StableTip, forkHeight, forkHash)
	}
	entry, claim := residentClaim(t, f.mempool, spendID)
	if entry.token != residentToken {
		t.Fatalf("resident token seq=%d after disconnect, want the exact seq %d", entry.token.seq, residentToken.seq)
	}
	if claim == nil || !claim.finalized {
		t.Fatalf("resident claim=%+v after disconnect, want it untouched and finalized", claim)
	}
	if got := f.mempool.Len(); got != 1 {
		t.Fatalf("mempool len after disconnect=%d, want the single untouched resident", got)
	}

	// Now disconnect a block that DID carry the transaction: the connect
	// released its token, and the disconnect must not requeue it.
	including := f.blockIncluding(t, forkHash, forkHeight+1, forkGenerated, 203, spend)
	if _, err := f.engine.ApplyBlock(including, nil); err != nil {
		t.Fatalf("ApplyBlock(including spend): %v", err)
	}
	if got := f.mempool.Len(); got != 0 {
		t.Fatalf("mempool len after the including connect=%d, want 0", got)
	}
	beforeSecond := mustAdmissionContext(t, f.owner, "before the second disconnect")
	if _, err := f.engine.DisconnectTip(); err != nil {
		t.Fatalf("DisconnectTip(including 101): %v", err)
	}
	afterSecond := mustAdmissionContext(t, f.owner, "after the second disconnect")
	if afterSecond.Generation != beforeSecond.Generation+1 {
		t.Fatalf("second disconnect generation=%d, want exactly one advance from %d", afterSecond.Generation, beforeSecond.Generation)
	}
	if afterSecond.StableTip.Hash != forkHash {
		t.Fatalf("stable tip after the second disconnect=%+v, want the parent %x", afterSecond.StableTip, forkHash)
	}
	if got := f.mempool.Len(); got != 0 {
		t.Fatalf("mempool len after the second disconnect=%d, want 0: standalone disconnect adds no requeue", got)
	}
	outpoints, claims, highWater := ownerClaimCount(f.owner)
	if outpoints != 0 || claims != 0 {
		t.Fatalf("owner holds outpoints=%d claims=%d after the disconnects, want none", outpoints, claims)
	}
	if highWater != 1 {
		t.Fatalf("token high-water=%d, want the single consumed sequence retained", highWater)
	}
}

// mustBeginCanonicalTransition runs the canonical-index preflight and opens a
// transition in the same order production does, so a test never opens one with
// an unread rollback index.
func mustBeginCanonicalTransition(t *testing.T, engine *SyncEngine) *canonicalTransition {
	t.Helper()
	canonicalIndex, err := engine.canonicalIndexPreflight()
	if err != nil {
		t.Fatalf("canonicalIndexPreflight: %v", err)
	}
	tr, err := engine.beginCanonicalTransition(canonicalIndex)
	if err != nil {
		t.Fatalf("beginCanonicalTransition: %v", err)
	}
	return tr
}

// TestDisconnectCorruptUndoLeavesStateUnchanged pins RUB-1132 step 7 on the
// standalone disconnect path: a parse-valid but checksum-broken undo record
// must be refused BEFORE the canonical transition opens, leaving chainstate,
// the canonical index, the blockstore tip and the persisted snapshot exactly as
// they were. Rust twin: `disconnect_corrupt_undo_leaves_state_unchanged`.
func TestDisconnectCorruptUndoLeavesStateUnchanged(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	subsidy := consensus.BlockSubsidy(1, 0)
	block := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1),
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
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
	beforeHeight, beforeHash, beforeOK, err := store.Tip()
	if err != nil {
		t.Fatalf("Tip(before): %v", err)
	}
	beforeSnapshot, err := os.ReadFile(engine.cfg.ChainStatePath)
	if err != nil {
		t.Fatalf("read chainstate snapshot: %v", err)
	}

	corrupt, original := corruptStoredUndoChecksum(t, store, summary.BlockHash)

	_, err = engine.DisconnectTip()
	if err == nil {
		t.Fatal("DisconnectTip accepted a checksum-broken undo record")
	}
	if !errors.Is(err, ErrUndoIntegrity) {
		t.Fatalf("err = %v, want errors.Is ErrUndoIntegrity", err)
	}
	if err.Error() != "UNDO_INTEGRITY: checksum mismatch" {
		t.Fatalf("message = %q, want exactly %q", err.Error(), "UNDO_INTEGRITY: checksum mismatch")
	}
	// A corrupt LOCAL record must never be reported as a consensus fault: node/p2p
	// ban-scores the relaying peer on any *consensus.TxError in the chain.
	var txErr *consensus.TxError
	if errors.As(err, &txErr) {
		t.Fatalf("local corruption surfaced as consensus.TxError: %v", err)
	}

	afterState, err := stateToDisk(engine.chainState)
	if err != nil {
		t.Fatalf("stateToDisk(after): %v", err)
	}
	if !reflect.DeepEqual(afterState, beforeState) {
		t.Fatalf("chainstate mutated: before=%+v after=%+v", beforeState, afterState)
	}
	afterIndex, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot(after): %v", err)
	}
	if !reflect.DeepEqual(afterIndex, beforeIndex) {
		t.Fatalf("canonical index mutated: before=%v after=%v", beforeIndex, afterIndex)
	}
	afterHeight, afterHash, afterOK, err := store.Tip()
	if err != nil {
		t.Fatalf("Tip(after): %v", err)
	}
	if afterHeight != beforeHeight || afterHash != beforeHash || afterOK != beforeOK {
		t.Fatalf("blockstore tip moved: before=(%d,%x,%v) after=(%d,%x,%v)",
			beforeHeight, beforeHash, beforeOK, afterHeight, afterHash, afterOK)
	}
	afterSnapshot, err := os.ReadFile(engine.cfg.ChainStatePath)
	if err != nil {
		t.Fatalf("re-read chainstate snapshot: %v", err)
	}
	if !bytes.Equal(afterSnapshot, beforeSnapshot) {
		t.Fatal("persisted chainstate snapshot was rewritten by a refused disconnect")
	}
	// The refusal must not heal the record either.
	undoPath := filepath.Join(store.undoDir, hex.EncodeToString(summary.BlockHash[:])+".json")
	if after, err := os.ReadFile(undoPath); err != nil || !bytes.Equal(after, corrupt) {
		t.Fatalf("refused disconnect rewrote the undo record (err=%v)", err)
	}

	// W6 positive control: the same disconnect must succeed once the record is
	// valid again, so the rejection above is attributable to the corruption and
	// not to a path that now refuses everything.
	restoreStoredUndo(t, store, summary.BlockHash, original)
	disconnected, err := engine.DisconnectTip()
	if err != nil {
		t.Fatalf("DisconnectTip after restore: %v", err)
	}
	if disconnected.DisconnectedHeight != 1 || engine.chainState.Height != 0 ||
		engine.chainState.TipHash != devnetGenesisBlockHash {
		t.Fatalf("restored disconnect=(%d) state=(%d,%x), want height 0 at genesis",
			disconnected.DisconnectedHeight, engine.chainState.Height, engine.chainState.TipHash)
	}
}
