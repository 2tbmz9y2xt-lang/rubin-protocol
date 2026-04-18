package node

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestShouldPersistChainStateSnapshotCadence(t *testing.T) {
	if !shouldPersistChainStateSnapshot(nil, nil) {
		t.Fatalf("nil state+summary must persist to stay fail-closed")
	}
	if !shouldPersistChainStateSnapshot(NewChainState(), &ChainStateConnectSummary{BlockHeight: 1}) {
		t.Fatalf("tipless state must persist to seed first snapshot")
	}

	smallState := NewChainState()
	smallState.HasTip = true
	smallState.Utxos = make(map[consensus.Outpoint]consensus.UtxoEntry, chainStateSnapshotSmallUtxoCutoff)
	for i := uint64(0); i < chainStateSnapshotSmallUtxoCutoff; i++ {
		var txid [32]byte
		txid[0] = byte(i)
		smallState.Utxos[consensus.Outpoint{Txid: txid, Vout: uint32(i)}] = consensus.UtxoEntry{Value: i + 1}
	}
	if !shouldPersistChainStateSnapshot(smallState, &ChainStateConnectSummary{BlockHeight: 17}) {
		t.Fatalf("small utxo set must persist every block")
	}

	largeState := NewChainState()
	largeState.HasTip = true
	largeState.Utxos = make(map[consensus.Outpoint]consensus.UtxoEntry, chainStateSnapshotSmallUtxoCutoff+1)
	for i := uint64(0); i <= chainStateSnapshotSmallUtxoCutoff; i++ {
		var txid [32]byte
		txid[0] = byte(i)
		txid[1] = byte(i >> 8)
		largeState.Utxos[consensus.Outpoint{Txid: txid, Vout: uint32(i)}] = consensus.UtxoEntry{Value: i + 1}
	}
	if shouldPersistChainStateSnapshot(largeState, &ChainStateConnectSummary{BlockHeight: chainStateSnapshotIntervalBlocks - 1}) {
		t.Fatalf("large utxo set must skip non-interval snapshots")
	}
	if !shouldPersistChainStateSnapshot(largeState, &ChainStateConnectSummary{BlockHeight: chainStateSnapshotIntervalBlocks}) {
		t.Fatalf("large utxo set must persist on interval boundary")
	}
	if !shouldPersistChainStateSnapshot(largeState, &ChainStateConnectSummary{BlockHeight: 0}) {
		t.Fatalf("height zero summary must persist")
	}
}

func TestCloneChainState_NilAndDeepCopy(t *testing.T) {
	if cloneChainState(nil) != nil {
		t.Fatalf("cloneChainState(nil) must be nil")
	}

	src := NewChainState()
	src.HasTip = true
	src.Height = 7
	src.AlreadyGenerated = 42
	src.TipHash[0] = 0xaa
	var txid [32]byte
	txid[0] = 0x11
	op := consensus.Outpoint{Txid: txid, Vout: 1}
	src.Utxos[op] = consensus.UtxoEntry{Value: 9}

	cloned := cloneChainState(src)
	if cloned == src {
		t.Fatalf("clone must allocate a new state")
	}
	cloned.Height = 8
	cloned.TipHash[0] ^= 0xff
	entry := cloned.Utxos[op]
	entry.Value = 99
	cloned.Utxos[op] = entry

	if src.Height != 7 || src.TipHash[0] != 0xaa || src.Utxos[op].Value != 9 {
		t.Fatalf("clone mutated original state")
	}
}

func TestReconcileChainStateWithBlockStoreReplaysMissingCanonicalBlocks(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}

	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath)
	liveState := NewChainState()
	engine, err := NewSyncEngine(liveState, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	genesisSnapshot := cloneChainState(liveState)

	genesisParsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, genesisParsed.Header.Timestamp+1, block1Coinbase)
	summary, err := engine.ApplyBlock(block1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(block1): %v", err)
	}

	stale := cloneChainState(genesisSnapshot)
	changed, err := ReconcileChainStateWithBlockStore(stale, store, cfg)
	if err != nil {
		t.Fatalf("ReconcileChainStateWithBlockStore: %v", err)
	}
	if !changed {
		t.Fatalf("expected reconcile to replay missing canonical block")
	}
	if !stale.HasTip || stale.Height != 1 || stale.TipHash != summary.BlockHash {
		t.Fatalf("unexpected reconciled state: has_tip=%v height=%d tip=%x", stale.HasTip, stale.Height, stale.TipHash)
	}
}

func TestReconcileChainStateWithBlockStoreResetsMismatchedSnapshot(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}

	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath)
	liveState := NewChainState()
	engine, err := NewSyncEngine(liveState, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}

	mismatched := cloneChainState(liveState)
	mismatched.TipHash[0] ^= 0xff
	changed, err := ReconcileChainStateWithBlockStore(mismatched, store, cfg)
	if err != nil {
		t.Fatalf("ReconcileChainStateWithBlockStore: %v", err)
	}
	if !changed {
		t.Fatalf("expected reconcile to rewrite mismatched snapshot")
	}
	if !mismatched.HasTip || mismatched.Height != 0 || mismatched.TipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected reconciled genesis state: has_tip=%v height=%d tip=%x", mismatched.HasTip, mismatched.Height, mismatched.TipHash)
	}
}

func TestReconcileChainStateWithBlockStore_InputValidationAndNoopPaths(t *testing.T) {
	target := consensus.POW_LIMIT

	if _, err := ReconcileChainStateWithBlockStore(nil, &BlockStore{}, DefaultSyncConfig(&target, devnetGenesisChainID, "")); err == nil {
		t.Fatalf("expected nil chainstate error")
	}

	state := NewChainState()
	if _, err := ReconcileChainStateWithBlockStore(state, nil, DefaultSyncConfig(&target, devnetGenesisChainID, "")); err == nil {
		t.Fatalf("expected nil blockstore error")
	}

	dir := t.TempDir()
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	changed, err := ReconcileChainStateWithBlockStore(state, store, DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("ReconcileChainStateWithBlockStore(empty): %v", err)
	}
	if changed {
		t.Fatalf("empty store must not rewrite chainstate")
	}

	dirty := NewChainState()
	dirty.HasTip = true
	dirty.Height = 7
	dirty.AlreadyGenerated = 99
	dirty.TipHash[0] = 0xaa
	dirty.Utxos[consensus.Outpoint{Txid: [32]byte{0x01}, Vout: 1}] = consensus.UtxoEntry{Value: 7}
	changed, err = ReconcileChainStateWithBlockStore(dirty, store, DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("ReconcileChainStateWithBlockStore(empty dirty): %v", err)
	}
	if !changed {
		t.Fatalf("dirty empty-store snapshot must be reset")
	}
	if dirty.HasTip || dirty.Height != 0 || dirty.AlreadyGenerated != 0 || dirty.TipHash != ([32]byte{}) || len(dirty.Utxos) != 0 {
		t.Fatalf("dirty empty-store snapshot not reset: %+v", dirty)
	}
}

func TestTruncateIncompleteCanonicalSuffix_InputValidation(t *testing.T) {
	if _, err := truncateIncompleteCanonicalSuffix(nil); err == nil {
		t.Fatalf("expected nil blockstore error")
	}

	store := mustOpenBlockStore(t, BlockStorePath(t.TempDir()))
	store.index.Canonical = []string{"zz"}
	if _, err := truncateIncompleteCanonicalSuffix(store); err == nil {
		t.Fatalf("expected malformed canonical hash error")
	}
}

func TestReconcileChainStateWithBlockStore_NoopForCanonicalTipAndResetsAheadSnapshot(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}

	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath)
	liveState := NewChainState()
	engine, err := NewSyncEngine(liveState, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}

	synced := cloneChainState(liveState)
	changed, err := ReconcileChainStateWithBlockStore(synced, store, cfg)
	if err != nil {
		t.Fatalf("ReconcileChainStateWithBlockStore(synced): %v", err)
	}
	if changed {
		t.Fatalf("matching canonical tip must be a no-op")
	}

	ahead := cloneChainState(liveState)
	ahead.Height = 5
	changed, err = ReconcileChainStateWithBlockStore(ahead, store, cfg)
	if err != nil {
		t.Fatalf("ReconcileChainStateWithBlockStore(ahead): %v", err)
	}
	if !changed {
		t.Fatalf("ahead snapshot must be reset and replayed")
	}
	if !ahead.HasTip || ahead.Height != 0 || ahead.TipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected reconciled state after ahead reset: has_tip=%v height=%d tip=%x", ahead.HasTip, ahead.Height, ahead.TipHash)
	}
}

func TestReconcileChainStateWithBlockStore_TruncatesIncompleteCanonicalSuffix(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}

	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath)
	liveState := NewChainState()
	engine, err := NewSyncEngine(liveState, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}

	genesisParsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, genesisParsed.Header.Timestamp+1, block1Coinbase)
	if _, err := engine.ApplyBlock(block1, nil); err != nil {
		t.Fatalf("ApplyBlock(block1): %v", err)
	}

	block1Parsed, err := consensus.ParseBlockBytes(block1)
	if err != nil {
		t.Fatalf("ParseBlockBytes(block1): %v", err)
	}
	block1Hash, err := consensus.BlockHash(block1Parsed.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(block1): %v", err)
	}
	if err := os.Remove(filepath.Join(store.undoDir, hex.EncodeToString(block1Hash[:])+".json")); err != nil {
		t.Fatalf("Remove(block1 undo): %v", err)
	}

	state := cloneChainState(liveState)
	changed, err := ReconcileChainStateWithBlockStore(state, store, cfg)
	if err != nil {
		t.Fatalf("ReconcileChainStateWithBlockStore: %v", err)
	}
	if !changed {
		t.Fatalf("expected reconcile to truncate incomplete canonical suffix")
	}
	tipHeight, tipHash, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if !ok || tipHeight != 0 || tipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected truncated tip: ok=%v height=%d hash=%x", ok, tipHeight, tipHash)
	}
	if !state.HasTip || state.Height != 0 || state.TipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected reconciled state after truncation: has_tip=%v height=%d tip=%x", state.HasTip, state.Height, state.TipHash)
	}
}

func TestReconcileChainStateWithBlockStore_PropagatesCorruptCanonicalArtifact(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}

	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath)
	liveState := NewChainState()
	engine, err := NewSyncEngine(liveState, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}

	genesisParsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, genesisParsed.Header.Timestamp+1, block1Coinbase)
	if _, err := engine.ApplyBlock(block1, nil); err != nil {
		t.Fatalf("ApplyBlock(block1): %v", err)
	}

	block1Parsed, err := consensus.ParseBlockBytes(block1)
	if err != nil {
		t.Fatalf("ParseBlockBytes(block1): %v", err)
	}
	block1Hash, err := consensus.BlockHash(block1Parsed.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(block1): %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.undoDir, hex.EncodeToString(block1Hash[:])+".json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt undo): %v", err)
	}

	state := cloneChainState(liveState)
	if _, err := ReconcileChainStateWithBlockStore(state, store, cfg); err == nil {
		t.Fatalf("expected corrupt canonical artifact error")
	}

	tipHeight, tipHash, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if !ok || tipHeight != 1 || tipHash != block1Hash {
		t.Fatalf("canonical tip changed after corrupt artifact: ok=%v height=%d hash=%x", ok, tipHeight, tipHash)
	}
}

func TestTruncateIncompleteCanonicalSuffix_PropagatesIndexWriteFailure(t *testing.T) {
	dir := t.TempDir()
	store := mustOpenBlockStore(t, BlockStorePath(dir))

	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir))
	liveState := NewChainState()
	engine, err := NewSyncEngine(liveState, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}

	genesisParsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, genesisParsed.Header.Timestamp+1, block1Coinbase)
	block1Summary, err := engine.ApplyBlock(block1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(block1): %v", err)
	}
	if err := os.Remove(filepath.Join(store.undoDir, hex.EncodeToString(block1Summary.BlockHash[:])+".json")); err != nil {
		t.Fatalf("Remove(block1 undo): %v", err)
	}

	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == store.indexPath {
			return os.ErrPermission
		}
		return prevWrite(path, data, mode)
	}

	if _, err := truncateIncompleteCanonicalSuffix(store); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected truncate write failure, got %v", err)
	}
}

func TestReconcileChainStateWithBlockStore_ResetsDirtyTiplessSnapshotBeforeReplay(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}

	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath)
	expected := NewChainState()
	engine, err := NewSyncEngine(expected, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}

	dirty := NewChainState()
	dirty.AlreadyGenerated = 123456789
	var phantomTxid [32]byte
	phantomTxid[0] = 0xaa
	phantom := consensus.Outpoint{Txid: phantomTxid, Vout: 9}
	dirty.Utxos[phantom] = consensus.UtxoEntry{Value: 777}

	changed, err := ReconcileChainStateWithBlockStore(dirty, store, cfg)
	if err != nil {
		t.Fatalf("ReconcileChainStateWithBlockStore: %v", err)
	}
	if !changed {
		t.Fatalf("expected dirty tipless snapshot to be reset and replayed")
	}
	if !dirty.HasTip || dirty.Height != expected.Height || dirty.TipHash != expected.TipHash || dirty.AlreadyGenerated != expected.AlreadyGenerated {
		t.Fatalf("unexpected reconciled dirty snapshot: got has_tip=%v height=%d tip=%x generated=%d; want has_tip=%v height=%d tip=%x generated=%d",
			dirty.HasTip, dirty.Height, dirty.TipHash, dirty.AlreadyGenerated,
			expected.HasTip, expected.Height, expected.TipHash, expected.AlreadyGenerated)
	}
	if _, ok := dirty.Utxos[phantom]; ok {
		t.Fatalf("stale phantom utxo survived dirty tipless replay")
	}
	if len(dirty.Utxos) != len(expected.Utxos) {
		t.Fatalf("unexpected utxo count after dirty replay: got=%d want=%d", len(dirty.Utxos), len(expected.Utxos))
	}
}

// TestReconcileChainStateWithBlockStore_PropagatesCorruptBlockBytesSwap
// pins the cross-client re-hash defence: a parseable-but-wrong
// <hash>.bin (block 1's payload overwritten with block 2's bytes,
// which still link to b1_hash as prev_hash so chain-integrity
// inside ConnectBlock would PASS) MUST be rejected by reconcile's
// pre-replay re-hash check. Mirror of Rust
// `reconcile_propagates_corrupt_canonical_block_artifact`.
func TestReconcileChainStateWithBlockStore_PropagatesCorruptBlockBytesSwap(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}

	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath)
	liveState := NewChainState()
	engine, err := NewSyncEngine(liveState, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	genesisParsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, genesisParsed.Header.Timestamp+1, block1Coinbase)
	if _, err := engine.ApplyBlock(block1, nil); err != nil {
		t.Fatalf("ApplyBlock(block1): %v", err)
	}
	block1Parsed, err := consensus.ParseBlockBytes(block1)
	if err != nil {
		t.Fatalf("ParseBlockBytes(block1): %v", err)
	}
	block1Hash, err := consensus.BlockHash(block1Parsed.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(block1): %v", err)
	}
	// Build a second valid block at height 2 whose prev_hash is
	// block1Hash. Overwrite block 1's <hash>.bin with block 2's
	// bytes so the file is parseable, prev_hash links to the
	// current canonical tip (passes connect_block prev-hash
	// integrity), but its header hashes to block2_hash, NOT
	// block1_hash — only the re-hash check catches the swap.
	block2Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, 2)
	block2 := buildSingleTxBlock(t, block1Hash, target, block1Parsed.Header.Timestamp+1, block2Coinbase)
	block1Path := filepath.Join(store.blocksDir, hex.EncodeToString(block1Hash[:])+".bin")
	if err := os.WriteFile(block1Path, block2, 0o600); err != nil {
		t.Fatalf("overwrite block1 bytes: %v", err)
	}

	state := NewChainState()
	if _, err := state.ConnectBlockWithCoreExtProfilesAndSuiteContext(
		devnetGenesisBlockBytes, &target, nil, devnetGenesisChainID,
		cfg.CoreExtProfiles, cfg.RotationProvider, cfg.SuiteRegistry,
	); err != nil {
		t.Fatalf("seed genesis state: %v", err)
	}
	_, err = ReconcileChainStateWithBlockStore(state, store, cfg)
	if err == nil {
		t.Fatalf("expected canonical-artifact-corruption error, got nil")
	}
	want := "canonical artifact corruption during chainstate replay at height 1"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
}
