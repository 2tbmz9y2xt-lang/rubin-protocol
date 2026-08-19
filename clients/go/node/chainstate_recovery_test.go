package node

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
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
	src.AlreadyGenerated = consensus.Uint128FromU64(42)
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
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
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
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
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
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
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
	dirty.AlreadyGenerated = consensus.Uint128FromU64(99)
	dirty.TipHash[0] = 0xaa
	dirty.Utxos[consensus.Outpoint{Txid: [32]byte{0x01}, Vout: 1}] = consensus.UtxoEntry{Value: 7}
	changed, err = ReconcileChainStateWithBlockStore(dirty, store, DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("ReconcileChainStateWithBlockStore(empty dirty): %v", err)
	}
	if !changed {
		t.Fatalf("dirty empty-store snapshot must be reset")
	}
	if dirty.HasTip || dirty.Height != 0 || !dirty.AlreadyGenerated.IsZero() || dirty.TipHash != ([32]byte{}) || len(dirty.Utxos) != 0 {
		t.Fatalf("dirty empty-store snapshot not reset: %+v", dirty)
	}
}

// TestChainStateRecoveryReplayHashMessagesArePinned: verifyReplayBlockHash now
// composes its per-stage prefix from the shared identity helper. The two stages
// reachable through it must still produce the exact baseline strings — the
// third ("hash header") is defense-in-depth only: ParseBlockBytes returns
// HeaderBytes sliced to exactly BLOCK_HEADER_BYTES
// (consensus/block_basic.go:72), and the only error BlockHash returns is a
// header length other than BLOCK_HEADER_BYTES (consensus/block_parse.go:56-59).
func TestChainStateRecoveryReplayHashMessagesArePinned(t *testing.T) {
	parsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	genesisHash := mustHeaderHash(t, parsed.HeaderBytes)
	var wrong [32]byte
	wrong[0] = 0xfe
	for _, tc := range []struct {
		name  string
		bytes []byte
		hash  [32]byte
		want  string
	}{
		{
			name: "parse_failure", bytes: []byte("not a block"), hash: devnetGenesisBlockHash,
			want: "parse block bytes during chainstate replay at height 3: ",
		},
		{
			name: "identity_mismatch", bytes: devnetGenesisBlockBytes, hash: wrong,
			want: "canonical artifact corruption during chainstate replay at height 3: expected " +
				hex.EncodeToString(wrong[:]) + ", on-disk header hashes to " + hex.EncodeToString(genesisHash[:]),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyReplayBlockHash(tc.bytes, tc.hash, 3)
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("message = %v, want the prefix %q", err, tc.want)
			}
		})
	}
}

func TestChainStateRecoveryRequireCompleteCanonicalPrefixInputValidation(t *testing.T) {
	if err := requireCompleteCanonicalPrefix(nil); err == nil {
		t.Fatalf("expected nil blockstore error")
	}

	store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
	store.index.Canonical = []string{"zz"}
	err := requireCompleteCanonicalPrefix(store)
	if err == nil {
		t.Fatalf("expected malformed canonical hash error")
	}
	// A structural error keeps its own identity; it is neither fail-closed class.
	if errors.Is(err, errCanonicalIndexZeroCompletePrefix) || errors.Is(err, errCanonicalIndexIncompleteSuffix) {
		t.Fatalf("structural error must keep precedence, got %v", err)
	}
}

func TestReconcileChainStateWithBlockStore_NoopForCanonicalTipAndResetsAheadSnapshot(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
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

func TestReconcileChainStateWithBlockStorePreservesWidePersistedSupply(t *testing.T) {
	dir := t.TempDir()
	path := ChainStatePath(dir)
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, path)
	live := NewChainState()
	engine, err := NewSyncEngine(live, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	want := consensus.Uint128{Hi: 1, Lo: 7}
	live.AlreadyGenerated = want
	if err := live.Save(path); err != nil {
		t.Fatalf("Save(wide): %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}
	restarted, err := LoadChainState(path)
	if err != nil {
		t.Fatalf("LoadChainState: %v", err)
	}
	changed, err := ReconcileChainStateWithBlockStore(restarted, store, cfg)
	if err != nil {
		t.Fatalf("ReconcileChainStateWithBlockStore: %v", err)
	}
	if changed || restarted.AlreadyGenerated != want {
		t.Fatalf("recovery changed wide supply: changed=%v supply=%s", changed, restarted.AlreadyGenerated.String())
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("no-op recovery rewrote durable bytes: err=%v", err)
	}
}

// assertReconcileFailsClosed runs the reconcile over a datadir it must refuse
// and proves the refusal changed nothing: no canonical-index write reached the
// atomic lane, the index bytes are identical, the chainstate view is untouched
// and the call reports no change. It returns the error so each caller pins its
// own class and message.
func assertReconcileFailsClosed(t *testing.T, store *BlockStore, state *ChainState, cfg SyncConfig) error {
	t.Helper()
	indexBefore, stateBefore := mustReadIndexFile(t, store), state.view()
	previousWrite := writeFileAtomicFn
	writes := 0
	withWriteFileAtomicFn(t, func(path string, data []byte, mode os.FileMode) error {
		writes++
		return previousWrite(path, data, mode)
	})

	changed, err := ReconcileChainStateWithBlockStore(state, store, cfg)
	if err == nil {
		t.Fatalf("committed canonical corruption must fail closed")
	}
	if changed {
		t.Fatalf("a refused recovery must report no change")
	}
	if writes != 0 {
		t.Fatalf("fail-closed recovery performed %d canonical-index writes, want 0", writes)
	}
	if !bytes.Equal(mustReadIndexFile(t, store), indexBefore) {
		t.Fatalf("canonical index bytes changed on the fail-closed path")
	}
	if after := state.view(); after != stateBefore {
		t.Fatalf("chainstate mutated before the refusal: %+v -> %+v", stateBefore, after)
	}
	return err
}

// TestChainStateRecoveryIncompleteCanonicalSuffixIsFatal: a committed canonical
// row whose undo record is gone is corruption of committed chain, not garbage to
// drop. Recovery refuses and never reaches any service start.
func TestChainStateRecoveryIncompleteCanonicalSuffixIsFatal(t *testing.T) {
	dir := t.TempDir()
	store, liveState, cfg := storeAtGenesis(t, dir)
	block1Hash := appendCanonicalBlock(t, store, liveState, cfg)
	if err := os.Remove(filepath.Join(store.undoDir, hex.EncodeToString(block1Hash[:])+".json")); err != nil {
		t.Fatalf("Remove(block1 undo): %v", err)
	}

	err := assertReconcileFailsClosed(t, store, cloneChainState(liveState), cfg)
	if !errors.Is(err, errCanonicalIndexIncompleteSuffix) {
		t.Fatalf("reconcile err = %v, want errCanonicalIndexIncompleteSuffix", err)
	}
	if want := "index declares 2 entries; the complete header/block/undo prefix ends after 1; datadir reset and full resync required"; !strings.Contains(err.Error(), want) {
		t.Fatalf("message = %q, want it to contain %q", err.Error(), want)
	}
	tipHeight, tipHash, ok, tipErr := store.Tip()
	if tipErr != nil || !ok || tipHeight != 1 || tipHash != block1Hash {
		t.Fatalf("canonical tip moved: ok=%v height=%d hash=%x err=%v", ok, tipHeight, tipHash, tipErr)
	}
}

func TestReconcileChainStateWithBlockStore_PropagatesCorruptCanonicalArtifact(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
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

func TestReconcileChainStateWithBlockStore_ResetsDirtyTiplessSnapshotBeforeReplay(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
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
	dirty.AlreadyGenerated = consensus.Uint128FromU64(123456789)
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
// pins the cross-client re-hash defense: a parseable-but-wrong
// <hash>.bin (block 1's payload overwritten with block 2's bytes,
// which still link to b1_hash as prev_hash so chain-integrity
// inside ConnectBlock would PASS) MUST be rejected before any state
// changes. Mirror of Rust
// `reconcile_propagates_corrupt_canonical_block_artifact`.
//
// Go-primary divergence (RUB-890, sibling RUB-897): the STRICT canonical
// artifact check now catches this swap in the complete-prefix scan, ahead of
// replay, so the message is the artifact one rather than the replay one — a
// strictly earlier refusal on the same input. Replay's own re-hash defense is
// unchanged and still pinned by
// TestChainStateRecoveryReplayHashMessagesArePinned.
func TestReconcileChainStateWithBlockStore_PropagatesCorruptBlockBytesSwap(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
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
	// block1_hash — only an identity re-hash catches the swap; since
	// RUB-890 the startup scan performs it before replay.
	block2Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, 2)
	block2 := buildSingleTxBlock(t, block1Hash, target, block1Parsed.Header.Timestamp+1, block2Coinbase)
	block1Path := filepath.Join(store.blocksDir, hex.EncodeToString(block1Hash[:])+".bin")
	if err := os.WriteFile(block1Path, block2, 0o600); err != nil {
		t.Fatalf("overwrite block1 bytes: %v", err)
	}

	state := NewChainState()
	if _, err := state.ConnectBlockWithSuiteContext(
		devnetGenesisBlockBytes, &target, nil, devnetGenesisChainID,
		cfg.RotationProvider, cfg.SuiteRegistry,
	); err != nil {
		t.Fatalf("seed genesis state: %v", err)
	}
	_, err = ReconcileChainStateWithBlockStore(state, store, cfg)
	if err == nil {
		t.Fatalf("expected canonical-artifact-corruption error, got nil")
	}
	if errors.Is(err, errCanonicalIndexZeroCompletePrefix) || errors.Is(err, errCanonicalIndexIncompleteSuffix) {
		t.Fatalf("a corrupt artifact must keep structural precedence, got %v", err)
	}
	if !errors.Is(err, errCanonicalArtifactUnbound) {
		t.Fatalf("refusal = %v, want it to carry errCanonicalArtifactUnbound", err)
	}
	want := "canonical block artifact " + hex.EncodeToString(block1Hash[:]) + ": " +
		errCanonicalArtifactUnbound.Error() + ": hashes to "
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
}

// storeAtGenesis returns a fresh store holding the canonical devnet genesis at
// height 0, plus the live chainstate and the sync config used to build it.
func storeAtGenesis(t *testing.T, dir string) (*BlockStore, *ChainState, SyncConfig) {
	t.Helper()
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir))
	state := NewChainState()
	engine, err := NewSyncEngine(state, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	return store, state, cfg
}

// B2 rules 5-6 + parity matrix row 12: a canonical index that claims blocks but
// has NO complete artifact set at height 0 is fatal. The guard fires before any
// index write and before any chainstate reset/save, carrying the exact
// cross-client literal as its message prefix. Rust mirror:
// `zero_complete_canonical_prefix_is_fatal_before_any_mutation`.
func TestReconcileZeroCompleteCanonicalPrefixIsFatal(t *testing.T) {
	dir := t.TempDir()
	store, liveState, cfg := storeAtGenesis(t, dir)
	if err := os.Remove(filepath.Join(store.headersDir, hex.EncodeToString(devnetGenesisBlockHash[:])+".bin")); err != nil {
		t.Fatalf("Remove(genesis header): %v", err)
	}

	err := assertReconcileFailsClosed(t, store, cloneChainState(liveState), cfg)
	if !errors.Is(err, errCanonicalIndexZeroCompletePrefix) {
		t.Fatalf("reconcile err = %v, want errCanonicalIndexZeroCompletePrefix", err)
	}
	if got, want := err.Error(), "persisted canonical index has zero complete prefix: datadir reset and full resync required"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
	if got, snapErr := store.CanonicalIndexSnapshot(); snapErr != nil || len(got) != 1 {
		t.Fatalf("canonical index = %v (%v), want length 1", got, snapErr)
	}
}

// TestChainStateRecoveryStrictArtifactsRejectPresentButUnboundFiles: startup
// must be STRICT, not merely present-file counting. A header, block or undo
// file that EXISTS but is not bound to the indexed hash is committed-canonical
// corruption: it is a structural error (first precedence, like the corrupt-undo
// path), never an absent artifact that would degrade into the zero-prefix or
// incomplete-suffix class, and it is never truncated or repaired. The chainstate
// is already at the tip here, so no replay runs — only the strict prefix check
// can catch it.
func TestChainStateRecoveryStrictArtifactsRejectPresentButUnboundFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		// wantIs is the typed identity the refusal must carry: unbound
		// header/block artifacts are the Go-only errCanonicalArtifactUnbound
		// class, undo keeps its own cross-client ErrUndoIntegrity.
		wantIs  error
		corrupt func(t *testing.T, store *BlockStore, otherBlock []byte, otherHeader []byte)
	}{
		{
			name:   "header_of_another_block",
			wantIs: errCanonicalArtifactUnbound,
			corrupt: func(t *testing.T, store *BlockStore, _ []byte, otherHeader []byte) {
				plantCanonicalArtifact(t, store.headersDir, devnetGenesisBlockHash, otherHeader)
			},
		},
		{
			// Length is validateBlockHeaderHash's other leg: an emptied file
			// is the residue closest to absence — present, inside the size
			// bound, zero bytes — and still an identity failure, not a gap.
			name:   "header_emptied_to_zero_bytes",
			wantIs: errCanonicalArtifactUnbound,
			corrupt: func(t *testing.T, store *BlockStore, _ []byte, _ []byte) {
				plantCanonicalArtifact(t, store.headersDir, devnetGenesisBlockHash, nil)
			},
		},
		{
			name:   "block_bytes_of_another_block",
			wantIs: errCanonicalArtifactUnbound,
			corrupt: func(t *testing.T, store *BlockStore, otherBlock []byte, _ []byte) {
				plantCanonicalArtifact(t, store.blocksDir, devnetGenesisBlockHash, otherBlock)
			},
		},
		{
			name:   "unparseable_block_bytes",
			wantIs: errCanonicalArtifactUnbound,
			corrupt: func(t *testing.T, store *BlockStore, _ []byte, _ []byte) {
				plantCanonicalArtifact(t, store.blocksDir, devnetGenesisBlockHash, []byte("not a block"))
			},
		},
		{
			// A read-class refusal (the RUB-1057 size bound): neither absence
			// nor an identity failure, so it carries neither sentinel.
			name:   "header_over_the_size_bound",
			wantIs: errStoreFileTooLarge,
			corrupt: func(t *testing.T, store *BlockStore, _ []byte, _ []byte) {
				plantCanonicalArtifact(t, store.headersDir, devnetGenesisBlockHash, make([]byte, headerFileMaxBytes+1))
			},
		},
		{
			name:   "undecodable_undo_record",
			wantIs: ErrUndoIntegrity,
			corrupt: func(t *testing.T, store *BlockStore, _ []byte, _ []byte) {
				mustWriteFile(t, filepath.Join(store.undoDir,
					hex.EncodeToString(devnetGenesisBlockHash[:])+".json"), []byte("not json"))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, liveState, cfg := storeAtGenesis(t, dir)
			otherBlock, otherHeader := anotherDevnetBlock(t, *cfg.ExpectedTarget)
			tc.corrupt(t, store, otherBlock, otherHeader)

			err := assertReconcileFailsClosed(t, store, cloneChainState(liveState), cfg)
			if errors.Is(err, errCanonicalIndexZeroCompletePrefix) || errors.Is(err, errCanonicalIndexIncompleteSuffix) {
				t.Fatalf("structural error must keep precedence, got %v", err)
			}
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("refusal = %v, want it to carry %v", err, tc.wantIs)
			}
			if errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refusal = %v, want a structural error rather than absence", err)
			}
			if wantUnbound := errors.Is(tc.wantIs, errCanonicalArtifactUnbound); errors.Is(err, errCanonicalArtifactUnbound) != wantUnbound {
				t.Fatalf("refusal = %v, want the unbound identity present=%v", err, wantUnbound)
			}
			// The operator sees this as "chainstate reconcile failed: <err>":
			// every leaf must name the canonical row it condemns, or the
			// message identifies no artifact at all.
			if !strings.Contains(err.Error(), hex.EncodeToString(devnetGenesisBlockHash[:])) {
				t.Fatalf("refusal must name the corrupt canonical row: %v", err)
			}
		})
	}
}

// anotherDevnetBlock builds a second valid devnet block: its bytes parse and its
// header hashes, but to a DIFFERENT identity than genesis — the strongest
// "present but not bound" spelling.
func anotherDevnetBlock(t *testing.T, target [32]byte) (blockBytes []byte, headerBytes []byte) {
	t.Helper()
	genesis, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	other := buildSingleTxBlock(t, devnetGenesisBlockHash, target, genesis.Header.Timestamp+1,
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1))
	parsed, err := consensus.ParseBlockBytes(other)
	if err != nil {
		t.Fatalf("ParseBlockBytes(other): %v", err)
	}
	return other, parsed.HeaderBytes
}

func plantCanonicalArtifact(t *testing.T, dir string, blockHash [32]byte, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, hex.EncodeToString(blockHash[:])+".bin"), content, 0o600); err != nil {
		t.Fatalf("plant artifact: %v", err)
	}
}

// B2 rule 3: a structural/corruption error keeps its ORIGINAL error and wins
// over the zero-prefix guard even though the complete prefix is also zero. Rust
// mirror: `zero_complete_canonical_prefix_loses_to_artifact_error`.
func TestReconcileZeroCompletePrefixLosesToArtifactError(t *testing.T) {
	dir := t.TempDir()
	store, liveState, cfg := storeAtGenesis(t, dir)
	undo := filepath.Join(store.undoDir, hex.EncodeToString(devnetGenesisBlockHash[:])+".json")
	if err := os.WriteFile(undo, []byte("not json"), 0o600); err != nil {
		t.Fatalf("corrupt undo: %v", err)
	}
	_, err := ReconcileChainStateWithBlockStore(cloneChainState(liveState), store, cfg)
	if err == nil {
		t.Fatalf("corrupt artifact must fail")
	}
	if errors.Is(err, errCanonicalIndexZeroCompletePrefix) {
		t.Fatalf("structural error must win over the zero-prefix guard, got %v", err)
	}
}

// TestChainStateRecoveryStructuralErrorWinsAcrossTheWholeIndex: the prefix check
// is a FULL scan of the declared index, not a stop-at-the-first-gap scan. A
// structural/corruption error anywhere in the index outranks both fail-closed
// classes, even when it sits behind an absent artifact of the same row (a) or
// behind an already-incomplete row (b). Stopping earlier would report committed
// corruption as the zero-prefix or incomplete-suffix class and send the operator
// after the wrong file. Rows (c) and (d) pin the ORDER inside one row: with two
// artifacts unbound, the refusal names the earlier kind in the fixed
// header -> block -> undo order, so reordering it renames the condemned file.
func TestChainStateRecoveryStructuralErrorWinsAcrossTheWholeIndex(t *testing.T) {
	for _, tc := range []struct {
		name string
		// corrupt plants the corruption and returns the artifact clause the
		// refusal must name.
		corrupt func(t *testing.T, store *BlockStore, live *ChainState, cfg SyncConfig) string
	}{
		{
			// Row 0 header ABSENT, row 0 block bound to another identity: a
			// scan that stops at the first absent artifact of a row never
			// reads the block and reports zero-complete-prefix.
			name: "later_artifact_of_the_same_row",
			corrupt: func(t *testing.T, store *BlockStore, _ *ChainState, cfg SyncConfig) string {
				otherBlock, _ := anotherDevnetBlock(t, *cfg.ExpectedTarget)
				if err := os.Remove(filepath.Join(store.headersDir,
					hex.EncodeToString(devnetGenesisBlockHash[:])+".bin")); err != nil {
					t.Fatalf("Remove(genesis header): %v", err)
				}
				plantCanonicalArtifact(t, store.blocksDir, devnetGenesisBlockHash, otherBlock)
				return "canonical block artifact " + hex.EncodeToString(devnetGenesisBlockHash[:])
			},
		},
		{
			// Row 1 incomplete (undo gone), row 2 header bound to another
			// identity: a scan that stops at the first incomplete ROW never
			// reads row 2 and reports incomplete-suffix.
			name: "row_after_the_first_incomplete_row",
			corrupt: func(t *testing.T, store *BlockStore, live *ChainState, cfg SyncConfig) string {
				block1Hash := appendCanonicalBlock(t, store, live, cfg)
				block2Hash := appendCanonicalBlock(t, store, live, cfg)
				_, otherHeader := anotherDevnetBlock(t, *cfg.ExpectedTarget)
				if err := os.Remove(filepath.Join(store.undoDir,
					hex.EncodeToString(block1Hash[:])+".json")); err != nil {
					t.Fatalf("Remove(block1 undo): %v", err)
				}
				plantCanonicalArtifact(t, store.headersDir, block2Hash, otherHeader)
				return "canonical header artifact " + hex.EncodeToString(block2Hash[:])
			},
		},
		{
			// Row 0 header AND block both unbound: the fixed header -> block
			// -> undo order is what decides which artifact the refusal names,
			// so a reordered table renames the condemned file.
			name: "first_artifact_of_a_row_in_the_fixed_order",
			corrupt: func(t *testing.T, store *BlockStore, _ *ChainState, cfg SyncConfig) string {
				otherBlock, otherHeader := anotherDevnetBlock(t, *cfg.ExpectedTarget)
				plantCanonicalArtifact(t, store.headersDir, devnetGenesisBlockHash, otherHeader)
				plantCanonicalArtifact(t, store.blocksDir, devnetGenesisBlockHash, otherBlock)
				return "canonical header artifact " + hex.EncodeToString(devnetGenesisBlockHash[:])
			},
		},
		{
			// Row 0 block AND undo both unbound, header intact: the same fixed
			// order one rung lower, so the refusal names the block.
			name: "block_before_undo_in_the_fixed_order",
			corrupt: func(t *testing.T, store *BlockStore, _ *ChainState, cfg SyncConfig) string {
				otherBlock, _ := anotherDevnetBlock(t, *cfg.ExpectedTarget)
				plantCanonicalArtifact(t, store.blocksDir, devnetGenesisBlockHash, otherBlock)
				mustWriteFile(t, filepath.Join(store.undoDir,
					hex.EncodeToString(devnetGenesisBlockHash[:])+".json"), []byte("not json"))
				return "canonical block artifact " + hex.EncodeToString(devnetGenesisBlockHash[:])
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, liveState, cfg := storeAtGenesis(t, dir)
			want := tc.corrupt(t, store, liveState, cfg)

			err := assertReconcileFailsClosed(t, store, cloneChainState(liveState), cfg)
			if errors.Is(err, errCanonicalIndexZeroCompletePrefix) || errors.Is(err, errCanonicalIndexIncompleteSuffix) {
				t.Fatalf("structural error must win over both fail-closed classes, got %v", err)
			}
			if !errors.Is(err, errCanonicalArtifactUnbound) {
				t.Fatalf("refusal = %v, want it to carry errCanonicalArtifactUnbound", err)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("refusal = %v, want it to name %q", err, want)
			}
		})
	}
}

// TestChainStateRecoveryRejectsBrokenCanonicalLinkage: spec §6.4.1 requires
// every later header's prev_block_hash to equal the PRECEDING INDEXED hash. A
// spliced index can satisfy every identity rule — all twelve artifacts present
// and hash-bound — and still describe a chain that was never built, so only the
// linkage rule refuses it. The snapshot sits AT the spliced tip here, so the
// replay step never runs and the prefix scan is the only defense left.
func TestChainStateRecoveryRejectsBrokenCanonicalLinkage(t *testing.T) {
	for _, tc := range []struct {
		name string
		// incomplete drops those spliced rows' undo records; corruptBlock
		// unbinds row 2's block. Linkage is structural, so it outranks the
		// incomplete-suffix class whether the gap sits before the offending row
		// or IS that row; within a row the artifact scan runs first, so an
		// unbound block outranks that row's own linkage violation.
		incomplete   []int
		corruptBlock bool
	}{
		{name: "every_artifact_bound"},
		{name: "linkage_outranks_an_earlier_incomplete_row", incomplete: []int{1}},
		{name: "linkage_outranks_the_offending_rows_own_incompleteness", incomplete: []int{2}},
		{name: "an_unbound_block_outranks_that_rows_linkage", corruptBlock: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, liveState, cfg := storeAtGenesis(t, dir)
			block1 := appendCanonicalBlock(t, store, liveState, cfg)
			block2 := appendCanonicalBlock(t, store, liveState, cfg)
			block3 := appendCanonicalBlock(t, store, liveState, cfg)
			// [g, b1, b3, b2]: row 2's header links to b2, but the preceding
			// INDEXED hash is b1. Every row keeps all three bound artifacts.
			spliced := []string{
				hex.EncodeToString(devnetGenesisBlockHash[:]),
				hex.EncodeToString(block1[:]),
				hex.EncodeToString(block3[:]),
				hex.EncodeToString(block2[:]),
			}
			if err := store.RestoreCanonicalIndex(spliced); err != nil {
				t.Fatalf("RestoreCanonicalIndex: %v", err)
			}
			for _, row := range tc.incomplete {
				if err := os.Remove(filepath.Join(store.undoDir, spliced[row]+".json")); err != nil {
					t.Fatalf("Remove(row %d undo): %v", row, err)
				}
			}
			if tc.corruptBlock {
				plantCanonicalArtifact(t, store.blocksDir, block3, []byte("not a block"))
			}

			// The snapshot matches the spliced tip, so no replay is scheduled.
			atTip := cloneChainState(liveState)
			atTip.Height, atTip.TipHash = 3, block2
			if _, _, replayNeeded, rerr := reconcileReplayStart(cloneChainState(atTip), store, 3); rerr != nil || replayNeeded {
				t.Fatalf("replay start: needed=%v err=%v, want no replay to run", replayNeeded, rerr)
			}

			err := assertReconcileFailsClosed(t, store, atTip, cfg)
			if errors.Is(err, errCanonicalIndexZeroCompletePrefix) || errors.Is(err, errCanonicalIndexIncompleteSuffix) {
				t.Fatalf("linkage is structural and must outrank both fail-closed classes, got %v", err)
			}
			if !errors.Is(err, errCanonicalArtifactUnbound) {
				t.Fatalf("refusal = %v, want it to carry errCanonicalArtifactUnbound", err)
			}
			want := fmt.Sprintf("canonical header artifact %x links to %x, expected %x", block3, block2, block1)
			if tc.corruptBlock {
				want = fmt.Sprintf("canonical block artifact %x", block3)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("refusal = %v, want it to contain %q", err, want)
			}
		})
	}
}

// TestChainStateRecoveryCompletePrefixEndsAtTheFirstIncompleteRow: the complete
// prefix ends at the FIRST incomplete row, never at the last one. Recording the
// last would claim a longer proven prefix than the store holds (i) and would
// hide a zero-length prefix behind a later complete row (ii).
func TestChainStateRecoveryCompletePrefixEndsAtTheFirstIncompleteRow(t *testing.T) {
	for _, tc := range []struct {
		name       string
		incomplete []int
		// headerless removes the row's HEADER instead of its undo: the row is
		// incomplete, but its INDEXED hash still anchors the next row's linkage.
		headerless []int
		wantErr    error
		wantMsg    string
	}{
		{
			name: "first_of_two_incomplete_rows", incomplete: []int{1, 2},
			wantErr: errCanonicalIndexIncompleteSuffix,
			wantMsg: "index declares 3 entries; the complete header/block/undo prefix ends after 1",
		},
		{
			name: "incomplete_row_zero_behind_a_complete_row", incomplete: []int{0, 2},
			wantErr: errCanonicalIndexZeroCompletePrefix,
			wantMsg: "persisted canonical index has zero complete prefix",
		},
		{
			name: "absent_header_still_anchors_the_next_rows_linkage", headerless: []int{1},
			wantErr: errCanonicalIndexIncompleteSuffix,
			wantMsg: "index declares 3 entries; the complete header/block/undo prefix ends after 1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, liveState, cfg := storeAtGenesis(t, dir)
			rows := [][32]byte{
				devnetGenesisBlockHash,
				appendCanonicalBlock(t, store, liveState, cfg),
				appendCanonicalBlock(t, store, liveState, cfg),
			}
			for _, row := range tc.incomplete {
				if err := os.Remove(filepath.Join(store.undoDir, hex.EncodeToString(rows[row][:])+".json")); err != nil {
					t.Fatalf("Remove(row %d undo): %v", row, err)
				}
			}
			for _, row := range tc.headerless {
				if err := os.Remove(filepath.Join(store.headersDir, hex.EncodeToString(rows[row][:])+".bin")); err != nil {
					t.Fatalf("Remove(row %d header): %v", row, err)
				}
			}
			err := assertReconcileFailsClosed(t, store, cloneChainState(liveState), cfg)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("reconcile err = %v, want %v", err, tc.wantErr)
			}
			if errors.Is(err, errCanonicalArtifactUnbound) {
				t.Fatalf("an absent artifact is not a binding failure: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("message = %q, want it to contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}
