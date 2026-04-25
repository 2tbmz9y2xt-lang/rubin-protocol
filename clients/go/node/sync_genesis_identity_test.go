package node

import (
	"context"
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// assertGenesisHashMismatchTxError verifies that err is a *consensus.TxError
// with code BLOCK_ERR_LINKAGE_INVALID and message "genesis_hash mismatch".
// The TxError wrap is what clients/go/node/p2p/handlers_block.go relies on
// to escalate ban score for peers relaying wrong-genesis blocks: that file
// uses the standard `var txErr *consensus.TxError; errors.As(err, &txErr)`
// pattern. Checking the wrap-and-fields here pins the exact contract the
// P2P inbound block path consumes.
func assertGenesisHashMismatchTxError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected genesis_hash mismatch TxError, got nil")
	}
	var txErr *consensus.TxError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected *consensus.TxError, got %T: %v", err, err)
	}
	if txErr.Code != consensus.BLOCK_ERR_LINKAGE_INVALID {
		t.Fatalf("expected code %s, got %s", consensus.BLOCK_ERR_LINKAGE_INVALID, txErr.Code)
	}
	if txErr.Msg != "genesis_hash mismatch" {
		t.Fatalf("expected msg %q, got %q", "genesis_hash mismatch", txErr.Msg)
	}
}

// isGenesisHashMismatchTxError reports whether err is the genesis_hash
// TxError emitted by applyCanonicalParsedBlock. Used by the zero-ChainID
// skip test to assert the negative shape (this specific TxError must NOT
// fire) without constraining the unrelated downstream consensus error a
// mutated block may produce in test mode.
func isGenesisHashMismatchTxError(err error) bool {
	if err == nil {
		return false
	}
	var txErr *consensus.TxError
	if !errors.As(err, &txErr) {
		return false
	}
	return txErr.Code == consensus.BLOCK_ERR_LINKAGE_INVALID && txErr.Msg == "genesis_hash mismatch"
}

// newGenesisIdentityTestEngine builds the minimal SyncEngine fixture used by
// the height-0 genesis-identity guard tests: empty chainstate, blockstore in
// a t.TempDir, POW_LIMIT target, and the caller-supplied ChainID. The
// caller-supplied ChainID picks the runtime mode under test:
//   - DevnetGenesisChainID() exercises the production devnet path where the
//     new genesis-hash guard MUST fire on a non-canonical height-0 block.
//   - the all-zero ChainID exercises the long-standing test-mode skip path
//     that the existing chain_id guard already honors and that the new
//     genesis-hash guard mirrors.
func newGenesisIdentityTestEngine(t *testing.T, chainID [32]byte) *SyncEngine {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	st := NewChainState()
	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, chainID, ChainStatePath(dir))
	engine, err := NewSyncEngine(st, store, cfg)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	return engine
}

// mutatedDevnetGenesisBlock returns the published devnet genesis block
// bytes with one byte flipped in the header nonce field. The header layout
// (consensus.BlockHeader, BLOCK_HEADER_BYTES = 116) is:
//
//	bytes 0..4     Version (uint32 little-endian)
//	bytes 4..36    PrevBlockHash
//	bytes 36..68   MerkleRoot
//	bytes 68..76   Timestamp
//	bytes 76..108  Target
//	bytes 108..116 Nonce
//
// Flipping a nonce byte changes the SHA-derived block hash without
// disturbing PrevBlockHash (so applyDirectBlockIfPossible's empty-chain
// branch in sync_reorg.go still admits the block at the linkage layer)
// and without disturbing MerkleRoot or Target (defense in depth: the
// height-0 genesis-hash guard fires in applyCanonicalParsedBlock before
// the chain ever reaches ConnectBlock-side merkle, expected_target, and
// PoW validation, but preserving these fields keeps the test focused
// on the guard even if future changes reorder the validation pipeline).
// The chain_id guard at the same call site reads cfg.ChainID, not the
// header, so it is unaffected by any header-byte mutation. This is the
// same shape a malformed or maliciously relayed peer block would take
// when probing whether a freshly started node will accept any zero-prev
// block as its genesis.
//
// DevnetGenesisBlockBytes() already returns a defensive copy, so we mutate
// it directly. The nonce field is the last 8 bytes of the header, derived
// from consensus.BLOCK_HEADER_BYTES rather than hard-coded so the test
// stays correct if the header layout grows additional trailing fields.
func mutatedDevnetGenesisBlock() []byte {
	wrong := DevnetGenesisBlockBytes()
	wrong[consensus.BLOCK_HEADER_BYTES-8] ^= 0xFF
	return wrong
}

// TestSyncEngineApplyBlock_AcceptsCanonicalDevnetGenesisAtHeight0 is the
// regression for the happy path. The new guard must NOT block the published
// devnet genesis bytes; if it does, devnet boot itself breaks.
func TestSyncEngineApplyBlock_AcceptsCanonicalDevnetGenesisAtHeight0(t *testing.T) {
	engine := newGenesisIdentityTestEngine(t, DevnetGenesisChainID())
	if _, err := engine.ApplyBlock(DevnetGenesisBlockBytes(), nil); err != nil {
		t.Fatalf("apply canonical devnet genesis: %v", err)
	}
}

// TestSyncEngineApplyBlock_RejectsWrongDevnetGenesisAtHeight0 covers the
// canonical attack vector named in the task acceptance criterion: an
// arbitrary block whose chain_id matches devnet and whose prev_block_hash is
// zero, yet whose contents differ from the published devnet genesis. The
// runtime guard MUST reject it at admission instead of locking the local
// chainstate onto a wrong identity.
func TestSyncEngineApplyBlock_RejectsWrongDevnetGenesisAtHeight0(t *testing.T) {
	engine := newGenesisIdentityTestEngine(t, DevnetGenesisChainID())
	_, err := engine.ApplyBlock(mutatedDevnetGenesisBlock(), nil)
	assertGenesisHashMismatchTxError(t, err)
}

// TestSyncEngineApplyBlockWithReorg_RejectsWrongDevnetGenesisAtHeight0 is
// the P2P-path counterpart of the previous test. The acceptance criterion
// explicitly requires "P2P-relayed wrong genesis cannot become local
// genesis"; ApplyBlockWithReorg is the entrypoint exercised by the inbound
// block path (peer_runtime.go calls it for every block message).
func TestSyncEngineApplyBlockWithReorg_RejectsWrongDevnetGenesisAtHeight0(t *testing.T) {
	engine := newGenesisIdentityTestEngine(t, DevnetGenesisChainID())
	_, err := engine.ApplyBlockWithReorg(mutatedDevnetGenesisBlock(), nil)
	assertGenesisHashMismatchTxError(t, err)
}

// TestSyncEngineApplyBlock_GenesisHashGuard_SkipsWhenChainIDZero pins the
// test-mode skip clause. The existing chain_id guard at the same site has
// always been a no-op when cfg.ChainID is zero so unit tests can build
// minimal SyncEngine fixtures without wiring a full devnet identity. The
// new genesis-hash guard mirrors that contract: with a zero ChainID it must
// not surface "genesis_hash mismatch", regardless of the block hash.
//
// We assert via the negative shape — the error, if any, must NOT be the
// new guard's specific error string. The mutated block may still fail
// further down in consensus connect; that downstream behavior is not what
// this test pins, so we only refute the new guard firing.
func TestSyncEngineApplyBlock_GenesisHashGuard_SkipsWhenChainIDZero(t *testing.T) {
	var zeroChainID [32]byte
	engine := newGenesisIdentityTestEngine(t, zeroChainID)
	_, err := engine.ApplyBlock(mutatedDevnetGenesisBlock(), nil)
	if isGenesisHashMismatchTxError(err) {
		t.Fatalf("genesis hash guard fired in zero-ChainID test mode: must skip to mirror chain_id guard pattern")
	}
}

// TestSyncEngineBootstrapCanonicalGenesisIfEmpty_DevnetImports verifies that
// the bootstrap helper applies the published devnet genesis bytes to an
// empty chainstate under a devnet ChainID, leaving the tip at the canonical
// devnet genesis hash and height 0. This is the production path that lets
// miner-driven empty-chain mining produce a valid first post-genesis block
// without tripping the height-0 genesis-identity guard.
func TestSyncEngineBootstrapCanonicalGenesisIfEmpty_DevnetImports(t *testing.T) {
	engine := newGenesisIdentityTestEngine(t, DevnetGenesisChainID())
	if err := engine.BootstrapCanonicalGenesisIfEmpty(); err != nil {
		t.Fatalf("bootstrap canonical genesis: %v", err)
	}
	view := engine.chainState.view()
	if !view.hasTip {
		t.Fatal("chainstate must have a tip after bootstrap")
	}
	if view.height != 0 {
		t.Fatalf("expected height 0, got %d", view.height)
	}
	if view.tipHash != DevnetGenesisBlockHash() {
		t.Fatalf("tip hash must equal published devnet genesis hash")
	}
}

// TestSyncEngineBootstrapCanonicalGenesisIfEmpty_NoOpWithZeroChainID pins
// the test-mode skip path. With the all-zero ChainID — the convention used
// by ephemeral unit tests that don't want a full devnet identity — the
// bootstrap MUST be a no-op so those tests' synthetic-genesis fixtures
// keep working. This mirrors the same skip clause the genesis-hash guard
// uses (see TestSyncEngineApplyBlock_GenesisHashGuard_SkipsWhenChainIDZero).
func TestSyncEngineBootstrapCanonicalGenesisIfEmpty_NoOpWithZeroChainID(t *testing.T) {
	var zeroChainID [32]byte
	engine := newGenesisIdentityTestEngine(t, zeroChainID)
	if err := engine.BootstrapCanonicalGenesisIfEmpty(); err != nil {
		t.Fatalf("bootstrap on zero ChainID must be a no-op, got error: %v", err)
	}
	view := engine.chainState.view()
	if view.hasTip {
		t.Fatal("zero-ChainID bootstrap must NOT install a tip; chainstate must remain empty for synthetic-genesis test fixtures")
	}
}

// TestSyncEngineBootstrapCanonicalGenesisIfEmpty_IdempotentAfterTip pins
// idempotency: once the chain has any tip, calling the helper again must
// not re-apply the genesis or otherwise mutate the chainstate. Idempotency
// matters because Miner.MineOne calls the helper on every invocation; if
// it weren't idempotent, the second mining call would attempt to re-apply
// the genesis on top of the existing tip and fail on linkage.
func TestSyncEngineBootstrapCanonicalGenesisIfEmpty_IdempotentAfterTip(t *testing.T) {
	engine := newGenesisIdentityTestEngine(t, DevnetGenesisChainID())
	if err := engine.BootstrapCanonicalGenesisIfEmpty(); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	tipBefore := engine.chainState.view().tipHash
	if err := engine.BootstrapCanonicalGenesisIfEmpty(); err != nil {
		t.Fatalf("second bootstrap (must be a no-op): %v", err)
	}
	tipAfter := engine.chainState.view().tipHash
	if tipBefore != tipAfter {
		t.Fatalf("tip mutated by no-op bootstrap call: before=%x after=%x", tipBefore, tipAfter)
	}
}

// TestSyncEngineBootstrapCanonicalGenesisIfEmpty_NilReceiver pins the
// nil-receiver branch of the helper. The method is reachable from a nil
// pointer because Go allows method calls on nil receivers when the method
// itself checks for nil; the standard nil-safe contract used by other
// exported SyncEngine methods (HeaderSyncRequest, RecordBestKnownHeight,
// BestKnownHeight, LastReorgDepth) is what this test pins.
func TestSyncEngineBootstrapCanonicalGenesisIfEmpty_NilReceiver(t *testing.T) {
	var s *SyncEngine
	err := s.BootstrapCanonicalGenesisIfEmpty()
	if err == nil {
		t.Fatal("expected error on nil receiver")
	}
	if err.Error() != "sync engine is not initialized" {
		t.Fatalf("expected %q, got %q", "sync engine is not initialized", err.Error())
	}
}

// TestSyncEngineBootstrapCanonicalGenesisIfEmpty_NilChainState pins the
// second disjunct of the nil-guard. After a SyncEngine is constructed via
// NewSyncEngine its chainState is non-nil (constructor rejects nil), but
// runtime state corruption could leave the field nil. The helper must
// surface the same explicit error class instead of panicking.
func TestSyncEngineBootstrapCanonicalGenesisIfEmpty_NilChainState(t *testing.T) {
	engine := newGenesisIdentityTestEngine(t, DevnetGenesisChainID())
	engine.chainState = nil
	err := engine.BootstrapCanonicalGenesisIfEmpty()
	if err == nil {
		t.Fatal("expected error on nil chainState")
	}
	if err.Error() != "sync engine is not initialized" {
		t.Fatalf("expected %q, got %q", "sync engine is not initialized", err.Error())
	}
}

// newAliasingTestPair builds a SyncEngine plus a fresh ChainState that does
// NOT alias the engine's internal chainState. Returned values are intended
// for NewMiner mismatched-aliasing tests: the caller passes the standalone
// ChainState as the miner's chainState argument while the SyncEngine still
// holds its own different ChainState.
func newAliasingTestPair(t *testing.T, chainID [32]byte) (*SyncEngine, *ChainState, *BlockStore) {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	engineState := NewChainState()
	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, chainID, ChainStatePath(dir))
	engine, err := NewSyncEngine(engineState, store, cfg)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	otherState := NewChainState()
	return engine, otherState, store
}

// TestNewMiner_RejectsMismatchedChainState pins the chainState aliasing
// guard. NewMiner must refuse construction when chainState != sync.chainState
// because Miner.MineOne's bootstrap call mutates sync.chainState; if the
// miner reads from a different ChainState the bootstrap mutation never
// reaches the snapshot used by buildBlock.
func TestNewMiner_RejectsMismatchedChainState(t *testing.T) {
	engine, otherState, store := newAliasingTestPair(t, DevnetGenesisChainID())
	_, err := NewMiner(otherState, store, engine, DefaultMinerConfig())
	if err == nil {
		t.Fatal("expected error on mismatched chainState")
	}
	if err.Error() != "miner chainstate must alias sync engine chainstate" {
		t.Fatalf("expected %q, got %q", "miner chainstate must alias sync engine chainstate", err.Error())
	}
}

// TestNewMiner_RejectsMismatchedBlockStore pins the symmetric blockStore
// aliasing guard. NewMiner must refuse construction when blockStore !=
// sync.blockStore; otherwise BootstrapCanonicalGenesisIfEmpty would persist
// the canonical genesis through sync.blockStore while buildBlock reads
// timestamp context from the miner's separate blockStore.
func TestNewMiner_RejectsMismatchedBlockStore(t *testing.T) {
	dir := t.TempDir()
	storeA, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore A: %v", err)
	}
	otherDir := t.TempDir()
	storeB, err := OpenBlockStore(BlockStorePath(otherDir))
	if err != nil {
		t.Fatalf("open blockstore B: %v", err)
	}
	engineState := NewChainState()
	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, DevnetGenesisChainID(), ChainStatePath(dir))
	engine, err := NewSyncEngine(engineState, storeA, cfg)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	_, err = NewMiner(engineState, storeB, engine, DefaultMinerConfig())
	if err == nil {
		t.Fatal("expected error on mismatched blockStore")
	}
	if err.Error() != "miner blockstore must alias sync engine blockstore" {
		t.Fatalf("expected %q, got %q", "miner blockstore must alias sync engine blockstore", err.Error())
	}
}

// TestMinerMineOne_PropagatesBootstrapError pins the err-propagation branch
// in Miner.MineOne. If BootstrapCanonicalGenesisIfEmpty returns an error,
// MineOne must surface it instead of continuing into buildBlock with an
// inconsistent SyncEngine state. We trigger the helper failure by nilling
// the engine's chainState after NewMiner succeeded — runtime state
// corruption that the production code must handle.
func TestMinerMineOne_PropagatesBootstrapError(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	engineState := NewChainState()
	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, DevnetGenesisChainID(), ChainStatePath(dir))
	engine, err := NewSyncEngine(engineState, store, cfg)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	miner, err := NewMiner(engineState, store, engine, DefaultMinerConfig())
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	// Corrupt the SyncEngine's chainState reference after construction.
	// Miner.MineOne's first nil-check passes (m.sync, m.chainState,
	// m.blockStore all non-nil), but the bootstrap call delegates to the
	// engine and the helper's nil-guard fires.
	engine.chainState = nil
	_, err = miner.MineOne(context.TODO(), nil)
	if err == nil {
		t.Fatal("expected bootstrap error to propagate from MineOne")
	}
	if err.Error() != "sync engine is not initialized" {
		t.Fatalf("expected %q, got %q", "sync engine is not initialized", err.Error())
	}
}
