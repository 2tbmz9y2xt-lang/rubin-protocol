package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// boundarySpacingSeconds halves the synthetic window's block interval so the
// retarget lands near POW_LIMIT/2, inside the /4 clamp.
const boundarySpacingSeconds = consensus.TARGET_BLOCK_INTERVAL / 2

func newStockDevnetEngine(t *testing.T, mutate func(*SyncConfig)) (*SyncEngine, *BlockStore, string) {
	t.Helper()
	dir := t.TempDir()
	store := mustCreateBlockStore(t, BlockStorePath(dir))
	cfg := DefaultSyncConfig(nil, devnetGenesisChainID, ChainStatePath(dir))
	if mutate != nil {
		mutate(&cfg)
	}
	engine, err := NewSyncEngine(NewChainState(), store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if err := engine.BootstrapCanonicalGenesisIfEmpty(); err != nil {
		t.Fatalf("BootstrapCanonicalGenesisIfEmpty: %v", err)
	}
	return engine, store, dir
}

// setStaticExpectedTargetAfterGenesis installs a static expected target once the
// published genesis is applied: at height 0 the static value still binds — that
// path is deliberately untouched — so setting a wrong one earlier would reject
// the published genesis itself.
func setStaticExpectedTargetAfterGenesis(engine *SyncEngine, target *[32]byte) {
	engine.cfg.ExpectedTarget = target
}

func wrongTarget() [32]byte {
	out := consensus.POW_LIMIT
	out[1] = 0x7f
	return out
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove(%s): %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func mustBlockHash(t *testing.T, block []byte) [32]byte {
	t.Helper()
	return mustHeaderHash(t, blockHeaderBytes(t, block))
}

func requireNotStored(t *testing.T, store *BlockStore, hash [32]byte) {
	t.Helper()
	if _, err := store.GetBlockByHash(hash); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected candidate stored: err=%v", err)
	}
}

// mineTargetScheduleBlock builds a single-transaction block whose header really
// satisfies PoW against `target`, reusing the production header-prefix and
// nonce-search helpers; buildSingleTxBlock pins nonce 7 and only works at
// POW_LIMIT-scale targets.
func mineTargetScheduleBlock(t *testing.T, prevHash [32]byte, target [32]byte, timestamp uint64, tx []byte) []byte {
	t.Helper()
	_, txid, _, _, err := consensus.ParseTx(tx)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	root, err := consensus.MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	headerBytes, _, err := mineHeaderNonce(context.Background(), makeHeaderPrefix(prevHash, root, timestamp, target), target)
	if err != nil {
		t.Fatalf("mineHeaderNonce: %v", err)
	}
	block := append([]byte(nil), headerBytes...)
	block = consensus.AppendCompactSize(block, 1)
	return append(block, tx...)
}

func nextCandidateBlock(t *testing.T, engine *SyncEngine, target [32]byte, timestamp uint64) []byte {
	t.Helper()
	view := engine.chainState.view()
	height := view.height + 1
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, consensus.BlockSubsidyBig(height, view.alreadyGenerated.Big()))
	return mineTargetScheduleBlock(t, view.tipHash, target, timestamp, coinbase)
}

func requireBlockTxError(t *testing.T, err error, code consensus.ErrorCode, msg string) {
	t.Helper()
	var txErr *consensus.TxError
	if !errors.As(err, &txErr) {
		t.Fatalf("err=%T %v, want *consensus.TxError %s/%q", err, err, code, msg)
	}
	if txErr.Code != code || txErr.Msg != msg {
		t.Fatalf("err=%s/%q, want %s/%q", txErr.Code, txErr.Msg, code, msg)
	}
}

func applyCanonicalChain(t *testing.T, engine *SyncEngine, blocks uint64) {
	t.Helper()
	for i := uint64(1); i <= blocks; i++ {
		block := nextCandidateBlock(t, engine, consensus.POW_LIMIT, reorgTestTimestamp(i))
		if _, err := engine.ApplyBlockWithReorg(block, nil); err != nil {
			t.Fatalf("apply canonical block %d: %v", i, err)
		}
	}
}

func canonicalTipSnapshot(t *testing.T, store *BlockStore) (uint64, [32]byte) {
	t.Helper()
	height, hash, ok, err := store.Tip()
	if err != nil || !ok {
		t.Fatalf("Tip()=(%d,%x,%v,%v)", height, hash, ok, err)
	}
	return height, hash
}

// newTargetScheduleBoundaryChain materializes a stock devnet chain whose tip is
// at WINDOW_SIZE-1, so the next candidate sits exactly on a retarget boundary.
//
// Heights 1..WINDOW_SIZE-2 are synthetic HEADERS plus a matching canonical
// index — 10,078 real blocks would cost ~30k fsync'd writes and an O(n^2) index
// rewrite, while the derivation reads only headers by hash and MTP only the last
// 11. Height 0 (the published genesis) and the TOP height are applied for real
// so they own block and undo artifacts, which a reorg preview must disconnect.
// Returns the window timestamps ascending plus the retarget value the boundary
// candidate must carry, checked here to be distinct from the parent's own target
// so the boundary rows are discriminating rather than tautological.
func newTargetScheduleBoundaryChain(t *testing.T) (*SyncEngine, *BlockStore, []uint64, [32]byte) {
	t.Helper()
	engine, store, _ := newStockDevnetEngine(t, nil)

	times := make([]uint64, consensus.WINDOW_SIZE)
	times[0] = reorgTestTimestamp(0)
	canonical := make([]string, 1, consensus.WINDOW_SIZE)
	canonical[0] = hex.EncodeToString(devnetGenesisBlockHash[:])
	prev := devnetGenesisBlockHash
	for height := 1; height < consensus.WINDOW_SIZE-1; height++ {
		times[height] = times[0] + uint64(height)*boundarySpacingSeconds
		raw, hash := scheduleHeader(t, prev, consensus.POW_LIMIT, times[height], uint64(height))
		mustWriteFile(t, filepath.Join(store.headersDir, hex.EncodeToString(hash[:])+".bin"), raw)
		canonical = append(canonical, hex.EncodeToString(hash[:]))
		prev = hash
	}
	store.index.Canonical = canonical
	store.rebuildCanonicalHeightIndex()
	engine.chainState.mu.Lock()
	engine.chainState.Height = uint64(consensus.WINDOW_SIZE - 2)
	engine.chainState.TipHash = prev
	engine.chainState.mu.Unlock()
	// The TOP canonical block is applied for real so it owns block and undo
	// artifacts: a reorg preview disconnects it, and synthetic header-only
	// heights cannot be disconnected.
	times[consensus.WINDOW_SIZE-1] = times[0] + uint64(consensus.WINDOW_SIZE-1)*boundarySpacingSeconds
	top := nextCandidateBlock(t, engine, consensus.POW_LIMIT, times[consensus.WINDOW_SIZE-1])
	if _, err := engine.ApplyBlockWithReorg(top, nil); err != nil {
		t.Fatalf("apply the real top canonical block: %v", err)
	}
	want, err := consensus.RetargetV1Clamped(consensus.POW_LIMIT, times)
	if err != nil || want == consensus.POW_LIMIT {
		t.Fatalf("boundary retarget=%x err=%v, want a value distinct from POW_LIMIT", want, err)
	}
	return engine, store, times, want
}

func TestTargetScheduleRuntimePublishedGenesisUnchanged(t *testing.T) {
	// The predicate HOLDS here, so the height-0 short-circuit is the only
	// reason nothing is derived: the primitive rejects height 0 outright with
	// errTargetHeightInvalid, and this engine has no static target to fall
	// back on. Bootstrap succeeding is the proof that height 0 never derives.
	engine, store, _ := newStockDevnetEngine(t, nil)
	height, hash := canonicalTipSnapshot(t, store)
	if engine.cfg.ExpectedTarget != nil || height != 0 || hash != devnetGenesisBlockHash {
		t.Fatalf("static=%v tip=(%d,%x), want no static target and the published genesis at height 0", engine.cfg.ExpectedTarget, height, hash)
	}
	if err := engine.BootstrapCanonicalGenesisIfEmpty(); err != nil {
		t.Fatalf("idempotent bootstrap: %v", err)
	}
}

// targetRuntimeCase drives one height-1 candidate through a live apply entry
// point on its own stock devnet chain. Every rejecting row must also satisfy the
// shared no-side-effect obligation checked by runTargetRuntimeCase.
type targetRuntimeCase struct {
	name          string
	network       string    // "" keeps the stock devnet network
	static        *[32]byte // installed AFTER genesis
	prevHash      *[32]byte // overrides the selected parent
	target        [32]byte
	pinNonce      bool // skip the PoW search so the header fails PoW
	viaApplyBlock bool // canonical ApplyBlock instead of ApplyBlockWithReorg
	wantCode      consensus.ErrorCode
	wantMsg       string
	wantIs        error // sentinel outcome that must NOT gain a consensus class
	thenAccept    bool  // a correctly targeted block at the SAME height must follow
}

func runTargetRuntimeCase(t *testing.T, tc targetRuntimeCase) {
	t.Helper()
	engine, store, _ := newStockDevnetEngine(t, func(cfg *SyncConfig) {
		if tc.network != "" {
			cfg.Network = tc.network
		}
	})
	if tc.static != nil {
		setStaticExpectedTargetAfterGenesis(engine, tc.static)
	}
	view := engine.chainState.view()
	prev := view.tipHash
	if tc.prevHash != nil {
		prev = *tc.prevHash
	}
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidyBig(1, view.alreadyGenerated.Big()))
	// pinNonce rows MUST skip the search: their targets are unsatisfiable
	// (zero, or 1) and mineHeaderNonce would spin forever.
	block := buildSingleTxBlock(t, prev, tc.target, reorgTestTimestamp(1), coinbase)
	if !tc.pinNonce {
		block = mineTargetScheduleBlock(t, prev, tc.target, reorgTestTimestamp(1), coinbase)
	}
	apply := engine.ApplyBlockWithReorg
	if tc.viaApplyBlock {
		apply = engine.ApplyBlock
	}
	_, err := apply(block, nil)
	switch {
	case tc.wantIs != nil:
		var txErr *consensus.TxError
		if !errors.Is(err, tc.wantIs) || errors.As(err, &txErr) {
			t.Fatalf("err=%v, want bare %v with no consensus class", err, tc.wantIs)
		}
	case tc.wantCode != "":
		requireBlockTxError(t, err, tc.wantCode, tc.wantMsg)
	default:
		if err != nil {
			t.Fatalf("want acceptance, got %v", err)
		}
		return
	}
	// Shared obligation: a rejected candidate is never stored and never moves
	// the canonical tip.
	requireNotStored(t, store, mustBlockHash(t, block))
	if height, tip := canonicalTipSnapshot(t, store); height != 0 || tip != devnetGenesisBlockHash {
		t.Fatalf("rejected candidate moved the tip to (%d,%x)", height, tip)
	}
	if !tc.thenAccept {
		return
	}
	good := nextCandidateBlock(t, engine, consensus.POW_LIMIT, reorgTestTimestamp(1))
	summary, err := engine.ApplyBlockWithReorg(good, nil)
	if err != nil || summary.BlockHeight != 1 {
		t.Fatalf("valid candidate at the same height: summary=%v err=%v", summary, err)
	}
}

func TestTargetScheduleRuntimeApplyMatrix(t *testing.T) {
	wrong, foreign := wrongTarget(), [32]byte{0xab}
	tiny := [32]byte{}
	tiny[31] = 0x01
	for _, tc := range []targetRuntimeCase{
		// PoW range and PoW work both precede the expected-target equality;
		// each block also carries an unexpected target, so a target check
		// running ahead of PoW would change the answer.
		{name: "pow_work_precedes_target", target: tiny, pinNonce: true, wantCode: consensus.BLOCK_ERR_POW_INVALID, wantMsg: "pow invalid"},
		{name: "pow_range_precedes_target", target: [32]byte{}, pinNonce: true, wantCode: consensus.BLOCK_ERR_TARGET_INVALID, wantMsg: "target out of range"},
		// Mis-targeted AND mis-linked: derivation uses the RESOLVED canonical
		// tip as selected parent, so the target check wins over linkage.
		{name: "resolved_parent_target_precedes_linkage", target: wrong, prevHash: &foreign, viaApplyBlock: true, wantCode: consensus.BLOCK_ERR_TARGET_INVALID, wantMsg: "target mismatch"},
		// Control: no schedule context exists for an unknown parent, so the
		// candidate keeps its orphan outcome instead of gaining a target class.
		{name: "unresolved_parent_stays_orphan", target: consensus.POW_LIMIT, prevHash: &foreign, wantIs: ErrParentNotFound},
		// The candidate carries the STATIC target: under the predicate the
		// derived value (the genesis POW_LIMIT) binds and rejects it,
		// otherwise the static value binds and it is accepted as before.
		{name: "predicate_true_derives", target: wrong, static: &wrong, wantCode: consensus.BLOCK_ERR_TARGET_INVALID, wantMsg: "target mismatch"},
		{name: "predicate_false_keeps_static", target: wrong, static: &wrong, network: "regtest"},
		// Reject-then-valid at the SAME height on one chain.
		{name: "reject_then_valid_same_height", target: wrong, wantCode: consensus.BLOCK_ERR_TARGET_INVALID, wantMsg: "target mismatch", thenAccept: true},
	} {
		t.Run(tc.name, func(t *testing.T) { runTargetRuntimeCase(t, tc) })
	}

	t.Run("predicate_is_pure_startup_identity", func(t *testing.T) {
		// The predicate is exactly two immutable startup terms and reads no
		// chain state, so destroying canonical[0] must NOT flip rule
		// selection — that dependency is what made an empty or recovering
		// store change the rules mid-flight.
		engine, store, _ := newStockDevnetEngine(t, nil)
		if err := store.TruncateCanonical(0); err != nil {
			t.Fatalf("TruncateCanonical: %v", err)
		}
		if !StockDevnetTargetSchedule(engine.cfg.Network, engine.cfg.ChainID) {
			t.Fatal("predicate flipped when canonical[0] was destroyed")
		}
		// The single shared accessor normalizes the network itself, because
		// node/p2p hands it the operator's RAW SyncConfig value.
		for _, tc := range []struct {
			network string
			chainID [32]byte
			want    bool
		}{
			{"", devnetGenesisChainID, true},
			{"devnet", devnetGenesisChainID, true},
			{"DEVNET", devnetGenesisChainID, true},
			{" DevNet\t", devnetGenesisChainID, true},
			{"regtest", devnetGenesisChainID, false},
			{"mainnet", devnetGenesisChainID, false},
			{"devnet", [32]byte{0x01}, false},
			{"devnet", [32]byte{}, false},
		} {
			if got := StockDevnetTargetSchedule(tc.network, tc.chainID); got != tc.want {
				t.Fatalf("StockDevnetTargetSchedule(%q, %x...)=%v, want %v", tc.network, tc.chainID[:2], got, tc.want)
			}
		}
	})

	t.Run("storeless_devnet_fails_closed", func(t *testing.T) {
		// Once the predicate holds the derived target is the ONLY binding
		// rule, so a storeless caller is refused WITH OR WITHOUT a configured
		// static target: falling back to that field would silently restore the
		// hole this issue closes. Same wording and same category (a plain
		// error, not a consensus class) as Rust's UNBOUND_DEVNET_TARGET_ERR.
		const want = "target schedule context: stock devnet predicate holds but there is no block store"
		static := consensus.POW_LIMIT
		for _, configured := range []*[32]byte{nil, &static} {
			cfg := DefaultSyncConfig(configured, devnetGenesisChainID, "")
			ctx, err := targetContextForCandidate(nil, cfg, foreign, 1)
			if err == nil || err.Error() != want || ctx != nil {
				t.Fatalf("storeless devnet (static=%v): ctx=%v err=%v, want the fail-closed refusal", configured, ctx, err)
			}
			var txErr *consensus.TxError
			if errors.As(err, &txErr) {
				t.Fatalf("refusal carries consensus class %s; Rust returns a plain message", txErr.Code)
			}
		}
		// A non-stock identity keeps its pre-existing static behavior.
		nonStock := DefaultSyncConfig(&static, devnetGenesisChainID, "")
		nonStock.Network = "regtest"
		if ctx, err := targetContextForCandidate(nil, nonStock, foreign, 1); err != nil || ctx.expected != &static {
			t.Fatalf("non-stock storeless engine: ctx=%v err=%v, want the configured target", ctx, err)
		}
	})
}

func TestTargetScheduleRuntimeParallelValidationSeesDerivedTarget(t *testing.T) {
	// The static target is deliberately wrong: a shadow run still reading
	// SyncConfig.ExpectedTarget would reject the block the sequential run
	// accepts, recording a fabricated divergence.
	wrong := wrongTarget()
	engine, _, _ := newStockDevnetEngine(t, func(cfg *SyncConfig) { cfg.ParallelValidationMode = "shadow" })
	setStaticExpectedTargetAfterGenesis(engine, &wrong)
	// Assert rather than skip: the Rust mirror asserts here, and a skip would
	// turn this row into a silent no-op the day the fixture stops satisfying
	// the IBD predicate.
	if !engine.isInIBDUnchecked() {
		t.Fatal("fixture chain is not in IBD, so PV shadow would not run")
	}
	block := nextCandidateBlock(t, engine, consensus.POW_LIMIT, reorgTestTimestamp(1))
	if _, err := engine.ApplyBlockWithReorg(block, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg: %v", err)
	}
	mismatches, samples := engine.PVShadowStats()
	if mismatches != 0 || len(samples) != 0 {
		t.Fatalf("pv shadow mismatches=%d samples=%v, want none", mismatches, samples)
	}
	if engine.pvTelemetry.Snapshot().BlocksValidated == 0 {
		t.Fatal("pv shadow did not run, so it proves nothing about the target it used")
	}
}

func TestTargetScheduleRuntimeTargetContextPrecedesMTP(t *testing.T) {
	// Height 1: the selected-parent header and the whole MTP window are the
	// same missing genesis header, so the error class identifies which context
	// was acquired first. Target context wins.
	genesisHeaderName := hex.EncodeToString(devnetGenesisBlockHash[:]) + ".bin"
	engine, store, _ := newStockDevnetEngine(t, nil)
	block := nextCandidateBlock(t, engine, consensus.POW_LIMIT, reorgTestTimestamp(1))
	mustRemove(t, filepath.Join(store.headersDir, genesisHeaderName))
	_, err := engine.ApplyBlockWithReorg(block, nil)
	if !errors.Is(err, ErrParentNotFound) || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err=%v, want the target-context class (ErrParentNotFound), not the MTP read error", err)
	}

	// Height 2 with the genesis header missing: the non-boundary derivation
	// reads only the height-1 header and succeeds, so the failure now comes
	// from the MTP window — the ordering is real, not an artifact of both
	// contexts sharing one file.
	engine, store, _ = newStockDevnetEngine(t, nil)
	applyCanonicalChain(t, engine, 1)
	next := nextCandidateBlock(t, engine, consensus.POW_LIMIT, reorgTestTimestamp(2))
	mustRemove(t, filepath.Join(store.headersDir, genesisHeaderName))
	_, err = engine.ApplyBlockWithReorg(next, nil)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err=%v, want the MTP read error after a successful target context", err)
	}
}

func TestTargetScheduleRuntimeReorgPreviewRejectsBeforeDisconnect(t *testing.T) {
	engine, store, _ := newStockDevnetEngine(t, nil)
	applyCanonicalChain(t, engine, 2)
	before := durableStoreFingerprint(t, store)
	_, beforeTip := canonicalTipSnapshot(t, store)
	beforeCounts := engine.BlockApplyCounts()

	// A competing height-1 branch at a quarter of POW_LIMIT carries MORE chain
	// work than the two canonical blocks, so fork choice selects it and the
	// reorg preview must reject it — before any disconnect, any store write,
	// and any contribution to chain work.
	heavier := consensus.POW_LIMIT
	heavier[0] = 0x3f
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0))
	side := mineTargetScheduleBlock(t, devnetGenesisBlockHash, heavier, reorgTestTimestamp(9), coinbase)
	sideHash := mustBlockHash(t, side)
	_, err := engine.ApplyBlockWithReorg(side, nil)
	requireBlockTxError(t, err, consensus.BLOCK_ERR_TARGET_INVALID, "target mismatch")
	requireNotStored(t, store, sideHash)
	if durableStoreFingerprint(t, store) != before {
		t.Fatalf("durable store state changed by a rejected side branch")
	}
	if _, tip := canonicalTipSnapshot(t, store); tip != beforeTip {
		t.Fatalf("canonical tip moved to %x", tip)
	}
	if _, err := store.ChainWork(sideHash); err == nil {
		t.Fatal("rejected side block contributed chain work")
	}
	// A consensus rejection of a selected winning branch records exactly one
	// rejected outcome and no accepted one, whichever phase catches it, so the
	// count no longer distinguishes preview from commit. The four assertions
	// above are what prove the PREVIEW rejected it: nothing stored, durable
	// fingerprint unchanged, tip unmoved, no chain work contributed.
	want := beforeCounts
	want.Rejected++
	if got := engine.BlockApplyCounts(); got != want {
		t.Fatalf("block-apply counts=%+v, want %+v", got, want)
	}
}

// TestTargetScheduleRuntimeRecoveryDerivesPerBlock proves the expected target
// is derived and BOUND per replayed block, using a corrupt height-1 canonical
// header as its vehicle.
//
// Rewired for RUB-890: strict fail-closed startup now refuses that datadir at
// the complete-prefix scan, ahead of replay, so the test asserts that refusal
// explicitly and then drives the per-block evidence through
// replayCanonicalBlocks — entered one step lower, but the same step
// ReconcileChainStateWithBlockStore reaches once the scan passes. The
// reconcile-level propagation is asserted by the structural-refusal row below;
// the per-block rows no longer travel through the reconcile entry point.
func TestTargetScheduleRuntimeRecoveryDerivesPerBlock(t *testing.T) {
	engine, store, dir := newStockDevnetEngine(t, nil)
	genesisSnapshot := cloneChainState(engine.chainState)
	applyCanonicalChain(t, engine, 2)
	cfg := engine.cfg
	replayed := NewChainState()
	changed, err := ReconcileChainStateWithBlockStore(replayed, store, cfg)
	if err != nil || !changed || replayed.Height != 2 {
		t.Fatalf("baseline reconcile: changed=%v height=%d err=%v", changed, replayed.Height, err)
	}

	// The derived VALUE must bind, not merely be computed: resume replay from
	// the height-0 snapshot under a deliberately WRONG static expected target.
	// Replay can only succeed if ConnectBlock received the derived value, and
	// height 0 (which still uses the static target) is never re-entered.
	wrongCfg := cfg
	wrongStatic := wrongTarget()
	wrongCfg.ExpectedTarget = &wrongStatic
	resumed := cloneChainState(genesisSnapshot)
	if changed, rerr := ReconcileChainStateWithBlockStore(resumed, store, wrongCfg); rerr != nil || !changed || resumed.Height != 2 {
		t.Fatalf("resume under a wrong static target: changed=%v height=%d err=%v", changed, resumed.Height, rerr)
	}

	// Corrupt the height-1 HEADER artifact only: replay of height 1 still
	// derives from the intact genesis header and its block artifact still
	// re-hashes, so the failure lands on height 2's own parent lookup — the
	// per-block evidence.
	height1Hash, ok, err := store.CanonicalHash(1)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(1)=(%x,%v,%v)", height1Hash, ok, err)
	}
	mustWriteFile(t, filepath.Join(store.headersDir, hex.EncodeToString(height1Hash[:])+".bin"), []byte{0x00})
	before := durableStoreFingerprint(t, store)
	chainStatePath := ChainStatePath(dir)
	if err := os.Remove(chainStatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clear chainstate snapshot: %v", err)
	}

	// Strict fail-closed startup (RUB-890) refuses this datadir at the
	// complete-prefix scan, BEFORE any replay runs: a canonical header that no
	// longer hashes to its indexed value is committed-canonical corruption, not
	// something replay is allowed to discover. That refusal is asserted here in
	// its own right — structural error, chainstate untouched, nothing written.
	refused := NewChainState()
	refusedBefore := refused.view()
	if _, rerr := ReconcileChainStateWithBlockStore(refused, store, cfg); !errors.Is(rerr, errCanonicalArtifactUnbound) {
		t.Fatalf("startup err=%v, want the unbound-artifact refusal before replay", rerr)
	}
	if after := refused.view(); after != refusedBefore {
		t.Fatalf("chainstate mutated before the refusal: %+v -> %+v", refusedBefore, after)
	}
	if durableStoreFingerprint(t, store) != before {
		t.Fatalf("durable store state changed on the refused startup")
	}
	if _, serr := os.Stat(chainStatePath); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("chainstate snapshot written on the refused startup: %v", serr)
	}

	// The per-block target evidence therefore drives replayCanonicalBlocks
	// directly: the same step the reconcile reaches once the scan passes,
	// entered with exactly the arguments a tipless snapshot produces (replay
	// from height 0 through the canonical tip).
	//
	// The selected parent is the canonical index entry at height-1, never the
	// replayed block's own hash. With ONLY the height-1 header corrupted, a
	// self-parenting derivation would already fail at height 1; the canonical
	// parent lets height 1 replay from the intact genesis header so that only
	// height 2 fails. How far the replay got is the witness.
	tipHeight, _, hasTip, err := store.Tip()
	if err != nil || !hasTip {
		t.Fatalf("Tip()=(%d,%v,%v)", tipHeight, hasTip, err)
	}
	partial := NewChainState()
	if _, err := replayCanonicalBlocks(partial, store, cfg, 0, tipHeight, true); !errors.Is(err, errTargetHistoryCorrupt) {
		t.Fatalf("replay err=%v, want errTargetHistoryCorrupt", err)
	}
	if partial.Height != 1 {
		t.Fatalf("replay reached height %d before failing, want 1", partial.Height)
	}

	// A non-devnet replay derives nothing and keeps cfg.ExpectedTarget, so the
	// corrupt header surfaces from the MTP window, never from the schedule.
	nonStock := cfg
	nonStock.Network = "regtest"
	if _, err := replayCanonicalBlocks(NewChainState(), store, nonStock, 0, tipHeight, true); err == nil || errors.Is(err, errTargetHistoryCorrupt) {
		t.Fatalf("non-devnet replay err=%v, want a failure that is not the schedule class", err)
	}
	// No additional durable write after a target-context failure: the
	// canonical index, the artifacts, and the absent chainstate snapshot must
	// all be exactly as they were.
	if durableStoreFingerprint(t, store) != before {
		t.Fatalf("durable store state changed after a target-context failure")
	}
	if _, err := os.Stat(chainStatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("chainstate snapshot written after target-context failure: %v", err)
	}
}

// durableStoreFingerprint captures every durable thing a failing path must not
// change: the canonical index plus the block/header/undo artifact listings.
func durableStoreFingerprint(t *testing.T, store *BlockStore) string {
	t.Helper()
	parts, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot: %v", err)
	}
	for _, dir := range []string{store.blocksDir, store.headersDir, store.undoDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir(%s): %v", dir, err)
		}
		for _, entry := range entries {
			parts = append(parts, entry.Name())
		}
	}
	return strings.Join(parts, "|")
}

func TestTargetScheduleRuntimeBoundaryReadBoundsAndBinding(t *testing.T) {
	engine, store, times, want := newTargetScheduleBoundaryChain(t)
	parent := engine.chainState.view().tipHash

	reads := 0
	counting := func(hash [32]byte) ([]byte, error) {
		reads++
		return store.GetHeaderByHash(hash)
	}

	nonBoundary, err := expectedTargetForCandidateWithReader(counting, parent, consensus.WINDOW_SIZE-1)
	if err != nil || reads != 1 || nonBoundary != consensus.POW_LIMIT {
		t.Fatalf("non-boundary: target=%x err=%v reads=%d, want %x nil 1", nonBoundary, err, reads, consensus.POW_LIMIT)
	}

	reads = 0
	boundary, err := expectedTargetForCandidateWithReader(counting, parent, consensus.WINDOW_SIZE)
	if err != nil || reads != consensus.WINDOW_SIZE || boundary != want {
		t.Fatalf("boundary: target=%x err=%v reads=%d, want %x nil %d", boundary, err, reads, want, consensus.WINDOW_SIZE)
	}

	// The production resolver every call site uses must agree with both.
	for _, tc := range []struct {
		height uint64
		want   [32]byte
	}{{consensus.WINDOW_SIZE - 1, consensus.POW_LIMIT}, {consensus.WINDOW_SIZE, want}} {
		ctx, err := engine.targetContextForCandidate(parent, tc.height)
		if err != nil || ctx.expected == nil || *ctx.expected != tc.want {
			t.Fatalf("resolver at height %d: ctx=%v err=%v, want %x", tc.height, ctx, err, tc.want)
		}
	}

	// ...and the derived value is what actually binds a boundary candidate:
	// reject-then-valid at the same boundary height, where the parent's own
	// target is no longer the expected one.
	timestamp := times[len(times)-1] + boundarySpacingSeconds
	stale := nextCandidateBlock(t, engine, consensus.POW_LIMIT, timestamp)
	_, err = engine.ApplyBlockWithReorg(stale, nil)
	requireBlockTxError(t, err, consensus.BLOCK_ERR_TARGET_INVALID, "target mismatch")
	requireNotStored(t, store, mustBlockHash(t, stale))

	good := nextCandidateBlock(t, engine, want, timestamp)
	summary, err := engine.ApplyBlockWithReorg(good, nil)
	if err != nil || summary.BlockHeight != consensus.WINDOW_SIZE {
		t.Fatalf("boundary candidate at the derived target: summary=%v err=%v", summary, err)
	}
	if height, _ := canonicalTipSnapshot(t, store); height != consensus.WINDOW_SIZE {
		t.Fatalf("canonical tip height=%d, want %d", height, consensus.WINDOW_SIZE)
	}
}

func mustMiner(t *testing.T, engine *SyncEngine, store *BlockStore, cfg MinerConfig) *Miner {
	t.Helper()
	miner, err := NewMiner(engine.chainState, store, engine, cfg)
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	return miner
}

func TestTargetScheduleRuntimeMinerUsesDerivedTarget(t *testing.T) {
	// A deliberately wrong static MinerConfig.Target: on a stock devnet chain
	// the template must ignore it for both header construction and the nonce
	// search, or SyncEngine.ApplyBlock would reject the miner's own block.
	// Far HARDER than POW_LIMIT (POW_LIMIT >> 16), so a header found by
	// searching against the derived target does not satisfy it, while a search
	// that used it necessarily would. That is what separates the nonce search
	// from header construction.
	staticTarget := [32]byte{}
	for i := 2; i < 32; i++ {
		staticTarget[i] = 0xff
	}
	cfg := DefaultMinerConfig()
	cfg.Target = staticTarget

	engine, store, _ := newStockDevnetEngine(t, nil)
	mined, err := mustMiner(t, engine, store, cfg).MineOne(context.Background(), nil)
	if err != nil {
		t.Fatalf("MineOne: %v", err)
	}
	header, err := store.GetHeaderByHash(mined.Hash)
	if err != nil {
		t.Fatalf("GetHeaderByHash: %v", err)
	}
	if parsed, perr := consensus.ParseBlockHeaderBytes(header); perr != nil || parsed.Target != consensus.POW_LIMIT {
		t.Fatalf("mined target=%x err=%v, want the derived %x", parsed.Target, perr, consensus.POW_LIMIT)
	}
	// The NONCE SEARCH used the derived target too, not just the header field.
	if err := consensus.PowCheck(header, staticTarget); err == nil {
		t.Fatal("mined header also satisfies the static MinerConfig.Target: the nonce search used it")
	}

	// Boundary height: the template must commit to the retargeted value.
	boundaryEngine, boundaryStore, _, want := newTargetScheduleBoundaryChain(t)
	got, err := mustMiner(t, boundaryEngine, boundaryStore, cfg).templateTarget(boundaryEngine.chainState.view().tipHash, consensus.WINDOW_SIZE)
	if err != nil || got != want {
		t.Fatalf("boundary template target=%x err=%v, want %x", got, err, want)
	}

	// Non-stock configuration keeps the static MinerConfig.Target verbatim.
	regtestEngine, regtestStore, _ := newStockDevnetEngine(t, func(c *SyncConfig) { c.Network = "regtest" })
	got, err = mustMiner(t, regtestEngine, regtestStore, cfg).templateTarget(regtestEngine.chainState.view().tipHash, 1)
	if err != nil || got != staticTarget {
		t.Fatalf("regtest template target=%x err=%v, want the static %x", got, err, staticTarget)
	}
}

// mineOrderedBlock mines a valid block, advancing the timestamp until its hash
// orders as requested against `other`. Fork choice breaks EQUAL-work ties on the
// lexicographically lower tip hash, so a test that needs a branch row to win or
// lose such a tie has to pin the ordering instead of relying on luck.
func mineOrderedBlock(t *testing.T, prev, target [32]byte, baseTs uint64, tx []byte, other [32]byte, wantLower bool) []byte {
	t.Helper()
	for offset := uint64(0); offset < 512; offset++ {
		block := mineTargetScheduleBlock(t, prev, target, baseTs+offset, tx)
		hash := mustBlockHash(t, block)
		if (bytes.Compare(hash[:], other[:]) < 0) == wantLower {
			return block
		}
	}
	t.Fatal("no timestamp in range produced the required hash ordering")
	return nil
}

// countDerivations pins how many times the CALLERS invoke the derivation
// primitive. The read count INSIDE the primitive is its own property and is
// pinned by its own tests; what matters here is that no caller derives twice for
// one block, and that the preview and commit loops stay linear in branch length.
// The seam is a package global, so these rows must not run in parallel.
func countDerivations(t *testing.T, body func()) int {
	t.Helper()
	previous := deriveExpectedTargetFn
	defer func() { deriveExpectedTargetFn = previous }()
	count := 0
	deriveExpectedTargetFn = func(store *BlockStore, parentHash [32]byte, candidateHeight uint64) ([32]byte, error) {
		count++
		return previous(store, parentHash, candidateHeight)
	}
	body()
	return count
}

// twoRowWinningBranch stores branch row A as a losing side block, then returns
// row B so that applying B makes [A, B] outweigh the two canonical blocks and
// take the switching reorg path.
func twoRowWinningBranch(t *testing.T, engine *SyncEngine, store *BlockStore) []byte {
	t.Helper()
	_, canonicalTip := canonicalTipSnapshot(t, store)
	rowA := mineTargetScheduleBlock(t, devnetGenesisBlockHash, consensus.POW_LIMIT, reorgTestTimestamp(9),
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
	if _, err := engine.ApplyBlockWithReorg(rowA, nil); err != nil {
		t.Fatalf("store losing branch row A: %v", err)
	}
	hashA := mustBlockHash(t, rowA)
	parsedA, err := consensus.ParseBlockBytes(rowA)
	if err != nil {
		t.Fatalf("ParseBlockBytes(rowA): %v", err)
	}
	subsidy := consensus.BlockSubsidy(2, consensus.BlockSubsidy(1, 0))
	return mineOrderedBlock(t, hashA, consensus.POW_LIMIT, parsedA.Header.Timestamp+1,
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy), canonicalTip, true)
}

func TestTargetScheduleRuntimeReorgCommitLoopBindsDerivedTarget(t *testing.T) {
	engine, store, _ := newStockDevnetEngine(t, nil)
	applyCanonicalChain(t, engine, 2)
	// A deliberately wrong static target: the reorg completes only if the
	// commit loop binds the DERIVED value for every row it applies. Reverting
	// the commit loop alone turns this success into a target rejection.
	wrong := wrongTarget()
	setStaticExpectedTargetAfterGenesis(engine, &wrong)
	rowB := twoRowWinningBranch(t, engine, store)
	summary, err := engine.ApplyBlockWithReorg(rowB, nil)
	if err != nil || summary.BlockHeight != 2 {
		t.Fatalf("switching reorg under a wrong static target: summary=%v err=%v", summary, err)
	}
	if height, tip := canonicalTipSnapshot(t, store); height != 2 || tip != mustBlockHash(t, rowB) {
		t.Fatalf("canonical tip=(%d,%x), want the branch tip at height 2", height, tip)
	}
}

func TestTargetScheduleRuntimeSideBranchStoreRejectsBeforeStoreBlock(t *testing.T) {
	// A branch that does NOT win fork choice takes storeSideBlockAndSummary,
	// a different derivation site from the reorg preview. A wrong declared
	// target must be rejected there before StoreBlock, contributing nothing to
	// storage or to chain work.
	engine, store, _ := newStockDevnetEngine(t, nil)
	applyCanonicalChain(t, engine, 2)
	before := durableStoreFingerprint(t, store)
	_, beforeTip := canonicalTipSnapshot(t, store)
	side := mineTargetScheduleBlock(t, devnetGenesisBlockHash, wrongTarget(), reorgTestTimestamp(9),
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
	sideHash := mustBlockHash(t, side)
	_, err := engine.ApplyBlockWithReorg(side, nil)
	requireBlockTxError(t, err, consensus.BLOCK_ERR_TARGET_INVALID, "target mismatch")
	requireNotStored(t, store, sideHash)
	if durableStoreFingerprint(t, store) != before {
		t.Fatal("durable store state changed by a rejected non-switching side branch")
	}
	if _, tip := canonicalTipSnapshot(t, store); tip != beforeTip {
		t.Fatalf("canonical tip moved to %x", tip)
	}
	if _, err := store.ChainWork(sideHash); err == nil {
		t.Fatal("rejected side block contributed chain work")
	}
}

func TestTargetScheduleRuntimeParallelValidationOnErrorSeesDerivedTarget(t *testing.T) {
	// The shadow-on-ERROR call site. The candidate carries the correct derived
	// target but an invalid coinbase subsidy, so the sequential connect fails
	// AFTER the target check. A shadow lane still reading the (wrong) static
	// target would fail at the target check instead and record a fabricated
	// seq/par divergence.
	engine, _, _ := newStockDevnetEngine(t, func(cfg *SyncConfig) { cfg.ParallelValidationMode = "shadow" })
	wrong := wrongTarget()
	setStaticExpectedTargetAfterGenesis(engine, &wrong)
	view := engine.chainState.view()
	bad := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidyBig(1, view.alreadyGenerated.Big())+1)
	block := mineTargetScheduleBlock(t, view.tipHash, consensus.POW_LIMIT, reorgTestTimestamp(1), bad)
	_, err := engine.ApplyBlockWithReorg(block, nil)
	if err == nil {
		t.Fatal("candidate with an over-paying coinbase was accepted")
	}
	var txErr *consensus.TxError
	if errors.As(err, &txErr) && txErr.Code == consensus.BLOCK_ERR_TARGET_INVALID {
		t.Fatalf("sequential path failed at the target check, not past it: %s/%q", txErr.Code, txErr.Msg)
	}
	mismatches, samples := engine.PVShadowStats()
	if mismatches != 0 || len(samples) != 0 || engine.pvTelemetry.Snapshot().BlocksValidated == 0 {
		t.Fatalf("pv shadow-on-error mismatches=%d samples=%v validated=%d", mismatches, samples,
			engine.pvTelemetry.Snapshot().BlocksValidated)
	}
}

func TestTargetScheduleRuntimeBranchCrossingRetargetBoundary(t *testing.T) {
	// The only path where boundary derivation walks BRANCH ancestry instead of
	// canonical ancestry: a branch row at the boundary height whose parent is
	// another branch row. Its window ends at the branch row's timestamp, so the
	// canonical-derived value is the WRONG answer here — binding it would be
	// fork-class.
	engine, store, times, canonicalWant := newTargetScheduleBoundaryChain(t)
	_, canonicalTip := canonicalTipSnapshot(t, store)
	forkParent, ok, err := store.CanonicalHash(consensus.WINDOW_SIZE - 2)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(fork parent)=(%x,%v,%v)", forkParent, ok, err)
	}

	// Row A at WINDOW_SIZE-1 must LOSE the equal-work tie so it is stored as a
	// side block rather than triggering a reorg of its own.
	heightA := uint64(consensus.WINDOW_SIZE - 1)
	rowA := mineOrderedBlock(t, forkParent, consensus.POW_LIMIT, times[consensus.WINDOW_SIZE-2]+boundarySpacingSeconds,
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, heightA, consensus.BlockSubsidyBig(heightA, engine.chainState.view().alreadyGenerated.Big())),
		canonicalTip, false)
	if _, err := engine.ApplyBlockWithReorg(rowA, nil); err != nil {
		t.Fatalf("store losing branch row A at the pre-boundary height: %v", err)
	}
	parsedA, err := consensus.ParseBlockBytes(rowA)
	if err != nil {
		t.Fatalf("ParseBlockBytes(rowA): %v", err)
	}
	branchTimes := append(append([]uint64(nil), times[:consensus.WINDOW_SIZE-1]...), parsedA.Header.Timestamp)
	branchWant, err := consensus.RetargetV1Clamped(consensus.POW_LIMIT, branchTimes)
	if err != nil || branchWant == canonicalWant {
		t.Fatalf("branch retarget=%x err=%v, want a value distinct from the canonical %x", branchWant, err, canonicalWant)
	}

	// Row B sits exactly on the boundary. The canonical-derived value must be
	// rejected; the branch-derived value must get past the target check.
	heightB := uint64(consensus.WINDOW_SIZE)
	coinbaseB := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, heightB, consensus.BlockSubsidyBig(heightB, engine.chainState.view().alreadyGenerated.Big()))
	tsB := parsedA.Header.Timestamp + boundarySpacingSeconds
	_, err = engine.ApplyBlockWithReorg(mineTargetScheduleBlock(t, mustBlockHash(t, rowA), canonicalWant, tsB, coinbaseB), nil)
	requireBlockTxError(t, err, consensus.BLOCK_ERR_TARGET_INVALID, "target mismatch")

	_, err = engine.ApplyBlockWithReorg(mineTargetScheduleBlock(t, mustBlockHash(t, rowA), branchWant, tsB, coinbaseB), nil)
	var txErr *consensus.TxError
	if errors.As(err, &txErr) && txErr.Code == consensus.BLOCK_ERR_TARGET_INVALID {
		t.Fatalf("branch-derived boundary target rejected: %s/%q", txErr.Code, txErr.Msg)
	}
}

func TestTargetScheduleRuntimeCallerDerivesOncePerBlockAndRow(t *testing.T) {
	t.Run("direct_tip_apply_derives_once", func(t *testing.T) {
		engine, _, _ := newStockDevnetEngine(t, nil)
		block := nextCandidateBlock(t, engine, consensus.POW_LIMIT, reorgTestTimestamp(1))
		got := countDerivations(t, func() {
			if _, err := engine.ApplyBlockWithReorg(block, nil); err != nil {
				t.Fatalf("ApplyBlockWithReorg: %v", err)
			}
		})
		// One acquisition in applyDirectTipBlock, threaded through the choke
		// point verbatim — a second walk here would double a boundary block's
		// ancestry cost.
		if got != 1 {
			t.Fatalf("derivations=%d, want 1", got)
		}
	})

	t.Run("non_switching_side_branch_derives_once", func(t *testing.T) {
		engine, _, _ := newStockDevnetEngine(t, nil)
		applyCanonicalChain(t, engine, 2)
		side := mineTargetScheduleBlock(t, devnetGenesisBlockHash, consensus.POW_LIMIT, reorgTestTimestamp(9),
			coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
		got := countDerivations(t, func() {
			if _, err := engine.ApplyBlockWithReorg(side, nil); err != nil {
				t.Fatalf("store side block: %v", err)
			}
		})
		if got != 1 {
			t.Fatalf("derivations=%d, want 1", got)
		}
	})

	t.Run("switching_reorg_is_linear_in_branch_length", func(t *testing.T) {
		engine, store, _ := newStockDevnetEngine(t, nil)
		applyCanonicalChain(t, engine, 2)
		rowB := twoRowWinningBranch(t, engine, store)
		got := countDerivations(t, func() {
			if _, err := engine.ApplyBlockWithReorg(rowB, nil); err != nil {
				t.Fatalf("switching reorg: %v", err)
			}
		})
		// One derivation per prepared row during the complete preflight; the
		// commit-only publication derives none. Linear, not quadratic.
		if got != 2 {
			t.Fatalf("derivations=%d for a 2-row branch, want 2 (one per prepared row during preflight)", got)
		}
	})

	t.Run("replay_derives_once_per_block", func(t *testing.T) {
		engine, store, _ := newStockDevnetEngine(t, nil)
		applyCanonicalChain(t, engine, 2)
		cfg := engine.cfg
		got := countDerivations(t, func() {
			if _, err := ReconcileChainStateWithBlockStore(NewChainState(), store, cfg); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
		})
		// Heights 1 and 2; height 0 keeps the static target and derives nothing.
		if got != 2 {
			t.Fatalf("derivations=%d for a 2-block replay, want 2", got)
		}
	})
}

func TestTargetScheduleRuntimeSideBranchTargetContextPrecedesMTP(t *testing.T) {
	// storeSideBlockAndSummary acquires target context BEFORE the MTP window.
	// The genesis header is both the branch's selected parent and the whole MTP
	// window for height 1, so removing it makes the error class name whichever
	// context was acquired first: the target class, not the MTP read error.
	engine, store, _ := newStockDevnetEngine(t, nil)
	applyCanonicalChain(t, engine, 2)
	side := mineTargetScheduleBlock(t, devnetGenesisBlockHash, consensus.POW_LIMIT, reorgTestTimestamp(9),
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
	// Warm the chain-work cache first: fork choice runs before the store path
	// and would otherwise read the same header, masking the ordering.
	_, tip := canonicalTipSnapshot(t, store)
	for _, hash := range [][32]byte{tip, devnetGenesisBlockHash} {
		if _, err := store.ChainWork(hash); err != nil {
			t.Fatalf("warm ChainWork(%x): %v", hash, err)
		}
	}
	mustRemove(t, filepath.Join(store.headersDir, hex.EncodeToString(devnetGenesisBlockHash[:])+".bin"))
	_, err := engine.ApplyBlockWithReorg(side, nil)
	if !errors.Is(err, ErrParentNotFound) || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err=%v, want the target-context class (ErrParentNotFound), not the MTP read error", err)
	}
}
