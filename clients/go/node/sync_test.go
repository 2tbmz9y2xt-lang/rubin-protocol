package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestDefaultSyncConfigAndEngineInit_Defaults(t *testing.T) {
	st := NewChainState()
	var chainID [32]byte
	cfg := DefaultSyncConfig(nil, chainID, "x.json")
	if cfg.HeaderBatchLimit == 0 || cfg.IBDLagSeconds == 0 {
		t.Fatalf("expected non-zero defaults: %#v", cfg)
	}
	if cfg.IBDLagSeconds != defaultIBDLagSeconds {
		t.Fatalf("ibd_lag_seconds=%d, want %d", cfg.IBDLagSeconds, defaultIBDLagSeconds)
	}
	if cfg.ParallelValidationMode != "off" {
		t.Fatalf("parallel_validation_mode=%q, want off", cfg.ParallelValidationMode)
	}

	cfg.HeaderBatchLimit = 0
	cfg.IBDLagSeconds = 0
	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if engine.cfg.HeaderBatchLimit != 512 {
		t.Fatalf("header_batch_limit=%d, want 512", engine.cfg.HeaderBatchLimit)
	}
	if engine.cfg.IBDLagSeconds != defaultIBDLagSeconds {
		t.Fatalf("ibd_lag_seconds=%d, want %d", engine.cfg.IBDLagSeconds, defaultIBDLagSeconds)
	}
}

func TestNewSyncEngine_ParallelValidationModeParse(t *testing.T) {
	st := NewChainState()
	cfg := DefaultSyncConfig(nil, [32]byte{}, "")
	cfg.ParallelValidationMode = "shadow"
	if _, err := NewSyncEngine(st, nil, cfg); err != nil {
		t.Fatalf("expected shadow mode ok: %v", err)
	}

	cfg.ParallelValidationMode = "on"
	if _, err := NewSyncEngine(st, nil, cfg); err != nil {
		t.Fatalf("expected on mode ok: %v", err)
	}

	cfg.ParallelValidationMode = "nope"
	if _, err := NewSyncEngine(st, nil, cfg); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

// TestValidateParallelValidationMode pins the validation-only wrapper to
// the canonical parser's accept set: wrapper and NewSyncEngine must
// agree on every value, so a nil wrapper result can never precede an
// engine-side mode-parse rejection (RUB-665 validate-before-mutate).
func TestValidateParallelValidationMode(t *testing.T) {
	for _, mode := range []string{"", "off", "shadow", "on", "OFF", "Shadow", " on ", "\toff\n"} {
		if err := ValidateParallelValidationMode(mode); err != nil {
			t.Errorf("ValidateParallelValidationMode(%q) = %v, want nil", mode, err)
			continue
		}
		cfg := DefaultSyncConfig(nil, [32]byte{}, "")
		cfg.ParallelValidationMode = mode
		if _, err := NewSyncEngine(NewChainState(), nil, cfg); err != nil {
			t.Errorf("NewSyncEngine rejected %q accepted by wrapper: %v", mode, err)
		}
	}
	for _, mode := range []string{"nope", "of", "offf", "off shadow", "off,on", "0", "-", "øff"} {
		err := ValidateParallelValidationMode(mode)
		if err == nil {
			t.Errorf("ValidateParallelValidationMode(%q) = nil, want error", mode)
			continue
		}
		if !strings.Contains(err.Error(), "invalid parallel_validation_mode") {
			t.Errorf("ValidateParallelValidationMode(%q) error = %q, want canonical parser text", mode, err)
		}
		cfg := DefaultSyncConfig(nil, [32]byte{}, "")
		cfg.ParallelValidationMode = mode
		if _, err := NewSyncEngine(NewChainState(), nil, cfg); err == nil {
			t.Errorf("NewSyncEngine accepted %q rejected by wrapper", mode)
		}
	}
}

func TestPVShadowMismatch_SequentialTruthPreserved(t *testing.T) {
	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, "")
	// Storeless engine: a stock devnet identity now fails closed rather than
	// falling back to the static target (RUB-655), so this PV fixture declares
	// a non-devnet network. The chain id must stay devnet — it is the sighash
	// domain these signed transactions were built against.
	cfg.Network = "regtest"
	cfg.ParallelValidationMode = "shadow"
	cfg.PVShadowMaxSamples = 2

	signer := mustNodeMLDSA87Keypair(t)
	keyID := sha3.Sum256(signer.PubkeyBytes())
	fromAddr, err := ParseMineAddress(hex.EncodeToString(keyID[:]))
	if err != nil {
		t.Fatalf("ParseMineAddress: %v", err)
	}
	st, ops := testSpendableChainState(fromAddr, []uint64{100})

	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	var stderr bytes.Buffer
	engine.SetStderr(&stderr)
	inOp := ops[0]

	// tx1: valid structure, but corrupt the signature so sequential path returns TX_ERR_SIG_INVALID.
	changeAddress := append([]byte(nil), fromAddr...)
	toAddress := append([]byte(nil), fromAddr...)
	tx1 := mustBuildSignedTransferTxForSyncTest(t, engine.chainState.Utxos, []consensus.Outpoint{inOp}, 1, 0, 1, signer, changeAddress, toAddress)
	parsed1, _, wtxid1, _, err := consensus.ParseTx(tx1)
	if err != nil {
		t.Fatalf("ParseTx(tx1): %v", err)
	}
	// Flip one byte in the first witness signature (P2PK => witness[0]).
	if len(parsed1.Witness) == 0 || len(parsed1.Witness[0].Signature) == 0 {
		t.Fatal("expected witness signature in tx1")
	}
	parsed1.Witness[0].Signature[0] ^= 0xFF
	tx1, err = consensus.MarshalTx(parsed1)
	if err != nil {
		t.Fatalf("MarshalTx(tx1): %v", err)
	}
	// Recompute wtxid after corruption (coinbase witness commitment must match).
	_, _, wtxid1, _, err = consensus.ParseTx(tx1)
	if err != nil {
		t.Fatalf("ParseTx(tx1 after corrupt): %v", err)
	}

	// tx2: missing UTXO, so parallel pre-check may return TX_ERR_MISSING_UTXO before flushing sigs.
	tx2obj := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  2,
		Inputs:   []consensus.TxInput{{PrevTxid: [32]byte{0x99}, PrevVout: 0, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: 1, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: changeAddress}},
		Locktime: 0,
	}
	tx2, err := consensus.MarshalTx(tx2obj)
	if err != nil {
		t.Fatalf("MarshalTx(tx2): %v", err)
	}
	_, _, wtxid2, _, err := consensus.ParseTx(tx2)
	if err != nil {
		t.Fatalf("ParseTx(tx2): %v", err)
	}

	height := st.Height + 1
	subsidy := consensus.BlockSubsidyBig(height, st.AlreadyGenerated.Big())
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t, height, subsidy, [][32]byte{{}, wtxid1, wtxid2})
	block := buildMultiTxBlock(t, st.TipHash, target, 2, coinbase, tx1, tx2)

	_, err = engine.ApplyBlock(block, nil)
	if err == nil || !strings.Contains(err.Error(), string(consensus.TX_ERR_SIG_INVALID)) {
		t.Fatalf("expected sequential truth error %s, got %v", consensus.TX_ERR_SIG_INVALID, err)
	}

	mismatches, samples := engine.PVShadowStats()
	if mismatches == 0 || len(samples) == 0 {
		t.Fatalf("expected pv shadow mismatch recorded, got mismatches=%d samples=%v", mismatches, samples)
	}
	if !strings.Contains(stderr.String(), "pv_shadow: mismatch") {
		t.Fatalf("expected pv_shadow diagnostic on stderr, got: %q", stderr.String())
	}
}

func TestPVShadowStats_NilEngine(t *testing.T) {
	var nilEngine *SyncEngine
	m, s := nilEngine.PVShadowStats()
	if m != 0 || s != nil {
		t.Fatalf("expected zero stats for nil engine, got mismatches=%d samples=%v", m, s)
	}
}

func TestBlockApplyCountsNilEngine(t *testing.T) {
	var nilEngine *SyncEngine
	if got := nilEngine.BlockApplyCounts(); got != (BlockApplyCounts{}) {
		t.Fatalf("nil BlockApplyCounts=%+v, want zero", got)
	}
	nilEngine.noteBlockApplyAccepted()
	nilEngine.noteBlockApplyAcceptedN(2)
	nilEngine.noteBlockApplyRejected()
	nilEngine.noteBlockApplyOutcome(blockApplyMetricNone)
	nilEngine.noteBlockApplyOutcome(blockApplyMetricAccepted)
	nilEngine.noteBlockApplyOutcome(blockApplyMetricRejected)
	if got := nilEngine.BlockApplyCounts(); got != (BlockApplyCounts{}) {
		t.Fatalf("nil BlockApplyCounts after notes=%+v, want zero", got)
	}
}

func TestPVShadowMismatch_IsBounded(t *testing.T) {
	st := NewChainState()
	cfg := DefaultSyncConfig(nil, [32]byte{}, "")
	cfg.ParallelValidationMode = "shadow"
	cfg.PVShadowMaxSamples = 1
	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}

	engine.recordPVShadowMismatch("a")
	engine.recordPVShadowMismatch("b")
	m, samples := engine.PVShadowStats()
	if m != 2 {
		t.Fatalf("mismatches=%d, want 2", m)
	}
	if len(samples) != 1 || samples[0] != "a" {
		t.Fatalf("samples=%v, want [a]", samples)
	}
}

func TestPVShadow_NoMismatchOnValidBlock(t *testing.T) {
	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, "")
	// Storeless engine: a stock devnet identity now fails closed rather than
	// falling back to the static target (RUB-655), so this PV fixture declares
	// a non-devnet network. The chain id must stay devnet — it is the sighash
	// domain these signed transactions were built against.
	cfg.Network = "regtest"
	cfg.ParallelValidationMode = "shadow"
	cfg.PVShadowMaxSamples = 3

	signer := mustNodeMLDSA87Keypair(t)
	keyID := sha3.Sum256(signer.PubkeyBytes())
	fromAddr, err := ParseMineAddress(hex.EncodeToString(keyID[:]))
	if err != nil {
		t.Fatalf("ParseMineAddress: %v", err)
	}
	st, ops := testSpendableChainState(fromAddr, []uint64{100})
	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	var stderr bytes.Buffer
	engine.SetStderr(&stderr)

	height := st.Height + 1
	tx1 := mustBuildSignedTransferTxForSyncTest(t, st.Utxos, []consensus.Outpoint{ops[0]}, 1, 0, 1, signer, fromAddr, fromAddr)
	_, _, wtxid1, _, err := consensus.ParseTx(tx1)
	if err != nil {
		t.Fatalf("ParseTx(tx1): %v", err)
	}
	subsidy := consensus.BlockSubsidyBig(height, st.AlreadyGenerated.Big())
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t, height, subsidy, [][32]byte{{}, wtxid1})
	block := buildMultiTxBlock(t, st.TipHash, target, 2, coinbase, tx1)

	if _, err := engine.ApplyBlock(block, nil); err != nil {
		t.Fatalf("ApplyBlock(valid): %v", err)
	}
	m, samples := engine.PVShadowStats()
	if m != 0 || len(samples) != 0 {
		t.Fatalf("expected no mismatches on valid block, got mismatches=%d samples=%v stderr=%q", m, samples, stderr.String())
	}
}

func TestNewSyncEngine_NilChainState(t *testing.T) {
	_, err := NewSyncEngine(nil, nil, SyncConfig{})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRecheckLiveTipIdentityRejectsSupplyOnlyMove(t *testing.T) {
	state := NewChainState()
	prior := chainTipScalarsOf(state)
	state.AlreadyGenerated = consensus.Uint128FromU64(1)
	err := (&SyncEngine{}).recheckLiveTipIdentity(&canonicalTransition{chainState: state}, prior)
	if err == nil || err.Error() != "live chainstate tip moved during canonical apply" {
		t.Fatalf("err=%v, want exact supply-only tip-move error", err)
	}
}

func TestNewSyncEngine_MainnetGuard(t *testing.T) {
	st := NewChainState()

	cfg := DefaultSyncConfig(nil, [32]byte{}, "")
	cfg.Network = "mainnet"
	if _, err := NewSyncEngine(st, nil, cfg); err == nil {
		t.Fatalf("expected error for mainnet without explicit expected_target")
	}

	allFF := consensus.POW_LIMIT
	cfg = DefaultSyncConfig(&allFF, [32]byte{}, "")
	cfg.Network = "mainnet"
	if _, err := NewSyncEngine(st, nil, cfg); err == nil {
		t.Fatalf("expected error for mainnet with devnet POW_LIMIT")
	}

	okTarget := consensus.POW_LIMIT
	okTarget[0] = 0x7f
	cfg = DefaultSyncConfig(&okTarget, [32]byte{}, "")
	cfg.Network = "mainnet"
	if _, err := NewSyncEngine(st, nil, cfg); err != nil {
		t.Fatalf("expected success for mainnet with explicit non-devnet target: %v", err)
	}
}

func TestSyncEngine_HeaderSyncRequest(t *testing.T) {
	st := NewChainState()
	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}

	r := engine.HeaderSyncRequest()
	if r.HasFrom {
		t.Fatalf("expected HasFrom=false when no tip")
	}
	if r.Limit != engine.cfg.HeaderBatchLimit {
		t.Fatalf("limit=%d, want %d", r.Limit, engine.cfg.HeaderBatchLimit)
	}

	st.HasTip = true
	st.TipHash = mustHash32Hex(t, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	r = engine.HeaderSyncRequest()
	if !r.HasFrom || r.FromHash != st.TipHash {
		t.Fatalf("unexpected request: %#v", r)
	}
}

func TestSyncEngine_RecordBestKnownHeight(t *testing.T) {
	st := NewChainState()
	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if got := engine.BestKnownHeight(); got != 0 {
		t.Fatalf("best_known=%d, want 0", got)
	}

	engine.RecordBestKnownHeight(7)
	engine.RecordBestKnownHeight(6)
	engine.RecordBestKnownHeight(9)
	if got := engine.BestKnownHeight(); got != 9 {
		t.Fatalf("best_known=%d, want 9", got)
	}

	var nilEngine *SyncEngine
	nilEngine.RecordBestKnownHeight(10)
	if got := nilEngine.BestKnownHeight(); got != 0 {
		t.Fatalf("nil best_known=%d, want 0", got)
	}
}

func TestSyncEngine_IsInIBDEdgeCases(t *testing.T) {
	var nilEngine *SyncEngine
	if !nilEngine.IsInIBD(0) {
		t.Fatalf("expected IBD for nil engine")
	}

	st := NewChainState()
	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	st.HasTip = true
	engine.tipTimestamp = 100
	engine.cfg.IBDLagSeconds = 10
	if engine.IsInIBD(99) {
		t.Fatalf("did not expect IBD when tip timestamp is in future")
	}
	if engine.IsInIBD(100) {
		t.Fatalf("did not expect IBD when now equals tip timestamp")
	}
	if engine.IsInIBD(110) {
		t.Fatalf("did not expect IBD when lag equals threshold")
	}
}

func TestSyncEngineIBDLogic(t *testing.T) {
	st := NewChainState()
	cfg := DefaultSyncConfig(nil, [32]byte{}, "")
	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	if !engine.IsInIBD(1_000) {
		t.Fatalf("expected IBD when no tip")
	}

	st.HasTip = true
	st.Height = 10
	engine.tipTimestamp = 1_000
	engine.cfg.IBDLagSeconds = 100
	if engine.IsInIBD(900) {
		t.Fatalf("did not expect IBD when tip is in future")
	}
	if !engine.IsInIBD(1_200) {
		t.Fatalf("expected IBD when lag exceeds threshold")
	}
	if engine.IsInIBD(1_050) {
		t.Fatalf("did not expect IBD when lag below threshold")
	}
}

func TestCanonicalBlockRelayTerminalNew(t *testing.T) {
	injectStateSync := func(t *testing.T, engine *SyncEngine, failAt int) *bool {
		t.Helper()
		failed := new(bool)
		calls := 0
		withAtomicWriteOps(t, func(ops *atomicWriteOps) {
			syncParent := ops.syncParent
			ops.syncParent = func(parent string) error {
				if parent == filepath.Dir(engine.cfg.ChainStatePath) {
					calls++
				}
				if !*failed && calls == failAt {
					*failed = true
					return os.ErrPermission
				}
				return syncParent(parent)
			}
		})
		return failed
	}

	t.Run("direct complete visible NEW", func(t *testing.T) {
		engine, store, _ := newPersistenceFaultEngine(t)
		pb, err := consensus.ParseBlockBytes(DevnetGenesisBlockBytes())
		if err != nil {
			t.Fatalf("parse genesis: %v", err)
		}
		failed := injectStateSync(t, engine, 1)
		summary, err := engine.ApplyBlockWithReorg(DevnetGenesisBlockBytes(), nil)
		if !*failed || summary == nil || !errors.Is(err, os.ErrPermission) || summary.BlockHash != devnetGenesisBlockHash || len(summary.CanonicalAppliedBlocks) != 1 {
			t.Fatalf("failed=%v summary=%+v err=%v", *failed, summary, err)
		}
		view := engine.chainState.view()
		index, indexErr := store.CanonicalIndexSnapshot()
		wantIndex := []string{hex.EncodeToString(summary.BlockHash[:])}
		if !view.hasTip || view.height != summary.BlockHeight || view.tipHash != summary.BlockHash || engine.chainState.StateDigest() != summary.PostStateDigest || indexErr != nil || !reflect.DeepEqual(index, wantIndex) {
			t.Fatalf("live=%+v digest=%x index=%v indexErr=%v, want summary=%+v index=%v", view, engine.chainState.StateDigest(), index, indexErr, summary, wantIndex)
		}
		if engine.tipTimestamp != pb.Header.Timestamp || engine.IsInIBD(pb.Header.Timestamp) {
			t.Fatalf("tipTimestamp=%d IBD=%v, want published timestamp %d and post-transition non-IBD", engine.tipTimestamp, engine.IsInIBD(pb.Header.Timestamp), pb.Header.Timestamp)
		}
	})

	t.Run("preferred complete visible NEW", func(t *testing.T) {
		engine, _, target := newReorgTestEngine(t)
		subsidy1 := consensus.BlockSubsidy(1, 0)
		coinbase1 := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1)
		blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbase1)
		if _, err := engine.ApplyBlockWithReorg(blockA1, nil); err != nil {
			t.Fatalf("apply A1: %v", err)
		}
		sideB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(2), coinbase1)
		_, sideB1Hash := mustParseReorgBlockForTest(t, sideB1)
		if _, err := engine.ApplyBlockWithReorg(sideB1, nil); err != nil {
			t.Fatalf("store B1: %v", err)
		}
		subsidy2 := consensus.BlockSubsidy(2, subsidy1)
		sideB2 := buildSingleTxBlock(t, sideB1Hash, target, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
		parsedB2, sideB2Hash := mustParseReorgBlockForTest(t, sideB2)
		failed := injectStateSync(t, engine, 3)
		summary, err := engine.ApplyBlockWithReorg(sideB2, nil)
		if !*failed || summary == nil || !errors.Is(err, os.ErrPermission) || summary.BlockHash != sideB2Hash || len(summary.CanonicalAppliedBlocks) != 2 {
			t.Fatalf("failed=%v summary=%+v err=%v", *failed, summary, err)
		}
		view := engine.chainState.view()
		index, indexErr := engine.blockStore.CanonicalIndexSnapshot()
		wantIndex := []string{hex.EncodeToString(devnetGenesisBlockHash[:]), hex.EncodeToString(sideB1Hash[:]), hex.EncodeToString(sideB2Hash[:])}
		if !view.hasTip || view.height != summary.BlockHeight || view.tipHash != summary.BlockHash || engine.chainState.StateDigest() != summary.PostStateDigest || indexErr != nil || !reflect.DeepEqual(index, wantIndex) {
			t.Fatalf("live=%+v digest=%x index=%v indexErr=%v, want summary=%+v index=%v", view, engine.chainState.StateDigest(), index, indexErr, summary, wantIndex)
		}
		if engine.tipTimestamp != parsedB2.Header.Timestamp || engine.IsInIBD(parsedB2.Header.Timestamp) {
			t.Fatalf("tipTimestamp=%d IBD=%v, want published timestamp %d and post-transition non-IBD", engine.tipTimestamp, engine.IsInIBD(parsedB2.Header.Timestamp), parsedB2.Header.Timestamp)
		}
	})

	t.Run("precommit remains nil", func(t *testing.T) {
		engine, _, _ := newPersistenceFaultEngine(t)
		withAtomicWriteOps(t, func(ops *atomicWriteOps) {
			ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) { return nil, os.ErrPermission }
		})
		if summary, err := engine.ApplyBlockWithReorg(DevnetGenesisBlockBytes(), nil); summary != nil || err == nil {
			t.Fatalf("summary=%+v err=%v, want nil precommit summary and error", summary, err)
		}
	})
}

func TestSyncEngineApplyBlockPersistsChainstateAndStore(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("apply genesis block: %v", err)
	}

	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, block1Coinbase)

	summary, err := engine.ApplyBlock(block1, nil)
	if err != nil {
		t.Fatalf("apply block: %v", err)
	}
	if summary.BlockHeight != 1 {
		t.Fatalf("block height=%d, want 1", summary.BlockHeight)
	}
	if _, err := os.Stat(chainStatePath); err != nil {
		t.Fatalf("chainstate file not persisted: %v", err)
	}

	loaded, err := LoadChainState(chainStatePath)
	if err != nil {
		t.Fatalf("reload chainstate: %v", err)
	}
	if !loaded.HasTip || loaded.Height != 1 {
		t.Fatalf("unexpected persisted chainstate: has_tip=%v height=%d", loaded.HasTip, loaded.Height)
	}

	height, _, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("blockstore tip: %v", err)
	}
	if !ok || height != 1 {
		t.Fatalf("unexpected blockstore tip: ok=%v height=%d", ok, height)
	}
}

func TestSyncEngineBlockApplyCountsCanonicalAcceptedRejected(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	if got := engine.BlockApplyCounts(); got != (BlockApplyCounts{}) {
		t.Fatalf("initial BlockApplyCounts=%+v, want zero", got)
	}

	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	if got := engine.BlockApplyCounts(); got.Accepted != 1 || got.Rejected != 0 {
		t.Fatalf("after genesis BlockApplyCounts=%+v, want accepted=1 rejected=0", got)
	}

	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, block1Coinbase)
	summary1, err := engine.ApplyBlock(block1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(block1): %v", err)
	}
	if got := engine.BlockApplyCounts(); got.Accepted != 2 || got.Rejected != 0 {
		t.Fatalf("after block1 BlockApplyCounts=%+v, want accepted=2 rejected=0", got)
	}
	tipHeight, tipHash, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("Tip after accepted block1: %v", err)
	}
	if !ok || tipHeight != summary1.BlockHeight || tipHash != summary1.BlockHash {
		t.Fatalf("canonical tip after accepted block1=%d/%x ok=%v, want %d/%x", tipHeight, tipHash, ok, summary1.BlockHeight, summary1.BlockHash)
	}

	block2Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, consensus.BlockSubsidyBig(2, summary1.AlreadyGenerated.Big()))
	invalidBlock2 := append([]byte(nil), buildSingleTxBlock(t, summary1.BlockHash, target, 3, block2Coinbase)...)
	invalidBlock2[4+32] ^= 0x01 // keep the block parseable but break merkle-root validation.
	if _, err := engine.ApplyBlock(invalidBlock2, nil); err == nil {
		t.Fatalf("expected invalid canonical block rejection")
	}
	if got := engine.BlockApplyCounts(); got.Accepted != 2 || got.Rejected != 1 {
		t.Fatalf("after invalid block BlockApplyCounts=%+v, want accepted=2 rejected=1", got)
	}
	tipHeight, tipHash, ok, err = store.Tip()
	if err != nil {
		t.Fatalf("Tip after rejected block2: %v", err)
	}
	if !ok || tipHeight != summary1.BlockHeight || tipHash != summary1.BlockHash {
		t.Fatalf("canonical tip changed after rejected block2=%d/%x ok=%v, want %d/%x", tipHeight, tipHash, ok, summary1.BlockHeight, summary1.BlockHash)
	}
}

// TestSyncEngineApplyBlockPutUndoFailureRollsBackCanonicalTip lives in
// sync_unix_test.go behind a `//go:build unix` tag: after the E.3
// TOCTOU hardening the undo write no longer routes through
// writeFileAtomicFn (it uses the fixed-scratch hard-link lane), so the only
// portable way to provoke an undo-write failure is a chmod-based
// permission error on the undo directory, which needs os.Geteuid() to
// skip under root. See that file for the actual test body.

func TestChainStateDisconnectBlockRestoresSpentUTXOState(t *testing.T) {
	sourceKP, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		t.Fatalf("NewMLDSA87Keypair(source): %v", err)
	}
	defer sourceKP.Close()

	destKP, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		t.Fatalf("NewMLDSA87Keypair(dest): %v", err)
	}
	defer destKP.Close()

	sourceAddress := consensus.P2PKCovenantDataForPubkey(sourceKP.PubkeyBytes())
	destAddress := consensus.P2PKCovenantDataForPubkey(destKP.PubkeyBytes())

	st := NewChainState()
	st.HasTip = true
	st.Height = 100
	st.TipHash = mustHash32Hex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	st.AlreadyGenerated = consensus.Uint128FromU64(123_456)

	sourceOutpoint := consensus.Outpoint{
		Txid: mustHash32Hex(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Vout: 0,
	}
	st.Utxos[sourceOutpoint] = consensus.UtxoEntry{
		Value:             1_000,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      append([]byte(nil), sourceAddress...),
		CreationHeight:    1,
		CreatedByCoinbase: true,
	}

	before, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk before: %v", err)
	}
	prevState, err := chainStateFromDisk(before)
	if err != nil {
		t.Fatalf("chainStateFromDisk before: %v", err)
	}

	spendTx := mustBuildSignedTransferTxForSyncTest(
		t,
		st.Utxos,
		[]consensus.Outpoint{sourceOutpoint},
		700,
		50,
		1,
		sourceKP,
		sourceAddress,
		destAddress,
	)
	_, _, spendWTxID, _, err := consensus.ParseTx(spendTx)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}
	subsidy := consensus.BlockSubsidyBig(101, st.AlreadyGenerated.Big())
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t, 101, subsidy+50, [][32]byte{{}, spendWTxID})
	target := consensus.POW_LIMIT
	block := buildMultiTxBlock(t, st.TipHash, target, 2, coinbase, spendTx)

	summary, err := st.ConnectBlock(block, &target, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}
	pb, err := consensus.ParseBlockBytes(block)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	undo, err := buildBlockUndo(prevState, pb, summary.BlockHeight)
	if err != nil {
		t.Fatalf("buildBlockUndo: %v", err)
	}

	disconnectSummary, err := st.DisconnectBlock(block, undo)
	if err != nil {
		t.Fatalf("DisconnectBlock: %v", err)
	}
	if !disconnectSummary.HasTip || disconnectSummary.NewHeight != 100 {
		t.Fatalf("unexpected disconnect summary: %+v", disconnectSummary)
	}

	after, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk after: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("chainstate mismatch after disconnect")
	}
}

func TestSyncEngineDisconnectTipPersistsChainstateAndStore(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("apply genesis block: %v", err)
	}
	genesisBlock, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}

	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, block1Coinbase)
	block1Parsed, err := consensus.ParseBlockBytes(block1)
	if err != nil {
		t.Fatalf("ParseBlockBytes(block1): %v", err)
	}
	block1Hash, err := consensus.BlockHash(block1Parsed.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(block1): %v", err)
	}
	if _, err := engine.ApplyBlock(block1, nil); err != nil {
		t.Fatalf("apply block1: %v", err)
	}

	summary, err := engine.DisconnectTip()
	if err != nil {
		t.Fatalf("DisconnectTip: %v", err)
	}
	if !summary.HasTip || summary.NewHeight != 0 || summary.NewTipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected disconnect summary: %+v", summary)
	}
	if engine.tipTimestamp != genesisBlock.Header.Timestamp {
		t.Fatalf("tip_timestamp=%d, want %d", engine.tipTimestamp, genesisBlock.Header.Timestamp)
	}

	loaded, err := LoadChainState(chainStatePath)
	if err != nil {
		t.Fatalf("LoadChainState: %v", err)
	}
	if !loaded.HasTip || loaded.Height != 0 || loaded.TipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected persisted chainstate: %+v", loaded)
	}

	tipHeight, tipHash, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("store.Tip: %v", err)
	}
	if !ok || tipHeight != 0 || tipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected store tip after disconnect: ok=%v height=%d hash=%x", ok, tipHeight, tipHash)
	}
	if _, err := store.GetUndo(block1Hash); err != nil {
		t.Fatalf("GetUndo(block1): %v", err)
	}
}

func TestSyncEngineApplyBlockNoMutationOnFailure(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := filepath.Join(dir, "chainstate.json")
	st := NewChainState()
	st.HasTip = true
	st.Height = 5
	st.TipHash = mustHash32Hex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	st.AlreadyGenerated = consensus.Uint128FromU64(10)
	st.Utxos[consensus.Outpoint{
		Txid: mustHash32Hex(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Vout: 0,
	}] = consensus.UtxoEntry{
		Value:             1,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x22),
		CreationHeight:    1,
		CreatedByCoinbase: false,
	}

	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	before, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk before: %v", err)
	}

	if _, err := engine.ApplyBlock([]byte{0x01, 0x02}, nil); err == nil {
		t.Fatalf("expected apply error")
	}
	after, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk after: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("chainstate mutated on failed apply")
	}
}

func TestSyncEngineApplyBlock_RollbackOnSaveFailure(t *testing.T) {
	dir := t.TempDir()
	badDir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(badDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	chainStatePath := filepath.Join(badDir, "chainstate.json")

	st := &ChainState{
		HasTip:  true,
		Height:  0,
		TipHash: devnetGenesisBlockHash,
		Utxos:   nil,
	}
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	engine.tipTimestamp = 999
	engine.bestKnownHeight = 123

	before, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk before: %v", err)
	}

	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block := buildSingleTxBlock(t, st.TipHash, target, 2, block1Coinbase)

	if _, err := engine.ApplyBlock(block, nil); err == nil {
		t.Fatalf("expected apply error")
	}

	if got := engine.BlockApplyCounts(); got != (BlockApplyCounts{}) {
		t.Fatalf("persist failure changed BlockApplyCounts=%+v, want zero", got)
	}
	after, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk after: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("chainstate mutated on rollback path")
	}
	if engine.tipTimestamp != 999 {
		t.Fatalf("tip_timestamp=%d, want 999", engine.tipTimestamp)
	}
	if engine.bestKnownHeight != 123 {
		t.Fatalf("best_known_height=%d, want 123", engine.bestKnownHeight)
	}
}

func TestRestoreChainState_NilDestination(t *testing.T) {
	if err := testRestoreChainState(nil, chainStateDisk{}); err == nil {
		t.Fatalf("expected error")
	}
}

func mustBuildSignedTransferTxForSyncTest(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	inputs []consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
	toAddress []byte,
) []byte {
	t.Helper()

	txInputs := make([]consensus.TxInput, 0, len(inputs))
	var totalIn uint64
	for _, op := range inputs {
		entry, ok := utxos[op]
		if !ok {
			t.Fatalf("missing utxo for %x:%d", op.Txid, op.Vout)
		}
		totalIn += entry.Value
		txInputs = append(txInputs, consensus.TxInput{
			PrevTxid: op.Txid,
			PrevVout: op.Vout,
			Sequence: 0,
		})
	}

	change := totalIn - amount - fee
	outputs := []consensus.TxOutput{{
		Value:        amount,
		CovenantType: consensus.COV_TYPE_P2PK,
		CovenantData: append([]byte(nil), toAddress...),
	}}
	if change > 0 {
		outputs = append(outputs, consensus.TxOutput{
			Value:        change,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), changeAddress...),
		})
	}

	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  nonce,
		Inputs:   txInputs,
		Outputs:  outputs,
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return txBytes
}

func buildMultiTxBlock(t *testing.T, prevHash [32]byte, target [32]byte, timestamp uint64, txs ...[]byte) []byte {
	t.Helper()
	txids := make([][32]byte, 0, len(txs))
	totalLen := consensus.BLOCK_HEADER_BYTES + 8
	for _, txBytes := range txs {
		_, txid, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			t.Fatalf("ParseTx: %v", err)
		}
		txids = append(txids, txid)
		totalLen += len(txBytes)
	}
	root, err := consensus.MerkleRootTxids(txids)
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	header := make([]byte, 0, consensus.BLOCK_HEADER_BYTES)
	header = consensus.AppendU32le(header, 1)
	header = append(header, prevHash[:]...)
	header = append(header, root[:]...)
	header = consensus.AppendU64le(header, timestamp)
	header = append(header, target[:]...)
	header = consensus.AppendU64le(header, 7)

	block := make([]byte, 0, totalLen)
	block = append(block, header...)
	block = consensus.AppendCompactSize(block, uint64(len(txs)))
	for _, txBytes := range txs {
		block = append(block, txBytes...)
	}
	return block
}

func coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t *testing.T, height uint64, value uint64, wtxids [][32]byte) []byte {
	t.Helper()
	wroot, err := consensus.WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commitment := consensus.WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: value, covenantType: consensus.COV_TYPE_P2PK, covenantData: testP2PKCovenantData(0x11)},
		{value: 0, covenantType: consensus.COV_TYPE_ANCHOR, covenantData: commitment[:]},
	})
}

func mustDecodeHexBytes(t *testing.T, raw string) []byte {
	t.Helper()
	out, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	return out
}

// TestSyncEngine_isInIBDUnchecked exercises the internal isInIBDUnchecked()
// method used to choose between sequential and parallel signature verification
// during block connection.
func TestSyncEngine_isInIBDUnchecked(t *testing.T) {
	t.Run("nil_engine", func(t *testing.T) {
		var nilEngine *SyncEngine
		if !nilEngine.isInIBDUnchecked() {
			t.Fatal("expected IBD for nil engine")
		}
	})

	t.Run("nil_chainstate", func(t *testing.T) {
		engine := &SyncEngine{}
		if !engine.isInIBDUnchecked() {
			t.Fatal("expected IBD when chainState is nil")
		}
	})

	t.Run("no_tip", func(t *testing.T) {
		st := NewChainState()
		engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		if !engine.isInIBDUnchecked() {
			t.Fatal("expected IBD when no tip")
		}
	})

	t.Run("zero_timestamp", func(t *testing.T) {
		st := NewChainState()
		st.HasTip = true
		engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		engine.tipTimestamp = 0
		if !engine.isInIBDUnchecked() {
			t.Fatal("expected IBD when the zero timestamp is older than the lag threshold")
		}
	})

	t.Run("tip_in_future", func(t *testing.T) {
		st := NewChainState()
		st.HasTip = true
		engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		// A future tip is outside IBD by the merged Section 9 rule.
		engine.tipTimestamp = ^uint64(0)
		engine.cfg.IBDLagSeconds = 100
		if engine.isInIBDUnchecked() {
			t.Fatal("did not expect IBD when tip timestamp is in future")
		}
	})

	t.Run("recent_tip_not_ibd", func(t *testing.T) {
		st := NewChainState()
		st.HasTip = true
		engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		// Tip is very recent (1 second ago).
		engine.tipTimestamp = uint64(time.Now().Unix()) - 1
		engine.cfg.IBDLagSeconds = 86400
		if engine.isInIBDUnchecked() {
			t.Fatal("did not expect IBD when tip is recent")
		}
	})

	t.Run("old_tip_is_ibd", func(t *testing.T) {
		st := NewChainState()
		st.HasTip = true
		engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		// Tip is very old.
		engine.tipTimestamp = 1000
		engine.cfg.IBDLagSeconds = 100
		if !engine.isInIBDUnchecked() {
			t.Fatal("expected IBD when tip is very old")
		}
	})
}

// TestTxErrCode exercises the four branches of txErrCode: nil → "OK", a
// direct *consensus.TxError pointer → its Code, a wrapped *consensus.TxError
// (via fmt.Errorf + %w) → still the Code thanks to errors.As, and a plain
// non-TxError → "ERR". The wrapped case is the reason for using errors.As
// instead of a direct type assertion.
func TestTxErrCode(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if got := txErrCode(nil); got != "OK" {
			t.Fatalf("txErrCode(nil)=%q want %q", got, "OK")
		}
	})

	t.Run("direct_tx_error", func(t *testing.T) {
		err := &consensus.TxError{Code: consensus.TX_ERR_SIG_INVALID, Msg: "bad sig"}
		if got := txErrCode(err); got != string(consensus.TX_ERR_SIG_INVALID) {
			t.Fatalf("txErrCode(direct)=%q want %q", got, consensus.TX_ERR_SIG_INVALID)
		}
	})

	t.Run("wrapped_tx_error_classified_via_errors_as", func(t *testing.T) {
		inner := &consensus.TxError{Code: consensus.TX_ERR_VALUE_CONSERVATION, Msg: "v"}
		wrapped := fmt.Errorf("apply_block: tx 7: %w", inner)
		if got := txErrCode(wrapped); got != string(consensus.TX_ERR_VALUE_CONSERVATION) {
			t.Fatalf("txErrCode(wrapped)=%q want %q", got, consensus.TX_ERR_VALUE_CONSERVATION)
		}
	})

	t.Run("doubly_wrapped_tx_error_still_classified", func(t *testing.T) {
		inner := &consensus.TxError{Code: consensus.TX_ERR_NONCE_REPLAY, Msg: "replay"}
		wrapped := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", inner))
		if got := txErrCode(wrapped); got != string(consensus.TX_ERR_NONCE_REPLAY) {
			t.Fatalf("txErrCode(double-wrapped)=%q want %q", got, consensus.TX_ERR_NONCE_REPLAY)
		}
	})

	t.Run("non_tx_error", func(t *testing.T) {
		if got := txErrCode(errors.New("io: broken pipe")); got != "ERR" {
			t.Fatalf("txErrCode(non-TxError)=%q want %q", got, "ERR")
		}
	})
}

func TestValidateMainnetGenesisGuard_ExportedWrapperParity(t *testing.T) {
	// The exported wrapper is the entry point used by cmd/rubin-node/main.go
	// to run the guard BEFORE reconcile (mirror of Rust main.rs ordering).
	// It must produce identical results to the unexported form used inside
	// NewSyncEngine — same pass on devnet, same reject on misconfigured
	// mainnet. Cross-client parity: matches Rust validate_mainnet_genesis_guard
	// re-export (clients/rust/crates/rubin-node/src/lib.rs).

	t.Run("devnet_passes", func(t *testing.T) {
		cfg := SyncConfig{Network: "devnet"}
		if err := ValidateMainnetGenesisGuard(cfg); err != nil {
			t.Fatalf("devnet: ValidateMainnetGenesisGuard returned %v, want nil", err)
		}
		// Wrapper and inner must agree.
		if inner := validateMainnetGenesisGuard(cfg); inner != nil {
			t.Fatalf("devnet: validateMainnetGenesisGuard returned %v, want nil", inner)
		}
	})

	t.Run("mainnet_without_expected_target_rejects", func(t *testing.T) {
		cfg := SyncConfig{Network: "mainnet"} // ExpectedTarget==nil
		err := ValidateMainnetGenesisGuard(cfg)
		if err == nil {
			t.Fatal("mainnet without ExpectedTarget: ValidateMainnetGenesisGuard returned nil, want error")
		}
		inner := validateMainnetGenesisGuard(cfg)
		if inner == nil || inner.Error() != err.Error() {
			t.Fatalf("wrapper/inner divergence: wrapper=%v inner=%v", err, inner)
		}
	})
}

func TestValidateMempoolEntryParsedRejectsBadSource(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddr := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddr := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddr, []uint64{1_000_000})
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddr, toAddr)
	tx, txid, wtxid, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}

	tests := []struct {
		name    string
		entry   mempoolEntry
		wantErr string
	}{
		{
			name: "valid",
			entry: mempoolEntry{
				raw: txBytes, txid: txid, wtxid: wtxid,
				weight: weight, size: len(txBytes),
				admissionSeq: 1, source: "local",
				inputs: []consensus.Outpoint{{Txid: outpoints[0].Txid, Vout: outpoints[0].Vout}},
			},
		},
		{
			name: "bad_txid",
			entry: mempoolEntry{
				raw: txBytes, txid: [32]byte{0xff}, wtxid: wtxid,
				weight: weight, size: len(txBytes),
				admissionSeq: 1, source: "local",
				inputs: []consensus.Outpoint{{Txid: outpoints[0].Txid, Vout: outpoints[0].Vout}},
			},
			wantErr: "txid mismatch",
		},
		{
			name: "bad_source",
			entry: mempoolEntry{
				raw: txBytes, txid: txid, wtxid: wtxid,
				weight: weight, size: len(txBytes),
				admissionSeq: 1, source: "bogus_source",
				inputs: []consensus.Outpoint{{Txid: outpoints[0].Txid, Vout: outpoints[0].Vout}},
			},
			wantErr: "invalid mempool snapshot entry source",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMempoolEntryParsed(tc.entry)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want %q, got %v", tc.wantErr, err)
				}
			}
		})
	}
}

// pendingOutpointSyncFixture is the shared canonical-transition test bed: a
// devnet engine whose chain is long enough for its height-1 coinbase output to
// be spendable, the single mempool bound to that engine, and the keys needed to
// build competing spends of that output.
type pendingOutpointSyncFixture struct {
	engine           *SyncEngine
	store            *BlockStore
	target           [32]byte
	mempool          *Mempool
	owner            *PendingOutpointOwner
	sourceKP         *consensus.MLDSA87Keypair
	sourceAddress    []byte
	destAddress      []byte
	sourceOutpoint   consensus.Outpoint
	tipHash          [32]byte
	tipHeight        uint64
	alreadyGenerated uint64
}

func newPendingOutpointSyncFixture(t *testing.T) *pendingOutpointSyncFixture {
	t.Helper()
	engine, store, target := newReorgTestEngine(t)
	sourceKP := mustReorgMLDSA87Keypair(t)
	destKP := mustReorgMLDSA87Keypair(t)
	f := &pendingOutpointSyncFixture{
		engine:        engine,
		store:         store,
		target:        target,
		sourceKP:      sourceKP,
		sourceAddress: consensus.P2PKCovenantDataForPubkey(sourceKP.PubkeyBytes()),
		destAddress:   consensus.P2PKCovenantDataForPubkey(destKP.PubkeyBytes()),
		tipHash:       devnetGenesisBlockHash,
	}
	// COINBASE_MATURITY blocks so the height-1 coinbase output is spendable.
	for height := uint64(1); height <= 100; height++ {
		subsidy := consensus.BlockSubsidy(height, f.alreadyGenerated)
		coinbase := reorgTestCoinbaseForAddress(t, height, subsidy, f.sourceAddress)
		summary, err := engine.ApplyBlock(buildSingleTxBlock(t, f.tipHash, target, height+1, coinbase), nil)
		if err != nil {
			t.Fatalf("ApplyBlock(height=%d): %v", height, err)
		}
		if height == 1 {
			_, coinbaseTxid, _, _, err := consensus.ParseTx(coinbase)
			if err != nil {
				t.Fatalf("ParseTx(coinbase height 1): %v", err)
			}
			f.sourceOutpoint = consensus.Outpoint{Txid: coinbaseTxid, Vout: 0}
		}
		f.tipHash, f.tipHeight, f.alreadyGenerated = summary.BlockHash, height, f.alreadyGenerated+subsidy
	}
	mempool, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)
	f.mempool, f.owner = mempool, mempool.PendingOutpointOwner()
	return f
}

// spend builds a signed transfer of the fixture's spendable coinbase output.
// Distinct nonces produce distinct, mutually conflicting transactions.
func (f *pendingOutpointSyncFixture) spend(t *testing.T, amount uint64, nonce uint64) []byte {
	t.Helper()
	return mustBuildSignedTransferTxForSyncTest(
		t,
		f.engine.chainState.Utxos,
		[]consensus.Outpoint{f.sourceOutpoint},
		amount,
		100_000,
		nonce,
		f.sourceKP,
		f.sourceAddress,
		f.destAddress,
	)
}

// blockIncluding builds a canonical block at height carrying tx. alreadyGenerated
// is the branch-local total issued BEFORE height, so a block built on a side
// branch gets that branch's subsidy rather than the canonical chain's.
func (f *pendingOutpointSyncFixture) blockIncluding(t *testing.T, prevHash [32]byte, height uint64, alreadyGenerated uint64, timestamp uint64, tx []byte) []byte {
	t.Helper()
	_, _, wtxid, _, err := consensus.ParseTx(tx)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	subsidy := consensus.BlockSubsidy(height, alreadyGenerated)
	return buildMultiTxBlock(
		t,
		prevHash,
		f.target,
		timestamp,
		reorgTestCoinbaseForWtxids(t, height, subsidy+100_000, f.sourceAddress, [][32]byte{{}, wtxid}),
		tx,
	)
}

func mustAdmissionContext(t *testing.T, owner *PendingOutpointOwner, what string) PendingOutpointAdmissionContext {
	t.Helper()
	ctx, ok := owner.AdmissionContext()
	if !ok {
		t.Fatalf("AdmissionContext unavailable %s", what)
	}
	return ctx
}

// breakResidentClaim rebinds a resident record to a FOREIGN owner's token —
// precisely the record/claim inconsistency the typed standard delta refuses to
// mutate through — so the next canonical cleanup of that record fails.
func (f *pendingOutpointSyncFixture) breakResidentClaim(t *testing.T, txid [32]byte) {
	t.Helper()
	foreign := newPendingOutpointOwner(PendingOutpointTip{})
	token, err := foreign.Reserve(PendingOutpointAdmissionContext{}, PendingOutpointStandardMempool, [32]byte{0x01}, []consensus.Outpoint{f.sourceOutpoint})
	if err != nil {
		t.Fatalf("foreign Reserve: %v", err)
	}
	f.mempool.mu.Lock()
	defer f.mempool.mu.Unlock()
	f.mempool.txs[txid].token = token
}

func ownerClaimCount(owner *PendingOutpointOwner) (outpoints int, claims int, highWater uint64) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return len(owner.byOutpoint), len(owner.byToken), owner.tokenHighWater
}

// TestSyncPendingOutpointDirectConnectReleasesTokensAndCommitsStableTip proves
// the direct-connect row end to end: an included transaction's record and its
// exact claim are both gone after the connect, the owner's stable tip is the new
// canonical tip, exactly one generation was consumed, and the token high-water
// stayed advanced so no sequence can be reused.
func TestSyncPendingOutpointDirectConnectReleasesTokensAndCommitsStableTip(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	spend := f.spend(t, 700, 1)
	if err := f.mempool.AddTx(spend); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	before := mustAdmissionContext(t, f.owner, "before the direct connect")
	if before.StableTip.Hash != f.tipHash || before.StableTip.Height != f.tipHeight {
		t.Fatalf("stable tip before=%+v, want the live tip (%d,%x)", before.StableTip, f.tipHeight, f.tipHash)
	}
	if outpoints, claims, _ := ownerClaimCount(f.owner); outpoints != 1 || claims != 1 {
		t.Fatalf("owner state before connect=(%d,%d), want one claim", outpoints, claims)
	}

	summary, err := f.engine.ApplyBlock(f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, spend), nil)
	if err != nil {
		t.Fatalf("ApplyBlock(including spend): %v", err)
	}

	if got := f.mempool.Len(); got != 0 {
		t.Fatalf("mempool len after connect=%d, want 0", got)
	}
	outpoints, claims, highWater := ownerClaimCount(f.owner)
	if outpoints != 0 || claims != 0 {
		t.Fatalf("owner still holds outpoints=%d claims=%d after connect", outpoints, claims)
	}
	if highWater != 1 {
		t.Fatalf("token high-water=%d, want the consumed sequence retained", highWater)
	}
	after := mustAdmissionContext(t, f.owner, "after the direct connect")
	if after.StableTip.Hash != summary.BlockHash || after.StableTip.Height != summary.BlockHeight {
		t.Fatalf("stable tip after=%+v, want the connected block (%d,%x)", after.StableTip, summary.BlockHeight, summary.BlockHash)
	}
	if after.Generation != before.Generation+1 {
		t.Fatalf("generation after=%d, want exactly one advance from %d", after.Generation, before.Generation)
	}
}

// TestSyncPendingOutpointCleanupFailureLatchesTerminalFault pins the row this
// fixture actually reaches, which is NOT an ordinary abort. Breaking a resident
// record's claim fails the standard cleanup, and then fails the ROLLBACK's
// restore too, because restoreMempoolSnapshot rebuilds that same broken record
// through validateRestoredClaimBinding and refuses it. An unprovable restore is
// terminal by contract (canonicalTransition.end), so the engine latches the
// storage-persistence fault and leaves admission closed.
//
// The name and the assertions therefore state the latch, not a recovery: the
// canonical tip is unmoved on BOTH ChainState and BlockStore, the owner never
// reopens, AdmissionContext stays unavailable, a later mutator gets the latched
// fault, and no block-apply outcome is recorded — a cleanup/rollback failure is
// an operational fault, never a consensus verdict on the block.
//
// There is deliberately no ordinary-abort variant of this row: production has no
// nonterminal cleanup-abort path here, and inventing one would need a test-only
// failure seam the contract forbids.
func TestSyncPendingOutpointCleanupFailureLatchesTerminalFault(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	spend := f.spend(t, 700, 1)
	if err := f.mempool.AddTx(spend); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	f.breakResidentClaim(t, txID(t, spend))

	beforeHash, beforeHeight := f.engine.chainState.TipHash, f.engine.chainState.Height
	beforeCounts := f.engine.BlockApplyCounts()
	if _, err := f.engine.ApplyBlock(f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, spend), nil); err == nil {
		t.Fatal("apply committed a block whose standard cleanup failed")
	}
	if f.engine.chainState.TipHash != beforeHash || f.engine.chainState.Height != beforeHeight {
		t.Fatalf("canonical tip moved to (%d,%x) despite the cleanup failure, want (%d,%x)",
			f.engine.chainState.Height, f.engine.chainState.TipHash, beforeHeight, beforeHash)
	}
	storeHeight, storeHash, ok, err := f.store.Tip()
	if err != nil || !ok || storeHash != beforeHash || storeHeight != beforeHeight {
		t.Fatalf("blockstore tip=(%d,%x,ok=%v,err=%v), want the pre-apply canonical tip (%d,%x)",
			storeHeight, storeHash, ok, err, beforeHeight, beforeHash)
	}
	// The exact latch state: owner closed, admission unavailable, and the
	// storage-persistence fault returned to every later SyncEngine mutator.
	if ctx, reopened := f.owner.AdmissionContext(); reopened {
		t.Fatalf("owner reopened at %+v after a cleanup failure whose restore could not be proven", ctx)
	}
	if _, err := f.engine.DisconnectTip(); !errors.Is(err, errStoragePersistenceFault) {
		t.Fatalf("later SyncEngine mutator err=%v, want the latched storage persistence fault", err)
	}
	if got := f.engine.BlockApplyCounts(); got != beforeCounts {
		t.Fatalf("block-apply counts=%+v after a cleanup/rollback fault, want %+v unchanged", got, beforeCounts)
	}
}

// TestSyncPendingOutpointAdmissionConcurrentWithDirectConnectSmoke is a -race
// smoke over the hostile row, NOT a forced interleaving: there is no seam that
// pins an admission inside the guard window, so the schedule is whatever the
// runtime picks. What it does pin, for every schedule, is the outcome invariant
// — the racing candidate never survives a connect that consumed its outpoint,
// no claim outlives the connected block, and the owner reopens afterwards.
func TestSyncPendingOutpointAdmissionConcurrentWithDirectConnectSmoke(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	included := f.spend(t, 700, 1)
	racing := f.spend(t, 690, 2)
	block := f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, included)

	admitted := make(chan error, 1)
	go func() { admitted <- f.mempool.AddTx(racing) }()
	if _, err := f.engine.ApplyBlock(block, nil); err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}
	admitErr := <-admitted

	// Whichever side won, the outpoint has exactly one owner afterwards, and it
	// is never the racing candidate: the block consumed the outpoint on chain.
	if f.mempool.Contains(txID(t, racing)) {
		t.Fatalf("racing candidate survived the connect (admit err=%v)", admitErr)
	}
	if _, ok := f.owner.txidForOutpoint(f.sourceOutpoint); ok {
		t.Fatal("a claim on the spent outpoint outlived the connected block")
	}
	if got := f.mempool.Len(); got != 0 {
		t.Fatalf("mempool len=%d after the race, want 0", got)
	}
	if _, ok := f.owner.AdmissionContext(); !ok {
		t.Fatal("owner did not reopen after the connect")
	}
}

// boundMempool reads the engine's current binding under the engine lock.
func boundMempool(engine *SyncEngine) *Mempool {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	return engine.mempool
}

// unboundEngineOn builds a SECOND engine over the fixture's exact ChainState and
// BlockStore, bound to nothing, so the initial-binding rows run against a live
// chain the fixture already advanced.
func (f *pendingOutpointSyncFixture) unboundEngineOn(t *testing.T) *SyncEngine {
	t.Helper()
	engine, err := NewSyncEngine(f.engine.chainState, f.store, f.engine.cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine(second): %v", err)
	}
	if bound := boundMempool(engine); bound != nil {
		t.Fatalf("fresh engine already bound to %p", bound)
	}
	return engine
}

// newPool builds another mempool over the fixture's exact ChainState and store.
func (f *pendingOutpointSyncFixture) newPool(t *testing.T) *Mempool {
	t.Helper()
	pool, err := NewMempool(f.engine.chainState, f.store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	return pool
}

// assertBindingRejected drives one refused SetMempool and proves it changed
// neither the engine binding nor the candidate's owner context.
func assertBindingRejected(t *testing.T, engine *SyncEngine, candidate, want *Mempool, what string) {
	t.Helper()
	var before PendingOutpointAdmissionContext
	if candidate != nil {
		before = mustAdmissionContext(t, candidate.PendingOutpointOwner(), "before "+what)
	}
	engine.SetMempool(candidate)
	if bound := boundMempool(engine); bound != want {
		t.Fatalf("%s: engine mempool=%p, want %p", what, bound, want)
	}
	if candidate == nil {
		return
	}
	if got := mustAdmissionContext(t, candidate.PendingOutpointOwner(), "after "+what); got != before {
		t.Fatalf("%s: candidate context=%+v, want %+v unchanged", what, got, before)
	}
}

// TestSyncSetMempoolPendingOutpointConstructOnceAndRejectsStaleOrNonemptyBinding
// proves SetMempool is initialization-only. A transition must own ONE
// pointer-identical ChainState, Mempool and owner for its whole duration, and a
// pointer comparison cannot see that a detached pool's records were validated
// against a canonical history this engine has already left: so exactly one fresh
// empty candidate at the guarded live tip binds, an exact same-pointer retry is
// a no-op, and every stale-tip, nonempty, foreign-ChainState, nil-unbind or
// different-pointer candidate is refused with no mutation on either side.
func TestSyncSetMempoolPendingOutpointConstructOnceAndRejectsStaleOrNonemptyBinding(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	fixtureContext := mustAdmissionContext(t, f.owner, "on the bound fixture pool")

	// An exact same-pointer rebind is the ONLY accepted post-binding call.
	f.engine.SetMempool(f.mempool)
	if bound := boundMempool(f.engine); bound != f.mempool || bound.PendingOutpointOwner() != f.owner {
		t.Fatalf("same-pointer rebind changed the binding to %p", bound)
	}
	if got := mustAdmissionContext(t, f.owner, "after the same-pointer rebind"); got != fixtureContext {
		t.Fatalf("same-pointer rebind moved the context to %+v, want %+v", got, fixtureContext)
	}
	assertBindingRejected(t, f.engine, nil, f.mempool, "nil unbind after the initial binding")

	// A different pointer is refused even when it is fresh, empty, bound to the
	// same ChainState and reporting the same apparent context.
	replacement := f.newPool(t)
	if got := mustAdmissionContext(t, replacement.PendingOutpointOwner(), "on the replacement"); got != fixtureContext {
		t.Fatalf("replacement context=%+v, want the same apparent context %+v", got, fixtureContext)
	}
	assertBindingRejected(t, f.engine, replacement, f.mempool, "different-pointer replacement")

	// Initial-binding rejections, on a second engine that never bound anything.
	engine := f.unboundEngineOn(t)
	foreign, err := NewMempool(NewChainState(), f.store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool(foreign): %v", err)
	}
	assertBindingRejected(t, engine, foreign, nil, "foreign-chainstate candidate")

	// A nonempty candidate at the exact live tip: its records were admitted
	// against a canonical tip this engine never guarded.
	if err := f.mempool.AddTx(f.spend(t, 700, 1)); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	assertBindingRejected(t, engine, f.mempool, nil, "nonempty candidate")
	outpoints, claims, _ := ownerClaimCount(f.owner)
	if f.mempool.Len() != 1 || outpoints != 1 || claims != 1 {
		t.Fatalf("rejected nonempty candidate holds len=%d outpoints=%d claims=%d, want its single record untouched",
			f.mempool.Len(), outpoints, claims)
	}

	// A stale candidate: built at the live tip, then left behind while the
	// canonical tip advanced, so its owner tip no longer matches the guard.
	stale := f.newPool(t)
	subsidy := consensus.BlockSubsidy(f.tipHeight+1, f.alreadyGenerated)
	next := buildSingleTxBlock(t, f.tipHash, f.target, 202, reorgTestCoinbaseForAddress(t, f.tipHeight+1, subsidy, f.sourceAddress))
	if _, err := f.engine.ApplyBlock(next, nil); err != nil {
		t.Fatalf("ApplyBlock(next): %v", err)
	}
	assertBindingRejected(t, engine, stale, nil, "stale-tip candidate")

	// And the accepted row: one fresh empty pool at the current guarded tip.
	fresh := f.newPool(t)
	engine.SetMempool(fresh)
	if bound := boundMempool(engine); bound != fresh || bound.PendingOutpointOwner() != fresh.PendingOutpointOwner() {
		t.Fatalf("engine mempool=%p, want the fresh current-tip candidate %p", bound, fresh)
	}
}

// poolFingerprint is the deep observable image of one candidate pool and its
// owner. A refused binding must leave it byte-for-byte identical, so the
// comparison covers every field the freshness boundary reads AND the static
// policy configuration it must NOT read, rather than a spot check of two.
type poolFingerprint struct {
	len               int
	bytesUsed         int
	wtxids            int
	lastAdmissionSeq  uint64
	currentMinFeeRate uint64
	admission         MempoolAdmissionCounts
	stats             MempoolStats
	policy            MempoolConfig
	ownerOutpoints    int
	ownerClaims       int
	ownerHighWater    uint64
	ownerGeneration   uint64
	ownerInTransition bool
	ownerStableTip    PendingOutpointTip
}

func fingerprintPool(pool *Mempool) poolFingerprint {
	owner := pool.PendingOutpointOwner()
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return poolFingerprint{
		len:               len(pool.txs),
		bytesUsed:         pool.usedBytes,
		wtxids:            len(pool.wtxids),
		lastAdmissionSeq:  pool.lastAdmissionSeq,
		currentMinFeeRate: pool.currentMinFeeRate,
		admission:         pool.AdmissionCounts(),
		stats: MempoolStats{
			TxCount: len(pool.txs), BytesUsed: pool.usedBytes, MaxBytes: pool.maxBytes,
			LowWaterBytes: pool.effectiveLowWaterBytesLocked(), MinFeeRate: pool.currentMinFeeRateLocked(),
			EvictedResidentTotal: pool.evictedResidentTotal.Load(),
		},
		policy:            pool.policy,
		ownerOutpoints:    len(owner.byOutpoint),
		ownerClaims:       len(owner.byToken),
		ownerHighWater:    owner.tokenHighWater,
		ownerGeneration:   owner.generation,
		ownerInTransition: owner.inTransition,
		ownerStableTip:    owner.stableTip,
	}
}

// assertFreshnessRefusal drives ONE SetMempool that must be refused and proves
// the refusal was mutation-free on both sides: the engine keeps its (absent)
// binding and the candidate's deep image is unchanged.
func assertFreshnessRefusal(t *testing.T, engine *SyncEngine, candidate *Mempool, what string) {
	t.Helper()
	before := fingerprintPool(candidate)
	engineBefore := engine.BlockApplyCounts()
	engine.SetMempool(candidate)
	if bound := boundMempool(engine); bound != nil {
		t.Fatalf("%s: engine bound %p, want the refusal to leave it unbound", what, bound)
	}
	if after := fingerprintPool(candidate); after != before {
		t.Fatalf("%s: candidate mutated on refusal\n got=%+v\nwant=%+v", what, after, before)
	}
	if after := engine.BlockApplyCounts(); after != engineBefore {
		t.Fatalf("%s: engine block-apply counts moved to %+v, want %+v", what, after, engineBefore)
	}
}

// TestSyncSetMempoolRejectsUsedEmptyHistory pins the freshness boundary that
// emptiness alone cannot express. A pool that admitted at some tip and was
// drained back to zero is index-identical to a fresh one; only its
// history-bearing state — admission sequence, rolling fee floor, cumulative
// admission and eviction counters, owner token high-water and generation — still
// records that its records were validated under a canonical history the binding
// engine never guarded. Every such candidate is refused, byte-for-byte
// mutation-free, through the real SetMempool entry point; custom STATIC policy
// configuration is not history and still binds.
func TestSyncSetMempoolRejectsUsedEmptyHistory(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)

	// The realistic used-then-emptied candidate, produced entirely through
	// production paths: admit a spend, then let the canonical connect clean it
	// out. Residents are back to zero and the owner's stable tip is the new live
	// tip, so nothing but the history state distinguishes it from fresh.
	spend := f.spend(t, 700, 1)
	if err := f.mempool.AddTx(spend); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	if _, err := f.engine.ApplyBlock(f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, spend), nil); err != nil {
		t.Fatalf("ApplyBlock(including spend): %v", err)
	}
	if drained := fingerprintPool(f.mempool); drained.len != 0 || drained.ownerClaims != 0 {
		t.Fatalf("the used candidate is not drained: %+v", drained)
	}

	// A FRESH unbound engine per row. Sharing one would couple the rows: the
	// first row that wrongly bound would make every later row fail on the
	// already-bound pointer instead of on its own term, hiding which guard
	// actually holds.
	t.Run("used-then-emptied candidate", func(t *testing.T) {
		assertFreshnessRefusal(t, f.unboundEngineOn(t), f.mempool, "used-then-emptied candidate")
	})

	// Each isolated taint below is applied to its OWN otherwise-fresh pool at the
	// current live tip, so every guard is proven to fire on its own rather than
	// being masked by the combined row above. Every row is its own subtest so a
	// regression names the exact term of the boundary that stopped holding.
	for _, tc := range []struct {
		name  string
		taint func(t *testing.T, pool *Mempool)
	}{
		{"nonzero admission sequence", func(_ *testing.T, pool *Mempool) {
			pool.mu.Lock()
			defer pool.mu.Unlock()
			pool.lastAdmissionSeq = 1
		}},
		{"raised then partially decayed rolling floor", func(_ *testing.T, pool *Mempool) {
			pool.mu.Lock()
			defer pool.mu.Unlock()
			pool.currentMinFeeRate = 8
			pool.decayMinFeeRateAfterConnectedBlockLocked() // 8 -> 4, still above the default
		}},
		// The row the RAW read exists for: the accessor reports a below-default
		// floor AS the default, so a regression to it would accept this pool.
		{"below-default raw rolling floor", func(_ *testing.T, pool *Mempool) {
			pool.SetCurrentMinFeeRateForTest(0)
		}},
		{"cumulative accepted counter", func(_ *testing.T, pool *Mempool) { pool.admitAccepted.Add(1) }},
		{"cumulative conflict counter", func(_ *testing.T, pool *Mempool) { pool.admitConflict.Add(1) }},
		{"cumulative rejected counter", func(_ *testing.T, pool *Mempool) { pool.admitRejected.Add(1) }},
		{"cumulative unavailable counter", func(_ *testing.T, pool *Mempool) { pool.admitUnavailable.Add(1) }},
		{"cumulative eviction counter", func(_ *testing.T, pool *Mempool) { pool.evictedResidentTotal.Add(1) }},
		{"owner token high-water without live claims", func(t *testing.T, pool *Mempool) {
			owner := pool.PendingOutpointOwner()
			ctx := mustAdmissionContext(t, owner, "on the taint pool")
			token, err := owner.Reserve(ctx, PendingOutpointStandardMempool, [32]byte{0x07}, []consensus.Outpoint{f.sourceOutpoint})
			if err != nil {
				t.Fatalf("Reserve: %v", err)
			}
			if err := owner.Release(token); err != nil {
				t.Fatalf("Release: %v", err)
			}
		}},
		{"owner generation advanced by an aborted transition", func(t *testing.T, pool *Mempool) {
			owner := pool.PendingOutpointOwner()
			if _, err := owner.beginTransition(); err != nil {
				t.Fatalf("beginTransition: %v", err)
			}
			owner.endTransitionAborted()
		}},
		{"owner transition still active", func(t *testing.T, pool *Mempool) {
			if _, err := pool.PendingOutpointOwner().beginTransition(); err != nil {
				t.Fatalf("beginTransition: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := f.newPool(t)
			tc.taint(t, pool)
			assertFreshnessRefusal(t, f.unboundEngineOn(t), pool, tc.name)
		})
	}

	// The accepted row: a never-used pool carrying CUSTOM static policy still
	// binds, and its configuration survives the binding untouched. Only the nil
	// providers the engine fills in may change.
	cfg := DefaultMempoolConfig()
	cfg.MaxTransactions, cfg.MaxBytes, cfg.MinDaFeeRate = 7, 999_999, 3
	cfg.PolicyRejectNonCoinbaseAnchorOutputs = !cfg.PolicyRejectNonCoinbaseAnchorOutputs
	custom, err := NewMempoolWithConfig(f.engine.chainState, f.store, devnetGenesisChainID, cfg)
	if err != nil {
		t.Fatalf("NewMempoolWithConfig: %v", err)
	}
	accepting := f.unboundEngineOn(t)
	accepting.SetMempool(custom)
	if bound := boundMempool(accepting); bound != custom {
		t.Fatalf("engine mempool=%p, want the never-used custom-policy candidate %p", bound, custom)
	}
	got := fingerprintPool(custom)
	if got.policy.MaxTransactions != 7 || got.policy.MaxBytes != 999_999 || got.policy.MinDaFeeRate != 3 ||
		got.policy.PolicyRejectNonCoinbaseAnchorOutputs != cfg.PolicyRejectNonCoinbaseAnchorOutputs {
		t.Fatalf("binding altered the custom static policy: %+v", got.policy)
	}
}

// TestSyncSetMempoolBindingIsAtomicAgainstConcurrentAdmission proves the
// never-used decision is a DECISION, not a sample: the binding holds the guard
// EXCLUSIVELY, so an admission lifecycle — validate, insert, count — falls
// wholly before or wholly after it, never straddling it.
func TestSyncSetMempoolBindingIsAtomicAgainstConcurrentAdmission(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	// A distinguishable provider the binding fills in: proof of whose policy won.
	registry := consensus.DefaultSuiteRegistry()
	cfg := f.engine.cfg
	cfg.SuiteRegistry = registry
	newEngine := func(t *testing.T) *SyncEngine {
		t.Helper()
		engine, err := NewSyncEngine(f.engine.chainState, f.store, cfg)
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		return engine
	}
	// Phase 1 — the exclusion itself, deterministically. An in-flight admission
	// lifecycle IS a held read guard: under the old read guard the binding decided
	// straight through one, sampling a pool that had not yet inserted or counted.
	// Bounded in the safe direction — the only way to fail is completing early.
	blocked, held := newEngine(t), f.newPool(t)
	f.engine.chainState.admissionMu.RLock()
	decided := make(chan struct{})
	go func() { defer close(decided); blocked.SetMempool(held) }()
	select {
	case <-decided:
		f.engine.chainState.admissionMu.RUnlock()
		t.Fatal("SetMempool decided while an admission lifecycle still held the guard")
	case <-time.After(150 * time.Millisecond):
	}
	f.engine.chainState.admissionMu.RUnlock()
	<-decided
	if got := boundMempool(blocked); got != held {
		t.Fatalf("engine bound %p once the guard was released, want %p", got, held)
	}

	// Phase 2 — the binding-first serialization, DETERMINISTICALLY: bind, then
	// admit. Every admission necessarily ran after the binding, so it must land
	// in the bound pool under the policy the engine completed.
	spends := [2][]byte{f.spend(t, 700, 1), f.spend(t, 690, 2)}
	first, firstPool := newEngine(t), f.newPool(t)
	first.SetMempool(firstPool)
	if got := boundMempool(first); got != firstPool {
		t.Fatalf("binding-first: engine bound %p, want the fresh candidate %p", got, firstPool)
	}
	var firstWg sync.WaitGroup
	firstWg.Add(len(spends))
	for i := range spends {
		go func(i int) { defer firstWg.Done(); _ = firstPool.AddTx(spends[i]) }(i)
	}
	firstWg.Wait()
	if fp := fingerprintPool(firstPool); fp.policy.SuiteRegistry != registry || fp.admission.Accepted != 1 || fp.len != 1 || fp.ownerClaims != 1 {
		t.Fatalf("binding-first: %+v residents=%d claims=%d registry=%v, want one admitted entry under the engine's policy", fp.admission, fp.len, fp.ownerClaims, fp.policy.SuiteRegistry)
	}

	// Phase 3 — unconstrained race, deliberately NEUTRAL on which serialization
	// occurs: it pins only that whichever happens is one of exactly those two.
	for iter := 0; iter < 12; iter++ {
		engine, pool := newEngine(t), f.newPool(t)
		var wg sync.WaitGroup
		wg.Add(len(spends) + 1)
		for i := range spends {
			go func(i int) { defer wg.Done(); _ = pool.AddTx(spends[i]) }(i)
		}
		go func() { defer wg.Done(); engine.SetMempool(pool) }()
		wg.Wait()

		fp := fingerprintPool(pool)
		counted := fp.admission.Accepted + fp.admission.Conflict + fp.admission.Rejected + fp.admission.Unavailable
		// True of BOTH: one count per call, one claim per resident.
		if counted != uint64(len(spends)) || fp.len != int(fp.admission.Accepted) || fp.ownerClaims != fp.len || fp.ownerOutpoints != fp.len {
			t.Fatalf("iter %d: %+v residents=%d claims=%d outpoints=%d, want %d counts in bijection", iter, fp.admission, fp.len, fp.ownerClaims, fp.ownerOutpoints, len(spends))
		}
		got := boundMempool(engine)
		if got == nil { // A: an admission won the guard, so the pool had history.
			if counted == 0 {
				t.Fatalf("iter %d: refused a pool with no admission history", iter)
			}
			continue
		}
		if got != pool || fp.policy.SuiteRegistry != registry { // B: binding won.
			t.Fatalf("iter %d: bound %p want %p, registry %v", iter, got, pool, fp.policy.SuiteRegistry)
		}
	}
}

// TestSyncPendingOutpointUnprovenRestoreLatchesAdmissionClosed pins the
// fail-closed rule for a rollback whose EXACT restore failed: admission must not
// reopen over a state nobody can prove. The transition is made to fail at the
// standard cleanup and its restore is made to fail as well (an invalid mempool
// capacity limit), so the engine takes the terminal latch, not an ordinary abort.
func TestSyncPendingOutpointUnprovenRestoreLatchesAdmissionClosed(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	spend := f.spend(t, 700, 1)
	if err := f.mempool.AddTx(spend); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	f.breakResidentClaim(t, txID(t, spend))
	f.mempool.mu.Lock()
	f.mempool.maxTxs = 0 // the rollback's mempool restore now fails too
	f.mempool.mu.Unlock()

	block := f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, spend)
	if _, err := f.engine.ApplyBlock(block, nil); err == nil {
		t.Fatal("apply reported success although its restore could not be proven")
	}
	if ctx, ok := f.owner.AdmissionContext(); ok {
		t.Fatalf("owner reopened at %+v after an unproven restore", ctx)
	}
	if _, err := f.engine.DisconnectTip(); !errors.Is(err, errStoragePersistenceFault) {
		t.Fatalf("later SyncEngine mutator err=%v, want the latched storage persistence fault", err)
	}
}

// TestSyncPendingOutpointCorruptCanonicalIndexOutranksConsensusRejection pins
// the hostile row on BOTH canonical paths. Each subtest applies the SAME
// consensus-invalid candidate twice: against a healthy index, proving the path
// really reaches consensus validation, and against a malformed one, where the
// local index error must win.
//
// On the direct path that precedence IS the rollback preflight, and removing it
// reddens this test. On the reorg path branch collection scans the same index
// first, so the preflight cannot be observed here; its value there — supplying
// the EXACT rollback index — is pinned instead by
// TestApplyBlockWithReorgRollbackRestoresCanonicalIndexAndChainstateFile, which
// fails outright when the preflight is removed.
func TestSyncPendingOutpointCorruptCanonicalIndexOutranksConsensusRejection(t *testing.T) {
	// Height 0 is outside every MTP window these candidates read, so the
	// corruption reaches the preflight rather than an earlier context read.
	corrupt := func(f *pendingOutpointSyncFixture) {
		f.store.stateMu.Lock()
		f.store.index.Canonical[0] = "zz"
		f.store.stateMu.Unlock()
	}
	assertConsensusError := func(t *testing.T, err error) {
		t.Helper()
		var txErr *consensus.TxError
		if !errors.As(err, &txErr) {
			t.Fatalf("healthy-index err=%v, want a consensus rejection", err)
		}
	}
	assertIndexError := func(t *testing.T, err error) {
		t.Helper()
		var txErr *consensus.TxError
		if err == nil || errors.As(err, &txErr) || !strings.Contains(err.Error(), "canonical[0]") {
			t.Fatalf("err=%v, want the canonical[0] index error rather than a consensus rejection", err)
		}
	}
	coinbaseAt := func(t *testing.T, f *pendingOutpointSyncFixture, height, alreadyGenerated uint64) []byte {
		t.Helper()
		return reorgTestCoinbaseForAddress(t, height, consensus.BlockSubsidy(height, alreadyGenerated), f.sourceAddress)
	}

	t.Run("direct connect", func(t *testing.T) {
		f := newPendingOutpointSyncFixture(t)
		// Timestamp 1 is at or below the canonical MTP: consensus-invalid.
		invalid := buildSingleTxBlock(t, f.tipHash, f.target, 1, coinbaseAt(t, f, f.tipHeight+1, f.alreadyGenerated))
		_, err := f.engine.ApplyBlockWithReorg(invalid, nil)
		assertConsensusError(t, err)
		corrupt(f)
		_, err = f.engine.ApplyBlockWithReorg(invalid, nil)
		assertIndexError(t, err)
	})

	t.Run("preferred branch reorg", func(t *testing.T) {
		f := newPendingOutpointSyncFixture(t)
		height, generated := f.tipHeight+1, f.alreadyGenerated
		canonical := buildSingleTxBlock(t, f.tipHash, f.target, 500, coinbaseAt(t, f, height, generated))
		if _, err := f.engine.ApplyBlockWithReorg(canonical, nil); err != nil {
			t.Fatalf("ApplyBlockWithReorg(canonical): %v", err)
		}
		// The losing branch's first block is seeded straight into the store:
		// through fork choice it would tie on work, and a tie-break win would
		// make the final block a direct connect instead of the reorg this row
		// needs. Two blocks then outweigh the one-block canonical extension.
		side1 := buildSingleTxBlock(t, f.tipHash, f.target, 501, coinbaseAt(t, f, height, generated))
		parsed1, side1Hash := mustParseReorgBlockForTest(t, side1)
		if err := f.store.StoreBlock(side1Hash, parsed1.HeaderBytes, side1); err != nil {
			t.Fatalf("StoreBlock(side1): %v", err)
		}
		side2 := buildSingleTxBlock(t, side1Hash, f.target, 1, coinbaseAt(t, f, height+1, generated+consensus.BlockSubsidy(height, generated)))
		_, err := f.engine.ApplyBlockWithReorg(side2, nil)
		assertConsensusError(t, err)
		corrupt(f)
		_, err = f.engine.ApplyBlockWithReorg(side2, nil)
		assertIndexError(t, err)
	})
}
