package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
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
	err := (&SyncEngine{}).recheckCanonicalTransitionFreshness(&canonicalTransition{chainState: state}, &canonicalTransitionPlan{priorTip: prior})
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

// TestCanonicalBlockRelayTerminalNew pins TERMINAL_PERSISTENCE(new) end to end:
// an AMBIGUOUS canonical-index write whose strict readback finds the exact
// planned-new identity publishes the complete C/M/O/A1 image and its NEW summary,
// returns the terminal error and latches admission. A readback that proves
// neither identity is UNKNOWN and publishes nothing, and a proven pre-namespace
// refusal preserves OLD with no summary at all.
func TestCanonicalBlockRelayTerminalNew(t *testing.T) {
	injectIndexSync := func(t *testing.T, store *BlockStore) *bool {
		t.Helper()
		failed := new(bool)
		withAtomicWriteOps(t, func(ops *atomicWriteOps) {
			syncParent := ops.syncParent
			ops.syncParent = func(parent string) error {
				if !*failed && parent == store.rootPath {
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
		failed := injectIndexSync(t, store)
		summary, err := engine.ApplyBlockWithReorg(DevnetGenesisBlockBytes(), nil)
		if !*failed || summary == nil || !errors.Is(err, os.ErrPermission) || summary.BlockHash != devnetGenesisBlockHash || len(summary.CanonicalAppliedBlocks) != 1 {
			t.Fatalf("failed=%v summary=%+v err=%v", *failed, summary, err)
		}
		if !engine.persistenceFaulted() {
			t.Fatal("terminal NEW did not latch the engine")
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
		failed := injectIndexSync(t, engine.blockStore)
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

	t.Run("unreadable readback is UNKNOWN", func(t *testing.T) {
		engine, store, _ := newPersistenceFaultEngine(t)
		failed := injectIndexSync(t, store)
		reads := 0
		withLoadBlockStoreIndexFn(t, func(string) (blockStoreIndexDisk, []byte, error) {
			reads++
			return blockStoreIndexDisk{}, nil, os.ErrInvalid
		})
		summary, err := engine.ApplyBlockWithReorg(DevnetGenesisBlockBytes(), nil)
		if !*failed || summary != nil || !errors.Is(err, os.ErrPermission) || !errors.Is(err, os.ErrInvalid) || reads != 1 {
			t.Fatalf("failed=%v summary=%+v err=%v reads=%d", *failed, summary, err, reads)
		}
		if !engine.persistenceFaulted() || engine.chainState.view().hasTip {
			t.Fatalf("UNKNOWN latch=%v tip=%v, want a latched engine that published nothing", engine.persistenceFaulted(), engine.chainState.view().hasTip)
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
	// The durable snapshot is the precommit CHECKPOINT at the highest row both
	// identities share — here the pre-apply genesis tip — not the new tip: no
	// fallible postcommit tip save exists. Startup reconcile replays the suffix
	// from it, which is what makes either identity recoverable.
	if !loaded.HasTip || loaded.Height != 0 || loaded.TipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected persisted checkpoint: has_tip=%v height=%d tip=%x", loaded.HasTip, loaded.Height, loaded.TipHash)
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

// breakResidentClaim rebinds a resident record to a foreign owner's token so
// complete canonical M/O planning rejects the malformed record/claim image.
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

// TestSyncPendingOutpointPlanningInvariantLatchesTerminalFault pins the row this
// fixture actually reaches, which is NOT an ordinary abort. Breaking a resident
// record's claim fails complete canonical M/O planning before C publication.
// That local invariant is terminal by contract (canonicalTransition.end), so
// the engine latches the storage-persistence fault and leaves admission closed.
//
// The name and the assertions therefore state the latch, not a recovery: the
// canonical tip is unmoved on BOTH ChainState and BlockStore, the owner never
// reopens, AdmissionContext stays unavailable, a later mutator gets the latched
// fault, and no block-apply outcome is recorded — a planning-invariant failure is
// an operational fault, never a consensus verdict on the block.
//
// There is deliberately no ordinary-abort variant of this row: production has no
// nonterminal planning-abort path here, and inventing one would need a test-only
// failure seam the contract forbids.
func TestSyncPendingOutpointPlanningInvariantLatchesTerminalFault(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	spend := f.spend(t, 700, 1)
	if err := f.mempool.AddTx(spend); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	f.breakResidentClaim(t, txID(t, spend))

	beforeHash, beforeHeight := f.engine.chainState.TipHash, f.engine.chainState.Height
	beforeCounts := f.engine.BlockApplyCounts()
	if _, err := f.engine.ApplyBlock(f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, spend), nil); err == nil {
		t.Fatal("apply committed a block whose canonical M/O plan was invalid")
	}
	if f.engine.chainState.TipHash != beforeHash || f.engine.chainState.Height != beforeHeight {
		t.Fatalf("canonical tip moved to (%d,%x) despite the planning failure, want (%d,%x)",
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
		t.Fatalf("owner reopened at %+v after a terminal planning invariant", ctx)
	}
	if _, err := f.engine.DisconnectTip(); !errors.Is(err, errStoragePersistenceFault) {
		t.Fatalf("later SyncEngine mutator err=%v, want the latched storage persistence fault", err)
	}
	if got := f.engine.BlockApplyCounts(); got != beforeCounts {
		t.Fatalf("block-apply counts=%+v after a terminal planning fault, want %+v unchanged", got, beforeCounts)
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
	stateBefore := engine.DARelayState()
	var before PendingOutpointAdmissionContext
	if candidate != nil {
		before = mustAdmissionContext(t, candidate.PendingOutpointOwner(), "before "+what)
	}
	engine.SetMempool(candidate)
	if bound := boundMempool(engine); bound != want {
		t.Fatalf("%s: engine mempool=%p, want %p", what, bound, want)
	}
	if state := engine.DARelayState(); state != stateBefore {
		t.Fatalf("%s: engine DA relay=%p, want %p unchanged", what, state, stateBefore)
	}
	if candidate == nil {
		return
	}
	if got := mustAdmissionContext(t, candidate.PendingOutpointOwner(), "after "+what); got != before {
		t.Fatalf("%s: candidate context=%+v, want %+v unchanged", what, got, before)
	}
}

// TestSetMempoolCoBindsDARelayState
// proves SetMempool is initialization-only. A transition must own ONE
// pointer-identical ChainState, Mempool and owner for its whole duration, and a
// pointer comparison cannot see that a detached pool's records were validated
// against a canonical history this engine has already left: so exactly one fresh
// empty candidate at the guarded live tip binds, an exact same-pointer retry is
// a no-op, and every stale-tip, nonempty, foreign-ChainState, nil-unbind or
// different-pointer candidate is refused with no mutation on either side.
func TestSetMempoolCoBindsDARelayState(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	fixtureContext := mustAdmissionContext(t, f.owner, "on the bound fixture pool")
	relay := f.engine.DARelayState()
	if relay == nil {
		t.Fatal("initial binding did not publish DA relay")
	}
	if relay.mempool != f.mempool {
		t.Fatalf("initial DA relay mempool=%p, want exact pool %p", relay.mempool, f.mempool)
	}

	// An exact same-pointer rebind is the ONLY accepted post-binding call.
	f.engine.SetMempool(f.mempool)
	if bound := boundMempool(f.engine); bound != f.mempool || bound.PendingOutpointOwner() != f.owner {
		t.Fatalf("same-pointer rebind changed the binding to %p", bound)
	}
	if got := mustAdmissionContext(t, f.owner, "after the same-pointer rebind"); got != fixtureContext {
		t.Fatalf("same-pointer rebind moved the context to %+v, want %+v", got, fixtureContext)
	}
	if got := f.engine.DARelayState(); got != relay {
		t.Fatalf("same-pointer rebind replaced DA relay %p with %p", relay, got)
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

func TestSetMempoolRejectionDoesNotPublishDARelayState(t *testing.T) {
	TestSetMempoolCoBindsDARelayState(t)
}

func TestSetMempoolConcurrentCandidatesKeepOneDARelayPair(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	engine := f.unboundEngineOn(t)
	pools := []*Mempool{f.newPool(t), f.newPool(t)}
	start, entered, done := make(chan struct{}), make(chan struct{}, 2), make(chan struct{}, 2)
	engine.mutationMu.Lock()
	for _, pool := range pools {
		go func(pool *Mempool) { <-start; entered <- struct{}{}; engine.SetMempool(pool); done <- struct{}{} }(pool)
	}
	close(start)
	for range pools {
		<-entered
	}
	select {
	case <-done:
		engine.mutationMu.Unlock()
		t.Fatal("SetMempool completed while mutation lock was held")
	default:
	}
	engine.mutationMu.Unlock()
	for range pools {
		<-done
	}
	bound, relay := boundMempool(engine), engine.DARelayState()
	if (bound != pools[0] && bound != pools[1]) || relay == nil || relay.mempool != bound {
		t.Fatalf("bound=%p relay=%p relay.mempool=%p", bound, relay, relay.mempool)
	}
}

func TestClaimDARelayStateSecondClaimRejected(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	want := f.engine.DARelayState()
	if got := f.engine.DARelayState(); got != want {
		t.Fatalf("getter=%p, want %p", got, want)
	}
	if got, err := f.engine.ClaimDARelayState(); err != nil || got != want {
		t.Fatalf("first claim state=%p err=%v, want %p nil", got, err, want)
	}
	f.engine.SetMempool(f.mempool)
	if got, err := f.engine.ClaimDARelayState(); got != nil || err == nil || err.Error() != "sync engine DA relay state is already claimed" {
		t.Fatalf("second claim state=%p err=%v", got, err)
	}
	for _, engine := range []*SyncEngine{nil, {}} {
		if _, err := engine.ClaimDARelayState(); err == nil || err.Error() != "sync engine DA relay state is not initialized" {
			t.Fatalf("uninitialized claim: %v", err)
		}
	}
}

func TestClaimDARelayStateConcurrentSingleWinner(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	want := f.engine.DARelayState()
	type result struct {
		state *DARelayState
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			state, err := f.engine.ClaimDARelayState()
			results <- result{state, err}
		}()
	}
	close(start)
	winners := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			if result.state != want {
				t.Fatal("wrong winning state")
			}
			winners++
			continue
		}
		if result.state != nil || result.err.Error() != "sync engine DA relay state is already claimed" {
			t.Fatal("wrong losing claim")
		}
	}
	if winners != 1 {
		t.Fatalf("claim winners=%d, want one", winners)
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
			pool.currentMinFeeRate = canonicalMempoolFeeFloor(pool.currentMinFeeRate, pool.usedBytes, pool.effectiveLowWaterBytesLocked(), 1)
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

// TestSyncPendingOutpointMalformedPlanLatchesAdmissionClosed keeps the
// fail-closed admission assertion for a malformed mempool limit: complete M/O
// planning rejects it before C publication and terminally retains the guard.
func TestSyncPendingOutpointMalformedPlanLatchesAdmissionClosed(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	spend := f.spend(t, 700, 1)
	f.mempool.mu.Lock()
	f.mempool.maxTxs = 0
	f.mempool.mu.Unlock()

	block := f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, spend)
	if _, err := f.engine.ApplyBlock(block, nil); err == nil {
		t.Fatal("apply reported success with a malformed canonical M/O plan")
	}
	if ctx, ok := f.owner.AdmissionContext(); ok {
		t.Fatalf("owner reopened at %+v after a terminal malformed plan", ctx)
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

// countCanonicalIndexWrites installs the canonical-index write seam and returns
// the running count of writes aimed at that store's index, so a test can pin
// "exactly one prepared commit per transition" from the write itself.
func countCanonicalIndexWrites(t *testing.T, store *BlockStore) *int {
	t.Helper()
	writes, write := new(int), writeFileAtomicFn
	withWriteFileAtomicFn(t, func(path string, data []byte, mode os.FileMode) error {
		if path == store.indexPath {
			*writes++
		}
		return write(path, data, mode)
	})
	return writes
}

// newCutoverEngine builds a persistent engine on an EMPTY store, so a test can
// drive the bootstrap transition itself.
func newCutoverEngine(t *testing.T) (*SyncEngine, *BlockStore, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	return engine, store, dir
}

// TestCanonicalCutoverDirectAndBootstrapCommitTruth pins the direct and
// bootstrap rows: each transition derives one plan, writes the canonical index
// EXACTLY once, and exposes C/M/O, A1 and the summary only after that commit
// selected NEW. The durable checkpoint left behind is the highest row common to
// both identities — the pre-apply image — which is what lets restart replay
// either suffix.
func TestCanonicalCutoverDirectAndBootstrapCommitTruth(t *testing.T) {
	engine, store, dir := newCutoverEngine(t)
	mp, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mp)
	owner := mp.PendingOutpointOwner()
	before, ok := owner.AdmissionContext()
	if !ok {
		t.Fatal("owner unavailable before bootstrap")
	}

	writes := countCanonicalIndexWrites(t, store)
	if err := engine.BootstrapCanonicalGenesisIfEmpty(); err != nil {
		t.Fatalf("BootstrapCanonicalGenesisIfEmpty: %v", err)
	}
	if *writes != 1 {
		t.Fatalf("bootstrap canonical index writes=%d, want exactly 1", *writes)
	}
	// The bootstrap checkpoint is the exact empty pre-genesis state.
	checkpoint, err := LoadChainState(ChainStatePath(dir))
	if err != nil {
		t.Fatalf("LoadChainState(bootstrap checkpoint): %v", err)
	}
	if checkpoint.HasTip || len(checkpoint.Utxos) != 0 {
		t.Fatalf("bootstrap checkpoint=(hasTip=%v,utxos=%d), want the empty pre-genesis image", checkpoint.HasTip, len(checkpoint.Utxos))
	}
	after, ok := owner.AdmissionContext()
	if !ok || after.Generation != before.Generation+1 || after.StableTip.Hash != devnetGenesisBlockHash || !after.StableTip.HasTip {
		t.Fatalf("bootstrap owner=%+v ok=%v, want one generation advance bound to C1", after, ok)
	}
	index, err := store.CanonicalIndexSnapshot()
	if err != nil || len(index) != 1 || index[0] != hex.EncodeToString(devnetGenesisBlockHash[:]) {
		t.Fatalf("bootstrap index=%v err=%v", index, err)
	}

	// Bootstrap never reports success on a LATCHED engine. An UNTAGGED commit
	// failure over a write that really landed classifies as
	// TERMINAL_PERSISTENCE(new): C1 publishes, so a tip appears, and the race
	// tolerance would otherwise read that tip as "someone else bootstrapped".
	t.Run("bootstrap never reports success on a latched engine", func(t *testing.T) {
		latched, latchedStore, _ := newCutoverEngine(t)
		write, injected := writeFileAtomicFn, false
		withWriteFileAtomicFn(t, func(path string, data []byte, mode os.FileMode) error {
			if path == latchedStore.indexPath && !injected {
				injected = true
				if err := write(path, data, mode); err != nil {
					return err
				}
				return errors.New("untagged canonical index commit failure")
			}
			return write(path, data, mode)
		})
		err := latched.BootstrapCanonicalGenesisIfEmpty()
		if !injected || err == nil {
			t.Fatalf("injected=%v err=%v, want the terminal cause surfaced", injected, err)
		}
		if !latched.persistenceFaulted() || !latched.chainState.view().hasTip {
			t.Fatalf("latch=%v tip=%v, want a latched engine that published C1", latched.persistenceFaulted(), latched.chainState.view().hasTip)
		}
	})

	genesisView := engine.chainState.view()
	target := consensus.POW_LIMIT
	block := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
	*writes = 0
	summary, err := engine.ApplyBlock(block, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(1): %v", err)
	}
	if *writes != 1 {
		t.Fatalf("direct canonical index writes=%d, want exactly 1", *writes)
	}
	if len(summary.CanonicalAppliedBlocks) != 1 || summary.CanonicalAppliedBlocks[0].Hash != summary.BlockHash {
		t.Fatalf("A1=%+v, want exactly one row for the newly canonical block", summary.CanonicalAppliedBlocks)
	}
	// The direct checkpoint is the OLD tip: the highest row both identities share.
	checkpoint, err = LoadChainState(ChainStatePath(dir))
	if err != nil {
		t.Fatalf("LoadChainState(direct checkpoint): %v", err)
	}
	if !checkpoint.HasTip || checkpoint.Height != genesisView.height || checkpoint.TipHash != genesisView.tipHash {
		t.Fatalf("direct checkpoint=(%d,%x), want the pre-apply tip (%d,%x)", checkpoint.Height, checkpoint.TipHash, genesisView.height, genesisView.tipHash)
	}
	if live := engine.chainState.view(); live.height != summary.BlockHeight || live.tipHash != summary.BlockHash {
		t.Fatalf("live tip=(%d,%x), want the published C1", live.height, live.tipHash)
	}
	if tip, ok := owner.AdmissionContext(); !ok || tip.StableTip.Hash != summary.BlockHash {
		t.Fatalf("owner stable tip=%+v ok=%v, want C1", tip, ok)
	}

	// The store and the chainstate must agree on the parent HASH, not only on
	// the height: an index whose last row names a different block is refused
	// before staging, with nothing written and no latch.
	t.Run("parent hash disagreement refuses before staging", func(t *testing.T) {
		// Same length, same members, wrong position: every row still resolves to a
		// stored block, so nothing upstream of the plan can catch this.
		canonical := []string{hex.EncodeToString(devnetGenesisBlockHash[:]), hex.EncodeToString(summary.BlockHash[:])}
		foreign := []string{canonical[1], canonical[0]}
		if err := store.RestoreCanonicalIndex(foreign); err != nil {
			t.Fatalf("RestoreCanonicalIndex: %v", err)
		}
		beforeArtifacts := durableStoreFingerprint(t, store)
		mismatchWrites := countCanonicalIndexWrites(t, store)
		next := buildSingleTxBlock(t, summary.BlockHash, target, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, consensus.BlockSubsidy(2, consensus.BlockSubsidy(1, 0))))
		refused, err := engine.ApplyBlock(next, nil)
		if refused != nil || err == nil || !strings.Contains(err.Error(), "is not the canonical row at height 1") {
			t.Fatalf("summary=%+v err=%v, want the parent-row refusal", refused, err)
		}
		if *mismatchWrites != 0 || engine.persistenceFaulted() {
			t.Fatalf("index writes=%d latch=%v, want an OLD/open refusal", *mismatchWrites, engine.persistenceFaulted())
		}
		if got := durableStoreFingerprint(t, store); got != beforeArtifacts {
			t.Fatalf("the refusal staged artifacts:\n got=%s\nwant=%s", got, beforeArtifacts)
		}
		if err := store.RestoreCanonicalIndex(canonical); err != nil {
			t.Fatalf("RestoreCanonicalIndex(repair): %v", err)
		}
	})

	// A refused commit is OLD/open: no publication, no counter, no latch.
	beforeCounts, beforeView := engine.BlockApplyCounts(), engine.chainState.view()
	next := buildSingleTxBlock(t, summary.BlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, consensus.BlockSubsidy(2, consensus.BlockSubsidy(1, 0))))
	write := writeFileAtomicFn
	withWriteFileAtomicFn(t, func(path string, data []byte, mode os.FileMode) error {
		if path == store.indexPath {
			return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
		}
		return write(path, data, mode)
	})
	refused, err := engine.ApplyBlock(next, nil)
	if refused != nil || err == nil || engine.persistenceFaulted() {
		t.Fatalf("refused commit summary=%+v err=%v latch=%v", refused, err, engine.persistenceFaulted())
	}
	if engine.chainState.view() != beforeView || engine.BlockApplyCounts() != beforeCounts {
		t.Fatalf("refused commit published state=%+v counts=%+v", engine.chainState.view(), engine.BlockApplyCounts())
	}
	if _, ok := owner.AdmissionContext(); !ok {
		t.Fatal("refused commit left admission closed")
	}
}

// TestCanonicalCutoverStandaloneDisconnectOneCommit pins the standalone
// disconnect row: one commit, an EMPTY A1, and therefore zero connected-block
// fee decay.
func TestCanonicalCutoverStandaloneDisconnectOneCommit(t *testing.T) {
	f := newCanonicalMOFixture(t, 1, MempoolConfig{})
	if err := f.applyCoinbase(t); err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}
	f.mp.SetCurrentMinFeeRateForTest(64)
	beforeFloor := f.mp.CurrentMinFeeRateSnapshot()
	beforeIndex, err := f.store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot: %v", err)
	}

	writes := countCanonicalIndexWrites(t, f.store)
	summary, err := f.engine.DisconnectTip()
	if err != nil {
		t.Fatalf("DisconnectTip: %v", err)
	}
	if *writes != 1 {
		t.Fatalf("disconnect canonical index writes=%d, want exactly 1", *writes)
	}
	if got := f.mp.CurrentMinFeeRateSnapshot(); got != beforeFloor {
		t.Fatalf("fee floor=%d after a standalone disconnect, want the unchanged %d (no A1 row, no decay event)", got, beforeFloor)
	}
	afterIndex, err := f.store.CanonicalIndexSnapshot()
	if err != nil || len(afterIndex) != len(beforeIndex)-1 {
		t.Fatalf("index after disconnect=%v err=%v, want one row shorter", afterIndex, err)
	}
	if summary.NewHeight != uint64(len(afterIndex))-1 {
		t.Fatalf("disconnect summary=%+v, want the parent height", summary)
	}
	if tip, ok := f.mp.PendingOutpointOwner().AdmissionContext(); !ok || tip.StableTip.Height != summary.NewHeight {
		t.Fatalf("owner stable tip=%+v ok=%v, want the disconnected parent", tip, ok)
	}
}

// TestCanonicalCutoverApplyPlanMetadataBounds pins the exact charge formula
// 48 + 40*(disconnect_rows+connect_rows) + 32*sum(len(A1[row].CompleteDAIDs)),
// the inclusive production cap, and the refusal ORDER: an over-cap plan is
// refused before any artifact, checkpoint, generation or live mutation.
//
// The exact-cap and cap+8 rows run against the package-private cap override on
// the SAME production comparison; the production cap constant and its cap+8
// neighbour are pinned as literals and fed to that comparison directly.
func TestCanonicalCutoverApplyPlanMetadataBounds(t *testing.T) {
	rows := func(n int) []canonicalRowDescriptor { return make([]canonicalRowDescriptor, n) }
	applied := func(counts ...int) []CanonicalAppliedBlock {
		out := make([]CanonicalAppliedBlock, 0, len(counts))
		for _, n := range counts {
			out = append(out, CanonicalAppliedBlock{CompleteDAIDs: make([][32]byte, n)})
		}
		return out
	}
	for _, tc := range []struct {
		name             string
		disconnect, conn int
		ids              []int
		want             uint64
	}{
		{"empty", 0, 0, nil, 48},
		{"one connect row", 0, 1, applyIDCounts(0), 88},
		{"disconnect and connect", 2, 3, applyIDCounts(0, 0, 0), 248},
		{"ids charged per id", 0, 1, applyIDCounts(3), 184},
		{"cross block ids retained", 0, 2, applyIDCounts(1, 1), 192},
	} {
		got, err := canonicalPlanMetadataCharge(rows(tc.disconnect), rows(tc.conn), applied(tc.ids...))
		if err != nil || got != tc.want {
			t.Fatalf("%s charge=%d err=%v, want %d", tc.name, got, err, tc.want)
		}
	}

	if canonicalPlanMetadataCapBytes != 67108864 {
		t.Fatalf("production cap=%d, want the pinned 64 MiB literal 67108864", canonicalPlanMetadataCapBytes)
	}
	for _, term := range []uint64{canonicalPlanMetadataBaseBytes, canonicalPlanMetadataRowBytes, canonicalPlanMetadataIDBytes, canonicalPlanMetadataCapBytes} {
		if term%8 != 0 {
			t.Fatalf("charge term %d is not a multiple of 8: cap+8 would not be the smallest realizable overflow", term)
		}
	}
	if err := canonicalPlanMetadataBoundError(canonicalPlanMetadataCapBytes); err != nil {
		t.Fatalf("the exact cap must be accepted: %v", err)
	}
	if err := canonicalPlanMetadataBoundError(canonicalPlanMetadataCapBytes + 8); !errors.Is(err, errCanonicalPlanMetadataCap) {
		t.Fatalf("cap+8=%d err=%v, want the resource refusal", canonicalPlanMetadataCapBytes+8, err)
	}

	// Exact cap accepted / cap+8 refused on the real charge path.
	previousCap := canonicalPlanMetadataCap
	t.Cleanup(func() { canonicalPlanMetadataCap = previousCap })
	canonicalPlanMetadataCap = 168
	exact := &canonicalTransitionPlan{connect: rows(3)}
	if err := exact.checkCanonicalPlanMetadataBound(); err != nil {
		t.Fatalf("exact cap plan refused: %v", err)
	}
	over := &canonicalTransitionPlan{applied: applied(4)}
	if err := over.checkCanonicalPlanMetadataBound(); !errors.Is(err, errCanonicalPlanMetadataCap) {
		t.Fatalf("cap+8 plan err=%v, want the resource refusal", err)
	}

	// End to end: the refusal precedes every side effect.
	f := newCanonicalMOFixture(t, 1, MempoolConfig{})
	beforeIndex, err := f.store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot: %v", err)
	}
	beforeView, beforeOwner := f.engine.chainState.view(), mustCutoverAdmission(t, f.mp)
	// The bound fires before ARTIFACT, checkpoint, generation and live work, so
	// the durable store fingerprint — canonical index plus every block, header
	// and undo file — must be identical afterwards.
	beforeArtifacts := durableStoreFingerprint(t, f.store)
	beforeSnapshot, err := os.ReadFile(f.engine.cfg.ChainStatePath)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	writes := countCanonicalIndexWrites(t, f.store)
	canonicalPlanMetadataCap = 8
	if err := f.applyCoinbase(t); !errors.Is(err, errCanonicalPlanMetadataCap) {
		t.Fatalf("over-cap apply err=%v, want the resource refusal", err)
	}
	afterSnapshot, err := os.ReadFile(f.engine.cfg.ChainStatePath)
	if err != nil {
		t.Fatalf("read checkpoint after refusal: %v", err)
	}
	afterIndex, err := f.store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot after refusal: %v", err)
	}
	if *writes != 0 || !reflect.DeepEqual(afterIndex, beforeIndex) || !reflect.DeepEqual(afterSnapshot, beforeSnapshot) {
		t.Fatalf("over-cap refusal mutated index writes=%d index=%v checkpoint_changed=%v", *writes, afterIndex, !reflect.DeepEqual(afterSnapshot, beforeSnapshot))
	}
	if got := durableStoreFingerprint(t, f.store); got != beforeArtifacts {
		t.Fatalf("over-cap refusal staged artifacts:\n got=%s\nwant=%s", got, beforeArtifacts)
	}
	after := mustCutoverAdmission(t, f.mp)
	if f.engine.chainState.view() != beforeView || after.Generation != beforeOwner.Generation {
		t.Fatalf("over-cap refusal advanced the generation or the live image: view=%+v owner=%+v", f.engine.chainState.view(), after)
	}
}

func applyIDCounts(counts ...int) []int { return counts }

func mustCutoverAdmission(t *testing.T, mp *Mempool) PendingOutpointAdmissionContext {
	t.Helper()
	ctx, ok := mp.PendingOutpointOwner().AdmissionContext()
	if !ok {
		t.Fatal("owner admission context unavailable")
	}
	return ctx
}

// TestCanonicalCutoverPrecommitRecoverySet pins RECOVERY_PROOF: the new suffix
// is staged through the existing artifact writers, both suffix proof sets are
// strict-read through the same reader startup uses, and only then is the durable
// checkpoint replaced and read back. The write ORDER is observed from the
// filesystem, not asserted from the code.
func TestCanonicalCutoverPrecommitRecoverySet(t *testing.T) {
	engine, store, dir := newCutoverEngine(t)
	if err := engine.BootstrapCanonicalGenesisIfEmpty(); err != nil {
		t.Fatalf("BootstrapCanonicalGenesisIfEmpty: %v", err)
	}
	target := consensus.POW_LIMIT
	block := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))

	var order []string
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		sync := ops.syncParent
		ops.syncParent = func(parent string) error {
			switch parent {
			case store.blocksDir, store.headersDir, store.undoDir:
				order = append(order, "artifact")
			case dir:
				order = append(order, "checkpoint")
			case store.rootPath:
				order = append(order, "index")
			}
			return sync(parent)
		}
	})
	summary, err := engine.ApplyBlock(block, nil)
	if err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}
	if len(order) < 3 || order[len(order)-1] != "index" || order[len(order)-2] != "checkpoint" {
		t.Fatalf("durable write order=%v, want every artifact, then the checkpoint, then the index", order)
	}
	for _, stage := range order[:len(order)-2] {
		if stage != "artifact" {
			t.Fatalf("durable write order=%v, want artifacts before the checkpoint", order)
		}
	}

	// Both suffix rows read as valid.
	for _, hash := range [][32]byte{devnetGenesisBlockHash, summary.BlockHash} {
		if class, err := store.proveCanonicalArtifacts(hash); class != canonicalArtifactValid || err != nil {
			t.Fatalf("proveCanonicalArtifacts(%x)=(%v,%v), want valid", hash, class, err)
		}
	}
	// Definitive absence is POSITIVE evidence, so it is the invalid class, not
	// unavailability.
	var absent [32]byte
	if class, _ := store.proveCanonicalArtifacts(absent); class != canonicalArtifactInvalid {
		t.Fatalf("proveCanonicalArtifacts(absent) class=%v, want invalid", class)
	}
	if err := os.Remove(filepath.Join(store.undoDir, hex.EncodeToString(summary.BlockHash[:])+".json")); err != nil {
		t.Fatalf("Remove(undo): %v", err)
	}
	if class, _ := store.proveCanonicalArtifacts(summary.BlockHash); class != canonicalArtifactInvalid {
		t.Fatalf("proveCanonicalArtifacts(missing undo) class=%v, want invalid", class)
	}

	// A canonical artifact the retention profile requires, corrupted between the
	// reorg preview and the proof, is TERMINAL_STORE_INTEGRITY(canonical): the
	// pre-fence path takes the admission guard, installs the EXISTING latch and
	// retains it, publishing nothing.
	t.Run("pre-fence canonical corruption latches", func(t *testing.T) {
		reorgEngine, reorgStore, reorgTarget := newReorgTestEngine(t)
		subsidy1 := consensus.BlockSubsidy(1, 0)
		a1 := buildSingleTxBlock(t, devnetGenesisBlockHash, reorgTarget, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
		a1Summary, err := reorgEngine.ApplyBlock(a1, nil)
		if err != nil {
			t.Fatalf("ApplyBlock(A1): %v", err)
		}
		b1 := buildSingleTxBlock(t, devnetGenesisBlockHash, reorgTarget, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
		if _, err := reorgEngine.ApplyBlockWithReorg(b1, nil); err != nil {
			t.Fatalf("store B1: %v", err)
		}
		_, b1Hash := mustParseReorgBlockForTest(t, b1)
		b2 := buildSingleTxBlock(t, b1Hash, reorgTarget, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, consensus.BlockSubsidy(2, subsidy1)))
		rotation := &corruptCanonicalOnCreateRotation{overwrite: func() {
			writeRawStoreBlockFile(t, reorgStore, a1Summary.BlockHash, []byte("corrupt after preview"))
		}}
		reorgEngine.cfg.RotationProvider = rotation
		reorgWrites := countCanonicalIndexWrites(t, reorgStore)
		var integrity *canonicalStoreIntegrityError
		if _, err := reorgEngine.ApplyBlockWithReorg(b2, nil); !errors.As(err, &integrity) {
			t.Fatalf("reorg over a corrupt required artifact=%v, want the canonical store-integrity refusal", err)
		}
		if rotation.fires != 1 || *reorgWrites != 0 || !reorgEngine.persistenceFaulted() {
			t.Fatalf("fires=%d index writes=%d latch=%v", rotation.fires, *reorgWrites, reorgEngine.persistenceFaulted())
		}
		if reorgEngine.chainState.TipHash != a1Summary.BlockHash {
			t.Fatalf("terminal OLD moved the live tip to %x", reorgEngine.chainState.TipHash)
		}
		if _, err := reorgEngine.ApplyBlock(a1, nil); !errors.Is(err, errStoragePersistenceFault) {
			t.Fatalf("post-latch mutation=%v, want the retained fail-closed latch", err)
		}
	})

	// A staged NEW-suffix row that will not strict-read is a member of this
	// precommit recovery set, so it is TERMINAL_STORE_INTEGRITY(canonical): the
	// engine latches, publishes nothing and never reaches the checkpoint or the
	// index write.
	t.Run("staged connect row failing its proof latches", func(t *testing.T) {
		proofEngine, proofStore, proofDir := newCutoverEngine(t)
		if err := proofEngine.BootstrapCanonicalGenesisIfEmpty(); err != nil {
			t.Fatalf("BootstrapCanonicalGenesisIfEmpty: %v", err)
		}
		checkpointBefore, err := os.ReadFile(ChainStatePath(proofDir))
		if err != nil {
			t.Fatalf("read checkpoint: %v", err)
		}
		next := buildSingleTxBlock(t, devnetGenesisBlockHash, consensus.POW_LIMIT, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
		parsed, err := consensus.ParseBlockBytes(next)
		if err != nil {
			t.Fatalf("ParseBlockBytes: %v", err)
		}
		nextHash, err := consensus.BlockHash(parsed.HeaderBytes)
		if err != nil {
			t.Fatalf("BlockHash: %v", err)
		}
		// The undo file is read through this seam ONLY by the strict proof:
		// staging writes it without reading it back through readFileByPathFn.
		undoPath := filepath.Join(proofStore.undoDir, hex.EncodeToString(nextHash[:])+".json")
		// POSITIVE evidence: the read COMPLETES and the value is a malformed
		// state-reversal artifact. An acquisition failure here would be
		// unavailability instead — that row lives in
		// TestCanonicalCutoverStrictReadErrorClassification.
		previousRead, proofReads := readFileByPathFn, 0
		t.Cleanup(func() { readFileByPathFn = previousRead })
		readFileByPathFn = func(path string, limit int64) ([]byte, error) {
			if path == undoPath {
				proofReads++
				return []byte("{}"), nil
			}
			return previousRead(path, limit)
		}
		writes := countCanonicalIndexWrites(t, proofStore)
		summary, err := proofEngine.ApplyBlock(next, nil)
		var integrity *canonicalStoreIntegrityError
		if summary != nil || !errors.As(err, &integrity) {
			t.Fatalf("summary=%+v err=%v, want the canonical store-integrity refusal", summary, err)
		}
		if proofReads == 0 || *writes != 0 || !proofEngine.persistenceFaulted() {
			t.Fatalf("proof reads=%d index writes=%d latch=%v", proofReads, *writes, proofEngine.persistenceFaulted())
		}
		if live := proofEngine.chainState.view(); live.height != 0 || live.tipHash != devnetGenesisBlockHash {
			t.Fatalf("terminal OLD moved the live tip to (%d,%x)", live.height, live.tipHash)
		}
		checkpointAfter, err := os.ReadFile(ChainStatePath(proofDir))
		if err != nil || !reflect.DeepEqual(checkpointAfter, checkpointBefore) {
			t.Fatalf("the proof failure replaced the checkpoint: err=%v", err)
		}
		// The artifacts were staged first; only their proof failed.
		if _, err := proofStore.GetBlockByHash(nextHash); err != nil {
			t.Fatalf("staged block artifact missing: %v", err)
		}
	})

	// A checkpoint that cannot be written refuses BEFORE the index write, and
	// the staged artifacts are already durable.
	engine2, store2, dir2 := newCutoverEngine(t)
	engine2.cfg.ChainStatePath = filepath.Join(dir2, "checkpoint-dir")
	if err := os.Mkdir(engine2.cfg.ChainStatePath, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	writes := countCanonicalIndexWrites(t, store2)
	if err := engine2.BootstrapCanonicalGenesisIfEmpty(); err == nil {
		t.Fatal("bootstrap crossed the commit with an unwritable checkpoint")
	}
	if *writes != 0 || engine2.persistenceFaulted() {
		t.Fatalf("checkpoint refusal writes=%d latch=%v, want a precommit refusal", *writes, engine2.persistenceFaulted())
	}
	if _, err := store2.GetBlockByHash(devnetGenesisBlockHash); err != nil {
		t.Fatalf("staged block artifact missing after the checkpoint refusal: %v", err)
	}
	if index, err := store2.CanonicalIndexSnapshot(); err != nil || len(index) != 0 {
		t.Fatalf("canonical index=%v err=%v after the checkpoint refusal, want the empty old identity", index, err)
	}
}

// TestCanonicalCutoverPersistenceTruthTable is the closed classifier: every
// commit class maps to exactly one (truth, latch) pair, and the hostile readback
// identity set maps to exactly the OLD / NEW / UNKNOWN rows. The unit rows and
// the end-to-end rows must agree on the same input.
func TestCanonicalCutoverPersistenceTruthTable(t *testing.T) {
	cause := errors.New("commit cause")
	for _, tc := range []struct {
		name    string
		result  canonicalCommitResult
		truth   canonicalCommitTruth
		latched bool
	}{
		{"committed", canonicalCommitResult{class: canonicalCommitted}, canonicalTruthNew, false},
		{"precommit", canonicalCommitResult{class: canonicalCommitPrecommit, err: cause}, canonicalTruthOld, false},
		{"stale moved", canonicalCommitResult{class: canonicalCommitStale, err: errCanonicalIndexMoved}, canonicalTruthOld, false},
		{"stale spent", canonicalCommitResult{class: canonicalCommitStale, err: errPreparedIndexSpent}, canonicalTruthOld, true},
		{"empty class bytes", canonicalCommitResult{err: errNoncanonicalBytes}, canonicalTruthOld, false},
		{"empty class count", canonicalCommitResult{err: errNoncanonicalCount}, canonicalTruthOld, false},
		{"empty class integrity", canonicalCommitResult{err: cause}, canonicalTruthOld, true},
		{"terminal old", canonicalCommitResult{class: canonicalCommitTerminalOld, err: cause}, canonicalTruthOld, true},
		{"terminal new", canonicalCommitResult{class: canonicalCommitTerminalNew, err: cause}, canonicalTruthNew, true},
		{"terminal unknown", canonicalCommitResult{class: canonicalCommitTerminalUnknown, err: cause}, canonicalTruthUnknown, true},
		{"unknown class", canonicalCommitResult{class: canonicalCommitClass("NOT_A_CLASS"), err: cause}, canonicalTruthUnknown, true},
		{"zero value with no cause", canonicalCommitResult{}, canonicalTruthOld, true},
	} {
		truth, latched, got := classifyCanonicalCommit(tc.result)
		if truth != tc.truth || latched != tc.latched {
			t.Fatalf("%s -> truth=%v latched=%v, want %v/%v", tc.name, truth, latched, tc.truth, tc.latched)
		}
		if latched && got == nil {
			t.Fatalf("%s latched without a cause", tc.name)
		}
		if truth == canonicalTruthNew && !latched && got != nil {
			t.Fatalf("%s ordinary NEW carried an error: %v", tc.name, got)
		}
	}
	// A wrapped sentinel is still distinguished by identity, never by text.
	wrapped := canonicalCommitResult{class: canonicalCommitStale, err: fmt.Errorf("prepared canonical index is stale: %w", errPreparedIndexSpent)}
	if truth, latched, _ := classifyCanonicalCommit(wrapped); truth != canonicalTruthOld || !latched {
		t.Fatalf("re-spelled spent sentinel -> truth=%v latched=%v, want OLD/latched", truth, latched)
	}

	genesisHex := hex.EncodeToString(devnetGenesisBlockHash[:])
	third := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name      string
		readback  []string
		fail      bool
		truth     canonicalCommitTruth
		publishes bool
	}{
		{name: "exact old", readback: []string{}, truth: canonicalTruthOld},
		{name: "exact new", readback: []string{genesisHex}, truth: canonicalTruthNew, publishes: true},
		{name: "third identity", readback: []string{third}, truth: canonicalTruthUnknown},
		{name: "extra row", readback: []string{genesisHex, third}, truth: canonicalTruthUnknown},
		{name: "reordered", readback: []string{third, genesisHex}, truth: canonicalTruthUnknown},
		{name: "unreadable", fail: true, truth: canonicalTruthUnknown},
	} {
		t.Run("readback/"+tc.name, func(t *testing.T) {
			engine, store, _ := newCutoverEngine(t)
			write := writeFileAtomicFn
			withWriteFileAtomicFn(t, func(path string, data []byte, mode os.FileMode) error {
				if path == store.indexPath {
					// AMBIGUOUS: the lane cannot prove the namespace commit did
					// not cross, so the classifier must take one strict readback.
					return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
				}
				return write(path, data, mode)
			})
			reads := 0
			withLoadBlockStoreIndexFn(t, func(string) (blockStoreIndexDisk, []byte, error) {
				reads++
				if tc.fail {
					return blockStoreIndexDisk{}, nil, os.ErrInvalid
				}
				index := blockStoreIndexDisk{Version: blockStoreIndexVersion, Canonical: tc.readback}
				raw, err := encodeBlockStoreIndex(index)
				if err != nil {
					t.Fatalf("encodeBlockStoreIndex: %v", err)
				}
				return index, raw, nil
			})
			summary, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil)
			if err == nil || reads != 1 {
				t.Fatalf("err=%v strict readbacks=%d, want exactly one", err, reads)
			}
			if !engine.persistenceFaulted() {
				t.Fatalf("%s did not latch a terminal outcome", tc.name)
			}
			if (summary != nil) != tc.publishes || engine.chainState.view().hasTip != tc.publishes {
				t.Fatalf("%s summary=%v live_tip=%v, want published=%v", tc.name, summary != nil, engine.chainState.view().hasTip, tc.publishes)
			}
		})
	}
}

// TestCanonicalCutoverNoFalliblePostNewPublication proves the publication step
// cannot fail: none of its three functions can return an error at all, and once
// the canonical index write returns, no further durable write and no provider
// callback runs before the transition returns.
func TestCanonicalCutoverNoFalliblePostNewPublication(t *testing.T) {
	for _, fn := range []any{
		(*canonicalTransition).publishCanonicalTransition,
		assignCanonicalChainState,
		(*Mempool).publishCanonicalMempoolPlan,
		(*Mempool).publishCanonicalMempoolPlanLocked,
		(*PendingOutpointOwner).publishRestoreLocked,
	} {
		if out := reflect.TypeOf(fn).NumOut(); out != 0 {
			t.Fatalf("%v returns %d values: postcommit publication must not be able to fail", reflect.TypeOf(fn), out)
		}
	}

	provider := newCanonicalMOProvider(t, devnetGenesisChainID)
	f := newCanonicalMOFixture(t, 1, MempoolConfig{RotationProvider: provider})
	f.add(t, f.ops[0], 1)
	providerCalls := func() int {
		provider.mu.Lock()
		defer provider.mu.Unlock()
		return provider.create + provider.spend
	}
	// Counted at the ATOMIC-WRITE lane, not at one seam: every durable write the
	// process performs after the commit — including a chainstate save, which does
	// not go through the index seam — has to show up here.
	writesAfterCommit, providerAtCommit, committed := 0, 0, false
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		link, rename := ops.link, ops.rename
		note := func() {
			if committed {
				writesAfterCommit++
			}
		}
		ops.link = func(a, b string) error { note(); return link(a, b) }
		ops.rename = func(a, b string) error {
			note()
			err := rename(a, b)
			if err == nil && b == f.store.indexPath {
				committed, providerAtCommit = true, providerCalls()
			}
			return err
		}
	})
	if err := f.applyCoinbase(t); err != nil {
		t.Fatalf("applyCoinbase: %v", err)
	}
	if !committed {
		t.Fatal("the canonical index was never committed")
	}
	if writesAfterCommit != 0 {
		t.Fatalf("durable writes after the commit=%d, want 0", writesAfterCommit)
	}
	if got := providerCalls(); got != providerAtCommit {
		t.Fatalf("provider callbacks after the commit=%d, want none (was %d)", got-providerAtCommit, providerAtCommit)
	}
	owner := f.mp.PendingOutpointOwner()
	ctx, ok := owner.AdmissionContext()
	if !ok || ctx.StableTip.Hash != f.engine.chainState.view().tipHash {
		t.Fatalf("owner=%+v ok=%v, want the transition closed with stable tip C1", ctx, ok)
	}
}

// TestCanonicalCutoverConcurrentAdmissionAndBlockStore forces the schedules the
// fence must survive: admission attempted while the transition is parked inside
// the BlockStore commit, a concurrent BlockStore reader during that same window,
// a repeated attempt after a terminal latch, and no second commit anywhere.
func TestCanonicalCutoverConcurrentAdmissionAndBlockStore(t *testing.T) {
	f := newCanonicalMOFixture(t, 1, MempoolConfig{})
	// Built BEFORE the commit window: the fixture helper reads live chainstate
	// fields without the lock, which is a test-side race, not a production one.
	admissionTx := f.raw(t, f.ops[0], 9, false)
	entered, release := make(chan struct{}), make(chan struct{})
	write, writes := writeFileAtomicFn, 0
	withWriteFileAtomicFn(t, func(path string, data []byte, mode os.FileMode) error {
		if path == f.store.indexPath {
			writes++
			close(entered)
			<-release
		}
		return write(path, data, mode)
	})
	applied := make(chan error, 1)
	go func() { applied <- f.applyCoinbase(t) }()
	select {
	case <-entered:
	case err := <-applied:
		close(release)
		t.Fatalf("apply returned before the commit window: %v", err)
	case <-time.After(time.Second):
		close(release)
		t.Fatal("timed out waiting for the commit window")
	}

	// admissionMu is held across the commit, so admission blocks.
	admitted := make(chan error, 1)
	go func() { admitted <- f.mp.AddTx(admissionTx) }()
	select {
	case err := <-admitted:
		close(release)
		t.Fatalf("admission passed the fence during the commit: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	// BlockStore.commit owns stateMu internally and holds NO component lock
	// across its durable write, so a reader still completes.
	readDone := make(chan error, 1)
	go func() {
		_, err := f.store.GetBlockByHash(devnetGenesisBlockHash)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil {
			close(release)
			t.Fatalf("concurrent blockstore read during the commit: %v", err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("concurrent blockstore read deadlocked against the commit")
	}

	close(release)
	if err := <-applied; err != nil {
		t.Fatalf("apply: %v", err)
	}
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatalf("admission after the fence reopened: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("admission never completed after the fence reopened")
	}
	if writes != 1 {
		t.Fatalf("canonical index writes=%d, want exactly one commit", writes)
	}

	// Terminal repeat: the EXISTING latch refuses every later transition, and no
	// second commit is attempted.
	f.engine.latchTerminalFault(errors.New("terminal for the repeat row"))
	before := writes
	if err := f.applyCoinbase(t); !errors.Is(err, errStoragePersistenceFault) {
		t.Fatalf("repeat after latch=%v, want the existing fail-closed latch", err)
	}
	if _, err := f.engine.DisconnectTip(); !errors.Is(err, errStoragePersistenceFault) {
		t.Fatalf("disconnect after latch=%v, want the existing fail-closed latch", err)
	}
	if writes != before {
		t.Fatalf("canonical index writes after the latch=%d, want no second commit", writes-before)
	}
}

// TestCanonicalCutoverNonpersistentCompatibility walks the compatibility rows an
// engine with no BlockStore takes. Without a canonical index the chainstate save
// is the durable identity, so it selects truth exactly as the prepared commit
// does; with no chainstate path there is no persistence truth at all. Winning
// reorg and standalone disconnect keep requiring a store.
func TestCanonicalCutoverNonpersistentCompatibility(t *testing.T) {
	newEngine := func(t *testing.T, path string) (*SyncEngine, *Mempool) {
		t.Helper()
		target := consensus.POW_LIMIT
		engine, err := NewSyncEngine(NewChainState(), nil, DefaultSyncConfig(&target, devnetGenesisChainID, path))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		store, err := CreateBlockStore(BlockStorePath(t.TempDir()))
		if err != nil {
			t.Fatalf("CreateBlockStore: %v", err)
		}
		mp, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
		if err != nil {
			t.Fatalf("NewMempool: %v", err)
		}
		engine.SetMempool(mp)
		return engine, mp
	}

	t.Run("nil store empty path publishes and stays open", func(t *testing.T) {
		engine, mp := newEngine(t, "")
		summary, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil)
		if err != nil || summary == nil || !engine.chainState.view().hasTip {
			t.Fatalf("summary=%+v err=%v tip=%v", summary, err, engine.chainState.view().hasTip)
		}
		if ctx, ok := mp.PendingOutpointOwner().AdmissionContext(); !ok || ctx.StableTip.Hash != summary.BlockHash {
			t.Fatalf("owner=%+v ok=%v, want C1 with admission reopened", ctx, ok)
		}
	})

	t.Run("nil store nonempty path saves C1", func(t *testing.T) {
		dir := t.TempDir()
		engine, _ := newEngine(t, ChainStatePath(dir))
		summary, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil)
		if err != nil || summary == nil {
			t.Fatalf("summary=%+v err=%v", summary, err)
		}
		loaded, err := LoadChainState(ChainStatePath(dir))
		if err != nil || !loaded.HasTip || loaded.TipHash != summary.BlockHash {
			t.Fatalf("durable image=(%v,%x) err=%v, want C1", loaded.HasTip, loaded.TipHash, err)
		}
	})

	t.Run("proven pre-namespace save failure is OLD open", func(t *testing.T) {
		dir := t.TempDir()
		engine, mp := newEngine(t, filepath.Join(dir, "state-dir"))
		if err := os.Mkdir(engine.cfg.ChainStatePath, 0o700); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		summary, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil)
		if summary != nil || err == nil || engine.persistenceFaulted() || engine.chainState.view().hasTip {
			t.Fatalf("summary=%+v err=%v latch=%v tip=%v", summary, err, engine.persistenceFaulted(), engine.chainState.view().hasTip)
		}
		if _, ok := mp.PendingOutpointOwner().AdmissionContext(); !ok {
			t.Fatal("an OLD/open refusal left admission closed")
		}
	})

	t.Run("ambiguous save with exact C1 is terminal NEW", func(t *testing.T) {
		dir := t.TempDir()
		engine, _ := newEngine(t, ChainStatePath(dir))
		failed := false
		withAtomicWriteOps(t, func(ops *atomicWriteOps) {
			sync := ops.syncParent
			ops.syncParent = func(parent string) error {
				if !failed && parent == dir {
					failed = true
					return os.ErrPermission
				}
				return sync(parent)
			}
		})
		summary, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil)
		if !failed || summary == nil || err == nil || !engine.persistenceFaulted() {
			t.Fatalf("injected=%v summary=%+v err=%v latch=%v", failed, summary, err, engine.persistenceFaulted())
		}
		if !engine.chainState.view().hasTip {
			t.Fatal("terminal NEW did not publish C1")
		}
	})

	t.Run("ambiguous save with another image is UNKNOWN", func(t *testing.T) {
		dir := t.TempDir()
		engine, _ := newEngine(t, ChainStatePath(dir))
		failed := false
		withAtomicWriteOps(t, func(ops *atomicWriteOps) {
			sync := ops.syncParent
			ops.syncParent = func(parent string) error {
				if !failed && parent == dir {
					failed = true
					if err := os.Remove(ChainStatePath(dir)); err != nil {
						t.Fatalf("Remove(chainstate): %v", err)
					}
					return os.ErrPermission
				}
				return sync(parent)
			}
		})
		summary, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil)
		if !failed || summary != nil || err == nil || !engine.persistenceFaulted() {
			t.Fatalf("injected=%v summary=%+v err=%v latch=%v", failed, summary, err, engine.persistenceFaulted())
		}
		if engine.chainState.view().hasTip {
			t.Fatal("UNKNOWN published a guessed image")
		}
	})

	t.Run("nil store terminal M/O latches and saves nothing", func(t *testing.T) {
		dir := t.TempDir()
		engine, mp := newEngine(t, ChainStatePath(dir))
		owner := mp.PendingOutpointOwner()
		owner.mu.Lock()
		owner.byToken[PendingOutpointToken{owner: owner, seq: 1}] = nil
		owner.mu.Unlock()
		summary, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil)
		if summary != nil || !isCanonicalMOTerminalError(err) || !engine.persistenceFaulted() {
			t.Fatalf("summary=%+v err=%v latch=%v, want terminal OLD/latched", summary, err, engine.persistenceFaulted())
		}
		if engine.chainState.view().hasTip {
			t.Fatal("a terminal M/O invariant published C1")
		}
		if _, statErr := os.Stat(ChainStatePath(dir)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("terminal M/O reached Save(C1): stat=%v", statErr)
		}
		if _, ok := owner.AdmissionContext(); ok {
			t.Fatal("a terminal M/O invariant reopened admission")
		}
	})

	// Compatibility row 2 — nonnil BlockStore, EMPTY chainstate path: the same
	// one-commit classifier and fixed publication, with only the durable
	// checkpoint and its readiness proof omitted.
	t.Run("compat row 2: nonnil store with an empty chainstate path", func(t *testing.T) {
		dir := t.TempDir()
		store, err := CreateBlockStore(BlockStorePath(dir))
		if err != nil {
			t.Fatalf("CreateBlockStore: %v", err)
		}
		target := consensus.POW_LIMIT
		engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(&target, devnetGenesisChainID, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		mp, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
		if err != nil {
			t.Fatalf("NewMempool: %v", err)
		}
		engine.SetMempool(mp)
		writes := countCanonicalIndexWrites(t, store)
		summary, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil)
		if err != nil || summary == nil || *writes != 1 {
			t.Fatalf("summary=%+v err=%v index writes=%d, want one commit", summary, err, *writes)
		}
		index, err := store.CanonicalIndexSnapshot()
		if err != nil || len(index) != 1 || index[0] != hex.EncodeToString(devnetGenesisBlockHash[:]) {
			t.Fatalf("index=%v err=%v", index, err)
		}
		if ctx, ok := mp.PendingOutpointOwner().AdmissionContext(); !ok || ctx.StableTip.Hash != summary.BlockHash {
			t.Fatalf("owner=%+v ok=%v, want C1 with admission reopened", ctx, ok)
		}
		if _, statErr := os.Stat(ChainStatePath(dir)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("an empty chainstate path still wrote a checkpoint: stat=%v", statErr)
		}
	})

	t.Run("reorg and disconnect require a store", func(t *testing.T) {
		engine, _ := newEngine(t, "")
		if _, err := engine.DisconnectTip(); err == nil || err.Error() != "sync engine has no blockstore" {
			t.Fatalf("DisconnectTip=%v, want exactly the missing-store refusal", err)
		}
		if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
		target := consensus.POW_LIMIT
		side := buildSingleTxBlock(t, [32]byte{0xAA}, target, reorgTestTimestamp(9), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
		if _, err := engine.ApplyBlockWithReorg(side, nil); err == nil {
			t.Fatal("a non-genesis reorg candidate was accepted without a blockstore")
		}
	})
}

// canonicalArtifactSeam replaces the bounded artifact reader for exactly one
// path and counts how many times the recovery proof reads it. Removing the seam
// removes the injection, so every row below fails rather than passing vacuously.
func canonicalArtifactSeam(t *testing.T, path string, outcome func() ([]byte, error)) *int {
	t.Helper()
	reads, previous := new(int), readFileByPathFn
	t.Cleanup(func() { readFileByPathFn = previous })
	readFileByPathFn = func(p string, limit int64) ([]byte, error) {
		if p == path {
			*reads++
			return outcome()
		}
		return previous(p, limit)
	}
	return reads
}

// TestCanonicalCutoverStrictReadErrorClassification pins MP641's recovery-proof
// read rules: the read ORDER, the stop-at-the-first-non-valid-observation rule,
// and the split between an artifact that could not be ACQUIRED — OLD, admission
// open, no latch, no retry — and positive evidence about the artifact itself —
// OLD, latched. Classification is on the observation, never on a platform error
// name: os.ErrPermission and syscall.EIO and a partial-plus-non-EOF read all land
// in the same class, while os.ErrNotExist and a proven over-bound land in the
// other.
func TestCanonicalCutoverStrictReadErrorClassification(t *testing.T) {
	// A standalone disconnect at height 1. Its OLD/disconnect suffix is that one
	// row and its new suffix is empty, so nothing stages the row's artifacts and
	// the seamed header read below can only be the recovery proof's own.
	stage := func(t *testing.T) (*SyncEngine, *BlockStore, [32]byte) {
		t.Helper()
		engine, store, _ := newCutoverEngine(t)
		if err := engine.BootstrapCanonicalGenesisIfEmpty(); err != nil {
			t.Fatalf("BootstrapCanonicalGenesisIfEmpty: %v", err)
		}
		block := buildSingleTxBlock(t, devnetGenesisBlockHash, consensus.POW_LIMIT, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
		summary, err := engine.ApplyBlock(block, nil)
		if err != nil {
			t.Fatalf("ApplyBlock: %v", err)
		}
		return engine, store, summary.BlockHash
	}
	headerOf := func(store *BlockStore, hash [32]byte) string {
		return filepath.Join(store.headersDir, hex.EncodeToString(hash[:])+".bin")
	}

	for _, tc := range []struct {
		name      string
		outcome   func() ([]byte, error)
		unavail   bool
		wantLatch bool
	}{
		{"open failure", func() ([]byte, error) { return nil, os.ErrPermission }, true, false},
		{"metadata stat failure", func() ([]byte, error) { return nil, syscall.EIO }, true, false},
		{"partial bytes then non-EOF", func() ([]byte, error) { return nil, io.ErrUnexpectedEOF }, true, false},
		{"definitive absence", func() ([]byte, error) { return nil, os.ErrNotExist }, false, true},
		{"proven over-bound", func() ([]byte, error) { return nil, errStoreFileTooLarge }, false, true},
		{"clean short EOF is an invalid representation", func() ([]byte, error) { return []byte("short"), nil }, false, true},
		{"complete value with a hash mismatch", func() ([]byte, error) { return make([]byte, consensus.BLOCK_HEADER_BYTES), nil }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, store, hash := stage(t)
			writes := countCanonicalIndexWrites(t, store)
			reads := canonicalArtifactSeam(t, headerOf(store, hash), tc.outcome)
			summary, err := engine.DisconnectTip()
			var unavailable *canonicalArtifactUnavailableError
			var integrity *canonicalStoreIntegrityError
			if summary != nil || err == nil || errors.As(err, &unavailable) != tc.unavail || errors.As(err, &integrity) == tc.unavail {
				t.Fatalf("summary=%+v err=%v, want a refusal with unavailable=%v", summary, err, tc.unavail)
			}
			if engine.persistenceFaulted() != tc.wantLatch || *writes != 0 || engine.chainState.view().height != 1 {
				t.Fatalf("latch=%v writes=%d height=%d, want latch=%v, zero commits and the preserved OLD tip", engine.persistenceFaulted(), *writes, engine.chainState.view().height, tc.wantLatch)
			}
			// No same-attempt retry: the failing artifact is read exactly once.
			if *reads != 1 {
				t.Fatalf("reads of the failing artifact=%d, want exactly 1", *reads)
			}
			// Admission itself, not a proxy: a latched outcome RETAINS the write
			// guard until restart, an open one released it.
			if free := engine.chainState.admissionMu.TryLock(); free != !tc.wantLatch {
				t.Fatalf("admission free=%v, want %v", free, !tc.wantLatch)
			} else if free {
				engine.chainState.admissionMu.Unlock()
			}
		})
	}

	t.Run("reads header then block then the state-reversal artifact", func(t *testing.T) {
		_, store, hash := stage(t)
		headerPath := filepath.Join(store.headersDir, hex.EncodeToString(hash[:])+".bin")
		blockPath := filepath.Join(store.blocksDir, hex.EncodeToString(hash[:])+".bin")
		undoPath := filepath.Join(store.undoDir, hex.EncodeToString(hash[:])+".json")
		previous, order := readFileByPathFn, []string(nil)
		t.Cleanup(func() { readFileByPathFn = previous })
		readFileByPathFn = func(p string, limit int64) ([]byte, error) {
			switch p {
			case headerPath:
				order = append(order, "header")
			case blockPath:
				order = append(order, "block")
			case undoPath:
				order = append(order, "undo")
			}
			return previous(p, limit)
		}
		// Driven at the unit that OWNS the per-row order, so the recorded reads
		// are the proof's and only the proof's: a whole transition also reads
		// these same files for other reasons, and a tail slice of that sequence
		// cannot tell a reordered read from an inserted one.
		if class, err := store.proveCanonicalArtifacts(hash); class != canonicalArtifactValid || err != nil {
			t.Fatalf("proveCanonicalArtifacts=(%v,%v), want valid", class, err)
		}
		// EXACT equality, not a suffix: any extra, missing, repeated or moved
		// read fails, which is what makes both a reorder and an insertion red.
		if !slices.Equal(order, []string{"header", "block", "undo"}) {
			t.Fatalf("proof read order=%v, want exactly [header block undo]", order)
		}
	})

	t.Run("stops at the first non-valid observation", func(t *testing.T) {
		engine, store, hash := stage(t)
		// The header fails; the block and the state-reversal artifact of the SAME
		// row must not be inspected AFTERWARDS. Reads before the proof (the
		// disconnect's own prepared block/undo) are not the proof's and are not
		// counted, which is what the header-failure flag separates.
		headerPath := headerOf(store, hash)
		blockPath := filepath.Join(store.blocksDir, hex.EncodeToString(hash[:])+".bin")
		undoPath := filepath.Join(store.undoDir, hex.EncodeToString(hash[:])+".json")
		previous, headerFailed, blockReads, undoReads := readFileByPathFn, false, 0, 0
		t.Cleanup(func() { readFileByPathFn = previous })
		readFileByPathFn = func(p string, limit int64) ([]byte, error) {
			switch {
			case p == headerPath:
				headerFailed = true
				return nil, os.ErrPermission
			case headerFailed && p == blockPath:
				blockReads++
			case headerFailed && p == undoPath:
				undoReads++
			}
			return previous(p, limit)
		}
		if _, err := engine.DisconnectTip(); err == nil {
			t.Fatal("expected the header refusal")
		}
		if !headerFailed || blockReads != 0 || undoReads != 0 {
			t.Fatalf("after the header failed the proof read block=%d undo=%d later artifacts, want 0/0", blockReads, undoReads)
		}
	})

	t.Run("a later independent apply succeeds after the condition clears", func(t *testing.T) {
		engine, store, hash := stage(t)
		canonicalArtifactSeam(t, headerOf(store, hash), func() ([]byte, error) { return nil, os.ErrPermission })
		if _, err := engine.DisconnectTip(); err == nil || engine.persistenceFaulted() {
			t.Fatalf("first attempt err=%v latch=%v, want OLD/open", err, engine.persistenceFaulted())
		}
		readFileByPathFn = readFileByPathCapped
		summary, err := engine.DisconnectTip()
		if err != nil || summary == nil || summary.NewHeight != 0 {
			t.Fatalf("retry summary=%+v err=%v, want the ordinary path to succeed", summary, err)
		}
	})
}

// TestCanonicalCutoverCheckpointExactEnvelopeReadback pins the persistent
// checkpoint proof: the exact bytes handed to the atomic writer are re-read once
// and compared BYTE FOR BYTE. The discriminating row is a durable image that is
// semantically identical but byte-different — a decode-and-compare proof accepts
// it, byte equality does not.
func TestCanonicalCutoverCheckpointExactEnvelopeReadback(t *testing.T) {
	// reencodeCheckpoint rewrites the durable checkpoint the instant it lands,
	// through the SAME envelope encoder, from a compact rather than an indented
	// payload: same decoded image, different bytes, valid checksum.
	reencode := func(t *testing.T, path string) {
		t.Helper()
		loaded, err := LoadChainState(path)
		if err != nil {
			t.Fatalf("LoadChainState: %v", err)
		}
		disk, err := stateToDisk(loaded)
		if err != nil {
			t.Fatalf("stateToDisk: %v", err)
		}
		payload, err := json.Marshal(disk)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		raw, err := marshalStoreEnvelope(storeEnvelopeChainState, append(payload, '\n'))
		if err != nil {
			t.Fatalf("marshalStoreEnvelope: %v", err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	for _, tc := range []struct {
		name      string
		corrupt   func(t *testing.T, path string)
		wantLatch bool
	}{
		{
			name: "semantically identical but byte different",
			corrupt: func(t *testing.T, path string) {
				reencode(t, path)
				// A decode-and-compare proof would accept this image: it still
				// decodes, to the very same chainstate.
				if _, err := LoadChainState(path); err != nil {
					t.Fatalf("the re-encoded checkpoint must still decode: %v", err)
				}
			},
			wantLatch: true,
		},
		{
			name: "raw readback cannot acquire the bytes",
			corrupt: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatalf("Remove: %v", err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatalf("Mkdir: %v", err)
				}
			},
			wantLatch: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, store, dir := newCutoverEngine(t)
			path := ChainStatePath(dir)
			corrupted := false
			withAtomicWriteOps(t, func(ops *atomicWriteOps) {
				rename := ops.rename
				ops.rename = func(a, b string) error {
					err := rename(a, b)
					if err == nil && b == path && !corrupted {
						corrupted = true
						tc.corrupt(t, path)
					}
					return err
				}
			})
			writes := countCanonicalIndexWrites(t, store)
			err := engine.BootstrapCanonicalGenesisIfEmpty()
			var unavailable *canonicalArtifactUnavailableError
			var integrity *canonicalStoreIntegrityError
			if !corrupted || err == nil {
				t.Fatalf("corrupted=%v err=%v, want the checkpoint proof to refuse", corrupted, err)
			}
			if errors.As(err, &integrity) != tc.wantLatch || errors.As(err, &unavailable) == tc.wantLatch {
				t.Fatalf("err=%v, want integrity=%v", err, tc.wantLatch)
			}
			if engine.persistenceFaulted() != tc.wantLatch || *writes != 0 || engine.chainState.view().hasTip {
				t.Fatalf("latch=%v writes=%d tip=%v", engine.persistenceFaulted(), *writes, engine.chainState.view().hasTip)
			}
		})
	}

}
