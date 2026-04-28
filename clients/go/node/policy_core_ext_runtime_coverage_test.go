package node

// Runtime coverage for the CORE_EXT policy surface as wired by the rubin-node
// binary. Existing package-level tests in mempool_test.go and
// miner_core_ext_policy_test.go cover the mempool / miner behavior with a
// `testCoreExtProfiles` mock provider; this file complements them by
// exercising the same admit / mine paths through a
// `consensus.NewStaticCoreExtProfileProvider`-constructed
// CoreExtProfileProvider — i.e. the exact provider type that the rubin-node
// binary's buildGenesisCoreExtProfiles returns when the operator passes
// --genesis-file with a populated core_ext_profiles[] section.
//
// In production (function/field anchors only; line numbers are intentionally
// omitted to keep this comment stable as the rubin-node main.go evolves):
//   * parseGenesisConfigFull calls buildGenesisCoreExtProfiles(...) and
//     receives a consensus.NewStaticCoreExtProfileProvider(...) back;
//   * the resulting provider is written into mempoolCfg.CoreExtProfiles;
//   * the same provider is written into minerCfg.CoreExtProfiles.
//
// This test reproduces the wiring contract in-process: it builds a provider
// via the same public constructor that buildGenesisCoreExtProfiles uses, then
// hands it to MempoolConfig and MinerConfig and verifies that:
//   * pre-ACTIVE CORE_EXT output tx is rejected by BOTH mempool.AddTx (the
//     policy rejection path used by /submit_tx via state.mempool.AddTx) AND
//     mempool.RelayMetadata (the relay snapshot path
//     admissionSnapshotForInputs), with the rejection error matching the
//     fmt.Sprintf-built CORE_EXT output pre-ACTIVE policy reason derived
//     from the test's extID constant;
//   * pre-ACTIVE CORE_EXT spend tx (transaction whose input previous UTXO
//     has CovenantType=CORE_EXT) is rejected by BOTH mempool.AddTx AND
//     mempool.RelayMetadata, with the rejection error matching the
//     fmt.Sprintf-built CORE_EXT spend pre-ACTIVE policy reason; this
//     covers the input branch of RejectCoreExtTxPreActivation against the
//     production provider type;
//   * pre-ACTIVE CORE_EXT output tx is filtered by miner.MineOne (the
//     policy filter path used by /mine_next);
//   * ACTIVE-profile CORE_EXT output tx is admitted by BOTH mempool.AddTx
//     AND mempool.RelayMetadata (with non-zero RelayTxMetadata.Size) when
//     the activation height is at or below the next-block height;
//   * ACTIVE-profile CORE_EXT output tx is INCLUDED in the block produced
//     by miner.MineOne under the production provider type — the ACTIVE
//     counterpart of the pre-ACTIVE miner-filter assertion above. The
//     mined block is fetched from the block store and parsed; both
//     TxCount==2 (coinbase + the submitted CORE_EXT tx) and the
//     non-coinbase txid identity are asserted, plus the included tx's
//     CORE_EXT output covenant carries the test's extID. This closes
//     the runtime-coverage matrix's previously-missed class — ACTIVE
//     miner branch had been provable only at the mempool/relay layer,
//     not at the actual /mine_next pipeline that issues a connectable
//     block.
//
// Class-closure sweep (each entry covered by a sub-test below):
//   pre-ACTIVE CORE_EXT output : mempool.AddTx reject + RelayMetadata reject
//                                + miner.MineOne filter
//   pre-ACTIVE CORE_EXT spend  : mempool.AddTx reject + RelayMetadata reject
//   ACTIVE     CORE_EXT output : mempool.AddTx admit  + RelayMetadata admit
//                                + miner.MineOne include (TxCount==2,
//                                  parsed-block txid match, covenant ext_id
//                                  match)

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// staticCoreExtProvider returns a CoreExtProfileProvider built via the same
// public constructor that the rubin-node binary's buildGenesisCoreExtProfiles
// uses when --genesis-file core_ext_profiles[] is non-empty.
func staticCoreExtProvider(t *testing.T, extID uint16, activationHeight uint64) consensus.CoreExtProfileProvider {
	t.Helper()
	deployments := []consensus.CoreExtDeploymentProfile{{
		ExtID:            extID,
		ActivationHeight: activationHeight,
		// NewStaticCoreExtProfileProvider rejects deployments with empty
		// AllowedSuites; the production buildGenesisCoreExtProfiles surfaces
		// the same constraint via the genesis JSON's allowed_suite_ids[]
		// field. The values here mirror the cmd/rubin-node main_test.go
		// TestParseGenesisConfigFullBuildsCoreExtProfiles fixture.
		AllowedSuites: map[uint8]struct{}{
			consensus.SUITE_ID_ML_DSA_87: {},
			// suite_id=3 has no named consensus constant in this codebase;
			// kept as a raw placeholder fixture value matching the parser
			// test fixture's allowed_suite_ids=[1,3] shape.
			3: {},
		},
	}}
	provider, err := consensus.NewStaticCoreExtProfileProvider(deployments)
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}
	return provider
}

// TestRuntimeCoreExtPolicyFromStaticProfileProvider proves the production
// wiring chain --genesis-file -> CoreExtProfileProvider -> mempoolCfg /
// minerCfg actually enforces the documented pre-ACTIVE rejection contract
// when the live provider type (consensus.NewStaticCoreExtProfileProvider)
// is used. Existing package-level tests use a testCoreExtProfiles mock and
// would not catch a regression where the production provider type's
// LookupCoreExtProfile semantics drift from the mock.
func TestRuntimeCoreExtPolicyFromStaticProfileProvider(t *testing.T) {
	const extID uint16 = 7

	t.Run("MempoolRejectsPreActiveCoreExtOutput", func(t *testing.T) {
		fromKey := mustNodeMLDSA87Keypair(t)
		fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
		st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

		// Activation height is far ahead of the seeded chainstate
		// (testSpendableChainState seeds spendable P2PK UTXOs with
		// CreationHeight: 1 and sets st.Height = 100), so the next-block
		// height is still strictly below activation_height and the CORE_EXT
		// output tx must be rejected pre-ACTIVE by the mempool admit path.
		profiles := staticCoreExtProvider(t, extID, 1_000_000)
		mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
			PolicyRejectCoreExtPreActivation: true,
			CoreExtProfiles:                  profiles,
		})
		if err != nil {
			t.Fatalf("NewMempoolWithConfig: %v", err)
		}

		txBytes := mustBuildSignedCoreExtOutputTx(t, st.Utxos, outpoints[0], 90, 1, 1, fromKey, fromAddress, extID)
		err = mp.AddTx(txBytes)
		if err == nil {
			t.Fatalf("expected mempool to reject pre-ACTIVE CORE_EXT output, got nil error")
		}
		var admit *TxAdmitError
		if !errors.As(err, &admit) {
			t.Fatalf("expected *TxAdmitError, got %T: %v", err, err)
		}
		if admit.Kind != TxAdmitRejected {
			t.Fatalf("AddTx error kind=%v, want %v (TxAdmitRejected)", admit.Kind, TxAdmitRejected)
		}
		// Tighten the assertion to the exact CORE_EXT pre-ACTIVE policy
		// reason. TxAdmitRejected is a broad bucket that also covers parse,
		// signature, and other check failures; matching the explicit policy
		// message proves this rejection came from the CORE_EXT pre-ACTIVE
		// gate (RejectCoreExtTxPreActivation), not from an unrelated reject
		// path. The expected substring is built from the test's extID
		// constant so renaming extID will not silently break the assertion.
		wantOutputReason := fmt.Sprintf("CORE_EXT output pre-ACTIVE ext_id=%d", extID)
		if !strings.Contains(err.Error(), wantOutputReason) {
			t.Fatalf("AddTx error %q does not contain %q", err.Error(), wantOutputReason)
		}

		// Cover the sibling RelayMetadata path. /submit_tx invokes
		// state.mempool.AddTx, but the relay layer uses RelayMetadata
		// (admissionSnapshotForInputs) which is a distinct snapshot path;
		// the same policy gate must reject pre-ACTIVE CORE_EXT outputs on
		// both. Proof assertion: mp.RelayMetadata returns a non-nil error
		// whose message contains wantOutputReason.
		if _, relayErr := mp.RelayMetadata(txBytes); relayErr == nil || !strings.Contains(relayErr.Error(), wantOutputReason) {
			t.Fatalf("RelayMetadata error %v does not contain %q", relayErr, wantOutputReason)
		}
	})

	t.Run("MempoolAcceptsActiveCoreExtOutput", func(t *testing.T) {
		fromKey := mustNodeMLDSA87Keypair(t)
		fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
		st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

		// activation_height = 0 makes the profile ACTIVE from genesis, so the
		// next-block height passes the activation gate.
		profiles := staticCoreExtProvider(t, extID, 0)
		mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
			PolicyRejectCoreExtPreActivation: true,
			CoreExtProfiles:                  profiles,
		})
		if err != nil {
			t.Fatalf("NewMempoolWithConfig: %v", err)
		}

		txBytes := mustBuildSignedCoreExtOutputTx(t, st.Utxos, outpoints[0], 90, 1, 1, fromKey, fromAddress, extID)
		if err := mp.AddTx(txBytes); err != nil {
			t.Fatalf("expected ACTIVE-profile CORE_EXT output admission, got %v", err)
		}

		// Cover the sibling RelayMetadata path on the ACTIVE admission
		// branch. The runtime-coverage contract requires both pre-ACTIVE
		// rejection AND ACTIVE admission to be asserted through
		// RelayMetadata; the pre-ACTIVE rejection halves are above. Proof
		// assertion: mp.RelayMetadata returns a nil error and a populated
		// RelayTxMetadata (non-zero size) for the same txBytes that AddTx
		// admitted, using the same profiles instance.
		meta, relayErr := mp.RelayMetadata(txBytes)
		if relayErr != nil {
			t.Fatalf("expected ACTIVE-profile CORE_EXT output RelayMetadata success, got %v", relayErr)
		}
		if meta.Size == 0 {
			t.Fatalf("RelayMetadata returned zero Size for admitted CORE_EXT tx")
		}
	})

	t.Run("MempoolRejectsPreActiveCoreExtSpend", func(t *testing.T) {
		// CORE_EXT spend coverage: RejectCoreExtTxPreActivation enforces the
		// pre-ACTIVE gate on transaction inputs whose previous UTXO already
		// has CovenantType=CORE_EXT, in addition to outputs. This sub-test
		// exercises the input branch of RejectCoreExtTxPreActivation against
		// the production provider type built via NewStaticCoreExtProfileProvider.
		// Proof assertion: mp.AddTx returns *TxAdmitError with
		// Kind == TxAdmitRejected and err.Error() containing the
		// fmt.Sprintf-built spend reason (wantSpendReason, derived from
		// the test's extID constant).
		toKey := mustNodeMLDSA87Keypair(t)
		toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

		var prev [32]byte
		prev[0] = 0x55
		st := NewChainState()
		st.HasTip = true
		st.Height = 100
		st.TipHash[0] = 0x11
		st.Utxos[consensus.Outpoint{Txid: prev, Vout: 0}] = consensus.UtxoEntry{
			Value:        100,
			CovenantType: consensus.COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantDataForNodeTest(extID, nil),
		}

		profiles := staticCoreExtProvider(t, extID, 1_000_000)
		mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
			PolicyRejectCoreExtPreActivation: true,
			CoreExtProfiles:                  profiles,
		})
		if err != nil {
			t.Fatalf("NewMempoolWithConfig: %v", err)
		}

		txBytes := mustBuildCoreExtSpendTx(t, prev, 99, 1, 1, toAddress)
		err = mp.AddTx(txBytes)
		if err == nil {
			t.Fatalf("expected mempool to reject pre-ACTIVE CORE_EXT spend, got nil error")
		}
		var admit *TxAdmitError
		if !errors.As(err, &admit) {
			t.Fatalf("expected *TxAdmitError, got %T: %v", err, err)
		}
		if admit.Kind != TxAdmitRejected {
			t.Fatalf("AddTx error kind=%v, want %v (TxAdmitRejected)", admit.Kind, TxAdmitRejected)
		}
		wantSpendReason := fmt.Sprintf("CORE_EXT spend pre-ACTIVE ext_id=%d", extID)
		if !strings.Contains(err.Error(), wantSpendReason) {
			t.Fatalf("AddTx error %q does not contain %q", err.Error(), wantSpendReason)
		}

		// Cover the sibling RelayMetadata path on the input/spend branch.
		// Existing mempool_test.go:TestMempoolPolicyRejectsCoreExtSpendPreActivation
		// exercises both AddTx and RelayMetadata against a mock provider;
		// this assertion proves the same contract holds against the
		// production NewStaticCoreExtProfileProvider provider type. Proof
		// assertion: mp.RelayMetadata returns a non-nil error whose message
		// contains wantSpendReason.
		if _, relayErr := mp.RelayMetadata(txBytes); relayErr == nil || !strings.Contains(relayErr.Error(), wantSpendReason) {
			t.Fatalf("RelayMetadata error %v does not contain %q", relayErr, wantSpendReason)
		}
	})

	t.Run("MinerFiltersPreActiveCoreExtOutput", func(t *testing.T) {
		dir := t.TempDir()
		chainStatePath := ChainStatePath(dir)
		chainState := NewChainState()
		if err := chainState.Save(chainStatePath); err != nil {
			t.Fatalf("save chainstate: %v", err)
		}
		blockStore, err := OpenBlockStore(BlockStorePath(dir))
		if err != nil {
			t.Fatalf("open blockstore: %v", err)
		}
		syncEngine, err := NewSyncEngine(chainState, blockStore, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
		if err != nil {
			t.Fatalf("new sync engine: %v", err)
		}

		// Synthetic prev — mirror miner_core_ext_policy_test.go's setup; the
		// CORE_EXT output covenant is enough to trigger the miner's pre-ACTIVE
		// filter without a fully-signed spend chain (the filter runs before
		// signature checks).
		var prev [32]byte
		prev[0] = 0xA1
		txBytes := mustMarshalTxForNodeTest(t, &consensus.Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []consensus.TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
			Outputs: []consensus.TxOutput{{
				Value:        1,
				CovenantType: consensus.COV_TYPE_CORE_EXT,
				CovenantData: coreExtCovenantDataForNodeTest(extID, nil),
			}},
			Locktime: 0,
		})

		cfg := DefaultMinerConfig()
		cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
		cfg.PolicyRejectCoreExtPreActivation = true
		cfg.CoreExtProfiles = staticCoreExtProvider(t, extID, 1_000_000)
		miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
		if err != nil {
			t.Fatalf("NewMiner: %v", err)
		}
		mb, err := miner.MineOne(context.Background(), [][]byte{txBytes})
		if err != nil {
			t.Fatalf("MineOne: %v", err)
		}
		if mb.TxCount != 1 {
			t.Fatalf("MineOne tx_count=%d, want 1 (coinbase only; pre-ACTIVE CORE_EXT output must be filtered by miner)", mb.TxCount)
		}
	})

	t.Run("MinerIncludesActiveCoreExtOutput", func(t *testing.T) {
		// ACTIVE-profile counterpart to MinerFiltersPreActiveCoreExtOutput.
		// The pre-ACTIVE filter sub-test proves the miner DROPS a CORE_EXT
		// output tx when the profile is not yet active. This sub-test proves
		// the symmetric ACTIVE branch: when the profile is ACTIVE-from-genesis
		// (activation_height=0) and the next-block height passes the
		// activation gate, miner.MineOne INCLUDES a connectable signed
		// CORE_EXT output tx in the produced block. That covers the only
		// runtime branch of the production wiring chain that the
		// mempool/relay sub-tests above leave unproved — the /mine_next
		// pipeline whose `m.sync.ApplyBlock(blockBytes, ...)` connects the
		// new block to the chain.
		//
		// Setup mirrors mempool_test.go:TestMinerMineOneSelectsFromMempool:
		// a real blockstore with a populated chain history 0..100 so that
		// st.TipHash matches a stored header, then the same testSpendableChainState
		// P2PK UTXO and signed-tx helpers used by the mempool sub-tests.
		dir := t.TempDir()
		store, err := OpenBlockStore(BlockStorePath(dir))
		if err != nil {
			t.Fatalf("OpenBlockStore: %v", err)
		}

		var tipHash [32]byte
		for height := uint64(0); height <= 100; height++ {
			h, _ := mustPutBlock(t, store, height, byte(height), height+1, []byte{byte(height)})
			if height == 100 {
				tipHash = h
			}
		}

		fromKey := mustNodeMLDSA87Keypair(t)
		fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
		st, outpoints := testSpendableChainState(fromAddress, []uint64{100})
		st.HasTip = true
		st.Height = 100
		st.TipHash = tipHash

		syncEngine, err := NewSyncEngine(st, store, DefaultSyncConfig(nil, devnetGenesisChainID, ChainStatePath(dir)))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}

		// activation_height = 0: ACTIVE from genesis, so the next-block
		// height (101) passes the activation gate. The same `profiles`
		// instance is wired into both MempoolConfig and MinerConfig — the
		// production buildGenesisCoreExtProfiles -> mempoolCfg/minerCfg
		// pattern — so a regression that admits at mempool but rejects
		// at miner (or vice versa) on the ACTIVE branch would still be
		// caught.
		profiles := staticCoreExtProvider(t, extID, 0)

		mp, err := NewMempoolWithConfig(st, store, devnetGenesisChainID, MempoolConfig{
			PolicyRejectCoreExtPreActivation: true,
			CoreExtProfiles:                  profiles,
		})
		if err != nil {
			t.Fatalf("NewMempoolWithConfig: %v", err)
		}
		syncEngine.SetMempool(mp)

		txBytes := mustBuildSignedCoreExtOutputTx(t, st.Utxos, outpoints[0], 90, 1, 1, fromKey, fromAddress, extID)
		if err := mp.AddTx(txBytes); err != nil {
			t.Fatalf("mp.AddTx (ACTIVE CORE_EXT): %v", err)
		}

		cfg := DefaultMinerConfig()
		cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
		cfg.PolicyRejectCoreExtPreActivation = true
		cfg.CoreExtProfiles = profiles
		miner, err := NewMiner(st, store, syncEngine, cfg)
		if err != nil {
			t.Fatalf("NewMiner: %v", err)
		}

		mb, err := miner.MineOne(context.Background(), nil)
		if err != nil {
			t.Fatalf("MineOne (ACTIVE CORE_EXT): %v", err)
		}

		// Inclusion proof, level 1: tx_count == 2 (coinbase + the only tx
		// admitted to mempool, which is our CORE_EXT tx). A regression
		// where the miner silently filters the ACTIVE CORE_EXT output
		// would surface here as tx_count == 1.
		if mb.TxCount != 2 {
			t.Fatalf("MineOne tx_count=%d, want 2 (coinbase + ACTIVE CORE_EXT output)", mb.TxCount)
		}

		// Inclusion proof, level 2: parse the mined block from disk and
		// verify the non-coinbase txid equals the txid the test submitted.
		// `mb.TxCount==2` alone could be satisfied by an unrelated tx
		// (defensive — the mempool only had one tx in this sub-test, but
		// the assertion makes the proof robust to future test interleaving).
		blockBytes, err := store.GetBlockByHash(mb.Hash)
		if err != nil {
			t.Fatalf("GetBlockByHash(%x): %v", mb.Hash[:], err)
		}
		parsed, err := consensus.ParseBlockBytes(blockBytes)
		if err != nil {
			t.Fatalf("ParseBlockBytes: %v", err)
		}
		if len(parsed.Txs) != 2 || len(parsed.Txids) != 2 {
			t.Fatalf("parsed block tx layout = (%d Txs, %d Txids), want (2, 2)", len(parsed.Txs), len(parsed.Txids))
		}
		submittedTxID := txID(t, txBytes)
		if parsed.Txids[1] != submittedTxID {
			t.Fatalf("non-coinbase txid=%x, want submitted CORE_EXT txid=%x", parsed.Txids[1][:], submittedTxID[:])
		}

		// Inclusion proof, level 3: the included non-coinbase tx really
		// carries a CORE_EXT output, and that output's covenant payload
		// decodes to the test's extID. This closes the residual class
		// "miner included some tx that happened to match the txid but the
		// output is no longer CORE_EXT" — possible only via consensus
		// regression, but the assertion is cheap and surfaces it.
		coreExtTx := parsed.Txs[1]
		var seenCoreExt bool
		for _, out := range coreExtTx.Outputs {
			if out.CovenantType != consensus.COV_TYPE_CORE_EXT {
				continue
			}
			seenCoreExt = true
			cov, err := consensus.ParseCoreExtCovenantData(out.CovenantData)
			if err != nil {
				t.Fatalf("ParseCoreExtCovenantData: %v", err)
			}
			if cov.ExtID != extID {
				t.Fatalf("included CORE_EXT output ext_id=%d, want %d", cov.ExtID, extID)
			}
		}
		if !seenCoreExt {
			t.Fatalf("included non-coinbase tx has no CORE_EXT output covenant")
		}
	})
}
