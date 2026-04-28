package node

// Runtime coverage for the CORE_EXT policy surface as wired by the rubin-node
// binary. Existing package-level tests in mempool_test.go and
// miner_core_ext_policy_test.go cover the mempool / miner behavior with a
// `testCoreExtProfiles` mock provider; this file complements them by
// exercising the same admit / mine paths through a
// `consensus.NewStaticCoreExtProfileProvider`-constructed
// CoreExtProfileProvider — i.e. the exact provider type that
// clients/go/cmd/rubin-node/main.go's buildGenesisCoreExtProfiles returns when the
// operator passes --genesis-file with a populated core_ext_profiles[]
// section.
//
// In production:
//   * clients/go/cmd/rubin-node/main.go:800 calls buildGenesisCoreExtProfiles(...) and
//     receives a consensus.NewStaticCoreExtProfileProvider(...) back;
//   * clients/go/cmd/rubin-node/main.go:403 writes that provider into mempoolCfg;
//   * clients/go/cmd/rubin-node/main.go:456 (and :513) writes the same provider into
//     minerCfg.
//
// This test reproduces the wiring contract in-process: it builds a provider
// via the same public constructor that buildGenesisCoreExtProfiles uses, then
// hands it to MempoolConfig and MinerConfig and verifies that:
//   * pre-ACTIVE CORE_EXT output tx is rejected by mempool.AddTx (the policy
//     rejection path used by /submit_tx via state.mempool.AddTx);
//   * pre-ACTIVE CORE_EXT output tx is filtered by miner.MineOne (the policy
//     filter path used by /mine_next);
//   * ACTIVE-profile CORE_EXT output tx is admitted by mempool.AddTx when
//     the activation height is at or below the next-block height.

import (
	"context"
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// staticCoreExtProvider returns a CoreExtProfileProvider built via the same
// public constructor that clients/go/cmd/rubin-node/main.go's buildGenesisCoreExtProfiles
// uses when --genesis-file core_ext_profiles[] is non-empty.
func staticCoreExtProvider(t *testing.T, extID uint16, activationHeight uint64) consensus.CoreExtProfileProvider {
	t.Helper()
	deployments := []consensus.CoreExtDeploymentProfile{{
		ExtID:            extID,
		ActivationHeight: activationHeight,
		// NewStaticCoreExtProfileProvider rejects deployments with empty
		// AllowedSuites; the production buildGenesisCoreExtProfiles surfaces
		// the same constraint via the genesis JSON's allowed_suite_ids[]
		// field. The values here mirror clients/go/cmd/rubin-node/main_test.go's
		// TestParseGenesisConfigFullBuildsCoreExtProfiles fixture.
		AllowedSuites: map[uint8]struct{}{1: {}, 3: {}},
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

		// Activation height is far ahead of the seeded chainstate (which has
		// a single UTXO at creation_height=0), so the next-block height is
		// strictly below activation_height and the CORE_EXT output tx must be
		// rejected pre-ACTIVE by the mempool admit path.
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
}
