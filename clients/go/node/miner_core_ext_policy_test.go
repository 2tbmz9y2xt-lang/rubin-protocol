package node

import (
	"context"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func coreExtCovenantDataForNodeTest(extID uint16, payload []byte) []byte {
	out := consensus.AppendU16le(nil, extID)
	out = consensus.AppendCompactSize(out, uint64(len(payload)))
	out = append(out, payload...)
	return out
}

func mustMarshalTxForNodeTest(t *testing.T, tx *consensus.Tx) []byte {
	t.Helper()
	b, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return b
}

func TestMinerPolicyFiltersCoreExtOutputCreation(t *testing.T) {
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

	var prev [32]byte
	prev[0] = 0x11
	txBytes := mustMarshalTxForNodeTest(t, &consensus.Tx{
		Version:   0,
		TxKind:    0x00,
		TxNonce:   1,
		Inputs:    []consensus.TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs:   []consensus.TxOutput{{Value: 1, CovenantType: consensus.COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantDataForNodeTest(1, nil)}},
		Locktime:  0,
		Witness:   nil,
		DaPayload: nil,
	})

	cfg := DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
	cfg.PolicyRejectCoreExtPreActivation = true
	miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}

	mb, err := miner.MineOne(context.Background(), [][]byte{txBytes})
	if err != nil {
		t.Fatalf("mine one: %v", err)
	}
	if mb.TxCount != 1 {
		t.Fatalf("tx_count=%d, want 1 (coinbase only; CORE_EXT output tx must be filtered)", mb.TxCount)
	}

	cfg.PolicyRejectCoreExtPreActivation = false
	miner2, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner2: %v", err)
	}
	if _, err := miner2.MineOne(context.Background(), [][]byte{txBytes}); err == nil {
		t.Fatalf("expected mining failure when CORE_EXT output tx is not filtered")
	}
}

func TestMinerPolicyFiltersCoreExtSpend(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x22

	var anchor [32]byte
	anchor[0] = 0x01

	txBytes := mustMarshalTxForNodeTest(t, &consensus.Tx{
		Version:   0,
		TxKind:    0x00,
		TxNonce:   1,
		Inputs:    []consensus.TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs:   []consensus.TxOutput{{Value: 0, CovenantType: consensus.COV_TYPE_ANCHOR, CovenantData: anchor[:]}},
		Locktime:  0,
		Witness:   []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL}},
		DaPayload: nil,
	})

	setup := func(t *testing.T) (*ChainState, *BlockStore, *SyncEngine, MinerConfig) {
		t.Helper()
		dir := t.TempDir()
		chainStatePath := ChainStatePath(dir)

		chainState := NewChainState()
		chainState.Utxos = make(map[consensus.Outpoint]consensus.UtxoEntry)
		chainState.Utxos[consensus.Outpoint{Txid: prev, Vout: 0}] = consensus.UtxoEntry{
			Value:        100,
			CovenantType: consensus.COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantDataForNodeTest(1, nil),
		}
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
		cfg := DefaultMinerConfig()
		cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
		return chainState, blockStore, syncEngine, cfg
	}

	chainState1, blockStore1, syncEngine1, cfg1 := setup(t)
	cfg1.PolicyRejectCoreExtPreActivation = false
	miner1, err := NewMiner(chainState1, blockStore1, syncEngine1, cfg1)
	if err != nil {
		t.Fatalf("new miner1: %v", err)
	}
	mb1, err := miner1.MineOne(context.Background(), [][]byte{txBytes})
	if err != nil {
		t.Fatalf("mine one (policy off): %v", err)
	}
	if mb1.TxCount != 2 {
		t.Fatalf("tx_count=%d, want 2 (coinbase + CORE_EXT spend)", mb1.TxCount)
	}

	chainState2, blockStore2, syncEngine2, cfg2 := setup(t)
	cfg2.PolicyRejectCoreExtPreActivation = true
	miner2, err := NewMiner(chainState2, blockStore2, syncEngine2, cfg2)
	if err != nil {
		t.Fatalf("new miner2: %v", err)
	}
	mb2, err := miner2.MineOne(context.Background(), [][]byte{txBytes})
	if err != nil {
		t.Fatalf("mine one (policy on): %v", err)
	}
	if mb2.TxCount != 1 {
		t.Fatalf("tx_count=%d, want 1 (coinbase only; CORE_EXT spend must be filtered)", mb2.TxCount)
	}
}
