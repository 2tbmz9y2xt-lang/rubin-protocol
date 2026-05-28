package node

import (
	"context"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func daCommitTxBytesForMinerPolicyTest(txNonce uint64, manifest []byte) []byte {
	var daID [32]byte
	daID[0] = 0xa1
	var retl [32]byte
	retl[0] = 0xa2
	var txDataRoot [32]byte
	txDataRoot[0] = 0xa3
	var stateRoot [32]byte
	stateRoot[0] = 0xa4
	var withdrawalsRoot [32]byte
	withdrawalsRoot[0] = 0xa5

	b := make([]byte, 0, 256+len(manifest))
	b = consensus.AppendU32le(b, 1)
	b = append(b, 0x01) // tx_kind (DA commit)
	b = consensus.AppendU64le(b, txNonce)
	b = consensus.AppendCompactSize(b, 0) // input_count
	b = consensus.AppendCompactSize(b, 0) // output_count
	b = consensus.AppendU32le(b, 0)       // locktime

	b = append(b, daID[:]...)
	b = consensus.AppendU16le(b, 1) // chunk_count
	b = append(b, retl[:]...)
	b = consensus.AppendU64le(b, 1) // batch_number
	b = append(b, txDataRoot[:]...)
	b = append(b, stateRoot[:]...)
	b = append(b, withdrawalsRoot[:]...)
	b = append(b, 0x00)                   // batch_sig_suite
	b = consensus.AppendCompactSize(b, 0) // batch_sig_len

	b = consensus.AppendCompactSize(b, 0)                     // witness_count
	b = consensus.AppendCompactSize(b, uint64(len(manifest))) // da_payload_len (manifest)
	b = append(b, manifest...)
	return b
}

func minerMasterSwitchAnchorTx(t *testing.T, marker byte) (*consensus.Tx, map[consensus.Outpoint]consensus.UtxoEntry) {
	t.Helper()
	var prev [32]byte
	prev[0] = marker
	var anchor [32]byte
	anchor[0] = marker
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: uint64(marker),
		Inputs:  []consensus.TxInput{{PrevTxid: prev, PrevVout: 0}},
		Outputs: []consensus.TxOutput{{
			Value:        0,
			CovenantType: consensus.COV_TYPE_ANCHOR,
			CovenantData: anchor[:],
		}},
	}
	if _, _, _, err := consensus.TxWeightAndStats(tx); err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}
	utxos := map[consensus.Outpoint]consensus.UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: testP2PKCovenantData(marker),
		},
	}
	return tx, utxos
}

func requireMinerCandidateReject(t *testing.T, cfg MinerConfig, tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry, wantReject bool, wantNextDa uint64) {
	t.Helper()
	reject, nextDa, err := (&Miner{cfg: cfg}).rejectCandidate(tx, utxos, 0, 0)
	if err != nil {
		t.Fatalf("rejectCandidate: %v", err)
	}
	if reject != wantReject {
		t.Fatalf("reject=%v want %v", reject, wantReject)
	}
	if nextDa != wantNextDa {
		t.Fatalf("nextDa=%d want %d", nextDa, wantNextDa)
	}
}

func TestMinerDaAnchorMasterSwitchOffIgnoresAnchorSubflag(t *testing.T) {
	tx, utxos := minerMasterSwitchAnchorTx(t, 0x71)
	cfg := DefaultMinerConfig()
	cfg.PolicyDaAnchorAntiAbuse = false
	cfg.PolicyRejectNonCoinbaseAnchorOutputs = true

	requireMinerCandidateReject(t, cfg, tx, utxos, false, 0)
}

func TestMinerDaAnchorMasterSwitchOnRejectsNonCoinbaseAnchorWhenSubflagOn(t *testing.T) {
	tx, utxos := minerMasterSwitchAnchorTx(t, 0x72)
	cfg := DefaultMinerConfig()
	cfg.PolicyDaAnchorAntiAbuse = true
	cfg.PolicyRejectNonCoinbaseAnchorOutputs = true

	requireMinerCandidateReject(t, cfg, tx, utxos, true, 0)
}

func TestMinerDaAnchorMasterSwitchOnAllowsAnchorWhenSubflagOff(t *testing.T) {
	tx, utxos := minerMasterSwitchAnchorTx(t, 0x73)
	cfg := DefaultMinerConfig()
	cfg.PolicyDaAnchorAntiAbuse = true
	cfg.PolicyRejectNonCoinbaseAnchorOutputs = false

	requireMinerCandidateReject(t, cfg, tx, utxos, false, 0)

	daTx, daUtxos, _ := daTestTx(t, 0x74, 1_000_000, 900_000, 11)
	cfg.PolicyMaxDaBytesPerBlock = 10
	cfg.MinDaFeeRate = 0
	cfg.PolicyDaSurchargePerByte = 0
	requireMinerCandidateReject(t, cfg, daTx, daUtxos, true, 0)
}

func TestMinerCoreExtPolicyStillRunsWhenDaAnchorMasterOff(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x75
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_EXT, coreExtCovenantData(7, nil), nil)
	tx := mustParseTx(t, raw)
	utxos := map[consensus.Outpoint]consensus.UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: testP2PKCovenantData(0x75),
		},
	}
	cfg := DefaultMinerConfig()
	cfg.PolicyDaAnchorAntiAbuse = false
	cfg.PolicyRejectCoreExtPreActivation = true
	cfg.CoreExtProfiles = nil

	requireMinerCandidateReject(t, cfg, tx, utxos, true, 0)
}

func TestMinerPolicyRejectsNonCoinbaseAnchorOutputs(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	chainState.Utxos = make(map[consensus.Outpoint]consensus.UtxoEntry)
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
	var anchor [32]byte
	anchor[0] = 0x42
	txBytes := mustMarshalTxForNodeTest(t, &consensus.Tx{
		Version:   1,
		TxKind:    0x00,
		TxNonce:   1,
		Inputs:    []consensus.TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs:   []consensus.TxOutput{{Value: 0, CovenantType: consensus.COV_TYPE_ANCHOR, CovenantData: anchor[:]}},
		Locktime:  0,
		Witness:   []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL}},
		DaPayload: nil,
	})

	cfg := DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
	cfg.PolicyDaAnchorAntiAbuse = true
	cfg.PolicyRejectNonCoinbaseAnchorOutputs = true
	miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}
	mb, err := miner.MineOne(context.Background(), [][]byte{txBytes})
	if err != nil {
		t.Fatalf("mine one: %v", err)
	}
	if mb.TxCount != 1 {
		t.Fatalf("tx_count=%d, want 1 (coinbase only; non-coinbase CORE_ANCHOR must be filtered)", mb.TxCount)
	}

	cfg.PolicyDaAnchorAntiAbuse = false
	miner2, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner2: %v", err)
	}
	if _, err := miner2.MineOne(context.Background(), [][]byte{txBytes}); err == nil {
		t.Fatalf("expected mining failure when anchor tx is not filtered")
	}
}

func TestMinerPolicyCapsDaTemplateBytes(t *testing.T) {
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

	daTx := daCommitTxBytesForMinerPolicyTest(1, []byte("hello world")) // 11 bytes

	cfg := DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
	cfg.PolicyDaAnchorAntiAbuse = true
	cfg.PolicyRejectNonCoinbaseAnchorOutputs = false
	cfg.PolicyDaSurchargePerByte = 0
	cfg.PolicyMaxDaBytesPerBlock = 10

	miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}
	mb, err := miner.MineOne(context.Background(), [][]byte{daTx})
	if err != nil {
		t.Fatalf("mine one: %v", err)
	}
	if mb.TxCount != 1 {
		t.Fatalf("tx_count=%d, want 1 (coinbase only; DA tx over policy budget must be filtered)", mb.TxCount)
	}

	cfg.PolicyDaAnchorAntiAbuse = false
	miner2, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner2: %v", err)
	}
	mb, err = miner2.MineOne(context.Background(), [][]byte{daTx})
	if err != nil {
		t.Fatalf("mine one with DA policy disabled: %v", err)
	}
	if mb.TxCount != 1 {
		t.Fatalf("tx_count=%d, want 1 (coinbase only; standalone DA tx must be filtered)", mb.TxCount)
	}
}
