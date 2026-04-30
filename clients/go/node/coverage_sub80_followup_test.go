package node

import (
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type errCoreExtProfiles struct{}

func (errCoreExtProfiles) LookupCoreExtProfile(uint16, uint64) (consensus.CoreExtProfile, bool, error) {
	return consensus.CoreExtProfile{}, false, errors.New("boom")
}

func TestCoverageResidual_MempoolBranches(t *testing.T) {
	if _, err := NewMempool(nil, nil, [32]byte{}); err == nil {
		t.Fatalf("expected nil chainstate rejection")
	}
	if err := (*Mempool)(nil).EvictConfirmed([]byte{0x00}); err == nil {
		t.Fatalf("expected nil mempool eviction rejection")
	}
	if err := (*Mempool)(nil).RemoveConflicting([]byte{0x00}); err == nil {
		t.Fatalf("expected nil mempool conflict rejection")
	}
	if err := (*Mempool)(nil).EvictConfirmedParsed(&consensus.ParsedBlock{}); err == nil {
		t.Fatalf("expected nil mempool parsed eviction rejection")
	}
	if err := (*Mempool)(nil).RemoveConflictingParsed(&consensus.ParsedBlock{}); err == nil {
		t.Fatalf("expected nil mempool parsed conflict rejection")
	}
	if got := compareFeeRate(nil, &mempoolEntry{fee: 1, weight: 1, size: 1}); got != 0 {
		t.Fatalf("compareFeeRate(nil)= %d", got)
	}
	if got := compareFeeRate(&mempoolEntry{fee: 2, weight: 1, size: 1}, &mempoolEntry{fee: 1, weight: 1, size: 1}); got <= 0 {
		t.Fatalf("expected first feerate to win")
	}
	if got := compareFeeRate(&mempoolEntry{fee: 1, weight: 2, size: 1}, &mempoolEntry{fee: 1, weight: 1, size: 2}); got >= 0 {
		t.Fatalf("expected second feerate to win")
	}
	entries := []*mempoolEntry{{txid: [32]byte{0x02}, fee: 10, weight: 1, size: 1}, {txid: [32]byte{0x01}, fee: 10, weight: 1, size: 1}}
	sortMempoolEntries(entries)
	if entries[0].txid[0] != 0x01 {
		t.Fatalf("expected deterministic txid tie-break")
	}

	st := NewChainState()
	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	if mtp, err := mp.nextBlockMTP(0); err != nil || mtp != 0 {
		t.Fatalf("nextBlockMTP(0)=%d,%v", mtp, err)
	}
	if err := mp.EvictConfirmedParsed(nil); err == nil {
		t.Fatalf("expected nil parsed block eviction rejection")
	}
	if err := mp.RemoveConflictingParsed(nil); err == nil {
		t.Fatalf("expected nil parsed block conflict rejection")
	}
	if err := mp.validateNonCapacityAdmissionLocked(nil); err == nil {
		t.Fatalf("expected nil mempool entry rejection")
	}
	if err := mp.EvictConfirmed([]byte{0x00}); err == nil {
		t.Fatalf("expected invalid block bytes rejection")
	}
	if err := mp.RemoveConflicting([]byte{0x00}); err == nil {
		t.Fatalf("expected invalid block bytes rejection")
	}
}

func TestCoverageResidual_RemoveConflictingParsesBlockBytes(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	txPool := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	txBlock := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txPool); err != nil {
		t.Fatalf("AddTx(txPool): %v", err)
	}

	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0))
	block := buildMultiTxBlock(t, [32]byte{}, consensus.POW_LIMIT, 1, coinbase, txBlock)
	if err := mp.RemoveConflicting(block); err != nil {
		t.Fatalf("RemoveConflicting: %v", err)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
}

func TestCoverageResidual_MempoolLimitBranches(t *testing.T) {
	st := NewChainState()
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 1,
		MaxBytes:        10,
	})
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	mp.mu.Lock()
	if err := mp.validateNonCapacityAdmissionLocked(&mempoolEntry{txid: [32]byte{0x01}, size: 0}); err == nil {
		t.Fatalf("expected invalid size rejection")
	}
	if err := mp.addEntryLocked(&mempoolEntry{txid: [32]byte{0x02}, fee: 1, weight: 1, size: 1}); err != nil {
		t.Fatalf("addEntryLocked(count seed): %v", err)
	}
	if err := mp.addEntryLocked(&mempoolEntry{txid: [32]byte{0x03}, fee: 1, weight: 1, size: 1}); err == nil {
		t.Fatalf("expected capacity rejection")
	}
	mp.mu.Unlock()

	mpBytes, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        2,
	})
	if err != nil {
		t.Fatalf("NewMempool(bytes): %v", err)
	}
	mpBytes.mu.Lock()
	if err := mpBytes.addEntryLocked(&mempoolEntry{txid: [32]byte{0x04}, fee: 1, weight: 1, size: 1}); err != nil {
		t.Fatalf("addEntryLocked(byte seed): %v", err)
	}
	if err := mpBytes.addEntryLocked(&mempoolEntry{txid: [32]byte{0x05}, fee: 1, weight: 1, size: 2}); err == nil {
		t.Fatalf("expected byte-capacity rejection")
	}
	mpBytes.usedBytes = 1
	mpBytes.deleteEntryLocked([32]byte{0x06}, &mempoolEntry{size: 2})
	if mpBytes.usedBytes != 0 {
		t.Fatalf("delete underflow guard left usedBytes=%d", mpBytes.usedBytes)
	}
	mpBytes.mu.Unlock()
}

func TestCoverageResidual_CoreExtPolicyBranches(t *testing.T) {
	if reject, reason, err := rejectCoreExtCovenantDataPreActivation([]byte{0x01}, 0, nil, "output"); !reject || err == nil || reason == "" {
		t.Fatalf("expected parse failure path, got reject=%v reason=%q err=%v", reject, reason, err)
	}
	if active, err := coreExtProfileActive(1, 0, nil); err != nil || active {
		t.Fatalf("nil profiles should be inactive: active=%v err=%v", active, err)
	}
	if reject, reason, err := rejectCoreExtCovenantDataPreActivation([]byte{0x01, 0x00, 0x00}, 0, errCoreExtProfiles{}, "spend"); !reject || err == nil || reason == "" {
		t.Fatalf("expected lookup error path, got reject=%v reason=%q err=%v", reject, reason, err)
	}
	if reject, reason, err := RejectCoreExtTxPreActivation(&consensus.Tx{TxNonce: 1}, nil, 0, nil); err != nil || reject || reason != "" {
		t.Fatalf("tx without core-ext should pass: reject=%v reason=%q err=%v", reject, reason, err)
	}
}

func TestCoverageResidual_SyncBranches(t *testing.T) {
	if got := normalizedNetworkName("  MAINNET  "); got != "mainnet" {
		t.Fatalf("normalizedNetworkName=%q", got)
	}
	var nilEngine *SyncEngine
	if req := nilEngine.HeaderSyncRequest(); req.HasFrom || req.Limit != 0 {
		t.Fatalf("nil HeaderSyncRequest=%+v", req)
	}
	if _, err := nilEngine.ApplyBlock(nil, nil); err == nil {
		t.Fatalf("expected nil ApplyBlock rejection")
	}
	if _, err := nilEngine.DisconnectTip(); err == nil {
		t.Fatalf("expected nil DisconnectTip rejection")
	}
	if err := testValidateIncomingChainID(0, [32]byte{0x01}); err == nil {
		t.Fatalf("expected genesis chain_id mismatch")
	}
	if got, err := testBlockStoreCanonicalCount(nil); err != nil || got != 0 {
		t.Fatalf("nil blockstore count=%d err=%v", got, err)
	}

	st := NewChainState()
	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, devnetGenesisChainID, ""))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.DisconnectTip(); err == nil {
		t.Fatalf("expected missing blockstore rejection")
	}
	engine.SetMempool(nil)
	if engine.mempool != nil {
		t.Fatalf("expected mempool to remain nil")
	}
}
