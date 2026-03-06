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
	if got := compareFeeRate(nil, &mempoolEntry{fee: 1, size: 1}); got != 0 {
		t.Fatalf("compareFeeRate(nil)= %d", got)
	}
	if got := compareFeeRate(&mempoolEntry{fee: 2, size: 1}, &mempoolEntry{fee: 1, size: 1}); got <= 0 {
		t.Fatalf("expected first feerate to win")
	}
	if got := compareFeeRate(&mempoolEntry{fee: 1, size: 2}, &mempoolEntry{fee: 1, size: 1}); got >= 0 {
		t.Fatalf("expected second feerate to win")
	}
	entries := []*mempoolEntry{{txid: [32]byte{0x02}, fee: 10, size: 1}, {txid: [32]byte{0x01}, fee: 10, size: 1}}
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
	if err := validateIncomingChainID(0, [32]byte{0x01}); err == nil {
		t.Fatalf("expected genesis chain_id mismatch")
	}
	if got, err := blockStoreCanonicalCount(nil); err != nil || got != 0 {
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
