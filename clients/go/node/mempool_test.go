package node

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestMempoolAdd(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
}

func TestMempoolRelayMetadata(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 3, 5, fromKey, fromAddress, toAddress)
	meta, err := mp.RelayMetadata(txBytes)
	if err != nil {
		t.Fatalf("RelayMetadata: %v", err)
	}
	if meta.Fee != 3 {
		t.Fatalf("fee=%d, want 3", meta.Fee)
	}
	if meta.Size != len(txBytes) {
		t.Fatalf("size=%d, want %d", meta.Size, len(txBytes))
	}
}

func TestMempoolRelayMetadataNil(t *testing.T) {
	var mp *Mempool
	if _, err := mp.RelayMetadata([]byte{0x01}); err == nil {
		t.Fatal("nil mempool should reject RelayMetadata")
	}
}

func TestMempoolPolicyRejectsNonCoinbaseAnchorOutputs(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectNonCoinbaseAnchorOutputs: true,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedAnchorOutputTx(t, st.Utxos, outpoints[0], 0, 1, 1, fromKey, toAddress)
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "non-coinbase CORE_ANCHOR") {
		t.Fatalf("expected non-coinbase anchor policy rejection, got %v", err)
	}
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "non-coinbase CORE_ANCHOR") {
		t.Fatalf("expected relay metadata anchor policy rejection, got %v", err)
	}
}

func TestMempoolPolicyRejectsLowFeeDaCommit(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyDaSurchargePerByte: 1,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedDaCommitTx(t, st.Utxos, outpoints[0], 99, 1, 1, fromKey, toAddress, []byte("0123456789"))
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "DA fee below policy minimum") {
		t.Fatalf("expected DA surcharge rejection, got %v", err)
	}
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "DA fee below policy minimum") {
		t.Fatalf("expected relay metadata DA surcharge rejection, got %v", err)
	}
}

func TestMempoolPolicyAllowsSufficientFeeDaCommit(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyDaSurchargePerByte: 1,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedDaCommitTx(t, st.Utxos, outpoints[0], 80, 10, 1, fromKey, toAddress, []byte("0123456789"))
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("expected DA tx admission, got %v", err)
	}
}

func TestMempoolPolicyRejectsCoreExtOutputPreActivation(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectCoreExtPreActivation: true,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedCoreExtOutputTx(t, st.Utxos, outpoints[0], 90, 1, 1, fromKey, fromAddress, 7)
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "CORE_EXT output pre-ACTIVE ext_id=7") {
		t.Fatalf("expected CORE_EXT output rejection, got %v", err)
	}
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "CORE_EXT output pre-ACTIVE ext_id=7") {
		t.Fatalf("expected relay CORE_EXT output rejection, got %v", err)
	}
}

func TestMempoolPolicyRejectsCoreExtSpendPreActivation(t *testing.T) {
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
		CovenantData: coreExtCovenantDataForNodeTest(7, nil),
	}

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectCoreExtPreActivation: true,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildCoreExtSpendTx(t, prev, 99, 1, 1, toAddress)
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "CORE_EXT spend pre-ACTIVE ext_id=7") {
		t.Fatalf("expected CORE_EXT spend rejection, got %v", err)
	}
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "CORE_EXT spend pre-ACTIVE ext_id=7") {
		t.Fatalf("expected relay CORE_EXT spend rejection, got %v", err)
	}
}

func TestMempoolPolicyAllowsCoreExtWhenProfileActive(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectCoreExtPreActivation: true,
		CoreExtProfiles:                  testCoreExtProfiles{activeByExtID: map[uint16]bool{7: true}},
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedCoreExtOutputTx(t, st.Utxos, outpoints[0], 90, 1, 1, fromKey, fromAddress, 7)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("expected CORE_EXT tx admission, got %v", err)
	}
	meta, err := mp.RelayMetadata(txBytes)
	if err != nil {
		t.Fatalf("expected relay metadata success, got %v", err)
	}
	if meta.Fee != 1 {
		t.Fatalf("relay fee=%d, want 1", meta.Fee)
	}
}

func TestMempoolPolicyRejectsNilCheckedTransaction(t *testing.T) {
	mp := &Mempool{}
	if err := mp.applyPolicyLocked(nil, 0); err == nil || !strings.Contains(err.Error(), "nil checked transaction") {
		t.Fatalf("expected nil checked transaction rejection, got %v", err)
	}
	if err := mp.applyPolicyLocked(&consensus.CheckedTransaction{}, 0); err == nil || !strings.Contains(err.Error(), "nil checked transaction") {
		t.Fatalf("expected nil checked tx rejection, got %v", err)
	}
}

func TestMempoolPolicyPropagatesDaFeeComputationErrors(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})
	txBytes := mustBuildSignedDaCommitTx(t, st.Utxos, outpoints[0], 80, 10, 1, fromKey, toAddress, []byte("0123456789"))
	tx, _, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx(da): %v", err)
	}

	mp := &Mempool{
		chainState: &ChainState{},
		policy: MempoolConfig{
			PolicyDaSurchargePerByte: 1,
		},
	}
	if err := mp.applyPolicyLocked(&consensus.CheckedTransaction{Tx: tx}, 101); err == nil || !strings.Contains(err.Error(), "nil utxo set") {
		t.Fatalf("expected DA fee computation error, got %v", err)
	}
}

func TestMempoolDoubleSpend(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 89, 2, 2, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	if err := mp.AddTx(tx2); err == nil {
		t.Fatalf("expected double-spend rejection")
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
}

func TestMempoolFullEvictsLowestPriority(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100, 100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	mp.maxTxs = 2

	txLow := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	txHigh := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 4, 2, fromKey, fromAddress, toAddress)
	txBetter := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 90, 2, 3, fromKey, fromAddress, toAddress)

	if err := mp.AddTx(txLow); err != nil {
		t.Fatalf("AddTx(low): %v", err)
	}
	if err := mp.AddTx(txHigh); err != nil {
		t.Fatalf("AddTx(high): %v", err)
	}
	if err := mp.AddTx(txBetter); err != nil {
		t.Fatalf("AddTx(better) should evict low priority entry: %v", err)
	}
	if got := mp.Len(); got != 2 {
		t.Fatalf("mempool len=%d, want 2", got)
	}

	selected := mp.SelectTransactions(3, 1<<20)
	if len(selected) != 2 {
		t.Fatalf("selected=%d, want 2", len(selected))
	}
	got := []string{txIDHex(t, selected[0]), txIDHex(t, selected[1])}
	wantHigh := txIDHex(t, txHigh)
	wantBetter := txIDHex(t, txBetter)
	wantLow := txIDHex(t, txLow)
	if got[0] != wantHigh || got[1] != wantBetter {
		t.Fatalf("selected=%v, want [%s %s]", got, wantHigh, wantBetter)
	}
	if got[0] == wantLow || got[1] == wantLow {
		t.Fatalf("lowest-priority tx should have been evicted: %v", got)
	}
}

func TestMempoolFullRejectsWorsePriorityCandidate(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100, 100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	mp.maxTxs = 2

	txLow := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 2, 1, fromKey, fromAddress, toAddress)
	txHigh := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 4, 2, fromKey, fromAddress, toAddress)
	txWorse := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 90, 1, 3, fromKey, fromAddress, toAddress)

	if err := mp.AddTx(txLow); err != nil {
		t.Fatalf("AddTx(low): %v", err)
	}
	if err := mp.AddTx(txHigh); err != nil {
		t.Fatalf("AddTx(high): %v", err)
	}
	if err := mp.AddTx(txWorse); err == nil || !strings.Contains(err.Error(), "mempool full") {
		t.Fatalf("expected mempool full rejection, got %v", err)
	}
	if got := mp.Len(); got != 2 {
		t.Fatalf("mempool len=%d, want 2", got)
	}

	selected := mp.SelectTransactions(3, 1<<20)
	got := []string{txIDHex(t, selected[0]), txIDHex(t, selected[1])}
	if got[0] != txIDHex(t, txHigh) || got[1] != txIDHex(t, txLow) {
		t.Fatalf("selected=%v, want [%s %s]", got, txIDHex(t, txHigh), txIDHex(t, txLow))
	}
}

func TestMempoolFullRejectPreservesFutureEvictionCandidate(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100, 100, 100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	mp.maxTxs = 2

	txLow := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 2, 1, fromKey, fromAddress, toAddress)
	txHigh := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 4, 2, fromKey, fromAddress, toAddress)
	txWorse := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 90, 1, 3, fromKey, fromAddress, toAddress)
	txBetter := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[3]}, 90, 3, 4, fromKey, fromAddress, toAddress)

	if err := mp.AddTx(txLow); err != nil {
		t.Fatalf("AddTx(low): %v", err)
	}
	if err := mp.AddTx(txHigh); err != nil {
		t.Fatalf("AddTx(high): %v", err)
	}
	if err := mp.AddTx(txWorse); err == nil || !strings.Contains(err.Error(), "mempool full") {
		t.Fatalf("expected mempool full rejection, got %v", err)
	}
	if err := mp.AddTx(txBetter); err != nil {
		t.Fatalf("AddTx(better) should still evict low priority entry after prior reject: %v", err)
	}

	selected := mp.SelectTransactions(3, 1<<20)
	got := []string{txIDHex(t, selected[0]), txIDHex(t, selected[1])}
	if got[0] != txIDHex(t, txHigh) || got[1] != txIDHex(t, txBetter) {
		t.Fatalf("selected=%v, want [%s %s]", got, txIDHex(t, txHigh), txIDHex(t, txBetter))
	}
}

func TestRestoreMempoolSnapshotClearsStaleWorstHeapState(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	mp.maxTxs = 1

	txLow := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	txBetter := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 3, 2, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txLow); err != nil {
		t.Fatalf("AddTx(low): %v", err)
	}

	snapshot, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}

	staleTxid := [32]byte{0xee}
	staleItem := &mempoolHeapItem{txid: staleTxid, heapID: 99, index: 0}
	mp.worstHeap = mempoolWorstHeap{staleItem}
	mp.heapItems = map[[32]byte]*mempoolHeapItem{staleTxid: staleItem}
	mp.heapSeqs = map[[32]byte]uint64{staleTxid: 99}

	if err := restoreMempoolSnapshot(mp, snapshot); err != nil {
		t.Fatalf("restoreMempoolSnapshot: %v", err)
	}
	if len(mp.worstHeap) != 0 || len(mp.heapItems) != 0 || len(mp.heapSeqs) != 0 {
		t.Fatalf("restore must clear heap state: heap=%d items=%d seqs=%d", len(mp.worstHeap), len(mp.heapItems), len(mp.heapSeqs))
	}
	if err := mp.AddTx(txBetter); err != nil {
		t.Fatalf("AddTx(better) after restore should evict low priority entry: %v", err)
	}

	selected := mp.SelectTransactions(2, 1<<20)
	if len(selected) != 1 {
		t.Fatalf("selected count=%d, want 1", len(selected))
	}
	if txIDHex(t, selected[0]) != txIDHex(t, txBetter) {
		t.Fatalf("selected=%s, want %s", txIDHex(t, selected[0]), txIDHex(t, txBetter))
	}
}

func TestMempoolEviction(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}

	block := buildSingleTxBlock(t, [32]byte{}, consensus.POW_LIMIT, 1, txBytes)
	if err := mp.EvictConfirmed(block); err != nil {
		t.Fatalf("EvictConfirmed: %v", err)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
	if got := len(mp.worstHeap); got != 0 {
		t.Fatalf("worstHeap len=%d, want 0", got)
	}
	if got := len(mp.heapItems); got != 0 {
		t.Fatalf("heapItems len=%d, want 0", got)
	}
}

func TestMempoolSelectByFee(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100, 100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txLow := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	txHigh := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 3, 2, fromKey, fromAddress, toAddress)
	txMid := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 90, 2, 3, fromKey, fromAddress, toAddress)
	for _, txBytes := range [][]byte{txLow, txHigh, txMid} {
		if err := mp.AddTx(txBytes); err != nil {
			t.Fatalf("AddTx: %v", err)
		}
	}

	selected := mp.SelectTransactions(2, 1<<20)
	if len(selected) != 2 {
		t.Fatalf("selected=%d, want 2", len(selected))
	}
	if got, want := txIDHex(t, selected[0]), txIDHex(t, txHigh); got != want {
		t.Fatalf("selected[0]=%s, want %s", got, want)
	}
	if got, want := txIDHex(t, selected[1]), txIDHex(t, txMid); got != want {
		t.Fatalf("selected[1]=%s, want %s", got, want)
	}
}

func TestMinerMineOneSelectsFromMempool(t *testing.T) {
	dir := t.TempDir()
	store := mustOpenBlockStore(t, BlockStorePath(dir))

	var tipHash [32]byte
	for height := uint64(0); height <= 100; height++ {
		hash, _ := mustPutBlock(t, store, height, byte(height), height+1, []byte{byte(height)})
		if height == 100 {
			tipHash = hash
		}
	}

	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})
	st.HasTip = true
	st.Height = 100
	st.TipHash = tipHash

	syncEngine, err := NewSyncEngine(st, store, DefaultSyncConfig(nil, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	mp, err := NewMempool(st, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	syncEngine.SetMempool(mp)

	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}

	cfg := DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 124 }
	miner, err := NewMiner(st, store, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}
	mined, err := miner.MineOne(context.Background(), nil)
	if err != nil {
		t.Fatalf("MineOne: %v", err)
	}
	if mined.TxCount != 2 {
		t.Fatalf("tx_count=%d, want 2", mined.TxCount)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
}

func mustNodeMLDSA87Keypair(t *testing.T) *consensus.MLDSA87Keypair {
	t.Helper()
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unsupported") {
			t.Skipf("ML-DSA backend unavailable: %v", err)
		}
		t.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	t.Cleanup(func() { kp.Close() })
	return kp
}

func testSpendableChainState(fromAddress []byte, values []uint64) (*ChainState, []consensus.Outpoint) {
	st := NewChainState()
	st.HasTip = true
	st.Height = 100
	st.TipHash[0] = 0x11
	outpoints := make([]consensus.Outpoint, 0, len(values))
	for i, value := range values {
		var txid [32]byte
		txid[0] = byte(i + 1)
		txid[31] = byte(i + 9)
		op := consensus.Outpoint{Txid: txid, Vout: uint32(i)}
		st.Utxos[op] = consensus.UtxoEntry{
			Value:             value,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      append([]byte(nil), fromAddress...),
			CreationHeight:    1,
			CreatedByCoinbase: true,
		}
		outpoints = append(outpoints, op)
	}
	return st, outpoints
}

func mustBuildSignedTransferTx(
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

func mustBuildSignedAnchorOutputTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	anchorValue uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
) []byte {
	t.Helper()
	entry, ok := utxos[input]
	if !ok {
		t.Fatalf("missing utxo for %x:%d", input.Txid, input.Vout)
	}
	var anchorData [32]byte
	anchorData[0] = 0x42
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: nonce,
		Inputs: []consensus.TxInput{{
			PrevTxid: input.Txid,
			PrevVout: input.Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{Value: anchorValue, CovenantType: consensus.COV_TYPE_ANCHOR, CovenantData: anchorData[:]},
			{Value: entry.Value - anchorValue - fee, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), changeAddress...)},
		},
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction(anchor): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(anchor): %v", err)
	}
	return txBytes
}

func mustBuildSignedDaCommitTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	toAddress []byte,
	manifest []byte,
) []byte {
	t.Helper()
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x01,
		TxNonce: nonce,
		Inputs: []consensus.TxInput{{
			PrevTxid: input.Txid,
			PrevVout: input.Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{{
			Value:        amount,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), toAddress...),
		}},
		Locktime:  0,
		DaPayload: append([]byte(nil), manifest...),
		DaCommitCore: &consensus.DaCommitCore{
			ChunkCount:  1,
			BatchNumber: 1,
		},
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction(da): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(da): %v", err)
	}
	return txBytes
}

func mustBuildSignedCoreExtOutputTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
	extID uint16,
) []byte {
	t.Helper()
	entry, ok := utxos[input]
	if !ok {
		t.Fatalf("missing utxo for %x:%d", input.Txid, input.Vout)
	}
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: nonce,
		Inputs: []consensus.TxInput{{
			PrevTxid: input.Txid,
			PrevVout: input.Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{Value: amount, CovenantType: consensus.COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantDataForNodeTest(extID, nil)},
			{Value: entry.Value - amount - fee, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), changeAddress...)},
		},
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction(core_ext output): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(core_ext output): %v", err)
	}
	return txBytes
}

func mustBuildCoreExtSpendTx(
	t *testing.T,
	prev [32]byte,
	amount uint64,
	fee uint64,
	nonce uint64,
	toAddress []byte,
) []byte {
	t.Helper()
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: nonce,
		Inputs: []consensus.TxInput{{
			PrevTxid: prev,
			PrevVout: 0,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{{
			Value:        amount,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), toAddress...),
		}},
		Locktime: 0,
		Witness:  []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL}},
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(core_ext spend): %v", err)
	}
	if gotFee := uint64(100) - amount; gotFee != fee {
		t.Fatalf("fee mismatch: implied=%d declared=%d", gotFee, fee)
	}
	return txBytes
}

func txIDHex(t *testing.T, txBytes []byte) string {
	t.Helper()
	_, txid, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	return fmt.Sprintf("%x", txid[:])
}
