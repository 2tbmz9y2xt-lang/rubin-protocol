package node

import (
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestCoverage_DaAnchorPolicyGuards(t *testing.T) {
	if reject, _, _, err := RejectDaAnchorTxPolicy(nil, nil, 0, 0, 1); !reject || err == nil {
		t.Fatalf("expected nil tx rejection")
	}
	if reject, reason, err := RejectNonCoinbaseAnchorOutputs(nil); !reject || err == nil || reason == "" {
		t.Fatalf("expected nil tx rejection for anchor outputs")
	}

	tx := &consensus.Tx{
		Inputs: []consensus.TxInput{{PrevTxid: [32]byte{0x11}, PrevVout: 0}},
		Outputs: []consensus.TxOutput{{
			Value:        1,
			CovenantType: consensus.COV_TYPE_ANCHOR,
		}},
	}
	if reject, reason, err := RejectNonCoinbaseAnchorOutputs(tx); !reject || err != nil || reason == "" {
		t.Fatalf("expected anchor policy reject")
	}
	if _, err := mulU64NoOverflow(^uint64(0), 2); err == nil {
		t.Fatalf("expected mul overflow")
	}
}

func TestCoverage_ComputeFeeNoVerifyGuards(t *testing.T) {
	if _, err := computeFeeNoVerify(nil, nil); err == nil {
		t.Fatalf("expected nil tx rejection")
	}
	if _, err := computeFeeNoVerify(&consensus.Tx{}, nil); err == nil {
		t.Fatalf("expected missing inputs rejection")
	}
	tx := &consensus.Tx{
		Inputs:  []consensus.TxInput{{PrevTxid: [32]byte{0x01}, PrevVout: 0}},
		Outputs: []consensus.TxOutput{{Value: 1}},
	}
	if _, err := computeFeeNoVerify(tx, nil); err == nil {
		t.Fatalf("expected nil utxo set rejection")
	}
	if _, err := computeFeeNoVerify(tx, map[consensus.Outpoint]consensus.UtxoEntry{}); err == nil {
		t.Fatalf("expected missing utxo rejection")
	}
	utxos := map[consensus.Outpoint]consensus.UtxoEntry{
		{Txid: [32]byte{0x01}, Vout: 0}: {Value: ^uint64(0)},
	}
	// RUB-1127: two u64-max inputs. This used to be a "sum_in overflow"
	// policy error because sum_in was a u64 accumulator; sum_in is now exact
	// u128, so the fee is derived without error and carries the full value.
	tx.Inputs = append(tx.Inputs, consensus.TxInput{PrevTxid: [32]byte{0x01}, PrevVout: 0})
	wideFee, err := computeFeeNoVerify(tx, utxos)
	if err != nil {
		t.Fatalf("two u64-max inputs must derive a fee, got %v", err)
	}
	// 2*(2^64-1) - 1 (a single output of value 1), which exceeds u64.
	wantWideFee := consensus.Uint128{Hi: 1, Lo: ^uint64(0) - 2}
	if wideFee.Cmp(wantWideFee) != 0 {
		t.Fatalf("wide fee=%s want=%s", wideFee.String(), wantWideFee.String())
	}
	if wideFee.Cmp(consensus.Uint128FromU64(^uint64(0))) <= 0 {
		t.Fatalf("wide fee=%s must exceed u64", wideFee.String())
	}
	tx.Inputs = tx.Inputs[:1]
	// Output sums still overflow-check, now at the u128 boundary: two
	// u128-max-scale outputs are unrepresentable and stay fail-closed.
	tx.Outputs = []consensus.TxOutput{{Value: ^uint64(0)}, {Value: 1}}
	utxos = map[consensus.Outpoint]consensus.UtxoEntry{
		{Txid: [32]byte{0x01}, Vout: 0}: {Value: 10},
	}
	if _, err := computeFeeNoVerify(tx, utxos); err == nil {
		t.Fatalf("expected overspend on wide output sum")
	}
	tx.Outputs = []consensus.TxOutput{{Value: 11}}
	if _, err := computeFeeNoVerify(tx, utxos); err == nil {
		t.Fatalf("expected overspend")
	}
}

func TestCoverage_MempoolHelpers(t *testing.T) {
	if got := (*Mempool)(nil).Len(); got != 0 {
		t.Fatalf("nil Len=%d", got)
	}
	if err := (*Mempool)(nil).AddTx(nil); err == nil {
		t.Fatalf("expected nil mempool add rejection")
	}
	if selected := (*Mempool)(nil).SelectTransactions(1, 1); selected != nil {
		t.Fatalf("expected nil select result")
	}

	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	if err := mp.AddTx(tx2); err != nil {
		t.Fatalf("AddTx(tx2): %v", err)
	}
	var existingTxID [32]byte
	for txid := range mp.txs {
		existingTxID = txid
		break
	}
	if err := mp.validateNonCapacityAdmissionLocked(&mempoolEntry{txid: existingTxID, weight: 1, size: 1}); err == nil {
		t.Fatalf("expected duplicate tx rejection")
	}
	mp.maxTxs = len(mp.txs)
	if err := mp.addEntryLocked(&mempoolEntry{txid: [32]byte{0xaa}, fee: consensus.Uint128FromU64(1), weight: 1, size: 1}); err == nil {
		t.Fatalf("expected mempool full")
	}
	if got := pickEntries(mp.snapshotEntries(), 1, 1<<20); len(got) != 1 {
		t.Fatalf("pickEntries count=%d, want 1", len(got))
	}
}

func TestCoverage_BuildBlockUndoGuards(t *testing.T) {
	if _, err := buildBlockUndo(nil, nil, 0); err == nil {
		t.Fatalf("expected nil previous chainstate")
	}
	if _, err := buildBlockUndo(NewChainState(), nil, 0); err == nil {
		t.Fatalf("expected nil parsed block")
	}
	pb := &consensus.ParsedBlock{Txs: []*consensus.Tx{{}}, Txids: nil}
	if _, err := buildBlockUndo(NewChainState(), pb, 0); err == nil {
		t.Fatalf("expected txid length mismatch")
	}
	pb = &consensus.ParsedBlock{Txs: []*consensus.Tx{nil}, Txids: [][32]byte{{}}}
	if _, err := buildBlockUndo(NewChainState(), pb, 0); err == nil {
		t.Fatalf("expected nil tx rejection")
	}
}

func TestCoverage_DisconnectBlockGuards(t *testing.T) {
	if _, err := (*ChainState)(nil).DisconnectBlock(nil, nil); err == nil {
		t.Fatalf("expected nil chainstate rejection")
	}
	st := NewChainState()
	if _, err := st.DisconnectBlock(nil, &BlockUndo{}); err == nil {
		t.Fatalf("expected no tip rejection")
	}
	st.HasTip = true
	if _, err := st.DisconnectBlock(nil, nil); err == nil {
		t.Fatalf("expected nil undo rejection")
	}
}

func TestCoverage_BlockUndoCodecGuards(t *testing.T) {
	if _, err := marshalBlockUndo(nil); err == nil {
		t.Fatalf("expected marshal nil undo rejection")
	}
	if _, err := unmarshalBlockUndo([]byte("{")); err == nil {
		t.Fatalf("expected decode failure")
	}
	if _, err := blockUndoFromDisk(blockUndoDisk{
		Txs: []txUndoDisk{{Spent: []spentUndoDisk{{Txid: "zz"}}}},
	}); err == nil {
		t.Fatalf("expected invalid hex txid rejection")
	}
}
