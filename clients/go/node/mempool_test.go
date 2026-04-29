package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

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

func TestMempoolAcceptedEntryMetadataAndIndexes(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 3, 1, fromKey, fromAddress, toAddress)
	tx, txid, wtxid, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}

	if err := mp.addTxWithSource(txBytes, mempoolTxSourceRemote); err != nil {
		t.Fatalf("addTxWithSource: %v", err)
	}

	mp.mu.RLock()
	defer mp.mu.RUnlock()
	entry, ok := mp.txs[txid]
	if !ok {
		t.Fatalf("entry for txid %x missing", txid)
	}
	if !bytes.Equal(entry.raw, txBytes) {
		t.Fatal("entry raw bytes mismatch")
	}
	if entry.txid != txid {
		t.Fatalf("entry txid=%x, want %x", entry.txid, txid)
	}
	if entry.wtxid != wtxid {
		t.Fatalf("entry wtxid=%x, want %x", entry.wtxid, wtxid)
	}
	if entry.fee != 3 {
		t.Fatalf("entry fee=%d, want 3", entry.fee)
	}
	if entry.weight != weight {
		t.Fatalf("entry weight=%d, want %d", entry.weight, weight)
	}
	if entry.size != len(txBytes) {
		t.Fatalf("entry wire bytes=%d, want %d", entry.size, len(txBytes))
	}
	if entry.admissionSeq != 1 {
		t.Fatalf("entry admission_seq=%d, want 1", entry.admissionSeq)
	}
	if entry.source != mempoolTxSourceRemote {
		t.Fatalf("entry source=%q, want %q", entry.source, mempoolTxSourceRemote)
	}
	if got, ok := mp.wtxids[wtxid]; !ok || got != txid {
		t.Fatalf("wtxid index got %x ok=%v, want txid %x", got, ok, txid)
	}
	if got, ok := mp.spenders[outpoints[0]]; !ok || got != txid {
		t.Fatalf("spender index got %x ok=%v, want txid %x", got, ok, txid)
	}
}

func TestMempoolRejectsInvalidEntrySource(t *testing.T) {
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
	err = mp.addTxWithSource(txBytes, "sidecar")
	if err == nil || !strings.Contains(err.Error(), "invalid mempool tx source") {
		t.Fatalf("expected invalid source rejection, got %v", err)
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitRejected {
		t.Fatalf("expected TxAdmitRejected, got %v", txErr.Kind)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
	if mp.lastAdmissionSeq != 0 {
		t.Fatalf("lastAdmissionSeq after invalid source=%d, want 0", mp.lastAdmissionSeq)
	}
}

func TestMempoolAddEntryLockedInitializesMetadataIndexes(t *testing.T) {
	op := consensus.Outpoint{Txid: [32]byte{0x01}, Vout: 2}
	entry := &mempoolEntry{
		txid:         [32]byte{0x02},
		wtxid:        [32]byte{0x03},
		inputs:       []consensus.Outpoint{op},
		size:         7,
		admissionSeq: 9,
		source:       mempoolTxSourceReorg,
	}

	mp := &Mempool{}
	mp.addEntryLocked(entry)

	if mp.txs == nil || mp.wtxids == nil || mp.spenders == nil {
		t.Fatalf("indexes were not initialized: txs=%v wtxids=%v spenders=%v", mp.txs != nil, mp.wtxids != nil, mp.spenders != nil)
	}
	if got := mp.txs[entry.txid]; got != entry {
		t.Fatalf("tx index got %p, want entry %p", got, entry)
	}
	if got := mp.wtxids[entry.wtxid]; got != entry.txid {
		t.Fatalf("wtxid index got %x, want txid %x", got, entry.txid)
	}
	if got := mp.spenders[op]; got != entry.txid {
		t.Fatalf("spender index got %x, want txid %x", got, entry.txid)
	}
	if mp.lastAdmissionSeq != entry.admissionSeq {
		t.Fatalf("lastAdmissionSeq=%d, want %d", mp.lastAdmissionSeq, entry.admissionSeq)
	}
	if mp.usedBytes != entry.size {
		t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, entry.size)
	}
}

func TestMempoolEntryIndexesRemovedWithEntry(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 3, 1, fromKey, fromAddress, toAddress)
	_, txid, wtxid, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}

	mp.mu.Lock()
	mp.removeTxLocked(txid)
	if _, ok := mp.txs[txid]; ok {
		t.Fatalf("removed txid %x still present", txid)
	}
	if _, ok := mp.wtxids[wtxid]; ok {
		t.Fatalf("removed wtxid %x still indexed", wtxid)
	}
	if _, ok := mp.spenders[outpoints[0]]; ok {
		t.Fatalf("removed spender %x:%d still indexed", outpoints[0].Txid, outpoints[0].Vout)
	}
	mp.mu.Unlock()
}

func TestMempoolAdmissionSeqOnlyAcceptedTxs(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if err := mp.AddTx([]byte{0xde, 0xad}); err == nil {
		t.Fatal("malformed tx unexpectedly accepted")
	}
	if mp.lastAdmissionSeq != 0 {
		t.Fatalf("lastAdmissionSeq after malformed=%d, want 0", mp.lastAdmissionSeq)
	}

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 1, 2, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	if got := mp.txs[txID(t, tx1)].admissionSeq; got != 1 {
		t.Fatalf("tx1 admission_seq=%d, want 1", got)
	}
	if err := mp.AddTx(tx1); err == nil {
		t.Fatal("duplicate tx unexpectedly accepted")
	}
	if mp.lastAdmissionSeq != 1 {
		t.Fatalf("lastAdmissionSeq after duplicate=%d, want 1", mp.lastAdmissionSeq)
	}
	if err := mp.AddTx(tx2); err != nil {
		t.Fatalf("AddTx(tx2): %v", err)
	}
	if got := mp.txs[txID(t, tx2)].admissionSeq; got != 2 {
		t.Fatalf("tx2 admission_seq=%d, want 2", got)
	}
}

func TestMempoolAdmissionSeqDoesNotWrap(t *testing.T) {
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
	mp.lastAdmissionSeq = ^uint64(0)

	err = mp.AddTx(txBytes)
	if err == nil || !strings.Contains(err.Error(), "mempool admission sequence exhausted") {
		t.Fatalf("expected sequence exhaustion rejection, got %v", err)
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitUnavailable {
		t.Fatalf("expected TxAdmitUnavailable, got %v", txErr.Kind)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
	if mp.lastAdmissionSeq != ^uint64(0) {
		t.Fatalf("lastAdmissionSeq mutated to %d", mp.lastAdmissionSeq)
	}
}

func TestMempoolRejectsDuplicateWtxidIndexWithoutMutation(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	tx1ID := txID(t, tx1)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 1, 2, fromKey, fromAddress, toAddress)
	_, tx2ID, tx2Wtxid, _, err := consensus.ParseTx(tx2)
	if err != nil {
		t.Fatalf("ParseTx(tx2): %v", err)
	}

	mp.mu.Lock()
	mp.wtxids[tx2Wtxid] = tx1ID
	usedBytes := mp.usedBytes
	lastAdmissionSeq := mp.lastAdmissionSeq
	mp.mu.Unlock()

	err = mp.AddTx(tx2)
	if err == nil || !strings.Contains(err.Error(), "mempool wtxid conflict") {
		t.Fatalf("expected wtxid conflict rejection, got %v", err)
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitConflict {
		t.Fatalf("expected TxAdmitConflict, got %v", txErr.Kind)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1 after wtxid conflict", got)
	}
	if mp.Contains(tx2ID) {
		t.Fatalf("wtxid conflict admitted tx2 %x", tx2ID)
	}
	if mp.usedBytes != usedBytes {
		t.Fatalf("usedBytes=%d, want %d after wtxid conflict", mp.usedBytes, usedBytes)
	}
	if mp.lastAdmissionSeq != lastAdmissionSeq {
		t.Fatalf("lastAdmissionSeq=%d, want %d after wtxid conflict", mp.lastAdmissionSeq, lastAdmissionSeq)
	}
	if got := mp.wtxids[tx2Wtxid]; got != tx1ID {
		t.Fatalf("wtxid index overwritten with %x, want existing %x", got, tx1ID)
	}
}

func TestMempoolAddTxWaitsForChainStateWriter(t *testing.T) {
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

	st.admissionMu.Lock()
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		done <- mp.AddTx(txBytes)
	}()
	<-started

	select {
	case err := <-done:
		t.Fatalf("AddTx returned while chainstate writer lock held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	st.admissionMu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("AddTx after writer unlock: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AddTx remained blocked after chainstate writer unlock")
	}
}

func TestMempoolAddTxRejectsWhenWriterInvalidatesSnapshotBeforeAdmission(t *testing.T) {
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

	st.admissionMu.Lock()
	st.mu.Lock()
	delete(st.Utxos, outpoints[0])
	st.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		done <- mp.AddTx(txBytes)
	}()

	select {
	case err := <-done:
		t.Fatalf("AddTx returned while writer gate held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	st.admissionMu.Unlock()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), string(consensus.TX_ERR_MISSING_UTXO)) {
			t.Fatalf("expected missing utxo after writer mutation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AddTx remained blocked after writer gate unlock")
	}

	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
}

func TestMempoolAddTxWaitsForPolicyWriterBeforeSnapshot(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedAnchorOutputTx(t, st.Utxos, outpoints[0], 0, 1, 1, fromKey, toAddress)

	mp.mu.Lock()
	mp.policy.PolicyRejectNonCoinbaseAnchorOutputs = true

	done := make(chan error, 1)
	go func() {
		done <- mp.AddTx(txBytes)
	}()

	select {
	case err := <-done:
		t.Fatalf("AddTx returned while policy writer lock held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	mp.mu.Unlock()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "non-coinbase CORE_ANCHOR") {
			t.Fatalf("expected policy rejection after writer unlock, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AddTx remained blocked after policy writer unlock")
	}

	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
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

func TestMempoolRelayMetadataTrailingBytes(t *testing.T) {
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
	txBytes = append(txBytes, 0x00)
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "trailing bytes after canonical tx") {
		t.Fatalf("expected trailing-bytes rejection, got %v", err)
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

func TestMempoolPolicySnapshot_DoesNotMutateForDaPolicy(t *testing.T) {
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
	nextHeight, _, err := nextBlockContext(st)
	if err != nil {
		t.Fatalf("nextBlockContext: %v", err)
	}
	blockMTP, err := mp.nextBlockMTP(nextHeight)
	if err != nil {
		t.Fatalf("nextBlockMTP: %v", err)
	}
	checked, err := consensus.CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		txBytes,
		copyUtxoSet(st.Utxos),
		nextHeight,
		blockMTP,
		devnetGenesisChainID,
		mp.policy.CoreExtProfiles,
		mp.policy.RotationProvider,
		mp.policy.SuiteRegistry,
	)
	if err != nil {
		t.Fatalf("CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext: %v", err)
	}
	policyUtxos, err := policyInputSnapshot(checked.Tx, st.Utxos)
	if err != nil {
		t.Fatalf("policyInputSnapshot: %v", err)
	}
	before, err := policyInputSnapshot(checked.Tx, policyUtxos)
	if err != nil {
		t.Fatalf("policyInputSnapshot(before): %v", err)
	}

	if err := mp.applyPolicyAgainstState(checked, nextHeight, policyUtxos, mp.policySnapshot()); err != nil {
		t.Fatalf("applyPolicyAgainstState: %v", err)
	}
	if !reflect.DeepEqual(policyUtxos, before) {
		t.Fatalf("policy path mutated DA snapshot")
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

func TestMempoolPolicySnapshot_DoesNotMutateForCoreExtPolicy(t *testing.T) {
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
	nextHeight, _, err := nextBlockContext(st)
	if err != nil {
		t.Fatalf("nextBlockContext: %v", err)
	}
	blockMTP, err := mp.nextBlockMTP(nextHeight)
	if err != nil {
		t.Fatalf("nextBlockMTP: %v", err)
	}
	checked, err := consensus.CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		txBytes,
		copyUtxoSet(st.Utxos),
		nextHeight,
		blockMTP,
		devnetGenesisChainID,
		mp.policy.CoreExtProfiles,
		mp.policy.RotationProvider,
		mp.policy.SuiteRegistry,
	)
	if err != nil {
		t.Fatalf("CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext: %v", err)
	}
	policyUtxos, err := policyInputSnapshot(checked.Tx, st.Utxos)
	if err != nil {
		t.Fatalf("policyInputSnapshot: %v", err)
	}
	before, err := policyInputSnapshot(checked.Tx, policyUtxos)
	if err != nil {
		t.Fatalf("policyInputSnapshot(before): %v", err)
	}

	if err := mp.applyPolicyAgainstState(checked, nextHeight, policyUtxos, mp.policySnapshot()); err != nil {
		t.Fatalf("applyPolicyAgainstState: %v", err)
	}
	if !reflect.DeepEqual(policyUtxos, before) {
		t.Fatalf("policy path mutated CORE_EXT snapshot")
	}
}

func TestMempoolPolicyRejectsOversizedCoreExtPayload(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyMaxExtPayloadBytes: 32,
		CoreExtProfiles:          testCoreExtProfiles{activeByExtID: map[uint16]bool{7: true}},
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	// Build tx with oversized payload (49 bytes > 32 limit)
	entry := st.Utxos[outpoints[0]]
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []consensus.TxInput{{
			PrevTxid: outpoints[0].Txid,
			PrevVout: outpoints[0].Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{Value: 90, CovenantType: consensus.COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantDataForNodeTest(7, make([]byte, 49))},
			{Value: entry.Value - 91, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), fromAddress...)},
		},
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, st.Utxos, devnetGenesisChainID, fromKey); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "exceeds policy limit") {
		t.Fatalf("expected oversized payload rejection, got %v", err)
	}
}

func TestMempoolPolicyAllowsCoreExtPayloadUnderLimit(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyMaxExtPayloadBytes: 48,
		CoreExtProfiles:          testCoreExtProfiles{activeByExtID: map[uint16]bool{7: true}},
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	// Build tx with payload under limit (32 bytes <= 48 limit)
	entry := st.Utxos[outpoints[0]]
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []consensus.TxInput{{
			PrevTxid: outpoints[0].Txid,
			PrevVout: outpoints[0].Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{Value: 90, CovenantType: consensus.COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantDataForNodeTest(7, make([]byte, 32))},
			{Value: entry.Value - 91, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), fromAddress...)},
		},
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, st.Utxos, devnetGenesisChainID, fromKey); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("expected admission, got %v", err)
	}
}

func TestMempoolPolicyRejectsNilCheckedTransaction(t *testing.T) {
	mp := &Mempool{}
	if err := mp.applyPolicyAgainstState(nil, 0, nil, MempoolConfig{}); err == nil || !strings.Contains(err.Error(), "nil checked transaction") {
		t.Fatalf("expected nil checked transaction rejection, got %v", err)
	}
	if err := mp.applyPolicyAgainstState(&consensus.CheckedTransaction{}, 0, nil, MempoolConfig{}); err == nil || !strings.Contains(err.Error(), "nil checked transaction") {
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
	if err := mp.applyPolicyAgainstState(&consensus.CheckedTransaction{Tx: tx}, 101, nil, mp.policySnapshot()); err == nil || !strings.Contains(err.Error(), "nil utxo set") {
		t.Fatalf("expected DA fee computation error, got %v", err)
	}
}

func TestPolicyInputSnapshotCopiesOnlySpentInputs(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 200})

	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	tx, _, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	snapshot, err := policyInputSnapshot(tx, st.Utxos)
	if err != nil {
		t.Fatalf("policyInputSnapshot: %v", err)
	}
	if len(snapshot) != 1 {
		t.Fatalf("snapshot len=%d, want 1", len(snapshot))
	}
	if _, ok := snapshot[outpoints[0]]; !ok {
		t.Fatalf("snapshot missing spent input")
	}
	if _, ok := snapshot[outpoints[1]]; ok {
		t.Fatalf("snapshot unexpectedly copied unrelated utxo")
	}

	entry := snapshot[outpoints[0]]
	entry.CovenantData[0] ^= 0xff
	snapshot[outpoints[0]] = entry
	if reflect.DeepEqual(snapshot[outpoints[0]].CovenantData, st.Utxos[outpoints[0]].CovenantData) {
		t.Fatal("mutating snapshot covenant data leaked into original utxo set")
	}
}

func TestChainStateAdmissionSnapshotForInputsCopiesOnlyRequestedEntries(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 200})
	var missingTxid [32]byte
	missingTxid[0] = 0xee

	snapshot := st.admissionSnapshotForInputs([]consensus.Outpoint{
		outpoints[0],
		outpoints[0],
		{Txid: missingTxid, Vout: 9},
	})
	if snapshot == nil {
		t.Fatal("admissionSnapshotForInputs returned nil")
	}
	if len(snapshot.utxos) != 1 {
		t.Fatalf("snapshot len=%d, want 1", len(snapshot.utxos))
	}
	if _, ok := snapshot.utxos[outpoints[0]]; !ok {
		t.Fatal("snapshot missing requested input")
	}
	if _, ok := snapshot.utxos[outpoints[1]]; ok {
		t.Fatal("snapshot unexpectedly copied unrelated utxo")
	}

	entry := snapshot.utxos[outpoints[0]]
	entry.CovenantData[0] ^= 0xff
	snapshot.utxos[outpoints[0]] = entry
	if reflect.DeepEqual(snapshot.utxos[outpoints[0]].CovenantData, st.Utxos[outpoints[0]].CovenantData) {
		t.Fatal("mutating input snapshot leaked into original utxo set")
	}
}

func TestPolicyInputSnapshotRejectsMissingInput(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	tx, _, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	delete(st.Utxos, outpoints[0])

	_, err = policyInputSnapshot(tx, st.Utxos)
	if err == nil || !strings.Contains(err.Error(), string(consensus.TX_ERR_MISSING_UTXO)) {
		t.Fatalf("expected missing utxo rejection, got %v", err)
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
	tx1ID := txID(t, tx1)
	if got, ok := mp.spenders[outpoints[0]]; !ok || got != tx1ID {
		t.Fatalf("spender index got %x ok=%v, want tx1 %x", got, ok, tx1ID)
	}
	seqAfterTx1 := mp.lastAdmissionSeq
	if err := mp.AddTx(tx2); err == nil {
		t.Fatalf("expected double-spend rejection")
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
	if mp.Contains(txID(t, tx2)) {
		t.Fatalf("conflicting tx entered mempool")
	}
	if got, ok := mp.spenders[outpoints[0]]; !ok || got != tx1ID {
		t.Fatalf("spender index after conflict got %x ok=%v, want tx1 %x", got, ok, tx1ID)
	}
	if mp.lastAdmissionSeq != seqAfterTx1 {
		t.Fatalf("lastAdmissionSeq after conflict=%d, want %d", mp.lastAdmissionSeq, seqAfterTx1)
	}
}

func TestMempoolFullRejectsWithoutEviction(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100, 100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 2})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txLow := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	txHigh := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 4, 2, fromKey, fromAddress, toAddress)
	txBetter := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 90, 2, 3, fromKey, fromAddress, toAddress)

	if err := mp.AddTx(txLow); err != nil {
		t.Fatalf("AddTx(low): %v", err)
	}
	if err := mp.AddTx(txHigh); err != nil {
		t.Fatalf("AddTx(high): %v", err)
	}
	seqAfterAccepted := mp.lastAdmissionSeq
	if err := mp.AddTx(txBetter); err == nil || !strings.Contains(err.Error(), "mempool transaction count limit reached") {
		t.Fatalf("expected count-limit rejection without eviction, got %v", err)
	}
	if mp.lastAdmissionSeq != seqAfterAccepted {
		t.Fatalf("lastAdmissionSeq after capacity reject=%d, want %d", mp.lastAdmissionSeq, seqAfterAccepted)
	}
	if got := mp.Len(); got != 2 {
		t.Fatalf("mempool len=%d, want 2", got)
	}
	if mp.usedBytes != len(txLow)+len(txHigh) {
		t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, len(txLow)+len(txHigh))
	}

	selected := mp.SelectTransactions(3, 1<<20)
	if len(selected) != 2 {
		t.Fatalf("selected=%d, want 2", len(selected))
	}
	got := []string{txIDHex(t, selected[0]), txIDHex(t, selected[1])}
	wantHigh := txIDHex(t, txHigh)
	wantLow := txIDHex(t, txLow)
	if got[0] != wantHigh || got[1] != wantLow {
		t.Fatalf("selected=%v, want [%s %s]", got, wantHigh, wantLow)
	}
	if mp.Contains(txID(t, txBetter)) {
		t.Fatalf("rejected over-cap tx entered mempool")
	}
}

func TestMempoolByteCapRejectsWithoutMutation(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100})

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 2, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 2, 2, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        len(tx1) + len(tx2) - 1,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	if err := mp.AddTx(tx2); err == nil || !strings.Contains(err.Error(), "mempool byte limit exceeded") {
		t.Fatalf("expected byte-limit rejection, got %v", err)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
	if mp.usedBytes != len(tx1) {
		t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, len(tx1))
	}
	if mp.Contains(txID(t, tx2)) {
		t.Fatalf("rejected byte-cap tx entered mempool")
	}
}

func TestMempoolByteCapAllowsExactBoundary(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100})

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 2, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 2, 2, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        len(tx1) + len(tx2),
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	if err := mp.AddTx(tx2); err != nil {
		t.Fatalf("AddTx(tx2) at exact byte cap: %v", err)
	}
	if got := mp.Len(); got != 2 {
		t.Fatalf("mempool len=%d, want 2", got)
	}
	if mp.usedBytes != len(tx1)+len(tx2) {
		t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, len(tx1)+len(tx2))
	}
}

func TestMempoolAdmissionRejectsDoNotMutateByteAccounting(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 10})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 2, 1, fromKey, fromAddress, toAddress)
	txDoubleSpend := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 89, 3, 2, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	wantBytes := mp.usedBytes
	wantLen := mp.Len()

	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{name: "duplicate", raw: tx1},
		{name: "double_spend", raw: txDoubleSpend},
		{name: "malformed", raw: []byte{0xde, 0xad}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := mp.AddTx(tc.raw); err == nil {
				t.Fatalf("expected rejection")
			}
			if got := mp.Len(); got != wantLen {
				t.Fatalf("mempool len=%d, want %d", got, wantLen)
			}
			if mp.usedBytes != wantBytes {
				t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, wantBytes)
			}
		})
	}
}

func TestRestoreMempoolSnapshotRecomputesByteAccounting(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100})

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 2, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 2, 2, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        len(tx1) + len(tx2),
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	snapshot, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}
	if err := mp.AddTx(tx2); err != nil {
		t.Fatalf("AddTx(tx2): %v", err)
	}
	if err := restoreMempoolSnapshot(mp, snapshot); err != nil {
		t.Fatalf("restoreMempoolSnapshot: %v", err)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
	tx1ID := txID(t, tx1)
	_, _, tx1WTxID, _, err := consensus.ParseTx(tx1)
	if err != nil {
		t.Fatalf("ParseTx(tx1): %v", err)
	}
	restored := mp.txs[tx1ID]
	if restored == nil {
		t.Fatalf("restored entry for tx1 missing")
	}
	if restored.wtxid != tx1WTxID {
		t.Fatalf("restored wtxid=%x, want %x", restored.wtxid, tx1WTxID)
	}
	if restored.admissionSeq != 1 {
		t.Fatalf("restored admission_seq=%d, want 1", restored.admissionSeq)
	}
	if restored.source != mempoolTxSourceLocal {
		t.Fatalf("restored source=%q, want %q", restored.source, mempoolTxSourceLocal)
	}
	if mp.lastAdmissionSeq != restored.admissionSeq {
		t.Fatalf("lastAdmissionSeq after restore=%d, want %d", mp.lastAdmissionSeq, restored.admissionSeq)
	}
	if mp.usedBytes != len(tx1) {
		t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, len(tx1))
	}
	if mp.Contains(txID(t, tx2)) {
		t.Fatalf("restored mempool still contains tx2")
	}
	if err := mp.AddTx(tx2); err != nil {
		t.Fatalf("AddTx(tx2) after restore: %v", err)
	}
	if mp.usedBytes != len(tx1)+len(tx2) {
		t.Fatalf("usedBytes=%d, want %d after post-restore AddTx", mp.usedBytes, len(tx1)+len(tx2))
	}
}

func TestRestoreMempoolSnapshotRejectsInvalidEntriesWithoutMutation(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100})

	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 2, 1, fromKey, fromAddress, toAddress)
	txSecond := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 2, 2, fromKey, fromAddress, toAddress)
	txSecondID := txID(t, txSecond)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        len(txBytes) + len(txSecond),
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	snapshot, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}
	wantTxID := txID(t, txBytes)
	wantBytes := mp.usedBytes
	txDoubleSpend := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 89, 3, 2, fromKey, fromAddress, toAddress)
	doubleSpendID := txID(t, txDoubleSpend)
	snapshotEntry := func(txRaw []byte, id [32]byte, inputs []consensus.Outpoint) mempoolEntry {
		_, _, wtxid, _, err := consensus.ParseTx(txRaw)
		if err != nil {
			t.Fatalf("ParseTx(snapshotEntry): %v", err)
		}
		return mempoolEntry{
			raw:          append([]byte(nil), txRaw...),
			txid:         id,
			wtxid:        wtxid,
			inputs:       append([]consensus.Outpoint(nil), inputs...),
			size:         len(txRaw),
			admissionSeq: 99,
			source:       mempoolTxSourceLocal,
		}
	}
	cloneSnapshotForTest := func(base mempoolSnapshot) mempoolSnapshot {
		entries := make([]mempoolEntry, 0, len(base.entries))
		for i := range base.entries {
			entries = append(entries, cloneMempoolEntry(&base.entries[i]))
		}
		return mempoolSnapshot{entries: entries}
	}
	withEditedFirst := func(edit func(*mempoolEntry)) func(mempoolSnapshot) mempoolSnapshot {
		return func(base mempoolSnapshot) mempoolSnapshot {
			bad := cloneSnapshotForTest(base)
			edit(&bad.entries[0])
			return bad
		}
	}

	for _, tc := range []struct {
		name      string
		configure func(*Mempool)
		mutate    func(mempoolSnapshot) mempoolSnapshot
		want      string
	}{
		{
			name:   "zero_size",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.size = 0 }),
			want:   "invalid mempool snapshot entry size",
		},
		{
			name:   "size_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.size = len(entry.raw) + 1 }),
			want:   "mempool snapshot entry size mismatch",
		},
		{
			name:   "malformed_raw",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.raw, entry.size = []byte{0xde, 0xad}, 2 }),
			want:   "invalid mempool snapshot entry raw",
		},
		{
			name: "trailing_bytes",
			mutate: withEditedFirst(func(entry *mempoolEntry) {
				entry.raw = append(entry.raw, 0)
				entry.size = len(entry.raw)
			}),
			want: "mempool snapshot entry has trailing bytes",
		},
		{
			name: "txid_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) {
				entry.txid[0] ^= 0x01
			}),
			want: "mempool snapshot entry txid mismatch",
		},
		{
			name: "wtxid_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) {
				entry.wtxid[0] ^= 0x01
			}),
			want: "mempool snapshot entry wtxid mismatch",
		},
		{
			name:   "zero_admission_seq",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.admissionSeq = 0 }),
			want:   "invalid mempool snapshot entry admission_seq",
		},
		{
			name:   "invalid_source",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.source = "sidecar" }),
			want:   "invalid mempool snapshot entry source",
		},
		{
			name:   "input_count_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.inputs = nil }),
			want:   "mempool snapshot entry input count mismatch",
		},
		{
			name: "input_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) {
				entry.inputs[0].Vout++
			}),
			want: "mempool snapshot entry input mismatch",
		},
		{
			name: "duplicate_txid",
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				bad.entries = append(bad.entries, bad.entries[0])
				return bad
			},
			want: "duplicate mempool snapshot txid",
		},
		{
			name: "duplicate_admission_seq",
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				duplicate := snapshotEntry(txSecond, txSecondID, []consensus.Outpoint{outpoints[1]})
				duplicate.admissionSeq = bad.entries[0].admissionSeq
				bad.entries = append(bad.entries, duplicate)
				return bad
			},
			want: "duplicate mempool snapshot admission_seq",
		},
		{
			name: "duplicate_wtxid",
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				duplicate := snapshotEntry(txSecond, txSecondID, []consensus.Outpoint{outpoints[1]})
				duplicate.wtxid = bad.entries[0].wtxid
				bad.entries = append(bad.entries, duplicate)
				return bad
			},
			want: "duplicate mempool snapshot wtxid",
		},
		{
			name: "duplicate_spender",
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				bad.entries = append(bad.entries, snapshotEntry(txDoubleSpend, doubleSpendID, []consensus.Outpoint{outpoints[0]}))
				return bad
			},
			want: "duplicate mempool snapshot spender",
		},
		{
			name: "aggregate_count_over_cap",
			configure: func(m *Mempool) {
				m.maxTxs = 1
			},
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				bad.entries = append(bad.entries, snapshotEntry(txSecond, txSecondID, []consensus.Outpoint{outpoints[1]}))
				return bad
			},
			want: "mempool snapshot exceeds transaction cap",
		},
		{
			name: "aggregate_bytes_over_cap",
			configure: func(m *Mempool) {
				m.maxBytes = len(txBytes) + len(txSecond) - 1
			},
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				bad.entries = append(bad.entries, snapshotEntry(txSecond, txSecondID, []consensus.Outpoint{outpoints[1]}))
				return bad
			},
			want: "mempool snapshot exceeds byte cap",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mp.maxTxs = 10
			mp.maxBytes = len(txBytes) + len(txSecond)
			if tc.configure != nil {
				tc.configure(mp)
			}
			bad := tc.mutate(snapshot)
			if err := restoreMempoolSnapshot(mp, bad); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q rejection, got %v", tc.want, err)
			}
			if got := mp.Len(); got != 1 {
				t.Fatalf("mempool len=%d, want 1 after rejected restore", got)
			}
			if !mp.Contains(wantTxID) {
				t.Fatalf("rejected restore removed existing tx %x", wantTxID)
			}
			if mp.usedBytes != wantBytes {
				t.Fatalf("usedBytes=%d, want %d after rejected restore", mp.usedBytes, wantBytes)
			}
		})
	}
}

func TestRestoreMempoolSnapshotAllowsExactCapacityBoundary(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100})

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 2, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 2, 2, fromKey, fromAddress, toAddress)
	source, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 2,
		MaxBytes:        len(tx1) + len(tx2),
	})
	if err != nil {
		t.Fatalf("new source mempool: %v", err)
	}
	if err := source.AddTx(tx1); err != nil {
		t.Fatalf("source AddTx(tx1): %v", err)
	}
	if err := source.AddTx(tx2); err != nil {
		t.Fatalf("source AddTx(tx2): %v", err)
	}
	snapshot, err := snapshotMempool(source)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}

	target, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 2,
		MaxBytes:        len(tx1) + len(tx2),
	})
	if err != nil {
		t.Fatalf("new target mempool: %v", err)
	}
	if err := restoreMempoolSnapshot(target, snapshot); err != nil {
		t.Fatalf("restoreMempoolSnapshot exact boundary: %v", err)
	}
	if got := target.Len(); got != 2 {
		t.Fatalf("mempool len=%d, want 2", got)
	}
	if target.usedBytes != len(tx1)+len(tx2) {
		t.Fatalf("usedBytes=%d, want %d", target.usedBytes, len(tx1)+len(tx2))
	}
}

func TestMempoolAddTxHeightOverflow(t *testing.T) {
	st := &ChainState{HasTip: true, Height: ^uint64(0)} // MaxUint64
	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	err = mp.AddTx([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for height overflow")
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitUnavailable {
		t.Fatalf("expected TxAdmitUnavailable, got %v", txErr.Kind)
	}
}

func TestMempoolAddTxBlockMTPError(t *testing.T) {
	// Empty blockStore + non-zero height → prevTimestampsFromStore fails.
	dir := t.TempDir()
	store := mustOpenBlockStore(t, BlockStorePath(dir))
	st := &ChainState{HasTip: true, Height: 50}
	mp, err := NewMempool(st, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	err = mp.AddTx([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for missing block timestamps")
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitUnavailable {
		t.Fatalf("expected TxAdmitUnavailable, got %v", txErr.Kind)
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
	if got := mp.usedBytes; got != 0 {
		t.Fatalf("usedBytes=%d, want 0", got)
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
	txid := txID(t, txBytes)
	return fmt.Sprintf("%x", txid[:])
}

func txID(t *testing.T, txBytes []byte) [32]byte {
	t.Helper()
	_, txid, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	return txid
}

func TestTxAdmitErrorKinds(t *testing.T) {
	assertKind := func(t *testing.T, err error, wantKind TxAdmitErrorKind) {
		t.Helper()
		var txErr *TxAdmitError
		if !errors.As(err, &txErr) {
			t.Fatalf("expected *TxAdmitError, got %T: %v", err, err)
		}
		if txErr.Kind != wantKind {
			t.Fatalf("kind=%q, want %q (msg=%q)", txErr.Kind, wantKind, txErr.Message)
		}
	}

	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	t.Run("nil mempool", func(t *testing.T) {
		var mp *Mempool
		err := mp.AddTx([]byte{0x00})
		assertKind(t, err, TxAdmitUnavailable)
	})

	t.Run("duplicate tx conflict", func(t *testing.T) {
		st, outpoints := testSpendableChainState(fromAddress, []uint64{100})
		mp, err := NewMempool(st, nil, devnetGenesisChainID)
		if err != nil {
			t.Fatalf("new mempool: %v", err)
		}
		tx := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
		if err := mp.AddTx(tx); err != nil {
			t.Fatalf("first AddTx: %v", err)
		}
		err = mp.AddTx(tx)
		assertKind(t, err, TxAdmitConflict)
	})

	t.Run("double spend conflict", func(t *testing.T) {
		st, outpoints := testSpendableChainState(fromAddress, []uint64{100})
		mp, err := NewMempool(st, nil, devnetGenesisChainID)
		if err != nil {
			t.Fatalf("new mempool: %v", err)
		}
		tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
		tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 89, 2, 2, fromKey, fromAddress, toAddress)
		if err := mp.AddTx(tx1); err != nil {
			t.Fatalf("first AddTx: %v", err)
		}
		err = mp.AddTx(tx2)
		assertKind(t, err, TxAdmitConflict)
	})

	t.Run("mempool full unavailable", func(t *testing.T) {
		st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100})
		mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 1})
		if err != nil {
			t.Fatalf("new mempool: %v", err)
		}
		tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 5, 1, fromKey, fromAddress, toAddress)
		tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 1, 2, fromKey, fromAddress, toAddress)
		if err := mp.AddTx(tx1); err != nil {
			t.Fatalf("first AddTx: %v", err)
		}
		err = mp.AddTx(tx2)
		assertKind(t, err, TxAdmitUnavailable)
	})

	t.Run("invalid tx rejected", func(t *testing.T) {
		st, _ := testSpendableChainState(fromAddress, []uint64{100})
		mp, err := NewMempool(st, nil, devnetGenesisChainID)
		if err != nil {
			t.Fatalf("new mempool: %v", err)
		}
		// Garbage bytes that fail consensus.CheckTransaction → rejected.
		err = mp.AddTx([]byte{0xDE, 0xAD})
		assertKind(t, err, TxAdmitRejected)
	})
}

func TestTxAdmitErrorMessage(t *testing.T) {
	err := &TxAdmitError{Kind: TxAdmitConflict, Message: "tx already in mempool"}
	if err.Error() != "tx already in mempool" {
		t.Fatalf("Error()=%q, want %q", err.Error(), "tx already in mempool")
	}
}

func TestMempoolAllTxIDsReturnsEveryEntry(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100, 100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	want := make(map[[32]byte]struct{})
	for i := 0; i < 3; i++ {
		txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[i]}, 90, 1, 1, fromKey, fromAddress, toAddress)
		if err := mp.AddTx(txBytes); err != nil {
			t.Fatalf("AddTx[%d]: %v", i, err)
		}
		_, txid, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			t.Fatalf("ParseTx[%d]: %v", i, err)
		}
		want[txid] = struct{}{}
	}

	got := mp.AllTxIDs()
	if len(got) != 3 {
		t.Fatalf("AllTxIDs len=%d, want 3", len(got))
	}
	for _, id := range got {
		if _, ok := want[id]; !ok {
			t.Fatalf("AllTxIDs returned unexpected txid %x", id)
		}
	}
}

func TestMempoolAllTxIDsSortedDeterministic(t *testing.T) {
	// Verify that sorting AllTxIDs produces deterministic lexicographic order;
	// handlers sort the IDs before presenting them.
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100, 100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	var ids [][32]byte
	for i := 0; i < 3; i++ {
		txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[i]}, 90, 1, 1, fromKey, fromAddress, toAddress)
		if err := mp.AddTx(txBytes); err != nil {
			t.Fatalf("AddTx[%d]: %v", i, err)
		}
		_, txid, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			t.Fatalf("ParseTx[%d]: %v", i, err)
		}
		ids = append(ids, txid)
	}
	got := mp.AllTxIDs()
	if len(got) != 3 {
		t.Fatalf("AllTxIDs len=%d, want 3", len(got))
	}
	// Replicate handler sort: lexicographic on hex-encoded txid.
	sort.Slice(got, func(i, j int) bool {
		return hex.EncodeToString(got[i][:]) < hex.EncodeToString(got[j][:])
	})
	sort.Slice(ids, func(i, j int) bool {
		return hex.EncodeToString(ids[i][:]) < hex.EncodeToString(ids[j][:])
	})
	for i := range ids {
		if got[i] != ids[i] {
			t.Fatalf("sorted[%d]: got %x, want %x", i, got[i], ids[i])
		}
	}
}

func TestMempoolAllTxIDsEmpty(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, _ := testSpendableChainState(fromAddress, []uint64{100})
	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if got := mp.AllTxIDs(); len(got) != 0 {
		t.Fatalf("AllTxIDs on empty mempool returned %d entries, want 0", len(got))
	}
}

func TestMempoolAllTxIDsNilReceiver(t *testing.T) {
	var mp *Mempool
	if got := mp.AllTxIDs(); got != nil {
		t.Fatalf("AllTxIDs on nil receiver=%v, want nil", got)
	}
}

func TestMempoolTxByIDReturnsRawAndDefensiveCopy(t *testing.T) {
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
	_, txid, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	got, ok := mp.TxByID(txid)
	if !ok {
		t.Fatalf("TxByID ok=false, want true")
	}
	if !bytes.Equal(got, txBytes) {
		t.Fatalf("TxByID raw mismatch")
	}

	// Defensive-copy invariant: mutate the returned slice and verify the
	// mempool entry remains intact via a second TxByID call.
	got[0] ^= 0xff
	got2, ok2 := mp.TxByID(txid)
	if !ok2 {
		t.Fatalf("TxByID second call ok=false")
	}
	if !bytes.Equal(got2, txBytes) {
		t.Fatalf("mempool entry mutated by caller — defensive copy broken")
	}
}

func TestMempoolTxByIDMissing(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, _ := testSpendableChainState(fromAddress, []uint64{100})
	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	var unknown [32]byte
	raw, ok := mp.TxByID(unknown)
	if ok || raw != nil {
		t.Fatalf("TxByID on unknown txid returned raw=%v ok=%v, want nil,false", raw, ok)
	}
}

func TestMempoolTxByIDNilReceiver(t *testing.T) {
	var mp *Mempool
	var id [32]byte
	raw, ok := mp.TxByID(id)
	if ok || raw != nil {
		t.Fatalf("TxByID on nil receiver returned raw=%v ok=%v, want nil,false", raw, ok)
	}
}

func TestMempoolContainsReflectsAdmission(t *testing.T) {
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
	_, txid, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	if mp.Contains(txid) {
		t.Fatalf("Contains before admit=true, want false")
	}
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	if !mp.Contains(txid) {
		t.Fatalf("Contains after admit=false, want true")
	}
	var other [32]byte
	if mp.Contains(other) {
		t.Fatalf("Contains for unrelated txid=true, want false")
	}
}

func TestMempoolContainsNilReceiver(t *testing.T) {
	var mp *Mempool
	var id [32]byte
	if mp.Contains(id) {
		t.Fatalf("Contains on nil receiver=true, want false")
	}
}

// TestMempoolBytesUsedTracksUsedBytes pins the BytesUsed gauge: empty
// mempool reports 0; after a successful AddTx BytesUsed reflects the
// raw transaction byte size accounted in the existing usedBytes field.
// This is the metric scrape source for rubin_node_mempool_bytes.
func TestMempoolBytesUsedTracksUsedBytes(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if got := mp.BytesUsed(); got != 0 {
		t.Fatalf("BytesUsed empty=%d, want 0", got)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	if got := mp.BytesUsed(); got != len(txBytes) {
		t.Fatalf("BytesUsed=%d, want %d (raw tx size)", got, len(txBytes))
	}
}

// TestMempoolBytesUsedNilReceiver pins the nil-safety contract used by
// the /metrics rendering path: a nil mempool reports 0 bytes without
// panicking, so the scrape rendering can call BytesUsed unconditionally.
func TestMempoolBytesUsedNilReceiver(t *testing.T) {
	var mp *Mempool
	if got := mp.BytesUsed(); got != 0 {
		t.Fatalf("BytesUsed nil receiver=%d, want 0", got)
	}
}

// TestMempoolAdmissionCountsAcceptedBumpsExactlyOnce pins that a happy
// AddTx call increments only the Accepted bucket of the admission
// counters and leaves the other three buckets at zero.
func TestMempoolAdmissionCountsAcceptedBumpsExactlyOnce(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if got := mp.AdmissionCounts(); got != (MempoolAdmissionCounts{}) {
		t.Fatalf("AdmissionCounts pre-AddTx=%+v, want zero", got)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	got := mp.AdmissionCounts()
	if got.Accepted != 1 || got.Conflict != 0 || got.Rejected != 0 || got.Unavailable != 0 {
		t.Fatalf("AdmissionCounts after accepted AddTx=%+v, want only Accepted=1", got)
	}
}

// TestMempoolAdmissionCountsConflictBumpsExactlyOnce pins that a
// duplicate-txid AddTx call routes to the Conflict bucket. The first
// AddTx accepts; the second AddTx with the same bytes hits the
// validateAdmissionLocked duplicate-spender path which returns
// txAdmitConflict.
func TestMempoolAdmissionCountsConflictBumpsExactlyOnce(t *testing.T) {
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
		t.Fatalf("first AddTx: %v", err)
	}
	dupErr := mp.AddTx(txBytes)
	if dupErr == nil {
		t.Fatalf("duplicate AddTx unexpectedly accepted")
	}
	var admitErr *TxAdmitError
	if !errors.As(dupErr, &admitErr) || admitErr.Kind != TxAdmitConflict {
		t.Fatalf("duplicate AddTx err=%v (kind=%v), want TxAdmitConflict", dupErr, func() any {
			if admitErr != nil {
				return admitErr.Kind
			}
			return "<nil>"
		}())
	}
	got := mp.AdmissionCounts()
	if got.Accepted != 1 {
		t.Fatalf("AdmissionCounts.Accepted=%d, want 1 (first AddTx)", got.Accepted)
	}
	if got.Conflict != 1 || got.Rejected != 0 || got.Unavailable != 0 {
		t.Fatalf("AdmissionCounts after duplicate=%+v, want Conflict=1", got)
	}
}

// TestMempoolAdmissionCountsRejectedBumpsExactlyOnce pins that an
// AddTx call rejected by the parse-time path (here: trailing bytes
// after canonical tx) routes to the Rejected bucket via the
// txAdmitRejected helper inside checkTransactionWithSnapshot.
func TestMempoolAdmissionCountsRejectedBumpsExactlyOnce(t *testing.T) {
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
	// Append a trailing byte to force the "trailing bytes after canonical
	// tx" reject path inside checkTransactionWithSnapshot.
	bad := append([]byte{}, txBytes...)
	bad = append(bad, 0x00)
	addErr := mp.AddTx(bad)
	if addErr == nil {
		t.Fatalf("malformed AddTx unexpectedly accepted")
	}
	var admitErr *TxAdmitError
	if !errors.As(addErr, &admitErr) || admitErr.Kind != TxAdmitRejected {
		t.Fatalf("malformed AddTx err=%v, want TxAdmitRejected", addErr)
	}
	got := mp.AdmissionCounts()
	if got.Rejected != 1 || got.Accepted != 0 || got.Conflict != 0 || got.Unavailable != 0 {
		t.Fatalf("AdmissionCounts after malformed=%+v, want Rejected=1", got)
	}
}

// TestMempoolAdmissionCountsUnavailableBumpsExactlyOnce pins that an
// AddTx call hitting the nil-chainstate guard routes to the
// Unavailable bucket. nil-chainstate is the explicit unavailable
// branch documented in AddTx.
func TestMempoolAdmissionCountsUnavailableBumpsExactlyOnce(t *testing.T) {
	mp := &Mempool{} // chainState nil — exercises txAdmitUnavailable("nil chainstate")
	addErr := mp.AddTx([]byte{0x00})
	if addErr == nil {
		t.Fatalf("AddTx on nil-chainstate mempool unexpectedly accepted")
	}
	var admitErr *TxAdmitError
	if !errors.As(addErr, &admitErr) || admitErr.Kind != TxAdmitUnavailable {
		t.Fatalf("AddTx err=%v, want TxAdmitUnavailable", addErr)
	}
	got := mp.AdmissionCounts()
	if got.Unavailable != 1 || got.Accepted != 0 || got.Conflict != 0 || got.Rejected != 0 {
		t.Fatalf("AdmissionCounts after unavailable=%+v, want Unavailable=1", got)
	}
}

// TestMempoolAdmissionCountsNilReceiver pins the nil-safety contract
// used by /metrics rendering: a nil mempool returns the zero-value
// MempoolAdmissionCounts struct without panicking.
func TestMempoolAdmissionCountsNilReceiver(t *testing.T) {
	var mp *Mempool
	if got := mp.AdmissionCounts(); got != (MempoolAdmissionCounts{}) {
		t.Fatalf("AdmissionCounts nil receiver=%+v, want zero struct", got)
	}
}
