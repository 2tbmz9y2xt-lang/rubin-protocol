package main

import (
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func mustRPCState(t *testing.T, withGenesis bool) *devnetRPCState {
	t.Helper()
	dir := t.TempDir()
	return mustRPCStateAtDir(t, dir, withGenesis)
}

func mustRPCStateAtDir(t *testing.T, dir string, withGenesis bool) *devnetRPCState {
	t.Helper()
	chainStatePath := node.ChainStatePath(dir)
	chainState := node.NewChainState()
	if err := chainState.Save(chainStatePath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncCfg := node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), chainStatePath)
	syncEngine, err := node.NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if withGenesis {
		if _, err := syncEngine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
			t.Fatalf("ApplyBlock(genesis): %v", err)
		}
	}
	mempool, err := node.NewMempool(chainState, blockStore, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	syncEngine.SetMempool(mempool)
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, nil, nil, io.Discard, nil)
	state.nowUnix = func() uint64 { return 0 }
	return state
}

func mustRPCMLDSA87Keypair(t *testing.T) *consensus.MLDSA87Keypair {
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

func mustRPCStateWithSpendableUTXO(
	t *testing.T,
	fromAddress []byte,
	announceTx func([]byte) error,
) (*devnetRPCState, consensus.Outpoint, map[consensus.Outpoint]consensus.UtxoEntry) {
	t.Helper()
	return mustRPCStateWithSpendableUTXOAndMempoolConfig(t, fromAddress, announceTx, node.DefaultMempoolConfig())
}

func mustRPCStateWithSpendableUTXOAndMempoolConfig(
	t *testing.T,
	fromAddress []byte,
	announceTx func([]byte) error,
	mempoolConfig node.MempoolConfig,
) (*devnetRPCState, consensus.Outpoint, map[consensus.Outpoint]consensus.UtxoEntry) {
	t.Helper()
	state, outpoints, utxos := mustRPCStateWithSpendableUTXOsAndMempoolConfig(t, fromAddress, []uint64{1_000_000}, announceTx, mempoolConfig)
	return state, outpoints[0], utxos
}

func mustRPCStateWithSpendableUTXOsAndMempoolConfig(
	t *testing.T,
	fromAddress []byte,
	values []uint64,
	announceTx func([]byte) error,
	mempoolConfig node.MempoolConfig,
) (*devnetRPCState, []consensus.Outpoint, map[consensus.Outpoint]consensus.UtxoEntry) {
	t.Helper()
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	chainState := node.NewChainState()
	if len(values) == 0 {
		t.Fatalf("mustRPCStateWithSpendableUTXOsAndMempoolConfig requires at least one value")
	}
	outpoints := make([]consensus.Outpoint, 0, len(values))
	for i, value := range values {
		var prevTxid [32]byte
		prevTxid[0] = 0x44
		prevTxid[31] = byte(i)
		outpoint := consensus.Outpoint{Txid: prevTxid, Vout: 0}
		outpoints = append(outpoints, outpoint)
		chainState.Utxos[outpoint] = consensus.UtxoEntry{
			Value:             value,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      append([]byte(nil), fromAddress...),
			CreationHeight:    0,
			CreatedByCoinbase: false,
		}
	}
	if err := chainState.Save(chainStatePath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncCfg := node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), chainStatePath)
	syncEngine, err := node.NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := node.NewMempoolWithConfig(chainState, blockStore, node.DevnetGenesisChainID(), mempoolConfig)
	if err != nil {
		t.Fatalf("NewMempoolWithConfig: %v", err)
	}
	syncEngine.SetMempool(mempool)
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, announceTx, nil, io.Discard, nil)
	state.nowUnix = func() uint64 { return 0 }
	return state, outpoints, chainState.Utxos
}

func mustRPCSignedTransferTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	signer *consensus.MLDSA87Keypair,
	toAddress []byte,
) ([]byte, string) {
	t.Helper()
	return mustRPCSignedTransferTxWithFee(t, utxos, input, 100_000, 100_000, 1, signer, toAddress)
}

func mustRPCSignedTransferTxWithFee(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	toAddress []byte,
) ([]byte, string) {
	t.Helper()
	entry, ok := utxos[input]
	if !ok {
		t.Fatalf("missing utxo for %x:%d", input.Txid, input.Vout)
	}
	if amount > entry.Value || fee > entry.Value-amount {
		t.Fatalf("utxo value=%d, want at least amount=%d plus fee=%d", entry.Value, amount, fee)
	}
	changeAddress := consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())
	change := entry.Value - amount - fee
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
			{
				Value:        amount,
				CovenantType: consensus.COV_TYPE_P2PK,
				CovenantData: append([]byte(nil), toAddress...),
			},
		},
		Locktime: 0,
	}
	if change > 0 {
		tx.Outputs = append(tx.Outputs,
			consensus.TxOutput{
				Value:        change,
				CovenantType: consensus.COV_TYPE_P2PK,
				CovenantData: append([]byte(nil), changeAddress...),
			},
		)
	}
	if err := consensus.SignTransaction(tx, utxos, node.DevnetGenesisChainID(), signer); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	_, txid, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if consumed != len(txBytes) {
		t.Fatalf("consumed=%d, want %d", consumed, len(txBytes))
	}
	return txBytes, hex.EncodeToString(txid[:])
}

func mustRPCSignedDaCommitTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	toAddress []byte,
	commitTxPayload []byte,
	singleChunkPayload []byte,
) ([]byte, string) {
	t.Helper()
	if len(commitTxPayload) == 0 {
		t.Fatalf("DA_COMMIT tx payload must be non-empty")
	}
	if len(singleChunkPayload) == 0 {
		t.Fatalf("DA_COMMIT chunk payload must be non-empty")
	}
	entry, ok := utxos[input]
	if !ok {
		t.Fatalf("missing utxo for %x:%d", input.Txid, input.Vout)
	}
	if entry.Value < fee {
		t.Fatalf("utxo value=%d, want at least fee=%d", entry.Value, fee)
	}
	chunkPayloadCommitment := sha3.Sum256(singleChunkPayload)
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
			Value:        0,
			CovenantType: consensus.COV_TYPE_DA_COMMIT,
			CovenantData: chunkPayloadCommitment[:],
		}, {
			Value:        entry.Value - fee,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), toAddress...),
		}},
		Locktime:  0,
		DaPayload: append([]byte(nil), commitTxPayload...),
		DaCommitCore: &consensus.DaCommitCore{
			ChunkCount:  1,
			BatchNumber: 1,
		},
	}
	if err := consensus.SignTransaction(tx, utxos, node.DevnetGenesisChainID(), signer); err != nil {
		t.Fatalf("SignTransaction(da): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(da): %v", err)
	}
	parsed, txid, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx(da): %v", err)
	}
	if consumed != len(txBytes) {
		t.Fatalf("da consumed=%d, want %d", consumed, len(txBytes))
	}
	if parsed.TxKind != 0x01 || parsed.DaCommitCore == nil || len(parsed.DaPayload) == 0 {
		t.Fatalf("parsed DA_COMMIT shape mismatch: tx_kind=%d da_core_nil=%t da_payload_len=%d", parsed.TxKind, parsed.DaCommitCore == nil, len(parsed.DaPayload))
	}
	if !bytes.Equal(parsed.DaPayload, commitTxPayload) {
		t.Fatalf("parsed DA_COMMIT payload mismatch")
	}
	daCommitOutputs := 0
	for _, out := range parsed.Outputs {
		if out.CovenantType != consensus.COV_TYPE_DA_COMMIT {
			continue
		}
		daCommitOutputs++
		if out.Value != 0 {
			t.Fatalf("CORE_DA_COMMIT output value=%d, want 0", out.Value)
		}
		if !bytes.Equal(out.CovenantData, chunkPayloadCommitment[:]) {
			t.Fatalf("CORE_DA_COMMIT output commitment mismatch")
		}
	}
	if daCommitOutputs != 1 {
		t.Fatalf("CORE_DA_COMMIT outputs=%d, want 1", daCommitOutputs)
	}
	return txBytes, hex.EncodeToString(txid[:])
}

func mustRPCSignedAnchorOutputTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	signer *consensus.MLDSA87Keypair,
) []byte {
	t.Helper()
	entry, ok := utxos[input]
	if !ok {
		t.Fatalf("missing utxo for %x:%d", input.Txid, input.Vout)
	}
	if entry.Value < 1 {
		t.Fatalf("utxo value=%d, want at least 1 to pay anchor helper fee", entry.Value)
	}
	changeAddress := consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())
	var anchorData [32]byte
	anchorData[0] = 0x42
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 2,
		Inputs: []consensus.TxInput{{
			PrevTxid: input.Txid,
			PrevVout: input.Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{
				Value:        0,
				CovenantType: consensus.COV_TYPE_ANCHOR,
				CovenantData: anchorData[:],
			},
			{
				Value:        entry.Value - 1,
				CovenantType: consensus.COV_TYPE_P2PK,
				CovenantData: append([]byte(nil), changeAddress...),
			},
		},
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, node.DevnetGenesisChainID(), signer); err != nil {
		t.Fatalf("SignTransaction(anchor): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(anchor): %v", err)
	}
	if _, _, _, consumed, err := consensus.ParseTx(txBytes); err != nil {
		t.Fatalf("ParseTx(anchor): %v", err)
	} else if consumed != len(txBytes) {
		t.Fatalf("anchor consumed=%d, want %d", consumed, len(txBytes))
	}
	return txBytes
}

func TestDevnetRPCGetTipNoTip(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, false)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_tip")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	var got getTipResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.HasTip {
		t.Fatalf("HasTip=true, want false")
	}
	if got.Height != nil {
		t.Fatalf("Height=%v, want nil", *got.Height)
	}
	if got.TipHash != nil {
		t.Fatalf("TipHash=%v, want nil", *got.TipHash)
	}
}

func TestDevnetRPCGetTipWithGenesisTip(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_tip")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	var got getTipResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.HasTip {
		t.Fatalf("HasTip=false, want true")
	}
	if got.Height == nil || *got.Height != 0 {
		t.Fatalf("Height=%v, want 0", got.Height)
	}
	if got.TipHash == nil || len(*got.TipHash) != 64 {
		t.Fatalf("TipHash=%v, want 32-byte hex", got.TipHash)
	}
}

func TestDevnetRPCGetTipRejectsBadMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/get_tip", nil)
	rec := httptest.NewRecorder()
	handleGetTip(mustRPCState(t, false), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestDevnetRPCGetTipRejectsNilState(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/get_tip", nil)
	rec := httptest.NewRecorder()
	handleGetTip(nil, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
}

func TestDevnetRPCGetTipRejectsNilBlockStore(t *testing.T) {
	state := mustRPCState(t, false)
	state.blockStore = nil
	req := httptest.NewRequest(http.MethodGet, "/get_tip", nil)
	rec := httptest.NewRecorder()
	handleGetTip(state, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "blockstore unavailable") {
		t.Fatalf("body=%q, want blockstore unavailable", rec.Body.String())
	}
}

func TestDevnetRPCGetBlockRejectsSelectorMismatch(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_block")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}

func TestDevnetRPCGetBlockRejectsBadMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/get_block?height=0", nil)
	rec := httptest.NewRecorder()
	handleGetBlock(mustRPCState(t, true), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestDevnetRPCGetBlockRejectsNilBlockStore(t *testing.T) {
	state := mustRPCState(t, true)
	state.blockStore = nil
	req := httptest.NewRequest(http.MethodGet, "/get_block?height=0", nil)
	rec := httptest.NewRecorder()
	handleGetBlock(state, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "blockstore unavailable") {
		t.Fatalf("body=%q, want blockstore unavailable", rec.Body.String())
	}
}

func TestDevnetRPCGetBlockByHeightReturnsGenesis(t *testing.T) {
	state := mustRPCState(t, true)
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_block?height=0")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var got getBlockResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Height != 0 {
		t.Fatalf("height=%d, want 0", got.Height)
	}
	if got.Hash == "" || got.BlockHex == "" {
		t.Fatalf("expected populated hash and block hex")
	}
}

func TestDevnetRPCGetBlockByHashReturnsGenesis(t *testing.T) {
	state := mustRPCState(t, true)
	_, tipHash, ok, err := state.blockStore.Tip()
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if !ok {
		t.Fatal("expected tip")
	}
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	tipHex := hex.EncodeToString(tipHash[:])
	resp, err := http.Get(server.URL + "/get_block?hash=" + tipHex)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var got getBlockResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Hash != tipHex {
		t.Fatalf("hash=%q, want %q", got.Hash, tipHex)
	}
}

func TestDevnetRPCGetBlockByHeightReturns503WhenBlockBytesAreMissing(t *testing.T) {
	dir := t.TempDir()
	state := mustRPCStateAtDir(t, dir, true)
	_, tipHash, ok, err := state.blockStore.Tip()
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if !ok {
		t.Fatal("expected tip")
	}
	blockPath := filepath.Join(node.BlockStorePath(dir), "blocks", hex.EncodeToString(tipHash[:])+".bin")
	if err := os.Remove(blockPath); err != nil {
		t.Fatalf("Remove(block): %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/get_block?height=0", nil)
	rec := httptest.NewRecorder()
	handleGetBlock(state, rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
}

func TestDevnetRPCGetBlockRejectsInvalidHash(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_block?hash=zz")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}

func TestDevnetRPCGetBlockReturnsNotFoundForUnknownHash(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_block?hash=" + strings.Repeat("55", 32))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", resp.StatusCode)
	}
}

func TestDevnetRPCGetBlockRejectsInvalidHeight(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_block?height=nope")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}

func TestDevnetRPCGetBlockReturnsNotFoundForMissingHeight(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_block?height=9")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", resp.StatusCode)
	}
}

func TestDevnetRPCGetBlockReturnsUnavailableForBlockReadError(t *testing.T) {
	dir := t.TempDir()
	state := mustRPCStateAtDir(t, dir, true)
	_, tipHash, ok, err := state.blockStore.Tip()
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if !ok {
		t.Fatal("expected tip")
	}
	blockPath := filepath.Join(
		node.BlockStorePath(dir),
		"blocks",
		fmt.Sprintf("%x.bin", tipHash[:]),
	)
	if err := os.Remove(blockPath); err != nil {
		t.Fatalf("Remove block: %v", err)
	}
	if err := os.Mkdir(blockPath, 0o700); err != nil {
		t.Fatalf("Mkdir block placeholder: %v", err)
	}

	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()
	resp, err := http.Get(server.URL + "/get_block?height=0")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", resp.StatusCode)
	}
}

func TestDevnetRPCSubmitTxRejectsBadHex(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, false)))
	defer server.Close()

	resp, err := http.Post(server.URL+"/submit_tx", "application/json", strings.NewReader(`{"tx_hex":"zz"}`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}

func TestDevnetRPCSubmitTxRejectsBadMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/submit_tx", nil)
	rec := httptest.NewRecorder()
	handleSubmitTx(mustRPCState(t, false), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestDevnetRPCSubmitTxRejectsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, false)))
	defer server.Close()

	resp, err := http.Post(server.URL+"/submit_tx", "application/json", strings.NewReader(`{"tx_hex":`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}

func TestDevnetRPCSubmitTxRejectsTrailingJSONGarbage(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, false)))
	defer server.Close()

	resp, err := http.Post(server.URL+"/submit_tx", "application/json", strings.NewReader(`{"tx_hex":"00"}garbage`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}

func TestDevnetRPCSubmitTxRejectsNilMempool(t *testing.T) {
	state := mustRPCState(t, false)
	state.mempool = nil
	req := httptest.NewRequest(http.MethodPost, "/submit_tx", strings.NewReader(`{"tx_hex":"00"}`))
	rec := httptest.NewRecorder()
	handleSubmitTx(state, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
}

func TestDevnetRPCSubmitTxRejectsInvalidTx(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Post(server.URL+"/submit_tx", "application/json", strings.NewReader(`{"tx_hex":"00"}`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422", resp.StatusCode)
	}
}

// TestDevnetRPCSubmitTxRejectsOversizedContentLength covers the ContentLength
// short-circuit path (header advertises oversized body → 413 without reading
// any bytes).
func TestDevnetRPCSubmitTxRejectsOversizedContentLength(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, false)))
	defer server.Close()

	// 3 MiB body exceeds the 2 MiB cap; http.Post sets Content-Length.
	payload := strings.Repeat("a", 3*1024*1024)
	resp, err := http.Post(server.URL+"/submit_tx", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413", resp.StatusCode)
	}
}

// TestDevnetRPCSubmitTxRejectsOversizedChunkedTrailingBody covers the
// post-decode path: a valid short JSON value is followed by enough trailing
// bytes (on a chunked/unknown-length body) to exceed maxBodyBytes. The
// drainSubmitTxBody path must classify this as 413, not collapse into a
// generic 400, because http.MaxBytesReader surfaces *http.MaxBytesError
// during the io.ReadAll over the combined tail.
func TestDevnetRPCSubmitTxRejectsOversizedChunkedTrailingBody(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, false)))
	defer server.Close()

	payload := `{"tx_hex":"00"}` + strings.Repeat("a", 3*1024*1024) // >3 MiB trailer
	req, err := http.NewRequest(http.MethodPost, server.URL+"/submit_tx", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413 (trailing oversize must not collapse to 400)", resp.StatusCode)
	}
}

// TestDevnetRPCServerExplicitTimeouts pins the Rust-parity timeout surface on
// the underlying http.Server so a future edit that drops ReadTimeout /
// WriteTimeout / IdleTimeout gets caught before landing.
func TestDevnetRPCServerExplicitTimeouts(t *testing.T) {
	srv, err := startDevnetRPCServer("127.0.0.1:0", mustRPCState(t, false), io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("startDevnetRPCServer: %v", err)
	}
	if srv == nil || srv.server == nil {
		t.Fatal("nil server")
	}
	defer func() { _ = srv.Close(context.Background()) }()

	if got, want := srv.server.ReadHeaderTimeout, 5*time.Second; got != want {
		t.Errorf("ReadHeaderTimeout=%v, want %v", got, want)
	}
	if got, want := srv.server.ReadTimeout, 10*time.Second; got != want {
		t.Errorf("ReadTimeout=%v, want %v", got, want)
	}
	// WriteTimeout is intentionally zero: Go's WriteTimeout is a
	// request-scoped total-handler deadline, which would abort long-running
	// RPCs like /mine_next. See rationale in startDevnetRPCServer.
	if got := srv.server.WriteTimeout; got != 0 {
		t.Errorf("WriteTimeout=%v, want 0 (WriteTimeout aborts long handlers in Go)", got)
	}
	if got, want := srv.server.IdleTimeout, 60*time.Second; got != want {
		t.Errorf("IdleTimeout=%v, want %v", got, want)
	}
}

// TestDevnetRPCSubmitTxRejectsTrailingGarbageAfterBufferedWindow pins the
// drainSubmitTxBody full-stream scan: a valid JSON body followed by a long
// whitespace run that pushes trailing garbage past the decoder's internal
// buffer must still return 400. Without the MultiReader(dec.Buffered(), body)
// scan, the garbage byte slipped past and /submit_tx incorrectly accepted
// a malformed body.
func TestDevnetRPCSubmitTxRejectsTrailingGarbageAfterBufferedWindow(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, false)))
	defer server.Close()

	// 512 KiB of whitespace is chosen to exceed typical json.Decoder buffering
	// while remaining well below the 2 MiB body cap, so the trailing 'x' is
	// expected to be read from the underlying body stream rather than only from
	// dec.Buffered().
	payload := `{"tx_hex":"00"}` + strings.Repeat(" ", 512*1024) + "x"
	resp, err := http.Post(server.URL+"/submit_tx", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 (trailing garbage past buffered window must not be accepted)", resp.StatusCode)
	}
}

// TestDevnetRPCSubmitTxRejectsOversizedChunkedBody covers the previously
// mis-classified path: a chunked / unknown-length body that exceeds
// maxBodyBytes must surface as 413, not collapse to "invalid JSON body" 400
// due to the pre-MaxBytesReader body-limiting/reader behavior when the
// size limit is hit during json.Decode.
func TestDevnetRPCSubmitTxRejectsOversizedChunkedBody(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, false)))
	defer server.Close()

	// Valid JSON prefix so the decoder advances past the opening tokens and
	// only hits the body-size limit while reading the oversized string value.
	payload := `{"tx_hex":"` + strings.Repeat("a", 3*1024*1024) + `"}` // >3 MiB, cap is 2 MiB
	req, err := http.NewRequest(http.MethodPost, server.URL+"/submit_tx", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Force chunked transfer so the ContentLength short-circuit does not fire;
	// the MaxBytesReader branch must convert the oversize into 413.
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413 (chunked body must not collapse to 400)", resp.StatusCode)
	}
}

func TestDevnetRPCSubmitTxAcceptsValidTxAndAnnounces(t *testing.T) {
	fromKey := mustRPCMLDSA87Keypair(t)
	toKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	var announced []byte
	state, input, utxos := mustRPCStateWithSpendableUTXO(t, fromAddress, func(tx []byte) error {
		announced = append([]byte(nil), tx...)
		return nil
	})
	txBytes, wantTxID := mustRPCSignedTransferTx(t, utxos, input, fromKey, toAddress)
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	body, err := json.Marshal(submitTxRequest{TxHex: hex.EncodeToString(txBytes)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resp, err := http.Post(server.URL+"/submit_tx", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	var got submitTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Accepted {
		t.Fatalf("accepted=false, want true")
	}
	if got.TxID != wantTxID {
		t.Fatalf("txid=%q, want %q", got.TxID, wantTxID)
	}
	if got.Error != "" {
		t.Fatalf("error=%q, want empty", got.Error)
	}
	if got := state.mempool.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
	if !bytes.Equal(announced, txBytes) {
		t.Fatalf("announceTx payload mismatch")
	}
	metrics := renderPrometheusMetrics(state)
	if !strings.Contains(metrics, `rubin_node_submit_tx_total{result="accepted"} 1`) {
		t.Fatalf("missing accepted metric in %q", metrics)
	}
}

func TestDevnetRPCSubmitTxAcceptsDaCommitUnderDefaultPolicy(t *testing.T) {
	if got := node.DefaultMempoolConfig().PolicyDaSurchargePerByte; got != 0 {
		t.Fatalf("default DA surcharge=%d, want 0 for current default operator submit policy", got)
	}
	fromKey := mustRPCMLDSA87Keypair(t)
	toKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	var announced [][]byte
	state, input, utxos := mustRPCStateWithSpendableUTXO(t, fromAddress, func(tx []byte) error {
		announced = append(announced, append([]byte(nil), tx...))
		return nil
	})
	txBytes, wantTxID := mustRPCSignedDaCommitTx(t, utxos, input, 100_000, 7, fromKey, toAddress, []byte("commitmeta"), []byte("chunkdata0"))
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	body, err := json.Marshal(submitTxRequest{TxHex: hex.EncodeToString(txBytes)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resp, err := http.Post(server.URL+"/submit_tx", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	var got submitTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Accepted {
		t.Fatalf("accepted=false, want true")
	}
	if got.TxID != wantTxID {
		t.Fatalf("txid=%q, want parsed DA_COMMIT txid %q", got.TxID, wantTxID)
	}
	if got.Error != "" {
		t.Fatalf("error=%q, want empty", got.Error)
	}
	if len(announced) != 1 {
		t.Fatalf("announceTx calls=%d, want 1", len(announced))
	}
	if !bytes.Equal(announced[0], txBytes) {
		t.Fatalf("announceTx payload mismatch")
	}
	if got := state.mempool.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
	wantTxIDBytes, err := hex.DecodeString(wantTxID)
	if err != nil || len(wantTxIDBytes) != 32 {
		t.Fatalf("parsed DA_COMMIT txid %q did not decode to 32 bytes", wantTxID)
	}
	var wantTxIDArray [32]byte
	copy(wantTxIDArray[:], wantTxIDBytes)
	mempoolTx, ok := state.mempool.TxByID(wantTxIDArray)
	if !ok {
		t.Fatalf("mempool missing accepted DA_COMMIT txid %q", wantTxID)
	}
	if !bytes.Equal(mempoolTx, txBytes) {
		t.Fatalf("mempool tx bytes mismatch for accepted DA_COMMIT txid %q", wantTxID)
	}
	admission := state.mempool.AdmissionCounts()
	if admission.Accepted != 1 || admission.Rejected != 0 || admission.Conflict != 0 || admission.Unavailable != 0 {
		t.Fatalf("admission counts=%+v, want one accepted AddTx", admission)
	}
	metrics := renderPrometheusMetrics(state)
	for _, want := range []string{
		`rubin_node_submit_tx_total{result="accepted"} 1`,
		`rubin_node_mempool_admit_total{result="accepted"} 1`,
		`rubin_node_mempool_txs 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("missing %q in metrics %q", want, metrics)
		}
	}
}

func TestDevnetRPCSubmitTxRejectsDuplicateMempoolEntry(t *testing.T) {
	fromKey := mustRPCMLDSA87Keypair(t)
	toKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	state, input, utxos := mustRPCStateWithSpendableUTXO(t, fromAddress, nil)
	txBytes, _ := mustRPCSignedTransferTx(t, utxos, input, fromKey, toAddress)
	if err := state.mempool.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx(seed): %v", err)
	}

	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	body, err := json.Marshal(submitTxRequest{TxHex: hex.EncodeToString(txBytes)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resp, err := http.Post(server.URL+"/submit_tx", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status=%d, want 409", resp.StatusCode)
	}
	var got submitTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Accepted {
		t.Fatalf("accepted=true, want false")
	}
	if !strings.Contains(got.Error, "already in mempool") {
		t.Fatalf("error=%q, want duplicate message", got.Error)
	}
	metrics := renderPrometheusMetrics(state)
	if !strings.Contains(metrics, `rubin_node_submit_tx_total{result="conflict"} 1`) {
		t.Fatalf("missing conflict metric in %q", metrics)
	}
}

func TestDevnetRPCSubmitTxBelowRollingFloorReturnsUnavailable(t *testing.T) {
	fromKey := mustRPCMLDSA87Keypair(t)
	toKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	var announceCalled bool
	cfg := node.DefaultMempoolConfig()
	cfg.MaxTransactions = 1
	state, inputs, utxos := mustRPCStateWithSpendableUTXOsAndMempoolConfig(t, fromAddress, []uint64{1_000_000, 1_000_000, 1_000_000}, func(tx []byte) error {
		announceCalled = true
		return nil
	}, cfg)
	seedTx, _ := mustRPCSignedTransferTxWithFee(t, utxos, inputs[0], 100_000, 100_000, 1, fromKey, toAddress)
	betterTx, _ := mustRPCSignedTransferTxWithFee(t, utxos, inputs[1], 100_000, 700_000, 2, fromKey, toAddress)
	belowFloorTx, _ := mustRPCSignedTransferTxWithFee(t, utxos, inputs[2], 100_000, 1, 3, fromKey, toAddress)
	if err := state.mempool.AddTx(seedTx); err != nil {
		t.Fatalf("AddTx(seed): %v", err)
	}
	if err := state.mempool.AddTx(betterTx); err != nil {
		t.Fatalf("AddTx(better): %v", err)
	}
	if got := state.mempool.Len(); got != 1 {
		t.Fatalf("mempool len=%d after rolling-floor seed, want 1", got)
	}

	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()
	body, err := json.Marshal(submitTxRequest{TxHex: hex.EncodeToString(belowFloorTx)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resp, err := http.Post(server.URL+"/submit_tx", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", resp.StatusCode)
	}

	var got submitTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Accepted {
		t.Fatalf("accepted=true, want false")
	}
	if got.TxID != "" {
		t.Fatalf("txid=%q, want empty unavailable response", got.TxID)
	}
	if !strings.Contains(got.Error, "mempool fee below rolling minimum") {
		t.Fatalf("error=%q, want rolling minimum message", got.Error)
	}
	if announceCalled {
		t.Fatalf("announceTx was called for unavailable below-floor tx")
	}
	if got := state.mempool.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want unchanged 1", got)
	}
	admission := state.mempool.AdmissionCounts()
	if admission.Accepted != 2 || admission.Unavailable != 1 || admission.Conflict != 0 || admission.Rejected != 0 {
		t.Fatalf("admission counts=%+v, want two accepted and one unavailable", admission)
	}
	metrics := renderPrometheusMetrics(state)
	for _, want := range []string{
		`rubin_node_submit_tx_total{result="unavailable"} 1`,
		`rubin_node_mempool_admit_total{result="accepted"} 2`,
		`rubin_node_mempool_admit_total{result="unavailable"} 1`,
		`rubin_node_mempool_txs 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("missing %q in metrics %q", want, metrics)
		}
	}
}

func TestDevnetRPCSubmitTxRejectsLowFeeDaCommitWhenSurchargePolicyEnabled(t *testing.T) {
	fromKey := mustRPCMLDSA87Keypair(t)
	toKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	var announceCalled bool
	mempoolConfig := node.DefaultMempoolConfig()
	mempoolConfig.PolicyDaSurchargePerByte = 1
	state, input, utxos := mustRPCStateWithSpendableUTXOAndMempoolConfig(t, fromAddress, func(tx []byte) error {
		announceCalled = true
		return nil
	}, mempoolConfig)
	txBytes, _ := mustRPCSignedDaCommitTx(t, utxos, input, 1, 8, fromKey, toAddress, []byte("commitmeta"), []byte("chunkdata0"))
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	body, err := json.Marshal(submitTxRequest{TxHex: hex.EncodeToString(txBytes)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resp, err := http.Post(server.URL+"/submit_tx", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422", resp.StatusCode)
	}

	var got submitTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Accepted {
		t.Fatalf("accepted=true, want false")
	}
	if got.TxID != "" {
		t.Fatalf("txid=%q, want empty rejected response", got.TxID)
	}
	if !strings.Contains(got.Error, "DA fee below Stage C floor") {
		t.Fatalf("error=%q, want DA Stage C floor reject", got.Error)
	}
	if announceCalled {
		t.Fatalf("announceTx was called for rejected DA_COMMIT tx")
	}
	if got := state.mempool.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
	admission := state.mempool.AdmissionCounts()
	if admission.Rejected != 1 || admission.Accepted != 0 || admission.Conflict != 0 || admission.Unavailable != 0 {
		t.Fatalf("admission counts=%+v, want one rejected AddTx", admission)
	}
	metrics := renderPrometheusMetrics(state)
	for _, want := range []string{
		`rubin_node_submit_tx_total{result="rejected"} 1`,
		`rubin_node_mempool_admit_total{result="rejected"} 1`,
		`rubin_node_mempool_txs 0`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("missing %q in metrics %q", want, metrics)
		}
	}
}

func TestDevnetRPCSubmitTxRejectsNonCoinbaseCoreAnchorByPolicy(t *testing.T) {
	fromKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())

	var announceCalled bool
	state, input, utxos := mustRPCStateWithSpendableUTXO(t, fromAddress, func(tx []byte) error {
		announceCalled = true
		return nil
	})
	txBytes := mustRPCSignedAnchorOutputTx(t, utxos, input, fromKey)
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	body, err := json.Marshal(submitTxRequest{TxHex: hex.EncodeToString(txBytes)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resp, err := http.Post(server.URL+"/submit_tx", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422", resp.StatusCode)
	}

	var got submitTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Accepted {
		t.Fatalf("accepted=true, want false")
	}
	if got.TxID != "" {
		t.Fatalf("txid=%q, want empty rejected response", got.TxID)
	}
	if !strings.Contains(got.Error, "non-coinbase CORE_ANCHOR") {
		t.Fatalf("error=%q, want non-coinbase CORE_ANCHOR policy reject", got.Error)
	}
	if announceCalled {
		t.Fatalf("announceTx was called for rejected non-coinbase CORE_ANCHOR tx")
	}
	if got := state.mempool.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
	admission := state.mempool.AdmissionCounts()
	if admission.Rejected != 1 || admission.Accepted != 0 || admission.Conflict != 0 || admission.Unavailable != 0 {
		t.Fatalf("admission counts=%+v, want one rejected AddTx", admission)
	}
	metrics := renderPrometheusMetrics(state)
	for _, want := range []string{
		`rubin_node_submit_tx_total{result="rejected"} 1`,
		`rubin_node_mempool_admit_total{result="rejected"} 1`,
		`rubin_node_mempool_txs 0`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("missing %q in metrics %q", want, metrics)
		}
	}
}

func TestDevnetRPCMetricsEndpoint(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("content-type=%q", got)
	}
}

func TestDevnetRPCMetricsRejectsBadMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	rec := httptest.NewRecorder()
	handleMetrics(mustRPCState(t, true), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestRenderPrometheusMetricsIncludesV1Names(t *testing.T) {
	state := mustRPCState(t, true)
	state.metrics.note("/get_tip", http.StatusOK)
	state.metrics.noteSubmit("accepted")
	body := renderPrometheusMetrics(state)
	for _, name := range []string{
		"rubin_node_tip_height",
		"rubin_node_best_known_height",
		"rubin_node_in_ibd",
		"rubin_node_reorg_total",
		"rubin_node_last_reorg_depth",
		"rubin_node_block_apply_total",
		"rubin_node_peer_count",
		"rubin_node_mempool_txs",
		"rubin_node_rpc_requests_total",
		"rubin_node_submit_tx_total",
	} {
		if !strings.Contains(body, name) {
			t.Fatalf("missing metric %q", name)
		}
	}
	if !strings.Contains(body, `rubin_node_rpc_requests_total{route="/get_tip",status="200"} 1`) {
		t.Fatalf("missing route counter in %q", body)
	}
	if !strings.Contains(body, `rubin_node_submit_tx_total{result="accepted"} 1`) {
		t.Fatalf("missing submit counter in %q", body)
	}
}

func TestRenderPrometheusMetricsHandlesNilStateAndNilMetrics(t *testing.T) {
	var metrics *rpcMetrics
	metrics.note("/get_tip", http.StatusOK)
	metrics.noteSubmit("accepted")
	routeStatus, submitByResult := metrics.snapshot()
	if len(routeStatus) != 0 || len(submitByResult) != 0 {
		t.Fatalf("snapshot() on nil metrics returned data: routes=%v submit=%v", routeStatus, submitByResult)
	}

	body := renderPrometheusMetrics(nil)
	for _, want := range []string{
		"rubin_node_tip_height 0",
		"rubin_node_best_known_height 0",
		"rubin_node_in_ibd 0",
		"rubin_node_reorg_total 0",
		"rubin_node_last_reorg_depth 0",
		`rubin_node_block_apply_total{result="accepted"} 0`,
		`rubin_node_block_apply_total{result="rejected"} 0`,
		"rubin_node_peer_count 0",
		"rubin_node_mempool_txs 0",
		"rubin_node_mempool_bytes 0",
		`rubin_node_mempool_admit_total{result="accepted"} 0`,
		`rubin_node_mempool_admit_total{result="conflict"} 0`,
		`rubin_node_mempool_admit_total{result="rejected"} 0`,
		`rubin_node_mempool_admit_total{result="unavailable"} 0`,
		"rubin_node_p2p_peer_lifecycle_exits_total 0",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in metrics body %q", want, body)
		}
	}
}

func TestRenderPrometheusMetricsExposesBlockApplyCountersReadOnly(t *testing.T) {
	state := mustRPCState(t, true)
	initial := state.syncEngine.BlockApplyCounts()
	if initial.Accepted != 1 || initial.Rejected != 0 {
		t.Fatalf("initial BlockApplyCounts=%+v, want accepted=1 rejected=0 after devnet genesis", initial)
	}

	target := consensus.POW_LIMIT
	block1 := mustRPCSingleTxBlock(
		t,
		node.DevnetGenesisBlockHash(),
		target,
		mustRPCReorgTestTimestamp(t, 1),
		mustRPCCoinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)),
	)
	summary1, err := state.syncEngine.ApplyBlock(block1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(block1): %v", err)
	}

	invalidBlock2 := append([]byte(nil), mustRPCSingleTxBlock(
		t,
		summary1.BlockHash,
		target,
		mustRPCReorgTestTimestamp(t, 2),
		mustRPCCoinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, consensus.BlockSubsidy(2, summary1.AlreadyGenerated)),
	)...)
	invalidBlock2[4+32] ^= 0x01 // keep the block parseable but break merkle-root validation.
	if _, err := state.syncEngine.ApplyBlock(invalidBlock2, nil); err == nil {
		t.Fatalf("expected invalid canonical block rejection")
	}

	beforeRender := state.syncEngine.BlockApplyCounts()
	if beforeRender.Accepted != 2 || beforeRender.Rejected != 1 {
		t.Fatalf("pre-render BlockApplyCounts=%+v, want accepted=2 rejected=1", beforeRender)
	}
	body1 := renderPrometheusMetrics(state)
	body2 := renderPrometheusMetrics(state)
	for _, body := range []string{body1, body2} {
		for _, want := range []string{
			"# TYPE rubin_node_block_apply_total counter",
			`rubin_node_block_apply_total{result="accepted"} 2`,
			`rubin_node_block_apply_total{result="rejected"} 1`,
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("missing %q in metrics body %q", want, body)
			}
		}
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, `rubin_node_block_apply_total{`) &&
				(strings.Contains(line, `error=`) || strings.Contains(line, `hash=`) || strings.Contains(line, `peer=`)) {
				t.Fatalf("block apply metrics leaked unbounded labels in line %q from body %q", line, body)
			}
		}
	}
	if afterRender := state.syncEngine.BlockApplyCounts(); afterRender != beforeRender {
		t.Fatalf("renderPrometheusMetrics mutated BlockApplyCounts from %+v to %+v", beforeRender, afterRender)
	}
}

func TestRenderPrometheusMetricsExposesReorgCountersReadOnly(t *testing.T) {
	state := mustRPCState(t, true)
	target := consensus.POW_LIMIT
	subsidy1 := consensus.BlockSubsidy(1, 0)

	blockA1 := mustRPCSingleTxBlock(
		t,
		node.DevnetGenesisBlockHash(),
		target,
		mustRPCReorgTestTimestamp(t, 1),
		mustRPCCoinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1),
	)
	summaryA1, err := state.syncEngine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}

	blockB1 := mustRPCSingleTxBlock(
		t,
		node.DevnetGenesisBlockHash(),
		target,
		mustRPCReorgTestTimestamp(t, 2),
		mustRPCCoinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1),
	)
	if _, err := state.syncEngine.ApplyBlockWithReorg(blockB1, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}
	if state.syncEngine.LastReorgDepth() != 0 || state.syncEngine.ReorgCount() != 0 {
		t.Fatalf("side branch before heavier tip mutated reorg counters")
	}

	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockB2 := mustRPCSingleTxBlock(
		t,
		mustRPCBlockHash(t, blockB1),
		target,
		mustRPCReorgTestTimestamp(t, 3),
		mustRPCCoinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2),
	)
	summaryB2, err := state.syncEngine.ApplyBlockWithReorg(blockB2, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(B2): %v", err)
	}
	if summaryB2.BlockHash == summaryA1.BlockHash {
		t.Fatalf("heavier branch did not move canonical tip")
	}
	tipHeight, tipHash, ok, err := state.blockStore.Tip()
	if err != nil {
		t.Fatalf("blockStore.Tip: %v", err)
	}
	if !ok || tipHeight != summaryB2.BlockHeight || tipHash != summaryB2.BlockHash {
		t.Fatalf("canonical tip height/hash=%d/%x ok=%v, want %d/%x", tipHeight, tipHash, ok, summaryB2.BlockHeight, summaryB2.BlockHash)
	}
	if got := state.syncEngine.ReorgCount(); got != 1 {
		t.Fatalf("ReorgCount()=%d, want 1", got)
	}
	if got := state.syncEngine.LastReorgDepth(); got != 1 {
		t.Fatalf("LastReorgDepth()=%d, want 1", got)
	}

	body1 := renderPrometheusMetrics(state)
	body2 := renderPrometheusMetrics(state)
	for _, body := range []string{body1, body2} {
		for _, want := range []string{
			"# TYPE rubin_node_reorg_total counter",
			"rubin_node_reorg_total 1",
			"# TYPE rubin_node_last_reorg_depth gauge",
			"rubin_node_last_reorg_depth 1",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("missing %q in metrics body %q", want, body)
			}
		}
		if strings.Contains(body, "rubin_node_reorg_total{") || strings.Contains(body, "rubin_node_last_reorg_depth{") {
			t.Fatalf("reorg metrics unexpectedly used labels in body %q", body)
		}
	}
	if got := state.syncEngine.ReorgCount(); got != 1 {
		t.Fatalf("renderPrometheusMetrics mutated ReorgCount() to %d, want 1", got)
	}
	if got := state.syncEngine.LastReorgDepth(); got != 1 {
		t.Fatalf("renderPrometheusMetrics mutated LastReorgDepth() to %d, want 1", got)
	}
}

type rpcTestOutput struct {
	covenantData []byte
	value        uint64
	covenantType uint16
}

func mustRPCReorgTestTimestamp(t *testing.T, delta uint64) uint64 {
	t.Helper()
	genesisParsed, err := consensus.ParseBlockBytes(node.DevnetGenesisBlockBytes())
	if err != nil {
		t.Fatalf("ParseBlockBytes(devnet genesis): %v", err)
	}
	return genesisParsed.Header.Timestamp + delta
}

func mustRPCCoinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t *testing.T, height uint64, value uint64) []byte {
	t.Helper()
	if height > uint64(^uint32(0)) {
		t.Fatalf("coinbase height=%d exceeds locktime uint32 range", height)
	}
	wroot, err := consensus.WitnessMerkleRootWtxids([][32]byte{{}})
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commitment := consensus.WitnessCommitmentHash(wroot)
	return mustRPCCoinbaseTxWithOutputs(t, uint32(height), []rpcTestOutput{
		{value: value, covenantType: consensus.COV_TYPE_P2PK, covenantData: rpcTestP2PKCovenantData(0x11)},
		{value: 0, covenantType: consensus.COV_TYPE_ANCHOR, covenantData: commitment[:]},
	})
}

func mustRPCCoinbaseTxWithOutputs(t *testing.T, locktime uint32, outputs []rpcTestOutput) []byte {
	t.Helper()
	sizeHint := 128
	for _, out := range outputs {
		sizeHint += 16 + len(out.covenantData)
	}
	b := make([]byte, 0, sizeHint)
	b = consensus.AppendU32le(b, 1)
	b = append(b, 0x00)
	b = consensus.AppendU64le(b, 0)
	b = consensus.AppendCompactSize(b, 1)
	b = append(b, make([]byte, 32)...)
	b = consensus.AppendU32le(b, ^uint32(0))
	b = consensus.AppendCompactSize(b, 0)
	b = consensus.AppendU32le(b, ^uint32(0))
	b = consensus.AppendCompactSize(b, uint64(len(outputs)))
	for _, out := range outputs {
		b = consensus.AppendU64le(b, out.value)
		b = consensus.AppendU16le(b, out.covenantType)
		b = consensus.AppendCompactSize(b, uint64(len(out.covenantData)))
		b = append(b, out.covenantData...)
	}
	b = consensus.AppendU32le(b, locktime)
	b = consensus.AppendCompactSize(b, 0)
	b = consensus.AppendCompactSize(b, 0)
	if _, _, _, consumed, err := consensus.ParseTx(b); err != nil {
		t.Fatalf("ParseTx(coinbase): %v", err)
	} else if consumed != len(b) {
		t.Fatalf("ParseTx(coinbase) consumed=%d, want %d", consumed, len(b))
	}
	return b
}

func rpcTestP2PKCovenantData(seed byte) []byte {
	data := make([]byte, consensus.MAX_P2PK_COVENANT_DATA)
	data[0] = consensus.SUITE_ID_ML_DSA_87
	for i := 1; i < len(data); i++ {
		data[i] = seed + byte(i)
	}
	return data
}

func mustRPCSingleTxBlock(t *testing.T, prevHash [32]byte, target [32]byte, timestamp uint64, tx []byte) []byte {
	t.Helper()
	_, txid, _, _, err := consensus.ParseTx(tx)
	if err != nil {
		t.Fatalf("ParseTx(block tx): %v", err)
	}
	root, err := consensus.MerkleRootTxids([][32]byte{txid})
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

	block := make([]byte, 0, len(header)+len(tx)+4)
	block = append(block, header...)
	block = consensus.AppendCompactSize(block, 1)
	block = append(block, tx...)
	return block
}

func mustRPCBlockHash(t *testing.T, block []byte) [32]byte {
	t.Helper()
	if len(block) < consensus.BLOCK_HEADER_BYTES {
		t.Fatalf("block length=%d, want at least %d", len(block), consensus.BLOCK_HEADER_BYTES)
	}
	hash, err := consensus.BlockHash(block[:consensus.BLOCK_HEADER_BYTES])
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}
	return hash
}

// TestRenderPrometheusMetricsMempoolBytesAndAdmitTotal pins the new
// scrape surface added by #1288: rubin_node_mempool_bytes (gauge,
// reflects mempool.BytesUsed at scrape) and the four bounded
// rubin_node_mempool_admit_total{result=...} counter buckets in a
// fixed rendering order. The test bumps three buckets via real AddTx
// outcomes (accepted via valid tx, conflict via duplicate tx,
// rejected via trailing-bytes parse error), reads /metrics, and
// asserts (a) every bucket line is present in the fixed
// accepted/conflict/rejected/unavailable order, (b) values match the
// counter snapshot, (c) BytesUsed reflects the byte size of the
// accepted transaction. The unavailable bucket stays at 0 because the
// test mempool has a non-nil chainstate.
func TestRenderPrometheusMetricsMempoolBytesAndAdmitTotal(t *testing.T) {
	fromKey := mustRPCMLDSA87Keypair(t)
	toKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	state, input, utxos := mustRPCStateWithSpendableUTXO(t, fromAddress, nil)
	txBytes, _ := mustRPCSignedTransferTx(t, utxos, input, fromKey, toAddress)
	if err := state.mempool.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx accept: %v", err)
	}
	// Bump conflict bucket via duplicate AddTx.
	if err := state.mempool.AddTx(txBytes); err == nil {
		t.Fatalf("duplicate AddTx unexpectedly accepted")
	}
	// Bump rejected bucket via trailing-bytes parse error.
	bad := append([]byte{}, txBytes...)
	bad = append(bad, 0x00)
	if err := state.mempool.AddTx(bad); err == nil {
		t.Fatalf("malformed AddTx unexpectedly accepted")
	}

	body := renderPrometheusMetrics(state)
	for _, want := range []string{
		"# TYPE rubin_node_mempool_bytes gauge",
		"# TYPE rubin_node_mempool_admit_total counter",
		`rubin_node_mempool_admit_total{result="accepted"} 1`,
		`rubin_node_mempool_admit_total{result="conflict"} 1`,
		`rubin_node_mempool_admit_total{result="rejected"} 1`,
		`rubin_node_mempool_admit_total{result="unavailable"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in metrics body %q", want, body)
		}
	}
	// Fixed rendering order: accepted < conflict < rejected < unavailable.
	idxAccepted := strings.Index(body, `rubin_node_mempool_admit_total{result="accepted"}`)
	idxConflict := strings.Index(body, `rubin_node_mempool_admit_total{result="conflict"}`)
	idxRejected := strings.Index(body, `rubin_node_mempool_admit_total{result="rejected"}`)
	idxUnavailable := strings.Index(body, `rubin_node_mempool_admit_total{result="unavailable"}`)
	if idxAccepted < 0 || idxAccepted >= idxConflict || idxConflict >= idxRejected || idxRejected >= idxUnavailable {
		t.Fatalf("admit_total buckets not in fixed accepted<conflict<rejected<unavailable order; positions %d,%d,%d,%d body=%q", idxAccepted, idxConflict, idxRejected, idxUnavailable, body)
	}
	// BytesUsed reflected as gauge: equals the raw byte size of the
	// single accepted transaction.
	if !strings.Contains(body, fmt.Sprintf("rubin_node_mempool_bytes %d", len(txBytes))) {
		t.Fatalf("rubin_node_mempool_bytes does not reflect BytesUsed=%d in body %q", len(txBytes), body)
	}
}

// TestRenderPrometheusMetricsTwiceDoesNotIncrementAdmitCounters pins
// the scrape-time-no-increment contract: rendering /metrics is a pure
// counter Load() and MUST NOT bump any of the four
// rubin_node_mempool_admit_total buckets. After one accepted AddTx,
// rendering twice and re-snapshotting AdmissionCounts must yield the
// SAME accepted=1 value.
func TestRenderPrometheusMetricsTwiceDoesNotIncrementAdmitCounters(t *testing.T) {
	fromKey := mustRPCMLDSA87Keypair(t)
	toKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	state, input, utxos := mustRPCStateWithSpendableUTXO(t, fromAddress, nil)
	txBytes, _ := mustRPCSignedTransferTx(t, utxos, input, fromKey, toAddress)
	if err := state.mempool.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	pre := state.mempool.AdmissionCounts()
	_ = renderPrometheusMetrics(state)
	_ = renderPrometheusMetrics(state)
	post := state.mempool.AdmissionCounts()
	if pre != post {
		t.Fatalf("AdmissionCounts changed across two /metrics renders: pre=%+v post=%+v (scrape-time increment regression)", pre, post)
	}
}

// TestRenderPrometheusMetricsExposesPeerLifecycleExits wires a stub
// closure on devnetRPCState that returns a fixed non-zero count and
// renders /metrics once.
// Proof assertion: body contains "rubin_node_p2p_peer_lifecycle_exits_total 7"
// (the value returned by the stub) AND contains the HELP/TYPE
// preamble for that metric AND the metric is unlabeled (no `{...}`
// brace appears between the metric name and the value).
func TestRenderPrometheusMetricsExposesPeerLifecycleExits(t *testing.T) {
	state := mustRPCState(t, false)
	state.SetPeerLifecycleExitsFunc(func() uint64 { return 7 })
	body := renderPrometheusMetrics(state)
	for _, want := range []string{
		"# HELP rubin_node_p2p_peer_lifecycle_exits_total Total peer lifecycle exits observed by the p2p service since process start.",
		"# TYPE rubin_node_p2p_peer_lifecycle_exits_total counter",
		"rubin_node_p2p_peer_lifecycle_exits_total 7",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in metrics body %q", want, body)
		}
	}
	// Reject any labeled form: the metric must be emitted unlabeled
	// (single line "name <value>"), never "name{kind=...} <value>".
	if strings.Contains(body, "rubin_node_p2p_peer_lifecycle_exits_total{") {
		t.Fatalf("metric emitted with labels — must stay unlabeled per #1307: %q", body)
	}
}

// TestRenderPrometheusMetricsTwiceDoesNotMutatePeerLifecycleExits
// pins the scrape-time-no-mutation contract for the new lifecycle
// exit metric. The stub closure tracks how many times the renderer
// invokes it; the renderer is allowed to call the closure (it is a
// pure Load() on the production side), but the rendered counter
// value MUST equal what the closure returns each scrape — render
// itself MUST NOT add any per-scrape delta.
// Proof assertion: rendered value on second scrape equals first
// scrape's value (closure returns constant 5).
func TestRenderPrometheusMetricsTwiceDoesNotMutatePeerLifecycleExits(t *testing.T) {
	state := mustRPCState(t, false)
	const fixedValue uint64 = 5
	state.SetPeerLifecycleExitsFunc(func() uint64 { return fixedValue })
	body1 := renderPrometheusMetrics(state)
	body2 := renderPrometheusMetrics(state)
	want := "rubin_node_p2p_peer_lifecycle_exits_total 5"
	if !strings.Contains(body1, want) || !strings.Contains(body2, want) {
		t.Fatalf("expected %q in both renders; body1=%q body2=%q", want, body1, body2)
	}
}

// TestRenderPrometheusMetricsNilPeerLifecycleClosureRendersZero
// covers the test-fixture path where SetPeerLifecycleExitsFunc was
// never called.
// Proof assertion: body contains "rubin_node_p2p_peer_lifecycle_exits_total 0"
// without panic.
func TestRenderPrometheusMetricsNilPeerLifecycleClosureRendersZero(t *testing.T) {
	state := mustRPCState(t, false)
	// Deliberately do NOT call state.SetPeerLifecycleExitsFunc.
	body := renderPrometheusMetrics(state)
	want := "rubin_node_p2p_peer_lifecycle_exits_total 0"
	if !strings.Contains(body, want) {
		t.Fatalf("missing %q (nil closure must render 0): body=%q", want, body)
	}
}

func TestParseHex32ValueRejectsWrongLength(t *testing.T) {
	if _, err := parseHex32Value("00"); err == nil {
		t.Fatal("expected wrong-length error")
	}
}

func TestDecodeHexPayloadAcceptsPrefix(t *testing.T) {
	raw, err := decodeHexPayload("0x00ff")
	if err != nil {
		t.Fatalf("decodeHexPayload: %v", err)
	}
	if got := hex.EncodeToString(raw); got != "00ff" {
		t.Fatalf("got %q", got)
	}
}

func TestTipFromBlockStoreRejectsNilStore(t *testing.T) {
	if _, _, _, err := tipFromBlockStore(nil); err == nil {
		t.Fatal("expected nil-store error")
	}
}

func TestClassifySubmitErrVariants(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantResult string
	}{
		{name: "conflict already present", err: &node.TxAdmitError{Kind: node.TxAdmitConflict, Message: "already in mempool"}, wantStatus: http.StatusConflict, wantResult: "conflict"},
		{name: "conflict double spend", err: &node.TxAdmitError{Kind: node.TxAdmitConflict, Message: "double-spend conflict"}, wantStatus: http.StatusConflict, wantResult: "conflict"},
		{name: "unavailable mempool full", err: &node.TxAdmitError{Kind: node.TxAdmitUnavailable, Message: "mempool full"}, wantStatus: http.StatusServiceUnavailable, wantResult: "unavailable"},
		{name: "unavailable rolling floor", err: &node.TxAdmitError{Kind: node.TxAdmitUnavailable, Message: "mempool fee below rolling minimum"}, wantStatus: http.StatusServiceUnavailable, wantResult: "unavailable"},
		{name: "unavailable blockstore", err: &node.TxAdmitError{Kind: node.TxAdmitUnavailable, Message: "blockstore unavailable"}, wantStatus: http.StatusServiceUnavailable, wantResult: "unavailable"},
		{name: "rejected consensus", err: &node.TxAdmitError{Kind: node.TxAdmitRejected, Message: "transaction rejected"}, wantStatus: http.StatusUnprocessableEntity, wantResult: "rejected"},
		{name: "fallback unknown error", err: errors.New("something unexpected"), wantStatus: http.StatusUnprocessableEntity, wantResult: "rejected"},
		{name: "nil error", err: nil, wantStatus: http.StatusOK, wantResult: "accepted"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, result := classifySubmitErr(tc.err)
			if status != tc.wantStatus || result != tc.wantResult {
				t.Fatalf("got (%d, %q), want (%d, %q)", status, result, tc.wantStatus, tc.wantResult)
			}
		})
	}
}

func TestTxAdmitErrorKindHTTPMapping(t *testing.T) {
	// Parity table: must match Rust TxPoolAdmitErrorKind → HTTP status in devnet_rpc.rs.
	parity := []struct {
		kind       node.TxAdmitErrorKind
		wantStatus int
	}{
		{node.TxAdmitConflict, http.StatusConflict},              // 409
		{node.TxAdmitRejected, http.StatusUnprocessableEntity},   // 422
		{node.TxAdmitUnavailable, http.StatusServiceUnavailable}, // 503
	}
	for _, p := range parity {
		err := &node.TxAdmitError{Kind: p.kind, Message: "test"}
		status, _ := classifySubmitErr(err)
		if status != p.wantStatus {
			t.Errorf("kind %q: got status %d, want %d", p.kind, status, p.wantStatus)
		}
	}
}

func TestStartDevnetRPCServerLifecycle(t *testing.T) {
	state := mustRPCState(t, false)
	server, err := startDevnetRPCServer("127.0.0.1:0", state, nil, nil)
	if err != nil {
		t.Fatalf("startDevnetRPCServer: %v", err)
	}
	if server == nil || server.addr == "" {
		t.Fatalf("expected listening server, got %#v", server)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + server.addr + "/get_tip")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestStartDevnetRPCServerWritesListeningBannerAndCloseHandlesNil(t *testing.T) {
	state := mustRPCState(t, false)
	var stdout bytes.Buffer
	server, err := startDevnetRPCServer("127.0.0.1:0", state, &stdout, nil)
	if err != nil {
		t.Fatalf("startDevnetRPCServer: %v", err)
	}
	if !strings.Contains(stdout.String(), "rpc: listening=") {
		t.Fatalf("stdout=%q, want listening banner", stdout.String())
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var nilServer *runningDevnetRPCServer
	if err := nilServer.Close(context.Background()); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}

func TestStartDevnetRPCServerDisabledReturnsNil(t *testing.T) {
	server, err := startDevnetRPCServer("   ", mustRPCState(t, false), nil, nil)
	if err != nil {
		t.Fatalf("startDevnetRPCServer: %v", err)
	}
	if server != nil {
		t.Fatalf("server=%#v, want nil", server)
	}
}

func TestStartDevnetRPCServerRejectsNilState(t *testing.T) {
	server, err := startDevnetRPCServer("127.0.0.1:0", nil, nil, nil)
	if err == nil {
		t.Fatal("expected nil-state error")
	}
	if server != nil {
		t.Fatalf("server=%#v, want nil", server)
	}
}

func TestDevnetRPCSubmitTxLogsAnnounceTxError(t *testing.T) {
	fromKey := mustRPCMLDSA87Keypair(t)
	toKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	var stderrBuf bytes.Buffer
	state, input, utxos := mustRPCStateWithSpendableUTXO(t, fromAddress, func(tx []byte) error {
		return errors.New("p2p broadcast unavailable")
	})
	state.stderr = &stderrBuf

	txBytes, _ := mustRPCSignedTransferTx(t, utxos, input, fromKey, toAddress)
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	body, err := json.Marshal(submitTxRequest{TxHex: hex.EncodeToString(txBytes)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resp, err := http.Post(server.URL+"/submit_tx", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	// Transaction should still be accepted (announce failure is non-blocking).
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var got submitTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Accepted {
		t.Fatalf("accepted=false, want true")
	}

	// Verify the error was logged to stderr.
	stderrOutput := stderrBuf.String()
	if !strings.Contains(stderrOutput, "rpc: announce-tx:") {
		t.Fatalf("expected announce-tx error on stderr, got: %q", stderrOutput)
	}
	if !strings.Contains(stderrOutput, "p2p broadcast unavailable") {
		t.Fatalf("expected error message on stderr, got: %q", stderrOutput)
	}
}

func TestNewDevnetRPCStateNilStderrFallsBackToDiscard(t *testing.T) {
	state := newDevnetRPCState(nil, nil, nil, nil, nil, nil, nil, nil)
	if state.stderr != io.Discard {
		t.Fatal("expected io.Discard for nil stderr")
	}
}

func TestRPCBindHostIsLoopback(t *testing.T) {
	if !rpcBindHostIsLoopback("127.0.0.1:19112") {
		t.Fatal("expected loopback for 127.0.0.1")
	}
	if !rpcBindHostIsLoopback("[::1]:19112") {
		t.Fatal("expected loopback for ::1")
	}
	if !rpcBindHostIsLoopback("localhost:19112") {
		t.Fatal("expected loopback for localhost")
	}
	if rpcBindHostIsLoopback("0.0.0.0:19112") {
		t.Fatal("expected non-loopback for 0.0.0.0")
	}
	if rpcBindHostIsLoopback("example.com:19112") {
		t.Fatal("expected non-loopback for example.com")
	}
	if rpcBindHostIsLoopback("127.0.0.1") {
		t.Fatal("missing port must be rejected")
	}
	if rpcBindHostIsLoopback("not-a-host:19112") {
		t.Fatal("invalid host:port must be rejected")
	}
	if rpcBindHostIsLoopback("127.0.0.1:") {
		t.Fatal("empty port must be rejected")
	}
	if rpcBindHostIsLoopback("localhost:") {
		t.Fatal("empty port must be rejected for localhost")
	}
	if rpcBindHostIsLoopback("[::1]:") {
		t.Fatal("empty port must be rejected for bracket IPv6")
	}
	if rpcBindHostIsLoopback("127.0.0.1:99999") {
		t.Fatal("out-of-range port must be rejected")
	}
	if !rpcBindHostIsLoopback("127.0.0.1:0") {
		t.Fatal("port 0 is valid for bind addresses")
	}
}

func TestHandleMineNextNilState(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mine_next", nil)
	handleMineNext(nil, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", rec.Code)
	}
	var got mineNextResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Error != "rpc unavailable" {
		t.Fatalf("error=%q want rpc unavailable", got.Error)
	}
}

func TestDevnetRPCMineNextMineOneError(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	chainState := node.NewChainState()
	if err := chainState.Save(chainStatePath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncCfg := node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), chainStatePath)
	syncEngine, err := node.NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := syncEngine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	mempool, err := node.NewMempool(chainState, blockStore, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	syncEngine.SetMempool(mempool)
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))
	miner, err := node.NewMiner(chainState, blockStore, syncEngine, node.DefaultMinerConfig())
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, nil, nil, io.Discard, miner)
	state.nowUnix = func() uint64 { return 0 }

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/mine_next", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	handleMineNext(state, rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d want 422", rec.Code)
	}
	var got mineNextResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Mined || got.Error == "" {
		t.Fatalf("unexpected response: %+v", got)
	}
	if !strings.Contains(got.Error, context.Canceled.Error()) {
		t.Fatalf("error=%q want context canceled", got.Error)
	}
}

func TestDevnetRPCMineNextRejectsGet(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	t.Cleanup(server.Close)
	resp, err := http.Get(server.URL + "/mine_next")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

func TestDevnetRPCMineNextUnavailableWithoutMiner(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	t.Cleanup(server.Close)
	resp, err := http.Post(server.URL+"/mine_next", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", resp.StatusCode)
	}
}

func TestDevnetRPCMineNextMinesAfterGenesis(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	chainState := node.NewChainState()
	if err := chainState.Save(chainStatePath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncCfg := node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), chainStatePath)
	syncEngine, err := node.NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := syncEngine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	mempool, err := node.NewMempool(chainState, blockStore, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	syncEngine.SetMempool(mempool)
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))
	miner, err := node.NewMiner(chainState, blockStore, syncEngine, node.DefaultMinerConfig())
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	var announcedBlock []byte
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, nil, func(block []byte) error {
		announcedBlock = append([]byte(nil), block...)
		return nil
	}, io.Discard, miner)
	state.nowUnix = func() uint64 { return 0 }
	server := httptest.NewServer(newDevnetRPCHandler(state))
	t.Cleanup(server.Close)
	resp, err := http.Post(server.URL+"/mine_next", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	var got mineNextResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Mined || got.Height == nil || *got.Height != 1 || got.TxCount == nil || *got.TxCount != 1 {
		t.Fatalf("unexpected response: %+v", got)
	}
	if got.Nonce == nil {
		t.Fatalf("want nonce field in JSON for Go/Rust RPC parity, got %+v", got)
	}
	if len(announcedBlock) == 0 {
		t.Fatal("expected /mine_next to announce the mined full block")
	}
	parsedBlock, err := consensus.ParseBlockBytes(announcedBlock)
	if err != nil {
		t.Fatalf("ParseBlockBytes(announced): %v", err)
	}
	announcedHash, err := consensus.BlockHash(parsedBlock.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(announced): %v", err)
	}
	if got.BlockHash == nil || *got.BlockHash != hex.EncodeToString(announcedHash[:]) {
		t.Fatalf("announced block hash=%x response_block_hash=%v", announcedHash, got.BlockHash)
	}
	if len(parsedBlock.Txs) != 1 {
		t.Fatalf("mined block tx count=%d, want 1 coinbase tx only", len(parsedBlock.Txs))
	}
	coinbase := parsedBlock.Txs[0]
	var zeroTxid [32]byte
	if coinbase.TxKind != 0x00 || coinbase.TxNonce != 0 || len(coinbase.Witness) != 0 || len(coinbase.Inputs) != 1 {
		t.Fatalf("tx[0] is not a canonical coinbase shape: %+v", coinbase)
	}
	if coinbase.Inputs[0].PrevTxid != zeroTxid || coinbase.Inputs[0].PrevVout != ^uint32(0) || coinbase.Inputs[0].Sequence != ^uint32(0) || len(coinbase.Inputs[0].ScriptSig) != 0 {
		t.Fatalf("tx[0] coinbase input mismatch: %+v", coinbase.Inputs[0])
	}
	var anchorOutputs int
	for _, out := range coinbase.Outputs {
		if out.CovenantType != consensus.COV_TYPE_ANCHOR {
			continue
		}
		anchorOutputs++
		if out.Value != 0 {
			t.Fatalf("coinbase CORE_ANCHOR value=%d, want 0", out.Value)
		}
		if len(out.CovenantData) != 32 {
			t.Fatalf("coinbase CORE_ANCHOR covenant_data_len=%d, want 32", len(out.CovenantData))
		}
	}
	if anchorOutputs != 1 {
		t.Fatalf("coinbase CORE_ANCHOR outputs=%d, want 1", anchorOutputs)
	}
}

func TestDevnetRPCMineNextLogsAnnounceBlockError(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	chainState := node.NewChainState()
	if err := chainState.Save(chainStatePath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncCfg := node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), chainStatePath)
	syncEngine, err := node.NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := syncEngine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	mempool, err := node.NewMempool(chainState, blockStore, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	syncEngine.SetMempool(mempool)
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))
	miner, err := node.NewMiner(chainState, blockStore, syncEngine, node.DefaultMinerConfig())
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	var stderrBuf bytes.Buffer
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, nil, func(block []byte) error {
		return errors.New("p2p block broadcast unavailable")
	}, &stderrBuf, miner)
	state.nowUnix = func() uint64 { return 0 }
	server := httptest.NewServer(newDevnetRPCHandler(state))
	t.Cleanup(server.Close)
	resp, err := http.Post(server.URL+"/mine_next", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	var got mineNextResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Mined {
		t.Fatalf("mined=false, want true: %+v", got)
	}
	stderrOutput := stderrBuf.String()
	if !strings.Contains(stderrOutput, "rpc: announce-block:") {
		t.Fatalf("expected announce-block error on stderr, got: %q", stderrOutput)
	}
	if !strings.Contains(stderrOutput, "p2p block broadcast unavailable") {
		t.Fatalf("expected announce-block error message on stderr, got: %q", stderrOutput)
	}
}

func TestDevnetRPCGetMempoolEmpty(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_mempool")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var got getMempoolResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Count != 0 {
		t.Fatalf("Count=%d, want 0", got.Count)
	}
	if got.TxIDs == nil {
		t.Fatalf("TxIDs=nil, want empty slice (must serialize as [] not null)")
	}
	if len(got.TxIDs) != 0 {
		t.Fatalf("TxIDs=%v, want empty", got.TxIDs)
	}
}

func TestDevnetRPCGetMempoolRejectsBadMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/get_mempool", nil)
	rec := httptest.NewRecorder()
	handleGetMempool(mustRPCState(t, true), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestDevnetRPCGetMempoolUnavailableOnNilState(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/get_mempool", nil)
	rec := httptest.NewRecorder()
	handleGetMempool(nil, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
}

func TestDevnetRPCGetTxRejectsMissingTxIDParam(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_tx")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
	var got getTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Found {
		t.Fatalf("Found=true, want false for missing txid param")
	}
	if got.Error == "" {
		t.Fatalf("Error empty, want missing-txid message")
	}
}

func TestDevnetRPCGetTxRejectsInvalidLength(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/get_tx?txid=deadbeef")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}

func TestDevnetRPCGetTxRejectsNonHex(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	badTxid := strings.Repeat("z", 64)
	resp, err := http.Get(server.URL + "/get_tx?txid=" + badTxid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}

func TestDevnetRPCGetTxMissingReturnsFoundFalse(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	unknownTxid := strings.Repeat("11", 32)
	resp, err := http.Get(server.URL + "/get_tx?txid=" + unknownTxid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var got getTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Found {
		t.Fatalf("Found=true, want false for unknown txid")
	}
	if got.TxID != unknownTxid {
		t.Fatalf("TxID=%q, want echoed input", got.TxID)
	}
}

func TestDevnetRPCTxStatusMissingReturnsMissing(t *testing.T) {
	server := httptest.NewServer(newDevnetRPCHandler(mustRPCState(t, true)))
	defer server.Close()

	unknownTxid := strings.Repeat("22", 32)
	resp, err := http.Get(server.URL + "/tx_status?txid=" + unknownTxid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var got txStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Status != "missing" {
		t.Fatalf("Status=%q, want missing", got.Status)
	}
}

func TestDevnetRPCTxStatusRejectsInvalidTxID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/tx_status?txid=not-hex", nil)
	rec := httptest.NewRecorder()
	handleTxStatus(mustRPCState(t, true), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestDevnetRPCTxLifecyclePendingHappyPath(t *testing.T) {
	fromKey := mustRPCMLDSA87Keypair(t)
	toKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	state, input, utxos := mustRPCStateWithSpendableUTXO(t, fromAddress, nil)
	txBytes, wantTxID := mustRPCSignedTransferTx(t, utxos, input, fromKey, toAddress)
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	// submit
	body, err := json.Marshal(submitTxRequest{TxHex: hex.EncodeToString(txBytes)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resp, err := http.Post(server.URL+"/submit_tx", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("submit status=%d, want 200", resp.StatusCode)
	}

	// get_mempool — count=1 with the submitted txid
	mpResp, err := http.Get(server.URL + "/get_mempool")
	if err != nil {
		t.Fatalf("Get mempool: %v", err)
	}
	defer mpResp.Body.Close()
	var mp getMempoolResponse
	if err := json.NewDecoder(mpResp.Body).Decode(&mp); err != nil {
		t.Fatalf("Decode mempool: %v", err)
	}
	if mp.Count != 1 {
		t.Fatalf("mempool count=%d, want 1", mp.Count)
	}
	if len(mp.TxIDs) != 1 || mp.TxIDs[0] != wantTxID {
		t.Fatalf("mempool txids=%v, want [%q]", mp.TxIDs, wantTxID)
	}

	// get_tx — found=true, raw_hex matches
	txResp, err := http.Get(server.URL + "/get_tx?txid=" + wantTxID)
	if err != nil {
		t.Fatalf("Get tx: %v", err)
	}
	defer txResp.Body.Close()
	var gx getTxResponse
	if err := json.NewDecoder(txResp.Body).Decode(&gx); err != nil {
		t.Fatalf("Decode tx: %v", err)
	}
	if !gx.Found {
		t.Fatalf("Found=false, want true")
	}
	if gx.TxID != wantTxID {
		t.Fatalf("TxID=%q, want %q", gx.TxID, wantTxID)
	}
	if gx.RawHex == nil || *gx.RawHex != hex.EncodeToString(txBytes) {
		t.Fatalf("RawHex mismatch: got=%v want=%q", gx.RawHex, hex.EncodeToString(txBytes))
	}

	// tx_status — pending
	stResp, err := http.Get(server.URL + "/tx_status?txid=" + wantTxID)
	if err != nil {
		t.Fatalf("Get tx_status: %v", err)
	}
	defer stResp.Body.Close()
	var st txStatusResponse
	if err := json.NewDecoder(stResp.Body).Decode(&st); err != nil {
		t.Fatalf("Decode tx_status: %v", err)
	}
	if st.Status != "pending" {
		t.Fatalf("Status=%q, want pending", st.Status)
	}
	if st.TxID != wantTxID {
		t.Fatalf("TxID=%q, want %q", st.TxID, wantTxID)
	}
}

func TestDevnetRPCGetTxRejectsBadMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/get_tx?txid="+strings.Repeat("1", 64), nil)
	rec := httptest.NewRecorder()
	handleGetTx(mustRPCState(t, true), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestDevnetRPCGetTxUnavailableOnNilState(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/get_tx?txid="+strings.Repeat("1", 64), nil)
	rec := httptest.NewRecorder()
	handleGetTx(nil, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
}

func TestDevnetRPCTxStatusRejectsBadMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/tx_status?txid="+strings.Repeat("1", 64), nil)
	rec := httptest.NewRecorder()
	handleTxStatus(mustRPCState(t, true), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestDevnetRPCTxStatusUnavailableOnNilState(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/tx_status?txid="+strings.Repeat("1", 64), nil)
	rec := httptest.NewRecorder()
	handleTxStatus(nil, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
}

func TestDevnetRPCGetTxEmptyTxIDValueIsClassifiedAsMissing(t *testing.T) {
	// Go/Rust parity regression: ?txid= (present but empty value) must be
	// classified as missing parameter in BOTH clients.
	req := httptest.NewRequest(http.MethodGet, "/get_tx?txid=", nil)
	rec := httptest.NewRecorder()
	handleGetTx(mustRPCState(t, true), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
	var got getTxResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(got.Error, "missing required query parameter") {
		t.Fatalf("Error=%q, want 'missing required query parameter' to match Rust parity", got.Error)
	}
}

func TestDevnetRPCTxStatusEmptyTxIDValueIsClassifiedAsMissing(t *testing.T) {
	// Parity sibling for tx_status.
	req := httptest.NewRequest(http.MethodGet, "/tx_status?txid=", nil)
	rec := httptest.NewRecorder()
	handleTxStatus(mustRPCState(t, true), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
	var got txStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(got.Error, "missing required query parameter") {
		t.Fatalf("Error=%q, want 'missing required query parameter' to match Rust parity", got.Error)
	}
}

func TestDevnetRPCGetTxValuelessTxIDKeyClassifiedAsMissing(t *testing.T) {
	// Go/Rust parity regression: ?txid (key without `=`) or ?txid&txid=<hex>
	// — Go's net/url parses a
	// key without `=` into url.Values{"txid":[""]}, so Query().Get returns
	// "" (missing). Rust parser must match: treat key without `=` as
	// present-with-empty, classify as missing, first-match semantic (never
	// accept a later duplicate-key value).
	validHex := strings.Repeat("ab", 32)
	// Case 1: ?txid (no value, no duplicate)
	req := httptest.NewRequest(http.MethodGet, "/get_tx?txid", nil)
	rec := httptest.NewRecorder()
	handleGetTx(mustRPCState(t, true), rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("case ?txid status=%d, want 400", rec.Code)
	}
	// Case 2: ?txid&txid=<valid hex> — first key is valueless, Rust must
	// reject as missing (not accept the second key's hex).
	req2 := httptest.NewRequest(http.MethodGet, "/get_tx?txid&txid="+validHex, nil)
	rec2 := httptest.NewRecorder()
	handleGetTx(mustRPCState(t, true), rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("case ?txid&txid=<hex> status=%d, want 400 (first-match semantic)", rec2.Code)
	}
	var got getTxResponse
	if err := json.NewDecoder(rec2.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(got.Error, "missing required query parameter") {
		t.Fatalf("Error=%q, want 'missing required query parameter' (first-match semantic)", got.Error)
	}
}

func TestDevnetRPCGetTxFailsClosedOn503BeforeParsingInvalidTxID(t *testing.T) {
	// Contract: mempool unavailability is a 503 fail-closed regardless of
	// query-string validity. A nil mempool + invalid txid MUST return 503
	// (not 400). Previously handleGetTx parsed first and returned 400 on
	// bad query, masking the unavailability.
	req := httptest.NewRequest(http.MethodGet, "/get_tx?txid=invalid-not-hex", nil)
	rec := httptest.NewRecorder()
	handleGetTx(nil, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503 (mempool unavailable fail-closed takes precedence over 400 parse-error)", rec.Code)
	}
	var got getTxResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(got.Error, "mempool unavailable") {
		t.Fatalf("Error=%q, want 'mempool unavailable'", got.Error)
	}
}

func TestDevnetRPCTxStatusFailsClosedOn503BeforeParsingInvalidTxID(t *testing.T) {
	// Parity sibling of the handleGetTx ordering fix.
	req := httptest.NewRequest(http.MethodGet, "/tx_status?txid=invalid-not-hex", nil)
	rec := httptest.NewRecorder()
	handleTxStatus(nil, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
	var got txStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(got.Error, "mempool unavailable") {
		t.Fatalf("Error=%q, want 'mempool unavailable'", got.Error)
	}
}

// TestReadyHandlerReports503WhenNotReady pins the default-state contract:
// a fresh devnetRPCState must report not-ready until cmd/rubin-node has
// transitioned the gate at the all-subsystems-up boundary. The gate's
// default state is NotReady (zero value of int8 readyState), so a
// freshly constructed state observes 503 with body {"ready":false}.
// Reverting that default in the future would silently re-introduce the
// false-ready-during-partial-init class.
func TestReadyHandlerReports503WhenNotReady(t *testing.T) {
	state := mustRPCState(t, false)
	handler := newDevnetRPCHandler(state)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q, want application/json", got)
	}
	var body readyResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if body.Ready {
		t.Fatalf("body.Ready=true, want false")
	}
}

// TestReadyHandlerReports200AfterTryMarkReadyOnStartup pins the positive
// contract: once the boot-time TryMarkReadyOnStartup transition NotReady → Ready wins, GET /ready
// returns 200 with body {"ready":true}. A subsequent MarkShutdown stamp
// flips the response back to 503 and is sticky — TryMarkReadyOnStartup
// can no longer return the latch to Ready in this state's lifetime.
func TestReadyHandlerReports200AfterTryMarkReadyOnStartup(t *testing.T) {
	state := mustRPCState(t, false)
	if !state.TryMarkReadyOnStartup() {
		t.Fatalf("TryMarkReadyOnStartup failed on fresh state")
	}
	handler := newDevnetRPCHandler(state)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var body readyResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !body.Ready {
		t.Fatalf("body.Ready=false, want true")
	}

	// Stamp Shutdown — same handler instance must observe sticky
	// transition. After this point the latch must NEVER return to
	// Ready: TryMarkReadyOnStartup cannot succeed against a
	// current value of 2.
	state.MarkShutdown()
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status after MarkShutdown=%d, want 503", rec.Code)
	}
	if got := state.TryMarkReadyOnStartup(); got {
		t.Fatalf("TryMarkReadyOnStartup unexpectedly succeeded after MarkShutdown")
	}
	if state.IsReady() {
		t.Fatalf("IsReady=true after MarkShutdown, want false (sticky latch)")
	}
}

// TestReadyHandlerRejectsNonGet locks the method contract: only GET is
// served. POST/PUT/DELETE/etc must return 405 so probes that accidentally
// use a non-idempotent verb fail loudly rather than silently observing an
// unrelated body.
func TestReadyHandlerRejectsNonGet(t *testing.T) {
	state := mustRPCState(t, false)
	state.TryMarkReadyOnStartup()
	handler := newDevnetRPCHandler(state)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(method, "/ready", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("method=%s status=%d, want 405", method, rec.Code)
		}
		// Error body uses the same submitTxResponse JSON envelope as the
		// rest of the devnet RPC surface (see handleGetTip / handleSubmitTx
		// non-method paths) so the endpoint stays machine-readable on error
		// rather than returning plain-text http.Error.
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("method=%s Content-Type=%q, want application/json", method, got)
		}
		// RFC 9110 §15.5.6: 405 responses MUST list the permitted methods
		// in the Allow header so generic HTTP clients can self-correct.
		if got := rec.Header().Get("Allow"); got != http.MethodGet {
			t.Fatalf("method=%s Allow=%q, want %q", method, got, http.MethodGet)
		}
		var body submitTxResponse
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("method=%s Decode: %v", method, err)
		}
		if body.Accepted {
			t.Fatalf("method=%s body.Accepted=true, want false", method)
		}
		if !strings.Contains(body.Error, "GET required") {
			t.Fatalf("method=%s body.Error=%q, want substring 'GET required'", method, body.Error)
		}
	}
}

// TestRunningServerLatchMethodsNilSafe documents that the wrapper-level
// readiness latch methods all tolerate a nil receiver, keeping
// cmd/rubin-node's startup and shutdown paths robust if a future
// refactor introduces an early return before rpcServer is fully
// constructed. TryMarkReadyOnStartup must return false on nil; MarkShutdown
// must not panic; IsReady must return false on nil.
func TestRunningServerLatchMethodsNilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil-receiver latch method panicked: %v", r)
		}
	}()
	var s *runningDevnetRPCServer
	if got := s.TryMarkReadyOnStartup(); got {
		t.Fatalf("TryMarkReadyOnStartup on nil returned true, want false")
	}
	s.MarkShutdown()
	if got := s.IsReady(); got {
		t.Fatalf("IsReady on nil returned true, want false")
	}
}

// stateWithGate constructs a minimal *devnetRPCState wired with a
// readinessGate using the supplied shutdownCtx. Used by readiness gate
// tests that do not need the full mustRPCState fixture (chainstate,
// blockstore, etc.). Pass context.TODO() for state-only fixtures that
// don't exercise shutdown-ctx observation.
func stateWithGate(shutdownCtx context.Context) *devnetRPCState {
	return &devnetRPCState{gate: newReadinessGate(shutdownCtx)}
}

// TestReadinessGate_NilHandling exercises every nil-receiver guard on
// readinessGate and on devnetRPCState's gate-forwarding methods. The
// guards are defensive Go-conventional code paths the production
// rubin-node never enters (cmd/rubin-node always constructs a non-nil
// gate via newDevnetRPCState), but they exist to keep the surface
// robust against future refactors that introduce partial-init paths.
func TestReadinessGate_NilHandling(t *testing.T) {
	t.Run("nil_gate_pointer", func(t *testing.T) {
		var g *readinessGate
		if g.TryMarkReadyOnStartup() {
			t.Fatal("nil gate TryMarkReadyOnStartup returned true, want false")
		}
		g.MarkShutdown() // must not panic
		if g.IsReady() {
			t.Fatal("nil gate IsReady returned true, want false")
		}
		g.setShutdownCtx(context.TODO()) // must not panic
	})

	t.Run("gate_with_nil_shutdownCtx_field", func(t *testing.T) {
		// Direct struct construction: shutdownCtx zero value is nil.
		// Exercises observeShutdownLocked's "shutdownCtx == nil →
		// state-only" branch without violating SA1012 (no nil ctx is
		// passed through any constructor API).
		g := &readinessGate{}
		if !g.TryMarkReadyOnStartup() {
			t.Fatal("expected fresh gate with nil shutdownCtx to allow startup transition")
		}
		if !g.IsReady() {
			t.Fatal("expected IsReady=true after successful startup transition on state-only gate")
		}
		g.MarkShutdown()
		if g.IsReady() {
			t.Fatal("expected IsReady=false after MarkShutdown on state-only gate")
		}
	})

	t.Run("nil_devnetRPCState_pointer", func(t *testing.T) {
		var s *devnetRPCState
		if s.TryMarkReadyOnStartup() {
			t.Fatal("nil state TryMarkReadyOnStartup returned true, want false")
		}
		s.MarkShutdown() // must not panic
		if s.IsReady() {
			t.Fatal("nil state IsReady returned true, want false")
		}
		s.SetShutdownCtx(context.TODO()) // must not panic
	})

	t.Run("devnetRPCState_with_nil_gate", func(t *testing.T) {
		// State without a gate (theoretical partial-init path) must not
		// panic and must report not-ready for everything.
		s := &devnetRPCState{}
		if s.TryMarkReadyOnStartup() {
			t.Fatal("state with nil gate TryMarkReadyOnStartup returned true, want false")
		}
		s.MarkShutdown() // must not panic
		if s.IsReady() {
			t.Fatal("state with nil gate IsReady returned true, want false")
		}
		s.SetShutdownCtx(context.TODO()) // must not panic
	})
}

// TestReadinessGate_AlreadyReadyShortCircuit pins the
// state-not-NotReady branch of TryMarkReadyOnStartup: a second call on
// an already-Ready gate must return false (state != NotReady) but
// must NOT regress IsReady to false.
func TestReadinessGate_AlreadyReadyShortCircuit(t *testing.T) {
	state := stateWithGate(context.Background())
	if !state.TryMarkReadyOnStartup() {
		t.Fatal("first TryMarkReadyOnStartup returned false on fresh state")
	}
	if state.TryMarkReadyOnStartup() {
		t.Fatal("second TryMarkReadyOnStartup returned true on already-Ready state, want false")
	}
	if !state.IsReady() {
		t.Fatal("expected gate to stay in Ready after duplicate TryMarkReadyOnStartup")
	}
}

// TestReadinessGate_DeterministicShutdownBeforeStartup pins the
// deterministic regression: once MarkShutdown stamps the gate, any
// subsequent TryMarkReadyOnStartup MUST fail and IsReady MUST stay
// false. This is the exact bug class the prior atomic.Bool +
// check-then-set shape (PR #1301) could not catch.
func TestReadinessGate_DeterministicShutdownBeforeStartup(t *testing.T) {
	state := stateWithGate(context.TODO())
	state.MarkShutdown()
	if got := state.TryMarkReadyOnStartup(); got {
		t.Fatal("TryMarkReadyOnStartup succeeded after MarkShutdown, want false")
	}
	if state.IsReady() {
		t.Fatal("IsReady=true after MarkShutdown, want false (sticky)")
	}
	// Idempotent re-stamp: calling MarkShutdown again is a no-op for
	// observable state.
	state.MarkShutdown()
	if state.IsReady() {
		t.Fatal("IsReady=true after second MarkShutdown")
	}
	if got := state.TryMarkReadyOnStartup(); got {
		t.Fatal("TryMarkReadyOnStartup unexpectedly succeeded after second MarkShutdown")
	}
}

// TestReadinessGate_TryMarkReadyOnStartupObservesShutdownCtxUnderLock
// pins the strict ctx-observation contract for the boot-time
// transition: when the gate's wired shutdownCtx is already canceled
// at the moment TryMarkReadyOnStartup is called, the locked observe-
// then-decide path stamps Shutdown and the transition fails. This
// closes the production race where SIGINT/SIGTERM was delivered in
// the window between the lifecycle ctx being wired and the boot-time
// transition call site, before any explicit MarkShutdown runs.
//
// Reverting the in-lock observeShutdownLocked call from
// TryMarkReadyOnStartup turns this red.
func TestReadinessGate_TryMarkReadyOnStartupObservesShutdownCtxUnderLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state := stateWithGate(ctx)
	if got := state.TryMarkReadyOnStartup(); got {
		t.Fatal("TryMarkReadyOnStartup succeeded with pre-canceled shutdownCtx, want false")
	}
	if state.IsReady() {
		t.Fatal("IsReady=true after TryMarkReadyOnStartup with pre-canceled ctx, want false")
	}
}

// TestReadinessGate_IsReadyObservesShutdownCtxUnderLock pins the strict
// ctx-observation contract for the read path: even when state is
// Ready, IsReady MUST return false the moment the wired shutdownCtx is
// observed canceled inside the same lock. This closes the production
// race where SIGINT/SIGTERM was delivered AFTER TryMarkReadyOnStartup
// won, but BEFORE main.go reached MarkShutdown — without this contract
// /ready could briefly report 200 in that window.
//
// Reverting IsReady's in-lock observeShutdownLocked call to a state-
// only Load turns this red.
func TestReadinessGate_IsReadyObservesShutdownCtxUnderLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	state := stateWithGate(ctx)
	// Boot-time transition succeeds with live ctx.
	if got := state.TryMarkReadyOnStartup(); !got {
		t.Fatal("TryMarkReadyOnStartup failed on fresh state with live ctx, want true")
	}
	if !state.IsReady() {
		t.Fatal("IsReady=false after successful transition, want true")
	}
	// Cancel the wired shutdownCtx; do NOT call MarkShutdown explicitly.
	// IsReady MUST observe the cancellation under its own lock and
	// return false on the very next read.
	cancel()
	if state.IsReady() {
		t.Fatal("IsReady=true after wired shutdownCtx canceled, want false (gate must observe ctx under lock)")
	}
	// Sticky: even with a fresh live ctx wired afterwards, IsReady stays
	// false because observeShutdownLocked already stamped Shutdown.
	freshCtx := context.Background()
	state.gate.setShutdownCtx(freshCtx)
	if state.IsReady() {
		t.Fatal("IsReady=true after re-wiring fresh ctx onto already-stamped gate, want false (Shutdown is sticky)")
	}
}

// TestReadinessGate_ConcurrentRaceCannotResurrectReady is supplemental
// extra-evidence: with mutex-serialized transitions, neither order of
// concurrent TryMarkReadyOnStartup / MarkShutdown can leave IsReady
// true. NOT the primary regression — the deterministic
// shutdown-before-startup test and the ctx-observation tests above
// are the load-bearing proofs. N is kept small (256) so the test
// stays fast and non-flaky on shared CI runners.
func TestReadinessGate_ConcurrentRaceCannotResurrectReady(t *testing.T) {
	const iterations = 256
	for i := 0; i < iterations; i++ {
		state := stateWithGate(context.TODO())
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			state.TryMarkReadyOnStartup()
		}()
		go func() {
			defer wg.Done()
			state.MarkShutdown()
		}()
		wg.Wait()
		if state.IsReady() {
			t.Fatalf("iter %d: IsReady=true after concurrent TryMarkReadyOnStartup/MarkShutdown, want false", i)
		}
	}
}

// nonDevnetChainID and nonDevnetGenesisHash are fixed [32]byte values
// chosen specifically to NOT match node.DevnetGenesisChainID() or
// node.DevnetGenesisBlockHash(). The /chain_identity tests inject
// these via SetIdentity and assert the handler echoes them verbatim;
// a handler that secretly hardcodes devnet constants would emit the
// devnet hexes instead and fail the assertion. The values are fixed
// (not random) so the assertion is deterministic across CI runs.
var (
	nonDevnetChainID = [32]byte{
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	}
	nonDevnetGenesisHash = [32]byte{
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
	}
)

// TestDevnetRPCChainIdentityReportsWiredIdentity proves the handler
// echoes the identity values that flowed through SetIdentity. Network
// is exercised against a non-default ("testnet") to catch a handler
// that always reports "devnet".
func TestDevnetRPCChainIdentityReportsWiredIdentity(t *testing.T) {
	state := mustRPCState(t, false)
	state.SetIdentity("testnet", nonDevnetChainID, nonDevnetGenesisHash)
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	resp, err := http.Get(server.URL + "/chain_identity")
	if err != nil {
		t.Fatalf("GET /chain_identity: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q want application/json", got)
	}
	var body chainIdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Network != "testnet" {
		t.Fatalf("network=%q want testnet", body.Network)
	}
	if body.ChainIDHex != hex.EncodeToString(nonDevnetChainID[:]) {
		t.Fatalf("chain_id_hex=%q want %q", body.ChainIDHex, hex.EncodeToString(nonDevnetChainID[:]))
	}
	if body.GenesisHashHex != hex.EncodeToString(nonDevnetGenesisHash[:]) {
		t.Fatalf("genesis_hash_hex=%q want %q", body.GenesisHashHex, hex.EncodeToString(nonDevnetGenesisHash[:]))
	}
	// Hex contract: 64 lowercase chars, no 0x prefix.
	if len(body.ChainIDHex) != 64 || strings.HasPrefix(body.ChainIDHex, "0x") || strings.ToLower(body.ChainIDHex) != body.ChainIDHex {
		t.Fatalf("chain_id_hex shape violation: %q", body.ChainIDHex)
	}
	if len(body.GenesisHashHex) != 64 || strings.HasPrefix(body.GenesisHashHex, "0x") || strings.ToLower(body.GenesisHashHex) != body.GenesisHashHex {
		t.Fatalf("genesis_hash_hex shape violation: %q", body.GenesisHashHex)
	}
}

// TestDevnetRPCChainIdentityRejectsHardcodedDevnetConstants wires
// identity via SetIdentity with [32]byte values chosen to differ
// from node.DevnetGenesisChainID() and node.DevnetGenesisBlockHash(),
// then issues GET /chain_identity.
// Proof assertion: body.ChainIDHex != hex.EncodeToString(devnetChainID[:])
// and body.GenesisHashHex != hex.EncodeToString(devnetGenesisHash[:]).
func TestDevnetRPCChainIdentityRejectsHardcodedDevnetConstants(t *testing.T) {
	devnetChainID := node.DevnetGenesisChainID()
	devnetGenesisHash := node.DevnetGenesisBlockHash()
	if nonDevnetChainID == devnetChainID || nonDevnetGenesisHash == devnetGenesisHash {
		t.Fatalf("test fixture broken: non-devnet constants accidentally match devnet")
	}
	state := mustRPCState(t, false)
	state.SetIdentity("devnet", nonDevnetChainID, nonDevnetGenesisHash)
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	resp, err := http.Get(server.URL + "/chain_identity")
	if err != nil {
		t.Fatalf("GET /chain_identity: %v", err)
	}
	defer resp.Body.Close()
	var body chainIdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ChainIDHex == hex.EncodeToString(devnetChainID[:]) {
		t.Fatalf("chain_id_hex matches devnet constant; handler appears to hardcode devnet identity")
	}
	if body.GenesisHashHex == hex.EncodeToString(devnetGenesisHash[:]) {
		t.Fatalf("genesis_hash_hex matches devnet constant; handler appears to hardcode devnet identity")
	}
}

// TestDevnetRPCChainIdentityFailsClosedWithoutWiredIdentity asserts
// the handler returns 503 when SetIdentity has not been called. A
// fabricated 200 with devnet defaults would silently mislead an
// operator about which chain the node is on; failing closed is the
// load-bearing contract.
func TestDevnetRPCChainIdentityFailsClosedWithoutWiredIdentity(t *testing.T) {
	state := mustRPCState(t, false)
	// Deliberately do NOT call state.SetIdentity.
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	resp, err := http.Get(server.URL + "/chain_identity")
	if err != nil {
		t.Fatalf("GET /chain_identity: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q want application/json (no plain-text 503)", got)
	}
}

// TestDevnetRPCChainIdentityRejectsBadMethod asserts non-GET methods
// produce 405 + Allow: GET + JSON envelope (not plain-text), matching
// the canonical /ready handler shape.
func TestDevnetRPCChainIdentityRejectsBadMethod(t *testing.T) {
	state := mustRPCState(t, false)
	state.SetIdentity("devnet", nonDevnetChainID, nonDevnetGenesisHash)
	req := httptest.NewRequest(http.MethodPost, "/chain_identity", nil)
	rec := httptest.NewRecorder()
	newDevnetRPCHandler(state).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow=%q want GET", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q want application/json", got)
	}
}

// TestDevnetRPCHealthReportsLiveSnapshot brings up a state with the
// devnet genesis applied so has_tip=true, height=0, tip_hash=devnet
// genesis hash, and adds one peer + one mempool tx so the bounded
// counters are non-zero. Asserts every contracted field on /health.
// The spendable UTXO injection happens AFTER genesis is applied so
// blockstore.Tip() returns the genesis hash; mustRPCStateWithSpendableUTXO
// alone leaves blockstore empty because it pre-stages a UTXO directly
// in chainstate without going through syncEngine.ApplyBlock.
func TestDevnetRPCHealthReportsLiveSnapshot(t *testing.T) {
	fromKey := mustRPCMLDSA87Keypair(t)
	toKey := mustRPCMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	state, input, utxos := mustRPCStateWithSpendableUTXO(t, fromAddress, nil)
	if _, err := state.syncEngine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	state.SetIdentity("devnet", node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash())
	if !state.TryMarkReadyOnStartup() {
		t.Fatalf("TryMarkReadyOnStartup: false on a fresh gate")
	}
	// Inject one peer with a known address + version so peer_count == 1.
	if err := state.peerManager.AddPeer(&node.PeerState{
		Addr:              "127.0.0.1:30001",
		HandshakeComplete: true,
		BanScore:          0,
		LastError:         "",
		RemoteVersion: node.VersionPayloadV1{
			ProtocolVersion: 1,
			TxRelay:         true,
			BestHeight:      7,
		},
	}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	// Admit one tx so mempool_txs == 1 and mempool_bytes == len(txBytes).
	txBytes, _ := mustRPCSignedTransferTx(t, utxos, input, fromKey, toAddress)
	if err := state.mempool.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	var body healthResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Ready {
		t.Fatalf("ready=false; expected true after TryMarkReadyOnStartup")
	}
	if !body.HasTip {
		t.Fatalf("has_tip=false; expected true (no genesis applied?)")
	}
	if body.Height == nil {
		t.Fatalf("height is null; expected non-nil with has_tip=true")
	}
	if body.TipHash == nil || len(*body.TipHash) != 64 {
		t.Fatalf("tip_hash invalid: %v", body.TipHash)
	}
	if body.PeerCount != 1 {
		t.Fatalf("peer_count=%d want 1", body.PeerCount)
	}
	if body.MempoolTxs != 1 {
		t.Fatalf("mempool_txs=%d want 1", body.MempoolTxs)
	}
	if body.MempoolBytes != len(txBytes) {
		t.Fatalf("mempool_bytes=%d want %d", body.MempoolBytes, len(txBytes))
	}
}

// TestDevnetRPCHealthReportsReadyFalseAsField asserts a
// not-yet-ready node returns 200 with ready:false (not 503). The
// readiness gate is independent of /health's HTTP success; an
// orchestrator distinguishes "boot" (200 + ready:false) from "broken"
// (503).
func TestDevnetRPCHealthReportsReadyFalseAsField(t *testing.T) {
	state := mustRPCState(t, false)
	// Deliberately do NOT call TryMarkReadyOnStartup so IsReady is false.
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 (ready=false is a field, not an error)", resp.StatusCode)
	}
	var body healthResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Ready {
		t.Fatalf("ready=true on a non-ready node")
	}
	if body.HasTip {
		t.Fatalf("has_tip=true; expected false on a node without genesis applied")
	}
	if body.Height != nil || body.TipHash != nil {
		t.Fatalf("height/tip_hash non-nil with has_tip=false: %v / %v", body.Height, body.TipHash)
	}
}

// TestDevnetRPCHealthFailsClosedOnMissingState calls the /health
// handler with a nil *devnetRPCState.
// Proof assertion: rec.Code == http.StatusServiceUnavailable
// and rec.Header.Get("Content-Type") == "application/json".
func TestDevnetRPCHealthFailsClosedOnMissingState(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	newDevnetRPCHandler(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q want application/json (no plain-text 503)", got)
	}
}

// TestDevnetRPCHealthRejectsBadMethod asserts non-GET produces 405 +
// Allow: GET + JSON envelope.
func TestDevnetRPCHealthRejectsBadMethod(t *testing.T) {
	state := mustRPCState(t, false)
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rec := httptest.NewRecorder()
	newDevnetRPCHandler(state).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow=%q want GET", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q want application/json", got)
	}
}

// TestDevnetRPCPeersDeterministicSortByAddr injects three peers in
// non-sorted insertion order (and with map iteration randomization
// in PeerManager) and asserts /peers returns them sorted by addr
// ascending. Count == len(peers) is checked simultaneously.
func TestDevnetRPCPeersDeterministicSortByAddr(t *testing.T) {
	state := mustRPCState(t, false)
	addrs := []string{"127.0.0.1:30003", "127.0.0.1:30001", "127.0.0.1:30002"}
	for _, addr := range addrs {
		if err := state.peerManager.AddPeer(&node.PeerState{
			Addr:              addr,
			HandshakeComplete: true,
			BanScore:          0,
			LastError:         "",
			RemoteVersion: node.VersionPayloadV1{
				ProtocolVersion: 1,
				TxRelay:         true,
			},
		}); err != nil {
			t.Fatalf("AddPeer %q: %v", addr, err)
		}
	}
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	resp, err := http.Get(server.URL + "/peers")
	if err != nil {
		t.Fatalf("GET /peers: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	var body peersResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Count != len(body.Peers) {
		t.Fatalf("count=%d != len(peers)=%d", body.Count, len(body.Peers))
	}
	if body.Count != 3 {
		t.Fatalf("count=%d want 3", body.Count)
	}
	wantSorted := []string{"127.0.0.1:30001", "127.0.0.1:30002", "127.0.0.1:30003"}
	for i, want := range wantSorted {
		if body.Peers[i].Addr != want {
			t.Fatalf("peers[%d].addr=%q want %q (sort by addr asc violated)", i, body.Peers[i].Addr, want)
		}
	}
}

// TestDevnetRPCPeersEmptyReturnsEmptyArray asserts an initialized
// node with zero peers returns 200, count:0, and a JSON empty array
// for "peers" (NOT null and NOT 503). This is the false-positive
// case from the issue contract: zero peers is healthy.
func TestDevnetRPCPeersEmptyReturnsEmptyArray(t *testing.T) {
	state := mustRPCState(t, false)
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	resp, err := http.Get(server.URL + "/peers")
	if err != nil {
		t.Fatalf("GET /peers: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 (empty peer set is healthy)", resp.StatusCode)
	}
	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(rawBody), `"peers":[]`) {
		t.Fatalf("body=%q want JSON empty array `\"peers\":[]` (not null)", string(rawBody))
	}
	var body peersResponse
	if err := json.Unmarshal(rawBody, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Count != 0 {
		t.Fatalf("count=%d want 0", body.Count)
	}
	if len(body.Peers) != 0 {
		t.Fatalf("len(peers)=%d want 0", len(body.Peers))
	}
}

// TestDevnetRPCPeersFailsClosedOnNilPeerManager asserts /peers
// returns 503 when state.peerManager is nil. Constructed manually so
// the nil path is exercised through the public handler, not internal
// state mutation.
func TestDevnetRPCPeersFailsClosedOnNilPeerManager(t *testing.T) {
	state := &devnetRPCState{
		gate:    newReadinessGate(context.TODO()),
		stderr:  io.Discard,
		nowUnix: func() uint64 { return 0 },
		metrics: newRPCMetrics(),
		// peerManager intentionally left nil.
	}
	req := httptest.NewRequest(http.MethodGet, "/peers", nil)
	rec := httptest.NewRecorder()
	newDevnetRPCHandler(state).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q want application/json", got)
	}
}

// TestDevnetRPCPeersRejectsBadMethod asserts non-GET produces 405 +
// Allow: GET + JSON envelope.
func TestDevnetRPCPeersRejectsBadMethod(t *testing.T) {
	state := mustRPCState(t, false)
	req := httptest.NewRequest(http.MethodPost, "/peers", nil)
	rec := httptest.NewRecorder()
	newDevnetRPCHandler(state).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow=%q want GET", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q want application/json", got)
	}
}

// TestDevnetRPCPeersExposesAllBoundedFields populates one peer with
// every contracted field set to a distinct non-zero value and asserts
// every field round-trips through the JSON response. This catches a
// handler that silently drops a contracted field or maps it to the
// wrong PeerState/VersionPayloadV1 attribute.
func TestDevnetRPCPeersExposesAllBoundedFields(t *testing.T) {
	state := mustRPCState(t, false)
	peer := &node.PeerState{
		Addr:              "127.0.0.1:31337",
		HandshakeComplete: true,
		BanScore:          17,
		LastError:         "previous handshake timed out",
		RemoteVersion: node.VersionPayloadV1{
			ProtocolVersion:   2,
			TxRelay:           true,
			BestHeight:        99,
			PrunedBelowHeight: 12,
			DaMempoolSize:     34,
		},
	}
	if err := state.peerManager.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	server := httptest.NewServer(newDevnetRPCHandler(state))
	defer server.Close()

	resp, err := http.Get(server.URL + "/peers")
	if err != nil {
		t.Fatalf("GET /peers: %v", err)
	}
	defer resp.Body.Close()
	var body peersResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Count != 1 {
		t.Fatalf("count=%d want 1", body.Count)
	}
	got := body.Peers[0]
	want := peerEntry{
		Addr:              "127.0.0.1:31337",
		HandshakeComplete: true,
		BanScore:          17,
		LastError:         "previous handshake timed out",
		ProtocolVersion:   2,
		BestHeight:        99,
		TxRelay:           true,
		PrunedBelowHeight: 12,
		DaMempoolSize:     34,
	}
	if got != want {
		t.Fatalf("peer entry mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}
