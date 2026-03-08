package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, nil)
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
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	chainState := node.NewChainState()
	var prevTxid [32]byte
	prevTxid[0] = 0x44
	outpoint := consensus.Outpoint{Txid: prevTxid, Vout: 0}
	chainState.Utxos[outpoint] = consensus.UtxoEntry{
		Value:             100,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      append([]byte(nil), fromAddress...),
		CreationHeight:    0,
		CreatedByCoinbase: false,
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
	mempool, err := node.NewMempool(chainState, blockStore, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, announceTx)
	state.nowUnix = func() uint64 { return 0 }
	return state, outpoint, chainState.Utxos
}

func mustRPCSignedTransferTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	signer *consensus.MLDSA87Keypair,
	toAddress []byte,
) ([]byte, string) {
	t.Helper()
	changeAddress := consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []consensus.TxInput{{
			PrevTxid: input.Txid,
			PrevVout: input.Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{
				Value:        90,
				CovenantType: consensus.COV_TYPE_P2PK,
				CovenantData: append([]byte(nil), toAddress...),
			},
			{
				Value:        9,
				CovenantType: consensus.COV_TYPE_P2PK,
				CovenantData: append([]byte(nil), changeAddress...),
			},
		},
		Locktime: 0,
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
		"rubin_node_peer_count 0",
		"rubin_node_mempool_txs 0",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in metrics body %q", want, body)
		}
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
		errText    string
		wantStatus int
		wantResult string
	}{
		{name: "conflict already present", errText: "already in mempool", wantStatus: http.StatusConflict, wantResult: "conflict"},
		{name: "conflict double spend", errText: "double-spend conflict", wantStatus: http.StatusConflict, wantResult: "conflict"},
		{name: "unavailable mempool full", errText: "mempool full", wantStatus: http.StatusServiceUnavailable, wantResult: "unavailable"},
		{name: "unavailable blockstore", errText: "blockstore unavailable", wantStatus: http.StatusServiceUnavailable, wantResult: "unavailable"},
		{name: "rejected default", errText: "transaction rejected", wantStatus: http.StatusUnprocessableEntity, wantResult: "rejected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, result := classifySubmitErr(errors.New(tc.errText))
			if status != tc.wantStatus || result != tc.wantResult {
				t.Fatalf("got (%d, %q), want (%d, %q)", status, result, tc.wantStatus, tc.wantResult)
			}
		})
	}
}

func TestStartDevnetRPCServerLifecycle(t *testing.T) {
	state := mustRPCState(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := startDevnetRPCServer(ctx, "127.0.0.1:0", state, nil, nil)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout bytes.Buffer
	server, err := startDevnetRPCServer(ctx, "127.0.0.1:0", state, &stdout, nil)
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
	server, err := startDevnetRPCServer(context.Background(), "   ", mustRPCState(t, false), nil, nil)
	if err != nil {
		t.Fatalf("startDevnetRPCServer: %v", err)
	}
	if server != nil {
		t.Fatalf("server=%#v, want nil", server)
	}
}

func TestStartDevnetRPCServerRejectsNilState(t *testing.T) {
	server, err := startDevnetRPCServer(context.Background(), "127.0.0.1:0", nil, nil, nil)
	if err == nil {
		t.Fatal("expected nil-state error")
	}
	if server != nil {
		t.Fatalf("server=%#v, want nil", server)
	}
}
