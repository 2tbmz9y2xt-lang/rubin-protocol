package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func mustRPCState(t *testing.T, withGenesis bool) *devnetRPCState {
	t.Helper()
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
