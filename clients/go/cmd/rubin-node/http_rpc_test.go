package main

import (
	"bytes"
	"context"
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
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, nil, io.Discard, nil)
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
	syncEngine.SetMempool(mempool)
	peerManager := node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8))
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, announceTx, io.Discard, nil)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := startDevnetRPCServer(ctx, "127.0.0.1:0", mustRPCState(t, false), io.Discard, io.Discard)
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
// because the drainSubmitTxBody path truncated the stream before
// json.Decode.
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
		err        error
		wantStatus int
		wantResult string
	}{
		{name: "conflict already present", err: &node.TxAdmitError{Kind: node.TxAdmitConflict, Message: "already in mempool"}, wantStatus: http.StatusConflict, wantResult: "conflict"},
		{name: "conflict double spend", err: &node.TxAdmitError{Kind: node.TxAdmitConflict, Message: "double-spend conflict"}, wantStatus: http.StatusConflict, wantResult: "conflict"},
		{name: "unavailable mempool full", err: &node.TxAdmitError{Kind: node.TxAdmitUnavailable, Message: "mempool full"}, wantStatus: http.StatusServiceUnavailable, wantResult: "unavailable"},
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
	state := newDevnetRPCState(nil, nil, nil, nil, nil, nil, nil)
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
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, nil, io.Discard, miner)
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
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, nil, io.Discard, miner)
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
	if !got.Mined || got.Height == nil || *got.Height != 1 || got.TxCount == nil || *got.TxCount < 1 {
		t.Fatalf("unexpected response: %+v", got)
	}
	if got.Nonce == nil {
		t.Fatalf("want nonce field in JSON for Go/Rust RPC parity, got %+v", got)
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
